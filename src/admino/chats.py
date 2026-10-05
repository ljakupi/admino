"""Persisted, owner-private chats and their messages (GH-176, migration 0024).

The repository behind the chat routes and the agent turns: a member creates,
lists, renames and trashes their own chats; every turn appends the run's new
messages (``append_messages``) and the next run loads the latest ones back
(``load_recent_history``). The legacy ``session_id`` API keeps one chat per
(user, session id) through ``chats.legacy_session_id`` until #177
(``get_or_create_legacy_chat``, ``find_legacy_chat``). GH-66's promotion
notice reaches every live chat of the org (``append_org_notice``), and the
Super Admin's org metadata counts the org's chats (``count_org_chats``).

Inputs: an executor (an asyncpg pool or connection) or, for the two
transactional writes (``trash_chat``, ``append_messages``), the pool; the
caller's ``TenantContext``; a chat id; titles, ``LLMMessage``s and
``ToolCallRecord``s; page sizes and opaque cursors.
Outputs: ``ChatRecord``, ``ChatPage``, ``MessagePage``, ``LLMMessage`` lists,
counts and message statuses. Errors: ``ChatNotFoundError``,
``InvalidCursorError``, ``ValueError`` (a ``system`` message to store),
``audit_events.AuditRecordError`` and the driver's errors.

Behaviour:
- Lists are keyset-paginated: chats by ``(last_activity_at, id)`` descending,
  messages by ``seq`` descending (returned chronologically). A page fetches
  one row more than asked to know whether ``next_cursor`` is needed.
- Cursors are base64url JSON tagged with their kind, at most 200 characters:
  a chat-list cursor never decodes as a message cursor, and anything that
  doesn't decode is ``InvalidCursorError``. A cursor carries a position only,
  never a scope: the caller's tenant still filters every row.
- JSONB values travel as JSON text (``$n::jsonb``) and come back as text,
  decoded here. PostgreSQL's TEXT and JSONB refuse U+0000, so it is removed
  from message content and from every string (keys included) inside the JSON
  values before writing.
- ``append_messages`` and ``trash_chat`` each run in one transaction:
  ``append_messages`` touches the chat first (no row: nothing is written),
  then inserts the messages in order; ``trash_chat`` sets ``deleted_at`` and
  records ``chat.delete`` on the same connection, so a failed audit write
  rolls the trash back. ``get_or_create_legacy_chat`` uses no transaction of
  its own: a concurrent first message of the same session loses the INSERT
  on the partial unique key and selects the winner's chat.

Security notes:
- Owner-private chats (V1): every statement on a chat binds the caller's
  ``org_id`` and ``user_id`` and states ``deleted_at IS NULL``. Another org's
  chat, a colleague's chat, a trashed chat and an unknown id raise the same
  ``ChatNotFoundError`` with a fixed text and change nothing. Only the org
  notice and the platform count are org-wide (org id and live chats only).
- The sticky ``external_content`` flag (GH-243) is set only when an appended
  ``tool`` message holds wrapped external content
  (``untrusted.contains_wrapped``): a user or the model typing a marker can't
  set it, and nothing here ever clears it.
- System prompts and instructions are never stored: a ``system`` message is
  refused before any statement.
- No content in logs or errors: nothing is logged here, and no error carries
  a title, message, session id or chat id. The driver's errors (which quote
  the failing row) propagate untouched and must never be logged by text.
- Parameterized SQL only: every statement is a constant, every value a bind
  parameter. Imports nothing from the server, agent, LLM, tools or OAuth
  layers.
"""

from __future__ import annotations

import base64
import contextlib
import json
import re
from datetime import datetime  # noqa: TC003 — Pydantic resolves field annotations at runtime
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol
from uuid import UUID  # noqa: TC003 — Pydantic resolves field annotations at runtime

import asyncpg
from pydantic import AwareDatetime, Field, StrictInt

from admino import audit_events, untrusted
from admino.access import PlainUUID, SealedModel
from admino.audit_events import AuditAction, TargetType
from admino.models import LLMMessage
from admino.models import MessageStatus as MessageStatus
from admino.models import TitleSource as TitleSource

if TYPE_CHECKING:
    from collections.abc import Sequence

    from admino.models import ToolCallRecord
    from admino.tenancy import TenantContext

_NUL: Final = "\x00"
# What a cursor may look like before it is decoded: base64url, at most 200 characters.
_CURSOR_RE: Final = re.compile(r"[A-Za-z0-9_-]{1,200}")

# S1: a new chat of the caller (a legacy session id only for the legacy route).
_CREATE_SQL: Final = """
    INSERT INTO chats (org_id, owner_user_id, title, title_source, legacy_session_id)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
"""
# S2: the caller's live chat by id.
_GET_SQL: Final = """
    SELECT id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
    FROM chats
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
"""
# S3: the caller's live chat of a legacy session id.
_LEGACY_SQL: Final = """
    SELECT id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
    FROM chats
    WHERE org_id = $1 AND owner_user_id = $2 AND legacy_session_id = $3 AND deleted_at IS NULL
"""
# S4: the caller's live chats, latest activity first: the first page ...
_LIST_SQL: Final = """
    SELECT id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
    FROM chats
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
    ORDER BY last_activity_at DESC, id DESC
    LIMIT $3
"""
# ... and the page after a cursor's position.
_LIST_AFTER_SQL: Final = """
    SELECT id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
    FROM chats
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at IS NULL
        AND (last_activity_at, id) < ($3, $4)
    ORDER BY last_activity_at DESC, id DESC
    LIMIT $5
"""
# S5: a user title; last_activity_at is left alone (a rename isn't activity).
_RENAME_SQL: Final = """
    UPDATE chats SET title = $4, title_source = 'user'
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    RETURNING id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
"""
# S6: the trash is a timestamp (restore and purge are #194).
_TRASH_SQL: Final = """
    UPDATE chats SET deleted_at = now()
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    RETURNING id
"""
# S7: a turn's activity, and GH-243's sticky flag when a tool result held
# wrapped external content (never reset).
_TOUCH_SQL: Final = """
    UPDATE chats SET last_activity_at = now()
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    RETURNING id
"""
_TOUCH_EXTERNAL_SQL: Final = """
    UPDATE chats SET last_activity_at = now(), external_content = true
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    RETURNING id
"""
# S8: one message; seq is the identity column, so the insert order is the chat's order.
_INSERT_MESSAGE_SQL: Final = """
    INSERT INTO chat_messages
        (chat_id, org_id, role, content, tool_use_blocks, tool_call_id, tool_calls, status)
    VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8)
"""
# S9: a chat's latest messages (newest first) ...
_LATEST_MESSAGES_SQL: Final = """
    SELECT id, seq, role, content, tool_use_blocks, tool_call_id, tool_calls, status, created_at
    FROM chat_messages
    WHERE chat_id = $1 AND org_id = $2
    ORDER BY seq DESC
    LIMIT $3
"""
# ... and those before a cursor's seq.
_MESSAGES_BEFORE_SQL: Final = """
    SELECT id, seq, role, content, tool_use_blocks, tool_call_id, tool_calls, status, created_at
    FROM chat_messages
    WHERE chat_id = $1 AND org_id = $2 AND seq < $3
    ORDER BY seq DESC
    LIMIT $4
"""
# S10
_COUNT_MESSAGES_SQL: Final = "SELECT count(*) FROM chat_messages WHERE chat_id = $1 AND org_id = $2"
# S12: GH-66's promotion notice in every live chat of the org, one statement.
_ORG_NOTICE_SQL: Final = """
    INSERT INTO chat_messages (chat_id, org_id, role, content, status)
    SELECT id, org_id, 'user', $2, 'complete' FROM chats WHERE org_id = $1 AND deleted_at IS NULL
"""
# S13
_COUNT_ORG_CHATS_SQL: Final = "SELECT count(*) FROM chats WHERE org_id = $1 AND deleted_at IS NULL"


class ChatNotFoundError(LookupError):
    """Unknown id, another org's or another user's chat, or a trashed chat (one error for all)."""

    def __init__(self) -> None:
        super().__init__("Chat not found.")


class InvalidCursorError(ValueError):
    """A list or message cursor that doesn't decode."""

    def __init__(self) -> None:
        super().__init__("Invalid cursor.")


class Executor(Protocol):
    """What the reads and single-statement writes run through: an asyncpg pool or connection."""

    async def execute(self, query: str, *args: object) -> str:
        """Run one statement with bind parameters."""
        ...

    # Any: asyncpg returns untyped Records.
    async def fetch(self, query: str, *args: object) -> Any:
        """Run one query and return its rows."""
        ...

    async def fetchrow(self, query: str, *args: object) -> Any:
        """Run one query and return its first row, or None."""
        ...

    async def fetchval(self, query: str, *args: object) -> Any:
        """Run one query and return the first column of its first row, or None."""
        ...


class ChatRecord(SealedModel):
    """One chats row (without the legacy session id and the trash timestamp)."""

    id: PlainUUID
    org_id: PlainUUID
    owner_user_id: PlainUUID
    title: str
    title_source: TitleSource
    external_content: bool
    created_at: datetime
    last_activity_at: datetime


class MessageRecord(SealedModel):
    """One chat_messages row, its JSON columns decoded."""

    id: PlainUUID
    seq: int
    role: Literal["user", "assistant", "tool"]
    content: str
    # Any: stored tool inputs and tool-call summaries are arbitrary JSON objects.
    tool_use_blocks: list[dict[str, Any]] | None
    tool_call_id: str | None
    tool_calls: list[dict[str, Any]] | None
    status: MessageStatus
    created_at: datetime


class ChatPage(SealedModel):
    """One page of the caller's chats; ``next_cursor`` is None on the last page."""

    chats: list[ChatRecord]
    next_cursor: str | None


class MessagePage(SealedModel):
    """One page of a chat's messages, chronological; ``next_cursor`` points to earlier ones."""

    messages: list[MessageRecord]
    next_cursor: str | None


class _ChatCursor(SealedModel):
    """The position after the last chat of a list page."""

    kind: Literal["chats"] = "chats"
    last_activity_at: AwareDatetime
    id: UUID


class _MessageCursor(SealedModel):
    """The seq of the earliest message of a message page."""

    kind: Literal["messages"] = "messages"
    seq: StrictInt = Field(ge=1)


def _encode_cursor(cursor: _ChatCursor | _MessageCursor) -> str:
    """The opaque cursor string: unpadded base64url of the cursor's JSON."""
    return base64.urlsafe_b64encode(cursor.model_dump_json().encode()).rstrip(b"=").decode()


def _decode_cursor[C: (_ChatCursor, _MessageCursor)](cursor: str, kind: type[C]) -> C:
    """Decode a cursor of one kind.

    Raises:
        InvalidCursorError: If it isn't base64url JSON of that kind of cursor.
    """
    if _CURSOR_RE.fullmatch(cursor) is None:
        raise InvalidCursorError
    try:
        return kind.model_validate_json(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except ValueError:
        # binascii.Error and ValidationError are ValueErrors; neither reaches the caller.
        raise InvalidCursorError from None


# Any: a JSON value of any shape (object, array, string, number, bool, null).
def _without_nul(value: Any) -> Any:
    """The JSON value with U+0000 removed from every string, object keys included."""
    if isinstance(value, str):
        return value.replace(_NUL, "")
    if isinstance(value, list | tuple):
        return [_without_nul(item) for item in value]
    if isinstance(value, dict):
        return {_without_nul(key): _without_nul(item) for key, item in value.items()}
    return value


def _json_text(value: list[dict[str, Any]] | None) -> str | None:
    """The JSON text bound to a ``$n::jsonb`` parameter (U+0000 removed), None for NULL."""
    return None if value is None else json.dumps(_without_nul(value))


# Any: a decoded JSONB column (an array of objects here).
def _from_json(text: str | None) -> Any:
    """A JSONB column's value from its text, None for NULL."""
    return None if text is None else json.loads(text)


# Any: asyncpg returns untyped Records.
def _chat_record(row: Any) -> ChatRecord:
    """The ChatRecord of a chats row (the chat columns only)."""
    return ChatRecord.model_validate(dict(row))


# Any: asyncpg returns untyped Records.
def _message_record(row: Any) -> MessageRecord:
    """The MessageRecord of a chat_messages row, its JSON columns decoded."""
    return MessageRecord.model_validate(
        {
            **dict(row),
            "tool_use_blocks": _from_json(row["tool_use_blocks"]),
            "tool_calls": _from_json(row["tool_calls"]),
        }
    )


async def create_chat(
    executor: Executor, tenant: TenantContext, *, title: str | None = None
) -> ChatRecord:
    """Create a chat of the caller.

    Args:
        executor: The pool or a connection.
        tenant: The caller's org scope; the caller owns the chat.
        title: A validated title, or None for an untitled chat (``''``,
            ``auto``, for #179's automatic title).

    Returns:
        The stored chat.
    """
    row = await executor.fetchrow(
        _CREATE_SQL,
        tenant.org_id,
        tenant.user_id,
        "" if title is None else title,
        "auto" if title is None else "user",
        None,
    )
    return _chat_record(row)


async def get_chat(executor: Executor, tenant: TenantContext, chat_id: UUID) -> ChatRecord:
    """Return the caller's live chat.

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed.
    """
    row = await executor.fetchrow(_GET_SQL, chat_id, tenant.org_id, tenant.user_id)
    if row is None:
        raise ChatNotFoundError
    return _chat_record(row)


async def find_legacy_chat(
    executor: Executor, tenant: TenantContext, session_id: str
) -> ChatRecord:
    """Return the caller's live chat of a legacy session id; never creates one.

    Raises:
        ChatNotFoundError: If the caller has no live chat of that session id.
    """
    row = await executor.fetchrow(_LEGACY_SQL, tenant.org_id, tenant.user_id, session_id)
    if row is None:
        raise ChatNotFoundError
    return _chat_record(row)


async def get_or_create_legacy_chat(
    executor: Executor, tenant: TenantContext, session_id: str
) -> ChatRecord:
    """Return the caller's live chat of a legacy session id, creating it if needed.

    Runs without a transaction of its own (pass the pool): when a concurrent
    first message of the same session inserts the chat first, the INSERT
    fails on the partial unique key and the winner's chat is selected.

    Args:
        executor: The pool.
        tenant: The caller's org scope.
        session_id: The validated legacy session id.

    Returns:
        The chat (untitled, ``auto``, when created here).
    """
    with contextlib.suppress(ChatNotFoundError):
        return await find_legacy_chat(executor, tenant, session_id)
    # The driver's error quotes the session id: it is dropped, never logged.
    with contextlib.suppress(asyncpg.UniqueViolationError):
        row = await executor.fetchrow(
            _CREATE_SQL, tenant.org_id, tenant.user_id, "", "auto", session_id
        )
        return _chat_record(row)
    return await find_legacy_chat(executor, tenant, session_id)


async def list_chats(
    executor: Executor, tenant: TenantContext, *, limit: int, cursor: str | None
) -> ChatPage:
    """Return one page of the caller's live chats, latest activity first.

    Args:
        executor: The pool or a connection.
        tenant: The caller's org scope.
        limit: The page size (at least 1).
        cursor: The previous page's ``next_cursor``, or None for the first page.

    Returns:
        The chats by ``last_activity_at`` then id, both descending, and the
        cursor of the next page (None on the last one).

    Raises:
        InvalidCursorError: If the cursor isn't a chat-list cursor.
    """
    if cursor is None:
        rows = await executor.fetch(_LIST_SQL, tenant.org_id, tenant.user_id, limit + 1)
    else:
        after = _decode_cursor(cursor, _ChatCursor)
        rows = await executor.fetch(
            _LIST_AFTER_SQL,
            tenant.org_id,
            tenant.user_id,
            after.last_activity_at,
            after.id,
            limit + 1,
        )
    chats = [_chat_record(row) for row in rows[:limit]]
    next_cursor = None
    if len(rows) > limit:
        last = chats[-1]
        next_cursor = _encode_cursor(
            _ChatCursor(last_activity_at=last.last_activity_at, id=last.id)
        )
    return ChatPage(chats=chats, next_cursor=next_cursor)


async def rename_chat(
    executor: Executor, tenant: TenantContext, chat_id: UUID, title: str
) -> ChatRecord:
    """Give the caller's chat a user title; idempotent, activity unchanged.

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed.
    """
    row = await executor.fetchrow(_RENAME_SQL, chat_id, tenant.org_id, tenant.user_id, title)
    if row is None:
        raise ChatNotFoundError
    return _chat_record(row)


async def trash_chat(
    pool: asyncpg.Pool, tenant: TenantContext, chat_id: UUID, *, ip: str | None
) -> None:
    """Move the caller's chat to the trash and record ``chat.delete``, atomically.

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        chat_id: The chat.
        ip: The client IP, for the audit event.

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed;
            nothing is written.
        AuditRecordError: If the event can't be recorded; the trash is rolled back.
    """
    async with pool.acquire() as conn, conn.transaction():
        trashed = await conn.fetchval(_TRASH_SQL, chat_id, tenant.org_id, tenant.user_id)
        if trashed is None:
            raise ChatNotFoundError
        await audit_events.record(
            conn,
            action=AuditAction.CHAT_DELETE,
            actor_kind="member",
            actor_user_id=tenant.user_id,
            org_id=tenant.org_id,
            target_type=TargetType.CHAT,
            target_ids=(chat_id,),
            ip=ip,
        )


async def append_messages(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    chat_id: UUID,
    messages: Sequence[LLMMessage],
    *,
    final_status: MessageStatus = "complete",
    tool_calls: Sequence[ToolCallRecord] | None = None,
) -> None:
    """Append a run's new messages to the caller's chat, in one transaction.

    Every message is stored ``complete`` without tool calls except the last,
    which gets ``final_status`` and the run's tool calls (NULL when there are
    none). The chat's ``last_activity_at`` is bumped, and ``external_content``
    is set (for good) when an appended ``tool`` message holds wrapped external
    content. U+0000 is removed from the content and the JSON values.

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        chat_id: The chat.
        messages: The new user, assistant and tool messages, in order; an
            empty sequence runs no statement.
        final_status: The stored status of the run's last message.
        tool_calls: The run's tool-call summaries, stored on the last message.

    Raises:
        ValueError: If a ``system`` message is passed; nothing is written.
        ChatNotFoundError: Unless the chat is the caller's and not trashed;
            nothing is written.
    """
    if not messages:
        return
    if any(message.role == "system" for message in messages):
        msg = "System messages are never stored."
        raise ValueError(msg)
    last = len(messages) - 1
    calls = [record.model_dump(mode="json") for record in tool_calls or ()]
    rows = [
        (
            message.role,
            message.content.replace(_NUL, ""),
            _json_text(message.tool_use_blocks),
            message.tool_call_id,
            _json_text(calls) if index == last and calls else None,
            final_status if index == last else "complete",
        )
        for index, message in enumerate(messages)
    ]
    external = any(role == "tool" and untrusted.contains_wrapped(text) for role, text, *_ in rows)
    async with pool.acquire() as conn, conn.transaction():
        touched = await conn.fetchval(
            _TOUCH_EXTERNAL_SQL if external else _TOUCH_SQL,
            chat_id,
            tenant.org_id,
            tenant.user_id,
        )
        if touched is None:
            raise ChatNotFoundError
        for role, content, blocks, call_id, stored_calls, status in rows:
            await conn.execute(
                _INSERT_MESSAGE_SQL,
                chat_id,
                tenant.org_id,
                role,
                content,
                blocks,
                call_id,
                stored_calls,
                status,
            )


async def load_recent_history(
    executor: Executor, tenant: TenantContext, chat_id: UUID, *, limit: int
) -> list[LLMMessage]:
    """Return the latest messages of the caller's chat as the agent's history.

    Args:
        executor: The pool or a connection.
        tenant: The caller's org scope.
        chat_id: The chat.
        limit: How many of the latest messages to load (the context window).

    Returns:
        The messages in chronological order, without the leading ``tool``
        results whose assistant turn fell outside the window.

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed.
    """
    await get_chat(executor, tenant, chat_id)
    rows = await executor.fetch(_LATEST_MESSAGES_SQL, chat_id, tenant.org_id, limit)
    history = [
        LLMMessage(
            role=row["role"],
            content=row["content"],
            tool_call_id=row["tool_call_id"],
            tool_use_blocks=_from_json(row["tool_use_blocks"]),
        )
        for row in reversed(rows)
    ]
    # An orphan tool result first would break the provider's tool-call pairing.
    start = next((i for i, message in enumerate(history) if message.role != "tool"), len(history))
    return history[start:]


async def list_messages(
    executor: Executor, tenant: TenantContext, chat_id: UUID, *, limit: int, cursor: str | None
) -> MessagePage:
    """Return one page of the caller's chat's messages, latest page first.

    Args:
        executor: The pool or a connection.
        tenant: The caller's org scope.
        chat_id: The chat.
        limit: The page size (at least 1).
        cursor: The previous page's ``next_cursor``, or None for the latest page.

    Returns:
        Up to ``limit`` messages before the cursor, in chronological order,
        and the cursor of the earlier messages (None at the beginning).

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed.
        InvalidCursorError: If the cursor isn't a message cursor.
    """
    await get_chat(executor, tenant, chat_id)
    if cursor is None:
        rows = await executor.fetch(_LATEST_MESSAGES_SQL, chat_id, tenant.org_id, limit + 1)
    else:
        before = _decode_cursor(cursor, _MessageCursor)
        rows = await executor.fetch(
            _MESSAGES_BEFORE_SQL, chat_id, tenant.org_id, before.seq, limit + 1
        )
    messages = [_message_record(row) for row in reversed(rows[:limit])]
    next_cursor = None
    if len(rows) > limit:
        next_cursor = _encode_cursor(_MessageCursor(seq=messages[0].seq))
    return MessagePage(messages=messages, next_cursor=next_cursor)


async def count_messages(executor: Executor, tenant: TenantContext, chat_id: UUID) -> int:
    """Return how many messages the caller's chat holds.

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed.
    """
    await get_chat(executor, tenant, chat_id)
    return int(await executor.fetchval(_COUNT_MESSAGES_SQL, chat_id, tenant.org_id))


async def latest_message_status(
    executor: Executor, tenant: TenantContext, chat_id: UUID
) -> MessageStatus | None:
    """Return the status of the caller's chat's latest message (highest seq).

    Returns:
        The status, or None for a chat without messages.

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed.
    """
    await get_chat(executor, tenant, chat_id)
    row = await executor.fetchrow(_LATEST_MESSAGES_SQL, chat_id, tenant.org_id, 1)
    if row is None:
        return None
    status: MessageStatus = row["status"]
    return status


async def append_org_notice(executor: Executor, tenant: TenantContext, content: str) -> int:
    """Append GH-66's promotion notice to every live chat of the caller's org.

    One ``user`` message, status ``complete``, in every member's live chat of
    ``tenant.org_id`` (never another org's), in one statement; the chats'
    ``last_activity_at`` is left alone.

    Returns:
        The number of chats the notice was appended to.
    """
    status = await executor.execute(_ORG_NOTICE_SQL, tenant.org_id, content)
    # The command tag is "INSERT 0 <rows>".
    return int(status.rsplit(" ", 1)[1])


async def count_org_chats(executor: Executor, org_id: UUID) -> int:
    """Return how many chats of an org aren't trashed (platform metadata; a count only)."""
    return int(await executor.fetchval(_COUNT_ORG_CHATS_SQL, org_id))
