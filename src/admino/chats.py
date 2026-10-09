"""Persisted, owner-private chats and their messages (GH-176, migration 0024).

The repository behind the chat routes and the agent turns: a member creates,
lists, renames and trashes their own chats and reads one with a page of its
messages (``read_chat_detail``); every turn appends the run's new messages
(``append_messages``) and the next run loads the latest ones back
(GH-244's send path reads the chat and them in one statement, S16, with
``load_turn``). The legacy ``session_id`` API keeps one chat per (user,
session id) through ``chats.legacy_session_id`` until #177
(``find_legacy_chat``, ``get_or_create_legacy_chat``). GH-66's promotion
notice reaches every live chat of the org (``append_org_notice``), and the
Super Admin's org metadata counts the org's chats (``count_org_chats``).
GH-179's background task stores the automatic title (``set_auto_title``).
GH-187's attachments follow their chat: a turn links the files its user
message carried (``append_messages``), and the trash takes them along
(``trash_chat``). GH-189: the turn read (``load_turn``, T2') also returns the
chat's active attachments (``ActiveAttachment``: sent with one of its
messages, live, ``ready``, in the order they were sent), and a run whose
slot 4 held them stores the slot's ids on each of its assistant messages
(S8', migration 0029) and sets the chat's sticky ``external_content`` flag.
GH-190: the turn read (T2'') leaves out excluded files (``attachments.active``
false, migration 0030) and carries each active file's stored
``token_estimate`` and ``derived_bytes`` for the context budget and the byte
cap; each message of the chat detail carries the ids of its live attachments,
excluded ones too (S9' / S11'), and the detail no longer counts the messages
(Decision 13). The upload, reads and files are ``admino.attachments``, which
imports this module (never the reverse); their derived files are read by
``admino.attachment_context``.

Inputs: an executor (an asyncpg pool or connection) or, for the three
transactional writes (``trash_chat``, ``append_messages`` and
``append_org_notice``), the pool; the caller's ``TenantContext``; a chat id
(the server-generated id of a legacy chat to create); titles,
``LLMMessage``s, ``ToolCallRecord``s, attachment ids (the files a message
carries and the slot's ids its answers included) and whether the run
received external content; page sizes and opaque cursors.
Outputs: ``ChatRecord``, ``ChatPage``, ``ChatDetail`` (the chat, a
``MessagePage`` whose messages carry their ``attachment_ids``, and its latest
message status), ``ChatTurn`` (the chat, its history and its active
``ActiveAttachment``s with their estimates), counts, whether an automatic
title was stored and the id of a turn's last appended message.
Errors: ``ChatNotFoundError``, ``InvalidCursorError``, ``ValueError`` (a
``system`` message or a message of content parts to store, attachments
without a ``user`` message to carry them), ``audit_events.AuditRecordError``
and the driver's errors.

Behaviour:
- Lists are keyset-paginated: chats by ``(last_activity_at, id)`` descending,
  messages by ``seq`` descending (returned chronologically). A page fetches
  one row more than asked to know whether ``next_cursor`` is needed.
- Cursors are base64url JSON tagged with their kind, at most 200 characters:
  a chat-list cursor never decodes as a message cursor (nor as
  ``admino.attachments``' list cursor, which shares ``encode_cursor`` /
  ``decode_cursor`` and ``CursorStamp``), and anything that doesn't decode is
  ``InvalidCursorError``, so is one whose position can't be bound (a seq
  beyond BIGINT, a timestamp without a UTC equivalent). A cursor carries a
  position only, never a scope: the caller's tenant still filters every row.
- ``read_chat_detail`` runs the owner check once, first; the page (with each
  message's attachment ids) and the latest status (its ``status`` column
  only) follow it.
- JSONB values travel as JSON text (``$n::jsonb``) and come back as text,
  decoded here. PostgreSQL's TEXT and JSONB refuse U+0000, so it is removed
  from message content and from every string (keys included) inside the JSON
  values before writing. JSONB also refuses a lone surrogate, which a
  model-produced tool input or tool-call argument can carry (the ``str``
  fields refuse one already), so each is replaced by U+FFFD in those strings.
  JSON and JSONB have no NaN or infinity either, which a model's tool
  arguments can carry once parsed (``1e400`` parses as infinity): each
  non-finite number is stored as null, at any depth (GH-266), and the JSON
  text is written with ``allow_nan=False``, so a non-finite number that
  slipped through would raise instead of reaching the database.
- ``append_messages`` and ``trash_chat`` each run in one transaction:
  ``append_messages`` touches the chat first (no row: nothing is written),
  then inserts the messages in order, linking the given attachments (A9)
  right after the turn's first ``user`` message, so a later failure unlinks
  them with the turn; ``trash_chat`` sets ``deleted_at`` on the chat, then
  on its live attachments (A10; their files stay on disk until #194's
  purge), and records ``chat.delete`` on the same connection, so a failed
  audit write rolls the trash back. ``get_or_create_legacy_chat`` uses no
  transaction of its own: a concurrent first message of the same session
  loses the INSERT on the partial unique key ``chats_legacy_session_key`` and
  selects the winner's chat (whose id differs from the one given). Only that
  key's violation is the race (GH-271): any other unique violation (the given
  id already taken) propagates as the driver raised it.
- ``append_org_notice`` (GH-66) skips every chat whose latest message (highest
  seq, any role) is ``awaiting_confirmation``: a user message after the
  pending call's ``tool_use`` would separate it from its result and break the
  history the next run gets (GH-24). It runs in one transaction that first
  locks the org's live chats (``FOR UPDATE``, id order): a turn storing its
  messages holds its chat's row until it commits, so the notice waits and
  then sees that turn's awaiting message.

Security notes:
- Owner-private chats (V1): every statement on a chat binds the caller's
  ``org_id`` and ``user_id`` and states ``deleted_at IS NULL``. Another org's
  chat, a colleague's chat, a trashed chat and an unknown id raise the same
  ``ChatNotFoundError`` with a fixed text and change nothing. Only the org
  notice and the platform count are org-wide (org id and live chats only).
- Attachments are linked only when they are the caller's, in this chat, in
  the caller's org, unsent and live (A9 states all five), and trashed only
  with their chat after its owner check (A10 binds the trashed chat and the
  caller's org). The turn read (T2'') returns only the attachments of the
  caller's chat whose org and owner are the chat's, sent with one of its
  messages, live, ``ready`` and active; the detail page's attachment ids are
  those of the page's messages (the checked chat's) in the caller's org.
  None of them reads, writes or names a file.
- An automatic title never overwrites a user's: ``set_auto_title`` is a
  compare-and-set on ``title_source = 'auto' AND title = ''`` (plus the
  owner, org and ``deleted_at IS NULL`` filters) and returns False instead of
  raising, so a rename that lands while the title is generated always wins.
- The sticky ``external_content`` flag (GH-243) is set only when an appended
  ``tool`` message holds wrapped external content
  (``untrusted.contains_wrapped``) or the trusted caller says the run
  received some (``external_content=True``: GH-189's attachments): a user or
  the model typing a marker can't set it, and nothing here ever clears it
  (migration 0025's trigger refuses a reset in the database too).
- The runtime role may update only ``title``, ``title_source``,
  ``last_activity_at``, ``external_content`` and ``deleted_at`` of a chat
  (migration 0025), and only ``message_id``, ``updated_at`` and
  ``deleted_at`` (among others) of an attachment (migration 0027): every
  UPDATE here stays within them.
- System prompts and instructions are never stored: a ``system`` message is
  refused before any statement, and so is a message whose content is a list
  of content parts (GH-189: attachment content and images live only in one
  LLM call's context; the stored content is the user's text).
- No content in logs or errors: nothing is logged here, and no error carries
  a title, message, file name, session id or chat id. The driver's errors (which quote
  the failing row) propagate untouched and must never be logged by text.
- Parameterized SQL only: every statement is a constant, every value a bind
  parameter. Imports nothing from the server, agent, LLM, tools or OAuth
  layers, nor ``admino.attachments`` (which imports this module).
"""

from __future__ import annotations

import base64
import contextlib
import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal, Protocol
from uuid import UUID

import asyncpg
from pydantic import AfterValidator, AwareDatetime, ConfigDict, Field, StrictInt

from admino import audit_events, untrusted
from admino.access import PlainUUID, SealedModel
from admino.audit_events import AuditAction, TargetType
from admino.models import AttachmentKind, LLMMessage
from admino.models import MessageStatus as MessageStatus
from admino.models import TitleSource as TitleSource

if TYPE_CHECKING:
    from collections.abc import Sequence

    from admino.models import ToolCallRecord
    from admino.tenancy import TenantContext

_NUL: Final = "\x00"
# A surrogate code point not paired with its other half: PostgreSQL's JSONB refuses it.
_LONE_SURROGATE_RE: Final = re.compile(
    "[\\ud800-\\udbff](?![\\udc00-\\udfff])|(?<![\\ud800-\\udbff])[\\udc00-\\udfff]"
)
_REPLACEMENT_CHARACTER: Final = chr(0xFFFD)
# The largest seq a BIGINT column (and its bind parameter) holds.
_MAX_SEQ: Final = 2**63 - 1
# What a cursor may look like before it is decoded: base64url, at most 200 characters.
_CURSOR_RE: Final = re.compile(r"[A-Za-z0-9_-]{1,200}")
# The partial unique key (migration 0024) a concurrent first legacy message loses on.
_LEGACY_SESSION_KEY: Final = "chats_legacy_session_key"

# S1: a new chat of the caller (a legacy session id only for the legacy route).
_CREATE_SQL: Final = """
    INSERT INTO chats (org_id, owner_user_id, title, title_source, legacy_session_id)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
"""
# S1L: a legacy session's chat with the server-generated id (GH-266: the server holds the
# chat's runtime entry before the chat exists); the title and its source are the defaults.
_CREATE_LEGACY_SQL: Final = """
    INSERT INTO chats (id, org_id, owner_user_id, legacy_session_id)
    VALUES ($1, $2, $3, $4)
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
# A10 (GH-187): the trashed chat's live attachments go to the trash with it; their files
# stay on disk until #194's purge. Bound to the chat S6 just trashed and the caller's org.
_TRASH_ATTACHMENTS_SQL: Final = """
    UPDATE attachments SET deleted_at = now()
    WHERE chat_id = $1 AND org_id = $2 AND deleted_at IS NULL
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
    RETURNING id
"""
# S8' (GH-189, migration 0029): an assistant message of a run whose slot 4 held
# attachments, with the slot's ids (Decision 11).
_INSERT_INCLUDED_SQL: Final = """
    INSERT INTO chat_messages
        (chat_id, org_id, role, content, tool_use_blocks, tool_call_id, tool_calls, status,
         included_attachment_ids)
    VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8, $9::uuid[])
    RETURNING id
"""
# A9 (GH-187): the caller's unsent, live attachments of this chat go with the user message
# that carried them. An id that no longer matches (another chat's, another owner's or org's,
# trashed, already sent, unknown) is simply not linked: the send route checked them (A8)
# before the run, and anything that changed since must not fail the stored turn.
_LINK_ATTACHMENTS_SQL: Final = """
    UPDATE attachments SET message_id = $1, updated_at = now()
    WHERE id = ANY($2::uuid[]) AND chat_id = $3 AND org_id = $4 AND owner_user_id = $5
        AND message_id IS NULL AND deleted_at IS NULL
"""
# S9' (GH-190, Decision 12): a chat's latest messages (newest first), each with the ids of
# the live attachments linked to it (excluded ones too, as they stay listed) ...
_LATEST_MESSAGES_SQL: Final = """
    SELECT m.id, m.seq, m.role, m.content, m.tool_use_blocks, m.tool_call_id, m.tool_calls,
           m.status, m.created_at,
           ARRAY(
               SELECT a.id FROM attachments a
               WHERE a.message_id = m.id AND a.org_id = m.org_id AND a.deleted_at IS NULL
               ORDER BY a.created_at, a.id
           ) AS attachment_ids
    FROM chat_messages m
    WHERE m.chat_id = $1 AND m.org_id = $2
    ORDER BY m.seq DESC
    LIMIT $3
"""
# ... and S11', those before a cursor's seq.
_MESSAGES_BEFORE_SQL: Final = """
    SELECT m.id, m.seq, m.role, m.content, m.tool_use_blocks, m.tool_call_id, m.tool_calls,
           m.status, m.created_at,
           ARRAY(
               SELECT a.id FROM attachments a
               WHERE a.message_id = m.id AND a.org_id = m.org_id AND a.deleted_at IS NULL
               ORDER BY a.created_at, a.id
           ) AS attachment_ids
    FROM chat_messages m
    WHERE m.chat_id = $1 AND m.org_id = $2 AND m.seq < $3
    ORDER BY m.seq DESC
    LIMIT $4
"""
# S15: the status of a chat's latest message, without the rest of its row.
_LATEST_STATUS_SQL: Final = """
    SELECT status FROM chat_messages
    WHERE chat_id = $1 AND org_id = $2
    ORDER BY seq DESC
    LIMIT 1
"""
# S12a: GH-66's promotion notice first locks the org's live chats, in id order. A turn
# storing its messages holds its chat's row (S7's UPDATE) until it commits, so the lock
# waits for it and S12b then sees that turn's messages (GH-24). User deletions
# (org_users, invitations) and the org purge lock the chats they cascade over in the
# same id order before the users rows go, the purge also before the org row that
# S12b's insert key-share locks, so none of them deadlocks with the notice (GH-265).
_ORG_NOTICE_LOCK_SQL: Final = """
    SELECT id FROM chats
    WHERE org_id = $1 AND deleted_at IS NULL
    ORDER BY id
    FOR UPDATE
"""
# S12b: the notice in every live chat of the org whose latest message isn't awaiting a
# confirmation: a user message there would split the pending call's tool_use from its
# result and malform the history the next run gets (GH-24).
_ORG_NOTICE_SQL: Final = """
    INSERT INTO chat_messages (chat_id, org_id, role, content, status)
    SELECT c.id, c.org_id, 'user', $2, 'complete' FROM chats c
    WHERE c.org_id = $1 AND c.deleted_at IS NULL
        AND (SELECT m.status FROM chat_messages m
             WHERE m.chat_id = c.id AND m.org_id = c.org_id
             ORDER BY m.seq DESC LIMIT 1) IS DISTINCT FROM 'awaiting_confirmation'
"""
# S13
_COUNT_ORG_CHATS_SQL: Final = "SELECT count(*) FROM chats WHERE org_id = $1 AND deleted_at IS NULL"
# S14: #179's automatic title as a compare-and-set: only a still untitled chat
# whose title the user never set, so a rename (S5) always wins, also one that
# lands while the title is being generated. last_activity_at is left alone.
_SET_AUTO_TITLE_SQL: Final = """
    UPDATE chats SET title = $4
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
        AND title_source = 'auto' AND title = ''
    RETURNING id
"""
# S16 (GH-244): the caller's live chat with its latest messages (newest first) in ONE
# statement, because the send path may make at most 3 statements before its LLM call; it
# stands in for get_chat (S2) plus a message read. The window is counted per chat
# (LATERAL) and the owner filters sit on the chat, so no row means not found, and a chat
# without messages gives one row with NULL message columns.
# T2' (GH-189, Decision 13): the same statement also returns the chat's active
# attachments (sent with one of its messages, live, ready) on every row, as text arrays
# in the order they were sent (Decision 3: the carrying message's seq, then upload
# order). They don't depend on the message window, and the attachment filters repeat
# the chat's org and owner.
# T2'' (GH-190, Decisions 10 and 14): an excluded file (active false, migration 0030) is
# not active, and each array also carries the stored token_estimate and derived_bytes
# ([id, filename, kind, page_count, token_estimate, derived_bytes]), so the send path
# checks the budget and the byte cap without another statement.
_TURN_SQL: Final = """
    SELECT c.id, c.org_id, c.owner_user_id, c.title, c.title_source, c.external_content,
           c.created_at, c.last_activity_at,
           ARRAY(
               SELECT ARRAY[a.id::text, a.filename, a.kind, a.page_count::text,
                            a.token_estimate::text, a.derived_bytes::text]
               FROM attachments a
               JOIN chat_messages am ON am.id = a.message_id AND am.org_id = a.org_id
               WHERE a.chat_id = c.id AND a.org_id = c.org_id
                 AND a.owner_user_id = c.owner_user_id
                 AND a.status = 'ready' AND a.active AND a.deleted_at IS NULL
               ORDER BY am.seq, a.created_at, a.id
           ) AS attachment_rows,
           m.role, m.content, m.tool_use_blocks, m.tool_call_id
    FROM chats c
    LEFT JOIN LATERAL (
        SELECT seq, role, content, tool_use_blocks, tool_call_id
        FROM chat_messages
        WHERE chat_id = c.id AND org_id = c.org_id
        ORDER BY seq DESC
        LIMIT $4
    ) m ON true
    WHERE c.id = $1 AND c.org_id = $2 AND c.owner_user_id = $3 AND c.deleted_at IS NULL
    ORDER BY m.seq DESC
"""


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
    # GH-190 (Decision 12): the live attachments linked to the message, active or not, by
    # created_at then id (S9' / S11').
    attachment_ids: list[PlainUUID] = Field(default_factory=list)


class ChatPage(SealedModel):
    """One page of the caller's chats; ``next_cursor`` is None on the last page."""

    chats: list[ChatRecord]
    next_cursor: str | None


class MessagePage(SealedModel):
    """One page of a chat's messages, chronological; ``next_cursor`` points to earlier ones."""

    messages: list[MessageRecord]
    next_cursor: str | None


class ChatDetail(SealedModel):
    """A chat of the caller with one page of its messages and its latest status."""

    chat: ChatRecord
    page: MessagePage
    # None for a chat without messages.
    latest_status: MessageStatus | None


class ActiveAttachment(SealedModel):
    """An active attachment of a chat: what slot 4 needs from its row (GH-189).

    ``filename`` is the stored name (``prompt_assembly.prompt_filename``
    makes the prompt name of it); ``page_count`` is None for a kind without
    pages. GH-190: ``token_estimate`` and ``derived_bytes`` are the stored
    values the budget and the byte cap are checked with (None for NULL).
    """

    # The stored name is user content: a validation error never repeats it.
    model_config = ConfigDict(hide_input_in_errors=True)

    id: PlainUUID
    filename: str
    kind: AttachmentKind
    page_count: int | None
    token_estimate: int | None = None
    derived_bytes: int | None = None


@dataclass(frozen=True)
class ChatTurn:
    """A chat of the caller, the agent's history of it and its active attachments.

    Read by one statement (S16, T2' since GH-189, T2'' since GH-190).
    ``attachments`` are the chat's sent, live, ``ready``, active files in the
    order they were sent: by the carrying message (oldest first), then
    ``created_at``, then ``id``.
    """

    chat: ChatRecord
    history: list[LLMMessage]
    attachments: tuple[ActiveAttachment, ...]


def _utc_representable(value: datetime) -> datetime:
    """The stamp unchanged if it has a UTC equivalent, which asyncpg binds.

    Raises:
        ValueError: If the conversion to UTC leaves the datetime range (year 1
            at +23:00, year 9999 at -23:00).
    """
    try:
        value.astimezone(UTC)
    except OverflowError:
        msg = "Timestamp outside the UTC range."
        raise ValueError(msg) from None
    return value


# A cursor's timestamp: aware and with a UTC equivalent, so asyncpg can bind it.
CursorStamp = Annotated[AwareDatetime, AfterValidator(_utc_representable)]


class _ChatCursor(SealedModel):
    """The position after the last chat of a list page."""

    kind: Literal["chats"] = "chats"
    last_activity_at: CursorStamp
    id: UUID


class _MessageCursor(SealedModel):
    """The seq of the earliest message of a message page."""

    kind: Literal["messages"] = "messages"
    seq: StrictInt = Field(ge=1, le=_MAX_SEQ)


def encode_cursor(cursor: SealedModel) -> str:
    """The opaque cursor string: unpadded base64url of the cursor's JSON.

    Shared with ``admino.attachments``' list cursor; each cursor model is
    tagged with its own ``kind``, so one list's cursor never decodes as
    another's.
    """
    return base64.urlsafe_b64encode(cursor.model_dump_json().encode()).rstrip(b"=").decode()


def decode_cursor[C: SealedModel](cursor: str, kind: type[C]) -> C:
    """Decode a cursor of one kind (at most 200 base64url characters).

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
def _jsonb_safe(value: Any) -> Any:
    """The JSON value with U+0000 removed and each lone surrogate replaced by U+FFFD in
    every string, object keys included (a surrogate pair, an emoji, is kept), and each
    non-finite number (NaN, an infinity) replaced by None, at any depth."""
    if isinstance(value, str):
        return _LONE_SURROGATE_RE.sub(_REPLACEMENT_CHARACTER, value.replace(_NUL, ""))
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, list | tuple):
        return [_jsonb_safe(item) for item in value]
    if isinstance(value, dict):
        return {_jsonb_safe(key): _jsonb_safe(item) for key, item in value.items()}
    return value


def _json_text(value: list[dict[str, Any]] | None) -> str | None:
    """The JSON text bound to a ``$n::jsonb`` parameter (``_jsonb_safe``), None for NULL.

    ``allow_nan=False`` is the fail-closed backstop: a non-finite number that
    ``_jsonb_safe`` missed raises ``ValueError`` instead of becoming ``NaN`` /
    ``Infinity`` text, which isn't JSON.
    """
    return None if value is None else json.dumps(_jsonb_safe(value), allow_nan=False)


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


def _int_or_none(text: str | None) -> int | None:
    """A T2'' array's number column (text there) as an int, None for NULL."""
    return None if text is None else int(text)


# Any: asyncpg returns untyped Records.
def _history(rows: Sequence[Any]) -> list[LLMMessage]:
    """The agent's history from a window of message rows read newest first.

    Returns:
        The messages in chronological order, their ``tool_use_blocks``
        decoded, without the leading ``tool`` results whose assistant turn
        fell outside the window.
    """
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
    executor: Executor, tenant: TenantContext, session_id: str, *, chat_id: UUID
) -> ChatRecord:
    """Return the caller's live chat of a legacy session id, creating it if needed.

    Runs without a transaction of its own (pass the pool): when a concurrent
    first message of the same session inserts the chat first, the INSERT
    fails on the partial unique key ``chats_legacy_session_key`` and the
    winner's chat is selected. That key's violation is the only one taken
    for the race.

    Args:
        executor: The pool.
        tenant: The caller's org scope.
        session_id: The validated legacy session id.
        chat_id: The id a chat created here gets (server-generated); unused
            when the session already has a live chat.

    Returns:
        The session's live chat with its own id, else the chat created here
        (``chat_id``, untitled, ``auto``), else the chat a concurrent first
        message of the session created meanwhile (another id).

    Raises:
        asyncpg.UniqueViolationError: When the INSERT violates any unique key
            but ``chats_legacy_session_key`` (e.g. ``chats_pkey``: ``chat_id``
            is an existing chat's, of any owner or org); the driver's own
            exception, unwrapped, and nothing is stored. It quotes the violated
            key's values (its DETAIL), so it must never be logged by text.
    """
    with contextlib.suppress(ChatNotFoundError):
        return await find_legacy_chat(executor, tenant, session_id)
    try:
        row = await executor.fetchrow(
            _CREATE_LEGACY_SQL, chat_id, tenant.org_id, tenant.user_id, session_id
        )
    except asyncpg.UniqueViolationError as exc:
        # Only the session key means a concurrent first message won; any other key (the
        # given id taken) is a fault and propagates. The race's error quotes the session
        # id: it is dropped, never logged.
        if exc.constraint_name != _LEGACY_SESSION_KEY:
            raise
        return await find_legacy_chat(executor, tenant, session_id)
    return _chat_record(row)


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
        after = decode_cursor(cursor, _ChatCursor)
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
        next_cursor = encode_cursor(_ChatCursor(last_activity_at=last.last_activity_at, id=last.id))
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


async def set_auto_title(
    executor: Executor, tenant: TenantContext, chat_id: UUID, title: str
) -> bool:
    """Store an automatic title on the caller's live, still untitled chat (S14).

    A compare-and-set in one statement: ``title_source`` stays ``auto`` and
    ``last_activity_at`` is untouched. No audit event (an automatic title
    isn't in the catalog) and no log line.

    Args:
        executor: The pool or a connection.
        tenant: The caller's org scope; the caller owns the chat.
        chat_id: The chat.
        title: An already sanitized title (1 to 80 characters).

    Returns:
        True when the title was stored. False, with nothing changed, for a
        chat the user titled, one already titled automatically, a trashed
        chat, another owner's or another org's chat and an unknown id (never
        ``ChatNotFoundError``).
    """
    stored = await executor.fetchval(
        _SET_AUTO_TITLE_SQL, chat_id, tenant.org_id, tenant.user_id, title
    )
    return stored is not None


async def trash_chat(
    pool: asyncpg.Pool, tenant: TenantContext, chat_id: UUID, *, ip: str | None
) -> None:
    """Move the caller's chat and its attachments to the trash and record ``chat.delete``.

    One transaction: the chat's ``deleted_at``, then the same stamp on each of
    its attachments that isn't trashed yet (GH-187, A10; one trashed earlier
    keeps its stamp), then the audit event. The attachments' files stay on
    disk (#194 restores and purges).

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        chat_id: The chat.
        ip: The client IP, for the audit event.

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed;
            nothing is written.
        AuditRecordError: If the event can't be recorded; the chat and its
            attachments are rolled back.
    """
    async with pool.acquire() as conn, conn.transaction():
        trashed = await conn.fetchval(_TRASH_SQL, chat_id, tenant.org_id, tenant.user_id)
        if trashed is None:
            raise ChatNotFoundError
        await conn.execute(_TRASH_ATTACHMENTS_SQL, chat_id, tenant.org_id)
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
    attachment_ids: Sequence[UUID] = (),
    included_attachment_ids: Sequence[UUID] = (),
    external_content: bool = False,
) -> UUID | None:
    """Append a run's new messages to the caller's chat, in one transaction.

    Every message is stored ``complete`` without tool calls except the last,
    which gets ``final_status`` and the run's tool calls (NULL when there are
    none). The chat's ``last_activity_at`` is bumped, and ``external_content``
    is set (for good) when an appended ``tool`` message holds wrapped external
    content or the caller says the run received some (GH-189: a run whose
    slot 4 held attachments). U+0000 is removed from the content and the
    JSON values; in the JSON values (a model's tool input or the tool-call
    arguments) each lone
    surrogate is stored as U+FFFD and each non-finite number (NaN, an
    infinity, an overflowing literal as parsed) as null, at any depth.

    With ``attachment_ids`` (GH-187), right after the turn's first ``user``
    message is inserted, the caller's unsent, live attachments of this chat
    among them are linked to it (A9), in the same transaction. That message
    isn't always the turn's first: a turn sent while a ``tool_use`` dangled
    stores its synthetic cancelled result before it. An id that no longer
    matches (deleted, trashed or sent meanwhile, another chat's, owner's or
    org's) is left as it is, without an error.

    With ``included_attachment_ids`` (GH-189, Decision 11), every
    ``assistant`` message is stored with those ids, in the given order (S8');
    every other message keeps NULL.

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        chat_id: The chat.
        messages: The new user, assistant and tool messages, in order; an
            empty sequence without attachments runs no statement.
        final_status: The stored status of the run's last message.
        tool_calls: The run's tool-call summaries, stored on the last message.
        attachment_ids: The attachments the user message carried (checked by
            the caller with ``attachments.check_sendable``); empty, the
            default, adds no statement.
        included_attachment_ids: The ids of the run's slot 4, in slot order;
            empty, the default, stores every message as before (S8).
        external_content: True when the run received external content its
            tool results don't show (its slot 4 held attachments): the chat's
            sticky flag is set like for a wrapped tool result.

    Returns:
        The id of the last appended message (GH-8: a streamed turn's
        ``message_saved`` names it); None for an empty sequence.

    Raises:
        ValueError: If a ``system`` message is passed, a message whose
            content is a list of content parts (never stored), or attachments
            without a ``user`` message to carry them; nothing is written.
        ChatNotFoundError: Unless the chat is the caller's and not trashed;
            nothing is written.
    """
    # The index of the message the attachments go with; None links nothing.
    carrier: int | None = None
    if attachment_ids:
        carrier = next(
            (index for index, message in enumerate(messages) if message.role == "user"), None
        )
        if carrier is None:
            msg = "Attachments need a user message to carry them."
            raise ValueError(msg)
    if not messages:
        return None
    if any(message.role == "system" for message in messages):
        msg = "System messages are never stored."
        raise ValueError(msg)
    # Content parts exist only in one LLM call's context (Decision 1): the stored
    # content is the user's text.
    texts = [message.content for message in messages if isinstance(message.content, str)]
    if len(texts) != len(messages):
        msg = "Content parts are never stored."
        raise ValueError(msg)
    last = len(messages) - 1
    # Python mode: the JSON mode mangles a lone surrogate in a key (or raises for a nested
    # one) before _json_text could replace it. Every ToolCallRecord field is JSON-native.
    calls = [record.model_dump() for record in tool_calls or ()]
    rows = [
        (
            message.role,
            text.replace(_NUL, ""),
            _json_text(message.tool_use_blocks),
            message.tool_call_id,
            _json_text(calls) if index == last and calls else None,
            final_status if index == last else "complete",
        )
        for index, (message, text) in enumerate(zip(messages, texts, strict=True))
    ]
    external = external_content or any(
        role == "tool" and untrusted.contains_wrapped(text) for role, text, *_ in rows
    )
    included = list(included_attachment_ids)
    async with pool.acquire() as conn, conn.transaction():
        touched = await conn.fetchval(
            _TOUCH_EXTERNAL_SQL if external else _TOUCH_SQL,
            chat_id,
            tenant.org_id,
            tenant.user_id,
        )
        if touched is None:
            raise ChatNotFoundError
        message_id: UUID | None = None
        for index, (role, content, blocks, call_id, stored_calls, status) in enumerate(rows):
            values = (chat_id, tenant.org_id, role, content, blocks, call_id, stored_calls, status)
            if included and role == "assistant":
                message_id = await conn.fetchval(_INSERT_INCLUDED_SQL, *values, included)
            else:
                message_id = await conn.fetchval(_INSERT_MESSAGE_SQL, *values)
            if index == carrier:
                await conn.execute(
                    _LINK_ATTACHMENTS_SQL,
                    message_id,
                    list(attachment_ids),
                    chat_id,
                    tenant.org_id,
                    tenant.user_id,
                )
    return message_id


async def load_turn(
    executor: Executor, tenant: TenantContext, chat_id: UUID, *, limit: int
) -> ChatTurn:
    """Return the caller's live chat and its latest messages as the agent's history (S16).

    One statement (T2''): the send path runs it under the chat's run lock as
    its last statement before the LLM call (GH-244).

    Args:
        executor: The pool or a connection.
        tenant: The caller's org scope.
        chat_id: The chat.
        limit: How many of the latest messages to load (the context window).

    Returns:
        The ``ChatTurn``: the chat as ``get_chat`` returns it, the latest
        ``limit`` messages as the agent's history (chronological, without the
        leading ``tool`` results whose assistant turn fell outside the
        window) and the chat's active attachments (GH-189, T2'': sent with one
        of its messages, live, ``ready``, not excluded, in the order they were
        sent, whatever the window, with their stored ``token_estimate`` and
        ``derived_bytes``; ``()`` for none).

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed.
    """
    rows = await executor.fetch(_TURN_SQL, chat_id, tenant.org_id, tenant.user_id, limit)
    if not rows:
        raise ChatNotFoundError
    chat = _chat_record({column: rows[0][column] for column in ChatRecord.model_fields})
    # A chat without messages gives one row whose message columns are NULL (role is NOT NULL).
    messages = [row for row in rows if row["role"] is not None]
    # Every row carries the same array; its numbers are text (NULL for none).
    attachments = tuple(
        ActiveAttachment(
            id=UUID(attachment_id),
            filename=filename,
            kind=kind,
            page_count=_int_or_none(page_count),
            token_estimate=_int_or_none(token_estimate),
            derived_bytes=_int_or_none(derived_bytes),
        )
        for (
            attachment_id,
            filename,
            kind,
            page_count,
            token_estimate,
            derived_bytes,
        ) in rows[0]["attachment_rows"]
    )
    return ChatTurn(chat=chat, history=_history(messages), attachments=attachments)


async def read_chat_detail(
    executor: Executor, tenant: TenantContext, chat_id: UUID, *, limit: int, cursor: str | None
) -> ChatDetail:
    """Return the caller's chat with one page of its messages and its latest status.

    The owner check (S2) runs once and first: a chat the caller can't reach
    runs nothing else, and the cursor is decoded only after it. The page
    (S9' or S11', each message with its ``attachment_ids``) and the latest
    status (S15, its ``status`` column only) bind the checked chat and the
    caller's org. GH-190 (Decision 13): the messages are no longer counted.

    Args:
        executor: The pool or a connection.
        tenant: The caller's org scope.
        chat_id: The chat.
        limit: The page size (at least 1).
        cursor: The previous page's ``next_cursor``, or None for the latest page.

    Returns:
        The chat; up to ``limit`` messages before the cursor, in
        chronological order, each with the ids of its live attachments
        (excluded ones too), with the cursor of the earlier messages (None
        at the beginning); the status of its latest message (highest seq;
        None without messages).

    Raises:
        ChatNotFoundError: Unless the chat is the caller's and not trashed.
        InvalidCursorError: If the cursor isn't a message cursor.
    """
    chat = await get_chat(executor, tenant, chat_id)
    if cursor is None:
        rows = await executor.fetch(_LATEST_MESSAGES_SQL, chat_id, tenant.org_id, limit + 1)
    else:
        before = decode_cursor(cursor, _MessageCursor)
        rows = await executor.fetch(
            _MESSAGES_BEFORE_SQL, chat_id, tenant.org_id, before.seq, limit + 1
        )
    messages = [_message_record(row) for row in reversed(rows[:limit])]
    next_cursor = None
    if len(rows) > limit:
        next_cursor = encode_cursor(_MessageCursor(seq=messages[0].seq))
    latest_status: MessageStatus | None = await executor.fetchval(
        _LATEST_STATUS_SQL, chat_id, tenant.org_id
    )
    return ChatDetail(
        chat=chat,
        page=MessagePage(messages=messages, next_cursor=next_cursor),
        latest_status=latest_status,
    )


async def append_org_notice(pool: asyncpg.Pool, tenant: TenantContext, content: str) -> int:
    """Append GH-66's promotion notice to every live chat of the caller's org.

    One ``user`` message, status ``complete``, in every member's live chat of
    ``tenant.org_id`` (never another org's) except a chat whose latest message
    awaits a confirmation (GH-24); the chats' ``last_activity_at`` is left
    alone. One transaction on one acquired connection: the org's live chats
    are locked first (waiting for a turn that is storing its messages), then
    the notice is inserted. User deletions and the org purge lock the chats
    in the same id order, so they don't deadlock with it (GH-265).

    Args:
        pool: The database pool.
        tenant: The caller's org scope.
        content: The notice text.

    Returns:
        The number of chats the notice was appended to.
    """
    async with pool.acquire() as conn, conn.transaction():
        await conn.fetch(_ORG_NOTICE_LOCK_SQL, tenant.org_id)
        status: str = await conn.execute(_ORG_NOTICE_SQL, tenant.org_id, content)
    # The command tag is "INSERT 0 <rows>".
    return int(status.rsplit(" ", 1)[1])


async def count_org_chats(executor: Executor, org_id: UUID) -> int:
    """Return how many chats of an org aren't trashed (platform metadata; a count only)."""
    return int(await executor.fetchval(_COUNT_ORG_CHATS_SQL, org_id))
