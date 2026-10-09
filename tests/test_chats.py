"""Tests for admino.chats: persisted, owner-private chats and their messages (GH-176).

The real ``admino.chats`` repository runs against the in-memory ``chats`` and
``chat_messages`` tables of tests/db_fakes.py (migration 0024: defaults, the
identity ``seq``, the CHECKs, the composite (chat_id, org_id) foreign key, the
partial unique legacy session index, PostgreSQL's U+0000 refusal, JSONB as JSON
text, the cascades from users). The fake applies only the predicates a
statement states, so a query without its owner, org or ``deleted_at IS NULL``
filter returns rows it must not.

What these tests pin down (contract §2; GH-266 contract §2):
- Surface: the thirteen coroutine functions with the contract's keyword-only
  parameters (``get_or_create_legacy_chat``'s ``chat_id`` required, no
  default; GH-187: ``append_messages`` takes ``attachment_ids``, specified in
  tests/test_chats_attachments.py; GH-189 (contract C4): also
  ``included_attachment_ids`` and ``external_content``, specified in
  tests/test_chats_turn_attachments.py); ``list_messages`` and
  ``latest_message_status`` no longer exist (GH-266: their only caller was the
  detail route); ``ChatNotFoundError`` is a
  ``LookupError``, ``InvalidCursorError`` a ``ValueError``; ``ChatRecord`` /
  ``MessageRecord`` / ``ChatDetail`` carry exactly the contract's fields and
  are frozen; every ``json.dumps`` in the module passes ``allow_nan=False``
  (GH-266's fail-closed backstop).
- Tenant isolation (owner-private V1): for every function that takes a chat id
  (get, rename, trash, append, load history, read the chat detail, count),
  another org's chat, another user's chat in the same org, a trashed
  chat and an unknown id raise the same ``ChatNotFoundError`` (same type, same
  text, no id or title in it) and change nothing (no INSERT, the whole state
  unchanged). Every chat-table statement binds the caller's org id, every
  statement filtering ``chats`` binds the caller's user id as the owner and
  states ``deleted_at IS NULL`` (the org notice and the platform count are
  org-wide: org and ``deleted_at`` only); no statement binds another org's or
  another user's id. Lists, the org notice and the org count never include
  another org's chats; another user's cursor shows only the caller's chats.
- ``create_chat``: no title is ``''`` + ``'auto'``, a title is that title +
  ``'user'``; the returned record is the stored row, org and owner the caller's.
- Legacy session chats: created once per (user, session id) and reused; per
  user (two users, same session id, two chats); a trashed one is replaced;
  ``find_legacy_chat`` never creates; a concurrent first insert
  (UniqueViolationError) is answered by selecting again; other insert errors
  propagate. GH-266: a chat created here gets exactly the given ``chat_id``
  (the INSERT binds it with the caller's org, the caller as owner and the
  session id; untitled, ``auto``); an existing live chat of the session is
  returned with its own id and no INSERT runs; after a concurrent first
  insert the winner's chat (not the given id) is returned and exactly one
  chat exists; a trashed chat's session gets a new chat with the given id.
  GH-271: only a violation of ``chats_legacy_session_key`` is that race (one
  more lookup, the winner's chat); a ``chats_pkey`` collision of the given id
  with any existing chat (the caller's own, trashed, a colleague's, another
  org's) and a unique violation naming another constraint or none propagate
  as the driver raised them: nothing stored, the colliding chat unchanged and
  never returned, no statement after the INSERT.
- ``list_chats``: the caller's live chats by ``last_activity_at DESC, id DESC``
  (ties by id), at most ``limit``, ``next_cursor`` None on the last page
  (exactly ``limit`` left included), walking the cursors returns every live
  chat exactly once in order (microsecond-apart stamps and ties across a page
  boundary); cursors are strings of at most 200 characters; garbage, a
  truncated cursor and a message cursor are ``InvalidCursorError``. So is a
  crafted cursor that decodes but can't be bound (security audit L-1): a
  ``last_activity_at`` whose offset puts it outside the datetime range in
  UTC (year 1 at +23:00, year 9999 at -23:00); it is refused before any
  statement binds it.
- ``rename_chat``: title + ``'user'``, ``last_activity_at`` unchanged,
  idempotent.
- ``trash_chat``: ``deleted_at`` set and exactly one ``chat.delete`` audit row
  (member actor, org, target chat, the IP, no metadata) in the same transaction
  on the same connection; a failed audit write raises ``AuditRecordError`` and
  nothing changes; trashing twice is ``ChatNotFoundError``; a trashed chat is
  invisible to get, list and the message reads.
- ``append_messages``: one transaction, the chat UPDATE first then one INSERT
  per message in order (seq order = list order); only the last message gets
  ``final_status`` and the dumped tool calls (empty or None: NULL), the others
  ``complete`` / NULL; ``tool_use_blocks`` and ``tool_call_id`` round-trip;
  ``last_activity_at`` bumped; ``external_content`` set (sticky) only by a
  ``tool`` message holding ``untrusted.wrap(...)`` output, never by a user or
  assistant message with a marker-looking text; U+0000 removed from content and
  from every string (keys included) inside the JSON values; a lone surrogate
  (U+D800 to U+DFFF, which model-produced tool inputs and tool-call arguments
  can carry and PostgreSQL's JSONB refuses) in any of those strings is stored
  as U+FFFD, so the turn is persisted (security audit L-2), while an emoji
  (what an escaped surrogate pair decodes to) is kept. GH-266 (re-audit
  L-4): a non-finite number (``NaN``, ``Infinity``, ``-Infinity``, an
  overflowing literal such as ``1e400`` as ``json.loads`` parses it) in
  ``tool_use_blocks`` or the tool calls, at the top level of the arguments or
  nested at any depth, is stored as null and the turn is persisted; finite
  numbers, ints, bools, null and look-alike strings ("NaN") are kept; the JSON
  text the driver gets is strict JSON. A ``system`` message is a
  ``ValueError`` with nothing written; an empty list runs no statement; a
  failure midway rolls everything back.
- ``load_recent_history``: the latest ``limit`` messages in chronological order
  as ``LLMMessage``s equal to what was appended (the tool turn's pairing kept),
  leading orphan ``tool`` messages of the tail dropped.
- ``read_chat_detail`` (GH-266, replaces ``list_messages`` and
  ``latest_message_status``): the caller's chat, one page of its messages (the
  latest page ascending, ``next_cursor`` to earlier messages, None at the
  beginning; walking returns every message once in order; bad and list cursors
  are ``InvalidCursorError``, and so is a crafted cursor whose seq a BIGINT
  can't hold (2**63, 10**40) or that is negative, refused before any statement
  binds it (security audit L-1)), the chat's message count and its latest
  message's status (highest seq; None when empty), the same on every page.
  The owner-checked lookup (S2) runs exactly once and first; a not-found chat
  (with or without a bad cursor) and an invalid cursor run S2 only; the
  status read selects only ``status`` (no statement but the page selects
  ``content``).
- ``append_org_notice`` (one user/complete message, the
  text verbatim, in every live chat of the org, of every member; none in
  another org's or a trashed chat; ``last_activity_at`` unchanged; returns the
  count) and ``count_org_chats`` (the org's live chats).
- GH-24 (contract §2, the GH-66 notice never breaks a chat awaiting a
  confirmation): ``append_org_notice(pool, tenant, content)`` skips every chat
  whose latest message (highest seq) is ``awaiting_confirmation``, whether that
  row is the assistant's ``tool_use`` or a ``tool`` row of a batch, and leaves
  it exactly as stored; a chat whose awaiting message was followed by anything
  (an approved call's result, a denial, a new turn), a chat without messages,
  the caller's other chats and colleagues' chats get the notice after their
  history; only the latest message's status decides (an earlier awaiting one
  doesn't count). The count excludes skipped chats. It runs exactly two
  statements on one connection acquired from the pool, inside one committed
  transaction: first the lock ``SELECT id FROM chats WHERE org_id = $1 AND
  deleted_at IS NULL ORDER BY id FOR UPDATE`` (binds the org only), then the
  INSERT (binds the org and the text, never a chat or user id); a turn that
  commits while the lock waits is seen by the INSERT (its chat is skipped); a
  failing INSERT propagates, rolls the transaction back and stores nothing.
- Deleting a users row removes that user's chats and messages (CASCADE); other
  users' chats stay.
- Hygiene: a module docstring with security notes; nothing imported from
  server, agent, llm*, tools or oauth; only constant SQL reaches the driver (no
  f-string, %-formatting, concatenation or ``.format`` building SQL); no title,
  content or legacy session id in any log line, also on the error paths where
  the driver's error text carries the row.

No real PostgreSQL, no network: every statement goes to ``FakeDb``.

Security notes:
- Owner-private chats: an Org Admin, a colleague and another org all get the
  answer of an unknown id; the isolation lives in the SQL, not in Python.
- Untrusted content: the sticky ``external_content`` flag can't be forged by a
  user typing a marker.
- No content in logs or errors: titles, messages and session ids never reach a
  log line or an exception text from this module.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import dataclasses
import inspect
import json
import math
import re
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import asyncpg
import pytest
from pydantic import BaseModel

from admino import untrusted
from admino.access import Principal
from admino.audit_events import AuditRecordError
from admino.models import LLMMessage, ToolCallRecord
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, ORG_ID_PARAM_RE, OTHER_ORG_ID, Call, FakeDb, norm, plain
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP: Final = "203.0.113.9"
_SESSION: Final = "legacy-sess_01"
_UNKNOWN_CHAT: Final = uuid.UUID("7c9e6679-7425-40de-944b-e07fc1f90ae7")
_VICTIM_TITLE: Final = "Victim payroll plans"
_PAST: Final = datetime(2026, 9, 1, 8, 0, 0, 250000, tzinfo=UTC)
# Stamps one microsecond apart: a cursor that loses precision skips or repeats chats.
_STAMP: Final = datetime(2026, 9, 10, 12, 0, 0, 123456, tzinfo=UTC)
_US: Final = timedelta(microseconds=1)

_STATUSES: Final = ("complete", "stopped", "error", "awaiting_confirmation", "limit_reached")
_NOT_FOUND_CASES: Final = ("other-org", "other-user", "trashed", "unknown")
# GH-271: whose existing chat the id given to a legacy insert collides with.
_COLLISIONS: Final = ("own-chat", "own-trashed", "colleague", "other-org")
# GH-271: the only unique key whose violation means "a concurrent first message won".
_LEGACY_SESSION_KEY: Final = "chats_legacy_session_key"
_CHAT_ID_FUNCTIONS: Final = (
    "get_chat",
    "rename_chat",
    "trash_chat",
    "append_messages",
    "load_recent_history",
    "read_chat_detail",
)
_ALL_FUNCTIONS: Final = (
    *_CHAT_ID_FUNCTIONS,
    "create_chat",
    "get_or_create_legacy_chat",
    "find_legacy_chat",
    "list_chats",
    "append_org_notice",
    "count_org_chats",
)
# Positional parameter count and keyword-only parameter names (contract §2).
_SIGNATURES: Final[dict[str, tuple[int, set[str]]]] = {
    "create_chat": (2, {"title"}),
    "get_chat": (3, set()),
    "get_or_create_legacy_chat": (3, {"chat_id"}),
    "find_legacy_chat": (3, set()),
    "list_chats": (2, {"limit", "cursor"}),
    "rename_chat": (4, set()),
    "trash_chat": (3, {"ip"}),
    # GH-189 (contract C4): the answers' included attachment ids and the sticky flag.
    "append_messages": (
        4,
        {
            "final_status",
            "tool_calls",
            "attachment_ids",
            "included_attachment_ids",
            "external_content",
        },
    ),
    "load_recent_history": (3, {"limit"}),
    "read_chat_detail": (3, {"limit", "cursor"}),
    "append_org_notice": (3, set()),
    "count_org_chats": (2, set()),
}
_CHAT_RECORD_FIELDS: Final = {
    "id",
    "org_id",
    "owner_user_id",
    "title",
    "title_source",
    "external_content",
    "created_at",
    "last_activity_at",
}
_CHAT_DETAIL_FIELDS: Final = {"chat", "page", "message_count", "latest_status"}
_MESSAGE_RECORD_FIELDS: Final = {
    "id",
    "seq",
    "role",
    "content",
    "tool_use_blocks",
    "tool_call_id",
    "tool_calls",
    "status",
    "created_at",
}
_GARBAGE_CURSORS: Final = (
    "not-a-cursor",
    "%%%",
    "e30",  # base64url of {}
    "W10",  # base64url of []
    "bnVsbA",  # base64url of null
    "eyJ4IjoxfQ",  # base64url of {"x":1}
    "AAAA",
    chr(0xFC),
    "x" * 201,
)

_CHAT_TABLE_RE: Final = re.compile(r"\b(?:chats|chat_messages)\b")
# A statement that filters chats rows: a SELECT from chats (the notice's INSERT ...
# SELECT included) or an UPDATE of chats.
_CHATS_FILTER_RE: Final = re.compile(r"\bfrom chats\b|^update chats\b")
_OWNER_PARAM_RE: Final = r"(?<![\w])(?:\w+\.)?owner_user_id = \$(\d+)"
_DB_METHODS: Final = frozenset({"execute", "executemany", "fetch", "fetchrow", "fetchval"})
_SQL_KEYWORD_RE: Final = re.compile(
    r"\b(?:select\b.*\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|where"
    r"|from\s+(?:chats|chat_messages)\b)",
    re.IGNORECASE | re.DOTALL,
)

_MARK_TITLE: Final = "Zebrafinch merger plan"
_MARK_CONTENT: Final = "Quokka-salary-figures"
_MARK_NOTICE: Final = "Narwhal promotion notice"
_MARK_SESSION: Final = "sessmarker4711"
_MARK_RACE_SESSION: Final = "racemarker0815"

# Security audit L-2: lone surrogates (PostgreSQL's JSONB refuses them) and their stand-in.
_HIGH: Final = chr(0xD800)
_LOW: Final = chr(0xDFFF)
_REPLACEMENT: Final = chr(0xFFFD)

# GH-266 (re-audit L-4): the non-finite numbers a model's tool arguments carry once
# json.loads parsed them (an overflowing literal such as 1e400 parses as inf). JSON and
# PostgreSQL's JSONB have none of them.
_NON_FINITE: Final = {
    "nan": float("nan"),
    "infinity": float("inf"),
    "minus-infinity": float("-inf"),
    "1e400": json.loads("1e400"),
}
# A provider's tool arguments as JSON text with every non-finite form, at the top level and
# nested, between finite numbers, ints, bools, null and strings that only look like them ...
_PROVIDER_ARGS_TEXT: Final = (
    '{"query": "NaN Infinity", "limit": 1e400, "score": NaN, "floor": -Infinity,'
    ' "ceiling": Infinity, "ratio": 0.5, "big": 1e300, "max": 1.7976931348623157e308,'
    ' "count": 7, "under": -1e400,'
    ' "flags": [true, false, null, "Infinity", "-Infinity", "NaN", "1e400", 0, -3],'
    ' "nested": {"a": [[NaN, 2.25], {"b": {"c": [Infinity, -0.5, 1e400, "x"]}}]}}'
)
# ... and what is stored: every non-finite number as null, everything else unchanged.
_PROVIDER_ARGS_STORED: Final = {
    "query": "NaN Infinity",
    "limit": None,
    "score": None,
    "floor": None,
    "ceiling": None,
    "ratio": 0.5,
    "big": 1e300,
    "max": 1.7976931348623157e308,
    "count": 7,
    "under": None,
    "flags": [True, False, None, "Infinity", "-Infinity", "NaN", "1e400", 0, -3],
    "nested": {"a": [[None, 2.25], {"b": {"c": [None, -0.5, None, "x"]}}]},
}


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def chats() -> ModuleType:
    """admino.chats, imported per test so each test fails on its own until it exists."""
    from admino import chats as module

    return module


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


@dataclass(frozen=True)
class _Member:
    """A stored member and the TenantContext of their session."""

    user_id: uuid.UUID
    tenant: TenantContext


def _member(db: FakeDb, *, org_id: uuid.UUID = ORG_ID, role: str = "editor") -> _Member:
    user_id = db.add_account(org_id=org_id, role=role)
    principal = Principal(user_id=user_id, kind="member", org_id=org_id, role=role)
    return _Member(user_id, TenantContext.from_principal(principal))


@dataclass(frozen=True)
class _World:
    """Alice and Bob (ORG_ID), Carol (OTHER_ORG_ID); each chat holds two messages."""

    alice: _Member
    bob: _Member
    carol: _Member
    chat: uuid.UUID  # Alice's live chat
    bob_chat: uuid.UUID
    carol_chat: uuid.UUID
    trashed: uuid.UUID  # Alice's trashed chat


def _world(db: FakeDb) -> _World:
    alice, bob, carol = _member(db), _member(db), _member(db, org_id=OTHER_ORG_ID)
    chat = db.add_chat(alice.user_id, title="Alice plans", created_at=_PAST)
    bob_chat = db.add_chat(bob.user_id, title=_VICTIM_TITLE, created_at=_PAST)
    carol_chat = db.add_chat(carol.user_id, title=_VICTIM_TITLE, created_at=_PAST)
    trashed = db.add_chat(
        alice.user_id, title="Old plans", created_at=_PAST, deleted_at=_PAST + timedelta(days=1)
    )
    for chat_id in (chat, bob_chat, carol_chat, trashed):
        db.add_chat_message(chat_id, "user", "Hello")
        db.add_chat_message(chat_id, "assistant", "Hi there", status="awaiting_confirmation")
    return _World(alice, bob, carol, chat, bob_chat, carol_chat, trashed)


def _target(world: _World, case: str) -> uuid.UUID:
    """The chat id Alice asks for in a not-found case."""
    return {
        "other-org": world.carol_chat,
        "other-user": world.bob_chat,
        "trashed": world.trashed,
        "unknown": _UNKNOWN_CHAT,
    }[case]


def _colliding(world: _World, case: str) -> uuid.UUID:
    """The existing chat whose id Alice's legacy insert is given (GH-271)."""
    return {
        "own-chat": world.chat,
        "own-trashed": world.trashed,
        "colleague": world.bob_chat,
        "other-org": world.carol_chat,
    }[case]


async def _call_with_chat(
    chats: ModuleType, db: FakeDb, name: str, tenant: TenantContext, chat_id: uuid.UUID
) -> Any:
    """Call one of the functions that take a chat id, with valid other arguments."""
    pool = db.pool
    if name == "get_chat":
        return await chats.get_chat(pool, tenant, chat_id)
    if name == "rename_chat":
        return await chats.rename_chat(pool, tenant, chat_id, "Renamed")
    if name == "trash_chat":
        return await chats.trash_chat(pool, tenant, chat_id, ip=_IP)
    if name == "append_messages":
        return await chats.append_messages(
            pool, tenant, chat_id, [LLMMessage(role="user", content="Injected?")]
        )
    if name == "load_recent_history":
        return await chats.load_recent_history(pool, tenant, chat_id, limit=10)
    assert name == "read_chat_detail"
    return await chats.read_chat_detail(pool, tenant, chat_id, limit=10, cursor=None)


def _as_uuid(value: Any) -> uuid.UUID | None:
    """A bind argument as a plain UUID (a UUID or a UUID string), else None."""
    if isinstance(value, uuid.UUID):
        return plain(value)
    if isinstance(value, str):
        with contextlib.suppress(ValueError):
            return uuid.UUID(value)
    return None


def _uuids(args: tuple[Any, ...]) -> set[uuid.UUID]:
    return {found for found in map(_as_uuid, args) if found is not None}


def _bound_uuid(call: Call, pattern: str) -> uuid.UUID | None:
    """The UUID bound to the first ``<column> = $n`` the pattern finds in the call's SQL."""
    match = re.search(pattern, call.normalized)
    assert match is not None, f"no {pattern} predicate in: {call.normalized}"
    return _as_uuid(call.args[int(match.group(1)) - 1])


def _chat_calls(db: FakeDb) -> list[Call]:
    return [call for call in db.calls if _CHAT_TABLE_RE.search(call.normalized)]


def _assert_scoped(
    calls: list[Call], member: _Member, *, owner: bool, foreign: set[uuid.UUID]
) -> None:
    """Every chat-table statement binds the member's org (and, filtering chats, the member
    as owner plus ``deleted_at IS NULL``) and none binds a foreign id."""
    assert calls, "the function must reach the chat tables"
    for call in calls:
        n = call.normalized
        bound = _uuids(call.args)
        assert member.tenant.org_id in bound, n
        assert not bound & foreign, n
        if re.search(r"\bwhere\b", n):
            assert _bound_uuid(call, ORG_ID_PARAM_RE) == member.tenant.org_id, n
        if _CHATS_FILTER_RE.search(n):
            assert "deleted_at is null" in n, n
            if owner:
                assert _bound_uuid(call, _OWNER_PARAM_RE) == member.user_id, n
        if n.startswith("insert into chats"):
            assert member.user_id in bound, n


def _field_names(record: Any) -> set[str]:
    """The fields of a frozen dataclass or a Pydantic model instance."""
    if dataclasses.is_dataclass(record):
        return {field.name for field in dataclasses.fields(record)}
    assert isinstance(record, BaseModel), type(record)
    return set(type(record).model_fields)


def _assert_record_is_row(record: Any, row: dict[str, Any]) -> None:
    """A ChatRecord carries exactly the stored row's values."""
    assert {name: getattr(record, name) for name in _CHAT_RECORD_FIELDS} == {
        name: row[name] for name in _CHAT_RECORD_FIELDS
    }


def _record(**args: Any) -> ToolCallRecord:
    return ToolCallRecord(
        tool="gmail", action="search", args=args, permission="allow", success=True, duration_ms=12
    )


def _tool_use(call_id: str, **tool_input: Any) -> dict[str, Any]:
    return {"type": "tool_use", "id": call_id, "name": "gmail.search", "input": tool_input}


def _non_finite_args(value: float | None) -> dict[str, Any]:
    """Tool arguments holding ``value`` at the top level and nested (lists, objects,
    several levels), next to finite values; ``None`` gives what must be stored."""
    return {
        "query": "invoice",
        "max_results": value,
        "filters": {"amount": [value, 12.5, {"min": value, "levels": [[3, value]]}]},
        "pages": [value],
    }


def _non_finite_turn(value: float | None) -> list[LLMMessage]:
    """A tool turn whose assistant tool call carries ``_non_finite_args(value)``."""
    return [
        LLMMessage(role="user", content="Find the large invoices"),
        LLMMessage(
            role="assistant",
            content="",
            tool_use_blocks=[_tool_use("call_f1", **_non_finite_args(value))],
        ),
        LLMMessage(role="tool", content="1 result", tool_call_id="call_f1"),
        LLMMessage(role="assistant", content="I found one invoice."),
    ]


def _insert_binds(call: Call) -> dict[str, Any]:
    """An ``INSERT INTO t (columns) VALUES (...)`` as column -> bound value (a literal in
    VALUES maps to its SQL text)."""
    match = re.fullmatch(
        r"insert into \w+ \((?P<columns>[^)]*)\) values \((?P<values>[^)]*)\)"
        r"(?: returning .*)?",
        call.normalized,
    )
    assert match is not None, call.normalized
    columns = [column.strip() for column in match.group("columns").split(",")]
    values = [value.strip() for value in match.group("values").split(",")]
    binds: dict[str, Any] = {}
    for column, value in zip(columns, values, strict=True):
        param = re.fullmatch(r"\$(\d+)(?:::\w+)?", value)
        binds[column] = value if param is None else call.args[int(param.group(1)) - 1]
    return binds


def _strict_float(text: str) -> float:
    """parse_float for strict JSON: an overflowing literal (1e400) is no JSON number."""
    number = float(text)
    if not math.isfinite(number):
        msg = f"non-finite number {text}"
        raise ValueError(msg)
    return number


def _refuse_constant(name: str) -> Any:
    """parse_constant for strict JSON: NaN, Infinity and -Infinity aren't JSON."""
    msg = f"not JSON: {name}"
    raise ValueError(msg)


def _strict_json(text: str) -> Any:
    """The value of strict JSON text (ValueError for NaN / Infinity / 1e400)."""
    return json.loads(text, parse_constant=_refuse_constant, parse_float=_strict_float)


def _wrapped(text: str = "Invoice attached, CHF 1200") -> str:
    """A tool result holding wrapped third-party content, as the tools produce it."""
    with untrusted.run_boundary():
        return untrusted.wrap("email", "gmail message 18c2f", text)


def _tool_turn(tool_result: str) -> list[LLMMessage]:
    """A user question, the assistant's tool call, its result and the answer."""
    return [
        LLMMessage(role="user", content="Find the invoice from Muster AG"),
        LLMMessage(
            role="assistant",
            content="",
            tool_use_blocks=[_tool_use("call_a1", query="from:muster invoice", max_results=5)],
        ),
        LLMMessage(role="tool", content=tool_result, tool_call_id="call_a1"),
        LLMMessage(role="assistant", content="I found one invoice."),
    ]


def _seven_message_history() -> list[LLMMessage]:
    """user, assistant calling two tools, both results, answer, user, answer."""
    return [
        LLMMessage(role="user", content="m0 question"),
        LLMMessage(
            role="assistant",
            content="m1 calling",
            tool_use_blocks=[_tool_use("call_a", query="a"), _tool_use("call_b", query="b")],
        ),
        LLMMessage(role="tool", content="m2 result a", tool_call_id="call_a"),
        LLMMessage(role="tool", content="m3 result b", tool_call_id="call_b"),
        LLMMessage(role="assistant", content="m4 answer"),
        LLMMessage(role="user", content="m5 follow-up"),
        LLMMessage(role="assistant", content="m6 answer"),
    ]


def _seed_history(db: FakeDb, chat_id: uuid.UUID, history: list[LLMMessage]) -> None:
    for message in history:
        db.add_chat_message(
            chat_id,
            message.role,
            message.content,
            tool_use_blocks=message.tool_use_blocks,
            tool_call_id=message.tool_call_id,
        )


def _expected_order(db: FakeDb, chat_ids: list[uuid.UUID]) -> list[uuid.UUID]:
    """The ids by last_activity_at DESC, id DESC (PostgreSQL compares UUIDs bytewise)."""
    rows = [db.chat_row(chat_id) for chat_id in chat_ids]
    ordered = sorted(
        (row for row in rows if row is not None),
        key=lambda row: (row["last_activity_at"], plain(row["id"]).int),
        reverse=True,
    )
    return [plain(row["id"]) for row in ordered]


async def _walk_chats(
    chats: ModuleType, db: FakeDb, tenant: TenantContext, limit: int
) -> tuple[list[list[uuid.UUID]], list[Any]]:
    """Every page of list_chats (ids) and every cursor seen on the way."""
    pages: list[list[uuid.UUID]] = []
    cursors: list[Any] = []
    cursor: str | None = None
    for _ in range(50):
        page = await chats.list_chats(db.pool, tenant, limit=limit, cursor=cursor)
        pages.append([plain(record.id) for record in page.chats])
        cursor = page.next_cursor
        cursors.append(cursor)
        if cursor is None:
            return pages, cursors
    msg = "the cursor walk never ended"
    raise AssertionError(msg)


async def _walk_details(
    chats: ModuleType, db: FakeDb, tenant: TenantContext, chat_id: uuid.UUID, limit: int
) -> list[Any]:
    """Every ChatDetail of read_chat_detail, following the page cursors to the beginning."""
    details: list[Any] = []
    cursor: str | None = None
    for _ in range(50):
        detail = await chats.read_chat_detail(db.pool, tenant, chat_id, limit=limit, cursor=cursor)
        details.append(detail)
        cursor = detail.page.next_cursor
        if cursor is None:
            return details
    msg = "the cursor walk never ended"
    raise AssertionError(msg)


async def _walk_messages(
    chats: ModuleType, db: FakeDb, tenant: TenantContext, chat_id: uuid.UUID, limit: int
) -> tuple[list[list[int]], list[Any]]:
    """Every message page of read_chat_detail (seqs, as returned) and every cursor seen."""
    details = await _walk_details(chats, db, tenant, chat_id, limit)
    pages = [[record.seq for record in detail.page.messages] for detail in details]
    return pages, [detail.page.next_cursor for detail in details]


async def _message_cursor(chats: ModuleType, db: FakeDb, member: _Member) -> str:
    """A real message cursor of read_chat_detail (a chat with two messages, limit 1)."""
    chat_id = db.add_chat(member.user_id)
    db.add_chat_message(chat_id, "user", "one")
    db.add_chat_message(chat_id, "assistant", "two")
    detail = await chats.read_chat_detail(db.pool, member.tenant, chat_id, limit=1, cursor=None)
    assert isinstance(detail.page.next_cursor, str)
    return detail.page.next_cursor


async def _list_cursor(chats: ModuleType, db: FakeDb, member: _Member) -> str:
    """A real cursor of list_chats (two chats, limit 1)."""
    db.add_chat(member.user_id, last_activity_at=_STAMP)
    db.add_chat(member.user_id, last_activity_at=_STAMP + _US)
    page = await chats.list_chats(db.pool, member.tenant, limit=1, cursor=None)
    assert isinstance(page.next_cursor, str)
    return page.next_cursor


def _cursor_payload(cursor: str) -> dict[str, Any]:
    """The JSON object a real cursor carries (admino.chats: unpadded base64url of JSON)."""
    payload = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    assert isinstance(payload, dict), payload
    return payload


def _is_seq(value: Any) -> bool:
    return type(value) is int


def _is_stamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def _crafted(cursor: str, is_field: Callable[[Any], bool], value: Any) -> str:
    """A real cursor with its one field ``is_field`` picks set to ``value``, encoded like
    admino.chats encodes it (a cursor that decodes, security audit L-1)."""
    payload = _cursor_payload(cursor)
    (name,) = [key for key, item in payload.items() if is_field(item)]
    payload[name] = value
    text = json.dumps(payload, separators=(",", ":"))
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


def _race_legacy_insert(
    monkeypatch: pytest.MonkeyPatch, db: FakeDb, owner: uuid.UUID, session_id: str
) -> list[uuid.UUID]:
    """Store the owner's legacy chat right before the first INSERT INTO chats runs (a
    concurrent first message); returns the list the concurrent chat's id lands in."""
    raced: list[uuid.UUID] = []
    original = db.handle

    def racing(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
        if not raced and norm(sql).startswith("insert into chats"):
            raced.append(db.add_chat(owner, legacy_session_id=session_id))
        return original(method, sql, args, via, tx)

    monkeypatch.setattr(db, "handle", racing)
    return raced


def _source_tree(chats: ModuleType) -> ast.Module:
    return ast.parse(Path(inspect.getfile(chats)).read_text(encoding="utf-8"))


def _imported_modules(tree: ast.Module) -> list[str]:
    """Every module imported (``from admino import x`` gives admino.x)."""
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module == "admino":
                modules += [f"admino.{alias.name}" for alias in node.names]
            else:
                modules.append(node.module)
    return modules


def _is_static_sql(node: ast.expr) -> bool:
    """A name, an attribute, a string literal, or a conditional between such."""
    if isinstance(node, ast.Name | ast.Attribute):
        return True
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.IfExp):
        return _is_static_sql(node.body) and _is_static_sql(node.orelse)
    return False


def _literal_text(node: ast.AST) -> str:
    """The string literal parts of an expression (empty for anything else)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_literal_text(part) for part in node.values)
    return ""


# ---------------------------------------------------------------------------
# 1. Module surface and hygiene
# ---------------------------------------------------------------------------


class TestSurface:
    """Names, signatures, error classes and the module's hygiene."""

    @pytest.mark.parametrize("name", _ALL_FUNCTIONS)
    def test_chats_function_is_a_coroutine_with_the_contract_parameters(
        self, chats: ModuleType, name: str
    ) -> None:
        function = getattr(chats, name)
        params = list(inspect.signature(function).parameters.values())
        positional = [
            param
            for param in params
            if param.kind
            in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}
        ]
        keyword_only = {
            param.name for param in params if param.kind is inspect.Parameter.KEYWORD_ONLY
        }

        assert inspect.iscoroutinefunction(function)
        assert (len(positional), keyword_only) == _SIGNATURES[name]

    def test_chats_errors_are_a_lookup_and_a_value_error(self, chats: ModuleType) -> None:
        assert issubclass(chats.ChatNotFoundError, LookupError)
        assert issubclass(chats.InvalidCursorError, ValueError)

    def test_chats_module_docstring_has_security_notes(self, chats: ModuleType) -> None:
        assert chats.__doc__ is not None
        assert "security" in chats.__doc__.lower()

    def test_chats_imports_no_server_agent_llm_tools_or_oauth(self, chats: ModuleType) -> None:
        forbidden = [
            module
            for module in _imported_modules(_source_tree(chats))
            if module in {"admino.server", "admino.agent", "admino.oauth"}
            or module.startswith(("admino.llm", "admino.tools"))
        ]

        assert forbidden == []

    def test_chats_passes_only_constant_sql_to_the_driver(self, chats: ModuleType) -> None:
        """The SQL argument of every execute/fetch* call is a name, an attribute, a literal or
        a conditional between those: never an f-string, a concatenation or a call result."""
        dynamic = [
            node.lineno
            for node in ast.walk(_source_tree(chats))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _DB_METHODS
            and node.args
            and not _is_static_sql(node.args[0])
        ]

        assert dynamic == []

    def test_chats_builds_no_sql_by_string_formatting(self, chats: ModuleType) -> None:
        """No f-string, ``%`` / ``+`` expression or ``.format`` call holds SQL text."""
        sites: list[int] = []
        for node in ast.walk(_source_tree(chats)):
            if isinstance(node, ast.JoinedStr):
                parts = [_literal_text(node)]
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod | ast.Add):
                parts = [_literal_text(node.left), _literal_text(node.right)]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
            ):
                parts = [_literal_text(node.func.value)]
            else:
                continue
            if any(_SQL_KEYWORD_RE.search(part) for part in parts):
                sites.append(node.lineno)

        assert sites == []

    def test_chats_list_messages_and_latest_message_status_are_gone(
        self, chats: ModuleType
    ) -> None:
        """GH-266: ``read_chat_detail`` replaced both (their only caller was the detail
        route); keeping them would be dead code."""
        assert callable(chats.read_chat_detail)
        assert [
            name for name in ("list_messages", "latest_message_status") if hasattr(chats, name)
        ] == []

    def test_chats_get_or_create_legacy_chat_id_is_required(self, chats: ModuleType) -> None:
        """GH-266: the server always names the id of a chat created here (no default)."""
        parameter = inspect.signature(chats.get_or_create_legacy_chat).parameters["chat_id"]

        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty

    def test_chats_every_json_dumps_passes_allow_nan_false(self, chats: ModuleType) -> None:
        """GH-266's fail-closed backstop: every ``json.dumps`` in the module refuses a
        non-finite number (ValueError) instead of writing ``NaN`` / ``Infinity`` text."""
        dumps = [
            node
            for node in ast.walk(_source_tree(chats))
            if isinstance(node, ast.Call)
            and (
                (isinstance(node.func, ast.Attribute) and node.func.attr == "dumps")
                or (isinstance(node.func, ast.Name) and node.func.id == "dumps")
            )
        ]
        refusing = [
            node.lineno
            for node in dumps
            if any(
                keyword.arg == "allow_nan"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            )
        ]

        assert dumps, "the JSONB values are serialized with json.dumps"
        assert refusing == [node.lineno for node in dumps]


# ---------------------------------------------------------------------------
# 2. create_chat and get_chat
# ---------------------------------------------------------------------------


class TestCreateChat:
    """A new chat of the caller: untitled (auto) or titled (user)."""

    async def test_chats_create_without_title_is_empty_and_auto(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)

        record = await chats.create_chat(db.pool, alice.tenant)

        assert (record.title, record.title_source) == ("", "auto")
        row = db.chat_row(record.id)
        assert row is not None
        assert (row["title"], row["title_source"]) == ("", "auto")
        assert (row["legacy_session_id"], row["deleted_at"], row["external_content"]) == (
            None,
            None,
            False,
        )

    async def test_chats_create_with_title_is_user_titled(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)

        record = await chats.create_chat(db.pool, alice.tenant, title="Quarterly VAT")

        assert (record.title, record.title_source) == ("Quarterly VAT", "user")
        row = db.chat_row(record.id)
        assert row is not None
        assert (row["title"], row["title_source"]) == ("Quarterly VAT", "user")

    async def test_chats_create_returns_the_stored_row_of_the_caller(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """One chats row, the caller's org and owner; the record is that row."""
        alice = _member(db)

        record = await chats.create_chat(db.pool, alice.tenant, title="Plans")

        (row,) = db.chats_of(alice.user_id)
        assert (plain(row["org_id"]), plain(row["owner_user_id"])) == (ORG_ID, alice.user_id)
        _assert_record_is_row(record, row)
        assert len(db.chats) == 1

    async def test_chats_record_has_exactly_the_contract_fields_and_is_frozen(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        record = await chats.create_chat(db.pool, alice.tenant)

        assert _field_names(record) == _CHAT_RECORD_FIELDS
        with pytest.raises((AttributeError, TypeError, ValueError)):
            record.title = "changed"


class TestGetChat:
    """The caller's live chat by id."""

    async def test_chats_get_returns_the_callers_live_chat(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        world = _world(db)

        record = await chats.get_chat(db.pool, world.alice.tenant, world.chat)

        row = db.chat_row(world.chat)
        assert row is not None
        _assert_record_is_row(record, row)


# ---------------------------------------------------------------------------
# 3. Tenant isolation at the data layer
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    """Owner-private chats: one not-found answer, scoped SQL, nothing changed."""

    @pytest.mark.parametrize("case", _NOT_FOUND_CASES)
    @pytest.mark.parametrize("name", _CHAT_ID_FUNCTIONS)
    async def test_chats_foreign_trashed_or_unknown_chat_is_not_found_and_changes_nothing(
        self, chats: ModuleType, db: FakeDb, name: str, case: str
    ) -> None:
        """ChatNotFoundError itself (no subclass), no INSERT attempted, every table as
        before (the trashed chat's deleted_at too), no id or title in the error."""
        world = _world(db)
        target = _target(world, case)
        before = db.snapshot()
        db.calls.clear()

        with pytest.raises(chats.ChatNotFoundError) as caught:
            await _call_with_chat(chats, db, name, world.alice.tenant, target)

        assert type(caught.value) is chats.ChatNotFoundError
        assert db.matching(r"^insert into\b") == []
        assert db.snapshot() == before
        assert str(target) not in str(caught.value)
        assert _VICTIM_TITLE not in str(caught.value)

    @pytest.mark.parametrize("name", _CHAT_ID_FUNCTIONS)
    async def test_chats_not_found_is_one_indistinguishable_error(
        self, chats: ModuleType, db: FakeDb, name: str
    ) -> None:
        """Another org's, another user's, a trashed and an unknown chat: same type, text, args."""
        world = _world(db)
        answers = set()
        for case in _NOT_FOUND_CASES:
            with pytest.raises(chats.ChatNotFoundError) as caught:
                await _call_with_chat(chats, db, name, world.alice.tenant, _target(world, case))
            answers.add((type(caught.value), str(caught.value), caught.value.args))

        assert len(answers) == 1

    @pytest.mark.parametrize("case", ["other-org", "other-user"])
    @pytest.mark.parametrize("name", _CHAT_ID_FUNCTIONS)
    async def test_chats_not_found_statements_bind_only_the_callers_scope(
        self, chats: ModuleType, db: FakeDb, name: str, case: str
    ) -> None:
        """Asking for a foreign chat binds the caller's org and user, never the owner's."""
        world = _world(db)
        db.calls.clear()

        with pytest.raises(chats.ChatNotFoundError):
            await _call_with_chat(chats, db, name, world.alice.tenant, _target(world, case))

        _assert_scoped(
            _chat_calls(db),
            world.alice,
            owner=True,
            foreign={world.bob.user_id, world.carol.user_id, OTHER_ORG_ID},
        )

    @pytest.mark.parametrize("name", _ALL_FUNCTIONS)
    async def test_chats_every_statement_binds_the_callers_org_owner_and_live_filter(
        self, chats: ModuleType, db: FakeDb, name: str
    ) -> None:
        """The happy path of every function (cursor forms included): each chat-table
        statement binds ORG_ID; filtering chats, Alice as owner (org-wide for the notice and
        the platform count) and ``deleted_at IS NULL``; no foreign org, user or chat id."""
        world = _world(db)
        alice, pool = world.alice, db.pool
        db.add_chat(alice.user_id, legacy_session_id=_SESSION, last_activity_at=_STAMP)
        db.calls.clear()

        if name in _CHAT_ID_FUNCTIONS and name != "read_chat_detail":
            await _call_with_chat(chats, db, name, alice.tenant, world.chat)
        elif name == "read_chat_detail":
            detail = await chats.read_chat_detail(
                pool, alice.tenant, world.chat, limit=1, cursor=None
            )
            await chats.read_chat_detail(
                pool, alice.tenant, world.chat, limit=1, cursor=detail.page.next_cursor
            )
        elif name == "create_chat":
            await chats.create_chat(pool, alice.tenant, title="New")
        elif name == "get_or_create_legacy_chat":
            await chats.get_or_create_legacy_chat(
                pool, alice.tenant, "fresh-session", chat_id=uuid.uuid4()
            )
            await chats.get_or_create_legacy_chat(
                pool, alice.tenant, "fresh-session", chat_id=uuid.uuid4()
            )
        elif name == "find_legacy_chat":
            await chats.find_legacy_chat(pool, alice.tenant, _SESSION)
        elif name == "list_chats":
            page = await chats.list_chats(pool, alice.tenant, limit=1, cursor=None)
            await chats.list_chats(pool, alice.tenant, limit=1, cursor=page.next_cursor)
        elif name == "append_org_notice":
            await chats.append_org_notice(pool, alice.tenant, "Notice")
        else:
            assert name == "count_org_chats"
            await chats.count_org_chats(pool, ORG_ID)

        _assert_scoped(
            _chat_calls(db),
            alice,
            owner=name not in {"append_org_notice", "count_org_chats"},
            foreign={
                world.bob.user_id,
                world.carol.user_id,
                OTHER_ORG_ID,
                world.bob_chat,
                world.carol_chat,
            },
        )

    async def test_chats_list_never_shows_another_users_or_orgs_chats(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        world = _world(db)

        page = await chats.list_chats(db.pool, world.alice.tenant, limit=100, cursor=None)

        assert [plain(record.id) for record in page.chats] == [world.chat]
        assert page.next_cursor is None

    async def test_chats_list_with_another_users_cursor_shows_only_own_chats(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """A cursor carries a position, never a scope: Carol's list stays Carol's."""
        world = _world(db)
        alice_cursor = await _list_cursor(chats, db, world.alice)
        older = db.add_chat(world.carol.user_id, last_activity_at=_STAMP - timedelta(days=30))

        page = await chats.list_chats(db.pool, world.carol.tenant, limit=100, cursor=alice_cursor)

        ids = [plain(record.id) for record in page.chats]
        assert older in ids
        assert {(plain(r.org_id), plain(r.owner_user_id)) for r in page.chats} == {
            (OTHER_ORG_ID, world.carol.user_id)
        }

    async def test_chats_legacy_lookup_never_returns_another_users_chat(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Bob's legacy session id: find is not found, get_or_create makes Alice her own."""
        world = _world(db)
        bobs = db.add_chat(world.bob.user_id, legacy_session_id=_SESSION)

        with pytest.raises(chats.ChatNotFoundError):
            await chats.find_legacy_chat(db.pool, world.alice.tenant, _SESSION)
        record = await chats.get_or_create_legacy_chat(
            db.pool, world.alice.tenant, _SESSION, chat_id=uuid.uuid4()
        )

        assert plain(record.id) != bobs
        assert plain(record.owner_user_id) == world.alice.user_id


# ---------------------------------------------------------------------------
# 4. Legacy session chats (until #177)
# ---------------------------------------------------------------------------


class TestLegacyChats:
    """One persisted chat per (user, legacy session id)."""

    async def test_chats_get_or_create_legacy_creates_once_and_reuses(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """First call inserts ('' / auto, the session id stored), the second returns it; a
        regular chat of the user is never mistaken for it."""
        alice = _member(db)
        regular = db.add_chat(alice.user_id, title="Regular")

        first = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=uuid.uuid4()
        )
        second = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=uuid.uuid4()
        )

        assert plain(first.id) == plain(second.id) != regular
        row = db.chat_row(first.id)
        assert row is not None
        assert (row["legacy_session_id"], row["title"], row["title_source"]) == (
            _SESSION,
            "",
            "auto",
        )
        _assert_record_is_row(second, row)
        assert len(db.chats_of(alice.user_id)) == 2

    @pytest.mark.parametrize("other_org", [OTHER_ORG_ID, ORG_ID], ids=["other-org", "same-org"])
    async def test_chats_get_or_create_legacy_is_per_user(
        self, chats: ModuleType, db: FakeDb, other_org: uuid.UUID
    ) -> None:
        """Same session id, two users: two chats, each owned by its user."""
        alice, other = _member(db), _member(db, org_id=other_org)

        mine = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=uuid.uuid4()
        )
        theirs = await chats.get_or_create_legacy_chat(
            db.pool, other.tenant, _SESSION, chat_id=uuid.uuid4()
        )

        assert plain(mine.id) != plain(theirs.id)
        assert (plain(mine.owner_user_id), plain(theirs.owner_user_id)) == (
            alice.user_id,
            other.user_id,
        )
        assert (plain(theirs.org_id)) == other_org

    async def test_chats_get_or_create_legacy_replaces_a_trashed_chat(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        trashed = db.add_chat(alice.user_id, legacy_session_id=_SESSION, deleted_at=_PAST)

        record = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=uuid.uuid4()
        )

        assert plain(record.id) != trashed
        row = db.chat_row(record.id)
        assert row is not None
        assert (row["deleted_at"], row["legacy_session_id"]) == (None, _SESSION)

    async def test_chats_find_legacy_returns_the_existing_chat(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        existing = db.add_chat(alice.user_id, legacy_session_id=_SESSION, title="Kept")

        record = await chats.find_legacy_chat(db.pool, alice.tenant, _SESSION)

        row = db.chat_row(existing)
        assert row is not None
        _assert_record_is_row(record, row)

    @pytest.mark.parametrize("state", ["absent", "trashed", "other-session", "regular-chat"])
    async def test_chats_find_legacy_never_creates(
        self, chats: ModuleType, db: FakeDb, state: str
    ) -> None:
        alice = _member(db)
        if state == "trashed":
            db.add_chat(alice.user_id, legacy_session_id=_SESSION, deleted_at=_PAST)
        elif state == "other-session":
            db.add_chat(alice.user_id, legacy_session_id="another-session")
        elif state == "regular-chat":
            db.add_chat(alice.user_id)
        before = db.snapshot()
        db.calls.clear()

        with pytest.raises(chats.ChatNotFoundError):
            await chats.find_legacy_chat(db.pool, alice.tenant, _SESSION)

        assert db.matching(r"^insert into\b") == []
        assert db.snapshot() == before

    async def test_chats_get_or_create_legacy_selects_again_after_a_concurrent_insert(
        self, chats: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A concurrent first message inserts the chat between the lookup and the INSERT:
        the UniqueViolationError is answered with the concurrent chat, no second row."""
        alice = _member(db)
        raced = _race_legacy_insert(monkeypatch, db, alice.user_id, _SESSION)

        record = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=uuid.uuid4()
        )

        assert len(raced) == 1, "the INSERT must have been attempted"
        assert plain(record.id) == raced[0]
        assert [plain(row["id"]) for row in db.chats_of(alice.user_id)] == raced

    async def test_chats_get_or_create_legacy_propagates_other_insert_errors(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Only a unique violation means "someone else inserted it"."""
        alice = _member(db)
        db.fail_sql = r"^insert into chats\b"

        with pytest.raises(asyncpg.exceptions.DeadlockDetectedError):
            await chats.get_or_create_legacy_chat(
                db.pool, alice.tenant, _SESSION, chat_id=uuid.uuid4()
            )

        assert db.chats_of(alice.user_id) == []

    # -- GH-266: the server names the id of a chat created here ------------------

    async def test_chats_get_or_create_legacy_new_chat_gets_the_given_id(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """One INSERT (S1L) binding the given id, the caller's org, the caller as owner and
        the session id; the chat is untitled (``''``, ``auto``), unflagged and live, and the
        record is the stored row."""
        alice = _member(db)
        chat_id = uuid.uuid4()
        db.calls.clear()

        record = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=chat_id
        )

        (insert,) = db.matching(r"^insert into chats\b")
        binds = {
            column: _as_uuid(value) or value for column, value in _insert_binds(insert).items()
        }
        assert {
            column: binds.get(column)
            for column in ("id", "org_id", "owner_user_id", "legacy_session_id")
        } == {
            "id": chat_id,
            "org_id": ORG_ID,
            "owner_user_id": alice.user_id,
            "legacy_session_id": _SESSION,
        }
        row = db.chat_row(chat_id)
        assert row is not None
        assert (
            row["title"],
            row["title_source"],
            row["external_content"],
            row["deleted_at"],
            row["legacy_session_id"],
        ) == ("", "auto", False, None, _SESSION)
        assert plain(record.id) == chat_id
        _assert_record_is_row(record, row)

    async def test_chats_get_or_create_legacy_existing_chat_keeps_its_id_and_inserts_nothing(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """The session's live chat is returned as is: its own id, the given id unused, no
        INSERT, nothing changed."""
        alice = _member(db)
        existing = db.add_chat(alice.user_id, legacy_session_id=_SESSION, title="Kept")
        unused = uuid.uuid4()
        before = db.snapshot()
        db.calls.clear()

        record = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=unused
        )

        assert plain(record.id) == existing
        assert db.matching(r"^insert into\b") == []
        assert db.snapshot() == before
        assert db.chat_row(unused) is None

    async def test_chats_get_or_create_legacy_concurrent_winner_is_returned_not_the_given_id(
        self, chats: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A concurrent first message of the session inserts first: its chat is returned
        (an id other than the given one) and the session has exactly one chat."""
        alice = _member(db)
        chat_id = uuid.uuid4()
        raced = _race_legacy_insert(monkeypatch, db, alice.user_id, _SESSION)

        record = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=chat_id
        )

        assert len(raced) == 1, "the INSERT must have been attempted"
        assert plain(record.id) == raced[0] != chat_id
        assert [plain(row["id"]) for row in db.chats_of(alice.user_id)] == raced
        assert db.chat_row(chat_id) is None

    async def test_chats_get_or_create_legacy_trashed_session_gets_a_new_chat_with_the_given_id(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """The session's only chat is trashed: a new live chat with the given id, the
        trashed one left as it was."""
        alice = _member(db)
        trashed = db.add_chat(alice.user_id, legacy_session_id=_SESSION, deleted_at=_PAST)
        trashed_row = db.chat_row(trashed)
        chat_id = uuid.uuid4()

        record = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=chat_id
        )

        assert plain(record.id) == chat_id
        row = db.chat_row(chat_id)
        assert row is not None
        assert (row["deleted_at"], row["legacy_session_id"]) == (None, _SESSION)
        assert db.chat_row(trashed) == trashed_row

    # -- GH-271: only the session-key violation is the concurrent first message --------

    @pytest.mark.parametrize("case", _COLLISIONS)
    async def test_chats_get_or_create_legacy_primary_key_collision_propagates_and_changes_nothing(
        self, chats: ModuleType, db: FakeDb, case: str
    ) -> None:
        """The given id is an existing chat's (Alice's own, her trashed one, a colleague's,
        another org's): the INSERT's ``chats_pkey`` violation propagates, the colliding
        chat is never returned or changed, nothing is stored and no statement runs after
        the INSERT."""
        world = _world(db)
        colliding = _colliding(world, case)
        before = db.snapshot()
        db.calls.clear()

        with pytest.raises(asyncpg.exceptions.UniqueViolationError) as caught:
            await chats.get_or_create_legacy_chat(
                db.pool, world.alice.tenant, _SESSION, chat_id=colliding
            )

        assert (caught.value.constraint_name, caught.value.table_name) == ("chats_pkey", "chats")
        assert db.snapshot() == before
        assert len(db.matching(r"^insert into chats\b")) == 1
        assert db.calls[-1].normalized.startswith("insert into chats"), db.calls[-1].normalized

    @pytest.mark.parametrize(
        "constraint",
        [None, "chats_legacy_session_id_key"],
        ids=["no-constraint-name", "another-constraint"],
    )
    async def test_chats_get_or_create_legacy_other_unique_violation_propagates(
        self,
        chats: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
        constraint: str | None,
    ) -> None:
        """A unique violation on the INSERT that doesn't name ``chats_legacy_session_key``
        (no constraint name, or a look-alike one) is not a concurrent first message: that
        very exception propagates, nothing is stored and no statement runs after it."""
        alice = _member(db)
        injected = asyncpg.exceptions.UniqueViolationError(
            "duplicate key value violates unique constraint"
        )
        if constraint is not None:
            injected.constraint_name = constraint
        statements: list[str] = []
        original = db.handle

        def failing(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
            statements.append(norm(sql))
            if norm(sql).startswith("insert into chats"):
                raise injected
            return original(method, sql, args, via, tx)

        monkeypatch.setattr(db, "handle", failing)
        before = db.snapshot()

        with pytest.raises(asyncpg.exceptions.UniqueViolationError) as caught:
            await chats.get_or_create_legacy_chat(
                db.pool, alice.tenant, _SESSION, chat_id=uuid.uuid4()
            )

        assert caught.value is injected
        assert db.snapshot() == before
        inserts = [statement.startswith("insert into chats") for statement in statements]
        assert (inserts.count(True), inserts[-1]) == (1, True), statements

    async def test_chats_get_or_create_legacy_race_answers_only_the_session_key_violation(
        self, chats: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Guard: in the concurrent-first-message race the INSERT fails on exactly
        ``chats_legacy_session_key``, and that is answered by one more lookup returning
        the winner's chat (lookup, INSERT, lookup)."""
        alice = _member(db)
        raced = _race_legacy_insert(monkeypatch, db, alice.user_id, _SESSION)
        racing = db.handle
        raised: list[Exception] = []

        def recording(
            method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None
        ) -> Any:
            try:
                return racing(method, sql, args, via, tx)
            except Exception as exc:
                raised.append(exc)
                raise

        monkeypatch.setattr(db, "handle", recording)
        db.calls.clear()

        record = await chats.get_or_create_legacy_chat(
            db.pool, alice.tenant, _SESSION, chat_id=uuid.uuid4()
        )

        assert [(type(exc), getattr(exc, "constraint_name", None)) for exc in raised] == [
            (asyncpg.exceptions.UniqueViolationError, _LEGACY_SESSION_KEY)
        ]
        assert plain(record.id) == raced[0]
        assert [call.normalized.split(" ", 1)[0] for call in db.calls] == [
            "select",
            "insert",
            "select",
        ]


# ---------------------------------------------------------------------------
# 5. list_chats
# ---------------------------------------------------------------------------


class TestListChats:
    """The caller's live chats, latest activity first, keyset-paginated."""

    async def test_chats_list_orders_by_last_activity_then_id_desc(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        stamps = [_STAMP + 2 * _US, _STAMP, _STAMP + 5 * _US, _STAMP, _STAMP + _US]
        ids = [db.add_chat(alice.user_id, last_activity_at=stamp) for stamp in stamps]

        page = await chats.list_chats(db.pool, alice.tenant, limit=50, cursor=None)

        assert [plain(record.id) for record in page.chats] == _expected_order(db, ids)
        for record in page.chats:
            row = db.chat_row(record.id)
            assert row is not None
            _assert_record_is_row(record, row)

    async def test_chats_list_respects_the_limit(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        ids = [db.add_chat(alice.user_id, last_activity_at=_STAMP + k * _US) for k in range(5)]

        page = await chats.list_chats(db.pool, alice.tenant, limit=2, cursor=None)

        assert [plain(record.id) for record in page.chats] == _expected_order(db, ids)[:2]
        assert isinstance(page.next_cursor, str)

    @pytest.mark.parametrize("total", [0, 2, 3])
    async def test_chats_list_last_page_has_no_cursor(
        self, chats: ModuleType, db: FakeDb, total: int
    ) -> None:
        """No chats, fewer than the limit, exactly the limit: next_cursor is None."""
        alice = _member(db)
        ids = [db.add_chat(alice.user_id, last_activity_at=_STAMP + k * _US) for k in range(total)]

        page = await chats.list_chats(db.pool, alice.tenant, limit=3, cursor=None)

        assert [plain(record.id) for record in page.chats] == _expected_order(db, ids)
        assert page.next_cursor is None

    @pytest.mark.parametrize("limit", [1, 3])
    async def test_chats_list_walk_returns_every_live_chat_once_in_order(
        self, chats: ModuleType, db: FakeDb, limit: int
    ) -> None:
        """Seven chats (three sharing a stamp across a page boundary, the others one
        microsecond apart), one trashed: each live chat exactly once, in order; full pages
        but the last; cursors are strings of at most 200 characters."""
        alice = _member(db)
        stamps = [_STAMP + 2 * _US, _STAMP + 4 * _US, _STAMP + _US, _STAMP + 4 * _US]
        stamps += [_STAMP + 5 * _US, _STAMP + 4 * _US, _STAMP + 3 * _US]
        ids = [db.add_chat(alice.user_id, last_activity_at=stamp) for stamp in stamps]
        db.add_chat(alice.user_id, last_activity_at=_STAMP + 4 * _US, deleted_at=_PAST)

        pages, cursors = await _walk_chats(chats, db, alice.tenant, limit)

        assert [chat_id for page in pages for chat_id in page] == _expected_order(db, ids)
        assert all(len(page) == limit for page in pages[:-1])
        assert 1 <= len(pages[-1]) <= limit
        assert all(isinstance(cursor, str) and len(cursor) <= 200 for cursor in cursors[:-1])

    async def test_chats_list_excludes_trashed_chats(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        live = db.add_chat(alice.user_id, last_activity_at=_STAMP)
        db.add_chat(alice.user_id, last_activity_at=_STAMP + _US, deleted_at=_PAST)

        page = await chats.list_chats(db.pool, alice.tenant, limit=50, cursor=None)

        assert [plain(record.id) for record in page.chats] == [live]

    @pytest.mark.parametrize("cursor", _GARBAGE_CURSORS)
    async def test_chats_list_bad_cursor_is_invalid(
        self, chats: ModuleType, db: FakeDb, cursor: str
    ) -> None:
        alice = _member(db)
        db.add_chat(alice.user_id)

        with pytest.raises(chats.InvalidCursorError):
            await chats.list_chats(db.pool, alice.tenant, limit=10, cursor=cursor)

    async def test_chats_list_truncated_cursor_is_invalid(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        cursor = await _list_cursor(chats, db, alice)

        with pytest.raises(chats.InvalidCursorError):
            await chats.list_chats(db.pool, alice.tenant, limit=10, cursor=cursor[:-4])

    async def test_chats_list_refuses_a_message_cursor(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        cursor = await _message_cursor(chats, db, alice)

        with pytest.raises(chats.InvalidCursorError):
            await chats.list_chats(db.pool, alice.tenant, limit=10, cursor=cursor)

    @pytest.mark.parametrize(
        "stamp",
        [
            pytest.param("0001-01-01T00:00:00+23:00", id="year-1-at-plus-23h"),
            pytest.param("9999-12-31T23:59:59-23:00", id="year-9999-at-minus-23h"),
        ],
    )
    async def test_chats_list_cursor_stamp_outside_the_utc_range_is_invalid(
        self, chats: ModuleType, db: FakeDb, stamp: str
    ) -> None:
        """Security audit L-1: a crafted cursor whose ``last_activity_at`` decodes but
        overflows on the conversion to UTC (asyncpg's DataError, a 500) is
        ``InvalidCursorError``, refused before a statement binds it."""
        alice = _member(db)
        crafted = _crafted(await _list_cursor(chats, db, alice), _is_stamp, stamp)
        db.calls.clear()

        with pytest.raises(chats.InvalidCursorError):
            await chats.list_chats(db.pool, alice.tenant, limit=10, cursor=crafted)

        assert not any(isinstance(arg, datetime) for call in db.calls for arg in call.args)


# ---------------------------------------------------------------------------
# 6. rename_chat
# ---------------------------------------------------------------------------


class TestRenameChat:
    """A user title; activity untouched; idempotent."""

    async def test_chats_rename_sets_title_and_user_source(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, title="", title_source="auto")

        record = await chats.rename_chat(db.pool, alice.tenant, chat_id, "Budget 2027")

        row = db.chat_row(chat_id)
        assert row is not None
        assert (row["title"], row["title_source"]) == ("Budget 2027", "user")
        _assert_record_is_row(record, row)

    async def test_chats_rename_keeps_last_activity(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, created_at=_PAST, last_activity_at=_PAST)

        await chats.rename_chat(db.pool, alice.tenant, chat_id, "Budget 2027")

        row = db.chat_row(chat_id)
        assert row is not None
        assert row["last_activity_at"] == _PAST

    async def test_chats_rename_is_idempotent(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, title="Budget 2027", title_source="user")

        first = await chats.rename_chat(db.pool, alice.tenant, chat_id, "Budget 2027")
        second = await chats.rename_chat(db.pool, alice.tenant, chat_id, "Budget 2027")

        row = db.chat_row(chat_id)
        assert row is not None
        _assert_record_is_row(first, row)
        _assert_record_is_row(second, row)


# ---------------------------------------------------------------------------
# 7. trash_chat
# ---------------------------------------------------------------------------


class TestTrashChat:
    """deleted_at plus one chat.delete event, atomically."""

    async def test_chats_trash_sets_deleted_at(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        started = datetime.now(UTC)

        result = await chats.trash_chat(db.pool, alice.tenant, chat_id, ip=_IP)

        row = db.chat_row(chat_id)
        assert result is None
        assert row is not None
        assert row["deleted_at"] is not None
        assert started <= row["deleted_at"] <= datetime.now(UTC)

    @pytest.mark.parametrize("ip", [_IP, None])
    async def test_chats_trash_records_one_chat_delete_event(
        self, chats: ModuleType, db: FakeDb, ip: str | None
    ) -> None:
        """Member actor, the org, target chat [id], the client IP, no metadata."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, title=_MARK_TITLE)

        await chats.trash_chat(db.pool, alice.tenant, chat_id, ip=ip)

        (row,) = db.audit
        assert {
            "action": row["action"],
            "actor_kind": row["actor_kind"],
            "actor_user_id": plain(row["actor_user_id"]),
            "org_id": plain(row["org_id"]),
            "target_type": row["target_type"],
            "target_ids": row["target_ids"],
            "ip": row["ip"],
            "metadata": row["metadata"],
        } == {
            "action": "chat.delete",
            "actor_kind": "member",
            "actor_user_id": alice.user_id,
            "org_id": ORG_ID,
            "target_type": "chat",
            "target_ids": [str(chat_id)],
            "ip": ip,
            "metadata": {},
        }

    async def test_chats_trash_and_audit_share_one_transaction(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.calls.clear()

        await chats.trash_chat(db.pool, alice.tenant, chat_id, ip=_IP)

        (update,) = db.matching(r"^update chats\b")
        (audit,) = db.matching(r"^insert into audit_events\b")
        assert update.tx is not None
        assert (update.via, update.tx) == (audit.via, audit.tx)
        assert (update.tx, "commit") in db.transactions

    async def test_chats_trash_audit_failure_rolls_back(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await chats.trash_chat(db.pool, alice.tenant, chat_id, ip=_IP)

        assert db.snapshot() == before
        row = db.chat_row(chat_id)
        assert row is not None
        assert row["deleted_at"] is None

    async def test_chats_trash_twice_is_not_found(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        await chats.trash_chat(db.pool, alice.tenant, chat_id, ip=_IP)
        before = db.snapshot()

        with pytest.raises(chats.ChatNotFoundError):
            await chats.trash_chat(db.pool, alice.tenant, chat_id, ip=_IP)

        assert db.snapshot() == before
        assert len(db.audit_rows("chat.delete")) == 1

    async def test_chats_trashed_chat_is_invisible(self, chats: ModuleType, db: FakeDb) -> None:
        """After trash_chat: get and the message reads are not found, list skips it."""
        alice = _member(db)
        kept = db.add_chat(alice.user_id, last_activity_at=_STAMP)
        chat_id = db.add_chat(alice.user_id, last_activity_at=_STAMP + _US)
        db.add_chat_message(chat_id, "user", "Hello")

        await chats.trash_chat(db.pool, alice.tenant, chat_id, ip=_IP)

        page = await chats.list_chats(db.pool, alice.tenant, limit=50, cursor=None)
        assert [plain(record.id) for record in page.chats] == [kept]
        for name in ("get_chat", "read_chat_detail", "load_recent_history"):
            with pytest.raises(chats.ChatNotFoundError):
                await _call_with_chat(chats, db, name, alice.tenant, chat_id)


# ---------------------------------------------------------------------------
# 8. append_messages
# ---------------------------------------------------------------------------


class TestAppendMessages:
    """One transaction: the chat UPDATE, then one INSERT per message."""

    async def test_chats_append_stores_messages_in_order(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        history = _tool_turn("2 results")

        await chats.append_messages(db.pool, alice.tenant, chat_id, history)

        rows = db.messages_of(chat_id)
        assert [(row["role"], row["content"]) for row in rows] == [
            (message.role, message.content) for message in history
        ]
        assert [row["seq"] for row in rows] == sorted(row["seq"] for row in rows)
        assert {plain(row["org_id"]) for row in rows} == {ORG_ID}

    @pytest.mark.parametrize("status", _STATUSES)
    async def test_chats_append_last_message_gets_final_status_and_tool_calls(
        self, chats: ModuleType, db: FakeDb, status: str
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        records = [_record(query="invoice"), _record(query="receipt", max_results=3)]

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            _tool_turn("2 results"),
            final_status=status,
            tool_calls=records,
        )

        rows = db.messages_of(chat_id)
        assert [(row["status"], row["tool_calls"]) for row in rows] == [
            ("complete", None),
            ("complete", None),
            ("complete", None),
            (status, [record.model_dump(mode="json") for record in records]),
        ]

    async def test_chats_append_defaults_to_complete_without_tool_calls(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)

        await chats.append_messages(
            db.pool, alice.tenant, chat_id, [LLMMessage(role="user", content="Hi")]
        )

        (row,) = db.messages_of(chat_id)
        assert (row["status"], row["tool_calls"]) == ("complete", None)

    async def test_chats_append_empty_tool_calls_is_null(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            [LLMMessage(role="user", content="Hi"), LLMMessage(role="assistant", content="Hey")],
            final_status="stopped",
            tool_calls=[],
        )

        assert [(row["status"], row["tool_calls"]) for row in db.messages_of(chat_id)] == [
            ("complete", None),
            ("stopped", None),
        ]

    async def test_chats_append_round_trips_tool_use_blocks_and_tool_call_id(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        history = _tool_turn("2 results")

        await chats.append_messages(db.pool, alice.tenant, chat_id, history)

        rows = db.messages_of(chat_id)
        assert [(row["tool_use_blocks"], row["tool_call_id"]) for row in rows] == [
            (message.tool_use_blocks, message.tool_call_id) for message in history
        ]

    async def test_chats_append_bumps_last_activity(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, created_at=_PAST, last_activity_at=_PAST)
        started = datetime.now(UTC)

        await chats.append_messages(
            db.pool, alice.tenant, chat_id, [LLMMessage(role="user", content="Hi")]
        )

        row = db.chat_row(chat_id)
        assert row is not None
        assert started <= row["last_activity_at"] <= datetime.now(UTC)

    async def test_chats_append_wrapped_tool_result_sets_external_content(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)

        await chats.append_messages(db.pool, alice.tenant, chat_id, _tool_turn(_wrapped()))

        row = db.chat_row(chat_id)
        assert row is not None
        assert row["external_content"] is True

    @pytest.mark.parametrize("origin", ["set-by-append", "seeded"])
    async def test_chats_append_external_content_is_sticky(
        self, chats: ModuleType, db: FakeDb, origin: str
    ) -> None:
        """Once set, later clean appends never reset it."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, external_content=origin == "seeded")
        if origin == "set-by-append":
            await chats.append_messages(db.pool, alice.tenant, chat_id, _tool_turn(_wrapped()))

        await chats.append_messages(db.pool, alice.tenant, chat_id, _tool_turn("No results"))
        await chats.append_messages(
            db.pool, alice.tenant, chat_id, [LLMMessage(role="user", content="Thanks")]
        )

        row = db.chat_row(chat_id)
        assert row is not None
        assert row["external_content"] is True
        assert len(db.messages_of(chat_id)) == 5 + 4 * (origin == "set-by-append")

    @pytest.mark.parametrize("role", ["user", "assistant"])
    async def test_chats_append_marker_outside_a_tool_message_is_not_external(
        self, chats: ModuleType, db: FakeDb, role: str
    ) -> None:
        """A user typing (or the model echoing) a real begin marker doesn't set the flag:
        only ``tool`` messages count."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)

        await chats.append_messages(
            db.pool, alice.tenant, chat_id, [LLMMessage(role=role, content=_wrapped())]
        )

        row = db.chat_row(chat_id)
        assert row is not None
        assert row["external_content"] is False
        assert untrusted.contains_wrapped(db.messages_of(chat_id)[0]["content"])

    async def test_chats_append_unwrapped_tool_result_is_not_external(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)

        await chats.append_messages(db.pool, alice.tenant, chat_id, _tool_turn("No results"))

        row = db.chat_row(chat_id)
        assert row is not None
        assert row["external_content"] is False
        assert len(db.messages_of(chat_id)) == 4

    async def test_chats_append_system_message_is_refused_and_writes_nothing(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """System prompts are never stored: ValueError, no message row, activity unchanged,
        the system text in no statement."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, created_at=_PAST)
        before = db.snapshot()
        db.calls.clear()
        system_text = "You are admino. Secret org instructions."

        with pytest.raises(ValueError) as caught:
            await chats.append_messages(
                db.pool,
                alice.tenant,
                chat_id,
                [
                    LLMMessage(role="user", content="Hi"),
                    LLMMessage(role="system", content=system_text),
                ],
            )

        assert not isinstance(caught.value, chats.InvalidCursorError)
        assert db.snapshot() == before
        assert db.matching(r"^insert into\b") == []
        assert all(system_text not in call.args for call in db.calls)

    @pytest.mark.parametrize("chat", ["own", "unknown"])
    async def test_chats_append_empty_list_runs_no_statement(
        self, chats: ModuleType, db: FakeDb, chat: str
    ) -> None:
        alice = _member(db)
        own = db.add_chat(alice.user_id, created_at=_PAST)
        before = db.snapshot()
        db.calls.clear()

        result = await chats.append_messages(
            db.pool, alice.tenant, own if chat == "own" else _UNKNOWN_CHAT, []
        )

        assert result is None
        assert db.calls == []
        assert db.snapshot() == before

    async def test_chats_append_strips_nul_from_content(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """PostgreSQL TEXT refuses U+0000: it is removed, the rest kept."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        nul = chr(0)

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            [
                LLMMessage(role="user", content=f"Hel{nul}lo{nul}"),
                LLMMessage(role="assistant", content=f"{nul}Hi"),
            ],
        )

        assert [row["content"] for row in db.messages_of(chat_id)] == ["Hello", "Hi"]

    async def test_chats_append_strips_nul_from_json_strings(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """JSONB refuses \\u0000: every string value inside tool_use_blocks and the dumped
        tool calls (nested lists and objects too) loses it."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        nul = chr(0)
        blocks = [_tool_use("call_n1", query=f"in{nul}voice", tags=[f"a{nul}", {"k": f"{nul}v"}])]

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            [
                LLMMessage(role="user", content="Search"),
                LLMMessage(role="assistant", content="", tool_use_blocks=blocks),
            ],
            tool_calls=[_record(query=f"in{nul}voice", filters={"from": [f"mu{nul}ster"]})],
        )

        rows = db.messages_of(chat_id)
        assert rows[1]["tool_use_blocks"] == [
            _tool_use("call_n1", query="invoice", tags=["a", {"k": "v"}])
        ]
        assert rows[1]["tool_calls"] == [
            _record(query="invoice", filters={"from": ["muster"]}).model_dump(mode="json")
        ]

    async def test_chats_append_strips_nul_from_json_keys(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Object keys are strings inside the JSON value too."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        nul = chr(0)
        blocks = [{"type": "tool_use", "id": "call_k1", "name": "gmail.search", "input": {}}]
        blocks[0]["input"] = {f"que{nul}ry": "invoice"}

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            [LLMMessage(role="assistant", content="", tool_use_blocks=blocks)],
        )

        (row,) = db.messages_of(chat_id)
        assert row["tool_use_blocks"][0]["input"] == {"query": "invoice"}

    async def test_chats_append_replaces_lone_surrogates_in_json_strings(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Security audit L-2: a model's tool input and the run's tool-call arguments are
        free-form JSON, so a lone surrogate gets through Pydantic; JSONB refuses it, which
        failed the whole append after the tools had run. Every lone surrogate (values,
        nested lists and objects, keys at any depth) is stored as one U+FFFD, the rest
        kept, and the turn is persisted. (Pydantic's JSON-mode dump of a record turns a
        surrogate in a key into three U+FFFD, or raises for a nested key.)"""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        blocks = [_tool_use("call_s1", query=f"in{_HIGH}voice", tags=[f"a{_LOW}", {"k": _HIGH}])]
        blocks[0]["input"][f"fil{_LOW}ter"] = "from:muster"
        blocks[0]["input"]["nested"] = {f"k{_HIGH}": [{f"j{_LOW}": "v"}]}
        blocks[0][f"no{_HIGH}te"] = "x"
        record = _record(
            query=f"in{_LOW}voice", filters={"from": [f"mu{_HIGH}ster"], f"t{_LOW}o": ["me"]}
        )
        record.args[f"li{_HIGH}mit"] = 5

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            [
                LLMMessage(role="user", content="Search"),
                LLMMessage(role="assistant", content="", tool_use_blocks=blocks),
            ],
            tool_calls=[record],
        )

        rows = db.messages_of(chat_id)
        assert [row["role"] for row in rows] == ["user", "assistant"]
        r = _REPLACEMENT
        stored_block = _tool_use("call_s1", query=f"in{r}voice", tags=[f"a{r}", {"k": r}])
        stored_block["input"][f"fil{r}ter"] = "from:muster"
        stored_block["input"]["nested"] = {f"k{r}": [{f"j{r}": "v"}]}
        stored_block[f"no{r}te"] = "x"
        assert rows[1]["tool_use_blocks"] == [stored_block]
        stored_record = _record(
            query=f"in{r}voice", filters={"from": [f"mu{r}ster"], f"t{r}o": ["me"]}
        )
        stored_record.args[f"li{r}mit"] = 5
        assert rows[1]["tool_calls"] == [stored_record.model_dump(mode="json")]

    async def test_chats_append_keeps_emoji_in_json_strings(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """A valid surrogate pair (a provider's escaped emoji decodes to one code point) is
        not a lone surrogate: stored unchanged, keys included."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        emoji = json.loads('"' + chr(92) + "ud83d" + chr(92) + 'ude00"')
        assert emoji == chr(0x1F600)
        blocks = [_tool_use("call_e1", query=f"party {emoji}", tags=[{emoji: emoji}])]

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            [LLMMessage(role="assistant", content="", tool_use_blocks=blocks)],
            tool_calls=[_record(query=f"party {emoji}")],
        )

        (row,) = db.messages_of(chat_id)
        assert row["tool_use_blocks"] == [
            _tool_use("call_e1", query=f"party {emoji}", tags=[{emoji: emoji}])
        ]
        assert row["tool_calls"] == [_record(query=f"party {emoji}").model_dump(mode="json")]

    # -- GH-266 (re-audit L-4): non-finite numbers in tool arguments --------------

    @pytest.mark.parametrize("value", list(_NON_FINITE.values()), ids=list(_NON_FINITE))
    async def test_chats_append_non_finite_tool_arguments_are_stored_as_null(
        self, chats: ModuleType, db: FakeDb, value: float
    ) -> None:
        """A model's tool input and the run's tool-call arguments holding NaN, Infinity,
        -Infinity or an overflowing 1e400 (top level and nested): the whole turn is stored
        (JSONB has no such number, so it failed after the tools had run) and each of them
        reads back as null in ``tool_use_blocks`` and in ``tool_calls``."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, created_at=_PAST)

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            _non_finite_turn(value),
            final_status="awaiting_confirmation",
            tool_calls=[_record(**_non_finite_args(value))],
        )

        rows = db.messages_of(chat_id)
        assert [(row["role"], row["status"]) for row in rows] == [
            ("user", "complete"),
            ("assistant", "complete"),
            ("tool", "complete"),
            ("assistant", "awaiting_confirmation"),
        ]
        assert rows[1]["tool_use_blocks"] == [_tool_use("call_f1", **_non_finite_args(None))]
        assert rows[3]["tool_calls"] == [_record(**_non_finite_args(None)).model_dump(mode="json")]
        row = db.chat_row(chat_id)
        assert row is not None
        assert row["last_activity_at"] > _PAST

    async def test_chats_append_non_finite_tool_arguments_keep_every_finite_value(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Arguments as a provider's JSON text parses (``json.loads``): only the non-finite
        numbers become null; finite floats (the largest included), ints, bools, null and
        strings that read "NaN" / "Infinity" / "1e400" are stored unchanged."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        parsed = json.loads(_PROVIDER_ARGS_TEXT)

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            [
                LLMMessage(role="user", content="Search"),
                LLMMessage(
                    role="assistant", content="", tool_use_blocks=[_tool_use("call_p1", **parsed)]
                ),
            ],
            tool_calls=[_record(**json.loads(_PROVIDER_ARGS_TEXT))],
        )

        rows = db.messages_of(chat_id)
        assert rows[1]["tool_use_blocks"] == [_tool_use("call_p1", **_PROVIDER_ARGS_STORED)]
        assert rows[1]["tool_calls"] == [_record(**_PROVIDER_ARGS_STORED).model_dump(mode="json")]

    async def test_chats_append_non_finite_json_text_sent_to_the_driver_is_strict(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Every JSON text bound to the INSERTs' ``tool_use_blocks`` and ``tool_calls`` is
        strict JSON: no NaN / Infinity token, no number that overflows a double."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.calls.clear()

        await chats.append_messages(
            db.pool,
            alice.tenant,
            chat_id,
            [
                LLMMessage(role="user", content="Search"),
                LLMMessage(
                    role="assistant",
                    content="",
                    tool_use_blocks=[_tool_use("call_j1", **json.loads(_PROVIDER_ARGS_TEXT))],
                ),
            ],
            tool_calls=[_record(**json.loads(_PROVIDER_ARGS_TEXT))],
        )

        texts = [
            binds[column]
            for binds in map(_insert_binds, db.matching(r"^insert into chat_messages\b"))
            for column in ("tool_use_blocks", "tool_calls")
            if binds[column] is not None
        ]
        assert len(texts) == 2
        assert [_strict_json(text) for text in texts] == [
            [_tool_use("call_j1", **_PROVIDER_ARGS_STORED)],
            [_record(**_PROVIDER_ARGS_STORED).model_dump(mode="json")],
        ]

    async def test_chats_append_runs_in_one_transaction_update_first(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """The chat UPDATE, then one INSERT per message, on one connection inside one
        committed transaction."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.calls.clear()

        await chats.append_messages(db.pool, alice.tenant, chat_id, _tool_turn("2 results"))

        calls = _chat_calls(db)
        verbs = [
            "update" if call.normalized.startswith("update chats") else call.normalized[:24]
            for call in calls
        ]
        assert verbs == ["update"] + ["insert into chat_message"] * 4
        assert {(call.via, call.tx) for call in calls} == {(calls[0].via, calls[0].tx)}
        assert calls[0].tx is not None
        assert (calls[0].tx, "commit") in db.transactions

    async def test_chats_append_failure_midway_rolls_everything_back(
        self, chats: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second INSERT fails: no message row, last_activity_at unchanged."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, created_at=_PAST)
        before = db.snapshot()
        inserts: list[str] = []
        original = db.handle

        def failing(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
            if norm(sql).startswith("insert into chat_messages"):
                inserts.append(sql)
                if len(inserts) == 2:
                    raise asyncpg.exceptions.DeadlockDetectedError("deadlock detected")
            return original(method, sql, args, via, tx)

        monkeypatch.setattr(db, "handle", failing)

        with pytest.raises(asyncpg.exceptions.DeadlockDetectedError):
            await chats.append_messages(db.pool, alice.tenant, chat_id, _tool_turn("2 results"))

        assert len(inserts) == 2
        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 9. load_recent_history
# ---------------------------------------------------------------------------


class TestLoadRecentHistory:
    """The latest messages as LLMMessages, chronological, no orphan tool results first."""

    async def test_chats_history_round_trip_preserves_the_tool_turn(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """What append_messages stored comes back equal (a restart round trip): the
        assistant's tool_use_blocks followed by the tool result with the same call id."""
        alice = _member(db)
        chat = await chats.create_chat(db.pool, alice.tenant)
        history = _tool_turn(_wrapped())

        await chats.append_messages(
            db.pool, alice.tenant, chat.id, history, tool_calls=[_record(query="invoice")]
        )
        loaded = await chats.load_recent_history(db.pool, alice.tenant, chat.id, limit=50)

        assert all(type(message) is LLMMessage for message in loaded)
        assert loaded == history

    @pytest.mark.parametrize(("limit", "start"), [(7, 0), (6, 1), (5, 4), (4, 4), (3, 4), (2, 5)])
    async def test_chats_history_is_the_latest_messages_without_leading_orphans(
        self, chats: ModuleType, db: FakeDb, limit: int, start: int
    ) -> None:
        """Seven messages (an assistant calling two tools at index 1): the latest ``limit``,
        minus the tool results whose assistant turn fell outside the window."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        history = _seven_message_history()
        _seed_history(db, chat_id, history)

        loaded = await chats.load_recent_history(db.pool, alice.tenant, chat_id, limit=limit)

        assert loaded == history[start:]
        assert {message.role for message in loaded} <= {"user", "assistant", "tool"}


# ---------------------------------------------------------------------------
# 10. read_chat_detail (GH-266: replaces list_messages and latest_message_status)
# ---------------------------------------------------------------------------

# The detail statements (contract §2.3): S2's owner check, the page (S9 / S9b), S10, S15.
_OWNER_CHECK_PREDICATES: Final = frozenset(
    {"id = $n", "org_id = $n", "owner_user_id = $n", "deleted_at is null"}
)
_OWNER_CHECK_RE: Final = re.compile(r"select .+ from chats(?: (?:as )?(?!where\b)\w+)? where (.+)")
_SELECT_MESSAGES_RE: Final = re.compile(r"select (?P<columns>.+?) from chat_messages\b.*")
_STATUS_READ_RE: Final = re.compile(
    r"select (?:\w+\.)?status from chat_messages(?: (?:as )?(?!where\b)\w+)? where .+"
    r" order by (?:\w+\.)?seq desc limit (?:1|\$\d+)"
)
_COUNT_READ_RE: Final = re.compile(r"select count\(\*\) from chat_messages where .+")


def _selects_content(call: Call) -> bool:
    """A SELECT of chat_messages whose column list holds ``content`` or a ``*`` (not the
    one of ``count(*)``)."""
    match = _SELECT_MESSAGES_RE.fullmatch(call.normalized)
    if match is None:
        return False
    columns = match.group("columns")
    return re.search(r"\bcontent\b", columns) is not None or "*" in columns.replace("count(*)", "")


def _detail_statement(call: Call) -> str:
    """A read_chat_detail statement's kind: "owner" (a SELECT from chats filtered by
    exactly id, org, owner and the live filter: S2), "status" (only ``status``, the highest
    seq: S15), "count" (S10), "page" (a SELECT of chat_messages with ``content``: S9 /
    S9b), else its SQL."""
    n = call.normalized
    if match := _OWNER_CHECK_RE.fullmatch(n):
        predicates = {
            re.sub(r"\$\d+", "$n", re.sub(r"^\w+\.", "", predicate.strip()))
            for predicate in match.group(1).split(" and ")
        }
        if predicates == _OWNER_CHECK_PREDICATES:
            return "owner"
    if _STATUS_READ_RE.fullmatch(n):
        return "status"
    if _COUNT_READ_RE.fullmatch(n):
        return "count"
    if _selects_content(call):
        return "page"
    return n


def _seed_statuses(db: FakeDb, chat_id: uuid.UUID, statuses: list[str]) -> list[int]:
    """One assistant message per status, in order; returns their seqs."""
    for index, status in enumerate(statuses):
        db.add_chat_message(chat_id, "assistant", f"m{index}", status=status)
    return [row["seq"] for row in db.messages_of(chat_id)]


class TestChatDetail:
    """The caller's chat with one page of its messages (the latest page ascending, the
    cursor walking back), its message count and its latest message's status."""

    async def test_chats_detail_returns_the_chat_latest_page_count_and_latest_status(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """The chat is the stored row; the page the latest three ascending with a cursor;
        the count all seven messages; the status the highest seq's."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id, title="Plans", created_at=_PAST)
        seqs = _seed_statuses(db, chat_id, [*["complete"] * 6, "limit_reached"])

        detail = await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=3, cursor=None)

        row = db.chat_row(chat_id)
        assert row is not None
        _assert_record_is_row(detail.chat, row)
        assert [record.seq for record in detail.page.messages] == seqs[-3:]
        assert isinstance(detail.page.next_cursor, str)
        assert (detail.message_count, type(detail.message_count)) == (7, int)
        assert detail.latest_status == "limit_reached"

    async def test_chats_detail_has_exactly_the_contract_fields_and_is_frozen(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)

        detail = await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=10, cursor=None)

        assert _field_names(detail) == _CHAT_DETAIL_FIELDS
        with pytest.raises((AttributeError, TypeError, ValueError)):
            detail.message_count = 99

    async def test_chats_messages_latest_page_is_ascending(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        _seed_history(db, chat_id, _seven_message_history())
        seqs = [row["seq"] for row in db.messages_of(chat_id)]

        detail = await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=3, cursor=None)

        assert [record.seq for record in detail.page.messages] == seqs[-3:]
        assert isinstance(detail.page.next_cursor, str)
        assert len(detail.page.next_cursor) <= 200

    async def test_chats_messages_records_carry_the_stored_fields(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Exactly the contract's fields, the JSON columns decoded, the stored values."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.add_chat_message(chat_id, "user", "Find it")
        db.add_chat_message(
            chat_id, "assistant", "", tool_use_blocks=[_tool_use("call_x", query="q")]
        )
        db.add_chat_message(chat_id, "tool", "result", tool_call_id="call_x")
        db.add_chat_message(
            chat_id,
            "assistant",
            "Done",
            tool_calls=[_record(query="q").model_dump(mode="json")],
            status="limit_reached",
        )

        detail = await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=10, cursor=None)

        page = detail.page
        assert all(_field_names(record) == _MESSAGE_RECORD_FIELDS for record in page.messages)
        expected = [
            {name: row[name] for name in _MESSAGE_RECORD_FIELDS} for row in db.messages_of(chat_id)
        ]
        assert [
            {name: getattr(record, name) for name in _MESSAGE_RECORD_FIELDS}
            for record in page.messages
        ] == expected
        assert page.next_cursor is None

    @pytest.mark.parametrize("limit", [1, 3])
    async def test_chats_messages_walk_returns_every_message_once_in_order(
        self, chats: ModuleType, db: FakeDb, limit: int
    ) -> None:
        """Each page ascending, each earlier than the one before, every message once."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        _seed_history(db, chat_id, _seven_message_history())
        other = db.add_chat(alice.user_id)
        db.add_chat_message(other, "user", "elsewhere")
        seqs = [row["seq"] for row in db.messages_of(chat_id)]

        pages, cursors = await _walk_messages(chats, db, alice.tenant, chat_id, limit)

        assert all(page == sorted(page) for page in pages)
        assert [seq for page in reversed(pages) for seq in page] == seqs
        assert all(len(page) == limit for page in pages[:-1])
        assert all(isinstance(cursor, str) and len(cursor) <= 200 for cursor in cursors[:-1])

    async def test_chats_detail_count_and_latest_status_are_the_chats_on_every_page(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Walking back with the cursor, every detail carries the chat's count and its
        latest message's status, never the page's (each earlier page ends otherwise)."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        _seed_statuses(
            db, chat_id, ["complete", "awaiting_confirmation", "error", "complete", "stopped"]
        )

        details = await _walk_details(chats, db, alice.tenant, chat_id, 2)

        assert [len(detail.page.messages) for detail in details] == [2, 2, 1]
        assert [(detail.message_count, detail.latest_status) for detail in details] == [
            (5, "stopped")
        ] * 3

    @pytest.mark.parametrize("total", [0, 3])
    async def test_chats_messages_beginning_has_no_cursor(
        self, chats: ModuleType, db: FakeDb, total: int
    ) -> None:
        """An empty chat, or exactly ``limit`` messages: no earlier page."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        for index in range(total):
            db.add_chat_message(chat_id, "user", f"m{index}")

        detail = await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=3, cursor=None)

        assert len(detail.page.messages) == total
        assert detail.page.next_cursor is None

    @pytest.mark.parametrize("cursor", _GARBAGE_CURSORS)
    async def test_chats_messages_bad_cursor_is_invalid(
        self, chats: ModuleType, db: FakeDb, cursor: str
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.add_chat_message(chat_id, "user", "Hello")

        with pytest.raises(chats.InvalidCursorError):
            await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=10, cursor=cursor)

    async def test_chats_messages_truncated_cursor_is_invalid(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        cursor = await _message_cursor(chats, db, alice)
        chat_id = db.add_chat(alice.user_id)

        with pytest.raises(chats.InvalidCursorError):
            await chats.read_chat_detail(
                db.pool, alice.tenant, chat_id, limit=10, cursor=cursor[:-4]
            )

    async def test_chats_messages_refuse_a_list_cursor(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        cursor = await _list_cursor(chats, db, alice)
        chat_id = db.add_chat(alice.user_id)
        db.add_chat_message(chat_id, "user", "Hello")

        with pytest.raises(chats.InvalidCursorError):
            await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=10, cursor=cursor)

    @pytest.mark.parametrize(
        "seq",
        [
            pytest.param(2**63, id="bigint-max-plus-1"),
            pytest.param(10**40, id="10-to-the-40"),
            pytest.param(-1, id="negative"),
        ],
    )
    async def test_chats_messages_cursor_seq_outside_bigint_is_invalid(
        self, chats: ModuleType, db: FakeDb, seq: int
    ) -> None:
        """Security audit L-1: a crafted cursor whose seq decodes but no BIGINT holds
        (asyncpg's DataError, a 500) is ``InvalidCursorError``, refused before a
        statement binds it; a negative seq too."""
        alice = _member(db)
        crafted = _crafted(await _message_cursor(chats, db, alice), _is_seq, seq)
        chat_id = db.add_chat(alice.user_id)
        db.add_chat_message(chat_id, "user", "Hello")
        db.calls.clear()

        with pytest.raises(chats.InvalidCursorError):
            await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=10, cursor=crafted)

        assert not any(seq in call.args for call in db.calls)

    # -- GH-266: the owner check once, the status without the row --------------

    @pytest.mark.parametrize("with_cursor", [False, True], ids=["latest-page", "cursor-page"])
    async def test_chats_detail_runs_the_owner_check_once_and_first(
        self, chats: ModuleType, db: FakeDb, with_cursor: bool
    ) -> None:
        """S2 exactly once and before anything else, then the page, the count and the
        status read, one statement each."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        _seed_history(db, chat_id, _seven_message_history())
        cursor = None
        if with_cursor:
            first = await chats.read_chat_detail(
                db.pool, alice.tenant, chat_id, limit=2, cursor=None
            )
            cursor = first.page.next_cursor
        db.calls.clear()

        await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=2, cursor=cursor)

        kinds = [_detail_statement(call) for call in db.calls]
        assert kinds[:1] == ["owner"]
        assert Counter(kinds) == Counter({"owner": 1, "page": 1, "count": 1, "status": 1})

    async def test_chats_detail_reads_the_latest_status_without_the_row(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """S15 selects only ``status`` of the chat's highest seq (bound to the chat and
        the caller's org): the page is the one statement that fetches ``content``."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        _seed_statuses(db, chat_id, ["complete", "awaiting_confirmation"])
        db.calls.clear()

        detail = await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=10, cursor=None)

        (status_read,) = [call for call in db.calls if _detail_statement(call) == "status"]
        assert _uuids(status_read.args) == {chat_id, ORG_ID}
        assert [_detail_statement(call) for call in db.calls if _selects_content(call)] == ["page"]
        assert detail.latest_status == "awaiting_confirmation"

    @pytest.mark.parametrize("cursor", [None, "not-a-cursor"], ids=["no-cursor", "bad-cursor"])
    @pytest.mark.parametrize("case", _NOT_FOUND_CASES)
    async def test_chats_detail_not_found_runs_only_the_owner_check(
        self, chats: ModuleType, db: FakeDb, case: str, cursor: str | None
    ) -> None:
        """Another org's, another user's, a trashed or an unknown chat: ChatNotFoundError
        after S2 alone, also with a bad cursor (the owner check comes first)."""
        world = _world(db)
        db.calls.clear()

        with pytest.raises(chats.ChatNotFoundError) as caught:
            await chats.read_chat_detail(
                db.pool, world.alice.tenant, _target(world, case), limit=10, cursor=cursor
            )

        assert type(caught.value) is chats.ChatNotFoundError
        assert [_detail_statement(call) for call in db.calls] == ["owner"]

    async def test_chats_detail_invalid_cursor_runs_only_the_owner_check(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """The caller's own chat with a bad cursor: InvalidCursorError after S2, nothing
        else runs."""
        world = _world(db)
        db.calls.clear()

        with pytest.raises(chats.InvalidCursorError):
            await chats.read_chat_detail(
                db.pool, world.alice.tenant, world.chat, limit=10, cursor="not-a-cursor"
            )

        assert [_detail_statement(call) for call in db.calls] == ["owner"]


# ---------------------------------------------------------------------------
# 11. The message count and the latest message status
# ---------------------------------------------------------------------------


class TestCounts:
    """Per-chat counts and the latest status (by seq, through read_chat_detail)."""

    async def test_chats_latest_status_is_the_highest_seq(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """The newest seq wins, whatever the created_at order."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.add_chat_message(chat_id, "user", "a", created_at=_PAST + timedelta(hours=2))
        db.add_chat_message(
            chat_id, "assistant", "b", status="stopped", created_at=_PAST + timedelta(hours=1)
        )
        db.add_chat_message(
            chat_id, "assistant", "c", status="awaiting_confirmation", created_at=_PAST
        )

        detail = await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=10, cursor=None)

        assert detail.latest_status == "awaiting_confirmation"

    async def test_chats_latest_status_of_an_empty_chat_is_none(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.add_chat_message(db.add_chat(alice.user_id), "assistant", "x", status="error")

        detail = await chats.read_chat_detail(db.pool, alice.tenant, chat_id, limit=10, cursor=None)

        assert (detail.latest_status, detail.message_count) == (None, 0)


# ---------------------------------------------------------------------------
# 12. append_org_notice and count_org_chats
# ---------------------------------------------------------------------------


def _org_chats(db: FakeDb) -> dict[str, Any]:
    """ORG_ID: Alice (two live, one trashed), Bob and a Viewer (one live each);
    OTHER_ORG_ID: Carol (one live). Every chat's last activity is in the past."""
    alice, bob, viewer = _member(db), _member(db), _member(db, role="viewer")
    carol = _member(db, org_id=OTHER_ORG_ID)
    live = [
        db.add_chat(alice.user_id, created_at=_PAST),
        db.add_chat(alice.user_id, created_at=_PAST),
        db.add_chat(bob.user_id, created_at=_PAST),
        db.add_chat(viewer.user_id, created_at=_PAST),
    ]
    trashed = db.add_chat(alice.user_id, created_at=_PAST, deleted_at=_PAST)
    foreign = db.add_chat(carol.user_id, created_at=_PAST)
    return {"alice": alice, "bob": bob, "live": live, "trashed": trashed, "foreign": foreign}


# GH-24: the two ways a chat's latest message awaits a confirmation.
_AWAITING_KINDS: Final = ("assistant-tool-use", "batch-tool-row")
# S12a: the lock on the org's live chats, in id order, waiting (no SKIP LOCKED / NOWAIT).
_NOTICE_LOCK_RE: Final = re.compile(
    r"select (?:\w+\.)?id from chats(?: (?:as )?(?!where\b)\w+)? where (?P<where>.+)"
    r" order by (?:\w+\.)?id for update"
)


@dataclass(frozen=True)
class _NoticeWorld:
    """Alice (the caller) and Bob in ORG_ID, Carol in OTHER_ORG_ID. ``skipped``: the
    org's live chats whose latest message awaits a confirmation; ``receiving``: the
    org's other live chats; ``never``: a trashed chat and another org's chat."""

    alice: _Member
    skipped: dict[str, uuid.UUID]
    receiving: dict[str, uuid.UUID]
    never: dict[str, uuid.UUID]

    @property
    def chats(self) -> dict[str, uuid.UUID]:
        return {**self.skipped, **self.receiving, **self.never}


def _ask(db: FakeDb, chat_id: uuid.UUID, call_id: str) -> None:
    """A user request and the assistant's tool call, stored awaiting its confirmation."""
    db.add_chat_message(chat_id, "user", "Send the summary to Muster AG")
    db.add_chat_message(
        chat_id,
        "assistant",
        "",
        tool_use_blocks=[_tool_use(call_id, query="summary")],
        status="awaiting_confirmation",
    )


def _chat(db: FakeDb, member: _Member, **fields: Any) -> uuid.UUID:
    return db.add_chat(member.user_id, created_at=_PAST, **fields)


def _notice_world(db: FakeDb) -> _NoticeWorld:
    alice, bob = _member(db), _member(db)
    carol = _member(db, org_id=OTHER_ORG_ID)
    tool_use = _chat(db, alice)
    _ask(db, tool_use, "call_w1")
    # A batch: the first call ran, the second awaits; the first call's tool row is the
    # latest message and carries the turn's final status.
    batch = _chat(db, bob)
    db.add_chat_message(batch, "user", "Search both mailboxes")
    db.add_chat_message(
        batch,
        "assistant",
        "",
        tool_use_blocks=[_tool_use("call_w2", query="a"), _tool_use("call_w3", query="b")],
    )
    db.add_chat_message(
        batch, "tool", "2 results", tool_call_id="call_w2", status="awaiting_confirmation"
    )
    approved = _chat(db, alice)
    _ask(db, approved, "call_w4")
    db.add_chat_message(approved, "tool", "Sent.", tool_call_id="call_w4")
    denied = _chat(db, bob)
    _ask(db, denied, "call_w5")
    db.add_chat_message(denied, "tool", "Tool call denied by user.", tool_call_id="call_w5")
    db.add_chat_message(denied, "assistant", "I did not send it.")
    next_turn = _chat(db, alice)
    _ask(db, next_turn, "call_w6")
    db.add_chat_message(next_turn, "tool", "Tool call cancelled.", tool_call_id="call_w6")
    db.add_chat_message(next_turn, "user", "Never mind")
    db.add_chat_message(next_turn, "assistant", "Fine.")
    empty = _chat(db, alice)
    plain_chat = _chat(db, bob)
    trashed = _chat(db, alice, deleted_at=_PAST)
    foreign = _chat(db, carol)
    for chat_id in (plain_chat, trashed, foreign):
        db.add_chat_message(chat_id, "user", "Hello")
        db.add_chat_message(chat_id, "assistant", "Hi there")
    return _NoticeWorld(
        alice=alice,
        skipped={"assistant-tool-use": tool_use, "batch-tool-row": batch},
        receiving={
            "approved": approved,
            "denied": denied,
            "next-turn": next_turn,
            "empty": empty,
            "plain": plain_chat,
        },
        never={"trashed": trashed, "other-org": foreign},
    )


def _appended(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> Any:
    """The rows stored after ``before`` as (role, content, status, tool_use_blocks,
    tool_call_id, tool_calls), or ``"history changed"`` when a row of ``before`` is
    gone, moved or altered."""
    if after[: len(before)] != before:
        return "history changed"
    return [
        (
            row["role"],
            row["content"],
            row["status"],
            row["tool_use_blocks"],
            row["tool_call_id"],
            row["tool_calls"],
        )
        for row in after[len(before) :]
    ]


def _notice_statement(call: Call) -> tuple[str, tuple[Any, ...]]:
    """A notice statement as ("lock" | "insert" | its SQL, its binds with UUIDs plain).

    "lock": S12a with exactly the org and live-chat predicates; "insert": an INSERT
    into chat_messages.
    """
    n = call.normalized
    kind = n
    if match := _NOTICE_LOCK_RE.fullmatch(n):
        predicates = {
            re.sub(r"^\w+\.", "", predicate.strip())
            for predicate in match.group("where").split(" and ")
        }
        if predicates == {"org_id = $1", "deleted_at is null"}:
            kind = "lock"
    elif n.startswith("insert into chat_messages "):
        kind = "insert"
    return kind, tuple(_as_uuid(arg) or arg for arg in call.args)


class _AcquireOnlyPool:
    """A pool that only hands out connections (``acquire()``, as asyncpg.Pool): a
    statement run on the pool itself, outside a transaction, fails."""

    def __init__(self, db: FakeDb) -> None:
        self._pool = db.pool

    def acquire(self) -> Any:
        return self._pool.acquire()


class TestOrgNotice:
    """GH-66's promotion notice: one user message in every live chat of the org, except
    a chat whose latest message awaits a confirmation (GH-24)."""

    async def test_chats_org_notice_reaches_every_live_chat_of_the_org(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Called with Bob's context, Alice's and the Viewer's chats get it too; the text
        verbatim, role user, status complete, no tool fields."""
        world = _org_chats(db)
        notice = "Your role changed: you are now an Org Admin.\nReload to see the new tools."

        await chats.append_org_notice(db.pool, world["bob"].tenant, notice)

        for chat_id in world["live"]:
            (row,) = db.messages_of(chat_id)
            assert (
                row["role"],
                row["content"],
                row["status"],
                row["tool_use_blocks"],
                row["tool_call_id"],
                row["tool_calls"],
            ) == ("user", notice, "complete", None, None, None)

    async def test_chats_org_notice_skips_trashed_and_other_org_chats(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        world = _org_chats(db)

        await chats.append_org_notice(db.pool, world["alice"].tenant, _MARK_NOTICE)

        assert db.messages_of(world["trashed"]) == []
        assert db.messages_of(world["foreign"]) == []

    async def test_chats_org_notice_keeps_last_activity(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        world = _org_chats(db)

        await chats.append_org_notice(db.pool, world["alice"].tenant, _MARK_NOTICE)

        rows = [db.chat_row(chat_id) for chat_id in world["live"]]
        assert {row["last_activity_at"] for row in rows if row is not None} == {_PAST}
        assert None not in rows

    async def test_chats_org_notice_returns_the_count(self, chats: ModuleType, db: FakeDb) -> None:
        world = _org_chats(db)
        lonely = _member(db, org_id=uuid.uuid4())

        count = await chats.append_org_notice(db.pool, world["alice"].tenant, _MARK_NOTICE)
        none = await chats.append_org_notice(db.pool, lonely.tenant, _MARK_NOTICE)

        assert (count, none) == (4, 0)
        assert (type(count), type(none)) == (int, int)

    # -- GH-24: never in a chat awaiting a confirmation, under a row lock ----------

    async def test_chats_org_notice_skips_chats_whose_latest_message_awaits_confirmation(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Alice's chat ending with the assistant's tool call and Bob's batch ending with a
        tool row, both awaiting, get nothing; an approved, a denied and a moved-on chat, an
        empty one and a plain colleague's chat each get one plain user message after their
        history; the trashed and the other org's chat never."""
        world = _notice_world(db)
        before = {name: db.messages_of(chat_id) for name, chat_id in world.chats.items()}

        await chats.append_org_notice(db.pool, world.alice.tenant, _MARK_NOTICE)

        appended = {
            name: _appended(before[name], db.messages_of(chat_id))
            for name, chat_id in world.chats.items()
        }
        notice = ("user", _MARK_NOTICE, "complete", None, None, None)
        assert appended == {
            name: [notice] if name in world.receiving else [] for name in world.chats
        }

    async def test_chats_org_notice_decides_by_the_latest_messages_status_only(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """One chat per status of its latest message (an earlier message awaiting in each):
        only a latest ``awaiting_confirmation`` is skipped."""
        alice = _member(db)
        by_status: dict[str, uuid.UUID] = {}
        for status in _STATUSES:
            chat_id = _chat(db, alice)
            db.add_chat_message(chat_id, "assistant", "earlier", status="awaiting_confirmation")
            db.add_chat_message(chat_id, "assistant", "latest", status=status)
            by_status[status] = chat_id

        await chats.append_org_notice(db.pool, alice.tenant, _MARK_NOTICE)

        added = {
            status: [row["content"] for row in db.messages_of(chat_id)[2:]]
            for status, chat_id in by_status.items()
        }
        assert added == {
            status: [] if status == "awaiting_confirmation" else [_MARK_NOTICE]
            for status in _STATUSES
        }

    @pytest.mark.parametrize("kind", _AWAITING_KINDS)
    async def test_chats_org_notice_leaves_an_awaiting_chat_exactly_as_stored(
        self, chats: ModuleType, db: FakeDb, kind: str
    ) -> None:
        """Every stored row (ids, seq order, tool fields, statuses) and the chats row as they
        were: the pending call's ``tool_use`` stays the chat's last turn."""
        world = _notice_world(db)
        chat_id = world.skipped[kind]
        before = (db.chat_row(chat_id), db.messages_of(chat_id))

        await chats.append_org_notice(db.pool, world.alice.tenant, _MARK_NOTICE)

        assert (db.chat_row(chat_id), db.messages_of(chat_id)) == before

    async def test_chats_org_notice_count_excludes_skipped_chats(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        world = _notice_world(db)

        count = await chats.append_org_notice(db.pool, world.alice.tenant, _MARK_NOTICE)

        assert (count, type(count)) == (len(world.receiving), int)

    async def test_chats_org_notice_locks_the_orgs_live_chats_then_inserts_in_one_transaction(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Exactly two statements: the lock (S12a: org and live filter only, id order, FOR
        UPDATE without SKIP LOCKED / NOWAIT, binds the org), then the INSERT (binds the org
        and the text); no chat or user id bound; both on one connection acquired from the
        pool, inside one committed transaction."""
        world = _notice_world(db)
        db.calls.clear()

        await chats.append_org_notice(db.pool, world.alice.tenant, _MARK_NOTICE)

        assert [_notice_statement(call) for call in db.calls] == [
            ("lock", (ORG_ID,)),
            ("insert", (ORG_ID, _MARK_NOTICE)),
        ]
        sites = {(call.via, call.tx) for call in db.calls}
        assert len(sites) == 1
        ((via, tx),) = sites
        assert via.startswith("conn-")
        assert tx is not None
        assert db.transactions == [(tx, "commit")]

    async def test_chats_org_notice_skips_a_chat_whose_turn_committed_while_the_lock_waited(
        self, chats: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#176 audit I-5: a turn storing ``tool_use`` + awaiting holds the chat's row, so
        the lock waits until it commits; the INSERT then sees the awaiting message and
        skips that chat (emulated: the turn's rows land while the lock statement runs)."""
        world = _notice_world(db)
        chat_id = world.receiving["plain"]
        turns: list[str] = []
        original = db.handle

        def turn_commits_first(
            method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None
        ) -> Any:
            if not turns and re.search(r"\bfor update\b", norm(sql)):
                turns.append(sql)
                _ask(db, chat_id, "call_w7")
            return original(method, sql, args, via, tx)

        monkeypatch.setattr(db, "handle", turn_commits_first)

        count = await chats.append_org_notice(db.pool, world.alice.tenant, _MARK_NOTICE)

        rows = db.messages_of(chat_id)
        assert ([(row["role"], row["status"]) for row in rows], count) == (
            [
                ("user", "complete"),
                ("assistant", "complete"),
                ("user", "complete"),
                ("assistant", "awaiting_confirmation"),
            ],
            len(world.receiving) - 1,
        )

    async def test_chats_org_notice_failed_insert_rolls_back_and_propagates(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """The INSERT fails after the lock: the driver error propagates, the one
        transaction is rolled back, nothing is stored."""
        world = _notice_world(db)
        before = db.snapshot()
        db.calls.clear()
        db.fail_sql = r"^insert into chat_messages\b"

        with pytest.raises(asyncpg.exceptions.DeadlockDetectedError):
            await chats.append_org_notice(db.pool, world.alice.tenant, _MARK_NOTICE)

        assert [_notice_statement(call)[0] for call in db.calls] == ["lock", "insert"]
        sites = {(call.via, call.tx) for call in db.calls}
        assert len(sites) == 1
        ((_, tx),) = sites
        assert tx is not None
        assert (db.transactions, db.open_transactions) == (
            [(tx, "rollback:DeadlockDetectedError")],
            0,
        )
        assert db.snapshot() == before

    async def test_chats_org_notice_runs_on_a_connection_it_acquires_from_the_pool(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """The first parameter is the pool: the function acquires its own connection and
        runs nothing on the pool itself."""
        world = _notice_world(db)

        count = await chats.append_org_notice(
            _AcquireOnlyPool(db), world.alice.tenant, _MARK_NOTICE
        )

        assert count == len(world.receiving)
        assert all(call.via.startswith("conn-") for call in db.calls)


class TestCountOrgChats:
    """Platform metadata: the org's chats that aren't trashed, a count only."""

    async def test_chats_count_org_chats_counts_live_chats_of_the_org(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        _org_chats(db)

        counts = [
            await chats.count_org_chats(db.pool, org_id)
            for org_id in (ORG_ID, OTHER_ORG_ID, uuid.uuid4())
        ]

        assert counts == [4, 1, 0]
        assert all(type(count) is int for count in counts)


# ---------------------------------------------------------------------------
# 13. Cascade
# ---------------------------------------------------------------------------


class TestCascade:
    """Deleting a user deletes their chats and messages (ON DELETE CASCADE)."""

    async def test_chats_deleting_a_user_removes_their_chats_and_messages(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice, bob = _member(db), _member(db)
        mine = await chats.create_chat(db.pool, alice.tenant, title="Mine")
        theirs = await chats.create_chat(db.pool, bob.tenant, title="Theirs")
        for member, chat in ((alice, mine), (bob, theirs)):
            await chats.append_messages(
                db.pool, member.tenant, chat.id, [LLMMessage(role="user", content="Hi")]
            )

        await db.pool.execute(
            "DELETE FROM users WHERE id = $1 AND org_id = $2", alice.user_id, ORG_ID
        )

        assert (db.chats_of(alice.user_id), db.messages_of(mine.id)) == ([], [])
        assert [plain(row["id"]) for row in db.chats_of(bob.user_id)] == [plain(theirs.id)]
        assert len(db.messages_of(theirs.id)) == 1


# ---------------------------------------------------------------------------
# 14. Logs
# ---------------------------------------------------------------------------


class TestLogs:
    """No title, content, notice or legacy session id in any log line."""

    async def test_chats_logs_no_title_content_or_session_id(
        self,
        chats: ModuleType,
        db: FakeDb,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A full flow plus the error paths whose driver errors carry the row (a too-long
        title's CHECK, the legacy key's unique violation, a failed write, a failed audit),
        at DEBUG, as an operator's log would show it."""
        with configured_logging("DEBUG", "text") as captured:
            await self._full_flow(chats, db, monkeypatch)

        texts = [captured.text]
        for record in captured.records:
            texts.append(record.getMessage())
            if record.exc_info and record.exc_info[1] is not None:
                texts.append(str(record.exc_info[1]))
        leaked = [
            marker
            for marker in (
                _MARK_TITLE,
                _MARK_CONTENT,
                _MARK_NOTICE,
                _MARK_SESSION,
                _MARK_RACE_SESSION,
            )
            if any(marker in text for text in texts)
        ]
        assert leaked == []
        assert db.audit_rows("chat.delete"), "the flow must reach the trash path"
        assert _MARK_TITLE not in json.dumps(db.audit, default=str)

    @staticmethod
    async def _full_flow(chats: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch) -> None:
        alice = _member(db)
        pool, tenant = db.pool, alice.tenant
        chat = await chats.create_chat(pool, tenant, title=_MARK_TITLE)
        await chats.rename_chat(pool, tenant, chat.id, f"{_MARK_TITLE} v2")
        turn = _tool_turn(_wrapped(_MARK_CONTENT))
        await chats.append_messages(
            pool,
            tenant,
            chat.id,
            turn,
            final_status="awaiting_confirmation",
            tool_calls=[_record(query=_MARK_CONTENT)],
        )
        await chats.list_chats(pool, tenant, limit=10, cursor=None)
        await chats.load_recent_history(pool, tenant, chat.id, limit=10)
        await chats.read_chat_detail(pool, tenant, chat.id, limit=1, cursor=None)
        await chats.append_org_notice(pool, tenant, _MARK_NOTICE)
        await chats.get_or_create_legacy_chat(pool, tenant, _MARK_SESSION, chat_id=uuid.uuid4())
        await chats.find_legacy_chat(pool, tenant, _MARK_SESSION)
        await chats.count_org_chats(pool, ORG_ID)
        with contextlib.suppress(Exception):
            await chats.rename_chat(pool, tenant, chat.id, _MARK_TITLE * 20)
        with contextlib.suppress(Exception):
            await chats.get_chat(pool, tenant, _UNKNOWN_CHAT)
        with contextlib.suppress(Exception):
            await chats.find_legacy_chat(pool, tenant, f"{_MARK_SESSION}x")
        db.fail_sql = r"^insert into chat_messages\b"
        with contextlib.suppress(Exception):
            await chats.append_messages(pool, tenant, chat.id, turn)
        db.fail_sql = None
        db.fail_audit = True
        with contextlib.suppress(Exception):
            await chats.trash_chat(pool, tenant, chat.id, ip=_IP)
        db.fail_audit = False
        await chats.trash_chat(pool, tenant, chat.id, ip=_IP)
        _race_legacy_insert(monkeypatch, db, alice.user_id, _MARK_RACE_SESSION)
        await chats.get_or_create_legacy_chat(
            pool, tenant, _MARK_RACE_SESSION, chat_id=uuid.uuid4()
        )
