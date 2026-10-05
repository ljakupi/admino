"""Tests for admino.chats: persisted, owner-private chats and their messages (GH-176).

The real ``admino.chats`` repository runs against the in-memory ``chats`` and
``chat_messages`` tables of tests/db_fakes.py (migration 0024: defaults, the
identity ``seq``, the CHECKs, the composite (chat_id, org_id) foreign key, the
partial unique legacy session index, PostgreSQL's U+0000 refusal, JSONB as JSON
text, the cascades from users). The fake applies only the predicates a
statement states, so a query without its owner, org or ``deleted_at IS NULL``
filter returns rows it must not.

What these tests pin down (contract §2):
- Surface: the fourteen coroutine functions with the contract's keyword-only
  parameters; ``ChatNotFoundError`` is a ``LookupError``, ``InvalidCursorError``
  a ``ValueError``; ``ChatRecord`` / ``MessageRecord`` carry exactly the
  contract's fields and are frozen.
- Tenant isolation (owner-private V1): for every function that takes a chat id
  (get, rename, trash, append, load history, list messages, count, latest
  status), another org's chat, another user's chat in the same org, a trashed
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
  propagate.
- ``list_chats``: the caller's live chats by ``last_activity_at DESC, id DESC``
  (ties by id), at most ``limit``, ``next_cursor`` None on the last page
  (exactly ``limit`` left included), walking the cursors returns every live
  chat exactly once in order (microsecond-apart stamps and ties across a page
  boundary); cursors are strings of at most 200 characters; garbage, a
  truncated cursor and a message cursor are ``InvalidCursorError``.
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
  from every string (keys included) inside the JSON values; a ``system``
  message is a ``ValueError`` with nothing written; an empty list runs no
  statement; a failure midway rolls everything back.
- ``load_recent_history``: the latest ``limit`` messages in chronological order
  as ``LLMMessage``s equal to what was appended (the tool turn's pairing kept),
  leading orphan ``tool`` messages of the tail dropped.
- ``list_messages``: the latest page ascending, ``next_cursor`` to earlier
  messages, None at the beginning; walking returns every message once in order;
  bad and list cursors are ``InvalidCursorError``.
- ``count_messages``, ``latest_message_status`` (highest seq; None when empty),
  ``append_org_notice`` (one user/complete message, the text verbatim, in every
  live chat of the org, of every member; none in another org's or a trashed
  chat; ``last_activity_at`` unchanged; returns the count) and
  ``count_org_chats`` (the org's live chats).
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
import contextlib
import dataclasses
import inspect
import json
import re
import uuid
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
_CHAT_ID_FUNCTIONS: Final = (
    "get_chat",
    "rename_chat",
    "trash_chat",
    "append_messages",
    "load_recent_history",
    "list_messages",
    "count_messages",
    "latest_message_status",
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
    "get_or_create_legacy_chat": (3, set()),
    "find_legacy_chat": (3, set()),
    "list_chats": (2, {"limit", "cursor"}),
    "rename_chat": (4, set()),
    "trash_chat": (3, {"ip"}),
    "append_messages": (4, {"final_status", "tool_calls"}),
    "load_recent_history": (3, {"limit"}),
    "list_messages": (3, {"limit", "cursor"}),
    "count_messages": (3, set()),
    "latest_message_status": (3, set()),
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
    if name == "list_messages":
        return await chats.list_messages(pool, tenant, chat_id, limit=10, cursor=None)
    if name == "count_messages":
        return await chats.count_messages(pool, tenant, chat_id)
    assert name == "latest_message_status"
    return await chats.latest_message_status(pool, tenant, chat_id)


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


async def _walk_messages(
    chats: ModuleType, db: FakeDb, tenant: TenantContext, chat_id: uuid.UUID, limit: int
) -> tuple[list[list[int]], list[Any]]:
    """Every page of list_messages (seqs, as returned) and every cursor seen on the way."""
    pages: list[list[int]] = []
    cursors: list[Any] = []
    cursor: str | None = None
    for _ in range(50):
        page = await chats.list_messages(db.pool, tenant, chat_id, limit=limit, cursor=cursor)
        pages.append([record.seq for record in page.messages])
        cursor = page.next_cursor
        cursors.append(cursor)
        if cursor is None:
            return pages, cursors
    msg = "the cursor walk never ended"
    raise AssertionError(msg)


async def _message_cursor(chats: ModuleType, db: FakeDb, member: _Member) -> str:
    """A real cursor of list_messages (a chat with two messages, limit 1)."""
    chat_id = db.add_chat(member.user_id)
    db.add_chat_message(chat_id, "user", "one")
    db.add_chat_message(chat_id, "assistant", "two")
    page = await chats.list_messages(db.pool, member.tenant, chat_id, limit=1, cursor=None)
    assert isinstance(page.next_cursor, str)
    return page.next_cursor


async def _list_cursor(chats: ModuleType, db: FakeDb, member: _Member) -> str:
    """A real cursor of list_chats (two chats, limit 1)."""
    db.add_chat(member.user_id, last_activity_at=_STAMP)
    db.add_chat(member.user_id, last_activity_at=_STAMP + _US)
    page = await chats.list_chats(db.pool, member.tenant, limit=1, cursor=None)
    assert isinstance(page.next_cursor, str)
    return page.next_cursor


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

        if name in _CHAT_ID_FUNCTIONS and name != "list_messages":
            await _call_with_chat(chats, db, name, alice.tenant, world.chat)
        elif name == "list_messages":
            page = await chats.list_messages(pool, alice.tenant, world.chat, limit=1, cursor=None)
            await chats.list_messages(
                pool, alice.tenant, world.chat, limit=1, cursor=page.next_cursor
            )
        elif name == "create_chat":
            await chats.create_chat(pool, alice.tenant, title="New")
        elif name == "get_or_create_legacy_chat":
            await chats.get_or_create_legacy_chat(pool, alice.tenant, "fresh-session")
            await chats.get_or_create_legacy_chat(pool, alice.tenant, "fresh-session")
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
        record = await chats.get_or_create_legacy_chat(db.pool, world.alice.tenant, _SESSION)

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

        first = await chats.get_or_create_legacy_chat(db.pool, alice.tenant, _SESSION)
        second = await chats.get_or_create_legacy_chat(db.pool, alice.tenant, _SESSION)

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

        mine = await chats.get_or_create_legacy_chat(db.pool, alice.tenant, _SESSION)
        theirs = await chats.get_or_create_legacy_chat(db.pool, other.tenant, _SESSION)

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

        record = await chats.get_or_create_legacy_chat(db.pool, alice.tenant, _SESSION)

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

        record = await chats.get_or_create_legacy_chat(db.pool, alice.tenant, _SESSION)

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
            await chats.get_or_create_legacy_chat(db.pool, alice.tenant, _SESSION)

        assert db.chats_of(alice.user_id) == []


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
        for name in ("get_chat", "list_messages", "load_recent_history", "count_messages"):
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
# 10. list_messages
# ---------------------------------------------------------------------------


class TestListMessages:
    """The latest page ascending; the cursor walks back to the beginning."""

    async def test_chats_messages_latest_page_is_ascending(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        _seed_history(db, chat_id, _seven_message_history())
        seqs = [row["seq"] for row in db.messages_of(chat_id)]

        page = await chats.list_messages(db.pool, alice.tenant, chat_id, limit=3, cursor=None)

        assert [record.seq for record in page.messages] == seqs[-3:]
        assert isinstance(page.next_cursor, str)
        assert len(page.next_cursor) <= 200

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

        page = await chats.list_messages(db.pool, alice.tenant, chat_id, limit=10, cursor=None)

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

    @pytest.mark.parametrize("total", [0, 3])
    async def test_chats_messages_beginning_has_no_cursor(
        self, chats: ModuleType, db: FakeDb, total: int
    ) -> None:
        """An empty chat, or exactly ``limit`` messages: no earlier page."""
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        for index in range(total):
            db.add_chat_message(chat_id, "user", f"m{index}")

        page = await chats.list_messages(db.pool, alice.tenant, chat_id, limit=3, cursor=None)

        assert len(page.messages) == total
        assert page.next_cursor is None

    @pytest.mark.parametrize("cursor", _GARBAGE_CURSORS)
    async def test_chats_messages_bad_cursor_is_invalid(
        self, chats: ModuleType, db: FakeDb, cursor: str
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.add_chat_message(chat_id, "user", "Hello")

        with pytest.raises(chats.InvalidCursorError):
            await chats.list_messages(db.pool, alice.tenant, chat_id, limit=10, cursor=cursor)

    async def test_chats_messages_truncated_cursor_is_invalid(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        cursor = await _message_cursor(chats, db, alice)
        chat_id = db.add_chat(alice.user_id)

        with pytest.raises(chats.InvalidCursorError):
            await chats.list_messages(db.pool, alice.tenant, chat_id, limit=10, cursor=cursor[:-4])

    async def test_chats_messages_refuse_a_list_cursor(self, chats: ModuleType, db: FakeDb) -> None:
        alice = _member(db)
        cursor = await _list_cursor(chats, db, alice)
        chat_id = db.add_chat(alice.user_id)
        db.add_chat_message(chat_id, "user", "Hello")

        with pytest.raises(chats.InvalidCursorError):
            await chats.list_messages(db.pool, alice.tenant, chat_id, limit=10, cursor=cursor)


# ---------------------------------------------------------------------------
# 11. count_messages and latest_message_status
# ---------------------------------------------------------------------------


class TestCounts:
    """Per-chat counts and the latest status (by seq)."""

    async def test_chats_count_messages_counts_only_this_chat(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id, other, empty = (db.add_chat(alice.user_id) for _ in range(3))
        for index in range(4):
            db.add_chat_message(chat_id, "user", f"m{index}")
        db.add_chat_message(other, "user", "elsewhere")

        counts = [
            await chats.count_messages(db.pool, alice.tenant, target)
            for target in (chat_id, other, empty)
        ]

        assert counts == [4, 1, 0]
        assert all(type(count) is int for count in counts)

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

        status = await chats.latest_message_status(db.pool, alice.tenant, chat_id)

        assert status == "awaiting_confirmation"

    async def test_chats_latest_status_of_an_empty_chat_is_none(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        alice = _member(db)
        chat_id = db.add_chat(alice.user_id)
        db.add_chat_message(db.add_chat(alice.user_id), "assistant", "x", status="error")

        assert await chats.latest_message_status(db.pool, alice.tenant, chat_id) is None


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


class TestOrgNotice:
    """GH-66's promotion notice: one user message in every live chat of the org."""

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
        await chats.list_messages(pool, tenant, chat.id, limit=1, cursor=None)
        await chats.count_messages(pool, tenant, chat.id)
        await chats.latest_message_status(pool, tenant, chat.id)
        await chats.append_org_notice(pool, tenant, _MARK_NOTICE)
        await chats.get_or_create_legacy_chat(pool, tenant, _MARK_SESSION)
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
        await chats.get_or_create_legacy_chat(pool, tenant, _MARK_RACE_SESSION)
