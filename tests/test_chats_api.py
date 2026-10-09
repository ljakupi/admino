"""HTTP spec of the persisted chat CRUD routes (GH-176, contract sections 6 and 7).

``POST /api/chats``, ``GET /api/chats``, ``GET /api/chats/{chat_id}``,
``PATCH /api/chats/{chat_id}`` and ``DELETE /api/chats/{chat_id}``. The app
from ``create_app()`` (a stub agent: none of these routes runs the LLM) runs
against the FakeDb world of tests/tenancy_world.py (orgs A and B with an Org
Admin, an Editor and a Viewer each, plus a Super Admin, all with real session
cookies resolved by the real ``server.require_session``). The real
``admino.chats`` repository, ``admino.audit_events`` and the module-level
``server._chat_runtime`` (``ChatRuntime``) run; nothing is mocked but the
database and the agent.

What these tests pin down:
- Access: no cookie is 401 ``{"detail": "Unauthorized"}``; the Org Admin and
  the Editor use every route; the Viewer (on their own stored chat) and the
  Super Admin get 403 ``{"detail": "Forbidden"}`` on every route with no
  statement naming ``chats`` or ``chat_messages`` and nothing changed. A
  cross-origin ``Origin`` on POST/PATCH/DELETE is refused by the CSRF
  middleware with nothing changed (the same request from the same origin
  succeeds). Each route has its own per-user bucket in ``server._RATE_LIMITS``
  (``/api/chats/create`` (0.5, 5), ``/api/chats/list`` (1.0, 10),
  ``/api/chats/get`` (1.0, 10), ``/api/chats/patch`` (0.5, 5),
  ``/api/chats/delete`` (0.5, 5)); an empty bucket is 429 for that user only.
- POST: ``{}`` is 201 with a ``ChatSummary`` (exactly ``id``, ``title`` "",
  ``title_source`` "auto", ``created_at``, ``last_activity_at``) and a stored
  row of the caller's org and owner; a title (stripped) is ``"user"``.
  Smuggled ``org_id`` / ``owner_user_id`` / ``title_source`` / ``id``, bad
  titles (empty, blank, over 200 characters, a Cc or a bidi Cf character, not
  a string) and a missing body are 422 without echo, nothing created.
- GET list: the caller's own live chats only (not another member's of the
  same org, not another org's, not a trashed one), by last activity then id,
  newest first; ``limit`` defaults to 50 and is 1 to 100 (0 / 101: 422); the
  ``next_cursor`` walk returns every chat once (ties on the timestamp
  included) and ends with null; a bad cursor (garbage, a message cursor) is
  422 ``{"detail": "Invalid cursor", "reason": "invalid_cursor"}``, never
  echoed. So is a crafted cursor that decodes but can't be bound (security
  audit L-1: a ``last_activity_at`` that overflows in UTC), never a 500.
- GET detail: the summary plus ``messages`` (chronological, the latest page,
  ``limit`` default 100, 1 to 100), ``next_cursor`` to earlier messages and
  the walk back to the first one (a crafted message cursor whose seq no
  BIGINT holds is the same 422 ``invalid_cursor``, security audit L-1); tool
  messages with their ``tool_call_id``;
  ``tool_calls`` as sanitized ``ToolCallRecord`` dicts; content sanitized like
  ``ChatResponse.response``; no ``tool_use_blocks`` key anywhere and nothing of
  their raw input. ``confirmation_status``: "none" (the latest message isn't
  awaiting a confirmation), "pending" with ``pending_confirmation`` filled
  from the runtime (the read keeps it), "expired" with null when the latest
  message is ``awaiting_confirmation`` and the runtime holds no live one
  (never set, past its expiry: reaped, after a new ``create_app()``).
  GH-190 (Decision 13): the interim ``context`` (``message_count``,
  ``max_context_messages``, ``truncated``) is gone, ``context_usage {used, max,
  percent}`` replaces it (its values: tests/test_chat_detail_context_api.py), and
  every message carries ``attachment_ids`` (Decision 12).
  GH-266: a request runs the owner-checked chat lookup (``admino.chats``'s S2) exactly
  once, the message page (S9' / S11') is read once and the latest status by a
  status-only query; GH-190 (Decision 14) adds the turn setup (T1) and the turn read
  (T2'') for ``context_usage`` and drops the message count. For a chat with a tool
  turn, an empty chat, an earlier page (``confirmation_status`` still the latest
  message's), a live pending and an expired confirmation; an invalid cursor runs the
  owner lookup only.
- PATCH: renames (stripped), ``title_source`` "user", ``last_activity_at``
  untouched, idempotent; bad, missing or null titles and extra keys are 422
  without echo, nothing changed.
- DELETE: 204 with no body; the row is trashed (``deleted_at`` set, messages
  kept); afterwards detail, PATCH and DELETE are 404 and the list skips it;
  exactly one ``chat.delete`` audit row (member actor, org, ``chat`` target,
  the chat id, the client IP, no metadata, no title); the chat's pending
  confirmation is dropped from the runtime (another member's never is).
- 404 identity: an unknown id, another org's chat, another member's chat of
  the same org (an Org Admin included) and a trashed chat answer GET detail,
  PATCH and DELETE with the same 404 ``{"detail": "Chat not found", "reason":
  "chat_not_found"}`` and change nothing; a non-UUID path id is 422.
  GET detail's 404 runs the one owner lookup and no other chat-table statement
  (GH-266).
- No title and no message content in any app log record.
- Every route declares its contract model (``route.response_model``) and
  status code.

All database calls are faked. No network, no real PostgreSQL, no LLM.

Security notes: emails, passwords and tokens are fixed fake values; the
markers and the "Bearer" value are fake content.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import scoped_settings, server
from admino.models import PendingConfirmation, ToolCall
from tests.db_fakes import ORG_ID, FakeDb
from tests.tenancy_world import (
    CLIENT_IP,
    FORBIDDEN,
    UNAUTHORIZED,
    build_world,
    make_app,
    make_client,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, MemberRole, Role, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CHAT_NOT_FOUND: Final = {"detail": "Chat not found", "reason": "chat_not_found"}
_INVALID_CURSOR: Final = {"detail": "Invalid cursor", "reason": "invalid_cursor"}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}

_SUMMARY_KEYS: Final = frozenset({"id", "title", "title_source", "created_at", "last_activity_at"})
# GH-190: ``context_usage`` replaces the interim ``context`` (Decision 13).
_DETAIL_KEYS: Final = _SUMMARY_KEYS | {
    "messages",
    "next_cursor",
    "pending_confirmation",
    "confirmation_status",
    "context_usage",
    # GH-245 (Decision 6): whether the chat's latest message failed (retry offered).
    "retryable",
}
# GH-190: every message carries its ``attachment_ids`` (Decision 12).
_MESSAGE_KEYS: Final = frozenset(
    {
        "id",
        "role",
        "content",
        "tool_call_id",
        "tool_calls",
        "status",
        "created_at",
        "attachment_ids",
    }
)

# A statement naming either chat table (the session lookup names neither).
_CHAT_SQL: Final = re.compile(r"\b(?:chats|chat_messages)\b")
# GH-266: admino.chats's owner-checked chat lookup (S2), normalized.
_OWNER_LOOKUP: Final = re.compile(
    r"select .+ from chats where id = \$1 and org_id = \$2 and owner_user_id = \$3"
    r" and deleted_at is null"
)
# A SELECT's column list and its table (normalized SQL).
_SELECT_FROM: Final = re.compile(r"select (.+?) from (chats|chat_messages)\b")
# What a detail request of a chat it finds runs on the chat tables (GH-266): the owner
# lookup once, the message page and the status-only read of the latest message; GH-190
# (Decision 14) adds the turn setup (T1) and the turn read (T2'') for ``context_usage``
# and drops the message count.
_DETAIL_READS: Final = Counter(
    {"owner-lookup": 1, "page": 1, "status": 1, "turn-setup": 1, "turn": 1}
)

_FOREIGN_ORIGIN: Final = "https://evil.example"
# TestClient sends ``Host: testserver``: an Origin with that host is same-origin.
_SAME_ORIGIN: Final = "http://testserver"

_ECHO: Final = "ECHOMARK176"
_RLO: Final = chr(0x202E)  # RIGHT-TO-LEFT OVERRIDE (Cf, bidi)
_BEL: Final = chr(0x07)  # BELL (Cc)
_REDACTED: Final = "[CREDENTIAL_REDACTED]"
_FAKE_BEARER: Final = "fake-bearer-176-otter"

# A recognisable value inside a stored tool_use block's raw input: never exposed.
_RAW_INPUT_MARKER: Final = "raw-input-176-heron"
_CALL_ID: Final = "call_176_a"
# A stored ToolCallRecord dump whose args hold a credential pattern.
_STORED_TOOL_CALL: Final[dict[str, Any]] = {
    "tool": "gmail",
    "action": "search",
    "args": {"query": "flight", "auth": f"Bearer {_FAKE_BEARER}"},
    "permission": "allow",
    "success": True,
    "duration_ms": 42,
}

# Titles and content that must never reach a log record.
_LOG_TITLE: Final = "Quokkaledger Steuerplan 176"
_LOG_RENAMED: Final = "Marmotinvoice Umbenannt 176"
_LOG_CONTENT: Final = "Wombatsecret Mandant 176 verlangt Rueckruf"

_T0: Final = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)

_RATE_KEYS: Final[dict[str, tuple[float, int]]] = {
    "/api/chats/create": (0.5, 5),
    "/api/chats/list": (1.0, 10),
    "/api/chats/get": (1.0, 10),
    "/api/chats/patch": (0.5, 5),
    "/api/chats/delete": (0.5, 5),
}


@dataclass(frozen=True)
class _Op:
    """One chat route: method, path (``{chat_id}`` filled per request), a valid body,
    its success status and its rate-limit key."""

    method: str
    path: str
    body: dict[str, Any] | None
    ok: int
    rate_key: str


_CREATE: Final = _Op("POST", "/api/chats", {}, 201, "/api/chats/create")
_LIST: Final = _Op("GET", "/api/chats", None, 200, "/api/chats/list")
_DETAIL: Final = _Op("GET", "/api/chats/{chat_id}", None, 200, "/api/chats/get")
_RENAME: Final = _Op("PATCH", "/api/chats/{chat_id}", {"title": "Renamed"}, 200, "/api/chats/patch")
_TRASH: Final = _Op("DELETE", "/api/chats/{chat_id}", None, 204, "/api/chats/delete")


def _op_id(op: _Op) -> str:
    """A space-free pytest id: ``"PATCH:/api/chats/{chat_id}"``."""
    return f"{op.method}:{op.path}"


_EVERY_OP: Final = [
    pytest.param(op, id=_op_id(op)) for op in (_CREATE, _LIST, _DETAIL, _RENAME, _TRASH)
]
_WRITE_OPS: Final = [pytest.param(op, id=_op_id(op)) for op in (_CREATE, _RENAME, _TRASH)]
_ID_OPS: Final = [pytest.param(op, id=_op_id(op)) for op in (_DETAIL, _RENAME, _TRASH)]

# Titles every reading of the ChatTitle rules refuses; the marker never comes back.
_BAD_TITLES: Final = [
    pytest.param("", id="empty"),
    pytest.param("   ", id="blank"),
    pytest.param(_ECHO + "x" * 200, id="over-200"),
    pytest.param(f"{_ECHO}{_BEL}", id="control-char"),
    pytest.param(f"{_ECHO}{_RLO}", id="bidi-override"),
    pytest.param(176, id="not-a-string"),
]

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin behind the fake database; every
    rate-limit bucket roomy (the rate-limit tests set their own)."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture()
def client(world: World) -> TestClient:
    """The app (a stub agent) and a client at ``CLIENT_IP``."""
    return make_client(make_app())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _at(minutes: int) -> datetime:
    return _T0 + timedelta(minutes=minutes)


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _outcome(response: httpx.Response) -> tuple[int, Any]:
    """(status, JSON body) or (status, text) when the body isn't JSON."""
    try:
        body = response.json()
    except ValueError:
        body = response.text
    return response.status_code, body


def _headers(caller: Account | None, origin: str | None = None) -> dict[str, str]:
    headers = dict(caller.cookie) if caller is not None else {}
    if origin is not None:
        headers["Origin"] = origin
    return headers


def _send(
    client: TestClient,
    op: _Op,
    caller: Account | None,
    chat_id: uuid.UUID,
    *,
    origin: str | None = None,
) -> httpx.Response:
    kwargs: dict[str, Any] = {"headers": _headers(caller, origin)}
    if op.body is not None:
        kwargs["json"] = op.body
    return client.request(op.method, op.path.format(chat_id=chat_id), **kwargs)


def _create(client: TestClient, caller: Account, body: Any) -> httpx.Response:
    return client.post("/api/chats", json=body, headers=caller.cookie)


def _list(client: TestClient, caller: Account, **params: Any) -> httpx.Response:
    return client.get("/api/chats", params=params, headers=caller.cookie)


def _detail(
    client: TestClient, caller: Account, chat_id: uuid.UUID | str, **params: Any
) -> httpx.Response:
    return client.get(f"/api/chats/{chat_id}", params=params, headers=caller.cookie)


def _patch(
    client: TestClient, caller: Account, chat_id: uuid.UUID | str, body: Any
) -> httpx.Response:
    return client.patch(f"/api/chats/{chat_id}", json=body, headers=caller.cookie)


def _delete(client: TestClient, caller: Account, chat_id: uuid.UUID | str) -> httpx.Response:
    return client.delete(f"/api/chats/{chat_id}", headers=caller.cookie)


def _chat_state(db: FakeDb) -> dict[str, Any]:
    """Deep copies of the chats, chat_messages and audit tables."""
    tables = db.snapshot()
    return {name: tables[name] for name in ("chats", "chat_messages", "audit")}


def _chat_statements(db: FakeDb, since: int) -> list[str]:
    return [call.normalized for call in db.calls[since:] if _CHAT_SQL.search(call.normalized)]


def _statement_kind(sql: str) -> str:
    """A chat-table statement of a detail request (GH-266): ``owner-lookup`` (S2),
    ``page`` (a chat_messages SELECT of ``content``; GH-190's S9' / S11' name it
    ``m.content``), ``count`` (``count(*)`` only), ``status`` (``status`` only),
    GH-190's ``turn-setup`` (T1, the organizations row joined to the chat) and ``turn``
    (T2'', the chat with its latest messages), else the normalized SQL itself."""
    if _OWNER_LOOKUP.fullmatch(sql):
        return "owner-lookup"
    if "from organizations o" in sql and "left join chats c" in sql:
        return "turn-setup"
    if "from chats c left join lateral" in sql:
        return "turn"
    match = _SELECT_FROM.match(sql)
    if match is not None and match.group(2) == "chat_messages":
        columns = [column.strip().removeprefix("m.") for column in match.group(1).split(",")]
        if "content" in columns:
            return "page"
        if columns == ["count(*)"]:
            return "count"
        if columns == ["status"]:
            return "status"
    return sql


def _statement_kinds(db: FakeDb, since: int) -> Counter[str]:
    """How often each kind of chat-table statement ran after the first ``since`` calls."""
    return Counter(_statement_kind(sql) for sql in _chat_statements(db, since))


def _no_echo(response: httpx.Response) -> None:
    """A 422 whose errors carry no input and whose body doesn't repeat the marker."""
    assert response.status_code == 422, response.text
    errors = response.json()["detail"]
    assert isinstance(errors, list), errors
    assert all("input" not in error for error in errors), errors
    assert _ECHO not in response.text


def _all_keys(value: Any) -> set[str]:
    """Every dict key anywhere in a JSON value."""
    if isinstance(value, dict):
        keys = set(value)
        for item in value.values():
            keys |= _all_keys(item)
        return keys
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value)) if value else set()
    return set()


def _runtime() -> Any:
    """The server's ChatRuntime (looked up at call time: it doesn't exist before GH-176)."""
    return server._chat_runtime


def _pending(
    chat_id: uuid.UUID,
    *,
    confirmation_id: str = "conf-176-a",
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> PendingConfirmation:
    now = datetime.now(UTC)
    return PendingConfirmation(
        confirmation_id=confirmation_id,
        session_id=str(chat_id),
        tool_call=ToolCall(
            tool="google_calendar",
            action="create",
            args={"summary": "Standup"},
            tool_call_id=_CALL_ID,
        ),
        created_at=created_at or now,
        expires_at=expires_at or now + timedelta(minutes=5),
    )


def _awaiting_chat(db: FakeDb, owner: Account) -> uuid.UUID:
    """A chat whose latest message is an assistant tool_use awaiting confirmation."""
    chat = db.add_chat(owner.user_id, title="Calendar")
    db.add_chat_message(chat, "user", "Book the standup")
    db.add_chat_message(
        chat,
        "assistant",
        "",
        tool_use_blocks=[
            {
                "type": "tool_use",
                "id": _CALL_ID,
                "name": "google_calendar.create",
                "input": {"summary": "Standup"},
            }
        ],
        status="awaiting_confirmation",
    )
    return chat


def _seed_tool_turn(db: FakeDb, owner: Account) -> tuple[uuid.UUID, list[uuid.UUID]]:
    """A chat with one tool turn: user, assistant tool_use, tool result, final answer
    (carrying the run's tool_calls). Returns the chat id and the message ids in order."""
    chat = db.add_chat(
        owner.user_id,
        title="Flight search",
        title_source="user",
        created_at=_at(0),
        last_activity_at=_at(5),
    )
    ids = [
        db.add_chat_message(chat, "user", "Find the flight confirmation"),
        db.add_chat_message(
            chat,
            "assistant",
            "",
            tool_use_blocks=[
                {
                    "type": "tool_use",
                    "id": _CALL_ID,
                    "name": "gmail.search",
                    "input": {"query": _RAW_INPUT_MARKER},
                }
            ],
        ),
        db.add_chat_message(chat, "tool", "One email found.", tool_call_id=_CALL_ID),
        db.add_chat_message(
            chat, "assistant", "Your flight leaves at 9.", tool_calls=[_STORED_TOOL_CALL]
        ),
    ]
    return chat, ids


def _walk_chats(client: TestClient, caller: Account, limit: int) -> list[list[str]]:
    """Follow ``next_cursor`` from the first page to the end; the chat ids per page."""
    pages: list[list[str]] = []
    params: dict[str, Any] = {"limit": limit}
    for _ in range(20):
        response = _list(client, caller, **params)
        assert response.status_code == 200, response.text
        body = response.json()
        pages.append([chat["id"] for chat in body["chats"]])
        if body["next_cursor"] is None:
            return pages
        params = {"limit": limit, "cursor": body["next_cursor"]}
    raise AssertionError("the chat cursor walk never ended")


def _walk_messages(
    client: TestClient, caller: Account, chat_id: uuid.UUID, limit: int
) -> list[list[str]]:
    """Follow ``next_cursor`` from the latest page back to the first; contents per page."""
    pages: list[list[str]] = []
    params: dict[str, Any] = {"limit": limit}
    for _ in range(20):
        response = _detail(client, caller, chat_id, **params)
        assert response.status_code == 200, response.text
        body = response.json()
        pages.append([message["content"] for message in body["messages"]])
        if body["next_cursor"] is None:
            return pages
        params = {"limit": limit, "cursor": body["next_cursor"]}
    raise AssertionError("the message cursor walk never ended")


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


def _crafted(cursor: Any, is_field: Callable[[Any], bool], value: Any) -> str:
    """A real cursor (unpadded base64url of JSON, as admino.chats encodes it) with its one
    field ``is_field`` picks set to ``value``: it still decodes (security audit L-1)."""
    assert isinstance(cursor, str), cursor
    payload = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    assert isinstance(payload, dict), payload
    (name,) = [key for key, item in payload.items() if is_field(item)]
    payload[name] = value
    text = json.dumps(payload, separators=(",", ":"))
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record, formatted with its exception (not httpx's request lines)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


# ---------------------------------------------------------------------------
# 1. Access: session, role, CSRF, per-user rate limits, response models
# ---------------------------------------------------------------------------


class TestChatsAccess:
    """401 without a session, chat.send only, same-origin writes, per-user buckets."""

    @pytest.mark.parametrize("op", _EVERY_OP)
    def test_chats_api_without_a_session_is_401_and_touches_no_chat(
        self, world: World, client: TestClient, op: _Op
    ) -> None:
        chat = world.db.add_chat(world.a["editor"].user_id, title="Kept")
        before = _chat_state(world.db)
        since = len(world.db.calls)

        response = _send(client, op, None, chat)

        assert _outcome(response) == (401, UNAUTHORIZED)
        assert _chat_statements(world.db, since) == []
        assert _chat_state(world.db) == before

    @pytest.mark.parametrize("role", ["viewer", "super_admin"])
    @pytest.mark.parametrize("op", _EVERY_OP)
    def test_chats_api_viewer_and_super_admin_are_403_before_any_chat_statement(
        self, world: World, client: TestClient, op: _Op, role: Role
    ) -> None:
        """The Viewer asks for their own stored chat (from before a demotion), the Super
        Admin for an Editor's: 403 Forbidden, no chat statement, nothing changed."""
        caller = world.by_role(role)
        owner = caller if role == "viewer" else world.a["editor"]
        chat = world.db.add_chat(owner.user_id, title="Kept")
        world.db.add_chat_message(chat, "user", "Earlier question")
        before = _chat_state(world.db)
        since = len(world.db.calls)

        response = _send(client, op, caller, chat)

        assert _outcome(response) == (403, FORBIDDEN)
        assert _chat_statements(world.db, since) == []
        assert _chat_state(world.db) == before

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_chats_api_org_admin_and_editor_use_every_route(
        self, world: World, client: TestClient, role: MemberRole
    ) -> None:
        caller = world.a[role]

        created = _create(client, caller, {"title": "Lifecycle"})
        assert created.status_code == 201, created.text
        chat_id = created.json()["id"]
        listed = _list(client, caller)
        detail = _detail(client, caller, chat_id)
        renamed = _patch(client, caller, chat_id, {"title": "Renamed"})
        deleted = _delete(client, caller, chat_id)

        assert [r.status_code for r in (listed, detail, renamed, deleted)] == [200, 200, 200, 204]
        assert [chat["id"] for chat in listed.json()["chats"]] == [chat_id]
        row = world.db.chat_row(uuid.UUID(chat_id))
        assert row is not None
        assert (str(row["owner_user_id"]), str(row["org_id"])) == (str(caller.user_id), str(ORG_ID))

    @pytest.mark.parametrize("op", _WRITE_OPS)
    def test_chats_api_cross_origin_write_is_refused_and_same_origin_succeeds(
        self, world: World, client: TestClient, op: _Op
    ) -> None:
        """A foreign Origin is 403 before any chat statement, nothing changed; the same
        request with the app's own origin succeeds."""
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id, title="Original")
        before = _chat_state(world.db)
        since = len(world.db.calls)

        refused = _send(client, op, caller, chat, origin=_FOREIGN_ORIGIN)
        refused_statements = _chat_statements(world.db, since)
        state_after_refusal = _chat_state(world.db)
        accepted = _send(client, op, caller, chat, origin=_SAME_ORIGIN)

        assert _outcome(refused) == (403, _CSRF_REFUSED)
        assert refused_statements == []
        assert state_after_refusal == before
        assert accepted.status_code == op.ok, accepted.text

    def test_chats_api_rate_limit_keys_have_the_contract_values(self) -> None:
        assert {key: server._RATE_LIMITS.get(key) for key in _RATE_KEYS} == _RATE_KEYS

    @pytest.mark.parametrize("op", _EVERY_OP)
    def test_chats_api_rate_limit_is_per_user(
        self, world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch, op: _Op
    ) -> None:
        """Burst 1: the Editor's second request (on another of their chats) is 429 with
        nothing changed; the Org Admin of the same org isn't throttled; the bucket is
        (route key, "user:<id>")."""
        monkeypatch.setitem(server._RATE_LIMITS, op.rate_key, (0.001, 1))
        caller = world.a["editor"]
        other = world.a["org_admin"]
        first_chat = world.db.add_chat(caller.user_id, title="First")
        second_chat = world.db.add_chat(caller.user_id, title="Second")
        other_chat = world.db.add_chat(other.user_id, title="Other")

        first = _send(client, op, caller, first_chat)
        before_limited = _chat_state(world.db)
        limited = _send(client, op, caller, second_chat)
        after_limited = _chat_state(world.db)
        unaffected = _send(client, op, other, other_chat)

        assert first.status_code == op.ok, first.text
        assert _outcome(limited) == (429, _RATE_LIMITED)
        assert after_limited == before_limited
        assert unaffected.status_code == op.ok, unaffected.text
        assert (op.rate_key, f"user:{caller.user_id}") in server._rate_buckets

    def test_chats_api_routes_declare_the_contract_response_models(self) -> None:
        from fastapi.routing import APIRoute

        from admino import models

        expected = {
            ("POST", "/api/chats"): (models.ChatSummary, 201),
            ("GET", "/api/chats"): (models.ChatListResponse, 200),
            ("GET", "/api/chats/{chat_id}"): (models.ChatDetailResponse, 200),
            ("PATCH", "/api/chats/{chat_id}"): (models.ChatSummary, 200),
            ("DELETE", "/api/chats/{chat_id}"): (None, 204),
        }
        app = make_app()
        found: dict[tuple[str, str], tuple[Any, int | None]] = {}
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            for method in route.methods:
                key = (method, route.path)
                if key in expected:
                    found[key] = (route.response_model, route.status_code or 200)

        assert found == expected


# ---------------------------------------------------------------------------
# 2. POST /api/chats
# ---------------------------------------------------------------------------


class TestChatsCreate:
    """201 ChatSummary; the row belongs to the caller; strict, echo-free validation."""

    def test_chats_api_create_without_title_returns_an_auto_titled_summary(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]

        response = _create(client, caller, {})

        assert response.status_code == 201, response.text
        body = response.json()
        assert set(body) == _SUMMARY_KEYS
        assert (body["title"], body["title_source"]) == ("", "auto")
        rows = world.db.chats_of(caller.user_id)
        assert [str(row["id"]) for row in rows] == [body["id"]]
        row = rows[0]
        assert str(row["org_id"]) == str(ORG_ID)
        assert (row["title"], row["title_source"], row["deleted_at"]) == ("", "auto", None)
        assert row["legacy_session_id"] is None
        assert _ts(body["created_at"]) == row["created_at"]
        assert _ts(body["last_activity_at"]) == row["last_activity_at"]

    def test_chats_api_create_with_title_stores_it_stripped_as_user_titled(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["org_admin"]

        response = _create(client, caller, {"title": "  Quarterly plan  "})

        assert response.status_code == 201, response.text
        body = response.json()
        assert (body["title"], body["title_source"]) == ("Quarterly plan", "user")
        row = world.db.chat_row(uuid.UUID(body["id"]))
        assert row is not None
        assert (row["title"], row["title_source"]) == ("Quarterly plan", "user")
        assert str(row["owner_user_id"]) == str(caller.user_id)

    @pytest.mark.parametrize(
        "key", ["org_id", "owner_user_id", "title_source", "id"], ids=lambda key: key
    )
    def test_chats_api_create_smuggled_field_is_422_and_creates_nothing(
        self, world: World, client: TestClient, key: str
    ) -> None:
        """Whose chat it is and how it is titled come from the session and the server."""
        caller = world.a["editor"]
        values = {
            "org_id": str(world.org_b),
            "owner_user_id": str(world.b["editor"].user_id),
            "title_source": "user",
            "id": str(uuid.uuid4()),
        }
        before = _chat_state(world.db)

        response = _create(client, caller, {"title": "Plan", key: values[key]})

        _no_echo(response)
        assert [(error["loc"], error["type"]) for error in response.json()["detail"]] == [
            (["body", key], "extra_forbidden")
        ]
        assert _chat_state(world.db) == before

    @pytest.mark.parametrize("title", _BAD_TITLES)
    def test_chats_api_create_bad_title_is_422_without_echo(
        self, world: World, client: TestClient, title: Any
    ) -> None:
        before = _chat_state(world.db)

        response = _create(client, world.a["editor"], {"title": title})

        _no_echo(response)
        assert _chat_state(world.db) == before

    def test_chats_api_create_without_a_body_is_422(self, world: World, client: TestClient) -> None:
        before = _chat_state(world.db)

        response = client.post("/api/chats", headers=world.a["editor"].cookie)

        _no_echo(response)
        assert _chat_state(world.db) == before


# ---------------------------------------------------------------------------
# 3. GET /api/chats
# ---------------------------------------------------------------------------


class TestChatsList:
    """The caller's own live chats, newest activity first, keyset-paginated."""

    def test_chats_api_list_returns_only_the_callers_live_chats_newest_first(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        older = world.db.add_chat(
            caller.user_id, title="Older", created_at=_at(0), last_activity_at=_at(30)
        )
        newer = world.db.add_chat(
            caller.user_id, title="Newer", created_at=_at(10), last_activity_at=_at(40)
        )
        world.db.add_chat(
            caller.user_id, title="Trashed", last_activity_at=_at(50), deleted_at=_at(51)
        )
        world.db.add_chat(world.a["org_admin"].user_id, title="Admin's", last_activity_at=_at(60))
        world.db.add_chat(world.b["editor"].user_id, title="Org B's", last_activity_at=_at(70))

        response = _list(client, caller)

        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {"chats", "next_cursor"}
        assert [(chat["id"], chat["title"]) for chat in body["chats"]] == [
            (str(newer), "Newer"),
            (str(older), "Older"),
        ]
        assert all(set(chat) == _SUMMARY_KEYS for chat in body["chats"])
        assert _ts(body["chats"][0]["last_activity_at"]) == _at(40)
        assert body["next_cursor"] is None

    def test_chats_api_list_limit_defaults_to_50_and_accepts_100(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        for minute in range(51):
            world.db.add_chat(caller.user_id, created_at=_at(minute), last_activity_at=_at(minute))

        default = _list(client, caller)
        widest = _list(client, caller, limit=100)

        assert default.status_code == 200, default.text
        assert len(default.json()["chats"]) == 50
        assert default.json()["next_cursor"] is not None
        assert widest.status_code == 200, widest.text
        assert (len(widest.json()["chats"]), widest.json()["next_cursor"]) == (51, None)

    @pytest.mark.parametrize("limit", [0, 101], ids=lambda limit: f"limit-{limit}")
    def test_chats_api_list_limit_out_of_bounds_is_422(
        self, world: World, client: TestClient, limit: int
    ) -> None:
        world.db.add_chat(world.a["editor"].user_id)

        response = _list(client, world.a["editor"], limit=limit)

        _no_echo(response)

    @pytest.mark.parametrize("total", [6, 7], ids=lambda total: f"{total}-chats")
    def test_chats_api_list_cursor_walk_returns_every_chat_once_in_order(
        self, world: World, client: TestClient, total: int
    ) -> None:
        """Pages of 3 over chats sharing timestamps (keyset on (last_activity_at, id)):
        every chat exactly once, in order, no empty last page."""
        caller = world.a["editor"]
        minutes = [0, 1, 1, 1, 2, 3, 3][:total]
        seeded = [
            (
                _at(minute),
                world.db.add_chat(caller.user_id, created_at=_at(0), last_activity_at=_at(minute)),
            )
            for minute in minutes
        ]
        expected = [str(chat) for _, chat in sorted(seeded, reverse=True)]

        pages = _walk_chats(client, caller, limit=3)

        assert [chat for page in pages for chat in page] == expected
        assert [len(page) for page in pages] == ([3, 3] if total == 6 else [3, 3, 1])

    @pytest.mark.parametrize(
        "cursor",
        [
            pytest.param("not-a-cursor", id="garbage"),
            pytest.param("%%%", id="percent-signs"),
            pytest.param(f"{_ECHO}-cursor", id="marker"),
        ],
    )
    def test_chats_api_list_invalid_cursor_is_422_invalid_cursor(
        self, world: World, client: TestClient, cursor: str
    ) -> None:
        world.db.add_chat(world.a["editor"].user_id)

        response = _list(client, world.a["editor"], cursor=cursor)

        assert _outcome(response) == (422, _INVALID_CURSOR)

    def test_chats_api_cursor_of_one_endpoint_is_invalid_on_the_other(
        self, world: World, client: TestClient
    ) -> None:
        """A list cursor on the messages endpoint and a message cursor on the list are
        both 422 invalid_cursor."""
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id, last_activity_at=_at(1))
        world.db.add_chat(caller.user_id, last_activity_at=_at(2))
        world.db.add_chat_message(chat, "user", "first")
        world.db.add_chat_message(chat, "assistant", "second")
        list_page = _list(client, caller, limit=1)
        message_page = _detail(client, caller, chat, limit=1)
        assert list_page.status_code == 200, list_page.text
        assert message_page.status_code == 200, message_page.text
        list_cursor = list_page.json()["next_cursor"]
        message_cursor = message_page.json()["next_cursor"]
        assert isinstance(list_cursor, str) and isinstance(message_cursor, str)

        on_messages = _detail(client, caller, chat, cursor=list_cursor)
        on_list = _list(client, caller, cursor=message_cursor)

        assert _outcome(on_messages) == (422, _INVALID_CURSOR)
        assert _outcome(on_list) == (422, _INVALID_CURSOR)

    @pytest.mark.parametrize(
        "stamp",
        [
            pytest.param("0001-01-01T00:00:00+23:00", id="year-1-at-plus-23h"),
            pytest.param("9999-12-31T23:59:59-23:00", id="year-9999-at-minus-23h"),
        ],
    )
    def test_chats_api_list_cursor_stamp_outside_the_utc_range_is_422_invalid_cursor(
        self, world: World, client: TestClient, stamp: str
    ) -> None:
        """Security audit L-1: a crafted cursor that decodes but whose ``last_activity_at``
        overflows on the conversion to UTC (asyncpg can't bind it: a 500) is the
        documented 422 ``invalid_cursor``."""
        caller = world.a["editor"]
        world.db.add_chat(caller.user_id, last_activity_at=_at(1))
        world.db.add_chat(caller.user_id, last_activity_at=_at(2))
        first = _list(client, caller, limit=1)
        assert first.status_code == 200, first.text
        crafted = _crafted(first.json()["next_cursor"], _is_stamp, stamp)

        response = _list(client, caller, cursor=crafted)

        assert _outcome(response) == (422, _INVALID_CURSOR)

    @pytest.mark.parametrize("path", ["list", "detail"])
    def test_chats_api_overlong_cursor_is_422_without_echo(
        self, world: World, client: TestClient, path: str
    ) -> None:
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id)
        cursor = (_ECHO * 30)[:250]

        if path == "list":
            response = _list(client, caller, cursor=cursor)
        else:
            response = _detail(client, caller, chat, cursor=cursor)

        assert response.status_code == 422, response.text
        assert _ECHO not in response.text


# ---------------------------------------------------------------------------
# 4. GET /api/chats/{chat_id}
# ---------------------------------------------------------------------------


class TestChatsDetail:
    """The summary, a page of sanitized messages, the confirmation state and context usage."""

    def test_chats_api_detail_returns_the_summary_and_chronological_messages(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat, ids = _seed_tool_turn(world.db, caller)
        stored = world.db.messages_of(chat)

        response = _detail(client, caller, chat)

        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == _DETAIL_KEYS
        assert (body["id"], body["title"], body["title_source"]) == (
            str(chat),
            "Flight search",
            "user",
        )
        assert (_ts(body["created_at"]), _ts(body["last_activity_at"])) == (_at(0), _at(5))
        assert all(set(message) == _MESSAGE_KEYS for message in body["messages"])
        assert [
            (m["id"], m["role"], m["content"], m["tool_call_id"], m["status"])
            for m in body["messages"]
        ] == [
            (str(ids[0]), "user", "Find the flight confirmation", None, "complete"),
            (str(ids[1]), "assistant", "", None, "complete"),
            (str(ids[2]), "tool", "One email found.", _CALL_ID, "complete"),
            (str(ids[3]), "assistant", "Your flight leaves at 9.", None, "complete"),
        ]
        assert [_ts(m["created_at"]) for m in body["messages"]] == [
            row["created_at"] for row in stored
        ]
        assert body["next_cursor"] is None

    def test_chats_api_detail_exposes_tool_calls_as_sanitized_records(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat, _ = _seed_tool_turn(world.db, caller)

        response = _detail(client, caller, chat)

        assert response.status_code == 200, response.text
        assert [m["tool_calls"] for m in response.json()["messages"]] == [
            None,
            None,
            None,
            [{**_STORED_TOOL_CALL, "args": {"query": "flight", "auth": _REDACTED}}],
        ]
        assert _FAKE_BEARER not in response.text

    def test_chats_api_detail_never_exposes_raw_tool_use_blocks(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat, _ = _seed_tool_turn(world.db, caller)

        response = _detail(client, caller, chat)

        assert response.status_code == 200, response.text
        assert len(response.json()["messages"]) == 4
        assert "tool_use_blocks" not in _all_keys(response.json())
        assert _RAW_INPUT_MARKER not in response.text

    def test_chats_api_detail_sanitizes_message_content(
        self, world: World, client: TestClient
    ) -> None:
        """Bidi controls and credential patterns are stripped, like ChatResponse.response."""
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id)
        world.db.add_chat_message(chat, "assistant", f"Ready{_RLO} now Bearer {_FAKE_BEARER}")

        response = _detail(client, caller, chat)

        assert response.status_code == 200, response.text
        assert [m["content"] for m in response.json()["messages"]] == [f"Ready now {_REDACTED}"]

    def test_chats_api_detail_pages_the_latest_100_then_walks_back(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id)
        for number in range(1, 102):
            world.db.add_chat_message(chat, "user" if number % 2 else "assistant", f"m{number}")

        latest = _detail(client, caller, chat)
        assert latest.status_code == 200, latest.text
        cursor = latest.json()["next_cursor"]
        assert isinstance(cursor, str)
        earlier = _detail(client, caller, chat, cursor=cursor)

        assert [m["content"] for m in latest.json()["messages"]] == [
            f"m{number}" for number in range(2, 102)
        ]
        assert earlier.status_code == 200, earlier.text
        assert (
            [m["content"] for m in earlier.json()["messages"]],
            earlier.json()["next_cursor"],
        ) == (
            ["m1"],
            None,
        )

    @pytest.mark.parametrize("total", [4, 5], ids=lambda total: f"{total}-messages")
    def test_chats_api_detail_cursor_walk_returns_every_message_once(
        self, world: World, client: TestClient, total: int
    ) -> None:
        """Pages of 2 from the latest back: each page chronological, no message twice,
        no empty first page."""
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id)
        for number in range(1, total + 1):
            world.db.add_chat_message(chat, "user" if number % 2 else "assistant", f"m{number}")

        pages = _walk_messages(client, caller, chat, limit=2)

        expected = (
            [["m3", "m4"], ["m1", "m2"]] if total == 4 else [["m4", "m5"], ["m2", "m3"], ["m1"]]
        )
        assert pages == expected

    @pytest.mark.parametrize("limit", [0, 101], ids=lambda limit: f"limit-{limit}")
    def test_chats_api_detail_limit_out_of_bounds_is_422(
        self, world: World, client: TestClient, limit: int
    ) -> None:
        chat = world.db.add_chat(world.a["editor"].user_id)

        response = _detail(client, world.a["editor"], chat, limit=limit)

        _no_echo(response)

    @pytest.mark.parametrize(
        "cursor",
        [
            pytest.param("not-a-cursor", id="garbage"),
            pytest.param("%%%", id="percent-signs"),
            pytest.param(f"{_ECHO}-cursor", id="marker"),
        ],
    )
    def test_chats_api_detail_invalid_cursor_is_422_invalid_cursor(
        self, world: World, client: TestClient, cursor: str
    ) -> None:
        chat = world.db.add_chat(world.a["editor"].user_id)
        world.db.add_chat_message(chat, "user", "hello")

        response = _detail(client, world.a["editor"], chat, cursor=cursor)

        assert _outcome(response) == (422, _INVALID_CURSOR)

    @pytest.mark.parametrize(
        "seq",
        [pytest.param(2**63, id="bigint-max-plus-1"), pytest.param(10**40, id="10-to-the-40")],
    )
    def test_chats_api_detail_cursor_seq_outside_bigint_is_422_invalid_cursor(
        self, world: World, client: TestClient, seq: int
    ) -> None:
        """Security audit L-1: a crafted message cursor that decodes but whose seq no
        BIGINT holds (asyncpg can't bind it: a 500) is the documented 422
        ``invalid_cursor``."""
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id)
        world.db.add_chat_message(chat, "user", "first")
        world.db.add_chat_message(chat, "assistant", "second")
        latest = _detail(client, caller, chat, limit=1)
        assert latest.status_code == 200, latest.text
        crafted = _crafted(latest.json()["next_cursor"], _is_seq, seq)

        response = _detail(client, caller, chat, cursor=crafted)

        assert _outcome(response) == (422, _INVALID_CURSOR)

    def test_chats_api_detail_confirmation_status_none_when_latest_message_is_complete(
        self, world: World, client: TestClient
    ) -> None:
        """An earlier message awaited a confirmation (since answered): only the latest
        message's status counts."""
        caller = world.a["editor"]
        chat = _awaiting_chat(world.db, caller)
        world.db.add_chat_message(
            chat, "tool", "Tool call denied by the user.", tool_call_id=_CALL_ID
        )
        world.db.add_chat_message(chat, "assistant", "Action google_calendar.create was denied.")

        response = _detail(client, caller, chat)

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["confirmation_status"], body["pending_confirmation"]) == ("none", None)

    def test_chats_api_detail_live_pending_confirmation_is_pending(
        self, world: World, client: TestClient
    ) -> None:
        """The runtime's live pending confirmation is summarised; reading keeps it."""
        caller = world.a["editor"]
        chat = _awaiting_chat(world.db, caller)
        pending = _pending(chat)
        _runtime().set_pending(chat, caller.user_id, pending)

        response = _detail(client, caller, chat)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["confirmation_status"] == "pending"
        summary = dict(body["pending_confirmation"])
        assert _ts(summary.pop("expires_at")) == pending.expires_at
        assert summary == {
            "confirmation_id": "conf-176-a",
            "tool": "google_calendar",
            "action": "create",
            "args": {"summary": "Standup"},
        }
        assert _runtime().get_pending(chat) == pending

    def test_chats_api_detail_awaiting_without_live_pending_is_expired(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat = _awaiting_chat(world.db, caller)

        response = _detail(client, caller, chat)

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["confirmation_status"], body["pending_confirmation"]) == ("expired", None)

    def test_chats_api_detail_pending_past_its_expiry_is_reaped_and_expired(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat = _awaiting_chat(world.db, caller)
        now = datetime.now(UTC)
        _runtime().set_pending(
            chat,
            caller.user_id,
            _pending(
                chat,
                created_at=now - timedelta(minutes=10),
                expires_at=now - timedelta(minutes=1),
            ),
        )

        response = _detail(client, caller, chat)

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["confirmation_status"], body["pending_confirmation"]) == ("expired", None)
        assert _runtime().get_pending(chat) is None

    def test_chats_api_detail_after_restart_pending_shows_expired(
        self, world: World, client: TestClient
    ) -> None:
        """Pending confirmations live in memory only: a new create_app() (a restart)
        turns a pending chat into an expired one."""
        caller = world.a["editor"]
        chat = _awaiting_chat(world.db, caller)
        _runtime().set_pending(chat, caller.user_id, _pending(chat))
        before_restart = _detail(client, caller, chat)

        restarted = make_client(make_app())
        after_restart = _detail(restarted, caller, chat)

        assert before_restart.status_code == 200, before_restart.text
        assert before_restart.json()["confirmation_status"] == "pending"
        assert after_restart.status_code == 200, after_restart.text
        body = after_restart.json()
        assert (body["confirmation_status"], body["pending_confirmation"]) == ("expired", None)

    @pytest.mark.parametrize(
        "count",
        [pytest.param(3, id="at-the-limit"), pytest.param(4, id="over-the-limit")],
    )
    def test_chats_api_detail_reports_context_usage_instead_of_the_interim_context(
        self, world: World, client: TestClient, count: int
    ) -> None:
        """GH-190 (Decision 13): the interim ``context`` is gone, ``context_usage``
        replaces it. With the stored platform max_context_messages 3 (not the default
        20), the usage of 4 messages is that of the latest 3: a turn loads no more."""
        row = world.db.platform_row()
        assert row is not None
        row["max_context_messages"] = 3
        scoped_settings._platform_cache = None
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id)
        latest = world.db.add_chat(caller.user_id)
        for number in range(count):
            world.db.add_chat_message(
                chat, "user" if number % 2 == 0 else "assistant", f"m{number}"
            )
        for number in range(count - 3, count):
            world.db.add_chat_message(
                latest, "user" if number % 2 == 0 else "assistant", f"m{number}"
            )

        response = _detail(client, caller, chat, limit=1)
        reference = _detail(client, caller, latest, limit=1)

        assert response.status_code == 200, response.text
        body = response.json()
        assert len(body["messages"]) == 1
        assert "context" not in body
        assert set(body["context_usage"]) == {"used", "max", "percent"}
        assert reference.status_code == 200, reference.text
        assert body["context_usage"] == reference.json()["context_usage"]

    @pytest.mark.parametrize(
        ("case", "status"),
        [
            pytest.param("messages", "none", id="tool-turn"),
            pytest.param("empty", "none", id="no-messages"),
            pytest.param("cursor", "expired", id="earlier-page"),
            pytest.param("pending", "pending", id="live-pending"),
            pytest.param("expired", "expired", id="expired"),
        ],
    )
    def test_chats_api_detail_runs_the_owner_lookup_once_and_reads_only_the_latest_status(
        self, world: World, client: TestClient, case: str, status: str
    ) -> None:
        """GH-266: one owner-checked lookup (S2) per request, not one per read; the
        page is read once; the latest status is read by a status-only query. GH-190
        (Decision 14): then the turn setup and the turn read, and no message count.
        ``confirmation_status`` is unchanged (on an earlier page too, it is the latest
        message's)."""
        caller = world.a["editor"]
        params: dict[str, Any] = {}
        if case == "messages":
            chat, _ = _seed_tool_turn(world.db, caller)
        elif case == "empty":
            chat = world.db.add_chat(caller.user_id)
        else:
            chat = _awaiting_chat(world.db, caller)
        if case == "pending":
            _runtime().set_pending(chat, caller.user_id, _pending(chat))
        if case == "cursor":
            latest = _detail(client, caller, chat, limit=1)
            assert latest.status_code == 200, latest.text
            params = {"limit": 1, "cursor": latest.json()["next_cursor"]}
        since = len(world.db.calls)

        response = _detail(client, caller, chat, **params)

        assert response.status_code == 200, response.text
        assert response.json()["confirmation_status"] == status
        assert _statement_kinds(world.db, since) == _DETAIL_READS

    def test_chats_api_detail_invalid_cursor_runs_only_the_owner_lookup(
        self, world: World, client: TestClient
    ) -> None:
        """GH-266: the cursor is decoded after the one owner lookup; a bad one is the
        422 ``invalid_cursor`` with no other chat statement."""
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id)
        world.db.add_chat_message(chat, "user", "hello")
        since = len(world.db.calls)

        response = _detail(client, caller, chat, cursor="not-a-cursor")

        assert _outcome(response) == (422, _INVALID_CURSOR)
        assert [_statement_kind(sql) for sql in _chat_statements(world.db, since)] == [
            "owner-lookup"
        ]


# ---------------------------------------------------------------------------
# 5. PATCH /api/chats/{chat_id}
# ---------------------------------------------------------------------------


class TestChatsRename:
    """Rename: user-titled, activity untouched, idempotent, echo-free validation."""

    def test_chats_api_rename_sets_a_user_title_and_keeps_last_activity(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id, created_at=_at(0), last_activity_at=_at(20))

        response = _patch(client, caller, chat, {"title": "Budget review"})

        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == _SUMMARY_KEYS
        assert (body["id"], body["title"], body["title_source"]) == (
            str(chat),
            "Budget review",
            "user",
        )
        assert _ts(body["last_activity_at"]) == _at(20)
        row = world.db.chat_row(chat)
        assert row is not None
        assert (row["title"], row["title_source"], row["last_activity_at"]) == (
            "Budget review",
            "user",
            _at(20),
        )

    def test_chats_api_rename_is_idempotent(self, world: World, client: TestClient) -> None:
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id, last_activity_at=_at(20))

        first = _patch(client, caller, chat, {"title": "Same title"})
        after_first = _chat_state(world.db)
        second = _patch(client, caller, chat, {"title": "Same title"})

        assert first.status_code == 200, first.text
        assert (second.status_code, second.json()) == (200, first.json())
        assert _chat_state(world.db) == after_first

    @pytest.mark.parametrize(
        "body",
        [
            *(pytest.param({"title": param.values[0]}, id=param.id) for param in _BAD_TITLES),
            pytest.param({}, id="missing-title"),
            pytest.param({"title": None}, id="null-title"),
            pytest.param({"title": "Fine", "title_source": "auto"}, id="extra-key"),
        ],
    )
    def test_chats_api_rename_invalid_body_is_422_without_echo_and_changes_nothing(
        self, world: World, client: TestClient, body: dict[str, Any]
    ) -> None:
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id, title="Original", title_source="user")
        before = _chat_state(world.db)

        response = _patch(client, caller, chat, body)

        _no_echo(response)
        assert _chat_state(world.db) == before


# ---------------------------------------------------------------------------
# 6. DELETE /api/chats/{chat_id}
# ---------------------------------------------------------------------------


class TestChatsTrash:
    """204; trashed (not purged); gone from every route; one content-free audit row."""

    def test_chats_api_delete_trashes_the_chat_and_keeps_its_messages(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id, title="To trash")
        world.db.add_chat_message(chat, "user", "hello")
        world.db.add_chat_message(chat, "assistant", "hi")

        response = _delete(client, caller, chat)

        assert response.status_code == 204, response.text
        assert response.content == b""
        row = world.db.chat_row(chat)
        assert row is not None
        assert row["deleted_at"] is not None
        assert row["title"] == "To trash"
        assert [m["content"] for m in world.db.messages_of(chat)] == ["hello", "hi"]

    def test_chats_api_deleted_chat_is_gone_from_every_route(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        kept = world.db.add_chat(caller.user_id, title="Kept")
        chat = world.db.add_chat(caller.user_id, title="Trashed")
        deleted = _delete(client, caller, chat)
        assert deleted.status_code == 204, deleted.text

        detail = _detail(client, caller, chat)
        listed = _list(client, caller)
        renamed = _patch(client, caller, chat, {"title": "Back"})
        again = _delete(client, caller, chat)

        assert _outcome(detail) == (404, _CHAT_NOT_FOUND)
        assert listed.status_code == 200, listed.text
        assert [c["id"] for c in listed.json()["chats"]] == [str(kept)]
        assert _outcome(renamed) == (404, _CHAT_NOT_FOUND)
        assert _outcome(again) == (404, _CHAT_NOT_FOUND)
        assert len(world.db.audit_rows("chat.delete")) == 1

    def test_chats_api_delete_records_one_content_free_audit_event(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat = world.db.add_chat(caller.user_id, title=_LOG_TITLE)

        response = _delete(client, caller, chat)

        assert response.status_code == 204, response.text
        rows = world.db.audit_rows("chat.delete")
        assert len(rows) == 1
        row = rows[0]
        assert (row["actor_kind"], str(row["actor_user_id"]), str(row["org_id"])) == (
            "member",
            str(caller.user_id),
            str(ORG_ID),
        )
        assert (row["target_type"], row["target_ids"]) == ("chat", [str(chat)])
        assert row["ip"] == CLIENT_IP
        assert row["metadata"] == {}
        assert "quokkaledger" not in repr(row).casefold()

    def test_chats_api_delete_drops_the_chats_pending_confirmation(
        self, world: World, client: TestClient
    ) -> None:
        caller = world.a["editor"]
        chat = _awaiting_chat(world.db, caller)
        _runtime().set_pending(chat, caller.user_id, _pending(chat))

        response = _delete(client, caller, chat)

        assert response.status_code == 204, response.text
        assert _runtime().get_pending(chat) is None

    def test_chats_api_delete_of_another_members_chat_keeps_their_pending_confirmation(
        self, world: World, client: TestClient
    ) -> None:
        owner = world.a["org_admin"]
        chat = _awaiting_chat(world.db, owner)
        pending = _pending(chat)
        _runtime().set_pending(chat, owner.user_id, pending)

        response = _delete(client, world.a["editor"], chat)

        assert _outcome(response) == (404, _CHAT_NOT_FOUND)
        assert _runtime().get_pending(chat) == pending


# ---------------------------------------------------------------------------
# 7. Not found: one answer for unknown, foreign and trashed chats
# ---------------------------------------------------------------------------


def _not_found_target(world: World, case: str) -> tuple[Account, uuid.UUID]:
    """The caller and the chat id of a not-found case (existing chats hold a message)."""
    editor = world.a["editor"]
    if case == "unknown":
        return editor, uuid.uuid4()
    if case == "other-org":
        caller, chat = editor, world.db.add_chat(world.b["editor"].user_id, title="Org B plan")
    elif case == "other-member":
        caller, chat = editor, world.db.add_chat(world.a["org_admin"].user_id, title="Admin plan")
    elif case == "org-admin-reads-member":
        caller, chat = world.a["org_admin"], world.db.add_chat(editor.user_id, title="Editor plan")
    else:
        caller, chat = editor, world.db.add_chat(editor.user_id, title="Old plan", deleted_at=_T0)
    world.db.add_chat_message(chat, "user", "private question")
    return caller, chat


class TestChatsNotFound:
    """Unknown, other org, other member (an Org Admin too), trashed: the same 404."""

    @pytest.mark.parametrize(
        "case",
        [
            pytest.param("unknown", id="unknown-id"),
            pytest.param("other-org", id="other-org"),
            pytest.param("other-member", id="same-org-other-member"),
            pytest.param("org-admin-reads-member", id="org-admin-reads-an-editors-chat"),
            pytest.param("trashed", id="own-trashed"),
        ],
    )
    def test_chats_api_not_found_is_identical_and_changes_nothing(
        self, world: World, client: TestClient, case: str
    ) -> None:
        caller, chat = _not_found_target(world, case)
        before = _chat_state(world.db)

        responses = [
            _detail(client, caller, chat),
            _patch(client, caller, chat, {"title": "Taken over"}),
            _delete(client, caller, chat),
        ]

        assert [_outcome(response) for response in responses] == [(404, _CHAT_NOT_FOUND)] * 3
        assert _chat_state(world.db) == before

    @pytest.mark.parametrize(
        "case",
        [
            pytest.param("unknown", id="unknown-id"),
            pytest.param("other-org", id="other-org"),
            pytest.param("other-member", id="same-org-other-member"),
            pytest.param("org-admin-reads-member", id="org-admin-reads-an-editors-chat"),
            pytest.param("trashed", id="own-trashed"),
        ],
    )
    def test_chats_api_detail_not_found_runs_only_the_owner_lookup(
        self, world: World, client: TestClient, case: str
    ) -> None:
        """GH-266: GET detail's 404 comes from its one owner-checked lookup; no other
        statement on a chat table runs."""
        caller, chat = _not_found_target(world, case)
        since = len(world.db.calls)

        response = _detail(client, caller, chat)

        assert _outcome(response) == (404, _CHAT_NOT_FOUND)
        assert [_statement_kind(sql) for sql in _chat_statements(world.db, since)] == [
            "owner-lookup"
        ]

    @pytest.mark.parametrize("op", _ID_OPS)
    def test_chats_api_non_uuid_chat_id_is_422_before_any_chat_statement(
        self, world: World, client: TestClient, op: _Op
    ) -> None:
        since = len(world.db.calls)

        response = client.request(
            op.method,
            f"/api/chats/{_ECHO}-not-a-uuid",
            headers=world.a["editor"].cookie,
            **({"json": op.body} if op.body is not None else {}),
        )

        _no_echo(response)
        assert _chat_statements(world.db, since) == []


# ---------------------------------------------------------------------------
# 8. No titles or content in logs
# ---------------------------------------------------------------------------


class TestChatsLogs:
    """Logs name chat ids only."""

    def test_chats_api_no_title_or_content_reaches_a_log_record(
        self, world: World, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        caller = world.a["editor"]

        created = _create(client, caller, {"title": _LOG_TITLE})
        assert created.status_code == 201, created.text
        chat = uuid.UUID(created.json()["id"])
        world.db.add_chat_message(chat, "user", _LOG_CONTENT)
        renamed = _patch(client, caller, chat, {"title": _LOG_RENAMED})
        listed = _list(client, caller)
        detail = _detail(client, caller, chat)
        deleted = _delete(client, caller, chat)

        assert [r.status_code for r in (renamed, listed, detail, deleted)] == [200, 200, 200, 204]
        assert [m["content"] for m in detail.json()["messages"]] == [_LOG_CONTENT]
        text = _app_log_text(caplog).casefold()
        for fragment in ("quokkaledger", "marmotinvoice", "wombatsecret", "steuerplan"):
            assert fragment not in text
