"""HTTP spec for per-org critical permission promotions with password re-auth (GH-161).

Replaces the tests of the removed ``/api/critical-permissions*`` routes and of
#149's interim 403 ("Critical permission promotions are temporarily
unavailable."). The FastAPI app from ``create_app()`` runs against the
in-memory database of tests/db_fakes.py (what ``admino.database.get_pool``
returns; both orgs seeded with ``DEFAULT_PERMISSIONS``) with a real
``AppConfig``. The real ``require_session``, ``admino.org_permissions``,
``admino.auth.reauthenticate``, ``admino.login_throttle`` and
``admino.audit_events`` code runs; only ``admino.passwords`` (a fast fake
hash), the throttle's sleeps (``login_delays``) and the agent's ``run`` are
stubbed. Time is moved with the contract's clock seam,
``admino.org_permissions.current_time``.

What these tests pin down (the GH-161 contract, "Critical promotions", "auth.py
reauthenticate" and "server.py routes"):
- Routes: ``GET /api/org/critical-permissions``, ``PATCH
  /api/org/critical-permissions/{tool}/{action}`` (optional body
  ``{"password": ...}``) and ``DELETE .../{tool}/{action}/pending``. Order in
  each: session (401) -> per-user rate limit (429, keys
  ``/api/org/critical-permissions/{get,promote,cancel}`` with (1.0, 5),
  (5/60, 5), (0.5, 5), before any database work) -> ``org.permissions.manage``
  (403 ``{"detail": "Forbidden"}`` for an Editor, a Viewer and the Super Admin,
  before any database work) -> work. Cross-origin PATCH / DELETE -> 403.
- The old ``/api/critical-permissions*`` routes and rate-limit keys are gone,
  and so are ``server._pending_promotions``, ``_promoted_permissions``,
  ``_resolve_pending_promotions`` and ``_PROMOTION_COOLDOWN_S``.
- GET: the 4 promotable pairs sorted by (tool, action), ``state`` from the
  org's own stored row, ``pending_at`` from the org's own pending entry.
- Promote (the pair isn't stored 'confirm'): the admin's OWN password, checked
  by ``auth.reauthenticate`` through ``login_throttle``. Right -> 200 ``state``
  'deny' + ``pending_at`` = now, one ``org.permission_promote`` audit row
  (tokens only, client IP), no session created. Wrong -> 403 ``{"detail":
  "Re-authentication failed."}``, nothing pending, no audit row, the failure
  counted on the account and IP subjects; a locked account refuses even the
  right password (never checked). No body -> 400 ``{"detail": "Password
  re-authentication is required."}``; extra keys or a bad password -> 422 that
  never echoes the password; a non-promotable pair -> 404 ``{"detail": "Not a
  promotable permission"}`` without a password check; invalid path
  identifiers -> 422. A repeat while pending keeps the first ``pending_at``
  and writes no second audit row. An audit failure is a 500 with nothing
  pending.
- The 5-minute cooldown: at 4:59 still pending; from 5:00 the org's next GET,
  PATCH or POST /api/message stores 'confirm' for THAT org only (no audit
  row). Another org's requests never resolve it, and another org's GET shows
  neither the pending entry nor the promotion.
- Demote (PATCH on a pair stored 'confirm'): no password (a body is ignored),
  200 'deny', ``org.permission_demote`` audit row; the admin can promote again
  afterwards with the right password.
- Cancel: drops the org's own pending entry, ``org.permission_promote_cancel``
  audit row; without a pending entry (or another org's) -> 404 ``{"detail":
  "No pending promotion for this permission"}``.
- GH-66 notice: a completed promotion appends ONE user-role message with the
  contract's exact text to every in-memory chat of the promoting org's users,
  none to other orgs' chats, never twice; it survives ``_trim_context``.
- The agent run of an org's member gets ``tool_policy`` (a ``ToolPolicy``)
  whose ``promoted`` holds that org's completed promotions only.
- GH-162: the fixture orgs have no data residency. In a residency org a
  completed gmail.send promotion still leaves every Google/Microsoft service
  off in the run's ``enabled_tools`` (memory on); other orgs are unaffected.
- The server lifespan no longer loads promoted permissions or a tools gate
  into the agent. GH-170: the startup prompt (``main._build_system_prompt``) is
  gone; the per-request base prompt (``prompt_assembly.base_prompt``) names only
  the tools it is given (no static tool line) and keeps the dynamic-permission
  and no-substitution guidance in every response language.

All database calls are faked. No network, no real PostgreSQL, no LLM.

Security notes:
- Tenant isolation: every read and write is the principal's own org; another
  org's admin can neither see nor cancel nor complete a promotion.
- Least privilege: only Org Admins promote; promotion needs the admin's own
  password, and a wrong one counts against the brute-force throttle like a
  failed login. Demotion only reduces privilege, so it needs no password.
- No password in any response (422s included); audit metadata is tokens only.
- The passwords used here are fixed fake values, never real secrets.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import server
from admino.config import AppConfig
from admino.login_throttle import ip_subject
from admino.models import AgentResult, LLMMessage
from admino.server import create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb, account_subject, fake_hash
from tests.lifespan_stubs import patch_login_throttle_purge_job, patch_org_purge_job

if TYPE_CHECKING:
    import httpx
    from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE: Final = "admino_session"
_IP_A: Final = "203.0.113.5"
_BASE: Final = "/api/org/critical-permissions"
_OLD_BASE: Final = "/api/critical-permissions"

_UNAUTHORIZED: Final = {"detail": "Unauthorized"}
_FORBIDDEN: Final = {"detail": "Forbidden"}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_REAUTH_FAILED: Final = {"detail": "Re-authentication failed."}
_REAUTH_REQUIRED: Final = {"detail": "Password re-authentication is required."}
_NOT_PROMOTABLE: Final = {"detail": "Not a promotable permission"}
_NO_PENDING: Final = {"detail": "No pending promotion for this permission"}
_PROMOTIONS_UNAVAILABLE: Final = {
    "detail": "Critical permission promotions are temporarily unavailable."
}

# The 4 promotable denials, sorted by (tool, action).
_PROMOTABLE: Final[list[tuple[str, str]]] = [
    ("gmail", "send"),
    ("google_calendar", "update"),
    ("outlook", "send"),
    ("outlook_calendar", "update"),
]
_GMAIL_SEND: Final = ("gmail", "send")
_OUTLOOK_SEND: Final = ("outlook", "send")
# GH-162: the tools an org's data residency switches off (RESIDENCY_BLOCKED_TOOLS).
_RESIDENCY_TOOLS: Final = (
    "gmail",
    "google_calendar",
    "google_drive",
    "outlook",
    "outlook_calendar",
    "onedrive",
)

_ADMIN_PASSWORD: Final = "admin correct horse battery staple"
_OTHER_PASSWORD: Final = "editor tr0ub4dor and three more"
_WRONG_PASSWORD: Final = "definitely not the stored password"

_COOLDOWN: Final = timedelta(minutes=5)
_JUST_BEFORE: Final = _COOLDOWN - timedelta(seconds=1)

_NOTICE_GMAIL: Final = (
    "PERMISSION UPDATE: The following actions are now available with user confirmation: "
    "gmail.send. Earlier denials for these actions no longer apply."
)
_NOTICE_GMAIL_OUTLOOK: Final = (
    "PERMISSION UPDATE: The following actions are now available with user confirmation: "
    "gmail.send, outlook.send. Earlier denials for these actions no longer apply."
)

_GET_KEY: Final = "/api/org/critical-permissions/get"
_PROMOTE_KEY: Final = "/api/org/critical-permissions/promote"
_CANCEL_KEY: Final = "/api/org/critical-permissions/cancel"
_EXPECTED_LIMITS: Final[dict[str, tuple[float, int]]] = {
    _GET_KEY: (1.0, 5),
    _PROMOTE_KEY: (5 / 60, 5),
    _CANCEL_KEY: (0.5, 5),
}
# Read at import, before any fixture patches the limits.
_CONFIGURED_LIMITS: Final = {key: server._RATE_LIMITS.get(key) for key in _EXPECTED_LIMITS}
_OLD_RATE_KEYS: Final = [
    "/api/critical-permissions/get",
    "/api/critical-permissions/promote",
    "/api/critical-permissions/cancel",
]
_REMOVED_SERVER_GLOBALS: Final = [
    "_pending_promotions",
    "_promoted_permissions",
    "_resolve_pending_promotions",
    "_PROMOTION_COOLDOWN_S",
]
_NON_ADMIN_ROLES: Final = ["editor", "viewer", "super_admin"]
# SQL a refused or rate-limited request must never run (session lookups are fine).
_WORK_SQL: Final = re.compile(r"\b(?:permissions|audit_events|login_throttle)\b")
_PERMISSION_AUDIT_PREFIX: Final = "org.permission"
_ECHO_MARKER: Final = "ECHOMARK42"

_NON_PROMOTABLE_PAIRS: Final = [
    pytest.param("gmail", "delete", id="immutable-gmail-delete"),
    pytest.param("outlook_calendar", "delete", id="immutable-outlook-calendar-delete"),
    pytest.param("gmail", "read", id="ordinary-gmail-read"),
    pytest.param("google_calendar", "create", id="stored-confirm-calendar-create"),
    pytest.param("nosuchtool", "send", id="unknown-pair"),
]
_BAD_IDENTIFIERS: Final = [
    pytest.param("GMAIL", "send", id="uppercase-tool"),
    pytest.param("gmail", "SEND", id="uppercase-action"),
    pytest.param("gmail<script>", "send", id="markup-tool"),
    pytest.param("gm..ail", "send", id="dots-tool"),
    pytest.param("9gmail", "send", id="leading-digit"),
    pytest.param("a" * 64, "send", id="64-chars"),
    pytest.param("gmail", "send;drop", id="semicolon-action"),
]
_BAD_BODIES: Final = [
    pytest.param({"password": ""}, id="empty-password"),
    pytest.param(
        {"password": _ADMIN_PASSWORD, "bearer_token": _ECHO_MARKER + "-legacy-token"},
        id="legacy-bearer-token-key",
    ),
    pytest.param(
        {"password": _ADMIN_PASSWORD, "tool": _ECHO_MARKER + "-tool"}, id="extra-tool-key"
    ),
    pytest.param({"password": _ECHO_MARKER + "x" * 119}, id="129-chars"),
    pytest.param({"password": 123456789012345}, id="int-password"),
    pytest.param({"password": [_ECHO_MARKER + "-in-a-list"]}, id="list-password"),
    pytest.param({"password": {"value": _ECHO_MARKER + "-nested"}}, id="object-password"),
    pytest.param(_ECHO_MARKER + "-bare-string", id="string-body"),
]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@dataclass
class _User:
    """A stored account with a live session."""

    id: uuid.UUID
    token: str
    email: str
    password: str


@dataclass
class _Verify:
    """How often the fake ``passwords.verify_password`` ran."""

    count: int = 0


class _Clock:
    """Moves ``admino.org_permissions.current_time`` (the contract's clock seam).

    The module is looked up on the first ``at`` call (in the test body), so
    each test that needs time fails on its own until the module exists.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._monkeypatch = monkeypatch
        self.t0 = datetime.now(UTC).replace(microsecond=0)

    def at(self, offset: timedelta = timedelta(0)) -> datetime:
        when = self.t0 + offset
        self._monkeypatch.setattr("admino.org_permissions.current_time", lambda: when)
        return when


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database get_pool() returns: two active orgs without data residency (GH-162:
    a residency org's runs have the Google/Microsoft tools off), each with the default
    matrix."""
    fake = FakeDb()
    fake.add_org(ORG_ID, data_residency=False)
    fake.add_org(OTHER_ORG_ID, data_residency=False)
    fake.add_platform_settings()
    fake.add_permissions(ORG_ID)
    fake.add_permissions(OTHER_ORG_ID)
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


@pytest.fixture(autouse=True)
def verify(monkeypatch: pytest.MonkeyPatch) -> _Verify:
    """Replace Argon2 with a fast fake and count the password checks."""
    spy = _Verify()

    def fake_verify(password: str, encoded: str) -> bool:
        spy.count += 1
        return encoded == fake_hash(password)

    monkeypatch.setattr("admino.passwords.verify_password", fake_verify)
    monkeypatch.setattr("admino.passwords.needs_rehash", lambda _encoded: False)
    monkeypatch.setattr("admino.passwords.hash_password", fake_hash)
    return spy


@pytest.fixture(autouse=True)
def _roomy_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Functional tests aren't about rate limits (the rate-limit tests set their own)."""
    for key in (*_EXPECTED_LIMITS, "/api/message"):
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    return _Clock(monkeypatch)


def _agent_result() -> AgentResult:
    return AgentResult(
        status="final",
        response="Done.",
        history=[
            LLMMessage(role="user", content="hi"),
            LLMMessage(role="assistant", content="Done."),
        ],
        tool_calls=[],
        pending_confirmation=None,
    )


@pytest.fixture()
def agent() -> MagicMock:
    stub = MagicMock(name="agent")
    stub.run = AsyncMock(return_value=_agent_result())
    return stub


def _config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
    )


@pytest.fixture()
def app(agent: MagicMock) -> FastAPI:
    """create_app with the stub agent and a real config (no lifespan under TestClient)."""
    return create_app(agent=agent, config=_config())  # type: ignore[arg-type]


def _client(app: FastAPI, *, raise_server_exceptions: bool = True) -> TestClient:
    return TestClient(
        app,
        client=(_IP_A, 50000),
        follow_redirects=False,
        raise_server_exceptions=raise_server_exceptions,
    )


def _account(
    db: FakeDb,
    role: str,
    org_id: uuid.UUID = ORG_ID,
    *,
    password: str = _ADMIN_PASSWORD,
) -> _User:
    """An account with this role (or a Super Admin), its password and a live session."""
    email = f"{role.replace('_', '-')}-{uuid.uuid4().hex[:8]}@example.ch"
    if role == "super_admin":
        user_id = db.add_account(
            kind="super_admin", role=None, email=email, password_hash=fake_hash(password)
        )
    else:
        user_id = db.add_account(
            role=role, org_id=org_id, email=email, password_hash=fake_hash(password)
        )
    return _User(id=user_id, token=db.open_session(user_id), email=email, password=password)


def _headers(user: _User | None, **extra: str) -> dict[str, str]:
    cookie = {} if user is None else {"Cookie": f"{_COOKIE}={user.token}"}
    return {**cookie, **extra}


def _path(pair: tuple[str, str]) -> str:
    return f"{_BASE}/{pair[0]}/{pair[1]}"


def _get(client: TestClient, user: _User | None, **extra: str) -> httpx.Response:
    return client.get(_BASE, headers=_headers(user, **extra))


def _promote(
    client: TestClient,
    user: _User | None,
    pair: tuple[str, str] = _GMAIL_SEND,
    *,
    password: str | None = None,
    **extra: str,
) -> httpx.Response:
    """PATCH with a password body (the user's own password unless one is given)."""
    if password is None:
        password = user.password if user is not None else _ADMIN_PASSWORD
    return client.patch(_path(pair), headers=_headers(user, **extra), json={"password": password})


def _patch_without_body(
    client: TestClient, user: _User | None, pair: tuple[str, str] = _GMAIL_SEND, **extra: str
) -> httpx.Response:
    return client.patch(_path(pair), headers=_headers(user, **extra))


def _cancel(
    client: TestClient, user: _User | None, pair: tuple[str, str] = _GMAIL_SEND, **extra: str
) -> httpx.Response:
    return client.delete(f"{_path(pair)}/pending", headers=_headers(user, **extra))


def _entry(response: httpx.Response, pair: tuple[str, str]) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    matches = [
        entry
        for entry in response.json()["permissions"]
        if (entry["tool"], entry["action"]) == pair
    ]
    assert len(matches) == 1, response.json()
    return matches[0]


def _ts(value: Any) -> datetime | None:
    """A response timestamp as an aware datetime (None stays None)."""
    if value is None:
        return None
    assert isinstance(value, str), value
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None, value
    return parsed


def _state_of(response: httpx.Response, pair: tuple[str, str]) -> tuple[str, datetime | None]:
    entry = _entry(response, pair)
    return entry["state"], _ts(entry["pending_at"])


def _stored(db: FakeDb, org_id: uuid.UUID, pair: tuple[str, str]) -> str | None:
    return db.org_permissions(org_id).get(pair[0], {}).get(pair[1])


def _permission_audit(db: FakeDb) -> list[str]:
    """The org.permission_* audit actions, in order."""
    return [row["action"] for row in db.audit if row["action"].startswith(_PERMISSION_AUDIT_PREFIX)]


def _work_sql(db: FakeDb, mark: int) -> list[str]:
    """Statements since ``mark`` that touch permissions, audit_events or login_throttle."""
    return [call.normalized for call in db.calls[mark:] if _WORK_SQL.search(call.normalized)]


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


def _plain_uuid(value: Any) -> uuid.UUID | None:
    return None if value is None else uuid.UUID(str(value))


def _assert_permission_event(
    event: dict[str, Any],
    *,
    action: str,
    actor: _User,
    org_id: uuid.UUID,
    metadata: dict[str, str],
) -> None:
    assert event["action"] == action
    assert (event["actor_kind"], _plain_uuid(event["actor_user_id"])) == ("member", actor.id)
    assert _plain_uuid(event["org_id"]) == org_id
    assert (event["target_type"], event["target_ids"]) == ("organization", [str(org_id)])
    assert event["ip"] == _IP_A
    assert event["metadata"] == metadata


def _api_route(app: FastAPI, method: str, path: str) -> APIRoute:
    matches = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == path and method in route.methods
    ]
    assert len(matches) == 1, f"{method} {path} is not registered"
    return matches[0]


def _old_routes(app: FastAPI) -> list[str]:
    return [
        route.path
        for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith(_OLD_BASE)
    ]


def _limited(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    """One request per key, then nothing for a long time."""
    monkeypatch.setitem(server._RATE_LIMITS, key, (0.001, 1))


def _lockout_after() -> int:
    """The stored lockout threshold the throttle applies (the primed platform cache)."""
    from admino import scoped_settings

    cache = scoped_settings._platform_cache
    assert cache is not None
    return int(cache.security.lockout_after_failures)


def _seed_chat(user: _User, chat_id: str) -> tuple[uuid.UUID, str]:
    """Store an in-memory chat of the user (after create_app, which clears them)."""
    key = server._chat_key(user.id, chat_id)
    server._sessions[key] = [
        LLMMessage(role="user", content="send an email to the auditor"),
        LLMMessage(role="assistant", content="I can't send email."),
    ]
    return key


def _added(key: tuple[uuid.UUID, str]) -> list[tuple[str, str]]:
    """(role, content) of every message appended after the two seeded ones."""
    return [(message.role, message.content) for message in server._sessions[key][2:]]


def _post_message(client: TestClient, user: _User, chat_id: str = "chat-161") -> httpx.Response:
    return client.post(
        "/api/message",
        headers=_headers(user),
        json={"message": "please send the report", "session_id": chat_id},
    )


def _policy_of(agent: MagicMock) -> Any:
    """The ToolPolicy the last agent run received."""
    from admino.models import ToolPolicy

    kwargs = agent.run.await_args.kwargs
    assert "tool_policy" in kwargs, sorted(kwargs)
    policy = kwargs["tool_policy"]
    assert isinstance(policy, ToolPolicy), policy
    return policy


def _complete(client: TestClient, clock: _Clock, admin: _User, *pairs: tuple[str, str]) -> None:
    """Promote the pairs at T0 and let the cooldown pass (the next request resolves them)."""
    clock.at()
    for pair in pairs or (_GMAIL_SEND,):
        response = _promote(client, admin, pair)
        assert response.status_code == 200, response.text
    clock.at(_COOLDOWN)


def _fresh_listing() -> dict[str, Any]:
    return {
        "permissions": [
            {"tool": tool, "action": action, "state": "deny", "pending_at": None}
            for tool, action in _PROMOTABLE
        ]
    }


# ---------------------------------------------------------------------------
# 1. Routes, rate-limit keys and removed state
# ---------------------------------------------------------------------------


class TestRoutes:
    """The three /api/org/critical-permissions routes replace /api/critical-permissions."""

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", _BASE),
            ("PATCH", _BASE + "/{tool}/{action}"),
            ("DELETE", _BASE + "/{tool}/{action}/pending"),
        ],
    )
    def test_critical_permissions_route_is_registered(
        self, app: FastAPI, method: str, path: str
    ) -> None:
        _api_route(app, method, path)

    def test_critical_permissions_old_routes_are_not_registered(self, app: FastAPI) -> None:
        assert _old_routes(app) == []

    def test_critical_permissions_old_get_is_404(self, db: FakeDb, app: FastAPI) -> None:
        admin = _account(db, "org_admin")

        response = _client(app).get(_OLD_BASE, headers=_headers(admin))

        assert response.status_code == 404
        assert _old_routes(app) == []

    def test_critical_permissions_old_patch_is_refused_and_changes_nothing(
        self, db: FakeDb, app: FastAPI, verify: _Verify
    ) -> None:
        """404 (or the static files' 405), no password check, nothing pending or stored."""
        admin = _account(db, "org_admin")
        db.add_permissions(ORG_ID, {"outlook": {"send": "confirm"}})
        client = _client(app)

        promote = client.patch(
            f"{_OLD_BASE}/gmail/send",
            headers=_headers(admin),
            json={"password": _ADMIN_PASSWORD},
        )
        demote = client.patch(f"{_OLD_BASE}/outlook/send", headers=_headers(admin))

        assert promote.status_code in {404, 405}
        assert demote.status_code in {404, 405}
        assert verify.count == 0
        assert _stored(db, ORG_ID, _OUTLOOK_SEND) == "confirm"
        assert _old_routes(app) == []

    def test_critical_permissions_old_delete_is_refused(self, db: FakeDb, app: FastAPI) -> None:
        admin = _account(db, "org_admin")

        response = _client(app).delete(f"{_OLD_BASE}/gmail/send/pending", headers=_headers(admin))

        assert response.status_code in {404, 405}
        assert _old_routes(app) == []

    @pytest.mark.parametrize("key", list(_EXPECTED_LIMITS))
    def test_critical_permissions_rate_limit_values(self, key: str) -> None:
        assert _CONFIGURED_LIMITS[key] == pytest.approx(_EXPECTED_LIMITS[key])

    @pytest.mark.parametrize("key", _OLD_RATE_KEYS)
    def test_critical_permissions_old_rate_limit_keys_are_removed(self, key: str) -> None:
        assert key not in server._RATE_LIMITS

    @pytest.mark.parametrize("name", _REMOVED_SERVER_GLOBALS)
    def test_critical_permissions_server_promotion_state_is_gone(self, name: str) -> None:
        assert not hasattr(server, name)

    def test_critical_permissions_cooldown_is_five_minutes(self) -> None:
        from admino import org_permissions

        assert timedelta(minutes=5) == org_permissions.PROMOTION_COOLDOWN


# ---------------------------------------------------------------------------
# 2. Session, role gate, rate limits and cross-origin protection
# ---------------------------------------------------------------------------


class TestAccess:
    """401 without a session; 403 for every role but the Org Admin; 429 per user."""

    @pytest.mark.parametrize("route", ["get", "promote", "demote", "cancel"])
    def test_critical_permissions_without_session_is_401(
        self, db: FakeDb, app: FastAPI, route: str, verify: _Verify
    ) -> None:
        _api_route(app, "GET", _BASE)
        client = _client(app)
        calls = {
            "get": lambda: _get(client, None),
            "promote": lambda: _promote(client, None),
            "demote": lambda: _patch_without_body(client, None),
            "cancel": lambda: _cancel(client, None),
        }

        response = calls[route]()

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert _work_sql(db, 0) == []
        assert verify.count == 0

    @pytest.mark.parametrize("role", _NON_ADMIN_ROLES)
    def test_critical_permissions_get_by_non_admin_is_403_without_db_work(
        self, db: FakeDb, app: FastAPI, role: str
    ) -> None:
        user = _account(db, role)
        mark = len(db.calls)

        response = _get(_client(app), user)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _work_sql(db, mark) == []

    @pytest.mark.parametrize("role", _NON_ADMIN_ROLES)
    def test_critical_permissions_promote_by_non_admin_is_403_before_reauth(
        self, db: FakeDb, app: FastAPI, verify: _Verify, clock: _Clock, role: str
    ) -> None:
        """A non-admin's own right password unlocks nothing: 403, no check, nothing counted."""
        user = _account(db, role)
        admin = _account(db, "org_admin")
        client = _client(app)
        mark = len(db.calls)

        response = _promote(client, user)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _work_sql(db, mark) == []
        assert verify.count == 0
        assert db.throttle == []
        clock.at(_COOLDOWN)
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"

    @pytest.mark.parametrize("role", _NON_ADMIN_ROLES)
    def test_critical_permissions_demote_by_non_admin_is_403_and_keeps_the_promotion(
        self, db: FakeDb, app: FastAPI, role: str
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        user = _account(db, role)
        mark = len(db.calls)

        response = _patch_without_body(_client(app), user)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _work_sql(db, mark) == []
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "confirm"

    @pytest.mark.parametrize("role", _NON_ADMIN_ROLES)
    def test_critical_permissions_cancel_by_non_admin_is_403_and_keeps_the_pending(
        self, db: FakeDb, app: FastAPI, clock: _Clock, role: str
    ) -> None:
        admin = _account(db, "org_admin")
        user = _account(db, role)
        client = _client(app)
        clock.at()
        assert _promote(client, admin).status_code == 200
        mark = len(db.calls)

        response = _cancel(client, user)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _work_sql(db, mark) == []
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", clock.t0)

    def test_critical_permissions_get_rate_limit_is_per_user_and_before_db_work(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _limited(monkeypatch, _GET_KEY)
        admin = _account(db, "org_admin")
        other_admin = _account(db, "org_admin")
        client = _client(app)

        first = _get(client, admin)
        mark = len(db.calls)
        second = _get(client, admin)
        work = _work_sql(db, mark)
        other = _get(client, other_admin)

        assert first.status_code == 200, first.text
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)
        assert work == []
        assert other.status_code == 200, other.text

    def test_critical_permissions_rate_limit_runs_before_the_role_gate(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An Editor's refused calls spend its own bucket: 403, then 429."""
        _limited(monkeypatch, _GET_KEY)
        editor = _account(db, "editor")
        client = _client(app)

        first = _get(client, editor)
        second = _get(client, editor)

        assert (first.status_code, first.json()) == (403, _FORBIDDEN)
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)

    def test_critical_permissions_promote_rate_limit_is_before_reauth(
        self,
        db: FakeDb,
        app: FastAPI,
        monkeypatch: pytest.MonkeyPatch,
        verify: _Verify,
    ) -> None:
        """The second attempt is 429: its password is never checked, nothing is pending."""
        _limited(monkeypatch, _PROMOTE_KEY)
        admin = _account(db, "org_admin")
        client = _client(app)

        first = _promote(client, admin, password=_WRONG_PASSWORD)
        mark = len(db.calls)
        second = _promote(client, admin)
        work = _work_sql(db, mark)

        assert (first.status_code, first.json()) == (403, _REAUTH_FAILED)
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)
        assert work == []
        assert verify.count == 1
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)

    def test_critical_permissions_cancel_rate_limit_is_before_db_work(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _limited(monkeypatch, _CANCEL_KEY)
        admin = _account(db, "org_admin")
        client = _client(app)

        first = _cancel(client, admin)
        mark = len(db.calls)
        second = _cancel(client, admin)

        assert (first.status_code, first.json()) == (404, _NO_PENDING)
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)
        assert _work_sql(db, mark) == []

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
        ],
    )
    def test_critical_permissions_cross_origin_promote_is_403(
        self,
        db: FakeDb,
        app: FastAPI,
        verify: _Verify,
        clock: _Clock,
        headers: dict[str, str],
    ) -> None:
        _api_route(app, "PATCH", _BASE + "/{tool}/{action}")
        admin = _account(db, "org_admin")
        client = _client(app)
        clock.at()

        response = _promote(client, admin, **headers)

        assert (response.status_code, response.json()) == (403, _CSRF_REFUSED)
        assert verify.count == 0
        assert db.audit_rows() == []
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)

    def test_critical_permissions_cross_origin_cancel_is_403(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        _api_route(app, "DELETE", _BASE + "/{tool}/{action}/pending")
        admin = _account(db, "org_admin")
        client = _client(app)
        clock.at()
        assert _promote(client, admin).status_code == 200

        response = _cancel(client, admin, **{"Sec-Fetch-Site": "cross-site"})

        assert (response.status_code, response.json()) == (403, _CSRF_REFUSED)
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", clock.t0)
        assert _permission_audit(db) == ["org.permission_promote"]


# ---------------------------------------------------------------------------
# 3. GET: the org's own state
# ---------------------------------------------------------------------------


class TestGet:
    """The 4 promotable pairs, sorted, with the org's stored state and pending entry."""

    def test_critical_permissions_get_lists_four_sorted_denied_entries(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        admin = _account(db, "org_admin")

        response = _get(_client(app), admin)

        assert response.status_code == 200, response.text
        assert response.json() == _fresh_listing()

    def test_critical_permissions_get_reads_the_own_orgs_stored_state(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        db.add_permissions(OTHER_ORG_ID, {"outlook_calendar": {"update": "confirm"}})
        admin_a = _account(db, "org_admin")
        admin_b = _account(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)

        listing_a = _get(client, admin_a)
        listing_b = _get(client, admin_b)

        states_a = {pair: _state_of(listing_a, pair)[0] for pair in _PROMOTABLE}
        states_b = {pair: _state_of(listing_b, pair)[0] for pair in _PROMOTABLE}
        assert states_a == {
            **dict.fromkeys(_PROMOTABLE, "deny"),
            _GMAIL_SEND: "confirm",
        }
        assert states_b == {
            **dict.fromkeys(_PROMOTABLE, "deny"),
            ("outlook_calendar", "update"): "confirm",
        }

    def test_critical_permissions_get_shows_only_the_own_orgs_pending_entry(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        admin_b = _account(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)
        clock.at()
        assert _promote(client, admin_a).status_code == 200

        listing_a = _get(client, admin_a)
        listing_b = _get(client, admin_b)

        assert _state_of(listing_a, _GMAIL_SEND) == ("deny", clock.t0)
        assert listing_b.json() == _fresh_listing()


# ---------------------------------------------------------------------------
# 4. PATCH: promotion with password re-auth
# ---------------------------------------------------------------------------


class TestPromote:
    """Password re-auth, then a 5-minute cooldown; #149's interim 403 is gone."""

    @pytest.mark.parametrize("pair", _PROMOTABLE)
    def test_critical_permissions_promote_with_right_password_starts_the_cooldown(
        self, db: FakeDb, app: FastAPI, clock: _Clock, pair: tuple[str, str]
    ) -> None:
        admin = _account(db, "org_admin")
        clock.at()

        response = _promote(_client(app), admin, pair)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body != _PROMOTIONS_UNAVAILABLE
        assert {key: body[key] for key in ("tool", "action", "state")} == {
            "tool": pair[0],
            "action": pair[1],
            "state": "deny",
        }
        assert _ts(body["pending_at"]) == clock.t0
        assert _stored(db, ORG_ID, pair) == "deny"

    def test_critical_permissions_promote_writes_one_audit_row_and_no_session(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin = _account(db, "org_admin")
        clock.at()

        response = _promote(_client(app), admin)

        assert response.status_code == 200, response.text
        event = _one(db.audit_rows("org.permission_promote"))
        _assert_permission_event(
            event,
            action="org.permission_promote",
            actor=admin,
            org_id=ORG_ID,
            metadata={"tool": "gmail", "action": "send", "old": "deny", "new": "confirm"},
        )
        assert [row["action"] for row in db.audit] == ["org.permission_promote"]
        assert len(db.sessions_of(admin.id)) == 1

    def test_critical_permissions_promote_with_wrong_password_is_403_and_changes_nothing(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app)
        clock.at()

        response = _promote(client, admin, password=_WRONG_PASSWORD)

        assert (response.status_code, response.json()) == (403, _REAUTH_FAILED)
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        assert _permission_audit(db) == []
        assert db.audit_rows("login.failure") == []
        assert db.audit_rows("login.success") == []
        clock.at(_COOLDOWN)
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"

    def test_critical_permissions_wrong_password_counts_in_the_login_throttle(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Like a failed login: one failure on the account's subject and on the client IP."""
        admin = _account(db, "org_admin")

        response = _promote(_client(app), admin, password=_WRONG_PASSWORD)

        assert response.status_code == 403
        account_row = db.throttle_row("account", account_subject(admin.email))
        ip_row = db.throttle_row("ip", ip_subject(_IP_A))
        assert account_row is not None
        assert account_row["failures"] == 1
        assert ip_row is not None
        assert ip_row["failures"] == 1

    def test_critical_permissions_another_members_password_is_refused(
        self, db: FakeDb, app: FastAPI, verify: _Verify
    ) -> None:
        """Re-auth is the admin's OWN password: a colleague's valid password fails."""
        admin = _account(db, "org_admin")
        _account(db, "editor", password=_OTHER_PASSWORD)
        client = _client(app)

        response = _promote(client, admin, password=_OTHER_PASSWORD)

        assert (response.status_code, response.json()) == (403, _REAUTH_FAILED)
        assert verify.count == 1
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)

    def test_critical_permissions_locked_account_refuses_the_right_password(
        self, db: FakeDb, app: FastAPI, verify: _Verify
    ) -> None:
        admin = _account(db, "org_admin")
        limit = _lockout_after()
        db.add_throttle(
            "account",
            account_subject(admin.email),
            failures=limit,
            locked_until=datetime.now(UTC) + timedelta(minutes=15),
        )
        client = _client(app)

        response = _promote(client, admin)

        assert (response.status_code, response.json()) == (403, _REAUTH_FAILED)
        assert verify.count == 0
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        assert _permission_audit(db) == []

    @pytest.mark.usefixtures("login_delays")
    def test_critical_permissions_lockout_after_wrong_passwords_refuses_the_right_one(
        self, db: FakeDb, app: FastAPI, verify: _Verify
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app)
        limit = _lockout_after()

        wrong = [_promote(client, admin, password=_WRONG_PASSWORD) for _ in range(limit)]
        right = _promote(client, admin)

        assert [response.status_code for response in wrong] == [403] * limit
        assert (right.status_code, right.json()) == (403, _REAUTH_FAILED)
        assert verify.count == limit
        # The Nth failure locks like a failed login does: a login.lockout event
        # carrying the admin's actor columns.
        lockouts = db.audit_rows("login.lockout")
        assert any(
            (_plain_uuid(row["actor_user_id"]), _plain_uuid(row["org_id"])) == (admin.id, ORG_ID)
            for row in lockouts
        ), lockouts
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        assert _permission_audit(db) == []

    def test_critical_permissions_promote_without_body_is_400(
        self, db: FakeDb, app: FastAPI, verify: _Verify
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app)

        response = _patch_without_body(client, admin)

        assert (response.status_code, response.json()) == (400, _REAUTH_REQUIRED)
        assert verify.count == 0
        assert db.throttle == []
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        assert _permission_audit(db) == []

    @pytest.mark.parametrize("body", _BAD_BODIES)
    def test_critical_permissions_bad_body_is_422_without_echo(
        self, db: FakeDb, app: FastAPI, verify: _Verify, body: Any
    ) -> None:
        _api_route(app, "PATCH", _BASE + "/{tool}/{action}")
        admin = _account(db, "org_admin")
        client = _client(app)

        response = client.patch(_path(_GMAIL_SEND), headers=_headers(admin), json=body)

        assert response.status_code == 422, response.text
        assert _ECHO_MARKER not in response.text
        assert _ADMIN_PASSWORD not in response.text
        assert "123456789012345" not in response.text
        detail = response.json()["detail"]
        assert isinstance(detail, list)
        assert all("input" not in error for error in detail), detail
        assert verify.count == 0
        assert db.throttle == []
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)

    @pytest.mark.parametrize(("tool", "action"), _NON_PROMOTABLE_PAIRS)
    def test_critical_permissions_non_promotable_pair_is_404_without_reauth(
        self, db: FakeDb, app: FastAPI, verify: _Verify, tool: str, action: str
    ) -> None:
        _api_route(app, "PATCH", _BASE + "/{tool}/{action}")
        admin = _account(db, "org_admin")
        before = db.org_permissions(ORG_ID)

        response = _promote(_client(app), admin, (tool, action))

        assert (response.status_code, response.json()) == (404, _NOT_PROMOTABLE)
        assert verify.count == 0
        assert db.throttle == []
        assert db.audit_rows() == []
        assert db.org_permissions(ORG_ID) == before

    @pytest.mark.parametrize(("tool", "action"), _BAD_IDENTIFIERS)
    def test_critical_permissions_invalid_path_identifier_is_422(
        self, db: FakeDb, app: FastAPI, verify: _Verify, tool: str, action: str
    ) -> None:
        _api_route(app, "PATCH", _BASE + "/{tool}/{action}")
        admin = _account(db, "org_admin")

        response = _promote(_client(app), admin, (tool, action))

        assert response.status_code == 422, response.text
        assert verify.count == 0
        assert db.audit_rows() == []

    def test_critical_permissions_repeat_while_pending_keeps_the_first_pending_at(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app)
        clock.at()
        first = _promote(client, admin)
        clock.at(timedelta(minutes=2))

        second = _promote(client, admin)

        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert (second.json()["state"], _ts(second.json()["pending_at"])) == ("deny", clock.t0)
        assert _permission_audit(db) == ["org.permission_promote"]

    def test_critical_permissions_repeat_while_pending_does_not_restart_the_cooldown(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app)
        clock.at()
        assert _promote(client, admin).status_code == 200
        clock.at(timedelta(minutes=3))
        assert _promote(client, admin).status_code == 200
        clock.at(_COOLDOWN)

        listing = _get(client, admin)

        assert _state_of(listing, _GMAIL_SEND) == ("confirm", None)

    def test_critical_permissions_audit_failure_is_500_with_nothing_pending(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app, raise_server_exceptions=False)
        clock.at()
        db.fail_audit = True

        response = _promote(client, admin)

        db.fail_audit = False
        assert response.status_code == 500
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        clock.at(_COOLDOWN + timedelta(minutes=1))
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"
        assert _permission_audit(db) == []


# ---------------------------------------------------------------------------
# 5. The cooldown and per-org isolation
# ---------------------------------------------------------------------------


class TestCooldown:
    """Pending for 5 minutes; then the promoting org's next request completes it."""

    def test_critical_permissions_still_pending_one_second_before_the_cooldown(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app)
        clock.at()
        assert _promote(client, admin).status_code == 200
        clock.at(_JUST_BEFORE)

        listing = _get(client, admin)

        assert _state_of(listing, _GMAIL_SEND) == ("deny", clock.t0)
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"

    def test_critical_permissions_get_after_the_cooldown_completes_the_promotion(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app)
        _complete(client, clock, admin)

        listing = _get(client, admin)

        assert _state_of(listing, _GMAIL_SEND) == ("confirm", None)
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "confirm"
        assert _permission_audit(db) == ["org.permission_promote"]

    def test_critical_permissions_promotion_is_isolated_to_one_org(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        """Org A's completed promotion: A's row 'confirm'; B's row, listing, pending untouched."""
        admin_a = _account(db, "org_admin")
        admin_b = _account(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)
        _complete(client, clock, admin_a)

        listing_a = _get(client, admin_a)
        listing_b = _get(client, admin_b)

        assert _state_of(listing_a, _GMAIL_SEND) == ("confirm", None)
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "confirm"
        assert _stored(db, OTHER_ORG_ID, _GMAIL_SEND) == "deny"
        assert listing_b.json() == _fresh_listing()

    def test_critical_permissions_another_orgs_request_never_completes_it(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        """Org B's GET after A's cooldown resolves only B's entries: A's row stays 'deny'."""
        admin_a = _account(db, "org_admin")
        admin_b = _account(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)
        _complete(client, clock, admin_a)

        listing_b = _get(client, admin_b)

        assert listing_b.json() == _fresh_listing()
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"
        assert _stored(db, OTHER_ORG_ID, _GMAIL_SEND) == "deny"
        assert _state_of(_get(client, admin_a), _GMAIL_SEND) == ("confirm", None)

    def test_critical_permissions_each_org_promotes_on_its_own(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        """Both orgs promote the same pair: two pending entries, two audit rows, one per org."""
        admin_a = _account(db, "org_admin")
        admin_b = _account(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)
        clock.at()
        assert _promote(client, admin_a).status_code == 200
        clock.at(timedelta(minutes=2))
        assert _promote(client, admin_b).status_code == 200
        clock.at(_COOLDOWN)

        listing_a = _get(client, admin_a)
        listing_b = _get(client, admin_b)

        assert _state_of(listing_a, _GMAIL_SEND) == ("confirm", None)
        assert _state_of(listing_b, _GMAIL_SEND) == ("deny", clock.t0 + timedelta(minutes=2))
        orgs = sorted(str(_plain_uuid(row["org_id"])) for row in db.audit)
        assert orgs == sorted([str(ORG_ID), str(OTHER_ORG_ID)])


# ---------------------------------------------------------------------------
# 6. PATCH on a promoted permission: demotion
# ---------------------------------------------------------------------------


class TestDemote:
    """A pair stored 'confirm' is demoted at once, without a password."""

    def test_critical_permissions_demote_needs_no_password(
        self, db: FakeDb, app: FastAPI, verify: _Verify
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        admin = _account(db, "org_admin")

        response = _patch_without_body(_client(app), admin)

        assert response.status_code == 200, response.text
        assert response.json() == {
            "tool": "gmail",
            "action": "send",
            "state": "deny",
            "pending_at": None,
        }
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"
        assert verify.count == 0

    def test_critical_permissions_demote_writes_a_demote_audit_row(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        admin = _account(db, "org_admin")

        response = _patch_without_body(_client(app), admin)

        assert response.status_code == 200, response.text
        _assert_permission_event(
            _one(db.audit_rows("org.permission_demote")),
            action="org.permission_demote",
            actor=admin,
            org_id=ORG_ID,
            metadata={"tool": "gmail", "action": "send", "old": "confirm", "new": "deny"},
        )
        assert _permission_audit(db) == ["org.permission_demote"]

    def test_critical_permissions_demote_ignores_a_password_body(
        self, db: FakeDb, app: FastAPI, verify: _Verify
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        admin = _account(db, "org_admin")

        response = _promote(_client(app), admin, password=_WRONG_PASSWORD)

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "deny"
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"
        assert verify.count == 0
        assert db.throttle == []

    def test_critical_permissions_demote_changes_only_the_own_org(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        db.add_permissions(OTHER_ORG_ID, {"gmail": {"send": "confirm"}})
        admin_a = _account(db, "org_admin")
        admin_b = _account(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)

        response = _patch_without_body(client, admin_a)

        assert response.status_code == 200, response.text
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"
        assert _stored(db, OTHER_ORG_ID, _GMAIL_SEND) == "confirm"
        assert _state_of(_get(client, admin_b), _GMAIL_SEND) == ("confirm", None)

    def test_critical_permissions_demote_audit_failure_is_500_and_keeps_the_promotion(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        admin = _account(db, "org_admin")
        db.fail_audit = True

        response = _patch_without_body(_client(app, raise_server_exceptions=False), admin)

        db.fail_audit = False
        assert response.status_code == 500
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "confirm"
        assert _permission_audit(db) == []

    def test_critical_permissions_admin_with_right_password_can_promote_again(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        """Promote -> complete -> demote -> promote again with the right password -> complete."""
        admin = _account(db, "org_admin")
        client = _client(app)
        _complete(client, clock, admin)
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("confirm", None)
        demoted = _patch_without_body(client, admin)
        assert (demoted.status_code, demoted.json()["state"]) == (200, "deny")
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        second_start = clock.at(_COOLDOWN + timedelta(minutes=1))

        again = _promote(client, admin)

        assert again.status_code == 200, again.text
        assert (again.json()["state"], _ts(again.json()["pending_at"])) == ("deny", second_start)
        clock.at(_COOLDOWN + timedelta(minutes=1) + _COOLDOWN)
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("confirm", None)
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "confirm"
        assert _permission_audit(db) == [
            "org.permission_promote",
            "org.permission_demote",
            "org.permission_promote",
        ]


# ---------------------------------------------------------------------------
# 7. DELETE .../pending: cancelling a cooldown
# ---------------------------------------------------------------------------


class TestCancel:
    """Cancel drops the org's own pending entry only."""

    def test_critical_permissions_cancel_drops_the_pending_entry(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app)
        clock.at()
        assert _promote(client, admin).status_code == 200
        clock.at(timedelta(minutes=1))

        response = _cancel(client, admin)

        assert response.status_code == 200, response.text
        assert response.json() == {
            "tool": "gmail",
            "action": "send",
            "state": "deny",
            "pending_at": None,
        }
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        clock.at(_COOLDOWN + timedelta(minutes=1))
        assert _state_of(_get(client, admin), _GMAIL_SEND) == ("deny", None)
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"

    def test_critical_permissions_cancel_writes_a_cancel_audit_row(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin = _account(db, "org_admin")
        client = _client(app)
        clock.at()
        assert _promote(client, admin).status_code == 200

        response = _cancel(client, admin)

        assert response.status_code == 200, response.text
        _assert_permission_event(
            _one(db.audit_rows("org.permission_promote_cancel")),
            action="org.permission_promote_cancel",
            actor=admin,
            org_id=ORG_ID,
            metadata={"tool": "gmail", "action": "send"},
        )
        assert _permission_audit(db) == [
            "org.permission_promote",
            "org.permission_promote_cancel",
        ]

    def test_critical_permissions_cancel_without_pending_is_404(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _api_route(app, "DELETE", _BASE + "/{tool}/{action}/pending")
        admin = _account(db, "org_admin")

        response = _cancel(_client(app), admin)

        assert (response.status_code, response.json()) == (404, _NO_PENDING)
        assert db.audit_rows() == []

    @pytest.mark.parametrize(("tool", "action"), _NON_PROMOTABLE_PAIRS)
    def test_critical_permissions_cancel_non_promotable_pair_is_404(
        self, db: FakeDb, app: FastAPI, tool: str, action: str
    ) -> None:
        _api_route(app, "DELETE", _BASE + "/{tool}/{action}/pending")
        admin = _account(db, "org_admin")

        response = _cancel(_client(app), admin, (tool, action))

        assert (response.status_code, response.json()) == (404, _NOT_PROMOTABLE)
        assert db.audit_rows() == []

    @pytest.mark.parametrize(("tool", "action"), _BAD_IDENTIFIERS)
    def test_critical_permissions_cancel_invalid_path_identifier_is_422(
        self, db: FakeDb, app: FastAPI, tool: str, action: str
    ) -> None:
        _api_route(app, "DELETE", _BASE + "/{tool}/{action}/pending")
        admin = _account(db, "org_admin")

        response = _cancel(_client(app), admin, (tool, action))

        assert response.status_code == 422, response.text

    def test_critical_permissions_cancel_keeps_the_other_orgs_pending_entry(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        admin_b = _account(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)
        clock.at()
        assert _promote(client, admin_a).status_code == 200
        assert _promote(client, admin_b).status_code == 200

        response = _cancel(client, admin_a)

        assert response.status_code == 200, response.text
        assert _state_of(_get(client, admin_a), _GMAIL_SEND) == ("deny", None)
        assert _state_of(_get(client, admin_b), _GMAIL_SEND) == ("deny", clock.t0)
        clock.at(_COOLDOWN)
        assert _state_of(_get(client, admin_b), _GMAIL_SEND) == ("confirm", None)
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"

    def test_critical_permissions_other_orgs_admin_cannot_cancel(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        admin_b = _account(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)
        clock.at()
        assert _promote(client, admin_a).status_code == 200

        response = _cancel(client, admin_b)

        assert (response.status_code, response.json()) == (404, _NO_PENDING)
        assert _state_of(_get(client, admin_a), _GMAIL_SEND) == ("deny", clock.t0)
        assert _permission_audit(db) == ["org.permission_promote"]
        clock.at(_COOLDOWN)
        assert _state_of(_get(client, admin_a), _GMAIL_SEND) == ("confirm", None)


# ---------------------------------------------------------------------------
# 8. GH-66: the promotion notice reaches the promoting org's chats only
# ---------------------------------------------------------------------------


class TestPromotionNotice:
    """One user-role notice per completed resolution, in the promoting org's chats only."""

    def test_critical_permissions_notice_reaches_only_the_promoting_orgs_chats(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        editor_a = _account(db, "editor")
        editor_b = _account(db, "editor", OTHER_ORG_ID)
        chat_admin_a = _seed_chat(admin_a, "chat-admin-a")
        chat_editor_a = _seed_chat(editor_a, "chat-editor-a")
        chat_editor_b = _seed_chat(editor_b, "chat-editor-b")
        client = _client(app)
        _complete(client, clock, admin_a)

        response = _get(client, admin_a)

        assert response.status_code == 200, response.text
        assert _added(chat_admin_a) == [("user", _NOTICE_GMAIL)]
        assert _added(chat_editor_a) == [("user", _NOTICE_GMAIL)]
        assert _added(chat_editor_b) == []

    def test_critical_permissions_notice_is_not_repeated(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        editor_a = _account(db, "editor")
        chat = _seed_chat(editor_a, "chat-editor-a")
        client = _client(app)
        _complete(client, clock, admin_a)
        assert _get(client, admin_a).status_code == 200
        clock.at(_COOLDOWN + timedelta(minutes=3))

        assert _get(client, admin_a).status_code == 200
        assert _post_message(client, editor_a, "another-chat").status_code == 200

        assert _added(chat) == [("user", _NOTICE_GMAIL)]

    def test_critical_permissions_notice_names_every_completed_pair_once(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        editor_a = _account(db, "editor")
        chat = _seed_chat(editor_a, "chat-editor-a")
        client = _client(app)
        _complete(client, clock, admin_a, _OUTLOOK_SEND, _GMAIL_SEND)

        assert _get(client, admin_a).status_code == 200

        assert _added(chat) == [("user", _NOTICE_GMAIL_OUTLOOK)]

    def test_critical_permissions_no_notice_before_the_cooldown(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        editor_a = _account(db, "editor")
        chat = _seed_chat(editor_a, "chat-editor-a")
        client = _client(app)
        clock.at()
        assert _promote(client, admin_a).status_code == 200
        clock.at(_JUST_BEFORE)

        assert _get(client, admin_a).status_code == 200

        assert _added(chat) == []

    def test_critical_permissions_another_orgs_request_delivers_no_notice(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        admin_b = _account(db, "org_admin", OTHER_ORG_ID)
        editor_a = _account(db, "editor")
        chat = _seed_chat(editor_a, "chat-editor-a")
        client = _client(app)
        _complete(client, clock, admin_a)

        assert _get(client, admin_b).status_code == 200
        before_own_request = _added(chat)
        assert _get(client, admin_a).status_code == 200

        assert before_own_request == []
        assert _added(chat) == [("user", _NOTICE_GMAIL)]

    def test_critical_permissions_notice_survives_the_agents_context_trim(
        self, db: FakeDb, app: FastAPI, clock: _Clock
    ) -> None:
        """GH-66: a user-role notice survives _filter_mid_system (a system one would not)."""
        from admino.agent import _trim_context

        admin_a = _account(db, "org_admin")
        chat = _seed_chat(admin_a, "chat-admin-a")
        client = _client(app)
        _complete(client, clock, admin_a)
        assert _get(client, admin_a).status_code == 200

        trimmed = _trim_context(server._sessions[chat], max_messages=40)

        assert [message.content for message in trimmed].count(_NOTICE_GMAIL) == 1


# ---------------------------------------------------------------------------
# 9. The agent run gets the org's own tool policy
# ---------------------------------------------------------------------------


class TestAgentPolicy:
    """POST /api/message resolves the sender's org and passes that org's ToolPolicy."""

    def test_critical_permissions_completed_promotion_reaches_the_orgs_run(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        editor_a = _account(db, "editor")
        client = _client(app)
        _complete(client, clock, admin_a)

        response = _post_message(client, editor_a)

        assert response.status_code == 200, response.text
        assert _GMAIL_SEND in _policy_of(agent).promoted
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "confirm"

    def test_critical_permissions_another_orgs_run_is_not_promoted(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        editor_b = _account(db, "editor", OTHER_ORG_ID)
        client = _client(app)
        _complete(client, clock, admin_a)
        assert _get(client, admin_a).status_code == 200

        response = _post_message(client, editor_b)

        assert response.status_code == 200, response.text
        assert _GMAIL_SEND not in _policy_of(agent).promoted
        assert _stored(db, OTHER_ORG_ID, _GMAIL_SEND) == "deny"

    def test_critical_permissions_pending_promotion_is_not_in_the_run(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, clock: _Clock
    ) -> None:
        admin_a = _account(db, "org_admin")
        editor_a = _account(db, "editor")
        client = _client(app)
        clock.at()
        assert _promote(client, admin_a).status_code == 200
        clock.at(_JUST_BEFORE)

        response = _post_message(client, editor_a)

        assert response.status_code == 200, response.text
        assert _GMAIL_SEND not in _policy_of(agent).promoted
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "deny"

    def test_critical_permissions_demoted_pair_leaves_the_next_run(
        self, db: FakeDb, app: FastAPI, agent: MagicMock
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        admin_a = _account(db, "org_admin")
        editor_a = _account(db, "editor")
        client = _client(app)
        assert _post_message(client, editor_a, "chat-before").status_code == 200
        promoted_before = _policy_of(agent).promoted
        assert _patch_without_body(client, admin_a).status_code == 200

        response = _post_message(client, editor_a, "chat-after")

        assert response.status_code == 200, response.text
        assert _GMAIL_SEND in promoted_before
        assert _GMAIL_SEND not in _policy_of(agent).promoted

    def test_critical_permissions_residency_keeps_a_promoted_connector_switched_off(
        self, db: FakeDb, app: FastAPI, agent: MagicMock, clock: _Clock
    ) -> None:
        """GH-162: a completed gmail.send promotion doesn't reopen gmail in a residency org.
        That org's run has every Google/Microsoft service off (memory on); the other org's
        run keeps them on."""
        db.add_org(ORG_ID, data_residency=True)
        admin_a = _account(db, "org_admin")
        editor_a = _account(db, "editor")
        editor_b = _account(db, "editor", OTHER_ORG_ID)
        client = _client(app)
        _complete(client, clock, admin_a)

        sent_a = _post_message(client, editor_a)
        policy_a = _policy_of(agent)
        sent_b = _post_message(client, editor_b)
        policy_b = _policy_of(agent)

        assert (sent_a.status_code, sent_b.status_code) == (200, 200), sent_a.text
        assert _stored(db, ORG_ID, _GMAIL_SEND) == "confirm"
        assert {
            tool: policy_a.enabled_tools.get(tool) for tool in _RESIDENCY_TOOLS
        } == dict.fromkeys(_RESIDENCY_TOOLS, False)
        assert policy_a.enabled_tools.get("memory", True) is True
        assert all(policy_b.enabled_tools.get(tool, True) for tool in _RESIDENCY_TOOLS)


# ---------------------------------------------------------------------------
# 10. The lifespan and the system prompt no longer carry a global policy
# ---------------------------------------------------------------------------


class _PlainAgent:
    """A stub agent whose attribute assignments stay visible in ``vars()``."""

    def __init__(self) -> None:
        self.run = AsyncMock(return_value=_agent_result())


class TestNoGlobalPolicy:
    """Startup loads no promoted permissions and no tools gate into the agent."""

    async def test_critical_permissions_lifespan_loads_no_promoted_permissions(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        db.add_org_settings(ORG_ID, gmail=False)
        stub = _PlainAgent()
        app = create_app(agent=stub, config=_config())  # type: ignore[arg-type]
        monkeypatch.setattr("admino.database.init_pool", AsyncMock(return_value=db.pool))
        monkeypatch.setattr("admino.database.close_pool", AsyncMock())
        monkeypatch.setattr("admino.audit_events.run_retention_job", AsyncMock())
        monkeypatch.setattr("admino.sessions.run_session_purge_job", AsyncMock())
        monkeypatch.setattr("admino.mailer.load_smtp_config", MagicMock(return_value=None))

        with patch_org_purge_job(AsyncMock()), patch_login_throttle_purge_job(AsyncMock()):
            async with server._lifespan(app):
                attributes = set(vars(stub))
                permission_reads = db.matching(r"^select\b.*\bfrom permissions\b")

        assert attributes == {"run"}
        assert permission_reads == []
        assert not hasattr(server, "_promoted_permissions")

    def test_critical_permissions_base_prompt_has_no_static_tool_line(self) -> None:
        """GH-170 (was ``main._build_system_prompt``, GH-161): the base prompt names only
        the tools it is given (the run's own, from the org's policy), never what the
        registry holds; without any, its last line says so."""
        from pydantic import BaseModel, Field

        from admino import prompt_assembly
        from admino.tools.registry import clear_registry, register_tool

        class _Args(BaseModel):
            q: str = Field(min_length=1, max_length=10)

        async def _handler(args: _Args, *, session_id: str, **_: object) -> str:
            return "ok"

        clear_registry()
        try:
            register_tool("gmail", "read", "Read mail", _Args)(_handler)
            prompt = prompt_assembly.base_prompt(tools=[], response_language=None)
        finally:
            clear_registry()

        assert ("You have access to the following tools" in prompt, prompt.splitlines()[-1]) == (
            False,
            "You have no tools available.",
        )


# GH-170: every response language base_prompt takes (None: none resolved).
_RESPONSE_LANGUAGES: Final[tuple[str | None, ...]] = (None, "de", "fr", "it", "en")


def _description(tool: str, action: str) -> Any:
    """A registry ToolDescription with an empty argument schema."""
    from admino.tools.registry import ToolDescription

    return ToolDescription(
        tool=tool,
        action=action,
        description=f"{tool}.{action} (GH-170 spec).",
        parameters_schema={"type": "object", "properties": {}},
    )


class TestSystemPromptDynamicPermissionGuidance:
    """The base prompt tells the LLM that permissions can change mid-conversation and
    never to substitute an unavailable action (kept from GH-66 / GH-77: the per-org
    promotions of GH-161 rely on it). GH-170: it lives in
    ``prompt_assembly.base_prompt``, rebuilt per request, in every response language."""

    @pytest.mark.parametrize("response_language", _RESPONSE_LANGUAGES)
    def test_system_prompt_includes_dynamic_permission_guidance(
        self, response_language: str | None
    ) -> None:
        from admino import prompt_assembly

        prompt = prompt_assembly.base_prompt(
            tools=[_description("gmail", "send")], response_language=response_language
        )

        lowered = prompt.lower()
        assert (
            "permissions can change during a conversation" in lowered,
            "never refuse based on earlier" in lowered,
        ) == (True, True)

    @pytest.mark.parametrize("response_language", _RESPONSE_LANGUAGES)
    def test_system_prompt_includes_no_substitution_guardrail(
        self, response_language: str | None
    ) -> None:
        """GH-77: never substitute a different action when the requested one isn't available."""
        from admino import prompt_assembly

        prompt = prompt_assembly.base_prompt(
            tools=[_description("google_calendar", "read")], response_language=response_language
        )

        lowered = prompt.lower()
        assert (
            "never substitute" in lowered,
            "not available" in lowered,
            "permissions can change during a conversation" in lowered,
        ) == (True, True, True)
