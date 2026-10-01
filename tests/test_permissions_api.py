"""HTTP spec for the per-org tool permission matrix, its read-only summary and the
per-run tool policy (GH-161).

Replaces the tests of the removed ``GET`` / ``PATCH /api/permissions``. The
FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with a real
``AppConfig``. The real ``require_session``, ``admino.org_permissions``,
``admino.scoped_settings`` and ``admino.audit_events`` code runs. The agent is
a spy (``_SpyAgent``): it records every run's keyword arguments and every
attribute the server assigns on it. Two active orgs (``ORG_ID`` and
``OTHER_ORG_ID``) each start with the ``DEFAULT_PERMISSIONS`` matrix.

What these tests pin down (the GH-161 implementation contract):
- Routes: ``GET`` / ``PATCH /api/org/permissions`` (rate keys
  ``/api/org/permissions/{get,patch}`` with (1.0, 5) / (0.2, 2)) and ``GET
  /api/permissions/summary`` (``/api/permissions/summary/get``, (1.0, 10)).
  Each sits behind a session (401 ``{"detail": "Unauthorized"}``), then a
  per-user rate limit (429 ``{"detail": "Rate limit exceeded"}``, bucket
  ``(key, "user:<id>")``, before any permissions / org_settings / audit
  statement), then the capability (403 ``{"detail": "Forbidden"}``, before any
  of those statements): ``org.permissions.manage`` (Org Admin only) for the
  matrix, ``org.permissions.view`` (Org Admin, Editor, Viewer; never the Super
  Admin) for the summary. The old ``/api/permissions`` routes and rate keys
  are gone (404 / 405).
- The matrix is the Org Admin's own org: GET lists the org's stored rows
  sorted by (tool, action) with the raw stored state; PATCH changes one row
  of that org only (org A's change never shows in org B's GET or runs), stores
  the normalized value (``allow`` on google_calendar.create becomes
  ``confirm``), treats a missing row as ``deny``, writes nothing for an
  unchanged value, and records one ``org.permission_change`` audit row (actor,
  org, target, client IP, metadata tool/action/old/new). A hardcoded denial of
  either tier (any value, ``deny`` included) is a 400 with the fixed message
  and an unknown (tool, action) pair a 400 ``{"detail": "Unknown tool
  action."}``; neither reads or writes the matrix. Bad bodies (extra keys
  included) are 422 without echoing the input. An audit failure is a 500
  with nothing changed. A cross-origin PATCH is a 403 before any database call.
- Per-run policy: ``POST /api/message`` and ``POST /api/confirm`` pass
  ``tool_policy`` (a ``models.ToolPolicy``) to ``_agent.run``: the sender's
  org's validated matrix, its promoted tier-2 pairs (stored ``confirm``) and
  its enabled services (org_settings, all on without a row). Two orgs'
  runs, also concurrent ones, each get their own org's policy; nothing is
  ever assigned to ``_agent._permissions`` / ``_promoted`` /
  ``_tools_enabled``; the server keeps no global promotion state.
- Enabled services (the cleanup of #159's interim gate): org A disabling a
  service never disables it for org B, and org B's disabled service stays off
  for org B only; ``PATCH /api/org/settings`` no longer touches the agent.
- The summary: one entry per stored (tool, action) of the caller's org,
  sorted, with the effective state: ``disabled`` for a disabled service, the
  hardcoded denials ``deny`` (whatever is stored), a promoted tier-2 pair
  ``confirm``, otherwise the stored state. Never another org's.

All database calls are faked. No network, no real PostgreSQL, no LLM.

Security notes:
- Tenant isolation: every statement on permissions / org_settings binds the
  caller's org id and never another org's (bound-id checks).
- Least privilege: only the Org Admin edits the matrix; the Super Admin reaches
  no org's matrix or summary.
- Hardcoded denials stay global: no org can override one, not even to ``deny``.
- No agent-wide mutable policy: the server never mutates the shared agent.
- Fail closed: an audit failure is a 500 and nothing is written; a 422 never
  echoes the input.
"""

from __future__ import annotations

import asyncio
import copy
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import server
from admino.config import AppConfig
from admino.models import AgentResult, LLMMessage, PendingConfirmation, ToolCall
from admino.permissions import (
    DEFAULT_PERMISSIONS,
    HARDCODED_DENIALS,
    IMMUTABLE_DENIALS,
    PROMOTABLE_DENIALS,
    check_permission,
    validate_permissions_config,
)
from admino.server import create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, TOOL_NAMES, Call, FakeDb, plain

if TYPE_CHECKING:
    import uuid
    from collections.abc import Callable

    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

    from admino.models import ToolPolicy

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_IP_A = "203.0.113.61"
_MATRIX = "/api/org/permissions"
_SUMMARY = "/api/permissions/summary"
_OLD = "/api/permissions"
_ORG_SETTINGS = "/api/org/settings"
_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_UNKNOWN = {"detail": "Unknown tool action."}
_HARDCODED = {"detail": "This tool/action pair is a hardcoded denial and cannot be changed."}
_UNSET: Final = object()

# action -> (method, path)
_ROUTES: dict[str, tuple[str, str]] = {
    "matrix_get": ("GET", _MATRIX),
    "matrix_patch": ("PATCH", _MATRIX),
    "summary_get": ("GET", _SUMMARY),
}
_ACTIONS = list(_ROUTES)
_MATRIX_ACTIONS = ["matrix_get", "matrix_patch"]
_ROUTE_KEYS: dict[str, str] = {
    "matrix_get": "/api/org/permissions/get",
    "matrix_patch": "/api/org/permissions/patch",
    "summary_get": "/api/permissions/summary/get",
}
_EXPECTED_LIMITS: dict[str, tuple[float, int]] = {
    "/api/org/permissions/get": (1.0, 5),
    "/api/org/permissions/patch": (0.2, 2),
    "/api/permissions/summary/get": (1.0, 10),
}
# Read at import, before any fixture patches the limits.
_CONFIGURED_LIMITS = {key: server._RATE_LIMITS.get(key) for key in _EXPECTED_LIMITS}
_OLD_RATE_KEYS = ["/api/permissions/get", "/api/permissions/patch"]
# Functional tests aren't about rate limits: these keys get a large bucket.
_ROOMY_KEYS = [
    *_EXPECTED_LIMITS,
    "/api/message",
    "/api/confirm",
    "/api/org/settings/get",
    "/api/org/settings/patch",
]
_DEFAULT_PATCH: dict[str, str] = {"tool": "gmail", "action": "read", "permission": "confirm"}
_FORBIDDEN_AGENT_ATTRS: Final = frozenset({"_permissions", "_promoted", "_tools_enabled"})
_REMOVED_SERVER_GLOBALS = [
    "_pending_promotions",
    "_promoted_permissions",
    "_resolve_pending_promotions",
    "_PROMOTION_COOLDOWN_S",
]
_ALL_ON: dict[str, bool] = dict.fromkeys(TOOL_NAMES, True)
_POLICY_TABLES = r"\b(?:permissions|org_settings|audit_events)\b"
_MATRIX_WRITE = r"^(?:insert into|update|delete from) permissions\b"
_CROSS_ORIGIN = [
    pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
    pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
]
# Every hardcoded denial that is a row of the seeded matrix (both tiers).
_HARDCODED_PAIRS = sorted(
    pair for pair in HARDCODED_DENIALS if pair[1] in DEFAULT_PERMISSIONS.get(pair[0], {})
)
_HARDCODED_PATCHES = [
    pytest.param(tool, action, value, id=f"{tool}.{action}-{value}")
    for tool, action in _HARDCODED_PAIRS
    for value in ("allow", "confirm", "deny")
]
# Well-formed pairs that aren't in DEFAULT_PERMISSIONS (documents.delete is a hardcoded
# denial of a tool that isn't in the matrix: the unknown check comes first).
_UNKNOWN_PATCHES = [
    pytest.param({"tool": "slack", "action": "post", "permission": "allow"}, id="unknown-tool"),
    pytest.param({"tool": "gmail", "action": "archive", "permission": "allow"}, id="gmail-archive"),
    pytest.param({"tool": "files", "action": "read", "permission": "allow"}, id="removed-files"),
    pytest.param({"tool": "memory", "action": "write", "permission": "confirm"}, id="memory-write"),
    pytest.param({"tool": "documents", "action": "delete", "permission": "deny"}, id="documents"),
]
_BAD_PATCH_BODIES = [
    pytest.param({"tool": "gmail", "action": "read", "permission": "block"}, id="state-unknown"),
    pytest.param({"tool": "gmail", "action": "read", "permission": "ALLOW"}, id="state-capitals"),
    pytest.param(
        {"tool": "gmail", "action": "read", "permission": "ECHOMARK42-allow"}, id="state-marker"
    ),
    pytest.param({"tool": "gmail", "action": "read", "permission": 1}, id="state-int"),
    pytest.param({"tool": "gmail", "action": "read", "permission": True}, id="state-bool"),
    pytest.param({"tool": "gmail", "action": "read", "permission": None}, id="state-null"),
    pytest.param({"tool": "gmail", "action": "read"}, id="missing-state"),
    pytest.param({"action": "read", "permission": "allow"}, id="missing-tool"),
    pytest.param({"tool": "gmail", "permission": "allow"}, id="missing-action"),
    pytest.param({}, id="empty-object"),
    pytest.param([], id="list"),
    pytest.param("ECHOMARK42", id="string"),
    pytest.param({"tool": "Gmail", "action": "read", "permission": "allow"}, id="tool-capital"),
    pytest.param({"tool": 42, "action": "read", "permission": "allow"}, id="tool-int"),
    pytest.param(
        {"tool": "'; DROP TABLE permissions; --ECHOMARK42", "action": "read", "permission": "deny"},
        id="tool-sql",
    ),
    pytest.param(
        {"tool": "gmail", "action": "read' OR '1'='1 ECHOMARK42", "permission": "allow"},
        id="action-sql",
    ),
    pytest.param({"tool": "gmail" + chr(0), "action": "read", "permission": "allow"}, id="nul"),
    pytest.param({"tool": "gmail\n", "action": "read", "permission": "allow"}, id="newline"),
    pytest.param(
        {"tool": "gm" + chr(0x430) + "il", "action": "read", "permission": "allow"},
        id="homoglyph",
    ),
    pytest.param({"tool": "a" * 64, "action": "read", "permission": "allow"}, id="tool-64-chars"),
    pytest.param(
        {"tool": "gmail", "action": "r" * 200 + "ECHOMARK42", "permission": "allow"},
        id="action-oversized",
    ),
    pytest.param(
        {"tool": "gmail", "action": "read", "permission": "allow", "note": "ECHOMARK42-extra"},
        id="extra-key",
    ),
    pytest.param(
        {"tool": "gmail", "action": "read", "permission": "allow", "org_id": str(OTHER_ORG_ID)},
        id="extra-org-id",
    ),
]


# ---------------------------------------------------------------------------
# The spy agent
# ---------------------------------------------------------------------------


class _Barrier:
    """Holds every arriving run until ``parties`` runs are in flight at once."""

    def __init__(self, parties: int) -> None:
        self.parties = parties
        self.arrived = 0
        self.event = asyncio.Event()

    async def arrive(self) -> None:
        self.arrived += 1
        if self.arrived >= self.parties:
            self.event.set()
        await asyncio.wait_for(self.event.wait(), timeout=5)


class _SpyAgent:
    """Stands in for the Agent: records each run's keyword arguments and the name of
    every attribute assigned on it (the server must never set the policy on it)."""

    assigned: list[str]

    def __init__(self) -> None:
        object.__setattr__(self, "assigned", [])
        self._llm = MagicMock(name="llm-client")
        self.runs: list[dict[str, Any]] = []
        self.results: list[AgentResult] = []
        self.barrier: _Barrier | None = None

    def __setattr__(self, name: str, value: Any) -> None:
        self.assigned.append(name)
        object.__setattr__(self, name, value)

    async def run(self, user_message: str, session_id: str, **kwargs: Any) -> AgentResult:
        self.runs.append({"user_message": user_message, "session_id": session_id, **kwargs})
        if self.barrier is not None:
            await self.barrier.arrive()
        return self.results.pop(0) if self.results else _agent_result()


def _agent_result(pending: PendingConfirmation | None = None) -> AgentResult:
    return AgentResult(
        status="final" if pending is None else "awaiting_confirmation",
        response="Done.",
        history=[
            LLMMessage(role="user", content="hi"),
            LLMMessage(role="assistant", content="Done."),
        ],
        tool_calls=[],
        pending_confirmation=pending,
    )


def _pending(session_id: str) -> PendingConfirmation:
    now = datetime.now(UTC)
    return PendingConfirmation(
        confirmation_id="confirm-161",
        session_id=session_id,
        tool_call=ToolCall(tool="google_calendar", action="create", args={}),
        created_at=now,
        expires_at=now + timedelta(seconds=300),
    )


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database get_pool() returns: two active orgs, each with the default matrix."""
    fake = FakeDb()
    for org_id in (ORG_ID, OTHER_ORG_ID):
        fake.add_org(org_id)
        fake.add_permissions(org_id)
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


@pytest.fixture(autouse=True)
def _roomy_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _ROOMY_KEYS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


@pytest.fixture()
def agent() -> _SpyAgent:
    return _SpyAgent()


def _config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
    )


@pytest.fixture()
def app(agent: _SpyAgent) -> FastAPI:
    """create_app with the spy agent and a real config (no lifespan under TestClient)."""
    return create_app(agent=agent, config=_config())  # type: ignore[arg-type]


def _client(app: FastAPI, ip: str = _IP_A, **kwargs: Any) -> TestClient:
    return TestClient(app, client=(ip, 50000), follow_redirects=False, **kwargs)


def _login(db: FakeDb, role: str, org_id: uuid.UUID = ORG_ID) -> tuple[uuid.UUID, str]:
    """An account with this role (or a Super Admin) and a live session: (id, token)."""
    if role == "super_admin":
        user_id = db.add_account(kind="super_admin", role=None)
    else:
        user_id = db.add_account(role=role, org_id=org_id)
    return user_id, db.open_session(user_id)


def _headers(token: str | None, **extra: str) -> dict[str, str]:
    cookie = {} if token is None else {"Cookie": f"{_COOKIE}={token}"}
    return {**cookie, **extra}


def _call(
    client: TestClient, action: str, token: str | None, *, body: Any = _UNSET, **headers: str
) -> httpx.Response:
    """Call one of the three routes (the PATCH with its default body unless one is given)."""
    method, path = _ROUTES[action]
    if body is _UNSET:
        body = _DEFAULT_PATCH if method == "PATCH" else None
    kwargs: dict[str, Any] = {} if body is None else {"json": body}
    return client.request(method, path, headers=_headers(token, **headers), **kwargs)


def _patch(client: TestClient, token: str, tool: str, action: str, value: str) -> httpx.Response:
    body = {"tool": tool, "action": action, "permission": value}
    return client.patch(_MATRIX, headers=_headers(token), json=body)


def _post_message(
    client: TestClient, token: str, message: str = "hello", session_id: str = "chat-161"
) -> httpx.Response:
    return client.post(
        "/api/message", headers=_headers(token), json={"message": message, "session_id": session_id}
    )


def _depends_on(dependant: Dependant, target: Callable[..., Any]) -> bool:
    return any(dep.call is target or _depends_on(dep, target) for dep in dependant.dependencies)


def _route(app: FastAPI, method: str, path: str) -> APIRoute:
    matches = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == path and method in route.methods
    ]
    assert len(matches) == 1, f"{method} {path} is not registered"
    return matches[0]


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of every table these routes may write (sessions excluded: any request
    may refresh last_seen_at)."""
    return copy.deepcopy(
        {
            "permissions": db.permissions,
            "org_settings": db.org_settings,
            "audit": db.audit,
            "users": db.users,
            "orgs": db.orgs,
        }
    )


def _policy_calls(db: FakeDb, since: int = 0) -> list[Call]:
    """Statements on permissions, org_settings or audit_events after call index ``since``."""
    return [call for call in db.calls[since:] if _matches(call, _POLICY_TABLES)]


def _matches(call: Call, pattern: str) -> bool:
    return re.search(pattern, call.normalized) is not None


def _binds(call: Call, org_id: uuid.UUID) -> bool:
    return any(str(arg) == str(org_id) for arg in call.args)


def _assert_scoped_to(db: FakeDb, org_id: uuid.UUID, other: uuid.UUID, since: int = 0) -> None:
    """Every permissions / org_settings statement since ``since`` binds ``org_id`` and none
    binds ``other``; at least one such statement ran."""
    calls = [
        call
        for call in db.calls[since:]
        if _matches(call, r"\b(?:permissions|org_settings)\b")
        and not _matches(call, r"^insert into audit_events\b")
    ]
    assert calls, "no permissions / org_settings statement ran"
    assert all(_binds(call, org_id) for call in calls), [call.sql for call in calls]
    assert not any(_binds(call, other) for call in calls), [call.sql for call in calls]


def _limited(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    """One request per key, then nothing for a long time."""
    monkeypatch.setitem(server._RATE_LIMITS, key, (0.001, 1))


def _entries(matrix: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    """A matrix as PermissionsResponse entries, sorted by (tool, action)."""
    return [
        {"tool": tool, "action": action, "permission": matrix[tool][action]}
        for tool in sorted(matrix)
        for action in sorted(matrix[tool])
    ]


def _defaults() -> dict[str, dict[str, str]]:
    return copy.deepcopy(DEFAULT_PERMISSIONS)


def _with(
    matrix: dict[str, dict[str, str]], tool: str, action: str, value: str
) -> dict[str, dict[str, str]]:
    changed = copy.deepcopy(matrix)
    changed[tool][action] = value
    return changed


def _effective(tool: str, action: str, stored: str, disabled: frozenset[str]) -> str:
    """The summary state the contract derives for one stored row."""
    if tool in disabled:
        return "disabled"
    if (tool, action) in IMMUTABLE_DENIALS:
        return "deny"
    if (tool, action) in PROMOTABLE_DENIALS:
        return "confirm" if stored == "confirm" else "deny"
    return stored


def _expected_summary(db: FakeDb, org_id: uuid.UUID) -> dict[str, list[dict[str, str]]]:
    tools = db.org_tools(org_id) or _ALL_ON
    disabled = frozenset(tool for tool, enabled in tools.items() if not enabled)
    matrix = db.org_permissions(org_id)
    return {
        "permissions": [
            {
                "tool": tool,
                "action": action,
                "state": _effective(tool, action, matrix[tool][action], disabled),
            }
            for tool in sorted(matrix)
            for action in sorted(matrix[tool])
        ]
    }


def _states(body: dict[str, Any]) -> dict[tuple[str, str], str]:
    return {(entry["tool"], entry["action"]): entry["state"] for entry in body["permissions"]}


def _echo_markers(value: Any) -> list[str]:
    """The ECHOMARK42 marker and every long string the request carried (any depth)."""
    markers = ["ECHOMARK42"]
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str) and len(item.strip()) >= 10:
            markers.append(item.strip())
    return markers


def _policy(run: dict[str, Any]) -> ToolPolicy:
    """The run's tool_policy keyword, which must be a models.ToolPolicy."""
    from admino.models import ToolPolicy

    assert "tool_policy" in run, f"the agent run got no tool_policy: {sorted(run)}"
    policy = run["tool_policy"]
    assert isinstance(policy, ToolPolicy), type(policy)
    return policy


def _decision(policy: ToolPolicy, tool: str, action: str) -> str:
    return check_permission(tool, action, policy.permissions, promoted=policy.promoted).allowed


def _assert_policy_of(policy: ToolPolicy, db: FakeDb, org_id: uuid.UUID) -> None:
    """The policy is exactly ``org_id``'s: its validated matrix, its promoted tier-2 pairs
    and its enabled services."""
    matrix = db.org_permissions(org_id)
    assert policy.permissions == validate_permissions_config(matrix)
    promoted = frozenset(
        (tool, action)
        for tool, action in PROMOTABLE_DENIALS
        if matrix.get(tool, {}).get(action) == "confirm"
    )
    assert policy.promoted == promoted
    assert dict(policy.enabled_tools) == (db.org_tools(org_id) or _ALL_ON)


def _assert_agent_untouched(agent: _SpyAgent) -> None:
    assigned = _FORBIDDEN_AGENT_ATTRS & set(agent.assigned)
    assert not assigned, f"the server set {sorted(assigned)} on the shared agent"
    assert not any(hasattr(agent, name) for name in _FORBIDDEN_AGENT_ATTRS)


def _seed_distinct_orgs(db: FakeDb) -> None:
    """Org A: gmail off, outlook.send promoted, outlook.read deny, a tampered memory.delete
    'allow', memory.recall confirm. Org B: outlook off, gmail.send promoted, gmail.read
    deny, memory.store deny."""
    db.add_org_settings(ORG_ID, gmail=False)
    db.add_permissions(
        ORG_ID,
        {"outlook": {"send": "confirm", "read": "deny"}, "memory": {"delete": "allow"}},
    )
    db.add_permissions(ORG_ID, {"memory": {"recall": "confirm"}})
    db.add_org_settings(OTHER_ORG_ID, outlook=False)
    db.add_permissions(
        OTHER_ORG_ID,
        {"gmail": {"send": "confirm", "read": "deny"}, "memory": {"store": "deny"}},
    )


# ---------------------------------------------------------------------------
# 1. The routes
# ---------------------------------------------------------------------------


class TestRoutes:
    """Three session routes with their own per-user rate-limit keys; /api/permissions is
    gone."""

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_permissions_api_route_is_registered(self, app: FastAPI, action: str) -> None:
        _route(app, *_ROUTES[action])

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_permissions_api_route_depends_on_require_session(
        self, app: FastAPI, action: str
    ) -> None:
        route = _route(app, *_ROUTES[action])
        assert _depends_on(route.dependant, server.require_session)

    @pytest.mark.parametrize(("key", "rate"), list(_EXPECTED_LIMITS.items()))
    def test_permissions_api_rate_limit_values(self, key: str, rate: tuple[float, int]) -> None:
        assert _CONFIGURED_LIMITS[key] == pytest.approx(rate)

    @pytest.mark.parametrize("key", _OLD_RATE_KEYS)
    def test_permissions_api_old_rate_limit_keys_are_removed(self, key: str) -> None:
        assert key not in server._RATE_LIMITS

    def test_permissions_api_old_route_is_not_registered(self, app: FastAPI) -> None:
        old = [
            route.path for route in app.routes if isinstance(route, APIRoute) and route.path == _OLD
        ]
        assert old == []

    def test_permissions_api_old_get_is_404_and_reads_nothing(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")

        response = _client(app).get(_OLD, headers=_headers(token))

        assert response.status_code == 404
        assert _policy_calls(db) == []

    def test_permissions_api_old_patch_is_refused_and_writes_nothing(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")
        before = _state(db)

        response = _client(app).patch(
            _OLD,
            headers=_headers(token),
            json={"tool": "gmail", "action": "read", "permission": "deny"},
        )

        assert response.status_code in {404, 405}
        assert _state(db) == before

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_permissions_api_route_without_a_session_is_401(
        self, db: FakeDb, app: FastAPI, action: str
    ) -> None:
        _route(app, *_ROUTES[action])
        before = _state(db)

        response = _call(_client(app), action, None)

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert _policy_calls(db) == []
        assert _state(db) == before

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_permissions_api_route_with_an_unknown_cookie_is_401(
        self, db: FakeDb, app: FastAPI, action: str
    ) -> None:
        _route(app, *_ROUTES[action])

        response = _call(_client(app), action, "not-a-session-token-at-all-0000000000000000")

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert _policy_calls(db) == []


# ---------------------------------------------------------------------------
# 2. Authorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    """The matrix is the Org Admin's; the summary every member's; the Super Admin gets
    neither. A refusal reads and writes nothing."""

    @pytest.mark.parametrize("role", ["editor", "viewer", "super_admin"])
    @pytest.mark.parametrize("action", _MATRIX_ACTIONS)
    def test_permissions_api_non_admin_gets_403_on_the_matrix(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent, action: str, role: str
    ) -> None:
        """The issue's test: a non-admin gets 403 on the routes, before any database work."""
        _route(app, *_ROUTES[action])
        _, token = _login(db, role)
        before = _state(db)
        since = len(db.calls)

        response = _call(_client(app), action, token)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _policy_calls(db, since) == []
        assert _state(db) == before
        _assert_agent_untouched(agent)

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    def test_permissions_api_member_may_read_the_summary(
        self, db: FakeDb, app: FastAPI, role: str
    ) -> None:
        _, token = _login(db, role)

        response = _call(_client(app), "summary_get", token)

        assert response.status_code == 200, response.text

    def test_permissions_api_super_admin_gets_403_on_the_summary(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _route(app, *_ROUTES["summary_get"])
        _, token = _login(db, "super_admin")
        since = len(db.calls)

        response = _call(_client(app), "summary_get", token)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _policy_calls(db, since) == []

    def test_permissions_api_rate_limit_runs_before_the_capability_check(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An Editor's refused calls spend its own bucket: 403, then 429."""
        _route(app, *_ROUTES["matrix_get"])
        _limited(monkeypatch, _ROUTE_KEYS["matrix_get"])
        _, token = _login(db, "editor")
        client = _client(app)

        first = _call(client, "matrix_get", token)
        second = _call(client, "matrix_get", token)

        assert (first.status_code, first.json()) == (403, _FORBIDDEN)
        assert (second.status_code, second.json()) == (429, _RATE_LIMITED)


# ---------------------------------------------------------------------------
# 3. Rate limits and CSRF
# ---------------------------------------------------------------------------


class TestRateLimitsAndCsrf:
    """Per-user buckets that refuse before any database work; cross-origin writes refused."""

    @pytest.mark.parametrize("action", _ACTIONS)
    def test_permissions_api_rate_limit_is_per_user_and_before_the_database(
        self, db: FakeDb, app: FastAPI, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """With a burst of 1: the second call is 429 without touching the matrix; another
        user's call still runs; the bucket is (key, "user:<id>")."""
        _route(app, *_ROUTES[action])
        _limited(monkeypatch, _ROUTE_KEYS[action])
        role = "editor" if action == "summary_get" else "org_admin"
        user_a, token_a = _login(db, role)
        _, token_b = _login(db, role, OTHER_ORG_ID)
        client = _client(app)

        first = _call(client, action, token_a)
        since = len(db.calls)
        limited = _call(client, action, token_a)
        limited_calls = _policy_calls(db, since)
        other = _call(client, action, token_b)

        assert first.status_code == 200, first.text
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert limited_calls == []
        assert other.status_code == 200, other.text
        assert (_ROUTE_KEYS[action], f"user:{user_a}") in server._rate_buckets

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    def test_permissions_api_cross_origin_patch_is_refused_before_the_database(
        self, db: FakeDb, app: FastAPI, headers: dict[str, str]
    ) -> None:
        _route(app, *_ROUTES["matrix_patch"])
        _, token = _login(db, "org_admin")
        before = _state(db)

        response = _call(_client(app), "matrix_patch", token, **headers)

        assert (response.status_code, response.json()) == (403, _CSRF_REFUSED)
        assert db.calls == []
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 4. GET /api/org/permissions
# ---------------------------------------------------------------------------


class TestMatrixGet:
    """The Org Admin reads their own org's stored rows, sorted, raw states."""

    def test_permissions_api_get_returns_only_the_admins_org_matrix(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"read": "deny"}})
        db.add_permissions(OTHER_ORG_ID, {"memory": {"recall": "confirm"}})
        _, token_a = _login(db, "org_admin", ORG_ID)
        _, token_b = _login(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)

        read_a = _call(client, "matrix_get", token_a)
        read_b = _call(client, "matrix_get", token_b)

        assert read_a.status_code == 200, read_a.text
        assert read_a.json() == {
            "permissions": _entries(_with(_defaults(), "gmail", "read", "deny"))
        }
        assert read_b.json() == {
            "permissions": _entries(_with(_defaults(), "memory", "recall", "confirm"))
        }

    def test_permissions_api_get_shows_a_promoted_pair_as_stored(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """A promoted tier-2 pair is stored 'confirm' and listed as such."""
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        _, token = _login(db, "org_admin")

        response = _call(_client(app), "matrix_get", token)

        entries = {
            (e["tool"], e["action"]): e["permission"] for e in response.json()["permissions"]
        }
        assert entries[("gmail", "send")] == "confirm"
        assert entries[("outlook", "send")] == "deny"

    def test_permissions_api_get_reads_only_the_admins_org(self, db: FakeDb, app: FastAPI) -> None:
        _, token = _login(db, "org_admin", OTHER_ORG_ID)
        since = len(db.calls)

        response = _call(_client(app), "matrix_get", token)

        assert response.status_code == 200, response.text
        _assert_scoped_to(db, OTHER_ORG_ID, ORG_ID, since)

    def test_permissions_api_get_of_an_org_without_rows_is_empty(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        third = db.add_org()
        _, token = _login(db, "org_admin", third)

        response = _call(_client(app), "matrix_get", token)

        assert (response.status_code, response.json()) == (200, {"permissions": []})


# ---------------------------------------------------------------------------
# 5. PATCH /api/org/permissions
# ---------------------------------------------------------------------------


class TestMatrixPatch:
    """One row of the Org Admin's own org; audited; hardcoded and unknown pairs refused."""

    def test_permissions_api_patch_changes_only_the_admins_org(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """The issue's test: org A's matrix never affects org B."""
        _, token_a = _login(db, "org_admin", ORG_ID)
        _, token_b = _login(db, "org_admin", OTHER_ORG_ID)
        client = _client(app)
        b_before = copy.deepcopy(
            {key: row for key, row in db.permissions.items() if key[0] == OTHER_ORG_ID}
        )

        patched = _patch(client, token_a, "gmail", "read", "confirm")
        read_b = _call(client, "matrix_get", token_b)

        expected_a = _with(_defaults(), "gmail", "read", "confirm")
        assert patched.status_code == 200, patched.text
        assert patched.json() == {"permissions": _entries(expected_a)}
        assert db.org_permissions(ORG_ID) == expected_a
        assert {key: row for key, row in db.permissions.items() if key[0] == OTHER_ORG_ID} == (
            b_before
        )
        assert read_b.json() == {"permissions": _entries(_defaults())}

    def test_permissions_api_patch_binds_only_the_admins_org(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin", ORG_ID)
        since = len(db.calls)

        response = _patch(_client(app), token, "memory", "recall", "deny")

        assert response.status_code == 200, response.text
        _assert_scoped_to(db, ORG_ID, OTHER_ORG_ID, since)

    def test_permissions_api_patch_is_audited_with_the_client_ip(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        admin_id, token = _login(db, "org_admin")

        response = _patch(_client(app), token, "gmail", "read", "confirm")

        assert response.status_code == 200, response.text
        assert len(db.audit) == 1, db.audit
        event = db.audit[0]
        assert event["action"] == "org.permission_change"
        assert (event["actor_kind"], plain(event["actor_user_id"])) == ("member", admin_id)
        assert plain(event["org_id"]) == ORG_ID
        assert (event["target_type"], event["target_ids"]) == ("organization", [str(ORG_ID)])
        assert event["ip"] == _IP_A
        assert event["metadata"] == {
            "tool": "gmail",
            "action": "read",
            "old": "allow",
            "new": "confirm",
        }

    def test_permissions_api_patch_unchanged_value_writes_nothing(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, token = _login(db, "org_admin")
        before = _state(db)
        since = len(db.calls)

        response = _patch(_client(app), token, "gmail", "read", "allow")

        assert response.status_code == 200, response.text
        assert response.json() == {"permissions": _entries(_defaults())}
        assert _state(db) == before
        assert [call for call in db.calls[since:] if _matches(call, _MATRIX_WRITE)] == []

    def test_permissions_api_patch_of_a_missing_row_starts_from_deny(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """Org A has no memory.list row: the change is audited as deny -> allow."""
        third = db.add_org()
        matrix = _defaults()
        del matrix["memory"]["list"]
        db.add_permissions(third, matrix)
        _, token = _login(db, "org_admin", third)

        response = _patch(_client(app), token, "memory", "list", "allow")

        assert response.status_code == 200, response.text
        assert db.org_permissions(third)["memory"]["list"] == "allow"
        assert [row["metadata"] for row in db.audit] == [
            {"tool": "memory", "action": "list", "old": "deny", "new": "allow"}
        ]

    def test_permissions_api_patch_stores_the_normalized_value(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """'allow' on a write-mutating action is stored (and audited) as 'confirm'."""
        db.add_permissions(ORG_ID, {"google_calendar": {"create": "deny"}})
        _, token = _login(db, "org_admin")

        response = _patch(_client(app), token, "google_calendar", "create", "allow")

        assert response.status_code == 200, response.text
        assert db.org_permissions(ORG_ID)["google_calendar"]["create"] == "confirm"
        entries = {
            (e["tool"], e["action"]): e["permission"] for e in response.json()["permissions"]
        }
        assert entries[("google_calendar", "create")] == "confirm"
        assert [row["metadata"] for row in db.audit] == [
            {"tool": "google_calendar", "action": "create", "old": "deny", "new": "confirm"}
        ]

    @pytest.mark.parametrize(("tool", "action", "value"), _HARDCODED_PATCHES)
    def test_permissions_api_patch_hardcoded_denial_is_400_and_touches_nothing(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent, tool: str, action: str, value: str
    ) -> None:
        """The issue's test: a hardcoded denial can't be overridden per org (either tier,
        any value, 'deny' included); the matrix isn't read or written."""
        _route(app, *_ROUTES["matrix_patch"])
        _, token = _login(db, "org_admin")
        before = _state(db)
        since = len(db.calls)

        response = _patch(_client(app), token, tool, action, value)

        assert (response.status_code, response.json()) == (400, _HARDCODED)
        assert _policy_calls(db, since) == []
        assert _state(db) == before
        _assert_agent_untouched(agent)

    def test_permissions_api_patch_cannot_demote_a_promotion_through_the_matrix(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        """A promoted tier-2 pair (stored 'confirm') changes only through the critical
        permission routes."""
        db.add_permissions(ORG_ID, {"outlook": {"send": "confirm"}})
        _, token = _login(db, "org_admin")
        before = _state(db)

        response = _patch(_client(app), token, "outlook", "send", "deny")

        assert (response.status_code, response.json()) == (400, _HARDCODED)
        assert _state(db) == before

    @pytest.mark.parametrize("body", _UNKNOWN_PATCHES)
    def test_permissions_api_patch_unknown_pair_is_400_and_touches_nothing(
        self, db: FakeDb, app: FastAPI, body: dict[str, str]
    ) -> None:
        _route(app, *_ROUTES["matrix_patch"])
        _, token = _login(db, "org_admin")
        before = _state(db)
        since = len(db.calls)

        response = _call(_client(app), "matrix_patch", token, body=body)

        assert (response.status_code, response.json()) == (400, _UNKNOWN)
        assert _policy_calls(db, since) == []
        assert _state(db) == before

    @pytest.mark.parametrize("body", _BAD_PATCH_BODIES)
    def test_permissions_api_patch_bad_body_is_422_without_echo(
        self, db: FakeDb, app: FastAPI, body: Any
    ) -> None:
        _route(app, *_ROUTES["matrix_patch"])
        _, token = _login(db, "org_admin")
        before = _state(db)
        since = len(db.calls)

        response = _call(_client(app), "matrix_patch", token, body=body)

        assert response.status_code == 422, response.text
        for marker in _echo_markers(body):
            assert marker not in response.text, marker
        errors = response.json()["detail"]
        assert all(isinstance(error, dict) and "input" not in error for error in errors)
        assert _policy_calls(db, since) == []
        assert _state(db) == before

    def test_permissions_api_patch_audit_failure_is_500_and_changes_nothing(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _route(app, *_ROUTES["matrix_patch"])
        _, token = _login(db, "org_admin")
        before = _state(db)
        db.fail_audit = True

        response = _patch(
            _client(app, raise_server_exceptions=False), token, "gmail", "read", "deny"
        )

        assert response.status_code == 500
        assert _state(db) == before
        assert db.org_permissions(ORG_ID) == _defaults()


# ---------------------------------------------------------------------------
# 6. Dispatch isolation: each run gets its own org's policy
# ---------------------------------------------------------------------------


class TestDispatchIsolation:
    """POST /api/message and POST /api/confirm pass the sender's org policy to the run; the
    shared agent is never mutated."""

    def test_permissions_api_message_run_gets_the_senders_org_policy(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        _, editor = _login(db, "editor")

        response = _post_message(_client(app), editor)

        assert response.status_code == 200, response.text
        assert len(agent.runs) == 1
        policy = _policy(agent.runs[0])
        _assert_policy_of(policy, db, ORG_ID)
        assert set(policy.enabled_tools) == set(TOOL_NAMES)

    def test_permissions_api_two_orgs_runs_get_their_own_matrix(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        db.add_permissions(ORG_ID, {"gmail": {"read": "deny"}})
        _, editor_a = _login(db, "editor", ORG_ID)
        _, editor_b = _login(db, "editor", OTHER_ORG_ID)
        client = _client(app)

        sent_a = _post_message(client, editor_a)
        since = len(db.calls)
        sent_b = _post_message(client, editor_b)

        assert (sent_a.status_code, sent_b.status_code) == (200, 200)
        policy_a, policy_b = (_policy(run) for run in agent.runs)
        assert _decision(policy_a, "gmail", "read") == "deny"
        assert _decision(policy_b, "gmail", "read") == "allow"
        _assert_policy_of(policy_b, db, OTHER_ORG_ID)
        _assert_scoped_to(db, OTHER_ORG_ID, ORG_ID, since)

    def test_permissions_api_matrix_patch_changes_only_the_patching_orgs_next_run(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        """The issue's test: org A's matrix never affects org B's dispatch."""
        _, admin_a = _login(db, "org_admin", ORG_ID)
        _, editor_a = _login(db, "editor", ORG_ID)
        _, editor_b = _login(db, "editor", OTHER_ORG_ID)
        client = _client(app)

        before = _post_message(client, editor_a, session_id="before")
        patched = _patch(client, admin_a, "gmail", "list", "deny")
        after_a = _post_message(client, editor_a, session_id="after")
        after_b = _post_message(client, editor_b, session_id="after")

        assert patched.status_code == 200, patched.text
        assert {before.status_code, after_a.status_code, after_b.status_code} == {200}
        first, second, third = (_policy(run) for run in agent.runs)
        assert _decision(first, "gmail", "list") == "allow"
        assert _decision(second, "gmail", "list") == "deny"
        assert _decision(third, "gmail", "list") == "allow"
        _assert_agent_untouched(agent)

    def test_permissions_api_promotion_reaches_only_its_orgs_run(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        """Org A's stored 'confirm' on gmail.send is a promotion for org A's runs only."""
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})
        _, editor_a = _login(db, "editor", ORG_ID)
        _, editor_b = _login(db, "editor", OTHER_ORG_ID)
        client = _client(app)

        _post_message(client, editor_a)
        _post_message(client, editor_b)

        policy_a, policy_b = (_policy(run) for run in agent.runs)
        assert policy_a.promoted == frozenset({("gmail", "send")})
        assert _decision(policy_a, "gmail", "send") == "confirm"
        assert policy_b.promoted == frozenset()
        assert _decision(policy_b, "gmail", "send") == "deny"

    def test_permissions_api_confirmed_run_gets_the_current_org_policy(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        """The message awaits a confirmation; the Org Admin changes the matrix in between;
        the resumed run gets org A's policy as it is now."""
        session_id = "chat-161"
        pending = _pending(session_id)
        agent.results = [_agent_result(pending), _agent_result()]
        _, admin_a = _login(db, "org_admin", ORG_ID)
        _, editor_a = _login(db, "editor", ORG_ID)
        client = _client(app)

        asked = _post_message(client, editor_a, "book it", session_id)
        patched = _patch(client, admin_a, "google_calendar", "list", "deny")
        confirmed = client.post(
            f"/api/confirm/{pending.confirmation_id}",
            headers=_headers(editor_a),
            json={
                "session_id": session_id,
                "confirmation_id": pending.confirmation_id,
                "approved": True,
            },
        )

        assert asked.status_code == 200, asked.text
        assert patched.status_code == 200, patched.text
        assert confirmed.status_code == 200, confirmed.text
        assert len(agent.runs) == 2
        assert agent.runs[1]["pending_confirmation"] is not None
        resumed = _policy(agent.runs[1])
        assert _decision(_policy(agent.runs[0]), "google_calendar", "list") == "allow"
        assert _decision(resumed, "google_calendar", "list") == "deny"
        _assert_policy_of(resumed, db, ORG_ID)

    def test_permissions_api_confirmed_run_of_org_b_keeps_org_bs_policy(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        session_id = "chat-161-b"
        pending = _pending(session_id)
        agent.results = [_agent_result(pending), _agent_result()]
        db.add_permissions(ORG_ID, {"google_calendar": {"list": "deny"}})
        db.add_org_settings(ORG_ID, memory=False)
        _, editor_b = _login(db, "editor", OTHER_ORG_ID)
        client = _client(app)

        _post_message(client, editor_b, "book it", session_id)
        confirmed = client.post(
            f"/api/confirm/{pending.confirmation_id}",
            headers=_headers(editor_b),
            json={
                "session_id": session_id,
                "confirmation_id": pending.confirmation_id,
                "approved": True,
            },
        )

        assert confirmed.status_code == 200, confirmed.text
        resumed = _policy(agent.runs[1])
        _assert_policy_of(resumed, db, OTHER_ORG_ID)
        assert resumed.enabled_tools["memory"] is True

    async def test_permissions_api_concurrent_runs_of_two_orgs_get_their_own_policy(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        """The issue's test, concurrent: both runs are in flight at once and each holds its
        own org's matrix, promotions and services."""
        _seed_distinct_orgs(db)
        user_a, editor_a = _login(db, "editor", ORG_ID)
        user_b, editor_b = _login(db, "editor", OTHER_ORG_ID)
        agent.barrier = _Barrier(2)
        transport = httpx.ASGITransport(app=app, client=(_IP_A, 50000))

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            sent_a, sent_b = await asyncio.wait_for(
                asyncio.gather(
                    client.post(
                        "/api/message",
                        headers=_headers(editor_a),
                        json={"message": "hello", "session_id": "together"},
                    ),
                    client.post(
                        "/api/message",
                        headers=_headers(editor_b),
                        json={"message": "hello", "session_id": "together"},
                    ),
                ),
                timeout=20,
            )

        assert (sent_a.status_code, sent_b.status_code) == (200, 200), (sent_a.text, sent_b.text)
        assert agent.barrier.arrived == 2
        runs = {plain(run["principal"].user_id): run for run in agent.runs}
        policy_a, policy_b = _policy(runs[user_a]), _policy(runs[user_b])
        _assert_policy_of(policy_a, db, ORG_ID)
        _assert_policy_of(policy_b, db, OTHER_ORG_ID)
        assert (policy_a.enabled_tools["gmail"], policy_b.enabled_tools["gmail"]) == (False, True)
        assert (policy_a.enabled_tools["outlook"], policy_b.enabled_tools["outlook"]) == (
            True,
            False,
        )
        assert _decision(policy_a, "outlook", "send") == "confirm"
        assert _decision(policy_b, "outlook", "send") == "deny"
        assert _decision(policy_a, "gmail", "send") == "deny"
        assert _decision(policy_b, "gmail", "send") == "confirm"
        _assert_agent_untouched(agent)

    def test_permissions_api_server_never_sets_the_policy_on_the_agent(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        """Matrix and services changes, runs and the summary assign nothing to
        _permissions / _promoted / _tools_enabled."""
        _, admin_a = _login(db, "org_admin", ORG_ID)
        _, editor_b = _login(db, "editor", OTHER_ORG_ID)
        client = _client(app)

        responses = [
            _patch(client, admin_a, "memory", "recall", "confirm"),
            client.patch(
                _ORG_SETTINGS, headers=_headers(admin_a), json={"tools": {"gmail": False}}
            ),
            _post_message(client, admin_a),
            _post_message(client, editor_b),
            _call(client, "summary_get", editor_b),
        ]

        assert [response.status_code for response in responses] == [200] * 5
        _assert_agent_untouched(agent)

    @pytest.mark.parametrize("name", _REMOVED_SERVER_GLOBALS)
    def test_permissions_api_server_keeps_no_global_promotion_state(self, name: str) -> None:
        assert not hasattr(server, name)


# ---------------------------------------------------------------------------
# 7. Enabled services per org (the retired interim gate)
# ---------------------------------------------------------------------------


class TestEnabledServicesPerOrg:
    """Each run takes its own org's enabled services from org_settings."""

    def test_permissions_api_org_a_disabling_a_service_leaves_org_b_on(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        """The issue's cleanup test: org A disabling a service doesn't disable it for B."""
        _, admin_a = _login(db, "org_admin", ORG_ID)
        _, editor_a = _login(db, "editor", ORG_ID)
        _, editor_b = _login(db, "editor", OTHER_ORG_ID)
        client = _client(app)

        patched = client.patch(
            _ORG_SETTINGS, headers=_headers(admin_a), json={"tools": {"gmail": False}}
        )
        _post_message(client, editor_a)
        _post_message(client, editor_b)

        assert patched.status_code == 200, patched.text
        policy_a, policy_b = (_policy(run) for run in agent.runs)
        assert dict(policy_a.enabled_tools) == {**_ALL_ON, "gmail": False}
        assert dict(policy_b.enabled_tools) == _ALL_ON

    def test_permissions_api_org_b_disabled_service_stays_off_for_org_b_only(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        """The issue's cleanup test: B's outlook stays off for B only, whatever A switches
        (off, then back on)."""
        db.add_org_settings(OTHER_ORG_ID, outlook=False)
        _, admin_a = _login(db, "org_admin", ORG_ID)
        _, editor_a = _login(db, "editor", ORG_ID)
        _, editor_b = _login(db, "editor", OTHER_ORG_ID)
        client = _client(app)

        off = client.patch(
            _ORG_SETTINGS, headers=_headers(admin_a), json={"tools": {"outlook": False}}
        )
        on = client.patch(
            _ORG_SETTINGS, headers=_headers(admin_a), json={"tools": {"outlook": True}}
        )
        _post_message(client, editor_a)
        _post_message(client, editor_b)

        assert (off.status_code, on.status_code) == (200, 200)
        policy_a, policy_b = (_policy(run) for run in agent.runs)
        assert dict(policy_a.enabled_tools) == _ALL_ON
        assert dict(policy_b.enabled_tools) == {**_ALL_ON, "outlook": False}

    def test_permissions_api_org_settings_patch_never_touches_the_agent(
        self, db: FakeDb, app: FastAPI, agent: _SpyAgent
    ) -> None:
        db.add_org_settings(OTHER_ORG_ID, memory=False)
        _, admin_a = _login(db, "org_admin", ORG_ID)

        response = _client(app).patch(
            _ORG_SETTINGS, headers=_headers(admin_a), json={"tools": {"gmail": False}}
        )

        assert response.status_code == 200, response.text
        _assert_agent_untouched(agent)
        assert agent.runs == []


# ---------------------------------------------------------------------------
# 8. GET /api/permissions/summary
# ---------------------------------------------------------------------------


class TestSummary:
    """Every member reads the effective state of each of their own org's tool actions."""

    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    def test_permissions_api_summary_returns_the_callers_org_effective_states(
        self, db: FakeDb, app: FastAPI, role: str
    ) -> None:
        _seed_distinct_orgs(db)
        _, token = _login(db, role, ORG_ID)

        response = _call(_client(app), "summary_get", token)

        assert response.status_code == 200, response.text
        assert response.json() == _expected_summary(db, ORG_ID)
        states = _states(response.json())
        assert states[("gmail", "read")] == "disabled"
        assert states[("gmail", "send")] == "disabled"
        assert states[("outlook", "send")] == "confirm"
        assert states[("outlook", "delete")] == "deny"
        assert states[("outlook", "read")] == "deny"
        assert states[("outlook", "list")] == "allow"
        assert states[("memory", "delete")] == "deny"
        assert states[("memory", "recall")] == "confirm"
        assert states[("google_calendar", "update")] == "deny"
        assert states[("google_calendar", "create")] == "confirm"
        assert len(states) == sum(len(actions) for actions in DEFAULT_PERMISSIONS.values())

    def test_permissions_api_summary_never_shows_another_orgs_states(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _seed_distinct_orgs(db)
        _, token_b = _login(db, "viewer", OTHER_ORG_ID)
        since = len(db.calls)

        response = _call(_client(app), "summary_get", token_b)

        assert response.status_code == 200, response.text
        assert response.json() == _expected_summary(db, OTHER_ORG_ID)
        states = _states(response.json())
        assert states[("gmail", "read")] == "deny"
        assert states[("gmail", "send")] == "confirm"
        assert states[("outlook", "send")] == "disabled"
        assert states[("memory", "recall")] == "allow"
        assert states[("memory", "store")] == "deny"
        _assert_scoped_to(db, OTHER_ORG_ID, ORG_ID, since)

    def test_permissions_api_summary_follows_an_org_settings_change(
        self, db: FakeDb, app: FastAPI
    ) -> None:
        _, admin_a = _login(db, "org_admin", ORG_ID)
        _, viewer_a = _login(db, "viewer", ORG_ID)
        _, viewer_b = _login(db, "viewer", OTHER_ORG_ID)
        client = _client(app)

        patched = client.patch(
            _ORG_SETTINGS, headers=_headers(admin_a), json={"tools": {"memory": False}}
        )
        read_a = _call(client, "summary_get", viewer_a)
        read_b = _call(client, "summary_get", viewer_b)

        assert patched.status_code == 200, patched.text
        assert (read_a.status_code, read_b.status_code) == (200, 200), read_a.text
        assert _states(read_a.json())[("memory", "recall")] == "disabled"
        assert _states(read_b.json())[("memory", "recall")] == "allow"

    def test_permissions_api_summary_is_read_only(self, db: FakeDb, app: FastAPI) -> None:
        _seed_distinct_orgs(db)
        _, token = _login(db, "editor", ORG_ID)
        before = _state(db)
        since = len(db.calls)

        response = _call(_client(app), "summary_get", token)

        assert response.status_code == 200, response.text
        assert _state(db) == before
        assert [call for call in db.calls[since:] if _matches(call, _MATRIX_WRITE)] == []
