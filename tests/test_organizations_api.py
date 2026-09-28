"""HTTP-layer spec for the organization lifecycle routes of the Super Admin (GH-154).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with a fake
config whose ``server.public_url`` is ``https://admino.example.ch``. The real
``admino.organizations``, ``admino.invitations``, ``admino.sessions``,
``admino.auth``, ``admino.email_outbox`` and ``admino.audit_events`` code runs
through the real ``require_session``; only Argon2 is replaced by a fast fake.

What these tests pin down:
- Eight routes, each behind a session (401 ``{"detail": "Unauthorized"}``
  without one) and ``admino.access.can`` (403 ``{"detail": "Forbidden"}`` for an
  Org Admin, an Editor and a Viewer, with nothing written and no audit row):
  ``GET /api/platform/orgs`` → 200 ``{"organizations": [...]}`` (every status,
  by created_at then id); ``POST /api/platform/orgs`` → 201 ``{"organization",
  "invitation"}``; ``PATCH .../{org_id}/limits``, ``POST .../{org_id}/deactivate``,
  ``POST .../{org_id}/reactivate``, ``POST .../{org_id}/deletion``, ``DELETE
  .../{org_id}/deletion`` and ``PATCH .../{org_id}/residency`` → 200 with the
  org's ``OrgSummary`` (exactly its eleven keys; the budget a decimal).
- Create: the invited first Org Admin gets the Super Admin's session
  ``ui_language``; the invitation email's link is built from
  ``server.public_url`` only (never Host or X-Forwarded-* headers); the
  response holds neither the token nor the link; a taken email → 409
  ``{"detail", "reason": "email_taken"}`` with nothing written; every invalid
  body → 422 without the input; status "deactivated" is accepted.
- Errors: an unknown org → 404 ``{"detail": "Organization not found"}``; a
  change the org's status doesn't allow (limits and residency included, while
  a deletion is pending) → 409 ``{"detail", "reason": "invalid_status"}``; a
  non-UUID id → 422 without echo; an audit failure → 500 with nothing written.
- Each change is audited: the Super Admin as actor (``super_admin`` + user id),
  the org, the org as target, the client IP and the exact metadata.
- End to end: once an org is deactivated or scheduled for deletion its members'
  cookies stop working and their correct password gets the generic login 401,
  other orgs are unaffected, and after a reactivation they can log in again.
  Scheduling emails only the org's active Org Admins.
- Rate limits per (route key, Super Admin): six keys with the spec's values;
  deactivate/reactivate share ``/api/platform/orgs/status`` and
  schedule/cancel share ``/api/platform/orgs/deletion``; one Super Admin never
  throttles another. Cross-origin writes → 403 before any database call.
- No org name, admin email, invitation token or link in any log record or
  audit row.

All database calls are faked. No network, no real PostgreSQL, no SMTP.

Security notes:
- Least privilege: only a Super Admin reaches these routes; an Org Admin can't
  even act on their own org.
- Link poisoning: the link base is ``server.public_url``, never a request header.
- Fail closed: an audit failure is a 500 and nothing is written.
- Operator blindness: org metadata and counts only; no secret in a response,
  a log record or an audit row; 422 bodies never echo input.
"""

from __future__ import annotations

import contextlib
import copy
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import auth, server
from admino.access import Capability
from admino.server import create_app
from tests.db_fakes import (
    INVITE_LINK_PREFIX,
    ORG_ID,
    ORG_NAME,
    OTHER_ORG_ID,
    PUBLIC_URL,
    TOKEN_RE,
    FakeDb,
    fake_hash,
    plain,
    sha256,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_IP_A = "203.0.113.5"
_IP_B = "198.51.100.23"
_ORGS = "/api/platform/orgs"
_NEW_NAME = "Kanzlei Zeitreise Marker AG"
_ADMIN_EMAIL = "Grace.Primary.Api.Marker@Example.ch"
_SEATS = 12
_BUDGET = "123.45"
_BUDGET_CENTS = 12345
_QUOTA = 5 * 1024**3
_PASSWORD = "violet-Anchor-93-quartz"
_OLD = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
_DELETED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_UNKNOWN_ORG = uuid.UUID("9e8d7c6b-5a49-4382-a716-0f1e2d3c4b5a")
# Two orgs created at the same instant: the lower id comes first.
_ORG_TIE_LOW = uuid.UUID("1a1a1a1a-0000-4000-8000-000000000001")
_ORG_TIE_HIGH = uuid.UUID("7b7b7b7b-0000-4000-8000-000000000002")
_ORG_OLDEST = uuid.UUID("f0f0f0f0-0000-4000-8000-000000000003")

_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_NOT_FOUND = {"detail": "Organization not found"}
_INVALID_STATUS = {
    "detail": "This change isn't possible in the organization's current status.",
    "reason": "invalid_status",
}
_EMAIL_TAKEN = {"detail": "A user with this email already exists.", "reason": "email_taken"}
_LOGIN_FAILED = {"detail": auth.LOGIN_FAILED_MESSAGE}

_SUMMARY_KEYS = frozenset(
    {
        "id",
        "name",
        "status",
        "seats",
        "monthly_budget_chf",
        "storage_quota",
        "data_residency",
        "deletion_requested_at",
        "purge_after",
        "created_at",
        "updated_at",
    }
)
_INVITATION_KEYS = frozenset({"id", "email", "role", "sent_at", "expires_at", "expired"})
_MEMBER_ROLES = ["org_admin", "editor", "viewer"]
_STATUSES = ["active", "deactivated", "pending_deletion"]

# action -> (method, path template)
_ROUTES: dict[str, tuple[str, str]] = {
    "list": ("GET", _ORGS),
    "create": ("POST", _ORGS),
    "limits": ("PATCH", _ORGS + "/{org_id}/limits"),
    "deactivate": ("POST", _ORGS + "/{org_id}/deactivate"),
    "reactivate": ("POST", _ORGS + "/{org_id}/reactivate"),
    "schedule": ("POST", _ORGS + "/{org_id}/deletion"),
    "cancel": ("DELETE", _ORGS + "/{org_id}/deletion"),
    "residency": ("PATCH", _ORGS + "/{org_id}/residency"),
}
_ALL_ACTIONS = list(_ROUTES)
_ORG_ACTIONS = ["limits", "deactivate", "reactivate", "schedule", "cancel", "residency"]
_WRITE_ACTIONS = ["create", *_ORG_ACTIONS]

_KEY_GET = "/api/platform/orgs/get"
_KEY_CREATE = "/api/platform/orgs/create"
_KEY_LIMITS = "/api/platform/orgs/limits"
_KEY_STATUS = "/api/platform/orgs/status"
_KEY_DELETION = "/api/platform/orgs/deletion"
_KEY_RESIDENCY = "/api/platform/orgs/residency"
_EXPECTED_LIMITS: dict[str, tuple[float, int]] = {
    _KEY_GET: (1.0, 10),
    _KEY_CREATE: (0.2, 5),
    _KEY_LIMITS: (0.5, 5),
    _KEY_STATUS: (0.5, 5),
    _KEY_DELETION: (0.2, 5),
    _KEY_RESIDENCY: (0.5, 5),
}
_RATE_KEYS = list(_EXPECTED_LIMITS)
# Read at import, before any fixture patches the limits.
_CONFIGURED_LIMITS = {key: server._RATE_LIMITS.get(key) for key in _RATE_KEYS}
_ROUTE_KEYS: dict[str, str] = {
    "list": _KEY_GET,
    "create": _KEY_CREATE,
    "limits": _KEY_LIMITS,
    "deactivate": _KEY_STATUS,
    "reactivate": _KEY_STATUS,
    "schedule": _KEY_DELETION,
    "cancel": _KEY_DELETION,
    "residency": _KEY_RESIDENCY,
}
_CAPABILITIES: dict[str, Capability] = {
    "list": Capability.ORG_LIFECYCLE_MANAGE,
    "create": Capability.ORG_CREATE,
    "limits": Capability.ORG_LIMITS_MANAGE,
    "deactivate": Capability.ORG_LIFECYCLE_MANAGE,
    "reactivate": Capability.ORG_LIFECYCLE_MANAGE,
    "schedule": Capability.ORG_LIFECYCLE_MANAGE,
    "cancel": Capability.ORG_LIFECYCLE_MANAGE,
    "residency": Capability.ORG_RESIDENCY_MANAGE,
}

# transition -> (the statuses it's allowed from, the status it sets, its audit action)
_TRANSITIONS: dict[str, tuple[frozenset[str], str, str]] = {
    "deactivate": (frozenset({"active"}), "deactivated", "org.deactivate"),
    "reactivate": (frozenset({"deactivated"}), "active", "org.reactivate"),
    "schedule": (
        frozenset({"active", "deactivated"}),
        "pending_deletion",
        "org.deletion_schedule",
    ),
    "cancel": (frozenset({"pending_deletion"}), "deactivated", "org.deletion_cancel"),
}
_ALLOWED_FROM: dict[str, frozenset[str]] = {
    **{name: allowed for name, (allowed, _, _) in _TRANSITIONS.items()},
    "limits": frozenset({"active", "deactivated"}),
    "residency": frozenset({"active", "deactivated"}),
}
# A status each action (and list/create) succeeds from.
_READY: dict[str, str] = {
    "list": "active",
    "create": "active",
    "limits": "active",
    "deactivate": "active",
    "reactivate": "deactivated",
    "schedule": "active",
    "cancel": "pending_deletion",
    "residency": "active",
}
_ALLOWED_TRANSITIONS = [
    pytest.param(name, start, id=f"{name}-from-{start}")
    for name, (allowed, _, _) in _TRANSITIONS.items()
    for start in _STATUSES
    if start in allowed
]
_REFUSED = [
    pytest.param(action, start, id=f"{action}-from-{start}")
    for action in _ORG_ACTIONS
    for start in _STATUSES
    if start not in _ALLOWED_FROM[action]
]
_DEFAULT_BODIES: dict[str, dict[str, Any]] = {
    "limits": {"seats": 7},
    "residency": {"enabled": False},
}
_CROSS_ORIGIN = [
    pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
    pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
]
_BAD_IDS = [
    pytest.param("not-a-uuid-ECHOMARK42", id="text"),
    pytest.param("12345", id="digits"),
    pytest.param("x" * 200, id="200-chars"),
]
_UNSET: Final = object()


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database the server's get_pool() returns."""
    fake = FakeDb()
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


@pytest.fixture(autouse=True)
def _fast_passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Argon2 with a fast fake (the real hashing is covered by test_passwords)."""
    monkeypatch.setattr(
        "admino.passwords.verify_password", lambda password, encoded: encoded == fake_hash(password)
    )
    monkeypatch.setattr("admino.passwords.needs_rehash", lambda _encoded: False)
    monkeypatch.setattr("admino.passwords.hash_password", fake_hash)


@pytest.fixture(autouse=True)
def configured_keys(monkeypatch: pytest.MonkeyPatch) -> frozenset[str]:
    """Functional tests aren't about rate limits: give the six org route keys (and the
    login and /me keys the end-to-end tests use) a large bucket; the rate-limit tests
    set their own. Returns the org keys the server configured itself, before this
    fixture patched them."""
    present = frozenset(key for key in _RATE_KEYS if key in server._RATE_LIMITS)
    for key in [*_RATE_KEYS, "/api/auth/login", "/api/auth/me"]:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))
    return present


def _config() -> MagicMock:
    """A minimal config with the public URL invitation links are built from."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = True
    config.server.public_url = PUBLIC_URL
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _app() -> FastAPI:
    """create_app with a stub agent and the fake config (no lifespan runs under TestClient)."""
    return create_app(agent=MagicMock(), config=_config())  # type: ignore[arg-type]


def _client(app: FastAPI, ip: str = _IP_A, **kwargs: Any) -> TestClient:
    """A client whose peer address is ``ip``; redirects are not followed."""
    return TestClient(app, client=(ip, 50000), follow_redirects=False, **kwargs)


def _headers(token: str | None, **extra: str) -> dict[str, str]:
    """Request headers carrying a session cookie (none for ``None``) plus any extra ones."""
    cookie = {} if token is None else {"Cookie": f"{_COOKIE}={token}"}
    return {**cookie, **extra}


def _depends_on(dependant: Dependant, target: Callable[..., Any]) -> bool:
    """True when the dependency tree below ``dependant`` contains ``target``."""
    return any(dep.call is target or _depends_on(dep, target) for dep in dependant.dependencies)


def _route(app: FastAPI, method: str, path: str) -> APIRoute:
    """The one APIRoute registered for (method, path)."""
    matches = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == path and method in route.methods
    ]
    assert len(matches) == 1, f"{method} {path} is not registered"
    return matches[0]


def _route_of(action: str) -> APIRoute:
    return _route(_app(), *_ROUTES[action])


def _super_admin(db: FakeDb, **fields: Any) -> tuple[uuid.UUID, str]:
    """A Super Admin with a live session: (user id, session token)."""
    user_id = db.add_account(kind="super_admin", role=None, **fields)
    return user_id, db.open_session(user_id)


def _member_session(db: FakeDb, role: str, org_id: uuid.UUID = ORG_ID) -> str:
    """A live session of a member of ``org_id`` with the given role."""
    return db.open_session(db.add_account(role=role, org_id=org_id))


def _create_body(**overrides: Any) -> dict[str, Any]:
    """A valid POST /api/platform/orgs body, with some fields replaced."""
    body: dict[str, Any] = {
        "name": _NEW_NAME,
        "primary_admin_email": _ADMIN_EMAIL,
        "seats": _SEATS,
        "monthly_budget_chf": _BUDGET,
        "storage_quota": _QUOTA,
        "status": "active",
    }
    body.update(overrides)
    return body


def _create_body_without(field: str) -> dict[str, Any]:
    body = _create_body()
    del body[field]
    return body


def _url(action: str, org_id: object = ORG_ID) -> str:
    return _ROUTES[action][1].replace("{org_id}", str(org_id))


def _call(
    client: TestClient,
    action: str,
    token: str | None,
    org_id: object = ORG_ID,
    *,
    body: Any = _UNSET,
    **headers: str,
) -> httpx.Response:
    """Call one of the eight routes with a valid body (unless ``body`` is given)."""
    method = _ROUTES[action][0]
    if body is _UNSET:
        body = _create_body() if action == "create" else _DEFAULT_BODIES.get(action)
    kwargs: dict[str, Any] = {} if body is None else {"json": body}
    return client.request(
        method, _url(action, org_id), headers=_headers(token, **headers), **kwargs
    )


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of every table (the sessions by token hash), for "nothing changed"
    checks. A session's last_seen_at may be refreshed by any request; its existence may
    not change."""
    return copy.deepcopy(
        {
            "users": db.users,
            "orgs": db.orgs,
            "invitations": db.invitations,
            "tokens": db.tokens,
            "outbox": db.outbox,
            "audit": db.audit,
            "sessions": sorted(db.sessions),
        }
    )


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


def _new_org_id(db: FakeDb, before: set[uuid.UUID]) -> uuid.UUID:
    """The id of the one organization created since ``before``."""
    return _one(sorted(set(db.orgs) - before))


def _dt(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def _uuid(value: Any) -> uuid.UUID | None:
    return None if value is None else plain(value)


def _assert_summary(entry: dict[str, Any], row: dict[str, Any]) -> None:
    """An OrgSummary JSON object: exactly its keys, every value from the org's row."""
    assert set(entry) == _SUMMARY_KEYS
    assert entry["id"] == str(row["id"])
    assert (entry["name"], entry["status"]) == (row["name"], row["status"])
    assert entry["seats"] == row["seats"]
    assert type(entry["seats"]) is int
    assert Decimal(entry["monthly_budget_chf"]) == row["monthly_budget_chf"]
    assert entry["storage_quota"] == row["storage_quota_bytes"]
    assert type(entry["storage_quota"]) is int
    assert entry["data_residency"] is row["data_residency"]
    for key in ("deletion_requested_at", "purge_after", "created_at", "updated_at"):
        assert _dt(entry[key]) == row[key], key


def _assert_org_event(
    row: dict[str, Any],
    *,
    action: str,
    actor: uuid.UUID,
    org_id: uuid.UUID,
    metadata: dict[str, Any],
    ip: str = _IP_B,
) -> None:
    """One org.* event of a Super Admin: the org's own log, target the org, the client IP,
    exactly the metadata (with the same value types)."""
    assert row["action"] == action
    assert (row["actor_kind"], _uuid(row["actor_user_id"])) == ("super_admin", actor)
    assert _uuid(row["org_id"]) == org_id
    assert (row["target_type"], row["target_ids"]) == ("organization", [str(org_id)])
    assert row["ip"] == ip
    assert row["metadata"] == metadata
    for key, value in metadata.items():
        assert type(row["metadata"][key]) is type(value), key


def _echo_markers(value: Any) -> list[str]:
    """What a 422 body must never contain: the ECHOMARK42 marker and every long string
    or large number the request carried (at any depth)."""
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
        elif isinstance(item, int) and not isinstance(item, bool) and abs(item) >= 100000:
            markers.append(str(item))
    return markers


def _assert_no_echo(response: httpx.Response, sent: Any) -> None:
    assert response.status_code == 422, response.text
    for marker in _echo_markers(sent):
        assert marker not in response.text, marker


def _member_account(
    db: FakeDb, email: str, org_id: uuid.UUID = ORG_ID, role: str = "editor"
) -> uuid.UUID:
    """An active member who can log in with _PASSWORD."""
    return db.add_account(role=role, org_id=org_id, email=email, password_hash=fake_hash(_PASSWORD))


def _login(client: TestClient, email: str, password: str = _PASSWORD) -> httpx.Response:
    """POST /api/auth/login; the client's cookie jar is emptied afterwards, so later
    requests carry only the cookie a test passes explicitly."""
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    client.cookies.clear()
    return response


def _me(client: TestClient, token: str) -> httpx.Response:
    return client.get("/api/auth/me", headers=_headers(token))


def _session_cookie_headers(response: httpx.Response) -> list[str]:
    return [
        h for h in response.headers.get_list("set-cookie") if h.lower().startswith(f"{_COOKIE}=")
    ]


def _session_cookie_value(response: httpx.Response) -> str:
    """The value of the one admino_session Set-Cookie header of a response."""
    header = _one(_session_cookie_headers(response))
    return str(header.split(";", 1)[0].split("=", 1)[1])


class _CanSpy:
    """Wraps admino.access.can wherever it is looked up; records every capability asked
    for and can refuse chosen capabilities."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, deny: frozenset[Capability] = frozenset()
    ) -> None:
        from admino import access

        real = access.can
        self.capabilities: list[Capability] = []

        def spy(principal: Any, capability: Any) -> bool:
            self.capabilities.append(capability)
            if capability in deny:
                return False
            return real(principal, capability)

        monkeypatch.setattr(access, "can", spy)
        monkeypatch.setattr(server, "can", spy, raising=False)
        with contextlib.suppress(ImportError):
            from admino import organizations

            if hasattr(organizations, "can"):
                monkeypatch.setattr(organizations, "can", spy)


# ---------------------------------------------------------------------------
# 1. The routes
# ---------------------------------------------------------------------------


class TestRoutes:
    """Eight Super Admin routes behind a session, with six per-user rate-limit keys."""

    @pytest.mark.parametrize("action", _ALL_ACTIONS)
    def test_organizations_api_route_is_registered(self, action: str) -> None:
        _route_of(action)

    @pytest.mark.parametrize("action", _ALL_ACTIONS)
    def test_organizations_api_route_depends_on_require_session(self, action: str) -> None:
        assert _depends_on(_route_of(action).dependant, server.require_session)

    def test_organizations_api_rate_limit_keys_are_configured(
        self, configured_keys: frozenset[str]
    ) -> None:
        """Each of the six keys has its own (rate, burst) entry in server._RATE_LIMITS."""
        assert configured_keys == frozenset(_RATE_KEYS)

    @pytest.mark.parametrize("key", _RATE_KEYS)
    def test_organizations_api_rate_limit_values(self, key: str) -> None:
        assert _CONFIGURED_LIMITS[key] == _EXPECTED_LIMITS[key]

    @pytest.mark.parametrize("action", _ALL_ACTIONS)
    def test_organizations_api_route_without_a_session_is_401(
        self, db: FakeDb, action: str
    ) -> None:
        """No cookie → 401 and nothing is read or written."""
        _route_of(action)
        db.add_org(ORG_ID, status=_READY[action])

        response = _call(_client(_app()), action, None)

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED
        assert db.calls == []

    @pytest.mark.parametrize("action", _ALL_ACTIONS)
    def test_organizations_api_route_with_an_unknown_cookie_is_401(
        self, db: FakeDb, action: str
    ) -> None:
        _route_of(action)
        db.add_org(ORG_ID, status=_READY[action])
        before = _state(db)

        response = _call(_client(_app()), action, "not-a-session-token")

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 2. Authorization: a Super Admin only, through admino.access.can()
# ---------------------------------------------------------------------------


class TestAuthorization:
    """Org Admins, Editors and Viewers get 403; the route asks can() for its capability."""

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    @pytest.mark.parametrize("action", _ALL_ACTIONS)
    def test_organizations_api_member_is_forbidden_and_nothing_is_written(
        self, db: FakeDb, action: str, role: str
    ) -> None:
        """403 {"detail": "Forbidden"}; no row changes, no audit row, no organizations
        statement. The member's own org is active (their session must resolve): the
        target is that org itself, or another org when the action needs another status."""
        _route_of(action)
        db.add_org(ORG_ID)
        target = ORG_ID
        if _READY[action] != "active":
            target = db.add_org(OTHER_ORG_ID, status=_READY[action])
        token = _member_session(db, role)
        before = _state(db)

        response = _call(_client(_app()), action, token, target)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        assert _state(db) == before
        assert db.audit == []
        assert db.matching(r"^(?:insert into|update|delete from) organizations\b") == []
        assert db.matching(r"\bfor update\b") == []

    @pytest.mark.parametrize("action", _ALL_ACTIONS)
    def test_organizations_api_route_asks_can_for_its_capability(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """list and the four transitions: org.lifecycle.manage; create: org.create;
        limits: org.limits.manage; residency: org.residency.manage."""
        db.add_org(ORG_ID, status=_READY[action])
        _, token = _super_admin(db)
        spy = _CanSpy(monkeypatch)

        response = _call(_client(_app()), action, token, ORG_ID)

        assert response.status_code in {200, 201}, response.text
        assert _CAPABILITIES[action] in spy.capabilities

    @pytest.mark.parametrize("action", _ALL_ACTIONS)
    def test_organizations_api_capability_refused_by_can_is_403(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """When can() refuses the route's capability even a Super Admin gets 403; nothing
        is written."""
        _route_of(action)
        db.add_org(ORG_ID, status=_READY[action])
        _, token = _super_admin(db)
        _CanSpy(monkeypatch, deny=frozenset({_CAPABILITIES[action]}))
        before = _state(db)

        response = _call(_client(_app()), action, token, ORG_ID)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 3. POST /api/platform/orgs
# ---------------------------------------------------------------------------

_BAD_CREATE_BODIES = [
    # name
    pytest.param(_create_body(name=""), id="name-empty"),
    pytest.param(_create_body(name="   \t "), id="name-blank"),
    pytest.param(_create_body(name="ECHOMARK42" + "a" * 111), id="name-121-chars"),
    pytest.param(_create_body(name="ECHOMARK42" + chr(0) + "x"), id="name-nul"),
    pytest.param(_create_body(name="ECHOMARK42\nBcc: x@evil.example"), id="name-newline"),
    pytest.param(_create_body(name="ECHOMARK42" + chr(0x202E) + "x"), id="name-rtl-override"),
    pytest.param(_create_body(name="ECHOMARK42" + chr(0x200B) + "x"), id="name-zero-width"),
    pytest.param(_create_body(name="ECHOMARK42" + chr(0x2028) + "x"), id="name-line-sep"),
    pytest.param(_create_body(name="ECHOMARK42" + chr(0x2029) + "x"), id="name-paragraph-sep"),
    pytest.param(_create_body(name=4242424242), id="name-int"),
    pytest.param(_create_body(name=None), id="name-null"),
    # primary_admin_email
    pytest.param(_create_body(primary_admin_email="ECHOMARK42 x@example.ch"), id="email-space"),
    pytest.param(_create_body(primary_admin_email="ECHOMARK42.example.ch"), id="email-no-at"),
    pytest.param(_create_body(primary_admin_email="ECHOMARK42@a@example.ch"), id="email-two-ats"),
    pytest.param(_create_body(primary_admin_email="@ECHOMARK42.example.ch"), id="email-no-local"),
    pytest.param(_create_body(primary_admin_email="ECHOMARK42@examplech"), id="email-no-dot"),
    pytest.param(
        _create_body(primary_admin_email="ECHOMARK42" + "a" * 234 + "@example.ch"),
        id="email-255-chars",
    ),
    pytest.param(_create_body(primary_admin_email=["ECHOMARK42@example.ch"]), id="email-list"),
    pytest.param(_create_body(primary_admin_email=None), id="email-null"),
    # seats
    pytest.param(_create_body(seats=0), id="seats-0"),
    pytest.param(_create_body(seats=100001), id="seats-100001"),
    pytest.param(_create_body(seats=-1), id="seats-negative"),
    pytest.param(_create_body(seats="10"), id="seats-string"),
    pytest.param(_create_body(seats=10.0), id="seats-float"),
    pytest.param(_create_body(seats=True), id="seats-bool"),
    pytest.param(_create_body(seats=None), id="seats-null"),
    # monthly_budget_chf
    pytest.param(_create_body(monthly_budget_chf="-0.01"), id="budget-negative"),
    pytest.param(_create_body(monthly_budget_chf="1.234"), id="budget-3-decimals"),
    pytest.param(_create_body(monthly_budget_chf="12345678901.00"), id="budget-11-digits"),
    pytest.param(_create_body(monthly_budget_chf="NaN"), id="budget-nan"),
    pytest.param(_create_body(monthly_budget_chf="Infinity"), id="budget-infinity"),
    pytest.param(_create_body(monthly_budget_chf=True), id="budget-bool"),
    pytest.param(_create_body(monthly_budget_chf="ECHOMARK42"), id="budget-text"),
    pytest.param(_create_body(monthly_budget_chf=None), id="budget-null"),
    pytest.param(_create_body(monthly_budget_chf=[]), id="budget-list"),
    # storage_quota
    pytest.param(_create_body(storage_quota=-1), id="storage-negative"),
    pytest.param(_create_body(storage_quota=2**53), id="storage-2-pow-53"),
    pytest.param(_create_body(storage_quota="1073741824"), id="storage-string"),
    pytest.param(_create_body(storage_quota=1.5), id="storage-float"),
    pytest.param(_create_body(storage_quota=True), id="storage-bool"),
    pytest.param(_create_body(storage_quota=None), id="storage-null"),
    # status
    pytest.param(_create_body(status="pending_deletion"), id="status-pending-deletion"),
    pytest.param(_create_body(status="ECHOMARK42"), id="status-unknown"),
    pytest.param(_create_body(status="ACTIVE"), id="status-capitals"),
    pytest.param(_create_body(status=None), id="status-null"),
    # missing fields
    pytest.param(_create_body_without("name"), id="no-name"),
    pytest.param(_create_body_without("primary_admin_email"), id="no-email"),
    pytest.param(_create_body_without("seats"), id="no-seats"),
    pytest.param(_create_body_without("monthly_budget_chf"), id="no-budget"),
    pytest.param(_create_body_without("storage_quota"), id="no-storage"),
    # unknown fields: the language comes from the session, never from the request
    pytest.param(_create_body(language="ECHOMARK42"), id="extra-language"),
    pytest.param(_create_body(ui_language="fr"), id="extra-ui-language"),
    pytest.param(_create_body(data_residency=False), id="extra-data-residency"),
    pytest.param(_create_body(org_id="ECHOMARK42"), id="extra-org-id"),
    pytest.param(_create_body(storage_quota_bytes=1024), id="extra-storage-quota-bytes"),
    # not an object
    pytest.param({}, id="empty-object"),
    pytest.param([], id="list"),
    pytest.param("ECHOMARK42", id="string"),
]


class TestCreateRoute:
    """A Super Admin creates an org with its first Org Admin's invitation."""

    def test_organizations_api_create_returns_201_with_the_org_and_the_invitation(
        self, db: FakeDb
    ) -> None:
        """201 {"organization": OrgSummary, "invitation": InvitationSummary}: the new org's
        values and the pending org_admin invitation."""
        _, token = _super_admin(db)
        before_ids = set(db.orgs)

        response = _call(_client(_app()), "create", token)

        assert response.status_code == 201, response.text
        body = response.json()
        assert set(body) == {"organization", "invitation"}
        org_id = _new_org_id(db, before_ids)
        organization = body["organization"]
        _assert_summary(organization, db.orgs[org_id])
        assert (organization["name"], organization["status"], organization["seats"]) == (
            _NEW_NAME,
            "active",
            _SEATS,
        )
        assert Decimal(organization["monthly_budget_chf"]) == Decimal(_BUDGET)
        assert organization["storage_quota"] == _QUOTA
        assert organization["data_residency"] is True
        assert (organization["deletion_requested_at"], organization["purge_after"]) == (None, None)
        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        invitation_row = db.invitation_of(invited["id"])
        assert invitation_row is not None
        invitation = body["invitation"]
        assert set(invitation) == _INVITATION_KEYS
        assert invitation["id"] == str(invitation_row["id"])
        assert (invitation["email"], invitation["role"], invitation["expired"]) == (
            _ADMIN_EMAIL,
            "org_admin",
            False,
        )
        assert _dt(invitation["sent_at"]) == invitation_row["sent_at"]
        assert _dt(invitation["expires_at"]) == invitation_row["expires_at"]

    def test_organizations_api_create_stores_the_org_row(self, db: FakeDb) -> None:
        """The requested name, status and limits; residency on; no deletion dates."""
        _, token = _super_admin(db)
        before_ids = set(db.orgs)

        response = _call(_client(_app()), "create", token)

        assert response.status_code == 201, response.text

        row = db.orgs[_new_org_id(db, before_ids)]
        assert (row["name"], row["status"], row["seats"]) == (_NEW_NAME, "active", _SEATS)
        assert row["monthly_budget_chf"] == Decimal(_BUDGET)
        assert row["storage_quota_bytes"] == _QUOTA
        assert row["data_residency"] is True
        assert (row["deletion_requested_at"], row["purge_after"]) == (None, None)

    @pytest.mark.parametrize("language", ["de", "fr", "en"])
    def test_organizations_api_create_invites_the_first_org_admin_in_the_callers_language(
        self, db: FakeDb, language: str
    ) -> None:
        """An invited org_admin member of the new org (no name, no password) with the Super
        Admin's session ui_language; exactly one invitation email, in that language."""
        _, token = _super_admin(db, ui_language=language)
        before_ids = set(db.orgs)

        response = _call(_client(_app()), "create", token)

        assert response.status_code == 201, response.text

        org_id = _new_org_id(db, before_ids)
        row = db.user_by_email(_ADMIN_EMAIL)
        assert row is not None
        assert (row["kind"], row["org_id"], row["role"], row["status"]) == (
            "member",
            org_id,
            "org_admin",
            "invited",
        )
        assert (row["name"], row["password_hash"]) == (None, None)
        assert row["ui_language"] == language
        emails = db.invitation_emails()
        assert [(email["user_id"], email["language"]) for email in emails] == [
            (row["id"], language)
        ]
        assert db.outbox == emails

    def test_organizations_api_create_link_comes_from_the_configured_public_url(
        self, db: FakeDb
    ) -> None:
        """A hostile Host / X-Forwarded-Host / X-Forwarded-Proto / Forwarded doesn't change
        the emailed link (link poisoning)."""
        _, token = _super_admin(db)

        response = _call(
            _client(_app()),
            "create",
            token,
            **{
                "Host": "evil.example",
                "X-Forwarded-Host": "evil.example",
                "X-Forwarded-Proto": "http",
                "Forwarded": "host=evil.example;proto=http",
            },
        )

        assert response.status_code == 201, response.text
        link = _one(db.invitation_emails())["params"]["accept_link"]
        assert link.startswith(INVITE_LINK_PREFIX)
        token_part = link[len(INVITE_LINK_PREFIX) :]
        assert TOKEN_RE.fullmatch(token_part)
        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        invitation = db.invitation_of(invited["id"])
        assert invitation is not None
        assert invitation["token_hash"] == sha256(token_part)
        assert "evil" not in json.dumps(db.outbox, default=str)

    def test_organizations_api_create_response_holds_no_token_or_link(self, db: FakeDb) -> None:
        _, token = _super_admin(db)

        response = _call(_client(_app()), "create", token)

        assert response.status_code == 201, response.text
        link = _one(db.invitation_emails())["params"]["accept_link"]
        secret = link[len(INVITE_LINK_PREFIX) :]
        assert secret not in response.text
        assert sha256(secret).hex() not in response.text
        assert "accept-invitation" not in response.text
        assert "accept_link" not in response.text
        assert "token" not in response.text.lower()

    def test_organizations_api_create_is_audited_with_the_client_ip(self, db: FakeDb) -> None:
        """Exactly org.create and invitation.create, both by the Super Admin in the new
        org's log with the client IP and content-free metadata."""
        actor, token = _super_admin(db)
        before_ids = set(db.orgs)

        response = _call(_client(_app(), ip=_IP_B), "create", token)

        assert response.status_code == 201, response.text
        org_id = _new_org_id(db, before_ids)
        assert sorted(row["action"] for row in db.audit) == ["invitation.create", "org.create"]
        _assert_org_event(
            _one(db.audit_rows("org.create")),
            action="org.create",
            actor=actor,
            org_id=org_id,
            metadata={
                "seats": _SEATS,
                "monthly_budget_chf_cents": _BUDGET_CENTS,
                "storage_quota_bytes": _QUOTA,
                "active": True,
            },
        )
        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        row = _one(db.audit_rows("invitation.create"))
        assert (row["actor_kind"], _uuid(row["actor_user_id"])) == ("super_admin", actor)
        assert _uuid(row["org_id"]) == org_id
        assert (row["target_type"], row["target_ids"]) == (
            "invitation",
            [response.json()["invitation"]["id"]],
        )
        assert row["ip"] == _IP_B
        assert row["metadata"] == {"role": "org_admin", "user_id": str(invited["id"])}

    def test_organizations_api_create_deactivated_org(self, db: FakeDb) -> None:
        """status "deactivated" is accepted: the org starts deactivated, still with its
        invitation and its email; org.create says active false."""
        _, token = _super_admin(db)
        before_ids = set(db.orgs)

        response = _call(_client(_app()), "create", token, body=_create_body(status="deactivated"))

        assert response.status_code == 201, response.text
        org_id = _new_org_id(db, before_ids)
        assert response.json()["organization"]["status"] == "deactivated"
        assert db.orgs[org_id]["status"] == "deactivated"
        assert _one(db.audit_rows("org.create"))["metadata"]["active"] is False
        assert len(db.invitation_emails()) == 1

    def test_organizations_api_create_status_defaults_to_active(self, db: FakeDb) -> None:
        _, token = _super_admin(db)
        before_ids = set(db.orgs)

        response = _call(_client(_app()), "create", token, body=_create_body_without("status"))

        assert response.status_code == 201, response.text
        assert response.json()["organization"]["status"] == "active"
        assert db.orgs[_new_org_id(db, before_ids)]["status"] == "active"

    def test_organizations_api_create_strips_the_name_and_the_email(self, db: FakeDb) -> None:
        _, token = _super_admin(db)
        before_ids = set(db.orgs)

        response = _call(
            _client(_app()),
            "create",
            token,
            body=_create_body(
                name="  " + _NEW_NAME + "\t", primary_admin_email=f" {_ADMIN_EMAIL} "
            ),
        )

        assert response.status_code == 201, response.text
        assert response.json()["organization"]["name"] == _NEW_NAME
        assert response.json()["invitation"]["email"] == _ADMIN_EMAIL
        assert db.orgs[_new_org_id(db, before_ids)]["name"] == _NEW_NAME
        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        assert invited["email"] == _ADMIN_EMAIL

    @pytest.mark.parametrize(
        ("budget", "stored"),
        [
            pytest.param(99.99, Decimal("99.99"), id="json-float"),
            pytest.param(100, Decimal("100.00"), id="json-int"),
            pytest.param("0", Decimal("0.00"), id="string-zero"),
            pytest.param("9999999999.99", Decimal("9999999999.99"), id="string-max"),
        ],
    )
    def test_organizations_api_create_accepts_the_budget_as_number_or_string(
        self, db: FakeDb, budget: Any, stored: Decimal
    ) -> None:
        _, token = _super_admin(db)
        before_ids = set(db.orgs)

        response = _call(
            _client(_app()), "create", token, body=_create_body(monthly_budget_chf=budget)
        )

        assert response.status_code == 201, response.text
        assert Decimal(response.json()["organization"]["monthly_budget_chf"]) == stored
        assert db.orgs[_new_org_id(db, before_ids)]["monthly_budget_chf"] == stored

    @pytest.mark.parametrize(
        "existing",
        [
            pytest.param({"org_id": OTHER_ORG_ID}, id="active-member-of-another-org"),
            pytest.param({"email": _ADMIN_EMAIL.upper()}, id="other-capitalization"),
            pytest.param({"kind": "super_admin", "role": None}, id="super-admin"),
            pytest.param({"status": "deactivated"}, id="deactivated"),
            pytest.param({"deleted_at": _DELETED_AT}, id="soft-deleted"),
            pytest.param(
                {"status": "invited", "name": None, "password_hash": None}, id="pending-invitee"
            ),
        ],
    )
    def test_organizations_api_create_taken_email_is_409_and_writes_nothing(
        self, db: FakeDb, existing: dict[str, Any]
    ) -> None:
        """409 {"detail", "reason": "email_taken"}: no org, no user, no invitation, no email,
        no audit row."""
        _route_of("create")
        _, token = _super_admin(db)
        db.add_account(**{"email": _ADMIN_EMAIL, **existing})
        before = _state(db)

        response = _call(_client(_app()), "create", token)

        assert response.status_code == 409
        assert response.json() == _EMAIL_TAKEN
        assert _state(db) == before

    def test_organizations_api_create_padded_capitalized_taken_email_is_409(
        self, db: FakeDb
    ) -> None:
        _route_of("create")
        _, token = _super_admin(db)
        db.add_account(email=_ADMIN_EMAIL, org_id=OTHER_ORG_ID)
        before = _state(db)

        response = _call(
            _client(_app()),
            "create",
            token,
            body=_create_body(primary_admin_email="  " + _ADMIN_EMAIL.upper() + " "),
        )

        assert response.status_code == 409
        assert response.json() == _EMAIL_TAKEN
        assert _state(db) == before

    def test_organizations_api_create_same_email_twice_is_409(self, db: FakeDb) -> None:
        """The first org's invited admin holds the email: a second org with it is refused
        and leaves the first org alone."""
        _, token = _super_admin(db)
        client = _client(_app())
        assert _call(client, "create", token).status_code == 201
        before = _state(db)

        response = _call(
            client, "create", token, body=_create_body(name="Zweite Kanzlei Marker GmbH")
        )

        assert response.status_code == 409
        assert response.json() == _EMAIL_TAKEN
        assert _state(db) == before

    @pytest.mark.parametrize("body", _BAD_CREATE_BODIES)
    def test_organizations_api_create_bad_body_is_422_without_echo(
        self, db: FakeDb, body: Any
    ) -> None:
        """422; nothing the caller sent comes back; nothing is written."""
        _route_of("create")
        _, token = _super_admin(db)
        before = _state(db)

        response = _call(_client(_app()), "create", token, body=body)

        _assert_no_echo(response, body)
        assert _state(db) == before
        assert db.matching(r"^insert into\b") == []


# ---------------------------------------------------------------------------
# 4. GET /api/platform/orgs
# ---------------------------------------------------------------------------


class TestListRoute:
    """Every org, whatever its status, as OrgSummary, by creation then id."""

    def test_organizations_api_list_returns_every_org_in_order(self, db: FakeDb) -> None:
        """200 {"organizations": [...]}: all statuses; created_at first, then id for a tie;
        exactly the summary keys; every value from the rows."""
        later = _OLD + timedelta(days=2)
        requested = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
        db.add_org(
            _ORG_TIE_HIGH,
            name="Summary Marker GmbH",
            seats=42,
            status="pending_deletion",
            monthly_budget_chf=Decimal("77.50"),
            storage_quota_bytes=123456789,
            data_residency=False,
            deletion_requested_at=requested,
            purge_after=requested + timedelta(days=30),
            created_at=later,
            updated_at=requested,
        )
        db.add_org(_ORG_OLDEST, status="deactivated", created_at=_OLD)
        db.add_org(_ORG_TIE_LOW, created_at=later)
        _, token = _super_admin(db)

        response = _call(_client(_app()), "list", token)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"organizations"}
        entries = body["organizations"]
        assert [entry["id"] for entry in entries] == [
            str(_ORG_OLDEST),
            str(_ORG_TIE_LOW),
            str(_ORG_TIE_HIGH),
        ]
        for entry in entries:
            _assert_summary(entry, db.orgs[uuid.UUID(entry["id"])])
        assert [entry["status"] for entry in entries] == [
            "deactivated",
            "active",
            "pending_deletion",
        ]

    def test_organizations_api_list_without_orgs_is_empty(self, db: FakeDb) -> None:
        _, token = _super_admin(db)

        response = _call(_client(_app()), "list", token)

        assert response.status_code == 200
        assert response.json() == {"organizations": []}

    def test_organizations_api_list_writes_nothing(self, db: FakeDb) -> None:
        """No row changes and no audit row; members' emails never appear."""
        db.add_org(ORG_ID)
        db.add_account(role="org_admin", email="member.of.the.org@example.ch")
        _, token = _super_admin(db)
        before = _state(db)

        response = _call(_client(_app()), "list", token)

        assert response.status_code == 200
        assert _state(db) == before
        assert "member.of.the.org" not in response.text


# ---------------------------------------------------------------------------
# 5. PATCH /api/platform/orgs/{org_id}/limits
# ---------------------------------------------------------------------------

_BAD_LIMITS_BODIES = [
    pytest.param({}, id="empty"),
    pytest.param({"seats": None, "monthly_budget_chf": None, "storage_quota": None}, id="all-null"),
    pytest.param({"seats": 0}, id="seats-0"),
    pytest.param({"seats": 100001}, id="seats-100001"),
    pytest.param({"seats": "10"}, id="seats-string"),
    pytest.param({"seats": 10.0}, id="seats-float"),
    pytest.param({"seats": True}, id="seats-bool"),
    pytest.param({"monthly_budget_chf": "-1"}, id="budget-negative"),
    pytest.param({"monthly_budget_chf": "1.234"}, id="budget-3-decimals"),
    pytest.param({"monthly_budget_chf": "12345678901.00"}, id="budget-11-digits"),
    pytest.param({"monthly_budget_chf": "NaN"}, id="budget-nan"),
    pytest.param({"monthly_budget_chf": True}, id="budget-bool"),
    pytest.param({"monthly_budget_chf": "ECHOMARK42"}, id="budget-text"),
    pytest.param({"storage_quota": -1}, id="storage-negative"),
    pytest.param({"storage_quota": 2**53}, id="storage-2-pow-53"),
    pytest.param({"storage_quota": "1073741824"}, id="storage-string"),
    pytest.param({"seats": 5, "name": "ECHOMARK42"}, id="extra-name"),
    pytest.param({"seats": 5, "status": "active"}, id="extra-status"),
    pytest.param({"seats": 5, "data_residency": False}, id="extra-residency"),
    pytest.param({"seats": 5, "storage_quota_bytes": 1024}, id="extra-column-name"),
    pytest.param([], id="list"),
]


class TestLimitsRoute:
    """Only the given limits change; old and new values are audited (the budget in cents)."""

    @pytest.mark.parametrize(
        ("body", "stored", "metadata"),
        [
            pytest.param(
                {"seats": 7}, {"seats": 7}, {"seats_old": 100, "seats_new": 7}, id="seats"
            ),
            pytest.param(
                {"monthly_budget_chf": "250.5"},
                {"monthly_budget_chf": Decimal("250.50")},
                {"monthly_budget_chf_cents_old": 1000, "monthly_budget_chf_cents_new": 25050},
                id="budget-string",
            ),
            pytest.param(
                {"monthly_budget_chf": 99.99},
                {"monthly_budget_chf": Decimal("99.99")},
                {"monthly_budget_chf_cents_old": 1000, "monthly_budget_chf_cents_new": 9999},
                id="budget-json-number",
            ),
            pytest.param(
                {"storage_quota": 2048},
                {"storage_quota_bytes": 2048},
                {"storage_quota_bytes_old": 4096, "storage_quota_bytes_new": 2048},
                id="storage",
            ),
            pytest.param(
                {"seats": 3, "monthly_budget_chf": 0, "storage_quota": 0},
                {"seats": 3, "monthly_budget_chf": Decimal(0), "storage_quota_bytes": 0},
                {
                    "seats_old": 100,
                    "seats_new": 3,
                    "monthly_budget_chf_cents_old": 1000,
                    "monthly_budget_chf_cents_new": 0,
                    "storage_quota_bytes_old": 4096,
                    "storage_quota_bytes_new": 0,
                },
                id="all",
            ),
            pytest.param(
                {"seats": 9, "monthly_budget_chf": None, "storage_quota": None},
                {"seats": 9},
                {"seats_old": 100, "seats_new": 9},
                id="nulls-are-not-given",
            ),
        ],
    )
    def test_organizations_api_limits_change_only_the_given_fields(
        self,
        db: FakeDb,
        body: dict[str, Any],
        stored: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        """200 with the updated OrgSummary; the other columns keep their values;
        org.limits_change with exactly the given fields' old and new values."""
        db.add_org(ORG_ID, monthly_budget_chf=Decimal("10.00"), storage_quota_bytes=4096)
        actor, token = _super_admin(db)
        before_row = copy.deepcopy(db.orgs[ORG_ID])

        response = _call(_client(_app(), ip=_IP_B), "limits", token, ORG_ID, body=body)

        assert response.status_code == 200, response.text
        row = db.orgs[ORG_ID]
        assert row == {**before_row, **stored, "updated_at": row["updated_at"]}
        _assert_summary(response.json(), row)
        _assert_org_event(
            _one(db.audit),
            action="org.limits_change",
            actor=actor,
            org_id=ORG_ID,
            metadata=metadata,
        )

    def test_organizations_api_limits_of_a_deactivated_org(self, db: FakeDb) -> None:
        db.add_org(ORG_ID, status="deactivated")
        _, token = _super_admin(db)

        response = _call(_client(_app()), "limits", token, ORG_ID, body={"seats": 4})

        assert response.status_code == 200, response.text
        assert (response.json()["seats"], db.orgs[ORG_ID]["seats"]) == (4, 4)

    def test_organizations_api_limits_seats_may_go_below_the_seats_in_use(self, db: FakeDb) -> None:
        db.add_org(ORG_ID)
        for _ in range(3):
            db.add_account(role="editor")
        _, token = _super_admin(db)

        response = _call(_client(_app()), "limits", token, ORG_ID, body={"seats": 1})

        assert response.status_code == 200, response.text
        assert db.orgs[ORG_ID]["seats"] == 1

    @pytest.mark.parametrize("body", _BAD_LIMITS_BODIES)
    def test_organizations_api_limits_bad_body_is_422_without_echo(
        self, db: FakeDb, body: Any
    ) -> None:
        """At least one limit, each within its bounds, no other field; nothing written."""
        _route_of("limits")
        db.add_org(ORG_ID)
        _, token = _super_admin(db)
        before = _state(db)

        response = _call(_client(_app()), "limits", token, ORG_ID, body=body)

        _assert_no_echo(response, body)
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 6. The status routes: deactivate, reactivate, schedule and cancel deletion
# ---------------------------------------------------------------------------


def _transition_metadata(name: str) -> dict[str, Any]:
    """The metadata of a transition on an org without users or sessions."""
    if name == "deactivate":
        return {"sessions_revoked": 0}
    if name == "schedule":
        return {"sessions_revoked": 0, "emails_queued": 0, "grace_days": 30}
    return {}


class TestStatusRoutes:
    """active <-> deactivated; active/deactivated -> pending_deletion -> deactivated."""

    @pytest.mark.parametrize(("name", "start"), _ALLOWED_TRANSITIONS)
    def test_organizations_api_transition_returns_the_updated_summary(
        self, db: FakeDb, name: str, start: str
    ) -> None:
        """200 with the OrgSummary of the stored row: the new status; deletion dates only
        after scheduling."""
        db.add_org(ORG_ID, status=start, updated_at=_OLD)
        _, token = _super_admin(db)

        response = _call(_client(_app()), name, token, ORG_ID)

        assert response.status_code == 200, response.text
        row = db.orgs[ORG_ID]
        body = response.json()
        _assert_summary(body, row)
        assert body["status"] == _TRANSITIONS[name][1]
        scheduled = name == "schedule"
        assert (body["deletion_requested_at"] is not None) is scheduled
        assert (body["purge_after"] is not None) is scheduled
        assert row["updated_at"] > _OLD

    @pytest.mark.parametrize(("name", "start"), _ALLOWED_TRANSITIONS)
    def test_organizations_api_transition_is_audited_with_the_client_ip(
        self, db: FakeDb, name: str, start: str
    ) -> None:
        db.add_org(ORG_ID, status=start)
        actor, token = _super_admin(db)

        response = _call(_client(_app(), ip=_IP_B), name, token, ORG_ID)

        assert response.status_code == 200, response.text

        _assert_org_event(
            _one(db.audit),
            action=_TRANSITIONS[name][2],
            actor=actor,
            org_id=ORG_ID,
            metadata=_transition_metadata(name),
        )

    @pytest.mark.parametrize(("action", "start"), _REFUSED)
    def test_organizations_api_change_the_status_doesnt_allow_is_409(
        self, db: FakeDb, action: str, start: str
    ) -> None:
        """409 {"detail", "reason": "invalid_status"}; nothing written, no audit row."""
        _route_of(action)
        db.add_org(ORG_ID, status=start)
        _, token = _super_admin(db)
        before = _state(db)

        response = _call(_client(_app()), action, token, ORG_ID)

        assert response.status_code == 409
        assert response.json() == _INVALID_STATUS
        assert _state(db) == before

    @pytest.mark.parametrize("start", ["active", "deactivated"])
    def test_organizations_api_schedule_sets_a_30_day_grace_period(
        self, db: FakeDb, start: str
    ) -> None:
        db.add_org(ORG_ID, status=start)
        _, token = _super_admin(db)
        before = datetime.now(UTC)

        response = _call(_client(_app()), "schedule", token, ORG_ID)

        assert response.status_code == 200, response.text
        body = response.json()

        requested = _dt(body["deletion_requested_at"])
        purge_after = _dt(body["purge_after"])
        assert requested is not None
        assert purge_after is not None
        assert before <= requested <= datetime.now(UTC)
        assert purge_after - requested == timedelta(days=30)

    def test_organizations_api_cancel_lands_on_deactivated_and_clears_the_dates(
        self, db: FakeDb
    ) -> None:
        """Schedule an active org, then cancel: deactivated (never active), no dates."""
        db.add_org(ORG_ID)
        _, token = _super_admin(db)
        client = _client(_app())
        assert _call(client, "schedule", token, ORG_ID).status_code == 200

        response = _call(client, "cancel", token, ORG_ID)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "deactivated"
        assert (body["deletion_requested_at"], body["purge_after"]) == (None, None)
        row = db.orgs[ORG_ID]
        assert (row["status"], row["deletion_requested_at"], row["purge_after"]) == (
            "deactivated",
            None,
            None,
        )

    @pytest.mark.parametrize("name", ["deactivate", "schedule"])
    def test_organizations_api_revokes_every_session_of_the_org_and_keeps_its_content(
        self, db: FakeDb, name: str
    ) -> None:
        """The org's members' sessions end (counted in the audit row); another org's and
        the Super Admin's stay; the users rows and invitations are kept."""
        db.add_org(ORG_ID)
        admin = db.add_account(role="org_admin")
        editor = db.add_account(role="editor")
        invitee = db.add_account(role="viewer", status="invited", name=None, password_hash=None)
        db.add_invitation(invitee)
        mine = [db.open_session(admin), db.open_session(editor), db.open_session(editor)]
        theirs = db.open_session(db.add_account(role="editor", org_id=OTHER_ORG_ID))
        _, token = _super_admin(db)
        users_before = copy.deepcopy(db.users)
        invitations_before = copy.deepcopy(db.invitations)

        response = _call(_client(_app()), name, token, ORG_ID)

        assert response.status_code == 200, response.text
        assert [db.session_revoked(session) for session in mine] == [True, True, True]
        assert not db.session_revoked(theirs)
        assert not db.session_revoked(token)
        assert db.users == users_before
        assert db.invitations == invitations_before
        metadata = _one(db.audit_rows(_TRANSITIONS[name][2]))["metadata"]
        assert metadata["sessions_revoked"] == 3

    def test_organizations_api_schedule_emails_only_active_org_admins(self, db: FakeDb) -> None:
        """One org_deletion_scheduled email per active, non-deleted Org Admin of the org, in
        their language, with the org's name and the purge date; nobody else."""
        db.add_org(ORG_ID)
        admin_de = db.add_account(role="org_admin", ui_language="de")
        admin_fr = db.add_account(role="org_admin", ui_language="fr")
        db.add_account(role="org_admin", status="deactivated")
        db.add_account(role="org_admin", status="invited", name=None, password_hash=None)
        db.add_account(role="org_admin", deleted_at=_DELETED_AT)
        db.add_account(role="editor")
        db.add_account(role="viewer")
        db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
        _, token = _super_admin(db)

        response = _call(_client(_app()), "schedule", token, ORG_ID)

        assert response.status_code == 200, response.text
        emails = [row for row in db.outbox if row["template_key"] == "org_deletion_scheduled"]
        assert len(db.outbox) == len(emails) == 2
        assert {(row["user_id"], row["language"]) for row in emails} == {
            (admin_de, "de"),
            (admin_fr, "fr"),
        }
        for email in emails:
            assert set(email["params"]) == {"org_name", "purge_after"}
            assert email["params"]["org_name"] == ORG_NAME
            assert _dt(email["params"]["purge_after"]) == db.orgs[ORG_ID]["purge_after"]
        metadata = _one(db.audit_rows("org.deletion_schedule"))["metadata"]
        assert metadata == {"sessions_revoked": 0, "emails_queued": 2, "grace_days": 30}

    def test_organizations_api_cancel_queues_no_email(self, db: FakeDb) -> None:
        db.add_org(ORG_ID, status="pending_deletion")
        db.add_account(role="org_admin")
        _, token = _super_admin(db)

        response = _call(_client(_app()), "cancel", token, ORG_ID)

        assert response.status_code == 200, response.text
        assert db.outbox == []


# ---------------------------------------------------------------------------
# 7. PATCH /api/platform/orgs/{org_id}/residency
# ---------------------------------------------------------------------------

_BAD_RESIDENCY_BODIES = [
    pytest.param({}, id="empty"),
    pytest.param({"enabled": None}, id="null"),
    pytest.param({"enabled": "true"}, id="string"),
    pytest.param({"enabled": 1}, id="one"),
    pytest.param({"enabled": 0}, id="zero"),
    pytest.param({"enabled": "ECHOMARK42"}, id="text"),
    pytest.param({"enabled": True, "org_id": "ECHOMARK42"}, id="extra-field"),
    pytest.param([], id="list"),
]


class TestResidencyRoute:
    """The residency switch, audited in the org's own log (also when unchanged)."""

    @pytest.mark.parametrize(
        ("previous", "enabled"),
        [
            pytest.param(True, False, id="turn-off"),
            pytest.param(False, True, id="turn-on"),
            pytest.param(True, True, id="unchanged"),
        ],
    )
    def test_organizations_api_residency_is_set_and_audited(
        self, db: FakeDb, previous: bool, enabled: bool
    ) -> None:
        db.add_org(ORG_ID, data_residency=previous)
        actor, token = _super_admin(db)

        response = _call(
            _client(_app(), ip=_IP_B), "residency", token, ORG_ID, body={"enabled": enabled}
        )

        assert response.status_code == 200, response.text
        assert db.orgs[ORG_ID]["data_residency"] is enabled
        _assert_summary(response.json(), db.orgs[ORG_ID])
        _assert_org_event(
            _one(db.audit),
            action="org.residency_change",
            actor=actor,
            org_id=ORG_ID,
            metadata={"enabled": enabled, "previous": previous},
        )

    def test_organizations_api_residency_of_a_deactivated_org(self, db: FakeDb) -> None:
        db.add_org(ORG_ID, status="deactivated")
        _, token = _super_admin(db)

        response = _call(_client(_app()), "residency", token, ORG_ID, body={"enabled": False})

        assert response.status_code == 200, response.text
        assert db.orgs[ORG_ID]["data_residency"] is False

    @pytest.mark.parametrize("body", _BAD_RESIDENCY_BODIES)
    def test_organizations_api_residency_bad_body_is_422_without_echo(
        self, db: FakeDb, body: Any
    ) -> None:
        _route_of("residency")
        db.add_org(ORG_ID)
        _, token = _super_admin(db)
        before = _state(db)

        response = _call(_client(_app()), "residency", token, ORG_ID, body=body)

        _assert_no_echo(response, body)
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 8. Unknown and malformed org ids
# ---------------------------------------------------------------------------


class TestOrgIds:
    """An unknown org is a 404; a non-UUID id a 422 that doesn't echo it."""

    @pytest.mark.parametrize("action", _ORG_ACTIONS)
    def test_organizations_api_unknown_org_is_404(self, db: FakeDb, action: str) -> None:
        """404 {"detail": "Organization not found"}; the org that exists (in a status the
        action is allowed from) is untouched; no audit row."""
        _route_of(action)
        db.add_org(ORG_ID, status=_READY[action])
        _, token = _super_admin(db)
        before = _state(db)

        response = _call(_client(_app()), action, token, _UNKNOWN_ORG)

        assert response.status_code == 404
        assert response.json() == _NOT_FOUND
        assert _state(db) == before

    @pytest.mark.parametrize("bad_id", _BAD_IDS)
    @pytest.mark.parametrize("action", _ORG_ACTIONS)
    def test_organizations_api_non_uuid_org_id_is_422_without_echo(
        self, db: FakeDb, action: str, bad_id: str
    ) -> None:
        _route_of(action)
        db.add_org(ORG_ID, status=_READY[action])
        _, token = _super_admin(db)
        before = _state(db)

        response = _call(_client(_app()), action, token, bad_id)

        assert response.status_code == 422
        assert "ECHOMARK42" not in response.text
        assert "x" * 20 not in response.text
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 9. End to end: what a deactivated or pending org's members can still do
# ---------------------------------------------------------------------------

_MEMBER_EMAIL = "member.e2e@example.ch"
_OUTSIDER_EMAIL = "outsider.e2e@example.ch"


class TestLifecycleEndToEnd:
    """Deactivation blocks every request and every login of the org's members at once."""

    def _world(self, db: FakeDb) -> dict[str, Any]:
        """A member of ORG_ID and one of OTHER_ORG_ID (each with a live session and a
        password), a Super Admin, and a client."""
        db.add_org(ORG_ID)
        db.add_org(OTHER_ORG_ID)
        member = _member_account(db, _MEMBER_EMAIL, role="org_admin")
        outsider = _member_account(db, _OUTSIDER_EMAIL, OTHER_ORG_ID)
        _, super_token = _super_admin(db)
        return {
            "member": member,
            "member_cookie": db.open_session(member),
            "outsider_cookie": db.open_session(outsider),
            "super": super_token,
            "client": _client(_app()),
        }

    @pytest.mark.parametrize("name", ["deactivate", "schedule"])
    def test_organizations_api_members_are_locked_out_at_once(self, db: FakeDb, name: str) -> None:
        """A cookie that worked gets 401 on /api/auth/me; the right password gets the
        generic login 401 without a cookie; another org's member and the Super Admin keep
        working."""
        world = self._world(db)
        client = world["client"]
        assert _me(client, world["member_cookie"]).status_code == 200

        assert _call(client, name, world["super"], ORG_ID).status_code == 200

        me = _me(client, world["member_cookie"])
        assert (me.status_code, me.json()) == (401, _UNAUTHORIZED)
        login = _login(client, _MEMBER_EMAIL)
        assert (login.status_code, login.json()) == (401, _LOGIN_FAILED)
        assert _session_cookie_headers(login) == []
        assert _me(client, world["outsider_cookie"]).status_code == 200
        assert _login(client, _OUTSIDER_EMAIL).status_code == 204
        assert _call(client, "list", world["super"]).status_code == 200

    def test_organizations_api_reactivated_members_can_log_in_again(self, db: FakeDb) -> None:
        """After reactivation the password works again; the cookie revoked at deactivation
        stays dead."""
        world = self._world(db)
        client = world["client"]
        assert _call(client, "deactivate", world["super"], ORG_ID).status_code == 200

        assert _call(client, "reactivate", world["super"], ORG_ID).status_code == 200

        login = _login(client, _MEMBER_EMAIL)
        assert login.status_code == 204
        me = _me(client, _session_cookie_value(login))
        assert me.status_code == 200
        assert me.json()["user_id"] == str(world["member"])
        assert _me(client, world["member_cookie"]).status_code == 401

    def test_organizations_api_cancelled_deletion_keeps_members_out_until_reactivated(
        self, db: FakeDb
    ) -> None:
        world = self._world(db)
        client = world["client"]
        assert _call(client, "schedule", world["super"], ORG_ID).status_code == 200
        assert _call(client, "cancel", world["super"], ORG_ID).status_code == 200

        refused = _login(client, _MEMBER_EMAIL)
        assert _call(client, "reactivate", world["super"], ORG_ID).status_code == 200
        allowed = _login(client, _MEMBER_EMAIL)

        assert (refused.status_code, refused.json()) == (401, _LOGIN_FAILED)
        assert allowed.status_code == 204


# ---------------------------------------------------------------------------
# 10. Rate limits: per route key and Super Admin
# ---------------------------------------------------------------------------


def _limited(monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    """One request per key, then nothing for a long time."""
    monkeypatch.setitem(server._RATE_LIMITS, key, (0.001, 1))


class TestRateLimits:
    """Each route spends its key's per-user bucket; one Super Admin never throttles another."""

    @pytest.mark.parametrize("action", _ALL_ACTIONS)
    def test_organizations_api_rate_limit_is_per_super_admin(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """With a burst of 1 on the route's key: the second call is 429 {"detail": "Rate
        limit exceeded"}; another Super Admin's call still runs; the bucket is (key,
        "user:<id>")."""
        _route_of(action)
        app = _app()
        _limited(monkeypatch, _ROUTE_KEYS[action])
        first_admin, token_a = _super_admin(db)
        _, token_b = _super_admin(db)
        client = _client(app)

        def call(token: str, index: int) -> httpx.Response:
            if action == "create":
                body = _create_body(primary_admin_email=f"first.admin.{index}@example.ch")
                return _call(client, action, token, body=body)
            return _call(client, action, token, _UNKNOWN_ORG)

        first = call(token_a, 1)
        limited = call(token_a, 2)
        other = call(token_b, 3)

        expected = {"list": 200, "create": 201}.get(action, 404)
        assert first.status_code == expected, first.text
        assert limited.status_code == 429
        assert limited.json() == _RATE_LIMITED
        assert other.status_code == expected, other.text
        if expected == 404:
            assert other.json() == _NOT_FOUND
        assert (_ROUTE_KEYS[action], f"user:{first_admin}") in server._rate_buckets

    def test_organizations_api_deactivate_and_reactivate_share_a_bucket(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """/api/platform/orgs/status: a deactivation spends the reactivation's token too;
        the throttled call changes nothing; another Super Admin can still reactivate."""
        app = _app()
        _limited(monkeypatch, _KEY_STATUS)
        db.add_org(ORG_ID)
        _, token_a = _super_admin(db)
        _, token_b = _super_admin(db)
        client = _client(app)

        deactivated = _call(client, "deactivate", token_a, ORG_ID)
        limited = _call(client, "reactivate", token_a, ORG_ID)
        status_after_limit = db.orgs[ORG_ID]["status"]
        other = _call(client, "reactivate", token_b, ORG_ID)

        assert deactivated.status_code == 200
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert status_after_limit == "deactivated"
        assert other.status_code == 200

    def test_organizations_api_schedule_and_cancel_share_a_bucket(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """/api/platform/orgs/deletion is one bucket for scheduling and cancelling."""
        app = _app()
        _limited(monkeypatch, _KEY_DELETION)
        db.add_org(ORG_ID)
        _, token_a = _super_admin(db)
        _, token_b = _super_admin(db)
        client = _client(app)

        scheduled = _call(client, "schedule", token_a, ORG_ID)
        limited = _call(client, "cancel", token_a, ORG_ID)
        status_after_limit = db.orgs[ORG_ID]["status"]
        other = _call(client, "cancel", token_b, ORG_ID)

        assert scheduled.status_code == 200
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert status_after_limit == "pending_deletion"
        assert other.status_code == 200

    def test_organizations_api_status_bucket_is_separate_from_the_others(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A spent /status bucket doesn't throttle limits, residency or deletion."""
        app = _app()
        _limited(monkeypatch, _KEY_STATUS)
        db.add_org(ORG_ID)
        _, token = _super_admin(db)
        client = _client(app)
        assert _call(client, "deactivate", token, ORG_ID).status_code == 200
        assert _call(client, "reactivate", token, ORG_ID).status_code == 429

        statuses = [
            _call(client, "limits", token, ORG_ID).status_code,
            _call(client, "residency", token, ORG_ID).status_code,
            _call(client, "schedule", token, ORG_ID).status_code,
        ]

        assert statuses == [200, 200, 200]


# ---------------------------------------------------------------------------
# 11. CSRF, and fail closed on an audit failure
# ---------------------------------------------------------------------------


class TestCrossOriginAndFailClosed:
    """Cross-origin writes never reach the database; a failed audit write keeps nothing."""

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    @pytest.mark.parametrize("action", _WRITE_ACTIONS)
    def test_organizations_api_cross_origin_write_is_refused_before_the_database(
        self, db: FakeDb, action: str, headers: dict[str, str]
    ) -> None:
        """403 {"detail": "Cross-origin request refused"}; no database call at all."""
        _route_of(action)
        db.add_org(ORG_ID, status=_READY[action])
        _, token = _super_admin(db)
        before = _state(db)

        response = _call(_client(_app()), action, token, ORG_ID, **headers)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert db.calls == []
        assert _state(db) == before

    @pytest.mark.parametrize("action", _WRITE_ACTIONS)
    def test_organizations_api_audit_failure_is_500_and_writes_nothing(
        self, db: FakeDb, action: str
    ) -> None:
        """No org, invitation or email; no status, limit or residency change; every session
        of the org is still there."""
        _route_of(action)
        db.add_org(ORG_ID, status=_READY[action])
        member = db.add_account(role="org_admin")
        db.open_session(member)
        _, token = _super_admin(db)
        before = _state(db)
        db.fail_audit = True

        response = _call(_client(_app(), raise_server_exceptions=False), action, token, ORG_ID)

        assert response.status_code == 500
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 12. No content in logs or audit rows
# ---------------------------------------------------------------------------


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record of every logger, with its traceback."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(record) for record in caplog.records)


class TestNoContentInLogs:
    """The org name, the admin email, the invitation token and link never reach a log
    record or an audit row."""

    def _flow(self, db: FakeDb) -> list[str]:
        """Create an org, refuse a duplicate, refuse a bad name, list, change limits and
        residency, deactivate, reactivate, schedule, cancel, refuse a second cancel and an
        unknown org, schedule ORG_ID's deletion (its admins are emailed); return the
        issued invitation token."""
        db.add_org(ORG_ID)
        db.add_account(role="org_admin", email="log.marker.member@example.ch")
        _, token = _super_admin(db, email="log.marker.superadmin@example.ch")
        client = _client(_app())
        created = _call(client, "create", token)
        assert created.status_code == 201, created.text
        org_id = created.json()["organization"]["id"]
        invited = db.user_by_email(_ADMIN_EMAIL)
        assert invited is not None
        issued = db.invitation_token(invited["id"])
        duplicate = _create_body(
            name="Zweite Marker Treuhand", primary_admin_email=" " + _ADMIN_EMAIL.upper()
        )
        assert _call(client, "create", token, body=duplicate).status_code == 409
        bad = _create_body(name="Dritte Marker" + chr(0), primary_admin_email="bad@marker.ch")
        assert _call(client, "create", token, body=bad).status_code == 422
        assert _call(client, "list", token).status_code == 200
        limits = {"seats": 3, "monthly_budget_chf": "9.99"}
        assert _call(client, "limits", token, org_id, body=limits).status_code == 200
        assert _call(client, "residency", token, org_id).status_code == 200
        for name in ("deactivate", "reactivate", "schedule", "cancel"):
            assert _call(client, name, token, org_id).status_code == 200
        assert _call(client, "cancel", token, org_id).status_code == 409
        assert _call(client, "deactivate", token, _UNKNOWN_ORG).status_code == 404
        assert _call(client, "schedule", token, ORG_ID).status_code == 200
        return [issued]

    def test_organizations_api_flow_logs_no_content(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        tokens = self._flow(db)

        text = _log_text(caplog)
        lowered = text.lower()
        assert "marker" not in lowered
        assert ORG_NAME.lower() not in lowered
        assert "accept-invitation" not in lowered
        for token in tokens:
            assert token not in text
            assert sha256(token).hex() not in text

    def test_organizations_api_audit_rows_carry_no_content(self, db: FakeDb) -> None:
        """No name, email, token or link; metadata values are ints, bools or IDs (plus the
        role)."""
        tokens = self._flow(db)

        stored = json.dumps(db.audit, default=str)
        lowered = stored.lower()
        assert "marker" not in lowered
        assert "treuhand" not in lowered
        assert "accept-invitation" not in lowered
        for token in tokens:
            assert token not in stored
        uuid_re = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        for row in db.audit:
            for value in row["metadata"].values():
                assert (
                    type(value) in {int, bool}
                    or value == "org_admin"
                    or (isinstance(value, str) and uuid_re.fullmatch(value))
                ), (row["action"], value)
