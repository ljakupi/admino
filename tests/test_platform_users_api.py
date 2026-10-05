"""HTTP-layer spec for the Super Admin user administration routes (GH-167).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with a fake
config whose ``server.public_url`` is ``https://admino.example.ch``. The real
``admino.platform_users`` service and the ``accounts``, ``invitations``,
``password_reset``, ``sessions``, ``email_outbox`` and ``audit_events`` code it
reuses run through the real ``require_session`` and real session cookies; only
Argon2 is replaced by a fast fake.

What these tests pin down:
- Six Super Admin routes under ``/api/platform/orgs/{org_id}``:
  ``GET .../users`` → 200 ``{"users": [...]}``: every active, deactivated and
  invited account of the org, oldest first (created_at, then id), each with
  exactly id, name, email, role, status, created_at and last_login_at.
  ``GET .../metadata`` → 200 with exactly ``seats`` (``used``: active + invited,
  ``limit``: the org's seats), ``storage_used_bytes``, ``chat_count`` (GH-176:
  the org's chats that aren't trashed, never a title) and ``file_count``
  (integers; storage and files 0 for now). ``POST .../users/{user_id}/deactivate``
  and ``.../reactivate`` → 200 with the user's summary. ``.../password-reset``
  → 202 with an empty body and a queued reset email. ``.../invitation`` → 200
  with an ``InvitationSummary``: no body, ``{}`` or ``{"email": null}`` resends
  the invited Org Admin's invitation (token rotated, old link dead, the queued
  old email cancelled); ``{"email": ...}`` replaces the invited account with a
  new one. No response carries a token or a link.
- Deactivation ends every session of the user at once (their cookie is 401 on
  the very next request). Every change is audited with ``actor_kind``
  ``super_admin``, the Super Admin's id, the affected org and the client IP.
  The reads write and audit nothing.
- Refusals: an unknown org → 404 ``Organization not found``; a user outside
  the org of the path (another org's user, an unknown id, a deleted account, a
  Super Admin, the caller) → 404 ``User not found`` with identical bytes; 409
  ``{"detail", "reason"}`` with ``last_admin``, ``invalid_status`` (user and org
  flavours), ``seat_limit``, ``email_taken`` or ``has_active_admin``. Nothing
  changes on a refusal; a refused replacement records only ``invitation.refuse``.
- Every route needs a session (401) and ``admino.access.can``:
  ``platform.org_metadata.view`` for the reads, ``platform.users.manage`` for
  the four actions. Org Admins, Editors and Viewers get 403 ``{"detail":
  "Forbidden"}`` before any query. A non-UUID id or a bad re-invite body is a
  422 that doesn't echo the input.
- Rate limits per (route key, Super Admin), checked before any database work;
  deactivate and reactivate share ``/api/platform/orgs/users/status``. A
  re-invite carrying an email is a 429 before any database work once the
  caller's refused-email budget (``server._INVITE_REFUSED_ROUTE``) is spent;
  each ``email_taken`` refusal spends exactly one token, a resend none.
- The four POST routes refuse a cross-site request before the handler; an
  audit failure is a 500 that changes nothing.
- Route table guarantees: no impersonation route or function, no PATCH/PUT
  under ``/api/platform/orgs/{org_id}/users``, no ``/api/platform/*`` request
  body field for a password or token and no ``email`` body field except the
  re-invite's, no ``/api/platform/*`` response field for a token, hash or link.
- No email, name, token or link of a target in any log line or audit row.

All database calls are faked. No network, no real PostgreSQL, no SMTP.

Security notes:
- Least privilege: only a Super Admin reaches these routes; members are refused
  before any query.
- Tenant isolation: another org's user under this org's path is a 404 with the
  bytes of an unknown id.
- No impersonation, no secrets: the Super Admin never sees a token or a link,
  never sets a password and never changes an existing user's email.
- Fail closed: an audit failure is a 500 and nothing is written.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import json
import logging
import re
import typing
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import BaseModel

from admino import accounts, invitations, org_users, organizations, server
from admino.access import Capability
from admino.server import create_app
from tests.db_fakes import (
    INVITE_LINK_PREFIX,
    LINK_PREFIX,
    ORG_ID,
    ORG_NAME,
    OTHER_ORG_ID,
    OTHER_ORG_NAME,
    TOKEN_RE,
    FakeDb,
    fake_hash,
    plain,
    sha256,
)
from tests.db_fakes import PUBLIC_URL as _PUBLIC_URL
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

    from tests.db_fakes import Call

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_IP_A = "203.0.113.5"
_IP_B = "198.51.100.23"
_ORGS = "/api/platform/orgs"
_UNKNOWN_ORG = uuid.UUID("9e8d7c6b-5a49-4382-a716-0f1e2d3c4b5a")
_UNSET: Final = object()

_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_ORG_NOT_FOUND = {"detail": "Organization not found"}
_USER_NOT_FOUND = {"detail": "User not found"}
_LAST_ADMIN = {"detail": str(accounts.LastAdminError()), "reason": "last_admin"}
_USER_INVALID_STATUS = {
    "detail": org_users.INVALID_USER_STATUS_MESSAGE,
    "reason": "invalid_status",
}
_ORG_INVALID_STATUS = {
    "detail": organizations.INVALID_STATUS_MESSAGE,
    "reason": "invalid_status",
}
_SEAT_LIMIT = {"detail": invitations.SEAT_LIMIT_MESSAGE, "reason": "seat_limit"}
_EMAIL_TAKEN = {"detail": "A user with this email already exists.", "reason": "email_taken"}
_HAS_ACTIVE_ADMIN_MESSAGE = "The organization already has an active Org Admin."
_HAS_ACTIVE_ADMIN = {"detail": _HAS_ACTIVE_ADMIN_MESSAGE, "reason": "has_active_admin"}

_USER_KEYS = frozenset({"id", "name", "email", "role", "status", "created_at", "last_login_at"})
_INVITATION_KEYS = frozenset({"id", "email", "role", "sent_at", "expires_at", "expired"})
_METADATA_KEYS = frozenset({"seats", "storage_used_bytes", "chat_count", "file_count"})
_MEMBER_ROLES = ["org_admin", "editor", "viewer"]
_ORG_STATUSES = ["active", "deactivated", "pending_deletion"]

# action -> (method, path template)
_ROUTES: dict[str, tuple[str, str]] = {
    "users": ("GET", _ORGS + "/{org_id}/users"),
    "metadata": ("GET", _ORGS + "/{org_id}/metadata"),
    "deactivate": ("POST", _ORGS + "/{org_id}/users/{user_id}/deactivate"),
    "reactivate": ("POST", _ORGS + "/{org_id}/users/{user_id}/reactivate"),
    "password_reset": ("POST", _ORGS + "/{org_id}/users/{user_id}/password-reset"),
    "invitation": ("POST", _ORGS + "/{org_id}/users/{user_id}/invitation"),
}
_ALL = list(_ROUTES)
_READS = ["users", "metadata"]
_USER_ACTIONS = ["deactivate", "reactivate", "password_reset", "invitation"]
_SUCCESS: dict[str, int] = {
    "users": 200,
    "metadata": 200,
    "deactivate": 200,
    "reactivate": 200,
    "password_reset": 202,
    "invitation": 200,
}
_CAPABILITY: dict[str, str] = {
    "users": "platform.org_metadata.view",
    "metadata": "platform.org_metadata.view",
    "deactivate": "platform.users.manage",
    "reactivate": "platform.users.manage",
    "password_reset": "platform.users.manage",
    "invitation": "platform.users.manage",
}

_KEY_USERS = "/api/platform/orgs/users/get"
_KEY_METADATA = "/api/platform/orgs/metadata/get"
_KEY_STATUS = "/api/platform/orgs/users/status"
_KEY_RESET = "/api/platform/orgs/users/password-reset"
_KEY_INVITATION = "/api/platform/orgs/users/invitation"
_KEY_REFUSED = server._INVITE_REFUSED_ROUTE
_EXPECTED_LIMITS: dict[str, tuple[float, int]] = {
    _KEY_USERS: (1.0, 10),
    _KEY_METADATA: (1.0, 10),
    _KEY_STATUS: (0.5, 5),
    _KEY_RESET: (1 / 60, 3),
    _KEY_INVITATION: (0.2, 5),
}
# Read at import, before any fixture patches the limits.
_CONFIGURED_LIMITS = {key: server._RATE_LIMITS.get(key) for key in _EXPECTED_LIMITS}
_ROUTE_KEYS: dict[str, str] = {
    "users": _KEY_USERS,
    "metadata": _KEY_METADATA,
    "deactivate": _KEY_STATUS,
    "reactivate": _KEY_STATUS,
    "password_reset": _KEY_RESET,
    "invitation": _KEY_INVITATION,
}
_ROOMY_KEYS = [*_EXPECTED_LIMITS, _KEY_REFUSED, "/api/auth/me", "/api/auth/invitations/get"]

# The status a target of ORG_ID needs for the route to succeed.
_READY_STATUS = {"deactivate": "active", "reactivate": "deactivated", "password_reset": "active"}

_TARGET_EMAIL = "platform.marker.target@example.test"
_TARGET_NAME = "Quillonmarker Person"
_CHAT_TITLE = "Marker chat title Okapi"
_INVITED_EMAIL = "platform.marker.invited@example.test"
_NEW_EMAIL = "Grace.Marker.Replacement@Example.ch"
_TAKEN_EMAIL = "platform.marker.taken@example.test"

_CROSS_ORIGIN = [
    pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
    pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
]
_BAD_IDS = [
    pytest.param("not-a-uuid-ECHOMARK42", id="text"),
    pytest.param("12345", id="digits"),
    pytest.param("x" * 200, id="200-chars"),
]
_ID_SLOTS = [pytest.param(action, "org_id", id=f"{action}-org-id") for action in _ALL] + [
    pytest.param(action, "user_id", id=f"{action}-user-id") for action in _USER_ACTIONS
]
_IMPERSONATION_WORDS = (
    "impersonat",
    "sudo",
    "login-as",
    "login_as",
    "act-as",
    "act_as",
    "become",
    "switch-user",
    "switch_user",
)
_SECRET_BODY_FIELDS = frozenset(
    {"password", "new_password", "password_hash", "token", "token_hash"}
)
_SECRET_RESPONSE_FIELDS = frozenset(
    {"token", "token_hash", "password_hash", "accept_link", "reset_link", "link"}
)


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
def _roomy_buckets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Functional tests aren't about rate limits: give the five route keys, the refused
    budget and the routes the checks use a large bucket (the rate-limit tests set their
    own, before their first request)."""
    for key in _ROOMY_KEYS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


def _config() -> MagicMock:
    """A minimal config with the public URL reset, login and invitation links use."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = True
    config.server.public_url = _PUBLIC_URL
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _app() -> FastAPI:
    """create_app with a stub agent and the fake config (it clears the rate buckets)."""
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


def _url(action: str, org_id: object = ORG_ID, user_id: object = None) -> str:
    path = _ROUTES[action][1].replace("{org_id}", str(org_id))
    return path.replace("{user_id}", str(user_id))


def _call(
    client: TestClient,
    action: str,
    token: str | None,
    org_id: object = ORG_ID,
    user_id: object = None,
    *,
    body: Any = _UNSET,
    **headers: str,
) -> httpx.Response:
    """Send one of the six routes; without ``body`` no request body is sent (for the
    re-invite: a resend)."""
    method = _ROUTES[action][0]
    kwargs: dict[str, Any] = {} if body is _UNSET else {"json": body}
    return client.request(
        method, _url(action, org_id, user_id), headers=_headers(token, **headers), **kwargs
    )


def _details(client: TestClient, token: str) -> httpx.Response:
    """GET the public invitation link route: 200 for a usable link, 404 otherwise."""
    return client.get(f"/api/auth/invitations/{token}")


def _me(client: TestClient, token: str) -> httpx.Response:
    return client.get("/api/auth/me", headers=_headers(token))


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of every table, for "nothing changed" checks. The sessions are kept by
    token hash only: any request may refresh a session's last_seen_at, but its existence
    may not change."""
    snapshot = db.snapshot()
    snapshot["sessions"] = sorted(snapshot["sessions"])
    return snapshot


def _only_session_lookups(calls: list[Call]) -> bool:
    """True when every call is require_session's own work (no route work)."""
    return all(
        "from sessions" in call.normalized
        or call.normalized.startswith("update sessions set last_seen_at")
        for call in calls
    )


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


def _dt(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def _session_cookie_headers(response: httpx.Response) -> list[str]:
    return [
        h for h in response.headers.get_list("set-cookie") if h.lower().startswith(f"{_COOKIE}=")
    ]


def _super_admin(db: FakeDb, *, ui_language: str = "en", **fields: Any) -> tuple[uuid.UUID, str]:
    """A Super Admin with a live session: (user id, session token)."""
    user_id = db.add_account(kind="super_admin", role=None, ui_language=ui_language, **fields)
    return user_id, db.open_session(user_id)


def _admin(db: FakeDb, org_id: uuid.UUID = ORG_ID, **fields: Any) -> uuid.UUID:
    """An Org Admin of ``org_id`` (active unless told otherwise)."""
    return db.add_account(role="org_admin", org_id=org_id, **fields)


def _user(db: FakeDb, org_id: uuid.UUID = ORG_ID, **fields: Any) -> uuid.UUID:
    """A member of ``org_id`` (an active Editor unless told otherwise)."""
    return db.add_account(org_id=org_id, **fields)


def _invited_admin(
    db: FakeDb,
    org_id: uuid.UUID = ORG_ID,
    *,
    role: str = "org_admin",
    sent_ago: timedelta = timedelta(0),
    invitation: bool = True,
    **fields: Any,
) -> tuple[uuid.UUID, str | None]:
    """An invited account of ``org_id`` (an Org Admin unless told otherwise) with a pending
    invitation and its invitation email still queued: (user id, raw token)."""
    user_id = db.add_account(
        role=role, status="invited", name=None, password_hash=None, org_id=org_id, **fields
    )
    if not invitation:
        return user_id, None
    token = db.add_invitation(user_id, sent_ago=sent_ago)
    row = db.invitation_of(user_id)
    assert row is not None
    db.add_email(
        user_id,
        template_key="invitation",
        params={
            "org_name": db.orgs[org_id]["name"],
            "accept_link": INVITE_LINK_PREFIX + token,
            "expires_at": row["expires_at"].isoformat(),
        },
    )
    return user_id, token


def _invited_token(user_id: uuid.UUID, token: str | None) -> str:
    assert token is not None, user_id
    return token


def _ready(db: FakeDb, action: str, org_id: uuid.UUID = ORG_ID) -> uuid.UUID | None:
    """A world in which ``action`` succeeds on ``org_id``; returns the target user (None
    for the two reads). The re-invite's org has no active Org Admin, only the invited
    one; every other org has an active Org Admin besides the target."""
    if action == "invitation":
        return _invited_admin(db, org_id, email=_INVITED_EMAIL)[0]
    _admin(db, org_id)
    status = _READY_STATUS.get(action)
    target = _user(db, org_id, status=status or "active", email=_TARGET_EMAIL, name=_TARGET_NAME)
    return target if status is not None else None


def _path_org(db: FakeDb, action: str) -> None:
    """ORG_ID exists (active); it has an active Org Admin except for the re-invite."""
    db.add_org(ORG_ID)
    if action != "invitation":
        _admin(db)


_OUTSIDER_CASES = ["other-org", "unknown", "deleted", "super-admin", "self"]


def _outsider(db: FakeDb, case: str, action: str, caller: uuid.UUID) -> uuid.UUID:
    """A user id the path's org (ORG_ID) doesn't own, in the status the action would need:
    another org's user, an unknown id, a deleted user of ORG_ID, another Super Admin or
    the calling Super Admin."""
    if case == "unknown":
        return uuid.uuid4()
    if case == "super-admin":
        return db.add_account(kind="super_admin", role=None)
    if case == "self":
        return caller
    org_id = OTHER_ORG_ID if case == "other-org" else ORG_ID
    deleted_at = datetime.now(UTC) - timedelta(days=1) if case == "deleted" else None
    if action == "invitation":
        return _invited_admin(db, org_id, deleted_at=deleted_at)[0]
    return _user(db, org_id, status=_READY_STATUS[action], deleted_at=deleted_at)


def _assert_user_entry(entry: dict[str, Any], row: dict[str, Any]) -> None:
    """A PlatformUserSummary JSON object: exactly its keys, every value from the row."""
    assert set(entry) == _USER_KEYS
    assert entry["id"] == str(row["id"])
    assert (entry["name"], entry["email"], entry["role"], entry["status"]) == (
        row["name"],
        row["email"],
        row["role"],
        row["status"],
    )
    assert _dt(entry["created_at"]) == row["created_at"]
    assert _dt(entry["last_login_at"]) == row["last_login_at"]


def _assert_event(
    row: dict[str, Any],
    *,
    action: str,
    actor: uuid.UUID,
    org_id: uuid.UUID = ORG_ID,
    metadata: Any = _UNSET,
    target_type: str | None = None,
    target_ids: list[uuid.UUID] | None = None,
    ip: str = _IP_B,
) -> None:
    """One event of a Super Admin acting on an org's user: the org's own log, the client
    IP, exactly the metadata (with the same value types; none when not given)."""
    assert row["action"] == action
    assert (row["actor_kind"], plain(row["actor_user_id"])) == ("super_admin", actor)
    assert plain(row["org_id"]) == org_id
    assert row["ip"] == ip
    if metadata is _UNSET:
        assert not row["metadata"], row["metadata"]
    else:
        assert row["metadata"] == metadata
        for key, value in metadata.items():
            assert type(row["metadata"][key]) is type(value), key
    if target_type is not None:
        assert (row["target_type"], row["target_ids"]) == (
            target_type,
            [str(target) for target in target_ids or []],
        )


def _assert_no_echo(response: httpx.Response, *markers: str) -> None:
    """A 422 whose errors carry no input and whose body repeats no marker."""
    assert response.status_code == 422, response.text
    errors = response.json()["detail"]
    assert isinstance(errors, list)
    assert errors
    assert all("input" not in error for error in errors)
    lowered = response.text.lower()
    for marker in markers:
        assert marker.lower() not in lowered, marker


def _emails_of(db: FakeDb, user_id: uuid.UUID, template_key: str) -> list[dict[str, Any]]:
    """The outbox rows of one template for one user, oldest first."""
    return [
        row
        for row in db.outbox
        if str(row["user_id"]) == str(user_id) and row["template_key"] == template_key
    ]


def _age_invitation(db: FakeDb, user_id: uuid.UUID, by: timedelta) -> uuid.UUID:
    """Move a user's invitation back in time; return its id."""
    row = db.invitation_of(user_id)
    assert row is not None
    for column in ("created_at", "sent_at", "expires_at"):
        row[column] -= by
    return plain(row["id"])


def _taken(db: FakeDb, count: int) -> list[str]:
    """Emails that already belong to users of OTHER_ORG_ID."""
    emails = [f"taken.{index}@example.ch" for index in range(count)]
    for email in emails:
        _user(db, OTHER_ORG_ID, email=email)
    return emails


def _new_user_id(db: FakeDb, email: str) -> uuid.UUID:
    row = db.user_by_email(email)
    assert row is not None, email
    return plain(row["id"])


class _CanSpy:
    """Wraps admino.access.can wherever it is looked up; records every capability asked
    for and can refuse chosen capabilities (by value)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, deny: frozenset[str] = frozenset()) -> None:
        from admino import access

        real = access.can
        self.capabilities: list[Any] = []

        def spy(principal: Any, capability: Any) -> bool:
            self.capabilities.append(capability)
            if str(capability) in deny:
                return False
            return real(principal, capability)

        monkeypatch.setattr(access, "can", spy)
        monkeypatch.setattr(server, "can", spy, raising=False)
        with contextlib.suppress(ImportError):
            from admino import platform_users

            if hasattr(platform_users, "can"):
                monkeypatch.setattr(platform_users, "can", spy)


# -- route-table walkers ----------------------------------------------------------


def _models_in(annotation: Any, seen: set[type[BaseModel]]) -> list[type[BaseModel]]:
    """Every pydantic model in an annotation, its unions and its nested fields."""
    found: list[type[BaseModel]] = []
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if annotation in seen:
            return found
        seen.add(annotation)
        found.append(annotation)
        for field in annotation.model_fields.values():
            found.extend(_models_in(field.annotation, seen))
    for arg in typing.get_args(annotation):
        found.extend(_models_in(arg, seen))
    return found


def _field_names(models: list[type[BaseModel]]) -> set[str]:
    """The field names and aliases of the models."""
    names: set[str] = set()
    for model in models:
        for name, field in model.model_fields.items():
            names.add(name)
            if field.alias:
                names.add(field.alias)
    return names


def _body_field_names(route: APIRoute) -> set[str]:
    """Every field name a route's request body accepts, at any depth."""
    names: set[str] = set()
    for param in route.dependant.body_params:
        models = _models_in(param.field_info.annotation, set())
        if models:
            names |= _field_names(models)
        else:
            names.add(param.alias)
    return names


def _response_field_names(route: APIRoute) -> set[str]:
    """Every field name of a route's response model, at any depth."""
    return _field_names(_models_in(route.response_model, set()))


def _platform_routes(app: FastAPI) -> list[APIRoute]:
    return [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith("/api/platform/")
    ]


# ---------------------------------------------------------------------------
# 1. The routes exist, need a session and are rate-limited
# ---------------------------------------------------------------------------


class TestRoutes:
    """Six Super Admin routes behind a session, with five per-user rate-limit keys."""

    @pytest.mark.parametrize("action", _ALL)
    def test_platform_users_api_route_is_registered(self, action: str) -> None:
        _route_of(action)

    @pytest.mark.parametrize("action", _ALL)
    def test_platform_users_api_route_depends_on_require_session(self, action: str) -> None:
        assert _depends_on(_route_of(action).dependant, server.require_session)

    @pytest.mark.parametrize("key", list(_EXPECTED_LIMITS))
    def test_platform_users_api_rate_limit_values(self, key: str) -> None:
        """(tokens per second, burst); deactivate and reactivate share the status key."""
        configured = _CONFIGURED_LIMITS[key]
        assert configured is not None, f"{key} has no rate limit"
        assert configured == pytest.approx(_EXPECTED_LIMITS[key])

    @pytest.mark.parametrize("action", _ALL)
    def test_platform_users_api_without_a_session_is_401_before_any_query(
        self, db: FakeDb, action: str
    ) -> None:
        _route_of(action)
        target = _ready(db, action)
        before = _state(db)

        response = _call(_client(_app()), action, None, ORG_ID, target)

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert db.calls == []
        assert _state(db) == before

    @pytest.mark.parametrize("action", _ALL)
    def test_platform_users_api_unknown_cookie_is_401(self, db: FakeDb, action: str) -> None:
        _route_of(action)
        target = _ready(db, action)
        before = _state(db)

        response = _call(_client(_app()), action, "not-a-session-token", ORG_ID, target)

        assert (response.status_code, response.json()) == (401, _UNAUTHORIZED)
        assert _state(db) == before

    @pytest.mark.parametrize("bad_id", _BAD_IDS)
    @pytest.mark.parametrize(("action", "slot"), _ID_SLOTS)
    def test_platform_users_api_non_uuid_id_is_422_without_echo(
        self, db: FakeDb, action: str, slot: str, bad_id: str
    ) -> None:
        """A path id that isn't a UUID → 422 without the input; nothing changes."""
        _route_of(action)
        _, token = _super_admin(db)
        target = _ready(db, action)
        before = _state(db)
        org_id, user_id = (bad_id, target) if slot == "org_id" else (ORG_ID, bad_id)

        response = _call(_client(_app()), action, token, org_id, user_id)

        _assert_no_echo(response, "ECHOMARK42", "x" * 20)
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 2. Authorization: a Super Admin only, through admino.access.can()
# ---------------------------------------------------------------------------


class TestAuthorization:
    """Org Admins, Editors and Viewers get 403 before any query; can() decides."""

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    @pytest.mark.parametrize("action", _ALL)
    def test_platform_users_api_member_is_forbidden_before_any_query(
        self, db: FakeDb, action: str, role: str
    ) -> None:
        """403 {"detail": "Forbidden"}, even on the member's own org: only the session
        lookup ran, nothing changed, nothing was audited."""
        _route_of(action)
        target = _ready(db, action)
        token = db.open_session(_user(db, role=role))
        before = _state(db)

        response = _call(_client(_app()), action, token, ORG_ID, target)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _only_session_lookups(db.calls)
        assert _state(db) == before
        assert db.audit == []

    @pytest.mark.parametrize("action", _ALL)
    def test_platform_users_api_route_asks_can_for_its_capability(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """The reads ask for platform.org_metadata.view, the four actions for
        platform.users.manage; a Super Admin succeeds."""
        target = _ready(db, action)
        _, token = _super_admin(db)
        spy = _CanSpy(monkeypatch)

        response = _call(_client(_app()), action, token, ORG_ID, target)

        assert response.status_code == _SUCCESS[action], response.text
        assert Capability(_CAPABILITY[action]) in spy.capabilities

    @pytest.mark.parametrize("action", _ALL)
    def test_platform_users_api_capability_refused_by_can_is_403(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """When can() refuses the route's capability even a Super Admin gets 403."""
        _route_of(action)
        target = _ready(db, action)
        _, token = _super_admin(db)
        _CanSpy(monkeypatch, deny=frozenset({_CAPABILITY[action]}))
        before = _state(db)

        response = _call(_client(_app()), action, token, ORG_ID, target)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 3. GET /api/platform/orgs/{org_id}/users
# ---------------------------------------------------------------------------


class TestUsersList:
    """Every non-deleted account of the org, invited ones included, oldest first."""

    def test_platform_users_api_list_returns_every_account_in_order(self, db: FakeDb) -> None:
        """Active, deactivated and invited accounts of ORG_ID by (created_at, id); another
        org's user, a deleted user and the Super Admin aren't listed."""
        _, token = _super_admin(db)
        base = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
        tie = base + timedelta(days=1)
        listed = [
            _admin(db, created_at=base + timedelta(days=3), last_login_at=base + timedelta(days=4)),
            _user(db, role="viewer", status="deactivated", created_at=tie, email=_TARGET_EMAIL),
            _user(db, created_at=tie, name=_TARGET_NAME),
            _user(db, created_at=tie),
            _invited_admin(db, created_at=base, email=_INVITED_EMAIL)[0],
            _invited_admin(db, role="viewer", created_at=base + timedelta(days=5))[0],
        ]
        _user(db, OTHER_ORG_ID, created_at=base)
        _user(db, created_at=base, deleted_at=base + timedelta(days=2))
        _invited_admin(db, created_at=base, deleted_at=base + timedelta(days=2))

        response = _call(_client(_app()), "users", token)

        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {"users"}
        expected = sorted(listed, key=lambda user_id: (db.users[user_id]["created_at"], user_id))
        assert [entry["id"] for entry in body["users"]] == [str(user_id) for user_id in expected]
        for entry, user_id in zip(body["users"], expected, strict=True):
            _assert_user_entry(entry, db.users[user_id])

    def test_platform_users_api_list_shows_invited_accounts_without_a_name(
        self, db: FakeDb
    ) -> None:
        """An invited Org Admin is listed with status "invited" and name null."""
        _, token = _super_admin(db)
        invited, _ = _invited_admin(db, email=_INVITED_EMAIL)

        response = _call(_client(_app()), "users", token)

        assert response.status_code == 200, response.text
        (entry,) = response.json()["users"]
        assert (entry["id"], entry["status"], entry["role"]) == (
            str(invited),
            "invited",
            "org_admin",
        )
        assert (entry["name"], entry["email"]) == (None, _INVITED_EMAIL)

    def test_platform_users_api_list_of_an_org_without_users_is_empty(self, db: FakeDb) -> None:
        _, token = _super_admin(db)
        db.add_org(OTHER_ORG_ID)
        _user(db)

        response = _call(_client(_app()), "users", token, OTHER_ORG_ID)

        assert (response.status_code, response.json()) == (200, {"users": []})

    @pytest.mark.parametrize("status", _ORG_STATUSES)
    def test_platform_users_api_list_in_any_org_status(self, db: FakeDb, status: str) -> None:
        _, token = _super_admin(db)
        user_id = _user(db)
        db.add_org(ORG_ID, status=status)

        response = _call(_client(_app()), "users", token)

        assert response.status_code == 200, response.text
        assert [entry["id"] for entry in response.json()["users"]] == [str(user_id)]


# ---------------------------------------------------------------------------
# 4. GET /api/platform/orgs/{org_id}/metadata
# ---------------------------------------------------------------------------


class TestMetadata:
    """Counts and sizes only: seats used and limit, storage, chats (GH-176) and files."""

    def test_platform_users_api_metadata_counts_active_and_invited_seats(self, db: FakeDb) -> None:
        """used = active + invited (an expired invitation included); deactivated, deleted
        and other orgs' users don't count; limit = the org's seats; no chats are stored,
        so the rest are 0."""
        _, token = _super_admin(db)
        _admin(db)
        _user(db)
        _invited_admin(db, role="editor")
        _invited_admin(db, role="viewer", sent_ago=timedelta(hours=100))
        _user(db, status="deactivated")
        _user(db, deleted_at=datetime.now(UTC) - timedelta(days=1))
        _invited_admin(db, deleted_at=datetime.now(UTC) - timedelta(days=1))
        _user(db, OTHER_ORG_ID)
        db.add_org(ORG_ID, seats=7)

        response = _call(_client(_app()), "metadata", token)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body == {
            "seats": {"used": 4, "limit": 7},
            "storage_used_bytes": 0,
            "chat_count": 0,
            "file_count": 0,
        }
        values = [*body["seats"].values(), *(body[key] for key in _METADATA_KEYS - {"seats"})]
        assert all(type(value) is int for value in values)

    def test_platform_users_api_metadata_counts_the_orgs_live_chats(self, db: FakeDb) -> None:
        """GH-176: chat_count = the org's chats that aren't trashed (every member's); another
        org's chats count for that org only; no response carries a chat title."""
        _, token = _super_admin(db)
        admin, editor, other = _admin(db), _user(db), _admin(db, OTHER_ORG_ID)
        for owner in (admin, admin, editor):
            db.add_chat(owner, title=_CHAT_TITLE)
        db.add_chat(editor, title=_CHAT_TITLE, deleted_at=datetime.now(UTC) - timedelta(days=1))
        for _ in range(2):
            db.add_chat(other, title=_CHAT_TITLE)
        client = _client(_app())

        response = _call(client, "metadata", token)
        other_response = _call(client, "metadata", token, OTHER_ORG_ID)

        assert (response.status_code, other_response.status_code) == (200, 200), response.text
        assert (response.json()["chat_count"], other_response.json()["chat_count"]) == (3, 2)
        assert set(response.json()) == _METADATA_KEYS
        assert _CHAT_TITLE not in response.text + other_response.text

    def test_platform_users_api_metadata_used_may_exceed_the_limit(self, db: FakeDb) -> None:
        _, token = _super_admin(db)
        for _ in range(3):
            _user(db)
        db.add_org(ORG_ID, seats=1)

        response = _call(_client(_app()), "metadata", token)

        assert response.status_code == 200, response.text
        assert response.json()["seats"] == {"used": 3, "limit": 1}

    def test_platform_users_api_metadata_of_an_org_without_users(self, db: FakeDb) -> None:
        _, token = _super_admin(db)
        db.add_org(OTHER_ORG_ID, seats=12)

        response = _call(_client(_app()), "metadata", token, OTHER_ORG_ID)

        assert response.status_code == 200, response.text
        assert set(response.json()) == _METADATA_KEYS
        assert response.json()["seats"] == {"used": 0, "limit": 12}

    @pytest.mark.parametrize("status", _ORG_STATUSES)
    def test_platform_users_api_metadata_in_any_org_status(self, db: FakeDb, status: str) -> None:
        _, token = _super_admin(db)
        _user(db)
        db.add_org(ORG_ID, status=status)

        response = _call(_client(_app()), "metadata", token)

        assert response.status_code == 200, response.text
        assert response.json()["seats"]["used"] == 1


class TestReadsWriteNothing:
    """The users list and the metadata are reads: nothing written or audited."""

    @pytest.mark.parametrize("action", _READS)
    def test_platform_users_api_read_writes_and_audits_nothing(
        self, db: FakeDb, action: str
    ) -> None:
        _, token = _super_admin(db)
        _ready(db, "users")
        _invited_admin(db)
        before = _state(db)

        response = _call(_client(_app()), action, token)

        assert response.status_code == 200, response.text
        assert _state(db) == before
        assert db.audit == []
        writes = db.matching(r"^(?:insert into|update|delete from) ")
        assert [call for call in writes if not _only_session_lookups([call])] == []


# ---------------------------------------------------------------------------
# 5. POST .../users/{user_id}/deactivate
# ---------------------------------------------------------------------------


class TestDeactivate:
    """A Super Admin deactivates an active user of any org."""

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_platform_users_api_deactivate_returns_the_summary(self, db: FakeDb, role: str) -> None:
        """200 with exactly the summary keys, status "deactivated"; the row is deactivated.
        An Org Admin can be deactivated while another active one remains."""
        _, token = _super_admin(db)
        _admin(db)
        target = _user(db, role=role, email=_TARGET_EMAIL, name=_TARGET_NAME)

        response = _call(_client(_app()), "deactivate", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        body = response.json()
        assert db.users[target]["status"] == "deactivated"
        _assert_user_entry(body, db.users[target])
        assert (body["status"], body["role"], body["email"]) == ("deactivated", role, _TARGET_EMAIL)

    def test_platform_users_api_deactivate_ends_the_users_sessions_at_once(
        self, db: FakeDb
    ) -> None:
        """The target's cookie works before and is 401 on its very next request; every
        session of the target is gone; the Super Admin's, the admin's and a bystander's
        stay, and the Super Admin's cookie isn't touched."""
        _, token = _super_admin(db)
        admin_token = db.open_session(_admin(db))
        target = _user(db)
        target_token = db.open_session(target)
        other_device = db.open_session(target)
        bystander_token = db.open_session(_user(db))
        client = _client(_app())
        assert _me(client, target_token).status_code == 200

        response = _call(client, "deactivate", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        assert _me(client, target_token).status_code == 401
        assert db.sessions_of(target) == []
        assert db.session_revoked(other_device)
        assert not any(db.session_revoked(t) for t in (token, admin_token, bystander_token))
        assert _session_cookie_headers(response) == []

    def test_platform_users_api_deactivate_is_audited(self, db: FakeDb) -> None:
        """One user.deactivate row: actor_kind super_admin, the Super Admin's id, the
        affected org, target the user, the client IP, {"sessions_revoked": 2}."""
        sa, token = _super_admin(db)
        _admin(db)
        target = _user(db)
        db.open_session(target)
        db.open_session(target)

        response = _call(_client(_app(), ip=_IP_B), "deactivate", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        _assert_event(
            _one(db.audit),
            action="user.deactivate",
            actor=sa,
            target_type="user",
            target_ids=[target],
            metadata={"sessions_revoked": 2},
        )

    def test_platform_users_api_deactivate_queues_the_status_email(self, db: FakeDb) -> None:
        """One account_deactivated email to the user, carrying only the org name."""
        _, token = _super_admin(db)
        _admin(db)
        target = _user(db)

        response = _call(_client(_app()), "deactivate", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        email = _one(_emails_of(db, target, "account_deactivated"))
        assert email["params"] == {"org_name": ORG_NAME}
        assert len(db.outbox) == 1

    def test_platform_users_api_deactivate_keeps_connections_and_memory(self, db: FakeDb) -> None:
        _, token = _super_admin(db)
        _admin(db)
        target = _user(db)
        db.add_oauth_token(target, "google", encrypted_refresh_token="enc-google-refresh")
        db.add_memory(target, "project", "annual report")
        db.add_user_settings(target, theme="dark")

        response = _call(_client(_app()), "deactivate", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        assert db.oauth_token(target, "google") is not None
        assert db.memories_of(target) == {"project": "annual report"}
        assert target in db.user_settings

    @pytest.mark.parametrize("other_admin", [None, "deactivated", "invited", "other-org"])
    def test_platform_users_api_deactivate_last_active_admin_is_409(
        self, db: FakeDb, other_admin: str | None
    ) -> None:
        """The org's only active Org Admin → 409 last_admin (a deactivated or invited
        admin, or another org's admin, doesn't count); their sessions stay and nothing
        changes."""
        _route_of("deactivate")
        _, token = _super_admin(db)
        target = _admin(db)
        target_token = db.open_session(target)
        if other_admin == "other-org":
            _admin(db, OTHER_ORG_ID)
        elif other_admin == "invited":
            _invited_admin(db)
        elif other_admin == "deactivated":
            _admin(db, status="deactivated")
        before = _state(db)
        client = _client(_app())

        response = _call(client, "deactivate", token, ORG_ID, target)

        assert (response.status_code, response.json()) == (409, _LAST_ADMIN)
        assert _state(db) == before
        assert _me(client, target_token).status_code == 200


# ---------------------------------------------------------------------------
# 6. POST .../users/{user_id}/reactivate
# ---------------------------------------------------------------------------


class TestReactivate:
    """A Super Admin reactivates a deactivated user if the org has a free seat."""

    def test_platform_users_api_reactivate_returns_the_summary(self, db: FakeDb) -> None:
        _, token = _super_admin(db)
        _admin(db)
        target = _user(db, status="deactivated", email=_TARGET_EMAIL, name=_TARGET_NAME)

        response = _call(_client(_app()), "reactivate", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        assert db.users[target]["status"] == "active"
        _assert_user_entry(response.json(), db.users[target])
        assert response.json()["status"] == "active"

    def test_platform_users_api_reactivate_is_audited(self, db: FakeDb) -> None:
        """One user.activate row: the Super Admin, the org, target the user, the IP."""
        sa, token = _super_admin(db)
        _admin(db)
        target = _user(db, status="deactivated")

        response = _call(_client(_app(), ip=_IP_B), "reactivate", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        _assert_event(
            _one(db.audit),
            action="user.activate",
            actor=sa,
            target_type="user",
            target_ids=[target],
        )

    def test_platform_users_api_reactivate_queues_the_status_email(self, db: FakeDb) -> None:
        """One account_activated email: the org name and the login link
        <public_url>/login."""
        _, token = _super_admin(db)
        _admin(db)
        target = _user(db, status="deactivated")

        response = _call(_client(_app()), "reactivate", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        email = _one(_emails_of(db, target, "account_activated"))
        assert email["params"] == {"org_name": ORG_NAME, "login_link": _PUBLIC_URL + "/login"}
        assert len(db.outbox) == 1

    def test_platform_users_api_reactivate_in_a_full_org_is_409(self, db: FakeDb) -> None:
        """Active + invited users fill every seat (2 of 2) → 409 seat_limit; nothing
        changes."""
        _route_of("reactivate")
        _, token = _super_admin(db)
        _admin(db)
        _invited_admin(db, role="editor")
        target = _user(db, status="deactivated")
        db.add_org(ORG_ID, seats=2)
        before = _state(db)

        response = _call(_client(_app()), "reactivate", token, ORG_ID, target)

        assert (response.status_code, response.json()) == (409, _SEAT_LIMIT)
        assert _state(db) == before

    def test_platform_users_api_reactivate_with_a_free_seat_succeeds(self, db: FakeDb) -> None:
        """1 active + 1 invited of 3 seats; deactivated, deleted and other orgs' users
        don't count."""
        _, token = _super_admin(db)
        _admin(db)
        _invited_admin(db, role="editor")
        _user(db, status="deactivated")
        _user(db, deleted_at=datetime.now(UTC) - timedelta(days=1))
        _user(db, OTHER_ORG_ID)
        target = _user(db, status="deactivated")
        db.add_org(ORG_ID, seats=3)

        response = _call(_client(_app()), "reactivate", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        assert db.users[target]["status"] == "active"


# ---------------------------------------------------------------------------
# 7. POST .../users/{user_id}/password-reset
# ---------------------------------------------------------------------------


class TestPasswordReset:
    """GH-151's reset email, triggered by the Super Admin; the token never reaches them."""

    def test_platform_users_api_password_reset_is_202_and_queues_the_link(self, db: FakeDb) -> None:
        """202 with an empty body; one password_reset email whose link is
        <public_url>/reset-password#token=<43 chars>; only the token's hash is stored."""
        _, token = _super_admin(db)
        _admin(db)
        target = _user(db, email=_TARGET_EMAIL)

        response = _call(_client(_app()), "password_reset", token, ORG_ID, target)

        assert response.status_code == 202, response.text
        assert response.content == b""
        email = _one(_emails_of(db, target, "password_reset"))
        link = email["params"]["reset_link"]
        assert link.startswith(LINK_PREFIX)
        reset_token = link[len(LINK_PREFIX) :]
        assert TOKEN_RE.fullmatch(reset_token)
        assert db.tokens[target]["token_hash"] == sha256(reset_token)
        assert reset_token not in str(response.headers)

    def test_platform_users_api_password_reset_newer_link_replaces_the_older(
        self, db: FakeDb
    ) -> None:
        _, token = _super_admin(db)
        _admin(db)
        target = _user(db)
        client = _client(_app())

        first = _call(client, "password_reset", token, ORG_ID, target)
        second = _call(client, "password_reset", token, ORG_ID, target)

        assert (first.status_code, second.status_code) == (202, 202)
        assert db.tokens[target]["token_hash"] == sha256(db.issued_token(-1))
        assert db.tokens[target]["token_hash"] != sha256(db.issued_token(0))

    def test_platform_users_api_password_reset_is_audited(self, db: FakeDb) -> None:
        """One password_reset.request row with the Super Admin as actor, the org, target
        the user, {"email_sent": true} and the client IP."""
        sa, token = _super_admin(db)
        _admin(db)
        target = _user(db)

        response = _call(_client(_app(), ip=_IP_B), "password_reset", token, ORG_ID, target)

        assert response.status_code == 202, response.text
        _assert_event(
            _one(db.audit),
            action="password_reset.request",
            actor=sa,
            target_type="user",
            target_ids=[target],
            metadata={"email_sent": True},
        )


# ---------------------------------------------------------------------------
# 8. POST .../users/{user_id}/invitation
# ---------------------------------------------------------------------------

_RESEND_BODIES = [
    pytest.param(_UNSET, id="no-body"),
    pytest.param({}, id="empty-object"),
    pytest.param({"email": None}, id="email-null"),
]
_REINVITE_BODIES = [
    pytest.param(_UNSET, id="resend"),
    pytest.param({"email": _NEW_EMAIL}, id="replace"),
]
_BAD_REINVITE_BODIES = [
    pytest.param({"email": "ECHOMARK42.example.ch"}, id="no-at"),
    pytest.param({"email": "ECHOMARK42@a@example.ch"}, id="two-ats"),
    pytest.param({"email": "@ECHOMARK42.example.ch"}, id="no-local-part"),
    pytest.param({"email": "ECHOMARK42@examplech"}, id="no-dot-in-domain"),
    pytest.param({"email": "ECHOMARK42 x@example.ch"}, id="inner-space"),
    pytest.param({"email": "ECHOMARK42" + chr(0) + "@example.ch"}, id="nul"),
    pytest.param({"email": "ECHOMARK42" + chr(0x200B) + "@example.ch"}, id="zero-width"),
    pytest.param({"email": "ECHOMARK42" + chr(0x202E) + "@example.ch"}, id="rtl-override"),
    pytest.param({"email": "ECHOMARK42" + chr(0x2028) + "@example.ch"}, id="line-separator"),
    pytest.param({"email": "ECHOMARK42" + "a" * 234 + "@example.ch"}, id="255-chars"),
    pytest.param({"email": ""}, id="empty"),
    pytest.param({"email": "   "}, id="blank"),
    pytest.param({"email": 4242424242}, id="int"),
    pytest.param({"email": True}, id="bool"),
    pytest.param({"email": ["ECHOMARK42@example.ch"]}, id="list"),
    pytest.param({"role": "editor"}, id="extra-role"),
    pytest.param({"email": "fresh.ECHOMARK42@example.ch", "language": "fr"}, id="extra-language"),
    pytest.param({"user_id": "ECHOMARK42"}, id="extra-user-id"),
    pytest.param({"password": "ECHOMARK42-secret"}, id="extra-password"),
    pytest.param([], id="list-body"),
    pytest.param("ECHOMARK42", id="string-body"),
]


class TestReinviteResend:
    """No email: the invited Org Admin's invitation is sent again with a new link."""

    @pytest.mark.parametrize("body", _RESEND_BODIES)
    def test_platform_users_api_resend_rotates_the_invitation(self, db: FakeDb, body: Any) -> None:
        """200 with the InvitationSummary (same id, new dates, not expired); the same
        invited account; the old link is dead and the new one works; the still-queued old
        email is cancelled; the response holds neither token nor link."""
        _, token = _super_admin(db)
        target, old = _invited_admin(db, email=_INVITED_EMAIL)
        old_token = _invited_token(target, old)
        invitation_id = _age_invitation(db, target, timedelta(hours=10))
        client = _client(_app())

        response = _call(client, "invitation", token, ORG_ID, target, body=body)

        assert response.status_code == 200, response.text
        summary = response.json()
        assert set(summary) == _INVITATION_KEYS
        row = db.invitations[invitation_id]
        assert (summary["id"], summary["email"], summary["role"], summary["expired"]) == (
            str(invitation_id),
            _INVITED_EMAIL,
            "org_admin",
            False,
        )
        assert _dt(summary["sent_at"]) == row["sent_at"]
        assert _dt(summary["expires_at"]) == row["expires_at"]
        assert row["sent_at"] > datetime.now(UTC) - timedelta(minutes=5)
        assert (db.users[target]["status"], db.users[target]["email"]) == (
            "invited",
            _INVITED_EMAIL,
        )
        new_token = db.invitation_token(target)
        assert new_token != old_token
        assert row["token_hash"] == sha256(new_token)
        assert _details(client, old_token).status_code == 404
        assert _details(client, new_token).status_code == 200
        emails = db.invitation_emails(target)
        assert [(email["status"], email["params"]) for email in emails[:-1]] == [("failed", {})]
        assert emails[-1]["status"] == "pending"
        assert emails[-1]["params"]["accept_link"] == INVITE_LINK_PREFIX + new_token
        for secret in (old_token, new_token, "accept-invitation", "#token="):
            assert secret not in response.text

    def test_platform_users_api_resend_is_audited(self, db: FakeDb) -> None:
        """One invitation.resend row: the Super Admin, the org, target the invitation,
        {"role": "org_admin", "user_id": <invited user>} and the client IP."""
        sa, token = _super_admin(db)
        target, _ = _invited_admin(db)
        invitation_id = _age_invitation(db, target, timedelta(0))

        response = _call(_client(_app(), ip=_IP_B), "invitation", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        _assert_event(
            _one(db.audit),
            action="invitation.resend",
            actor=sa,
            target_type="invitation",
            target_ids=[invitation_id],
            metadata={"role": "org_admin", "user_id": str(target)},
        )

    def test_platform_users_api_resend_of_an_expired_invitation(self, db: FakeDb) -> None:
        """An invitation past its 72 hours is sent again: expired false, a new expiry about
        72 hours away, a working link."""
        _, token = _super_admin(db)
        target, _ = _invited_admin(db, sent_ago=timedelta(hours=100))
        client = _client(_app())

        response = _call(client, "invitation", token, ORG_ID, target)

        assert response.status_code == 200, response.text
        assert response.json()["expired"] is False
        expires_at = _dt(response.json()["expires_at"])
        assert expires_at is not None
        assert expires_at > datetime.now(UTC) + timedelta(hours=71)
        assert _details(client, db.invitation_token(target)).status_code == 200

    def test_platform_users_api_resend_needs_no_free_seat(self, db: FakeDb) -> None:
        """The invitation already holds its seat: an org over its seats can resend."""
        _, token = _super_admin(db)
        target, _ = _invited_admin(db)
        _user(db)
        _user(db)
        db.add_org(ORG_ID, seats=1)

        response = _call(_client(_app()), "invitation", token, ORG_ID, target)

        assert response.status_code == 200, response.text

    @pytest.mark.parametrize("other", ["deactivated-admin", "other-org-admin", "invited-admin"])
    def test_platform_users_api_resend_ignores_admins_that_arent_active_here(
        self, db: FakeDb, other: str
    ) -> None:
        """A deactivated Org Admin, another org's active Org Admin or a second invited one
        isn't an active Org Admin of this org."""
        _, token = _super_admin(db)
        target, _ = _invited_admin(db)
        if other == "deactivated-admin":
            _admin(db, status="deactivated")
        elif other == "other-org-admin":
            _admin(db, OTHER_ORG_ID)
        else:
            _invited_admin(db)

        response = _call(_client(_app()), "invitation", token, ORG_ID, target)

        assert response.status_code == 200, response.text


class TestReinviteReplace:
    """An email: the invited account is replaced by a new invited Org Admin."""

    def test_platform_users_api_replace_invites_the_new_email(self, db: FakeDb) -> None:
        """200 with the new InvitationSummary (new id, the stripped email with its
        capitalization, org_admin, not expired); the old account, invitation, queued email
        and link are gone; the new invited account has the Super Admin's session language
        and its invitation email is queued in it; no token or link in the response."""
        _, token = _super_admin(db, ui_language="fr")
        target, old = _invited_admin(db, email=_INVITED_EMAIL)
        old_token = _invited_token(target, old)
        old_invitation = _age_invitation(db, target, timedelta(0))
        client = _client(_app())

        response = _call(
            client, "invitation", token, ORG_ID, target, body={"email": "  " + _NEW_EMAIL + " "}
        )

        assert response.status_code == 200, response.text
        summary = response.json()
        assert set(summary) == _INVITATION_KEYS
        new_id = _new_user_id(db, _NEW_EMAIL)
        new_row = db.users[new_id]
        invitation = db.invitation_of(new_id)
        assert invitation is not None
        assert summary["id"] == str(plain(invitation["id"]))
        assert summary["id"] != str(old_invitation)
        assert (summary["email"], summary["role"], summary["expired"]) == (
            _NEW_EMAIL,
            "org_admin",
            False,
        )
        assert new_id != target
        assert (new_row["email"], plain(new_row["org_id"])) == (_NEW_EMAIL, ORG_ID)
        assert (new_row["role"], new_row["status"], new_row["ui_language"]) == (
            "org_admin",
            "invited",
            "fr",
        )
        assert target not in db.users
        assert old_invitation not in db.invitations
        assert [row for row in db.outbox if str(row["user_id"]) == str(target)] == []
        assert _details(client, old_token).status_code == 404
        email = _one(db.invitation_emails(new_id))
        assert email["language"] == "fr"
        new_token = db.invitation_token(new_id)
        details = _details(client, new_token)
        assert details.status_code == 200
        assert details.json()["email"] == _NEW_EMAIL
        for secret in (old_token, new_token, "accept-invitation", "#token="):
            assert secret not in response.text

    def test_platform_users_api_replace_is_audited(self, db: FakeDb) -> None:
        """invitation.revoke (target the old invitation, {"user_id": <old user>}) and
        invitation.create (target the new one, {"role": "org_admin", "user_id": <new
        user>}), both by the Super Admin in the org's log with the client IP."""
        sa, token = _super_admin(db)
        target, _ = _invited_admin(db)
        old_invitation = _age_invitation(db, target, timedelta(0))

        response = _call(
            _client(_app(), ip=_IP_B),
            "invitation",
            token,
            ORG_ID,
            target,
            body={"email": _NEW_EMAIL},
        )

        assert response.status_code == 200, response.text
        new_id = _new_user_id(db, _NEW_EMAIL)
        new_invitation = _age_invitation(db, new_id, timedelta(0))
        assert sorted(row["action"] for row in db.audit) == [
            "invitation.create",
            "invitation.revoke",
        ]
        _assert_event(
            _one(db.audit_rows("invitation.revoke")),
            action="invitation.revoke",
            actor=sa,
            target_type="invitation",
            target_ids=[old_invitation],
            metadata={"user_id": str(target)},
        )
        _assert_event(
            _one(db.audit_rows("invitation.create")),
            action="invitation.create",
            actor=sa,
            target_type="invitation",
            target_ids=[new_invitation],
            metadata={"role": "org_admin", "user_id": str(new_id)},
        )

    def test_platform_users_api_replace_with_the_same_address_makes_a_new_account(
        self, db: FakeDb
    ) -> None:
        """The same address in other capitals: a new account and a new invitation id."""
        _, token = _super_admin(db)
        target, _ = _invited_admin(db, email=_INVITED_EMAIL)
        old_invitation = _age_invitation(db, target, timedelta(0))

        response = _call(
            _client(_app()),
            "invitation",
            token,
            ORG_ID,
            target,
            body={"email": _INVITED_EMAIL.upper()},
        )

        assert response.status_code == 200, response.text
        new_id = _new_user_id(db, _INVITED_EMAIL)
        assert new_id != target
        assert target not in db.users
        assert db.users[new_id]["email"] == _INVITED_EMAIL.upper()
        assert response.json()["email"] == _INVITED_EMAIL.upper()
        assert response.json()["id"] != str(old_invitation)

    @pytest.mark.parametrize(
        "holder", ["other-org-user", "super-admin", "same-org-deactivated", "other-org-invited"]
    )
    def test_platform_users_api_replace_with_a_taken_email_is_409(
        self, db: FakeDb, holder: str
    ) -> None:
        """An email held anywhere on the platform (any capitalization) → 409 email_taken;
        the old account, invitation and link stay; only invitation.refuse is recorded:
        the Super Admin, the org, {"role": "org_admin", "email_taken": true}, the IP."""
        _route_of("invitation")
        sa, token = _super_admin(db)
        target, old = _invited_admin(db, email=_INVITED_EMAIL)
        old_token = _invited_token(target, old)
        taken = "Taken.Person@Example.ch"
        if holder == "other-org-user":
            _user(db, OTHER_ORG_ID, email=taken)
        elif holder == "super-admin":
            db.add_account(kind="super_admin", role=None, email=taken)
        elif holder == "same-org-deactivated":
            _user(db, status="deactivated", email=taken)
        else:
            _invited_admin(db, OTHER_ORG_ID, email=taken)
        before = _state(db)
        client = _client(_app(), ip=_IP_B)

        response = _call(client, "invitation", token, ORG_ID, target, body={"email": taken.upper()})

        assert (response.status_code, response.json()) == (409, _EMAIL_TAKEN)
        after = _state(db)
        refusal = _one(after.pop("audit"))
        before.pop("audit")
        assert after == before
        _assert_event(
            refusal,
            action="invitation.refuse",
            actor=sa,
            metadata={"role": "org_admin", "email_taken": True},
        )
        assert _details(client, old_token).status_code == 200

    def test_platform_users_api_replace_without_a_free_seat_is_409(self, db: FakeDb) -> None:
        """An org over its seats even after the old seat is freed → 409 seat_limit; the old
        invitation stays; only invitation.refuse ({"seat_limit": true}) is recorded."""
        _route_of("invitation")
        sa, token = _super_admin(db)
        target, old = _invited_admin(db)
        old_token = _invited_token(target, old)
        _user(db)
        db.add_org(ORG_ID, seats=1)
        before = _state(db)
        client = _client(_app(), ip=_IP_B)

        response = _call(client, "invitation", token, ORG_ID, target, body={"email": _NEW_EMAIL})

        assert (response.status_code, response.json()) == (409, _SEAT_LIMIT)
        after = _state(db)
        refusal = _one(after.pop("audit"))
        before.pop("audit")
        assert after == before
        _assert_event(
            refusal,
            action="invitation.refuse",
            actor=sa,
            metadata={"role": "org_admin", "seat_limit": True},
        )
        assert db.user_by_email(_NEW_EMAIL) is None
        assert _details(client, old_token).status_code == 200

    @pytest.mark.parametrize("body", _BAD_REINVITE_BODIES)
    def test_platform_users_api_reinvite_bad_body_is_422_without_echo(
        self, db: FakeDb, body: Any
    ) -> None:
        """An invalid email, an unknown field or a non-object body → 422 that never repeats
        the input; nothing changes."""
        _route_of("invitation")
        _, token = _super_admin(db)
        target, _ = _invited_admin(db)
        before = _state(db)

        response = _call(_client(_app()), "invitation", token, ORG_ID, target, body=body)

        _assert_no_echo(response, "ECHOMARK42", "a" * 20, "4242424242")
        assert _state(db) == before


class TestReinviteRefusals:
    """Only while the org has no active Org Admin, for an invited Org Admin's invitation."""

    def test_platform_users_api_has_active_admin_message_is_the_services(self) -> None:
        from admino import platform_users

        assert platform_users.HAS_ACTIVE_ADMIN_MESSAGE == _HAS_ACTIVE_ADMIN_MESSAGE

    @pytest.mark.parametrize("body", _REINVITE_BODIES)
    def test_platform_users_api_reinvite_with_an_active_org_admin_is_409(
        self, db: FakeDb, body: Any
    ) -> None:
        """The org has an active Org Admin → 409 has_active_admin; nothing changes and the
        old link keeps working."""
        _route_of("invitation")
        _, token = _super_admin(db)
        target, old = _invited_admin(db)
        old_token = _invited_token(target, old)
        _admin(db)
        before = _state(db)
        client = _client(_app())

        response = _call(client, "invitation", token, ORG_ID, target, body=body)

        assert (response.status_code, response.json()) == (409, _HAS_ACTIVE_ADMIN)
        assert _state(db) == before
        assert _details(client, old_token).status_code == 200


# ---------------------------------------------------------------------------
# 9. Refusals shared by the routes
# ---------------------------------------------------------------------------

_INELIGIBLE = [
    pytest.param("deactivate", "deactivated", _UNSET, id="deactivate-deactivated"),
    pytest.param("deactivate", "invited", _UNSET, id="deactivate-invited"),
    pytest.param("reactivate", "active", _UNSET, id="reactivate-active"),
    pytest.param("reactivate", "invited", _UNSET, id="reactivate-invited"),
    pytest.param("password_reset", "deactivated", _UNSET, id="password-reset-deactivated"),
    pytest.param("password_reset", "invited", _UNSET, id="password-reset-invited"),
    *[
        pytest.param("invitation", kind, body, id=f"{flavour}-{kind}")
        for kind in (
            "invited-editor",
            "invited-viewer",
            "active-editor",
            "deactivated-admin",
            "invited-admin-without-invitation",
        )
        for flavour, body in (("resend", _UNSET), ("replace", {"email": _NEW_EMAIL}))
    ],
]
_ORG_STATUS_REFUSED = [
    pytest.param("reactivate", "pending_deletion", _UNSET, id="reactivate-pending-deletion"),
    pytest.param("password_reset", "deactivated", _UNSET, id="password-reset-deactivated"),
    pytest.param(
        "password_reset", "pending_deletion", _UNSET, id="password-reset-pending-deletion"
    ),
    *[
        pytest.param("invitation", status, body, id=f"{flavour}-{status}")
        for status in ("deactivated", "pending_deletion")
        for flavour, body in (("resend", _UNSET), ("replace", {"email": _NEW_EMAIL}))
    ],
]
_ORG_STATUS_ALLOWED = [
    *[
        pytest.param(action, status, id=f"{action}-{status}")
        for action in ("users", "metadata", "deactivate")
        for status in _ORG_STATUSES
    ],
    pytest.param("reactivate", "active", id="reactivate-active"),
    pytest.param("reactivate", "deactivated", id="reactivate-deactivated"),
    pytest.param("password_reset", "active", id="password-reset-active"),
    pytest.param("invitation", "active", id="invitation-active"),
]


def _ineligible(db: FakeDb, kind: str) -> uuid.UUID:
    """A user of ORG_ID whose status (or role) the action doesn't apply to."""
    if kind in {"invited", "invited-editor"}:
        return _invited_admin(db, role="editor")[0]
    if kind == "invited-viewer":
        return _invited_admin(db, role="viewer")[0]
    if kind == "invited-admin-without-invitation":
        return _invited_admin(db, invitation=False)[0]
    if kind == "deactivated-admin":
        return _admin(db, status="deactivated")
    if kind in {"active", "active-editor"}:
        return _user(db)
    assert kind == "deactivated", kind
    return _user(db, status="deactivated")


class TestRefusals:
    """404 and 409 bodies; nothing changes on a refusal."""

    @pytest.mark.parametrize("action", _ALL)
    def test_platform_users_api_unknown_org_is_404(self, db: FakeDb, action: str) -> None:
        """An unknown org (even with a real user id of another org) → 404."""
        _route_of(action)
        _, token = _super_admin(db)
        target = _ready(db, action)
        before = _state(db)

        response = _call(_client(_app()), action, token, _UNKNOWN_ORG, target)

        assert (response.status_code, response.json()) == (404, _ORG_NOT_FOUND)
        assert _state(db) == before

    @pytest.mark.parametrize("case", _OUTSIDER_CASES)
    @pytest.mark.parametrize("action", _USER_ACTIONS)
    def test_platform_users_api_user_outside_the_org_is_404(
        self, db: FakeDb, action: str, case: str
    ) -> None:
        """Another org's user under this org's path, an unknown id, a deleted user, a Super
        Admin or the caller → 404 {"detail": "User not found"}; nothing changes."""
        _route_of(action)
        caller, token = _super_admin(db)
        _path_org(db, action)
        target = _outsider(db, case, action, caller)
        before = _state(db)

        response = _call(_client(_app()), action, token, ORG_ID, target)

        assert (response.status_code, response.json()) == (404, _USER_NOT_FOUND)
        assert _state(db) == before

    @pytest.mark.parametrize("action", _USER_ACTIONS)
    def test_platform_users_api_404_bodies_are_identical(self, db: FakeDb, action: str) -> None:
        """Another org's user answers the same bytes as an unknown id (and the others)."""
        caller, token = _super_admin(db)
        _path_org(db, action)
        client = _client(_app())
        targets = [_outsider(db, case, action, caller) for case in _OUTSIDER_CASES]

        responses = [_call(client, action, token, ORG_ID, target) for target in targets]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize(("action", "kind", "body"), _INELIGIBLE)
    def test_platform_users_api_user_status_refusal_is_409(
        self, db: FakeDb, action: str, kind: str, body: Any
    ) -> None:
        """The user's status (or, for the re-invite, not an invited Org Admin with a pending
        invitation) doesn't allow it → 409 invalid_status; nothing changes."""
        _route_of(action)
        _, token = _super_admin(db)
        _path_org(db, action)
        target = _ineligible(db, kind)
        before = _state(db)

        response = _call(_client(_app()), action, token, ORG_ID, target, body=body)

        assert (response.status_code, response.json()) == (409, _USER_INVALID_STATUS)
        assert _state(db) == before

    @pytest.mark.parametrize(("action", "status", "body"), _ORG_STATUS_REFUSED)
    def test_platform_users_api_org_status_refusal_is_409(
        self, db: FakeDb, action: str, status: str, body: Any
    ) -> None:
        """Reactivating in an org pending deletion, a reset or a re-invite in an org that
        isn't active → 409 with the org's invalid_status body; nothing changes."""
        _route_of(action)
        _, token = _super_admin(db)
        target = _ready(db, action)
        db.add_org(ORG_ID, status=status)
        before = _state(db)

        response = _call(_client(_app()), action, token, ORG_ID, target, body=body)

        assert (response.status_code, response.json()) == (409, _ORG_INVALID_STATUS)
        assert _state(db) == before

    @pytest.mark.parametrize(("action", "status"), _ORG_STATUS_ALLOWED)
    def test_platform_users_api_works_in_the_org_status(
        self, db: FakeDb, action: str, status: str
    ) -> None:
        _, token = _super_admin(db)
        target = _ready(db, action)
        db.add_org(ORG_ID, status=status)

        response = _call(_client(_app()), action, token, ORG_ID, target)

        assert response.status_code == _SUCCESS[action], response.text


# ---------------------------------------------------------------------------
# 10. Rate limits (per Super Admin)
# ---------------------------------------------------------------------------


def _limited(monkeypatch: pytest.MonkeyPatch, key: str, burst: int = 1) -> None:
    """``burst`` requests per key, then nothing for a long time."""
    monkeypatch.setitem(server._RATE_LIMITS, key, (0.001, burst))


class TestRateLimits:
    """Each route spends its key's per-user bucket before any database work."""

    @pytest.mark.parametrize("action", _ALL)
    def test_platform_users_api_rate_limit_is_per_super_admin_and_before_the_database(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        """With a burst of 1: the second call is 429 {"detail": "Rate limit exceeded"} with
        only the session lookup run; another Super Admin is still served; the bucket is
        (key, "user:<id>")."""
        _route_of(action)
        app = _app()
        _limited(monkeypatch, _ROUTE_KEYS[action])
        first_admin, token_a = _super_admin(db)
        _, token_b = _super_admin(db)
        client = _client(app)
        target = uuid.uuid4()

        spent = _call(client, action, token_a, _UNKNOWN_ORG, target)
        calls_before = len(db.calls)
        limited = _call(client, action, token_a, _UNKNOWN_ORG, target)
        calls_during = db.calls[calls_before:]
        other = _call(client, action, token_b, _UNKNOWN_ORG, target)

        assert (spent.status_code, spent.json()) == (404, _ORG_NOT_FOUND)
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert _only_session_lookups(calls_during)
        assert (other.status_code, other.json()) == (404, _ORG_NOT_FOUND)
        assert (_ROUTE_KEYS[action], f"user:{first_admin}") in server._rate_buckets

    def test_platform_users_api_deactivate_and_reactivate_share_a_bucket(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A deactivation spends the reactivation's token; the throttled call changes
        nothing; another Super Admin can still reactivate."""
        app = _app()
        _limited(monkeypatch, _KEY_STATUS)
        _, token_a = _super_admin(db)
        _, token_b = _super_admin(db)
        _admin(db)
        target = _user(db)
        client = _client(app)

        deactivated = _call(client, "deactivate", token_a, ORG_ID, target)
        limited = _call(client, "reactivate", token_a, ORG_ID, target)
        status_after_limit = db.users[target]["status"]
        other = _call(client, "reactivate", token_b, ORG_ID, target)

        assert deactivated.status_code == 200, deactivated.text
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert status_after_limit == "deactivated"
        assert other.status_code == 200, other.text

    def test_platform_users_api_status_bucket_is_separate_from_the_others(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A spent status bucket doesn't throttle the reads, the reset or the re-invite."""
        app = _app()
        _limited(monkeypatch, _KEY_STATUS)
        _, token = _super_admin(db)
        _admin(db)
        target = _user(db)
        other_user = _user(db)
        invited, _ = _invited_admin(db, OTHER_ORG_ID)
        client = _client(app)
        assert _call(client, "deactivate", token, ORG_ID, target).status_code == 200
        assert _call(client, "reactivate", token, ORG_ID, target).status_code == 429

        statuses = [
            _call(client, "users", token).status_code,
            _call(client, "metadata", token).status_code,
            _call(client, "password_reset", token, ORG_ID, other_user).status_code,
            _call(client, "invitation", token, OTHER_ORG_ID, invited).status_code,
        ]

        assert statuses == [200, 200, 202, 200]


class TestRefusedEmailBudget:
    """A re-invite with an email spends and checks the caller's refused-email budget."""

    def test_platform_users_api_spent_refused_budget_is_429_before_the_database(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Budget 1: an email_taken refusal spends it; the next re-invite with a fresh
        email is 429 with only the session lookup run and nothing changed; the bucket is
        (server._INVITE_REFUSED_ROUTE, "user:<id>")."""
        app = _app()
        _limited(monkeypatch, _KEY_REFUSED)
        sa, token = _super_admin(db)
        target, _ = _invited_admin(db)
        (taken,) = _taken(db, 1)
        client = _client(app)

        refused = _call(client, "invitation", token, ORG_ID, target, body={"email": taken})
        calls_before = len(db.calls)
        before = _state(db)
        limited = _call(
            client, "invitation", token, ORG_ID, target, body={"email": "fresh.person@example.ch"}
        )
        calls_during = db.calls[calls_before:]

        assert (refused.status_code, refused.json()) == (409, _EMAIL_TAKEN)
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert _only_session_lookups(calls_during)
        assert _state(db) == before
        assert (_KEY_REFUSED, f"user:{sa}") in server._rate_buckets

    def test_platform_users_api_each_email_taken_refusal_spends_one_token(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Budget 2: two refusals → 409, 409; the third re-invite with an email → 429."""
        app = _app()
        _limited(monkeypatch, _KEY_REFUSED, burst=2)
        _, token = _super_admin(db)
        target, _ = _invited_admin(db)
        client = _client(app)

        statuses = [
            _call(client, "invitation", token, ORG_ID, target, body={"email": email}).status_code
            for email in [*_taken(db, 2), "fresh.person@example.ch"]
        ]

        assert statuses == [409, 409, 429]

    @pytest.mark.parametrize("body", _RESEND_BODIES)
    def test_platform_users_api_spent_refused_budget_still_allows_a_resend(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, body: Any
    ) -> None:
        """A re-invite without an email isn't an email probe: it still resends."""
        app = _app()
        _limited(monkeypatch, _KEY_REFUSED)
        _, token = _super_admin(db)
        target, _ = _invited_admin(db)
        (taken,) = _taken(db, 1)
        client = _client(app)
        assert (
            _call(client, "invitation", token, ORG_ID, target, body={"email": taken}).status_code
            == 409
        )

        response = _call(client, "invitation", token, ORG_ID, target, body=body)

        assert response.status_code == 200, response.text

    def test_platform_users_api_refused_budget_is_per_super_admin(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Another Super Admin keeps their own budget: their refusal is a 409."""
        app = _app()
        _limited(monkeypatch, _KEY_REFUSED)
        _, token_a = _super_admin(db)
        _, token_b = _super_admin(db)
        target, _ = _invited_admin(db)
        (taken,) = _taken(db, 1)
        client = _client(app)

        first = _call(client, "invitation", token_a, ORG_ID, target, body={"email": taken})
        limited = _call(client, "invitation", token_a, ORG_ID, target, body={"email": taken})
        other = _call(client, "invitation", token_b, ORG_ID, target, body={"email": taken})

        assert first.status_code == 409
        assert (limited.status_code, limited.json()) == (429, _RATE_LIMITED)
        assert (other.status_code, other.json()) == (409, _EMAIL_TAKEN)

    def test_platform_users_api_successful_replace_spends_no_refused_budget(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Budget 1: a successful replacement (200), then a refused one (409, not 429),
        then the next re-invite with an email is a 429."""
        app = _app()
        _limited(monkeypatch, _KEY_REFUSED)
        _, token = _super_admin(db)
        target, _ = _invited_admin(db)
        (taken,) = _taken(db, 1)
        client = _client(app)

        replaced = _call(client, "invitation", token, ORG_ID, target, body={"email": _NEW_EMAIL})
        new_id = _new_user_id(db, _NEW_EMAIL)
        refused = _call(client, "invitation", token, ORG_ID, new_id, body={"email": taken})
        limited = _call(
            client, "invitation", token, ORG_ID, new_id, body={"email": "fresh.person@example.ch"}
        )

        assert replaced.status_code == 200, replaced.text
        assert (refused.status_code, refused.json()) == (409, _EMAIL_TAKEN)
        assert limited.status_code == 429


# ---------------------------------------------------------------------------
# 11. CSRF, and fail closed on an audit failure
# ---------------------------------------------------------------------------

_AUDITED = [
    pytest.param("deactivate", _UNSET, id="deactivate"),
    pytest.param("reactivate", _UNSET, id="reactivate"),
    pytest.param("password_reset", _UNSET, id="password-reset"),
    pytest.param("invitation", _UNSET, id="resend"),
    pytest.param("invitation", {"email": _NEW_EMAIL}, id="replace"),
]


class TestCrossOriginAndFailClosed:
    """Cross-site POSTs never reach the handler; a failed audit write keeps nothing."""

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    @pytest.mark.parametrize(("action", "body"), _AUDITED)
    def test_platform_users_api_cross_origin_post_is_refused_before_the_handler(
        self, db: FakeDb, action: str, body: Any, headers: dict[str, str]
    ) -> None:
        """403 {"detail": "Cross-origin request refused"}; no database call at all."""
        _route_of(action)
        target = _ready(db, action)
        _, token = _super_admin(db)
        before = _state(db)

        response = _call(_client(_app()), action, token, ORG_ID, target, body=body, **headers)

        assert (response.status_code, response.json()) == (403, _CSRF_REFUSED)
        assert db.calls == []
        assert _state(db) == before

    @pytest.mark.parametrize(("action", "body"), _AUDITED)
    def test_platform_users_api_audit_failure_is_500_and_changes_nothing(
        self, db: FakeDb, action: str, body: Any
    ) -> None:
        """500; the audit insert was attempted; no status change, sessions intact, no
        token, no email, no new or deleted account."""
        _route_of(action)
        target = _ready(db, action)
        assert target is not None
        target_session = db.open_session(target)
        _, token = _super_admin(db)
        before = _state(db)
        db.fail_audit = True

        response = _call(
            _client(_app(), raise_server_exceptions=False),
            action,
            token,
            ORG_ID,
            target,
            body=body,
        )

        assert response.status_code == 500
        assert db.matching(r"^insert into audit_events\b") != []
        assert _state(db) == before
        assert not db.session_revoked(target_session)


# ---------------------------------------------------------------------------
# 12. No content in logs or audit rows
# ---------------------------------------------------------------------------


class TestNoContentInLogs:
    """No target's email or name, no org name, token or link in a log line or audit row."""

    def _flow(self, db: FakeDb) -> list[str]:
        """List and read metadata, deactivate (and refuse a second one), reactivate, reset
        a password, resend, replace, refuse a taken and an invalid email, refuse an unknown
        user; return every token issued along the way."""
        _, token = _super_admin(db, email="platform.marker.superadmin@example.test")
        _admin(db, email="platform.marker.admin@example.test", name="Admmarker Person")
        target = _user(db, email=_TARGET_EMAIL, name=_TARGET_NAME)
        db.open_session(target)
        invited, old = _invited_admin(db, OTHER_ORG_ID, email=_INVITED_EMAIL)
        third_org = db.add_org(name="Drittmarker Treuhand")
        _user(db, third_org, email=_TAKEN_EMAIL, name="Takenmarker Person")
        client = _client(_app())

        assert _call(client, "users", token).status_code == 200
        assert _call(client, "users", token, OTHER_ORG_ID).status_code == 200
        assert _call(client, "metadata", token).status_code == 200
        assert _call(client, "deactivate", token, ORG_ID, target).status_code == 200
        assert _call(client, "deactivate", token, ORG_ID, target).status_code == 409
        assert _call(client, "reactivate", token, ORG_ID, target).status_code == 200
        assert _call(client, "password_reset", token, ORG_ID, target).status_code == 202
        assert _call(client, "invitation", token, OTHER_ORG_ID, invited).status_code == 200
        resent = db.invitation_token(invited)
        replaced = _call(
            client, "invitation", token, OTHER_ORG_ID, invited, body={"email": _NEW_EMAIL}
        )
        assert replaced.status_code == 200
        new_id = _new_user_id(db, _NEW_EMAIL)
        refused = _call(
            client, "invitation", token, OTHER_ORG_ID, new_id, body={"email": _TAKEN_EMAIL}
        )
        assert refused.status_code == 409
        bad = {"email": "platform.marker.bad@@example.test"}
        assert _call(client, "invitation", token, OTHER_ORG_ID, new_id, body=bad).status_code == 422
        assert _call(client, "deactivate", token, ORG_ID, uuid.uuid4()).status_code == 404
        assert {row["action"] for row in db.audit} >= {
            "user.deactivate",
            "user.activate",
            "password_reset.request",
            "invitation.resend",
            "invitation.revoke",
            "invitation.create",
            "invitation.refuse",
        }
        return [
            _invited_token(invited, old),
            resent,
            db.invitation_token(new_id),
            db.issued_token(),
        ]

    def test_platform_users_api_flow_logs_no_content(self, db: FakeDb) -> None:
        """Captured the way main() configures logging, at DEBUG (a probe line proves the
        admino loggers reach the output)."""
        with configured_logging("DEBUG", "text") as logs:
            tokens = self._flow(db)
            logging.getLogger("admino.platform_users").debug("platform users probe line")

        formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
        text = logs.text + "\n".join(formatter.format(record) for record in logs.records)
        assert "platform users probe line" in text
        lowered = text.lower()
        assert "marker" not in lowered
        for content in (ORG_NAME, OTHER_ORG_NAME, "accept-invitation", "reset-password"):
            assert content.lower() not in lowered, content
        for issued in tokens:
            assert issued not in text
            assert sha256(issued).hex() not in text

    def test_platform_users_api_audit_rows_carry_no_content(self, db: FakeDb) -> None:
        """No email, name, org name, token or link; metadata values are ints, bools, IDs
        or the role."""
        tokens = self._flow(db)

        stored = json.dumps(db.audit, default=str)
        lowered = stored.lower()
        assert "marker" not in lowered
        for content in (ORG_NAME, OTHER_ORG_NAME, "/login", "accept-invitation", "reset-password"):
            assert content.lower() not in lowered, content
        for issued in tokens:
            assert issued not in stored
        uuid_re = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        for row in db.audit:
            for value in row["metadata"].values():
                assert (
                    type(value) in {int, bool}
                    or value == "org_admin"
                    or (isinstance(value, str) and uuid_re.fullmatch(value))
                ), (row["action"], value)


# ---------------------------------------------------------------------------
# 13. Route table guarantees: no impersonation, no passwords, tokens or email changes
# ---------------------------------------------------------------------------


class TestRouteTableGuarantees:
    """What the platform API can't do, read from the registered routes."""

    def test_platform_users_api_no_impersonation_route(self) -> None:
        """The six routes exist; no route's path, name or endpoint name speaks of
        impersonating, sudo, logging in or acting as, becoming or switching user."""
        app = _app()
        for action in _ALL:
            _route(app, *_ROUTES[action])
        offenders = []
        for route in app.routes:
            endpoint = getattr(route, "endpoint", None)
            text = " ".join(
                [
                    str(getattr(route, "path", "")),
                    str(getattr(route, "name", "")),
                    str(getattr(endpoint, "__name__", "")),
                ]
            ).lower()
            offenders += [(text, word) for word in _IMPERSONATION_WORDS if word in text]

        assert offenders == []

    def test_platform_users_api_no_impersonation_function(self) -> None:
        """admino.platform_users holds the six service functions; no function or class in
        it or in admino.server has "impersonat" in its name."""
        from admino import platform_users

        service_functions = {
            "list_users",
            "org_metadata",
            "deactivate_user",
            "reactivate_user",
            "trigger_password_reset",
            "reinvite_org_admin",
        }
        assert service_functions <= set(dir(platform_users))
        for module in (server, platform_users):
            names = set(dir(module))
            tree = ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))
            names |= {
                node.name
                for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            }
            assert [name for name in names if "impersonat" in name.lower()] == [], module

    def test_platform_users_api_no_patch_or_put_under_the_org_users(self) -> None:
        """Nothing under /api/platform/orgs/{org_id}/users changes a user's fields."""
        app = _app()
        _route(app, *_ROUTES["users"])
        under_users = re.compile(r"^/api/platform/orgs/\{[^}]+\}/users(?:/|$)")
        offenders = [
            (sorted(route.methods), route.path)
            for route in app.routes
            if isinstance(route, APIRoute)
            and under_users.match(route.path)
            and route.methods & {"PATCH", "PUT"}
        ]

        assert offenders == []

    def test_platform_users_api_no_platform_body_takes_a_password_or_token(self) -> None:
        """The re-invite body exists (with its email); no /api/platform/* request body has
        a password, new_password, password_hash, token or token_hash field, at any
        depth."""
        app = _app()
        assert "email" in _body_field_names(_route(app, *_ROUTES["invitation"]))
        offenders = {
            (route.path, name)
            for route in _platform_routes(app)
            for name in _body_field_names(route)
            if name in _SECRET_BODY_FIELDS
        }

        assert offenders == set()

    def test_platform_users_api_only_platform_email_body_field_is_the_reinvite(self) -> None:
        """No /api/platform/* route but the re-invite takes a field named email."""
        app = _app()
        with_email = sorted(
            (",".join(sorted(route.methods)), route.path)
            for route in _platform_routes(app)
            if "email" in _body_field_names(route)
        )

        assert with_email == [_ROUTES["invitation"]]

    def test_platform_users_api_no_platform_response_carries_a_token_hash_or_link(
        self,
    ) -> None:
        """The new routes' response models are in place; no /api/platform/* response
        model has a token, token_hash, password_hash, accept_link, reset_link or link
        field, at any depth."""
        app = _app()
        assert _response_field_names(_route(app, *_ROUTES["users"])) >= {"users", *_USER_KEYS}
        assert _response_field_names(_route(app, *_ROUTES["metadata"])) >= _METADATA_KEYS
        for action in ("deactivate", "reactivate"):
            assert _response_field_names(_route(app, *_ROUTES[action])) >= _USER_KEYS
        assert _response_field_names(_route(app, *_ROUTES["invitation"])) >= _INVITATION_KEYS
        offenders = {
            (route.path, name)
            for route in _platform_routes(app)
            for name in _response_field_names(route)
            if name in _SECRET_RESPONSE_FIELDS
        }

        assert offenders == set()
