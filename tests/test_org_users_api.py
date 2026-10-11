"""HTTP-layer spec for Org Admin user management: list, change, password reset (GH-164).

GH-165 adds the org's seat usage to the list.

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns) with a fake
config whose ``server.public_url`` is ``https://admino.example.ch``. The real
``admino.org_users``, ``admino.accounts``, ``admino.password_reset``,
``admino.email_outbox``, ``admino.sessions`` and ``admino.audit_events`` code
runs, through the real ``require_session``; only Argon2 is replaced by a fast
fake.

What these tests pin down:
- ``GET /api/org/users`` → 200 ``{"users": [...], "seats": {"used", "limit"}}``:
  the caller's org's active and deactivated users (never an invited account, a
  deleted user, another org's user or a Super Admin), ordered by ``created_at``
  then ``id``, each with exactly ``id, name, email, role, status, created_at,
  last_login_at``. ``seats`` (GH-165) has exactly ``used`` (the org's active and
  invited users that aren't deleted, an expired invitation included) and
  ``limit`` (the org's seats); it follows invitations, revocations,
  deactivations, reactivations and deletions, and is served from the same
  ``/api/org/users/get`` bucket.
- ``PATCH /api/org/users/{user_id}`` ``{role?, name?, email?}`` → 200 with the
  updated summary; a role change writes one ``user.role_change`` audit row, a
  name/email change one ``user.profile_change`` row (IDs, flags and role tokens
  only, with the client IP); an email change queues a content-free
  ``email_changed`` email to the OLD address and drops the user's live reset
  token; unchanged values write nothing. 404 ``{"detail": "User not found"}``
  for another org's user, an unknown id, an invited account, a deleted user and
  a Super Admin alike; 409 ``last_admin`` when the last active Org Admin would
  be demoted; 409 ``email_taken`` for an email used anywhere on the platform
  (case-insensitive), everything rolled back and one content-free
  ``user.profile_change`` ``{"email_taken": true}`` row; 422 without echo for a
  bad body or path id.
- A refused email change spends the caller's refused budget
  (``/api/org/invitations/refused``, shared with refused invitation sends):
  once spent, a PATCH carrying an email is 429 before any database work.
- ``POST /api/org/users/{user_id}/password-reset`` → 202 with an empty body;
  one ``password_reset`` email for the target, its link built from
  ``server.public_url``; the admin never sees the token; one
  ``password_reset.request`` audit row with the admin as actor; a deactivated
  target → 409 ``invalid_status``.
- All three routes depend on ``require_session`` (401 without a session),
  authorize through ``admino.access.can`` (``org.users.view`` /
  ``org.users.manage`` / ``org.users.role_change``): an Editor and a Super
  Admin get 403 ``{"detail": "Forbidden"}``; each has its own per-user
  rate-limit bucket; the two writes are refused cross-origin; an audit failure
  is a 500 with nothing changed; nothing identifying reaches a log line.

All database calls are faked. No network, no real PostgreSQL, no SMTP.

Security notes:
- Tenant isolation: another org's user answers 404 like an unknown id.
- Probing: the refused budget keeps "does this email exist" checks slow.
- Link poisoning: the reset link base is ``server.public_url``, never a header.
- Fail closed: an audit failure is a 500 and nothing is written or queued.
"""

from __future__ import annotations

import copy
import json
import logging
import sys
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import server
from admino.access import Capability
from admino.server import create_app
from tests.db_fakes import (
    LINK_PREFIX,
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

    from tests.db_fakes import Call

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_IP_A = "203.0.113.5"
_IP_B = "198.51.100.23"
_USERS = "/api/org/users"
_INVITES = "/api/org/invitations"
_DELETED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_USER_NOT_FOUND = {"detail": "User not found"}
_LAST_ADMIN = {
    "detail": "An organization must keep at least one active Org Admin.",
    "reason": "last_admin",
}
_EMAIL_TAKEN = {"detail": "A user with this email already exists.", "reason": "email_taken"}
_INVALID_STATUS = {
    "detail": "This change isn't possible in the user's current status.",
    "reason": "invalid_status",
}
_SUMMARY_KEYS = frozenset({"id", "name", "email", "role", "status", "created_at", "last_login_at"})
_NOT_ADMINS = ["editor", "super_admin"]
_OUTSIDERS = ["other-org", "unknown", "invited", "deleted", "super-admin"]
# Lowercase marker put in submitted VALUES only (never in a key: a 422 loc repeats keys).
_ECHO = "echomark42"

_ROUTES: list[tuple[str, str]] = [
    ("GET", "/api/org/users"),
    ("PATCH", "/api/org/users/{user_id}"),
    ("POST", "/api/org/users/{user_id}/password-reset"),
]
_KEY_LIST = "/api/org/users/get"
_KEY_PATCH = "/api/org/users/patch"
_KEY_RESET = "/api/org/users/password-reset"
# The per-user budget of refused "does this email exist" attempts (GH-153), shared by
# refused invitation sends and refused email changes.
_KEY_REFUSED = "/api/org/invitations/refused"
_KEY_INVITE_CREATE = "/api/org/invitations/create"
_ROOMY_KEYS = (_KEY_LIST, _KEY_PATCH, _KEY_RESET, _KEY_REFUSED, _KEY_INVITE_CREATE)
# Read at import, before any fixture patches the limits.
_CONFIGURED_LIMITS = {
    key: server._RATE_LIMITS.get(key) for key in (_KEY_LIST, _KEY_PATCH, _KEY_RESET)
}

_CROSS_ORIGIN = [
    pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
    pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
]
_BAD_IDS = ["not-a-uuid-echomark42", "12345", _ECHO + "0" * 26, "x" * 200]


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
    """Functional tests aren't about rate limits: give the routes they use a large bucket
    (the rate-limit and refused-budget tests set their own, before their first request)."""
    for key in _ROOMY_KEYS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


def _config() -> MagicMock:
    """A minimal config with the public URL reset links are built from."""
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
    """create_app with a stub agent and the fake config (it clears the rate buckets)."""
    return create_app(agent=MagicMock(), config=_config())  # type: ignore[arg-type]


def _client(app: FastAPI, ip: str = _IP_A, **kwargs: Any) -> TestClient:
    """A client whose peer address is ``ip``; redirects are not followed."""
    return TestClient(app, client=(ip, 50000), follow_redirects=False, **kwargs)


def _cookie(token: str, **extra: str) -> dict[str, str]:
    """Request headers carrying a session cookie (plus any extra headers)."""
    return {"Cookie": f"{_COOKIE}={token}", **extra}


def _session_cookie_headers(response: httpx.Response) -> list[str]:
    """Every Set-Cookie header naming admino_session."""
    return [
        h for h in response.headers.get_list("set-cookie") if h.lower().startswith(f"{_COOKIE}=")
    ]


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


def _admin(db: FakeDb, org_id: uuid.UUID = ORG_ID, **fields: Any) -> tuple[uuid.UUID, str]:
    """An active Org Admin with a live session: (user id, session token)."""
    user_id = db.add_account(role="org_admin", org_id=org_id, **fields)
    return user_id, db.open_session(user_id)


def _session_of(db: FakeDb, who: str) -> str:
    """A live session of a Super Admin or of a member of ORG_ID with the given role."""
    if who == "super_admin":
        return db.open_session(db.add_account(kind="super_admin", role=None))
    return db.open_session(db.add_account(role=who))


def _invited(
    db: FakeDb, org_id: uuid.UUID = ORG_ID, role: str = "editor", email: str | None = None
) -> uuid.UUID:
    """An invited account (no name, no password yet) with its pending invitation."""
    user_id = db.add_account(
        role=role, org_id=org_id, status="invited", name=None, password_hash=None, email=email
    )
    db.add_invitation(user_id)
    return user_id


def _outsider(db: FakeDb, case: str) -> uuid.UUID:
    """An id the caller's org doesn't own as a user: another org's user, an unknown id,
    an invited account, a deleted user or a Super Admin."""
    if case == "other-org":
        return db.add_account(org_id=OTHER_ORG_ID)
    if case == "invited":
        return _invited(db)
    if case == "deleted":
        return db.add_account(deleted_at=_DELETED_AT)
    if case == "super-admin":
        return db.add_account(kind="super_admin", role=None)
    return uuid.uuid4()


def _user_url(user_id: object) -> str:
    return f"{_USERS}/{user_id}"


def _reset_url(user_id: object) -> str:
    return f"{_USERS}/{user_id}/password-reset"


def _list(client: TestClient, token: str) -> httpx.Response:
    return client.get(_USERS, headers=_cookie(token))


def _patch(
    client: TestClient, token: str, user_id: object, body: object, **headers: str
) -> httpx.Response:
    return client.patch(_user_url(user_id), json=body, headers=_cookie(token, **headers))


def _reset(client: TestClient, token: str, user_id: object, **headers: str) -> httpx.Response:
    return client.post(_reset_url(user_id), headers=_cookie(token, **headers))


def _invite(client: TestClient, token: str, email: str) -> httpx.Response:
    return client.post(_INVITES, json={"email": email, "role": "editor"}, headers=_cookie(token))


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of every table these routes may touch, for "nothing changed" checks.

    Sessions are compared by (session id, user id) only: a request may refresh its own
    session's last_seen_at.
    """
    return copy.deepcopy(
        {
            "users": db.users,
            "orgs": db.orgs,
            "invitations": db.invitations,
            "tokens": db.tokens,
            "outbox": db.outbox,
            "audit": db.audit,
            "oauth_tokens": db.oauth_tokens,
            "memory": db.memory,
            "user_settings": db.user_settings,
            "sessions": sorted(
                (str(row["session_id"]), str(row["user_id"])) for row in db.sessions.values()
            ),
        }
    )


def _only_session_lookups(calls: list[Call]) -> bool:
    """True when every call is the session lookup of require_session (no route work)."""
    return all("from sessions" in call.normalized for call in calls)


def _assert_no_echo(response: httpx.Response) -> None:
    """A 422 body is safe: no error carries its input, and no marker value comes back."""
    errors = response.json()["detail"]
    assert isinstance(errors, list)
    assert all("input" not in error and "ctx" not in error for error in errors)
    assert _ECHO not in response.text.lower()


def _only_event(db: FakeDb, action: str) -> dict[str, Any]:
    """The one audit row of ``action``."""
    rows = db.audit_rows(action)
    assert len(rows) == 1, db.audit
    return rows[0]


def _assert_member_event(
    row: dict[str, Any], *, actor: uuid.UUID, target: uuid.UUID, ip: str, metadata: object
) -> None:
    """A content-free member event in ORG_ID: actor, target user, IP and metadata."""
    assert (row["actor_kind"], plain(row["actor_user_id"])) == ("member", actor)
    assert plain(row["org_id"]) == ORG_ID
    assert (row["target_type"], row["target_ids"]) == ("user", [str(target)])
    assert row["ip"] == ip
    assert row["metadata"] == metadata


def _assert_one_transaction(db: FakeDb, patterns: list[str]) -> None:
    """Every write matching ``patterns`` (each matched at least once) ran on the same
    connection inside the same transaction.

    The fake's rollback is global, so state checks alone can't tell an audit row written
    on the pool (outside the change's transaction) from one written inside it.
    """
    writes = []
    for pattern in patterns:
        matched = db.matching(pattern)
        assert matched, f"no statement matches {pattern}"
        writes.extend(matched)
    assert {(call.via, call.tx) for call in writes} == {(writes[0].via, writes[0].tx)}
    assert writes[0].tx is not None
    assert writes[0].via != "pool"


def _parsed(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def _server_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record (with its traceback) except the test client's own request log."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record) for record in caplog.records if not record.name.startswith("httpx")
    )


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
        monkeypatch.setattr(server, "can", spy)
        service = sys.modules.get("admino.org_users")
        if service is not None and hasattr(service, "can"):
            monkeypatch.setattr(service, "can", spy)


# ---------------------------------------------------------------------------
# 1. The routes exist, require a session and have their own rate limits
# ---------------------------------------------------------------------------


class TestRoutes:
    """GET /api/org/users, PATCH /api/org/users/{id}, POST /api/org/users/{id}/password-reset."""

    @pytest.mark.parametrize(("method", "path"), _ROUTES)
    def test_org_users_api_route_is_registered(self, method: str, path: str) -> None:
        _route(_app(), method, path)

    @pytest.mark.parametrize(("method", "path"), _ROUTES)
    def test_org_users_api_route_depends_on_require_session(self, method: str, path: str) -> None:
        """server.require_session is in the route's dependency tree."""
        route = _route(_app(), method, path)

        assert _depends_on(route.dependant, server.require_session)

    @pytest.mark.parametrize(("method", "path"), _ROUTES)
    def test_org_users_api_route_without_a_session_is_401(
        self, db: FakeDb, method: str, path: str
    ) -> None:
        """No cookie → 401 Unauthorized before any database call."""
        _route(_app(), method, path)
        target = db.add_account()
        url = path.replace("{user_id}", str(target))
        body = {"name": "Changed Name"} if method == "PATCH" else None

        response = _client(_app()).request(method, url, json=body)

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED
        assert db.calls == []

    @pytest.mark.parametrize(
        ("key", "rate"),
        [
            (_KEY_LIST, (1.0, 10)),
            (_KEY_PATCH, (0.5, 5)),
            (_KEY_RESET, (1 / 60, 3)),
        ],
    )
    def test_org_users_api_rate_limits_are_configured(
        self, key: str, rate: tuple[float, int]
    ) -> None:
        """(tokens per second, burst) per route key, as configured by the server."""
        assert _CONFIGURED_LIMITS[key] is not None, f"{key} has no rate limit"
        assert _CONFIGURED_LIMITS[key] == pytest.approx(rate)


# ---------------------------------------------------------------------------
# 2. Authorization: Org Admins only, through admino.access.can()
# ---------------------------------------------------------------------------


class TestAuthorization:
    """Editors and Super Admins get 403; can() decides."""

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    def test_org_users_api_list_forbidden_for_non_admins(self, db: FakeDb, who: str) -> None:
        """403 {"detail": "Forbidden"}; only the session lookup ran."""
        _route(_app(), "GET", "/api/org/users")
        db.add_account(role="org_admin")
        token = _session_of(db, who)

        response = _list(_client(_app()), token)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        assert _only_session_lookups(db.calls)

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"role": "org_admin"}, id="role"),
            pytest.param({"name": "Changed Name"}, id="name"),
            pytest.param({"email": "changed.address@example.ch"}, id="email"),
        ],
    )
    def test_org_users_api_patch_forbidden_for_non_admins(
        self, db: FakeDb, who: str, body: dict[str, str]
    ) -> None:
        """403 {"detail": "Forbidden"}; nothing changed, nothing queued or audited."""
        _route(_app(), "PATCH", "/api/org/users/{user_id}")
        db.add_account(role="org_admin")
        token = _session_of(db, who)
        target = db.add_account(role="editor")
        before = _state(db)

        response = _patch(_client(_app()), token, target, body)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        assert _state(db) == before
        assert _only_session_lookups(db.calls)

    @pytest.mark.parametrize("who", _NOT_ADMINS)
    def test_org_users_api_reset_forbidden_for_non_admins(self, db: FakeDb, who: str) -> None:
        """403 {"detail": "Forbidden"}; no token, no email, no audit row."""
        _route(_app(), "POST", "/api/org/users/{user_id}/password-reset")
        db.add_account(role="org_admin")
        token = _session_of(db, who)
        target = db.add_account()
        before = _state(db)

        response = _reset(_client(_app()), token, target)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        assert _state(db) == before
        assert _only_session_lookups(db.calls)

    def test_org_users_api_list_asks_for_org_users_view(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _CanSpy(monkeypatch)
        _, token = _admin(db)

        response = _list(_client(_app()), token)

        assert response.status_code == 200
        assert Capability.ORG_USERS_VIEW in spy.capabilities

    def test_org_users_api_list_refused_without_org_users_view(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When can() refuses org.users.view, even an Org Admin gets 403."""
        _route(_app(), "GET", "/api/org/users")
        _CanSpy(monkeypatch, deny=frozenset({Capability.ORG_USERS_VIEW}))
        _, token = _admin(db)

        response = _list(_client(_app()), token)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)

    def test_org_users_api_patch_with_role_asks_for_manage_and_role_change(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _CanSpy(monkeypatch)
        _, token = _admin(db)
        target = db.add_account(role="editor")

        response = _patch(_client(_app()), token, target, {"role": "org_admin"})

        assert response.status_code == 200
        assert Capability.ORG_USERS_MANAGE in spy.capabilities
        assert Capability.ORG_USERS_ROLE_CHANGE in spy.capabilities

    def test_org_users_api_patch_without_role_needs_only_org_users_manage(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With org.users.role_change refused, a name change still goes through."""
        spy = _CanSpy(monkeypatch, deny=frozenset({Capability.ORG_USERS_ROLE_CHANGE}))
        _, token = _admin(db)
        target = db.add_account(role="editor")

        response = _patch(_client(_app()), token, target, {"name": "Changed Name"})

        assert response.status_code == 200
        assert db.users[target]["name"] == "Changed Name"
        assert Capability.ORG_USERS_MANAGE in spy.capabilities

    def test_org_users_api_patch_role_refused_without_role_change(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With org.users.role_change refused, a PATCH carrying a role is 403 and changes
        nothing (not even the name it also carries)."""
        _route(_app(), "PATCH", "/api/org/users/{user_id}")
        _CanSpy(monkeypatch, deny=frozenset({Capability.ORG_USERS_ROLE_CHANGE}))
        _, token = _admin(db)
        target = db.add_account(role="editor")
        before = _state(db)

        response = _patch(
            _client(_app()), token, target, {"role": "org_admin", "name": "Changed Name"}
        )

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before

    def test_org_users_api_patch_refused_without_org_users_manage(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _route(_app(), "PATCH", "/api/org/users/{user_id}")
        _CanSpy(monkeypatch, deny=frozenset({Capability.ORG_USERS_MANAGE}))
        _, token = _admin(db)
        target = db.add_account(role="editor")
        before = _state(db)

        response = _patch(_client(_app()), token, target, {"name": "Changed Name"})

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before

    def test_org_users_api_reset_asks_for_org_users_manage(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _CanSpy(monkeypatch)
        _, token = _admin(db)

        response = _reset(_client(_app()), token, db.add_account())

        assert response.status_code == 202
        assert Capability.ORG_USERS_MANAGE in spy.capabilities

    def test_org_users_api_reset_refused_without_org_users_manage(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _route(_app(), "POST", "/api/org/users/{user_id}/password-reset")
        _CanSpy(monkeypatch, deny=frozenset({Capability.ORG_USERS_MANAGE}))
        _, token = _admin(db)
        target = db.add_account()
        before = _state(db)

        response = _reset(_client(_app()), token, target)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 3. GET /api/org/users
# ---------------------------------------------------------------------------


class TestList:
    """The caller's org's active and deactivated users."""

    def test_org_users_api_list_shape(self, db: FakeDb) -> None:
        """200 {"users": [...], "seats": {...}}: each item has exactly the summary keys,
        with the stored name, email, role, status, created date and last login."""
        _, token = _admin(db)
        created = datetime(2026, 9, 1, 9, 0, tzinfo=UTC)
        last_login = datetime(2026, 9, 30, 8, 15, tzinfo=UTC)
        target = db.add_account(
            role="org_admin",
            email="Shape.Person@Example.ch",
            name="Shape Person",
            created_at=created,
            last_login_at=last_login,
        )

        response = _list(_client(_app()), token)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"users", "seats"}
        assert all(set(item) == _SUMMARY_KEYS for item in body["users"])
        item = next(item for item in body["users"] if item["id"] == str(target))
        assert (item["name"], item["email"], item["role"], item["status"]) == (
            "Shape Person",
            "Shape.Person@Example.ch",
            "org_admin",
            "active",
        )
        assert _parsed(item["created_at"]) == created
        assert _parsed(item["last_login_at"]) == last_login

    def test_org_users_api_list_shows_a_never_logged_in_user_with_null(self, db: FakeDb) -> None:
        _, token = _admin(db)
        target = db.add_account(last_login_at=None)

        users = _list(_client(_app()), token).json()["users"]

        item = next(item for item in users if item["id"] == str(target))
        assert item["last_login_at"] is None

    def test_org_users_api_list_is_the_callers_org_members_only(self, db: FakeDb) -> None:
        """Active and deactivated members of the caller's org; never an invited account,
        a deleted user, another org's user or a Super Admin."""
        admin, token = _admin(db)
        editor = db.add_account(role="editor")
        second_admin = db.add_account(role="org_admin")
        deactivated = db.add_account(role="editor", status="deactivated")
        _invited(db)
        db.add_account(deleted_at=_DELETED_AT)
        db.add_account(org_id=OTHER_ORG_ID)
        _admin(db, org_id=OTHER_ORG_ID)
        db.add_account(kind="super_admin", role=None)

        users = _list(_client(_app()), token).json()["users"]

        assert {item["id"] for item in users} == {
            str(admin),
            str(editor),
            str(second_admin),
            str(deactivated),
        }
        statuses = {item["id"]: item["status"] for item in users}
        assert statuses[str(deactivated)] == "deactivated"

    def test_org_users_api_list_of_another_org_shows_only_that_org(self, db: FakeDb) -> None:
        """Org B's admin sees org B's users only."""
        _admin(db)
        db.add_account(role="editor")
        other_admin, other_token = _admin(db, org_id=OTHER_ORG_ID)
        other_member = db.add_account(org_id=OTHER_ORG_ID)

        users = _list(_client(_app()), other_token).json()["users"]

        assert {item["id"] for item in users} == {str(other_admin), str(other_member)}

    def test_org_users_api_list_order_is_created_at_then_id(self, db: FakeDb) -> None:
        """Ordered by created_at, then by id for equal dates (not by insertion)."""
        day = datetime(2026, 4, 1, 12, 0, tzinfo=UTC)
        tied = [db.add_account(created_at=day + timedelta(days=30)) for _ in range(3)]
        late = db.add_account(created_at=day + timedelta(days=20))
        admin, token = _admin(db, created_at=day)
        middle = db.add_account(created_at=day + timedelta(days=10))

        users = _list(_client(_app()), token).json()["users"]

        expected = [admin, middle, late, *sorted(tied, key=lambda user_id: user_id.int)]
        assert [item["id"] for item in users] == [str(user_id) for user_id in expected]

    def test_org_users_api_list_never_shows_secrets(self, db: FakeDb) -> None:
        """No password hash, token, kind or org id anywhere in the body."""
        _, token = _admin(db, password_hash=fake_hash("violet-Anchor-93-quartz"))
        target = db.add_account(password_hash=fake_hash("Tidal-Lantern-58-cobalt"))
        reset_token = db.add_reset_token(target)
        _invited(db)

        response = _list(_client(_app()), token)

        assert response.status_code == 200
        text = response.text
        assert "fake$" not in text
        assert "password" not in text.lower()
        assert "token" not in text.lower()
        assert "org_id" not in text
        assert str(ORG_ID) not in text
        assert reset_token not in text
        assert sha256(reset_token).hex() not in text


# ---------------------------------------------------------------------------
# 4. PATCH /api/org/users/{user_id}: changes
# ---------------------------------------------------------------------------


class TestPatchChanges:
    """Role, name and email changes, their audit rows and side effects."""

    @pytest.mark.parametrize(
        ("old_role", "new_role"),
        [("editor", "org_admin"), ("org_admin", "editor")],
    )
    def test_org_users_api_patch_role_change(
        self, db: FakeDb, old_role: str, new_role: str
    ) -> None:
        """200 with the updated summary (exactly the summary keys); the role is stored.
        Demoting another admin is fine while the caller stays an active admin."""
        _, token = _admin(db)
        target = db.add_account(role=old_role, name="Role Person", email="role.person@example.ch")

        response = _patch(_client(_app()), token, target, {"role": new_role})

        assert response.status_code == 200
        body = response.json()
        assert set(body) == _SUMMARY_KEYS
        assert (body["id"], body["role"], body["status"]) == (str(target), new_role, "active")
        assert (body["name"], body["email"]) == ("Role Person", "role.person@example.ch")
        assert db.users[target]["role"] == new_role

    def test_org_users_api_patch_role_change_is_audited(self, db: FakeDb) -> None:
        """One user.role_change row: the admin, ORG_ID, target the user, the client IP,
        metadata {"old_role", "new_role"}; nothing else is audited or queued."""
        admin, token = _admin(db)
        target = db.add_account(role="editor")

        response = _patch(_client(_app(), ip=_IP_B), token, target, {"role": "org_admin"})

        assert response.status_code == 200
        row = _only_event(db, "user.role_change")
        _assert_member_event(
            row,
            actor=admin,
            target=target,
            ip=_IP_B,
            metadata={"old_role": "editor", "new_role": "org_admin"},
        )
        assert [row["action"] for row in db.audit] == ["user.role_change"]
        assert db.outbox == []

    def test_org_users_api_patch_name_change(self, db: FakeDb) -> None:
        """The name is stripped and stored; one user.profile_change row
        {"name_changed": true, "email_changed": false}; no email is queued."""
        admin, token = _admin(db)
        target = db.add_account(name="Old Name")

        response = _patch(_client(_app(), ip=_IP_B), token, target, {"name": "  Ada Lovelace  "})

        assert response.status_code == 200
        assert response.json()["name"] == "Ada Lovelace"
        assert db.users[target]["name"] == "Ada Lovelace"
        _assert_member_event(
            _only_event(db, "user.profile_change"),
            actor=admin,
            target=target,
            ip=_IP_B,
            metadata={"name_changed": True, "email_changed": False},
        )
        assert [row["action"] for row in db.audit] == ["user.profile_change"]
        assert db.outbox == []

    def test_org_users_api_patch_email_change(self, db: FakeDb) -> None:
        """The email is stripped (capitalization kept) and stored; one user.profile_change
        row {"name_changed": false, "email_changed": true}."""
        admin, token = _admin(db)
        target = db.add_account(email="old.address@example.ch")

        response = _patch(
            _client(_app(), ip=_IP_B), token, target, {"email": "  New.Address@Example.ch  "}
        )

        assert response.status_code == 200
        assert response.json()["email"] == "New.Address@Example.ch"
        assert db.users[target]["email"] == "New.Address@Example.ch"
        _assert_member_event(
            _only_event(db, "user.profile_change"),
            actor=admin,
            target=target,
            ip=_IP_B,
            metadata={"name_changed": False, "email_changed": True},
        )

    def test_org_users_api_patch_email_change_notifies_the_old_address(self, db: FakeDb) -> None:
        """Exactly one queued email: email_changed, to the user, sent to the OLD address,
        params {"org_name": ORG_NAME} only (no address, name or link)."""
        _, token = _admin(db)
        target = db.add_account(email="old.address@example.ch", name="Mail Person")

        response = _patch(_client(_app()), token, target, {"email": "new.address@example.ch"})

        assert response.status_code == 200
        assert len(db.outbox) == 1
        row = db.outbox[0]
        assert row["template_key"] == "email_changed"
        assert row["user_id"] == target
        assert row["recipient_address"] == "old.address@example.ch"
        assert row["params"] == {"org_name": ORG_NAME}

    def test_org_users_api_patch_email_change_drops_the_reset_token(self, db: FakeDb) -> None:
        """A reset link already sent to the old address stops working; another user's
        token stays."""
        _, token = _admin(db)
        target = db.add_account(email="old.address@example.ch")
        bystander = db.add_account()
        db.add_reset_token(target)
        bystander_token = db.add_reset_token(bystander)

        response = _patch(_client(_app()), token, target, {"email": "new.address@example.ch"})

        assert response.status_code == 200
        assert target not in db.tokens
        assert db.tokens[bystander]["token_hash"] == sha256(bystander_token)

    def test_org_users_api_patch_role_and_name_write_both_events_in_order(self, db: FakeDb) -> None:
        """user.role_change first, then user.profile_change."""
        _, token = _admin(db)
        target = db.add_account(role="editor", name="Old Name")

        response = _patch(_client(_app()), token, target, {"role": "org_admin", "name": "New Name"})

        assert response.status_code == 200
        assert (db.users[target]["role"], db.users[target]["name"]) == ("org_admin", "New Name")
        assert [row["action"] for row in db.audit] == ["user.role_change", "user.profile_change"]

    def test_org_users_api_patch_unchanged_values_write_nothing(self, db: FakeDb) -> None:
        """Values equal to the stored ones: 200 with the summary, no audit row, no email,
        the reset token kept."""
        _, token = _admin(db)
        target = db.add_account(role="editor", name="Same Person", email="same.person@example.ch")
        db.add_reset_token(target)
        before = _state(db)

        response = _patch(
            _client(_app()),
            token,
            target,
            {"role": "editor", "name": "Same Person", "email": "same.person@example.ch"},
        )

        assert response.status_code == 200
        assert response.json()["email"] == "same.person@example.ch"
        assert _state(db) == before

    def test_org_users_api_patch_email_capitalization_only_is_allowed(self, db: FakeDb) -> None:
        """Changing only the capitalization of the user's own email is not "taken"."""
        _, token = _admin(db)
        target = db.add_account(email="case.person@example.ch")

        response = _patch(_client(_app()), token, target, {"email": "Case.Person@Example.ch"})

        assert response.status_code == 200
        assert db.users[target]["email"] == "Case.Person@Example.ch"

    def test_org_users_api_patch_demotion_deletes_nothing(self, db: FakeDb) -> None:
        """A second Org Admin demoted to Editor keeps their sessions, OAuth connections and
        memory (#162 derives the effect from the role); their session still works."""
        _, token = _admin(db)
        target = db.add_account(role="org_admin")
        target_tokens = [db.open_session(target), db.open_session(target)]
        db.add_oauth_token(target, "google", encrypted_refresh_token="gAAAA-fake-ciphertext")
        db.add_memory(target, "favourite.colour", "blue")
        client = _client(_app())

        response = _patch(client, token, target, {"role": "editor"})

        assert response.status_code == 200
        assert not any(db.session_revoked(session) for session in target_tokens)
        assert db.oauth_token(target, "google") is not None
        assert db.memories_of(target) == {"favourite.colour": "blue"}
        assert client.get("/api/auth/me", headers=_cookie(target_tokens[0])).status_code == 200

    def test_org_users_api_patch_deactivated_user_is_allowed(self, db: FakeDb) -> None:
        """A deactivated member can be renamed; the summary says deactivated."""
        _, token = _admin(db)
        target = db.add_account(status="deactivated")

        response = _patch(_client(_app()), token, target, {"name": "Renamed Person"})

        assert response.status_code == 200
        assert response.json()["status"] == "deactivated"
        assert db.users[target]["name"] == "Renamed Person"

    def test_org_users_api_patch_of_oneself_keeps_the_cookie(self, db: FakeDb) -> None:
        """An Org Admin may rename themselves; no session cookie is set or cleared."""
        admin, token = _admin(db)
        client = _client(_app())

        response = _patch(client, token, admin, {"name": "Self Renamed"})

        assert response.status_code == 200
        assert db.users[admin]["name"] == "Self Renamed"
        assert _session_cookie_headers(response) == []
        assert client.get("/api/auth/me", headers=_cookie(token)).status_code == 200


# ---------------------------------------------------------------------------
# 5. PATCH: refusals (404, 409, 422)
# ---------------------------------------------------------------------------


class TestPatchRefusals:
    """Outsiders, the last-admin guard, taken emails and bad input."""

    @pytest.mark.parametrize("case", _OUTSIDERS)
    def test_org_users_api_patch_outside_the_org_is_404(self, db: FakeDb, case: str) -> None:
        """404 {"detail": "User not found"}; nothing changed, queued or audited."""
        _, token = _admin(db)
        target = _outsider(db, case)
        before = _state(db)

        response = _patch(
            _client(_app()),
            token,
            target,
            {"role": "org_admin", "name": "Changed Name", "email": "changed@example.ch"},
        )

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND
        assert _state(db) == before

    def test_org_users_api_patch_404_bodies_are_identical(self, db: FakeDb) -> None:
        _, token = _admin(db)
        targets = [_outsider(db, case) for case in _OUTSIDERS]
        client = _client(_app())

        responses = [_patch(client, token, target, {"role": "org_admin"}) for target in targets]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize(
        "other",
        ["none", "admin-deactivated", "admin-invited", "admin-in-other-org"],
    )
    def test_org_users_api_patch_self_demotion_of_last_active_admin_is_409(
        self, db: FakeDb, other: str
    ) -> None:
        """The org's only ACTIVE Org Admin demoting themselves → 409 last_admin; the role
        and the name sent along are unchanged and nothing is audited."""
        admin, token = _admin(db, name="Only Admin")
        if other == "admin-deactivated":
            db.add_account(role="org_admin", status="deactivated")
        elif other == "admin-invited":
            _invited(db, role="org_admin")
        elif other == "admin-in-other-org":
            db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
        before = _state(db)

        response = _patch(_client(_app()), token, admin, {"role": "editor", "name": "Changed"})

        assert response.status_code == 409
        assert response.json() == _LAST_ADMIN
        assert _state(db) == before

    def test_org_users_api_patch_self_demotion_with_another_active_admin(self, db: FakeDb) -> None:
        admin, token = _admin(db)
        db.add_account(role="org_admin")

        response = _patch(_client(_app()), token, admin, {"role": "editor"})

        assert response.status_code == 200
        assert db.users[admin]["role"] == "editor"

    def test_org_users_api_patch_demoting_a_deactivated_admin_is_allowed(self, db: FakeDb) -> None:
        """The caller is the only active admin; demoting a deactivated admin passes."""
        _, token = _admin(db)
        target = db.add_account(role="org_admin", status="deactivated")

        response = _patch(_client(_app()), token, target, {"role": "editor"})

        assert response.status_code == 200
        assert db.users[target]["role"] == "editor"

    def test_org_users_api_patch_org_admin_on_the_last_admin_is_a_no_op(self, db: FakeDb) -> None:
        """Setting org_admin on the last admin passes the guard and writes nothing."""
        admin, token = _admin(db)
        before = _state(db)

        response = _patch(_client(_app()), token, admin, {"role": "org_admin"})

        assert response.status_code == 200
        assert response.json()["role"] == "org_admin"
        assert _state(db) == before

    @pytest.mark.parametrize(
        ("holder", "submitted"),
        [
            pytest.param("other-org", "TAKEN.Person@example.CH", id="other-org-case-insensitive"),
            pytest.param("same-org", "taken.person@example.ch", id="same-org"),
            pytest.param("super-admin", "Taken.Person@Example.ch", id="super-admin"),
            pytest.param("invited", "taken.person@example.ch", id="invited-account"),
        ],
    )
    def test_org_users_api_patch_taken_email_is_409(
        self, db: FakeDb, holder: str, submitted: str
    ) -> None:
        """An email used by any user on the platform → 409 email_taken (exact body); the
        email isn't echoed and the target keeps their address."""
        _, token = _admin(db)
        stored = "taken.person@example.ch"
        if holder == "other-org":
            db.add_account(org_id=OTHER_ORG_ID, email=stored)
        elif holder == "same-org":
            db.add_account(email=stored)
        elif holder == "super-admin":
            db.add_account(kind="super_admin", role=None, email=stored)
        else:
            _invited(db, email=stored)
        target = db.add_account(email="target.person@example.ch")

        response = _patch(_client(_app()), token, target, {"email": submitted})

        assert response.status_code == 409
        assert response.json() == _EMAIL_TAKEN
        assert "taken.person" not in response.text.lower()
        assert db.users[target]["email"] == "target.person@example.ch"

    def test_org_users_api_patch_taken_email_rolls_back_and_audits_once(self, db: FakeDb) -> None:
        """A taken email undoes the whole PATCH (no role or name change, no email queued,
        the reset token kept); then exactly one content-free user.profile_change row
        {"email_taken": true} is recorded with the actor, target and IP."""
        admin, token = _admin(db)
        db.add_account(org_id=OTHER_ORG_ID, email="taken.person@example.ch")
        target = db.add_account(role="editor", name="Kept Name", email="kept@example.ch")
        db.add_reset_token(target)
        before = _state(db)

        response = _patch(
            _client(_app(), ip=_IP_B),
            token,
            target,
            {"role": "org_admin", "name": "Changed Name", "email": "Taken.Person@example.ch"},
        )

        assert response.status_code == 409
        after = _state(db)
        audit_before = before.pop("audit")
        audit_after = after.pop("audit")
        assert after == before
        assert audit_after[: len(audit_before)] == audit_before
        added = audit_after[len(audit_before) :]
        assert len(added) == 1, added
        assert added[0]["action"] == "user.profile_change"
        _assert_member_event(
            added[0], actor=admin, target=target, ip=_IP_B, metadata={"email_taken": True}
        )

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({}, id="empty"),
            pytest.param({"role": None, "name": None, "email": None}, id="all-null"),
            pytest.param({"name": "Valid Name", "org_id": str(OTHER_ORG_ID)}, id="org_id"),
            pytest.param({"name": "Valid Name", "user_id": _ECHO}, id="user_id"),
            pytest.param({"name": "Valid Name", "status": "deactivated-" + _ECHO}, id="status"),
            pytest.param({"name": "Valid Name", "password": "Violet-" + _ECHO}, id="password"),
            pytest.param({"role": "editor", "kind": "super_admin"}, id="kind"),
            pytest.param({"role": "super_admin"}, id="role-super-admin"),
            pytest.param({"role": _ECHO}, id="role-unknown"),
            pytest.param({"role": "Editor"}, id="role-capitalized"),
            pytest.param({"email": _ECHO + ".example.ch"}, id="email-no-at"),
            pytest.param({"email": _ECHO + "@localhost"}, id="email-no-dot"),
            pytest.param({"email": _ECHO + " x@example.ch"}, id="email-space"),
            pytest.param({"email": _ECHO + "@" + "a" * 250 + ".ch"}, id="email-too-long"),
            pytest.param({"email": "   "}, id="email-blank"),
            pytest.param({"name": ""}, id="name-empty"),
            pytest.param({"name": "   "}, id="name-blank"),
            pytest.param({"name": _ECHO + " " + "x" * 120}, id="name-too-long"),
            pytest.param({"name": _ECHO + chr(0)}, id="name-control"),
            pytest.param({"name": _ECHO + chr(0x202E)}, id="name-format"),
            # Mid-string: a trailing U+2028/U+2029 is whitespace and would be stripped.
            pytest.param({"name": _ECHO + chr(0x2028) + "x"}, id="name-line-separator"),
            pytest.param({"name": _ECHO + chr(0x2029) + "x"}, id="name-para-separator"),
            pytest.param({"name": 42}, id="name-not-a-string"),
        ],
    )
    def test_org_users_api_patch_bad_body_is_422_without_echo(
        self, db: FakeDb, body: dict[str, Any]
    ) -> None:
        """422; no error repeats its input (no submitted email or name comes back); only
        the session lookup ran and nothing changed."""
        _route(_app(), "PATCH", "/api/org/users/{user_id}")
        _, token = _admin(db)
        target = db.add_account(role="editor")
        before = _state(db)

        response = _patch(_client(_app()), token, target, body)

        assert response.status_code == 422
        _assert_no_echo(response)
        assert _state(db) == before
        assert _only_session_lookups(db.calls)

    @pytest.mark.parametrize("bad_id", _BAD_IDS)
    def test_org_users_api_patch_non_uuid_is_422_without_echo(
        self, db: FakeDb, bad_id: str
    ) -> None:
        _route(_app(), "PATCH", "/api/org/users/{user_id}")
        _, token = _admin(db)
        before = _state(db)

        response = _patch(_client(_app()), token, bad_id, {"name": "Changed Name"})

        assert response.status_code == 422
        _assert_no_echo(response)
        assert "x" * 20 not in response.text
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 6. The refused-email budget (shared with refused invitation sends)
# ---------------------------------------------------------------------------


class TestRefusedEmailBudget:
    """A refused email change spends the per-user /api/org/invitations/refused budget."""

    def _taken(self, db: FakeDb, count: int) -> list[str]:
        emails = [f"taken.{index}@example.ch" for index in range(count)]
        for email in emails:
            db.add_account(org_id=OTHER_ORG_ID, email=email)
        return emails

    def test_org_users_api_refused_email_changes_spend_the_budget(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After 5 refused email changes, a PATCH carrying a fresh email is a 429 before any
        database work (only the session lookup runs); the budget is the per-user
        ("/api/org/invitations/refused", "user:<id>") bucket."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_REFUSED, (0.001, 5))
        admin, token = _admin(db)
        target = db.add_account(email="target.person@example.ch")
        client = _client(app)

        refused = [
            _patch(client, token, target, {"email": email}).status_code
            for email in self._taken(db, 5)
        ]
        calls_before = len(db.calls)
        before = _state(db)
        limited = _patch(client, token, target, {"email": "fresh.person@example.ch"})
        calls_during = db.calls[calls_before:]

        assert refused == [409] * 5
        assert limited.status_code == 429
        assert limited.json() == _RATE_LIMITED
        assert _only_session_lookups(calls_during)
        assert _state(db) == before
        assert (_KEY_REFUSED, f"user:{admin}") in server._rate_buckets

    def test_org_users_api_refused_budget_spares_patches_without_email(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With the budget spent, a name or role change still works."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_REFUSED, (0.001, 5))
        _, token = _admin(db)
        target = db.add_account(role="org_admin")
        client = _client(app)
        for email in self._taken(db, 5):
            assert _patch(client, token, target, {"email": email}).status_code == 409

        renamed = _patch(client, token, target, {"name": "Still Allowed"})
        demoted = _patch(client, token, target, {"role": "editor"})

        assert renamed.status_code == 200
        assert demoted.status_code == 200
        assert (db.users[target]["name"], db.users[target]["role"]) == ("Still Allowed", "editor")

    def test_org_users_api_refused_budget_is_per_admin(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Another Org Admin of the same org keeps their own budget."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_REFUSED, (0.001, 5))
        _, token_a = _admin(db)
        _, token_b = _admin(db)
        target = db.add_account()
        taken = self._taken(db, 5)
        client = _client(app)
        for email in taken:
            assert _patch(client, token_a, target, {"email": email}).status_code == 409

        limited = _patch(client, token_a, target, {"email": taken[0]})
        other = _patch(client, token_b, target, {"email": taken[0]})

        assert limited.status_code == 429
        assert other.status_code == 409
        assert other.json() == _EMAIL_TAKEN

    def test_org_users_api_refused_invitations_spend_the_email_change_budget(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """5 refused invitation sends (email taken) leave no budget for an email change."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_REFUSED, (0.001, 5))
        _, token = _admin(db)
        target = db.add_account(email="target.person@example.ch")
        client = _client(app)

        refused = [_invite(client, token, email).status_code for email in self._taken(db, 5)]
        limited = _patch(client, token, target, {"email": "fresh.person@example.ch"})

        assert refused == [409] * 5
        assert limited.status_code == 429
        assert limited.json() == _RATE_LIMITED
        assert db.users[target]["email"] == "target.person@example.ch"

    def test_org_users_api_refused_email_changes_spend_the_invitation_budget(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """5 refused email changes leave no budget for an invitation send."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_REFUSED, (0.001, 5))
        _, token = _admin(db)
        target = db.add_account()
        client = _client(app)
        for email in self._taken(db, 5):
            assert _patch(client, token, target, {"email": email}).status_code == 409

        limited = _invite(client, token, "fresh.invitee@example.ch")

        assert limited.status_code == 429
        assert db.user_by_email("fresh.invitee@example.ch") is None

    def test_org_users_api_successful_email_changes_dont_spend_the_budget(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a budget of 1: three successful changes, then a refused one (409, not 429),
        then the next email change is a 429."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _KEY_REFUSED, (0.001, 1))
        _, token = _admin(db)
        target = db.add_account()
        (taken,) = self._taken(db, 1)
        client = _client(app)

        changed = [
            _patch(client, token, target, {"email": f"changed.{index}@example.ch"}).status_code
            for index in range(3)
        ]
        refused = _patch(client, token, target, {"email": taken})
        limited = _patch(client, token, target, {"email": "changed.9@example.ch"})

        assert changed == [200, 200, 200]
        assert refused.status_code == 409
        assert limited.status_code == 429


# ---------------------------------------------------------------------------
# 7. Per-user rate limits of the three routes
# ---------------------------------------------------------------------------


_ROUTE_KEYS = {"list": _KEY_LIST, "patch": _KEY_PATCH, "reset": _KEY_RESET}
_SUCCESS = {"list": 200, "patch": 200, "reset": 202}


def _call(kind: str, client: TestClient, token: str, target: uuid.UUID) -> httpx.Response:
    if kind == "list":
        return _list(client, token)
    if kind == "patch":
        return _patch(client, token, target, {"name": f"Name {uuid.uuid4().hex[:8]}"})
    return _reset(client, token, target)


class TestRateLimits:
    """Each route spends its own per-user bucket first."""

    @pytest.mark.parametrize("kind", ["list", "patch", "reset"])
    def test_org_users_api_rate_limit_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, kind: str
    ) -> None:
        """One admin spending the route's bucket gets 429 before any route work; another
        admin of the same org is still served; the bucket is (key, "user:<id>")."""
        app = _app()
        key = _ROUTE_KEYS[kind]
        monkeypatch.setitem(server._RATE_LIMITS, key, (0.001, 1))
        first, token_a = _admin(db)
        second, token_b = _admin(db)
        target = db.add_account()
        client = _client(app)

        served = _call(kind, client, token_a, target)
        calls_before = len(db.calls)
        exhausted = _call(kind, client, token_a, target)
        calls_during = db.calls[calls_before:]
        other = _call(kind, client, token_b, target)

        assert served.status_code == _SUCCESS[kind]
        assert exhausted.status_code == 429
        assert exhausted.json() == _RATE_LIMITED
        assert _only_session_lookups(calls_during)
        assert other.status_code == _SUCCESS[kind]
        assert (key, f"user:{first}") in server._rate_buckets
        assert (key, f"user:{second}") in server._rate_buckets

    @pytest.mark.parametrize(
        ("spent", "fresh"), [("list", "patch"), ("patch", "reset"), ("reset", "list")]
    )
    def test_org_users_api_rate_limit_buckets_are_separate(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, spent: str, fresh: str
    ) -> None:
        """Spending one route's bucket doesn't throttle the caller on another route."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _ROUTE_KEYS[spent], (0.001, 1))
        _, token = _admin(db)
        target = db.add_account()
        client = _client(app)
        _call(spent, client, token, target)
        assert _call(spent, client, token, target).status_code == 429

        response = _call(fresh, client, token, target)

        assert response.status_code == _SUCCESS[fresh]


# ---------------------------------------------------------------------------
# 8. POST /api/org/users/{user_id}/password-reset
# ---------------------------------------------------------------------------


class TestPasswordReset:
    """An Org Admin sends a user of their org a reset link (#151's flow)."""

    def test_org_users_api_reset_is_202_with_an_empty_body(self, db: FakeDb) -> None:
        _, token = _admin(db)

        response = _reset(_client(_app()), token, db.add_account())

        assert response.status_code == 202
        assert response.content == b""

    def test_org_users_api_reset_queues_one_link_for_the_target(self, db: FakeDb) -> None:
        """One password_reset email to the target's address; its link is
        PUBLIC_URL/reset-password#token=<43-char token>, whose SHA-256 is the user's one
        live token. Nothing else is queued; the admin gets no token."""
        admin, token = _admin(db)
        target = db.add_account(email="reset.target@example.ch")

        response = _reset(_client(_app()), token, target)

        assert response.status_code == 202
        assert len(db.outbox) == 1
        row = db.outbox[0]
        assert row["template_key"] == "password_reset"
        assert row["user_id"] == target
        assert row["recipient_address"] == "reset.target@example.ch"
        link = row["params"]["reset_link"]
        assert link.startswith(LINK_PREFIX)
        raw = link[len(LINK_PREFIX) :]
        assert TOKEN_RE.fullmatch(raw)
        assert db.tokens[target]["token_hash"] == sha256(raw)
        assert admin not in db.tokens

    def test_org_users_api_reset_replaces_the_previous_token(self, db: FakeDb) -> None:
        _, token = _admin(db)
        target = db.add_account()
        old = db.add_reset_token(target)

        response = _reset(_client(_app()), token, target)

        assert response.status_code == 202
        assert db.tokens[target]["token_hash"] == sha256(db.issued_token())
        assert db.tokens[target]["token_hash"] != sha256(old)

    def test_org_users_api_reset_never_returns_the_token(self, db: FakeDb) -> None:
        """Neither the body nor any header carries the token or the link."""
        _, token = _admin(db)

        response = _reset(_client(_app()), token, db.add_account())

        assert response.status_code == 202
        raw = db.issued_token()
        assert raw not in response.text
        for name, value in response.headers.multi_items():
            assert raw not in value, name
            assert "reset-password" not in value, name

    def test_org_users_api_reset_link_ignores_forwarded_host_headers(self, db: FakeDb) -> None:
        """Link poisoning: the link base is server.public_url, not a request header."""
        _, token = _admin(db)

        response = _reset(
            _client(_app()),
            token,
            db.add_account(),
            **{"X-Forwarded-Host": "evil.example", "Forwarded": "host=evil.example"},
        )

        assert response.status_code == 202
        assert db.reset_links()[0].startswith(LINK_PREFIX)
        assert "evil" not in db.reset_links()[0]

    def test_org_users_api_reset_is_audited(self, db: FakeDb) -> None:
        """One password_reset.request row: the ADMIN is the actor, ORG_ID, target the user,
        the client IP, metadata {"email_sent": true}."""
        admin, token = _admin(db)
        target = db.add_account()

        response = _reset(_client(_app(), ip=_IP_B), token, target)

        assert response.status_code == 202
        _assert_member_event(
            _only_event(db, "password_reset.request"),
            actor=admin,
            target=target,
            ip=_IP_B,
            metadata={"email_sent": True},
        )
        assert [row["action"] for row in db.audit] == ["password_reset.request"]

    def test_org_users_api_reset_of_a_deactivated_user_is_409(self, db: FakeDb) -> None:
        """409 invalid_status; no token, no email, no audit row."""
        _, token = _admin(db)
        target = db.add_account(status="deactivated")
        before = _state(db)

        response = _reset(_client(_app()), token, target)

        assert response.status_code == 409
        assert response.json() == _INVALID_STATUS
        assert _state(db) == before

    @pytest.mark.parametrize("case", _OUTSIDERS)
    def test_org_users_api_reset_outside_the_org_is_404(self, db: FakeDb, case: str) -> None:
        """404 {"detail": "User not found"}; no token, no email, no audit row."""
        _, token = _admin(db)
        target = _outsider(db, case)
        before = _state(db)

        response = _reset(_client(_app()), token, target)

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND
        assert _state(db) == before

    def test_org_users_api_reset_404_bodies_are_identical(self, db: FakeDb) -> None:
        _, token = _admin(db)
        targets = [_outsider(db, case) for case in _OUTSIDERS]
        client = _client(_app())

        responses = [_reset(client, token, target) for target in targets]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize("bad_id", _BAD_IDS)
    def test_org_users_api_reset_non_uuid_is_422_without_echo(
        self, db: FakeDb, bad_id: str
    ) -> None:
        _route(_app(), "POST", "/api/org/users/{user_id}/password-reset")
        _, token = _admin(db)
        before = _state(db)

        response = _reset(_client(_app()), token, bad_id)

        assert response.status_code == 422
        _assert_no_echo(response)
        assert "x" * 20 not in response.text
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 9. CSRF: cross-origin writes are refused
# ---------------------------------------------------------------------------


class TestCrossOrigin:
    """The global middleware refuses cross-origin PATCH/POST before anything runs."""

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    def test_org_users_api_patch_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        _route(_app(), "PATCH", "/api/org/users/{user_id}")
        _, token = _admin(db)
        target = db.add_account(role="editor")
        before = _state(db)

        response = _patch(_client(_app()), token, target, {"role": "org_admin"}, **headers)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert db.calls == []
        assert _state(db) == before

    @pytest.mark.parametrize("headers", _CROSS_ORIGIN)
    def test_org_users_api_reset_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        _route(_app(), "POST", "/api/org/users/{user_id}/password-reset")
        _, token = _admin(db)
        target = db.add_account()
        before = _state(db)

        response = _reset(_client(_app()), token, target, **headers)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert db.calls == []
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 10. Fail closed: an audit failure is a 500 and nothing changes
# ---------------------------------------------------------------------------


class TestAuditFailure:
    """The audit write is part of the change: when it fails, everything rolls back."""

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"role": "org_admin"}, id="role"),
            pytest.param({"name": "Changed Name"}, id="name"),
            pytest.param({"email": "changed.address@example.ch"}, id="email"),
        ],
    )
    def test_org_users_api_patch_audit_failure_is_500_and_changes_nothing(
        self, db: FakeDb, body: dict[str, str]
    ) -> None:
        """500; the user row, the reset token and the outbox are untouched."""
        _, token = _admin(db)
        target = db.add_account(role="editor", email="old.address@example.ch")
        db.add_reset_token(target)
        before = _state(db)
        db.fail_audit = True

        response = _patch(_client(_app(), raise_server_exceptions=False), token, target, body)

        assert response.status_code == 500
        assert _state(db) == before

    def test_org_users_api_reset_audit_failure_is_500_and_queues_nothing(self, db: FakeDb) -> None:
        """500; no email queued and the previous token is still the live one."""
        _, token = _admin(db)
        target = db.add_account()
        db.add_reset_token(target)
        before = _state(db)
        db.fail_audit = True

        response = _reset(_client(_app(), raise_server_exceptions=False), token, target)

        assert response.status_code == 500
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 11. One change, one transaction
# ---------------------------------------------------------------------------


class TestOneTransaction:
    """The change, its queued email, its token step and its audit rows commit together."""

    def test_org_users_api_patch_writes_share_one_transaction(self, db: FakeDb) -> None:
        """Role, name and email at once: the users UPDATE, the email_changed email, the
        reset-token DELETE and both audit rows run on one connection in one transaction."""
        _, token = _admin(db)
        target = db.add_account(role="editor", email="old.address@example.ch")
        db.add_reset_token(target)

        response = _patch(
            _client(_app()),
            token,
            target,
            {"role": "org_admin", "name": "New Name", "email": "new.address@example.ch"},
        )

        assert response.status_code == 200
        assert len(db.audit) == 2
        _assert_one_transaction(
            db,
            [
                r"^update users\b",
                r"^insert into email_outbox\b",
                r"^delete from password_reset_tokens\b",
                r"^insert into audit_events\b",
            ],
        )

    def test_org_users_api_reset_writes_share_one_transaction(self, db: FakeDb) -> None:
        """The token upsert, the password_reset email and the audit row commit together."""
        _, token = _admin(db)
        target = db.add_account()

        response = _reset(_client(_app()), token, target)

        assert response.status_code == 202
        _assert_one_transaction(
            db,
            [
                r"^insert into password_reset_tokens\b",
                r"^insert into email_outbox\b",
                r"^insert into audit_events\b",
            ],
        )


# ---------------------------------------------------------------------------
# 12. No content in logs or audit rows
# ---------------------------------------------------------------------------


class TestNoContent:
    """Emails, names, tokens and links never reach a log line or an audit row."""

    def _flow(self, db: FakeDb) -> str:
        """Change a name and an email, refuse a taken email, reset, list; return the raw
        reset token issued."""
        _, token = _admin(db, email="log.marker.admin@example.ch", name="Admin Markername")
        target = db.add_account(email="log.marker.target@example.ch", name="Target Markername")
        db.add_reset_token(target)
        db.add_account(
            org_id=OTHER_ORG_ID, email="log.marker.taken@example.ch", name="Taken Markername"
        )
        client = _client(_app())
        changed = _patch(
            client,
            token,
            target,
            {"name": "Grace Markername", "email": "log.marker.new@example.ch"},
        )
        assert changed.status_code == 200
        assert db.outbox[-1]["template_key"] == "email_changed"
        taken = _patch(client, token, target, {"email": "LOG.MARKER.TAKEN@example.ch"})
        assert taken.status_code == 409
        assert _reset(client, token, target).status_code == 202
        assert _list(client, token).status_code == 200
        return db.issued_token()

    def test_org_users_api_flow_logs_no_content(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        raw = self._flow(db)

        text = _server_log_text(caplog).lower()
        assert "log.marker" not in text
        assert "markername" not in text
        assert "reset-password" not in text
        assert raw.lower() not in text
        assert sha256(raw).hex() not in text

    def test_org_users_api_audit_rows_carry_no_content(self, db: FakeDb) -> None:
        raw = self._flow(db)

        stored = json.dumps(db.audit, default=str).lower()
        assert {row["action"] for row in db.audit} >= {
            "user.profile_change",
            "password_reset.request",
        }
        assert "log.marker" not in stored
        assert "markername" not in stored
        assert "reset-password" not in stored
        assert raw.lower() not in stored


# ---------------------------------------------------------------------------
# 13. Seat usage in the list (GH-165)
# ---------------------------------------------------------------------------

_SEATS = 10
_KEY_STATUS = "/api/org/users/status"
_KEY_DELETE = "/api/org/users/delete"
_KEY_REVOKE = "/api/org/invitations/revoke"


def _seats(client: TestClient, token: str) -> dict[str, Any]:
    """The ``seats`` object of a successful GET /api/org/users."""
    response = _list(client, token)
    assert response.status_code == 200, response.text
    body = response.json()
    assert "seats" in body, body
    seats: dict[str, Any] = body["seats"]
    return seats


def _numbers(used: int, limit: int = _SEATS) -> dict[str, int]:
    return {"used": used, "limit": limit}


class TestListSeats:
    """{"seats": {"used", "limit"}} next to the users, from the same request."""

    @pytest.fixture(autouse=True)
    def _roomy_lifecycle_buckets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The flows below call the status, delete and revoke routes a few times each."""
        for key in (_KEY_STATUS, _KEY_DELETE, _KEY_REVOKE):
            monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))

    def test_org_users_api_seats_has_exactly_used_and_limit(self, db: FakeDb) -> None:
        """A fresh org with 10 seats and only its Org Admin: {"used": 1, "limit": 10}, both
        JSON integers."""
        db.add_org(ORG_ID, seats=_SEATS)
        _, token = _admin(db)

        seats = _seats(_client(_app()), token)

        assert seats == _numbers(1)
        assert set(seats) == {"used", "limit"}
        assert all(type(value) is int for value in seats.values())

    def test_org_users_api_seats_count_active_and_invited_users_only(self, db: FakeDb) -> None:
        """Counted: the admin, two Editors, a pending and an expired invitation (5).
        Not counted: a deactivated user, a deleted user, another org's users and
        invitations, a Super Admin."""
        db.add_org(ORG_ID, seats=_SEATS)
        _, token = _admin(db)
        db.add_account(role="editor")
        db.add_account(role="editor")
        _invited(db)
        expired = db.add_account(role="editor", status="invited", name=None, password_hash=None)
        db.add_invitation(expired, sent_ago=timedelta(days=10))
        db.add_account(role="editor", status="deactivated")
        db.add_account(deleted_at=_DELETED_AT)
        _admin(db, org_id=OTHER_ORG_ID)
        db.add_account(org_id=OTHER_ORG_ID)
        _invited(db, org_id=OTHER_ORG_ID)
        db.add_account(kind="super_admin", role=None)

        response = _list(_client(_app()), token)

        assert response.status_code == 200, response.text
        assert response.json()["seats"] == _numbers(5)
        assert len(response.json()["users"]) == 4  # the users list itself is unchanged

    @pytest.mark.parametrize("limit", [1, 7, 500])
    def test_org_users_api_seats_limit_is_the_orgs_seats(self, db: FakeDb, limit: int) -> None:
        db.add_org(ORG_ID, seats=limit)
        db.add_org(OTHER_ORG_ID, seats=42)
        _, token = _admin(db)

        assert _seats(_client(_app()), token) == _numbers(1, limit)

    def test_org_users_api_seats_of_another_org_are_its_own(self, db: FakeDb) -> None:
        """Org B's admin gets org B's count and limit, whatever org A holds."""
        db.add_org(ORG_ID, seats=_SEATS)
        db.add_org(OTHER_ORG_ID, seats=3)
        _admin(db)
        db.add_account(role="editor")
        _invited(db)
        _, other_token = _admin(db, org_id=OTHER_ORG_ID)
        _invited(db, org_id=OTHER_ORG_ID)

        assert _seats(_client(_app()), other_token) == _numbers(2, 3)

    def test_org_users_api_seats_follow_an_invitation_and_its_revocation(self, db: FakeDb) -> None:
        """POST /api/org/invitations takes a seat at once; revoking it frees the seat."""
        db.add_org(ORG_ID, seats=_SEATS)
        _, token = _admin(db)
        db.add_account(role="editor")
        client = _client(_app())
        before = _seats(client, token)

        invited = _invite(client, token, "seat.invitee@example.ch")
        assert invited.status_code == 201, invited.text
        after_invite = _seats(client, token)
        revoked = client.delete(f"{_INVITES}/{invited.json()['id']}", headers=_cookie(token))
        assert revoked.status_code == 204, revoked.text
        after_revoke = _seats(client, token)

        assert (before, after_invite, after_revoke) == (_numbers(2), _numbers(3), _numbers(2))

    def test_org_users_api_seats_follow_deactivation_and_reactivation(self, db: FakeDb) -> None:
        """A deactivated user frees a seat; reactivating takes it again."""
        db.add_org(ORG_ID, seats=_SEATS)
        _, token = _admin(db)
        target = db.add_account(role="editor")
        client = _client(_app())
        before = _seats(client, token)

        deactivated = client.post(f"{_user_url(target)}/deactivate", headers=_cookie(token))
        assert deactivated.status_code == 200, deactivated.text
        after_deactivate = _seats(client, token)
        reactivated = client.post(f"{_user_url(target)}/reactivate", headers=_cookie(token))
        assert reactivated.status_code == 200, reactivated.text
        after_reactivate = _seats(client, token)

        assert (before, after_deactivate, after_reactivate) == (
            _numbers(2),
            _numbers(1),
            _numbers(2),
        )

    def test_org_users_api_seats_follow_a_deletion(self, db: FakeDb) -> None:
        db.add_org(ORG_ID, seats=_SEATS)
        _, token = _admin(db)
        target = db.add_account(role="editor")
        client = _client(_app())
        before = _seats(client, token)

        deleted = client.delete(_user_url(target), headers=_cookie(token))
        assert deleted.status_code == 204, deleted.text

        assert (before, _seats(client, token)) == (_numbers(2), _numbers(1))

    def test_org_users_api_seats_follow_a_seats_change(self, db: FakeDb) -> None:
        """Read on every request: a changed seat limit shows on the next GET."""
        db.add_org(ORG_ID, seats=_SEATS)
        _, token = _admin(db)
        client = _client(_app())
        before = _seats(client, token)
        db.add_org(ORG_ID, seats=4)

        assert (before, _seats(client, token)) == (_numbers(1), _numbers(1, 4))

    def test_org_users_api_seats_use_the_list_bucket_only(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One GET spends one token of /api/org/users/get and no other bucket."""
        db.add_org(ORG_ID, seats=_SEATS)
        _, token = _admin(db)
        app = _app()
        real = server._check_rate_limit
        keys: list[str] = []

        def spy(route: str, caller: str) -> None:
            keys.append(route)
            real(route, caller)

        monkeypatch.setattr(server, "_check_rate_limit", spy)

        seats = _seats(_client(app), token)

        assert seats == _numbers(1)
        assert keys == [_KEY_LIST]

    def test_org_users_api_seats_change_nothing(self, db: FakeDb) -> None:
        """Reading the seat usage writes, queues and audits nothing."""
        db.add_org(ORG_ID, seats=_SEATS)
        _, token = _admin(db)
        _invited(db)
        before = _state(db)

        seats = _seats(_client(_app()), token)

        assert seats == _numbers(2)
        assert _state(db) == before
