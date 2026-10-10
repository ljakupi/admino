"""HTTP-layer spec for the Org Admin user lifecycle routes (GH-164).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns). The real
``admino.org_users``, ``admino.accounts``, ``admino.sessions``,
``admino.email_outbox`` and ``admino.audit_events`` code runs, through the real
``require_session`` and real session cookies; only Argon2 is replaced by a fast
fake.

What these tests pin down:
- ``POST /api/org/users/{user_id}/deactivate`` → 200 with the user's summary
  (status "deactivated"). Every session of the user is deleted, so their cookie
  is refused on its very next request; one ``user.deactivate`` audit row
  (metadata ``{"sessions_revoked": n}``, the client IP) and one queued
  ``account_deactivated`` email. Connections, memory and the user's persisted
  chats (GH-176) are kept.
- ``POST /api/org/users/{user_id}/reactivate`` → 200 with the summary (status
  "active"); the user can log in again; one ``user.activate`` audit row and one
  queued ``account_activated`` email whose login link is ``<public_url>/login``.
  A full org (active + invited users >= seats) → 409 ``seat_limit``.
- ``DELETE /api/org/users/{user_id}`` → 204 empty. The users row, the sessions,
  the OAuth connections, the memory, the user settings and (GH-176) the user's
  chats with their messages (the users row's ON DELETE CASCADE) are gone; one
  ``user.delete`` audit row. The server also forgets the user's in-memory state
  (cached access tokens, their entries in ``server._chat_runtime``: pending
  confirmations and chat locks, via ``ChatRuntime.forget_user``; pending OAuth
  states); other users' entries and chats stay. A refused delete forgets nothing.
- Wrong status → 409 ``invalid_status``; the org's last active Org Admin → 409
  ``last_admin``; another org's user, an unknown id, an invited account, a
  deleted user or a Super Admin → 404 ``{"detail": "User not found"}`` with the
  same bytes; an Editor and a Super Admin → 403
  ``{"detail": "Forbidden"}``. Nothing changes on any refusal.
- Self-deactivation and self-deletion (allowed when another active Org Admin
  remains) clear the ``admino_session`` cookie; any other target leaves it alone.
- Every route depends on ``require_session`` (401 without a cookie), asks
  ``admino.access.can()`` for ``org.users.manage``, spends a per-user rate-limit
  bucket (deactivate and reactivate share ``/api/org/users/status``; delete has
  ``/api/org/users/delete``), is refused cross-origin and answers a non-UUID id
  with a 422 that doesn't echo it. An audit failure is a 500 that changes nothing.
- No name or email of the target reaches a log line or an audit row.

All database calls are faked. No network, no real PostgreSQL, no SMTP.

Security notes:
- Tenant isolation: another org's user answers 404 like an unknown id.
- Immediate revocation: a deactivated or deleted user's cookie stops working at once.
- Fail closed: an audit failure is a 500 and nothing is written or forgotten.
"""

from __future__ import annotations

import contextlib
import copy
import json
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import invitations, server
from admino import oauth as oauth_mod
from admino.access import Capability
from admino.models import PendingConfirmation, ToolCall
from admino.server import create_app
from tests.db_fakes import ORG_ID, ORG_NAME, OTHER_ORG_ID, PUBLIC_URL, FakeDb, fake_hash

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_PASSWORD = "copper-Lantern-58-meadow"
_IP_A = "203.0.113.5"
_IP_B = "198.51.100.23"
_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}
_USER_NOT_FOUND = {"detail": "User not found"}
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_INVALID_STATUS = {
    "detail": "This change isn't possible in the user's current status.",
    "reason": "invalid_status",
}
_LAST_ADMIN = {
    "detail": "An organization must keep at least one active Org Admin.",
    "reason": "last_admin",
}
_SEAT_LIMIT = {"detail": invitations.SEAT_LIMIT_MESSAGE, "reason": "seat_limit"}
_SUMMARY_KEYS = {"id", "name", "email", "role", "status", "created_at", "last_login_at"}

_STATUS_KEY = "/api/org/users/status"
_DELETE_KEY = "/api/org/users/delete"
_EXPECTED_LIMITS: dict[str, tuple[float, int]] = {
    _STATUS_KEY: (0.5, 5),
    _DELETE_KEY: (0.2, 5),
}

# route name -> (method, path template)
_ROUTES: dict[str, tuple[str, str]] = {
    "deactivate": ("POST", "/api/org/users/{user_id}/deactivate"),
    "reactivate": ("POST", "/api/org/users/{user_id}/reactivate"),
    "delete": ("DELETE", "/api/org/users/{user_id}"),
}
_ROUTE_NAMES = list(_ROUTES)
# The status a target needs for the route to succeed.
_READY_STATUS = {"deactivate": "active", "reactivate": "deactivated", "delete": "active"}
_SUCCESS_CODE = {"deactivate": 200, "reactivate": 200, "delete": 204}

_TARGET_EMAIL = "lifecycle.marker.target@example.test"
_TARGET_NAME = "Quillonmarker Person"


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
def configured_limits(monkeypatch: pytest.MonkeyPatch) -> dict[str, tuple[float, int] | None]:
    """Functional tests aren't about rate limits: give both buckets a large size (the
    rate-limit tests set their own). Returns what the server configured itself for the
    two keys, before this fixture patched them (None when a key is missing)."""
    present = {key: server._RATE_LIMITS.get(key) for key in _EXPECTED_LIMITS}
    for key in _EXPECTED_LIMITS:
        monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))
    return present


@pytest.fixture(autouse=True)
def _clean_memory_state() -> Iterator[None]:
    """create_app clears the server's in-memory chat state; clear it after each test too
    so the entries seeded here never reach another test. (GH-176: the chat runtime is
    looked up when it is needed, so a server without it fails only the tests using it.)"""
    yield
    runtime = getattr(server, "_chat_runtime", None)
    if runtime is not None:
        runtime.clear()
    server._oauth_pending_states.clear()


@pytest.fixture()
def invalidate(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """A spy in place of the access-token cache's invalidate (oauth.access_tokens)."""
    spy = AsyncMock(return_value=None)
    monkeypatch.setattr(oauth_mod.access_tokens, "invalidate", spy)
    return spy


def _config() -> MagicMock:
    """A minimal config with the public URL the activation email's login link uses."""
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


def _cookie(token: str, **extra: str) -> dict[str, str]:
    """Request headers carrying a session cookie (plus any extra headers)."""
    return {"Cookie": f"{_COOKIE}={token}", **extra}


def _session_cookie_headers(response: httpx.Response) -> list[str]:
    """Every Set-Cookie header naming admino_session."""
    return [
        h for h in response.headers.get_list("set-cookie") if h.lower().startswith(f"{_COOKIE}=")
    ]


def _session_set_cookie(response: httpx.Response) -> tuple[str, dict[str, str | None]]:
    """Return (value, attributes) of the one admino_session Set-Cookie header."""
    headers = _session_cookie_headers(response)
    assert len(headers) == 1, response.headers.get_list("set-cookie")
    parts = [part.strip() for part in headers[0].split(";")]
    value = parts[0].split("=", 1)[1]
    attributes: dict[str, str | None] = {}
    for part in parts[1:]:
        key, sep, attr_value = part.partition("=")
        attributes[key.strip().lower()] = attr_value.strip() if sep else None
    return value, attributes


def _assert_cookie_cleared(response: httpx.Response) -> None:
    """The response makes the browser drop admino_session (empty value, Max-Age=0, path /)."""
    value, attributes = _session_set_cookie(response)
    assert value in {"", '""'}
    assert attributes.get("max-age") == "0"
    assert attributes.get("path") == "/"


def _depends_on(dependant: Dependant, target: Callable[..., Any]) -> bool:
    """True when the dependency tree below ``dependant`` contains ``target``."""
    return any(dep.call is target or _depends_on(dep, target) for dep in dependant.dependencies)


def _route(app: FastAPI, name: str) -> APIRoute:
    """The one APIRoute registered for the named route's (method, path)."""
    method, path = _ROUTES[name]
    matches = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == path and method in route.methods
    ]
    assert len(matches) == 1, f"{method} {path} is not registered"
    return matches[0]


def _call(
    client: TestClient, name: str, user_id: object, token: str | None, **headers: str
) -> httpx.Response:
    """Send the named route for ``user_id`` with the session ``token`` (None: no cookie)."""
    method, path = _ROUTES[name]
    request_headers = _cookie(token, **headers) if token is not None else dict(headers)
    return client.request(method, path.format(user_id=user_id), headers=request_headers)


def _deactivate(client: TestClient, token: str, user_id: object, **h: str) -> httpx.Response:
    return _call(client, "deactivate", user_id, token, **h)


def _reactivate(client: TestClient, token: str, user_id: object, **h: str) -> httpx.Response:
    return _call(client, "reactivate", user_id, token, **h)


def _delete(client: TestClient, token: str, user_id: object, **h: str) -> httpx.Response:
    return _call(client, "delete", user_id, token, **h)


def _member(db: FakeDb, **fields: Any) -> uuid.UUID:
    """An account (an Editor of ORG_ID unless told otherwise) that can log in with
    _PASSWORD."""
    fields.setdefault("password_hash", fake_hash(_PASSWORD))
    return db.add_account(**fields)


def _admin(db: FakeDb, **fields: Any) -> tuple[uuid.UUID, str]:
    """An active Org Admin of ORG_ID with a live session: (user id, session token)."""
    user_id = _member(db, role="org_admin", **fields)
    return user_id, db.open_session(user_id)


def _actor_token(db: FakeDb, who: str) -> str:
    """A live session of a Super Admin or of a member of ORG_ID with the given role."""
    if who == "super_admin":
        return db.open_session(_member(db, kind="super_admin", role=None))
    return db.open_session(_member(db, role=who))


def _target(db: FakeDb, name: str, **fields: Any) -> uuid.UUID:
    """A target of ORG_ID in the status the named route needs to succeed."""
    fields.setdefault("status", _READY_STATUS[name])
    return _member(db, **fields)


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of every table the routes may touch (sessions by key), for "nothing
    changed" checks."""
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
            "sessions": sorted(db.sessions),
        }
    )


def _emails(db: FakeDb, user_id: uuid.UUID, template_key: str) -> list[dict[str, Any]]:
    """The queued emails of one template for one user."""
    return [
        row
        for row in db.outbox
        if str(row["user_id"]) == str(user_id) and row["template_key"] == template_key
    ]


def _connect(db: FakeDb, user_id: uuid.UUID) -> None:
    """Give the user a Google and a Microsoft connection, two notes and settings."""
    db.add_oauth_token(user_id, "google", encrypted_refresh_token="enc-google-refresh")
    db.add_oauth_token(user_id, "microsoft", encrypted_refresh_token="enc-microsoft-refresh")
    db.add_memory(user_id, "favourite colour", "teal")
    db.add_memory(user_id, "project", "annual report")
    db.add_user_settings(user_id, theme="dark")


def _assert_connected(db: FakeDb, user_id: uuid.UUID) -> None:
    """The user's connections, notes and settings are all still stored."""
    assert db.oauth_token(user_id, "google") is not None
    assert db.oauth_token(user_id, "microsoft") is not None
    assert db.memories_of(user_id) == {"favourite colour": "teal", "project": "annual report"}
    assert user_id in db.user_settings


def _seed_chat(db: FakeDb, user_id: uuid.UUID) -> uuid.UUID:
    """A persisted chat of the user (GH-176) with one message; return its id."""
    chat_id = db.add_chat(user_id)
    db.add_chat_message(chat_id, "user", "hello")
    return chat_id


def _seed_memory_state(db: FakeDb, target: uuid.UUID, other: uuid.UUID) -> list[uuid.UUID]:
    """Chat state for two users: a persisted chat with a message, a pending confirmation of
    that chat in ``server._chat_runtime`` (which creates its runtime entry: the chat lock)
    and a pending OAuth state each. Call after create_app (it clears the runtime). Returns
    the chat ids (target's, other's)."""
    runtime = server._chat_runtime
    now = datetime.now(UTC)
    chats = []
    for user_id, label in ((target, "chat-1"), (other, "chat-2")):
        chat_id = _seed_chat(db, user_id)
        runtime.set_pending(
            chat_id,
            user_id,
            PendingConfirmation(
                confirmation_id=f"conf-{label}",
                session_id=str(chat_id),
                tool_call=ToolCall(tool="gmail", action="search", args={"query": "invoice"}),
                created_at=now,
                expires_at=now + timedelta(minutes=5),
            ),
        )
        chats.append(chat_id)
    for user_id, state in ((target, "state-of-the-target"), (other, "state-of-the-other")):
        server._oauth_pending_states[state] = server.OAuthPendingState(
            created_at=time.time(),
            provider="google",
            redirect_uri=PUBLIC_URL + "/api/oauth/callback",
            user_id=user_id,
            session_id=uuid.uuid4(),
        )
    return chats


def _memory_state(db: FakeDb, chats: list[uuid.UUID]) -> dict[str, Any]:
    """The seeded chats' stored rows and message counts, their pending confirmations in the
    chat runtime (confirmation id, None when gone), the runtime's entry count and the
    pending OAuth states' owners."""
    runtime = server._chat_runtime
    pending = {chat: runtime.get_pending(chat) for chat in chats}
    return {
        "chats": [chat for chat in chats if db.chat_row(chat) is not None],
        "messages": {chat: len(db.messages_of(chat)) for chat in chats},
        "pending": {
            chat: None if entry is None else entry.confirmation_id
            for chat, entry in pending.items()
        },
        "entries": len(runtime),
        "oauth": {state: entry.user_id for state, entry in server._oauth_pending_states.items()},
    }


def _invalidated(spy: AsyncMock) -> set[tuple[str, str]]:
    """Every (user id, provider) the access-token cache was told to forget."""
    seen: set[tuple[str, str]] = set()
    for awaited in spy.await_args_list:
        params = dict(zip(("user_id", "provider"), awaited.args, strict=False))
        params.update(awaited.kwargs)
        seen.add((str(params.get("user_id")), str(params.get("provider"))))
    return seen


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
        with contextlib.suppress(ImportError):
            from admino import org_users

            if hasattr(org_users, "can"):
                monkeypatch.setattr(org_users, "can", spy)


def _server_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured record (with its traceback) except the test client's own request log
    (httpx logs each request URL at INFO; the app runs uvicorn with access_log=False)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record) for record in caplog.records if not record.name.startswith("httpx")
    )


# ---------------------------------------------------------------------------
# 1. The routes exist, require a session and are rate-limited per user
# ---------------------------------------------------------------------------


class TestRoutes:
    """POST .../deactivate, POST .../reactivate and DELETE /api/org/users/{user_id}."""

    @pytest.mark.parametrize("name", _ROUTE_NAMES)
    def test_org_users_lifecycle_api_route_is_registered(self, name: str) -> None:
        _route(_app(), name)

    @pytest.mark.parametrize("name", _ROUTE_NAMES)
    def test_org_users_lifecycle_api_route_depends_on_require_session(self, name: str) -> None:
        """server.require_session is in the route's dependency tree."""
        route = _route(_app(), name)

        assert _depends_on(route.dependant, server.require_session)

    @pytest.mark.parametrize("name", _ROUTE_NAMES)
    def test_org_users_lifecycle_api_route_without_a_session_is_401(
        self, db: FakeDb, name: str
    ) -> None:
        """No cookie → 401 Unauthorized, and nothing is read or changed."""
        target = _target(db, name)
        before = _state(db)

        response = _call(_client(_app()), name, target, None)

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED
        assert db.calls == []
        assert _state(db) == before

    @pytest.mark.parametrize(("key", "rate"), list(_EXPECTED_LIMITS.items()))
    def test_org_users_lifecycle_api_rate_limits(
        self,
        configured_limits: dict[str, tuple[float, int] | None],
        key: str,
        rate: tuple[float, int],
    ) -> None:
        """(tokens per second, burst): deactivate and reactivate share the status bucket."""
        configured = configured_limits[key]
        assert configured is not None, f"{key} has no rate limit"
        assert configured == pytest.approx(rate)

    @pytest.mark.parametrize(
        "bad_id", ["not-a-uuid-ECHOMARK42", "1", "x" * 200, "00000000-0000-0000-0000-00000000000z"]
    )
    @pytest.mark.parametrize("name", _ROUTE_NAMES)
    def test_org_users_lifecycle_api_non_uuid_id_is_422_without_echo(
        self, db: FakeDb, name: str, bad_id: str
    ) -> None:
        """A path id that isn't a UUID → 422 without echo; nothing changes."""
        _route(_app(), name)
        _, token = _admin(db)
        before = _state(db)

        response = _call(_client(_app()), name, bad_id, token)

        assert response.status_code == 422
        assert "ECHOMARK42" not in response.text
        assert "x" * 20 not in response.text
        assert "00000000000z" not in response.text
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 2. Authorization: Org Admin only, through admino.access.can()
# ---------------------------------------------------------------------------


class TestAuthorization:
    """An Editor and a Super Admin are refused; can() decides."""

    @pytest.mark.parametrize("who", ["editor", "super_admin"])
    @pytest.mark.parametrize("name", _ROUTE_NAMES)
    def test_org_users_lifecycle_api_forbidden_without_org_users_manage(
        self, db: FakeDb, name: str, who: str
    ) -> None:
        """403 {"detail": "Forbidden"}; the target keeps its status, sessions, rows; nothing
        is audited or queued."""
        _route(_app(), name)
        token = _actor_token(db, who)
        target = _target(db, name)
        target_token = db.open_session(target) if name != "reactivate" else None
        _connect(db, target)
        before = _state(db)

        response = _call(_client(_app()), name, target, token)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        assert _state(db) == before
        assert target_token is None or not db.session_revoked(target_token)
        assert db.audit_rows() == []

    @pytest.mark.parametrize("name", _ROUTE_NAMES)
    def test_org_users_lifecycle_api_asks_for_org_users_manage(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        """An Org Admin succeeds, and org.users.manage was asked for."""
        spy = _CanSpy(monkeypatch)
        _, token = _admin(db)
        target = _target(db, name)

        response = _call(_client(_app()), name, target, token)

        assert response.status_code == _SUCCESS_CODE[name]
        assert Capability.ORG_USERS_MANAGE in spy.capabilities

    @pytest.mark.parametrize("name", _ROUTE_NAMES)
    def test_org_users_lifecycle_api_org_users_manage_refused_is_403(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        """When can() refuses org.users.manage even an Org Admin gets 403; nothing changes."""
        _route(_app(), name)
        _CanSpy(monkeypatch, deny=frozenset({Capability.ORG_USERS_MANAGE}))
        _, token = _admin(db)
        target = _target(db, name)
        before = _state(db)

        response = _call(_client(_app()), name, target, token)

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 3. Deactivate
# ---------------------------------------------------------------------------


class TestDeactivate:
    """POST /api/org/users/{user_id}/deactivate."""

    @pytest.mark.parametrize("role", ["editor", "org_admin"])
    def test_org_users_lifecycle_api_deactivate_returns_the_summary(
        self, db: FakeDb, role: str
    ) -> None:
        """200 with the user's OrgUserSummary (status "deactivated"); the row is
        deactivated. Another Org Admin can be deactivated while the caller stays active."""
        _, token = _admin(db)
        target = _member(db, role=role, email=_TARGET_EMAIL, name=_TARGET_NAME)

        response = _deactivate(_client(_app()), token, target)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == _SUMMARY_KEYS
        assert (body["id"], body["status"], body["role"]) == (str(target), "deactivated", role)
        assert (body["email"], body["name"]) == (_TARGET_EMAIL, _TARGET_NAME)
        assert db.users[target]["status"] == "deactivated"

    def test_org_users_lifecycle_api_deactivate_revokes_sessions_immediately(
        self, db: FakeDb
    ) -> None:
        """The target's cookie works before and is 401 on its very next request; every
        session row of the target is gone, everyone else's stays."""
        admin, admin_token = _admin(db)
        target = _member(db)
        target_token = db.open_session(target)
        other_device = db.open_session(target)
        bystander = db.open_session(_member(db))
        client = _client(_app())
        assert client.get("/api/auth/me", headers=_cookie(target_token)).status_code == 200

        response = _deactivate(client, admin_token, target)

        assert response.status_code == 200
        assert client.get("/api/auth/me", headers=_cookie(target_token)).status_code == 401
        assert db.sessions_of(target) == []
        assert db.session_revoked(other_device)
        assert not db.session_revoked(admin_token)
        assert not db.session_revoked(bystander)
        assert db.sessions_of(admin) != []

    def test_org_users_lifecycle_api_deactivate_is_audited(self, db: FakeDb) -> None:
        """One user.deactivate row: the admin, their org, target the user, the client IP,
        metadata {"sessions_revoked": 2}."""
        admin, admin_token = _admin(db)
        target = _member(db)
        db.open_session(target)
        db.open_session(target)

        response = _deactivate(_client(_app(), ip=_IP_B), admin_token, target)

        assert response.status_code == 200
        rows = db.audit_rows("user.deactivate")
        assert len(rows) == 1
        row = rows[0]
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == (
            "member",
            admin,
            ORG_ID,
        )
        assert (row["target_type"], row["target_ids"]) == ("user", [str(target)])
        assert row["ip"] == _IP_B
        assert row["metadata"] == {"sessions_revoked": 2}
        assert len(db.audit) == 1

    def test_org_users_lifecycle_api_deactivate_queues_the_status_email(self, db: FakeDb) -> None:
        """One account_deactivated email to the user, carrying only the org name."""
        _, admin_token = _admin(db)
        target = _member(db)

        response = _deactivate(_client(_app()), admin_token, target)

        assert response.status_code == 200
        rows = _emails(db, target, "account_deactivated")
        assert len(rows) == 1
        assert rows[0]["params"] == {"org_name": ORG_NAME}
        assert len(db.outbox) == 1

    def test_org_users_lifecycle_api_deactivate_keeps_connections_and_memory(
        self, db: FakeDb
    ) -> None:
        """Deactivation deletes sessions only: connections, notes, settings and the user's
        chats with their messages (GH-176) stay."""
        _, admin_token = _admin(db)
        target = _member(db)
        _connect(db, target)
        chat = _seed_chat(db, target)

        response = _deactivate(_client(_app()), admin_token, target)

        assert response.status_code == 200
        _assert_connected(db, target)
        assert [row["id"] for row in db.chats_of(target)] == [chat]
        assert [row["content"] for row in db.messages_of(chat)] == ["hello"]

    def test_org_users_lifecycle_api_deactivate_already_deactivated_is_409(
        self, db: FakeDb
    ) -> None:
        """409 invalid_status; nothing changes, nothing is audited or queued."""
        _route(_app(), "deactivate")
        _, admin_token = _admin(db)
        target = _member(db, status="deactivated")
        before = _state(db)

        response = _deactivate(_client(_app()), admin_token, target)

        assert response.status_code == 409
        assert response.json() == _INVALID_STATUS
        assert _state(db) == before

    @pytest.mark.parametrize("other_admin", [None, "deactivated", "invited", "other_org"])
    def test_org_users_lifecycle_api_deactivate_last_active_admin_is_409(
        self, db: FakeDb, other_admin: str | None
    ) -> None:
        """The org's only active Org Admin deactivating themselves → 409 last_admin (a
        deactivated or invited admin, or another org's admin, doesn't count); their
        sessions stay and nothing is audited or queued."""
        _route(_app(), "deactivate")
        admin, admin_token = _admin(db)
        if other_admin == "other_org":
            _member(db, role="org_admin", org_id=OTHER_ORG_ID)
        elif other_admin is not None:
            _member(db, role="org_admin", status=other_admin)
        before = _state(db)
        client = _client(_app())

        response = _deactivate(client, admin_token, admin)

        assert response.status_code == 409
        assert response.json() == _LAST_ADMIN
        assert _state(db) == before
        assert client.get("/api/auth/me", headers=_cookie(admin_token)).status_code == 200

    @pytest.mark.parametrize("case", ["other-org", "unknown", "invited", "deleted", "super-admin"])
    def test_org_users_lifecycle_api_deactivate_outside_the_org_is_404(
        self, db: FakeDb, case: str
    ) -> None:
        """Another org's user, an unknown id, an invited account, a deleted user or a Super
        Admin → 404 {"detail": "User not found"}; nothing changes."""
        _route(_app(), "deactivate")
        _, admin_token = _admin(db)
        target = _outsider(db, case, status="active")
        target_token = db.open_session(target) if target in db.users else None
        before = _state(db)

        response = _deactivate(_client(_app()), admin_token, target)

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND
        assert _state(db) == before
        assert target_token is None or not db.session_revoked(target_token)

    def test_org_users_lifecycle_api_deactivate_404_bodies_are_identical(self, db: FakeDb) -> None:
        """Another org's user, an invited account, a deleted user and an unknown id answer
        the same bytes."""
        _, admin_token = _admin(db)
        client = _client(_app())
        targets = [
            _outsider(db, case, status="active")
            for case in ("other-org", "invited", "deleted", "unknown")
        ]

        responses = [_deactivate(client, admin_token, target) for target in targets]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1

    def test_org_users_lifecycle_api_self_deactivation_clears_the_cookie(self, db: FakeDb) -> None:
        """An Org Admin deactivating themselves while another active Org Admin remains: 200,
        the session cookie is cleared and no longer works."""
        admin, admin_token = _admin(db)
        _admin(db)
        client = _client(_app())

        response = _deactivate(client, admin_token, admin)

        assert response.status_code == 200
        assert response.json()["status"] == "deactivated"
        _assert_cookie_cleared(response)
        assert db.sessions_of(admin) == []
        assert client.get("/api/auth/me", headers=_cookie(admin_token)).status_code == 401

    def test_org_users_lifecycle_api_deactivating_someone_else_leaves_the_cookie(
        self, db: FakeDb
    ) -> None:
        """Deactivating another user sets no admino_session cookie; the caller stays in."""
        _, admin_token = _admin(db)
        target = _member(db)
        client = _client(_app())

        response = _deactivate(client, admin_token, target)

        assert response.status_code == 200
        assert _session_cookie_headers(response) == []
        assert client.get("/api/auth/me", headers=_cookie(admin_token)).status_code == 200


def _outsider(db: FakeDb, case: str, *, status: str) -> uuid.UUID:
    """A user id the caller's org doesn't own: another org's user (in ``status``), an
    invited account, a deleted user, a Super Admin or an unknown id."""
    if case == "other-org":
        return _member(db, org_id=OTHER_ORG_ID, status=status)
    if case == "invited":
        return _member(db, status="invited", password_hash=None)
    if case == "deleted":
        return _member(db, status=status, deleted_at=datetime.now(UTC) - timedelta(days=1))
    if case == "super-admin":
        return _member(db, kind="super_admin", role=None)
    return uuid.uuid4()


# ---------------------------------------------------------------------------
# 4. Reactivate
# ---------------------------------------------------------------------------


class TestReactivate:
    """POST /api/org/users/{user_id}/reactivate."""

    def test_org_users_lifecycle_api_reactivate_returns_the_summary(self, db: FakeDb) -> None:
        """200 with the user's OrgUserSummary (status "active"); the row is active."""
        _, admin_token = _admin(db)
        target = _member(db, status="deactivated", email=_TARGET_EMAIL, name=_TARGET_NAME)

        response = _reactivate(_client(_app()), admin_token, target)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == _SUMMARY_KEYS
        assert (body["id"], body["status"], body["role"]) == (str(target), "active", "editor")
        assert (body["email"], body["name"]) == (_TARGET_EMAIL, _TARGET_NAME)
        assert db.users[target]["status"] == "active"
        assert _session_cookie_headers(response) == []

    def test_org_users_lifecycle_api_reactivated_user_can_log_in_again(
        self, db: FakeDb, login_delays: list[float]
    ) -> None:
        """Deactivated, the user's login is refused (401); reactivated, the same password
        logs in (204 with a session cookie)."""
        _, admin_token = _admin(db)
        target = _member(db, email=_TARGET_EMAIL)
        client = _client(_app())
        credentials = {"email": _TARGET_EMAIL, "password": _PASSWORD}

        assert _deactivate(client, admin_token, target).status_code == 200
        refused = client.post("/api/auth/login", json=credentials)
        client.cookies.clear()
        assert _reactivate(client, admin_token, target).status_code == 200
        accepted = client.post("/api/auth/login", json=credentials)
        client.cookies.clear()

        assert refused.status_code == 401
        assert _session_cookie_headers(refused) == []
        assert accepted.status_code == 204
        token, _ = _session_set_cookie(accepted)
        assert client.get("/api/auth/me", headers=_cookie(token)).status_code == 200

    def test_org_users_lifecycle_api_reactivate_is_audited(self, db: FakeDb) -> None:
        """One user.activate row: the admin, their org, target the user, the client IP."""
        admin, admin_token = _admin(db)
        target = _member(db, status="deactivated")

        response = _reactivate(_client(_app(), ip=_IP_B), admin_token, target)

        assert response.status_code == 200
        rows = db.audit_rows("user.activate")
        assert len(rows) == 1
        row = rows[0]
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == (
            "member",
            admin,
            ORG_ID,
        )
        assert (row["target_type"], row["target_ids"]) == ("user", [str(target)])
        assert row["ip"] == _IP_B
        assert len(db.audit) == 1

    def test_org_users_lifecycle_api_reactivate_queues_the_status_email(self, db: FakeDb) -> None:
        """One account_activated email: the org name and the login link
        <public_url>/login."""
        _, admin_token = _admin(db)
        target = _member(db, status="deactivated")

        response = _reactivate(_client(_app()), admin_token, target)

        assert response.status_code == 200
        rows = _emails(db, target, "account_activated")
        assert len(rows) == 1
        assert rows[0]["params"] == {"org_name": ORG_NAME, "login_link": PUBLIC_URL + "/login"}
        assert len(db.outbox) == 1

    def test_org_users_lifecycle_api_reactivate_active_user_is_409(self, db: FakeDb) -> None:
        """409 invalid_status; nothing changes, nothing is audited or queued."""
        _route(_app(), "reactivate")
        _, admin_token = _admin(db)
        target = _member(db)
        before = _state(db)

        response = _reactivate(_client(_app()), admin_token, target)

        assert response.status_code == 409
        assert response.json() == _INVALID_STATUS
        assert _state(db) == before

    def test_org_users_lifecycle_api_reactivate_in_a_full_org_is_409(self, db: FakeDb) -> None:
        """Active + invited users fill every seat (2 of 2) → 409 seat_limit; the user stays
        deactivated, nothing is audited or queued."""
        _route(_app(), "reactivate")
        _, admin_token = _admin(db)
        _member(db, status="invited", password_hash=None)
        target = _member(db, status="deactivated")
        db.add_org(ORG_ID, seats=2)
        before = _state(db)

        response = _reactivate(_client(_app()), admin_token, target)

        assert response.status_code == 409
        assert response.json() == _SEAT_LIMIT
        assert db.users[target]["status"] == "deactivated"
        assert _state(db) == before

    def test_org_users_lifecycle_api_reactivate_with_one_free_seat_succeeds(
        self, db: FakeDb
    ) -> None:
        """Deactivated and deleted users don't take a seat: 1 active + 1 invited of 3
        seats, plus other deactivated users → 200."""
        _, admin_token = _admin(db)
        _member(db, status="invited", password_hash=None)
        _member(db, status="deactivated")
        _member(db, status="active", deleted_at=datetime.now(UTC) - timedelta(days=1))
        _member(db, org_id=OTHER_ORG_ID)
        target = _member(db, status="deactivated")
        db.add_org(ORG_ID, seats=3)

        response = _reactivate(_client(_app()), admin_token, target)

        assert response.status_code == 200
        assert db.users[target]["status"] == "active"

    @pytest.mark.parametrize("case", ["other-org", "unknown", "invited", "deleted", "super-admin"])
    def test_org_users_lifecycle_api_reactivate_outside_the_org_is_404(
        self, db: FakeDb, case: str
    ) -> None:
        """Another org's (deactivated) user, an unknown id, an invited account, a deleted
        user or a Super Admin → 404 {"detail": "User not found"}; nothing changes."""
        _route(_app(), "reactivate")
        _, admin_token = _admin(db)
        target = _outsider(db, case, status="deactivated")
        before = _state(db)

        response = _reactivate(_client(_app()), admin_token, target)

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND
        assert _state(db) == before

    def test_org_users_lifecycle_api_reactivate_404_bodies_are_identical(self, db: FakeDb) -> None:
        _, admin_token = _admin(db)
        client = _client(_app())
        targets = [
            _outsider(db, case, status="deactivated")
            for case in ("other-org", "invited", "deleted", "unknown")
        ]

        responses = [_reactivate(client, admin_token, target) for target in targets]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1


# ---------------------------------------------------------------------------
# 5. Delete
# ---------------------------------------------------------------------------


class TestDelete:
    """DELETE /api/org/users/{user_id}."""

    def test_org_users_lifecycle_api_delete_is_204_empty(self, db: FakeDb) -> None:
        _, admin_token = _admin(db)
        target = _member(db)

        response = _delete(_client(_app()), admin_token, target)

        assert response.status_code == 204
        assert response.content == b""
        assert target not in db.users

    @pytest.mark.parametrize("status", ["active", "deactivated"])
    def test_org_users_lifecycle_api_delete_removes_account_sessions_connections_memory(
        self, db: FakeDb, status: str
    ) -> None:
        """The users row, every session, both OAuth connections, the notes and the settings
        are gone; another user's rows stay."""
        _, admin_token = _admin(db)
        target = _member(db, status=status)
        sessions = [db.open_session(target), db.open_session(target)]
        _connect(db, target)
        bystander = _member(db)
        bystander_token = db.open_session(bystander)
        _connect(db, bystander)

        response = _delete(_client(_app()), admin_token, target)

        assert response.status_code == 204
        assert target not in db.users
        assert all(db.session_revoked(token) for token in sessions)
        assert db.sessions_of(target) == []
        assert db.oauth_token(target, "google") is None
        assert db.oauth_token(target, "microsoft") is None
        assert db.memories_of(target) == {}
        assert target not in db.user_settings
        assert bystander in db.users
        assert not db.session_revoked(bystander_token)
        _assert_connected(db, bystander)

    def test_org_users_lifecycle_api_delete_revokes_the_cookie_immediately(
        self, db: FakeDb
    ) -> None:
        """The deleted user's cookie works before and is 401 on its very next request."""
        _, admin_token = _admin(db)
        target = _member(db)
        target_token = db.open_session(target)
        client = _client(_app())
        assert client.get("/api/auth/me", headers=_cookie(target_token)).status_code == 200

        response = _delete(client, admin_token, target)

        assert response.status_code == 204
        assert client.get("/api/auth/me", headers=_cookie(target_token)).status_code == 401

    def test_org_users_lifecycle_api_delete_is_audited(self, db: FakeDb) -> None:
        """One user.delete row (it survives the user): the admin, their org, target the
        user, the client IP, metadata {"sessions_revoked": 3}."""
        admin, admin_token = _admin(db)
        target = _member(db)
        for _ in range(3):
            db.open_session(target)

        response = _delete(_client(_app(), ip=_IP_B), admin_token, target)

        assert response.status_code == 204
        rows = db.audit_rows("user.delete")
        assert len(rows) == 1
        row = rows[0]
        assert (row["actor_kind"], row["actor_user_id"], row["org_id"]) == (
            "member",
            admin,
            ORG_ID,
        )
        assert (row["target_type"], row["target_ids"]) == ("user", [str(target)])
        assert row["ip"] == _IP_B
        assert row["metadata"] == {"sessions_revoked": 3}
        assert len(db.audit) == 1

    @pytest.mark.parametrize("other_admin", [None, "deactivated", "invited"])
    def test_org_users_lifecycle_api_delete_last_active_admin_is_409(
        self, db: FakeDb, other_admin: str | None
    ) -> None:
        """The org's only active Org Admin deleting themselves → 409 last_admin; their row,
        sessions, connections and notes stay; nothing is audited."""
        _route(_app(), "delete")
        admin, admin_token = _admin(db)
        _connect(db, admin)
        if other_admin is not None:
            _member(db, role="org_admin", status=other_admin)
        before = _state(db)
        client = _client(_app())

        response = _delete(client, admin_token, admin)

        assert response.status_code == 409
        assert response.json() == _LAST_ADMIN
        assert _state(db) == before
        assert client.get("/api/auth/me", headers=_cookie(admin_token)).status_code == 200

    def test_org_users_lifecycle_api_self_deletion_clears_the_cookie(self, db: FakeDb) -> None:
        """An Org Admin deleting themselves while another active Org Admin remains: 204, the
        cookie is cleared, the row is gone and the cookie no longer works."""
        admin, admin_token = _admin(db)
        _admin(db)
        client = _client(_app())

        response = _delete(client, admin_token, admin)

        assert response.status_code == 204
        _assert_cookie_cleared(response)
        assert admin not in db.users
        assert client.get("/api/auth/me", headers=_cookie(admin_token)).status_code == 401

    def test_org_users_lifecycle_api_deleting_someone_else_leaves_the_cookie(
        self, db: FakeDb
    ) -> None:
        _, admin_token = _admin(db)
        target = _member(db, role="org_admin")
        client = _client(_app())

        response = _delete(client, admin_token, target)

        assert response.status_code == 204
        assert _session_cookie_headers(response) == []
        assert client.get("/api/auth/me", headers=_cookie(admin_token)).status_code == 200

    @pytest.mark.parametrize("case", ["other-org", "unknown", "invited", "deleted", "super-admin"])
    def test_org_users_lifecycle_api_delete_outside_the_org_is_404(
        self, db: FakeDb, case: str
    ) -> None:
        """Another org's user, an unknown id, an invited account, a deleted user or a Super
        Admin → 404 {"detail": "User not found"}; nothing is removed."""
        _route(_app(), "delete")
        _, admin_token = _admin(db)
        target = _outsider(db, case, status="active")
        if case == "other-org":
            db.open_session(target)
            _connect(db, target)
        before = _state(db)

        response = _delete(_client(_app()), admin_token, target)

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND
        assert _state(db) == before

    def test_org_users_lifecycle_api_delete_404_bodies_are_identical(self, db: FakeDb) -> None:
        _, admin_token = _admin(db)
        client = _client(_app())
        targets = [
            _outsider(db, case, status="active")
            for case in ("other-org", "invited", "deleted", "unknown")
        ]

        responses = [_delete(client, admin_token, target) for target in targets]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1


# ---------------------------------------------------------------------------
# 6. Delete forgets the user's in-memory state
# ---------------------------------------------------------------------------


class TestDeleteForgetsMemoryState:
    """Cached access tokens, chats, confirmations, chat locks and OAuth states."""

    def test_org_users_lifecycle_api_delete_forgets_the_users_memory_state(
        self, db: FakeDb, invalidate: AsyncMock
    ) -> None:
        """After the delete, the target's chat and its messages are gone (CASCADE), so are
        the target's chat-runtime entry with its pending confirmation and the target's
        pending OAuth state; the other user's chat, pending confirmation, runtime entry and
        OAuth state stay, and the access-token cache forgot both providers of the target
        (and nobody else)."""
        _, admin_token = _admin(db)
        target = _member(db)
        other = _member(db)
        app = _app()
        target_chat, other_chat = _seed_memory_state(db, target, other)

        response = _delete(_client(app), admin_token, target)

        assert response.status_code == 204
        assert _memory_state(db, [target_chat, other_chat]) == {
            "chats": [other_chat],
            "messages": {target_chat: 0, other_chat: 1},
            "pending": {target_chat: None, other_chat: "conf-chat-2"},
            "entries": 1,
            "oauth": {"state-of-the-other": other},
        }
        calls = _invalidated(invalidate)
        assert {(str(target), "google"), (str(target), "microsoft")} <= calls
        assert {user for user, _ in calls} == {str(target)}

    @pytest.mark.parametrize("refusal", ["forbidden", "not-found", "last-admin"])
    def test_org_users_lifecycle_api_refused_delete_forgets_nothing(
        self, db: FakeDb, invalidate: AsyncMock, refusal: str
    ) -> None:
        """A 403, 404 or 409 delete leaves both users' chats, every chat-runtime entry,
        the pending OAuth states and the token cache alone."""
        _route(_app(), "delete")
        admin, admin_token = _admin(db)
        if refusal == "forbidden":
            token = _actor_token(db, "editor")
            target = _member(db)
        elif refusal == "not-found":
            token = admin_token
            target = _member(db, org_id=OTHER_ORG_ID)
        else:
            token = admin_token
            target = admin
        other = _member(db)
        app = _app()
        chats = _seed_memory_state(db, target, other)
        before = _memory_state(db, chats)

        response = _delete(_client(app), token, target)

        assert (
            response.status_code == {"forbidden": 403, "not-found": 404, "last-admin": 409}[refusal]
        )
        assert _memory_state(db, chats) == before
        assert before["entries"] == 2
        invalidate.assert_not_awaited()
        assert target in db.users


# ---------------------------------------------------------------------------
# 7. Rate limits (per user)
# ---------------------------------------------------------------------------


class TestRateLimits:
    """Deactivate and reactivate share one per-user bucket; delete has its own."""

    def test_org_users_lifecycle_api_status_bucket_is_shared_and_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a burst of 1, an admin's deactivate spends the bucket their reactivate needs
        (429), while another admin of the same org is still served."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _STATUS_KEY, (0.001, 1))
        first, token_a = _admin(db)
        _, token_b = _admin(db)
        target = _member(db)
        client = _client(app)

        deactivated = _deactivate(client, token_a, target)
        exhausted = _reactivate(client, token_a, target)
        other = _reactivate(client, token_b, target)

        assert deactivated.status_code == 200
        assert exhausted.status_code == 429
        assert exhausted.json() == _RATE_LIMITED
        assert other.status_code == 200
        assert db.users[target]["status"] == "active"
        assert (_STATUS_KEY, f"user:{first}") in server._rate_buckets

    def test_org_users_lifecycle_api_throttled_deactivate_changes_nothing(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty status bucket → 429 before any change: the second target stays active
        with its sessions."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _STATUS_KEY, (0.001, 1))
        _, token = _admin(db)
        first_target = _member(db)
        second_target = _member(db)
        second_token = db.open_session(second_target)
        client = _client(app)

        assert _deactivate(client, token, first_target).status_code == 200
        before = _state(db)
        exhausted = _deactivate(client, token, second_target)

        assert exhausted.status_code == 429
        assert exhausted.json() == _RATE_LIMITED
        assert _state(db) == before
        assert not db.session_revoked(second_token)

    def test_org_users_lifecycle_api_delete_bucket_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bucket is ("/api/org/users/delete", "user:<id>"): one admin spending it
        doesn't throttle another; the throttled delete removes nothing."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _DELETE_KEY, (0.001, 1))
        first, token_a = _admin(db)
        _, token_b = _admin(db)
        targets = [_member(db), _member(db)]
        client = _client(app)

        deleted = _delete(client, token_a, targets[0])
        exhausted = _delete(client, token_a, targets[1])
        kept = targets[1] in db.users
        other = _delete(client, token_b, targets[1])

        assert deleted.status_code == 204
        assert exhausted.status_code == 429
        assert exhausted.json() == _RATE_LIMITED
        assert kept
        assert other.status_code == 204
        assert (_DELETE_KEY, f"user:{first}") in server._rate_buckets

    def test_org_users_lifecycle_api_delete_bucket_is_separate_from_status(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Spending the status bucket doesn't throttle a delete (and vice versa)."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, _STATUS_KEY, (0.001, 1))
        monkeypatch.setitem(server._RATE_LIMITS, _DELETE_KEY, (0.001, 1))
        _, token = _admin(db)
        client = _client(app)

        deactivated = _deactivate(client, token, _member(db))
        deleted = _delete(client, token, _member(db))

        assert (deactivated.status_code, deleted.status_code) == (200, 204)


# ---------------------------------------------------------------------------
# 8. CSRF: refused cross-origin
# ---------------------------------------------------------------------------


class TestCrossOrigin:
    """State-changing requests from another origin never run."""

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
        ],
    )
    @pytest.mark.parametrize("name", _ROUTE_NAMES)
    def test_org_users_lifecycle_api_cross_origin_is_refused(
        self, db: FakeDb, name: str, headers: dict[str, str]
    ) -> None:
        """403 before anything runs; the target keeps its status, sessions and rows."""
        _route(_app(), name)
        _, admin_token = _admin(db)
        target = _target(db, name)
        target_token = db.open_session(target)
        _connect(db, target)
        before = _state(db)

        response = _call(_client(_app()), name, target, admin_token, **headers)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert _state(db) == before
        assert not db.session_revoked(target_token)


# ---------------------------------------------------------------------------
# 9. Fail closed: an audit failure changes nothing
# ---------------------------------------------------------------------------


class TestAuditFailure:
    """The audit row is written in the same transaction as the change."""

    @pytest.mark.parametrize("name", _ROUTE_NAMES)
    def test_org_users_lifecycle_api_audit_failure_is_500_and_changes_nothing(
        self, db: FakeDb, name: str
    ) -> None:
        """500; status, sessions, connections, notes, outbox and audit are unchanged, and
        the audit insert really was attempted."""
        _route(_app(), name)
        _, admin_token = _admin(db)
        target = _target(db, name)
        target_token = db.open_session(target)
        _connect(db, target)
        before = _state(db)
        db.fail_audit = True

        response = _call(_client(_app(), raise_server_exceptions=False), name, target, admin_token)

        assert response.status_code == 500
        assert db.matching(r"^insert into audit_events\b") != []
        assert _state(db) == before
        assert not db.session_revoked(target_token)
        assert db.users[target]["status"] == _READY_STATUS[name]

    def test_org_users_lifecycle_api_delete_audit_failure_forgets_nothing(
        self, db: FakeDb, invalidate: AsyncMock
    ) -> None:
        """A delete that fails on the audit write leaves the chats, the chat runtime's
        entries, the pending OAuth states and the token cache alone."""
        _, admin_token = _admin(db)
        target = _member(db)
        other = _member(db)
        app = _app()
        chats = _seed_memory_state(db, target, other)
        before = _memory_state(db, chats)
        db.fail_audit = True

        response = _delete(_client(app, raise_server_exceptions=False), admin_token, target)

        assert response.status_code == 500
        assert db.matching(r"^insert into audit_events\b") != []
        assert _memory_state(db, chats) == before
        assert before["entries"] == 2
        invalidate.assert_not_awaited()
        assert target in db.users


# ---------------------------------------------------------------------------
# 10. No content in logs or audit rows
# ---------------------------------------------------------------------------


class TestNoContentInLogs:
    """The target's name and email never reach a log line or an audit row."""

    def _flow(self, db: FakeDb) -> None:
        """Deactivate (twice: one refusal), reactivate (twice: one refusal), delete."""
        _, admin_token = _admin(db, email="lifecycle.marker.admin@example.test")
        target = _member(db, email=_TARGET_EMAIL, name=_TARGET_NAME)
        db.open_session(target)
        _connect(db, target)
        client = _client(_app())
        assert _deactivate(client, admin_token, target).status_code == 200
        assert _deactivate(client, admin_token, target).status_code == 409
        assert _reactivate(client, admin_token, target).status_code == 200
        assert _reactivate(client, admin_token, target).status_code == 409
        assert _delete(client, admin_token, target).status_code == 204
        assert _delete(client, admin_token, target).status_code == 404
        assert {row["action"] for row in db.audit} >= {
            "user.deactivate",
            "user.activate",
            "user.delete",
        }

    def test_org_users_lifecycle_api_flow_logs_no_content(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        self._flow(db)

        text = _server_log_text(caplog).lower()
        assert "lifecycle.marker" not in text
        assert "quillonmarker" not in text
        assert "enc-google-refresh" not in text

    def test_org_users_lifecycle_api_audit_rows_carry_no_content(self, db: FakeDb) -> None:
        self._flow(db)

        stored = json.dumps(db.audit, default=str).lower()
        assert "lifecycle.marker" not in stored
        assert "quillonmarker" not in stored
        assert ORG_NAME.lower() not in stored
        assert "/login" not in stored
