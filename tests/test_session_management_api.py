"""HTTP-layer spec for session policies and session management (GH-152).

The FastAPI app from ``create_app()`` runs against the in-memory database of
tests/db_fakes.py (what ``admino.database.get_pool`` returns). The real
``admino.auth``, ``admino.sessions``, ``admino.session_management`` and
``admino.audit_events`` code runs, through the real ``require_session``; only
Argon2 is replaced by a fast fake.

What these tests pin down:
- ``POST /api/auth/login``: the cookie's Max-Age is the session policy's lifetime
  (43200 by default; a Super Admin gets the platform policy, a member the org
  policy), and the stored row carries that policy's idle timeout and expiry.
- ``POST /api/auth/logout`` deletes the session row (unaudited, as before).
- Enforcement on every request: a session idle past its own timeout, or expired,
  is 401; a live session last seen minutes ago is 200 and its ``last_seen_at`` is
  updated; one seen seconds ago is 200 with no write.
- ``GET /api/me/sessions`` → 200 ``{"sessions": [...]}``: the caller's live
  sessions only, ``current`` true exactly for the request's own session, for
  every role (a Super Admin included), without any token or hash.
- ``DELETE /api/me/sessions/{session_id}`` → 204 and the row is deleted (the
  cookie is cleared when it was the current session); another user's or an
  unknown id → 404 ``{"detail": "Session not found"}``; a non-UUID → 422 without
  echo; one ``session.revoke`` audit row.
- ``POST /api/org/users/{user_id}/logout`` → 204 and every session of the target
  is deleted; 403 ``{"detail": "Forbidden"}`` for an Editor, a Viewer and a Super
  Admin; 404 ``{"detail": "User not found"}`` for a user of another org, an
  unknown id or a deleted user; one ``session.force_logout`` audit row.
- All three routes depend on ``require_session``, authorize through
  ``admino.access.can()`` (``account.manage`` / ``org.users.manage``), have their
  own per-user rate-limit bucket, and the two state-changing ones are refused
  cross-origin.
- The lifespan starts ``sessions.run_session_purge_job(get_pool())`` after the pool
  exists and cancels and awaits it before the pool closes.

All database calls are faked. No network, no real PostgreSQL.

Security notes:
- Tenant isolation: another org's user or another user's session answers 404
  with the same body as an unknown id (existence is not revealed).
- No token, hash, IP, user agent or email in any response body or log line.
- Fail closed: an audit failure is a 500 and nothing is deleted.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from admino import server
from admino import sessions as sessions_mod
from admino.access import Capability
from admino.server import _lifespan, create_app
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, fake_hash, sha256
from tests.lifespan_stubs import (
    patch_login_throttle_purge_job,
    patch_org_purge_job,
    patch_tools_gate,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_PASSWORD = "violet-Anchor-93-quartz"
_IP_A = "203.0.113.5"
_IP_B = "198.51.100.23"
_UA = "pytest-browser/1.0 (ua-marker-4411)"
_ME_SESSIONS = "/api/me/sessions"
_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}
_SESSION_NOT_FOUND = {"detail": "Session not found"}
_USER_NOT_FOUND = {"detail": "User not found"}
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_RATE_LIMITED = {"detail": "Rate limit exceeded"}
_SUMMARY_KEYS = {"id", "created_at", "last_seen_at", "expires_at", "ip", "user_agent", "current"}

# The real asyncio.sleep, kept before any test patches the module attribute.
_REAL_SLEEP = asyncio.sleep

_NEW_ROUTES: list[tuple[str, str]] = [
    ("GET", "/api/me/sessions"),
    ("DELETE", "/api/me/sessions/{session_id}"),
    ("POST", "/api/org/users/{user_id}/logout"),
]


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


def _config() -> MagicMock:
    """A minimal config (no old auth section)."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = True
    config.server.public_url = "https://admino.example.ch"
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


def _login(client: TestClient, email: str) -> httpx.Response:
    """POST /api/auth/login with the test password, then drop the client's cookie jar."""
    response = client.post("/api/auth/login", json={"email": email, "password": _PASSWORD})
    client.cookies.clear()
    return response


def _member(db: FakeDb, **fields: Any) -> uuid.UUID:
    """An account that can log in with _PASSWORD."""
    return db.add_account(password_hash=fake_hash(_PASSWORD), **fields)


def _super_admin(db: FakeDb) -> uuid.UUID:
    return _member(db, kind="super_admin", role=None, org_status=None)


def _delete_url(session_id: object) -> str:
    return f"{_ME_SESSIONS}/{session_id}"


def _logout_url(user_id: object) -> str:
    return f"/api/org/users/{user_id}/logout"


def _list(client: TestClient, token: str) -> httpx.Response:
    return client.get(_ME_SESSIONS, headers=_cookie(token))


def _session_updates(db: FakeDb) -> list[Any]:
    """Every UPDATE of the sessions table that reached the database."""
    return db.matching(r"^update sessions\b")


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
            from admino import session_management

            if hasattr(session_management, "can"):
                monkeypatch.setattr(session_management, "can", spy)


def _policy(idle: int, lifetime: int) -> Any:
    return sessions_mod.SessionPolicy(idle_timeout_minutes=idle, max_lifetime_hours=lifetime)


def _template_of(url: str) -> str:
    """The route template a concrete URL of the new routes belongs to."""
    if url == _ME_SESSIONS:
        return _ME_SESSIONS
    if url.startswith(_ME_SESSIONS + "/"):
        return "/api/me/sessions/{session_id}"
    return "/api/org/users/{user_id}/logout"


# ---------------------------------------------------------------------------
# 1. The new routes exist, require a session and are rate-limited per user
# ---------------------------------------------------------------------------


class TestRoutes:
    """GET /api/me/sessions, DELETE /api/me/sessions/{id}, POST /api/org/users/{id}/logout."""

    @pytest.mark.parametrize(("method", "path"), _NEW_ROUTES)
    def test_session_management_api_route_is_registered(self, method: str, path: str) -> None:
        _route(_app(), method, path)

    @pytest.mark.parametrize(("method", "path"), _NEW_ROUTES)
    def test_session_management_api_route_depends_on_require_session(
        self, method: str, path: str
    ) -> None:
        """server.require_session is in the route's dependency tree."""
        route = _route(_app(), method, path)

        assert _depends_on(route.dependant, server.require_session)

    @pytest.mark.parametrize(
        ("method", "url"),
        [
            ("GET", _ME_SESSIONS),
            ("DELETE", _delete_url(uuid.uuid4())),
            ("POST", _logout_url(uuid.uuid4())),
        ],
    )
    def test_session_management_api_route_without_a_session_is_401(
        self, db: FakeDb, method: str, url: str
    ) -> None:
        """No cookie → 401 Unauthorized, and nothing is read or deleted."""
        _route(_app(), method, _template_of(url))

        response = _client(_app()).request(method, url)

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED
        assert db.calls == []

    @pytest.mark.parametrize(
        ("key", "rate"),
        [
            ("/api/me/sessions/get", (1.0, 10)),
            ("/api/me/sessions/delete", (0.5, 5)),
            ("/api/org/users/logout", (0.5, 5)),
        ],
    )
    def test_session_management_api_rate_limits(self, key: str, rate: tuple[float, int]) -> None:
        """(tokens per second, burst) per route key."""
        _app()

        assert server._RATE_LIMITS[key] == pytest.approx(rate)


# ---------------------------------------------------------------------------
# 2. Login: the cookie lives as long as the session's policy
# ---------------------------------------------------------------------------


class TestLoginPolicy:
    """The stored idle timeout / expiry and the cookie's Max-Age come from the policy."""

    def test_session_management_api_member_login_uses_the_org_default(self, db: FakeDb) -> None:
        """Max-Age=43200; the row stores 60 minutes idle and expires 12 hours after
        creation."""
        user_id = _member(db)

        response = _login(_client(_app()), db.users[user_id]["email"])

        assert response.status_code == 204
        token, attributes = _session_set_cookie(response)
        assert attributes.get("max-age") == "43200"
        row = db.session(token)
        assert row["idle_timeout_minutes"] == 60
        assert row["expires_at"] - row["created_at"] == timedelta(hours=12)

    def test_session_management_api_super_admin_login_uses_the_platform_default(
        self, db: FakeDb
    ) -> None:
        """A Super Admin gets the same defaults (the platform policy, #160)."""
        user_id = _super_admin(db)

        response = _login(_client(_app()), db.users[user_id]["email"])

        token, attributes = _session_set_cookie(response)
        assert attributes.get("max-age") == "43200"
        assert db.session(token)["idle_timeout_minutes"] == 60

    def test_session_management_api_platform_policy_applies_to_super_admins_only(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With an 8-hour, 30-minute platform policy a Super Admin gets Max-Age=28800 and a
        30-minute row expiring after 8 hours; a member keeps 43200 / 60 minutes / 12 h."""
        monkeypatch.setattr(sessions_mod, "PLATFORM_SESSION_POLICY", _policy(30, 8))
        admin = _super_admin(db)
        member = _member(db)
        client = _client(_app())

        admin_token, admin_cookie = _session_set_cookie(_login(client, db.users[admin]["email"]))
        member_token, member_cookie = _session_set_cookie(_login(client, db.users[member]["email"]))

        assert admin_cookie.get("max-age") == "28800"
        admin_row = db.session(admin_token)
        assert admin_row["idle_timeout_minutes"] == 30
        assert admin_row["expires_at"] - admin_row["created_at"] == timedelta(hours=8)
        assert member_cookie.get("max-age") == "43200"
        member_row = db.session(member_token)
        assert member_row["idle_timeout_minutes"] == 60
        assert member_row["expires_at"] - member_row["created_at"] == timedelta(hours=12)

    def test_session_management_api_org_policy_applies_to_members_only(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a 2-hour, 20-minute org policy a member gets Max-Age=7200 and a 20-minute
        row; a Super Admin keeps 43200 / 60 minutes."""
        monkeypatch.setattr(sessions_mod, "DEFAULT_ORG_SESSION_POLICY", _policy(20, 2))
        member = _member(db)
        admin = _super_admin(db)
        client = _client(_app())

        member_token, member_cookie = _session_set_cookie(_login(client, db.users[member]["email"]))
        admin_token, admin_cookie = _session_set_cookie(_login(client, db.users[admin]["email"]))

        assert member_cookie.get("max-age") == "7200"
        assert db.session(member_token)["idle_timeout_minutes"] == 20
        assert admin_cookie.get("max-age") == "43200"
        assert db.session(admin_token)["idle_timeout_minutes"] == 60

    def test_session_management_api_new_session_is_live(self, db: FakeDb) -> None:
        """The session from a login resolves on the next request."""
        user_id = _member(db)
        client = _client(_app())
        token, _ = _session_set_cookie(_login(client, db.users[user_id]["email"]))

        assert client.get("/api/auth/me", headers=_cookie(token)).status_code == 200


# ---------------------------------------------------------------------------
# 3. Logout deletes the row
# ---------------------------------------------------------------------------


class TestLogoutDeletes:
    """POST /api/auth/logout: the current session's row is deleted, not flagged."""

    def test_session_management_api_logout_deletes_the_row(self, db: FakeDb) -> None:
        """204, and the row is gone from the table."""
        user_id = _member(db)
        token = db.open_session(user_id)

        response = _client(_app()).post("/api/auth/logout", headers=_cookie(token))

        assert response.status_code == 204
        assert db.session_revoked(token)
        assert db.matching(r"^delete from sessions\b") != []

    def test_session_management_api_logout_keeps_other_rows_and_is_unaudited(
        self, db: FakeDb
    ) -> None:
        """The user's other session stays; a plain logout writes no audit row."""
        user_id = _member(db)
        token = db.open_session(user_id)
        other = db.open_session(user_id)

        _client(_app()).post("/api/auth/logout", headers=_cookie(token))

        assert not db.session_revoked(other)
        assert db.audit_rows() == []


# ---------------------------------------------------------------------------
# 4. Enforcement on every request (the real require_session)
# ---------------------------------------------------------------------------

_ENFORCED_GETS = ["/api/auth/me", _ME_SESSIONS]


class TestEnforcement:
    """The idle timeout and expiry of the row are checked on every request."""

    @pytest.mark.parametrize("path", _ENFORCED_GETS)
    @pytest.mark.parametrize(
        ("idle", "seen_ago"),
        [
            pytest.param(60, timedelta(minutes=61), id="idle-60"),
            pytest.param(15, timedelta(minutes=16), id="idle-15"),
            pytest.param(480, timedelta(hours=8, minutes=1), id="idle-480"),
        ],
    )
    def test_session_management_api_idle_session_is_401(
        self, db: FakeDb, path: str, idle: int, seen_ago: timedelta
    ) -> None:
        """Idle past the row's own timeout → 401, and nothing is written."""
        _route(_app(), "GET", path)
        token = db.open_session(_member(db), idle_timeout_minutes=idle, last_seen_ago=seen_ago)

        response = _client(_app()).get(path, headers=_cookie(token))

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED
        assert _session_updates(db) == []

    @pytest.mark.parametrize("path", _ENFORCED_GETS)
    def test_session_management_api_expired_session_is_401(self, db: FakeDb, path: str) -> None:
        """Past expires_at → 401."""
        _route(_app(), "GET", path)
        token = db.open_session(_member(db), expires_in=timedelta(seconds=-1))

        response = _client(_app()).get(path, headers=_cookie(token))

        assert response.status_code == 401

    @pytest.mark.parametrize("path", _ENFORCED_GETS)
    def test_session_management_api_active_session_is_touched(self, db: FakeDb, path: str) -> None:
        """Last seen 5 minutes ago → 200 and last_seen_at is now (one UPDATE)."""
        _route(_app(), "GET", path)
        token = db.open_session(_member(db), last_seen_ago=timedelta(minutes=5))
        before = datetime.now(UTC)

        response = _client(_app()).get(path, headers=_cookie(token))

        assert response.status_code == 200
        assert db.session(token)["last_seen_at"] >= before
        assert len(_session_updates(db)) == 1

    @pytest.mark.parametrize("path", _ENFORCED_GETS)
    def test_session_management_api_fresh_session_is_not_written(
        self, db: FakeDb, path: str
    ) -> None:
        """Last seen 10 seconds ago → 200 and no UPDATE statement."""
        _route(_app(), "GET", path)
        token = db.open_session(_member(db), last_seen_ago=timedelta(seconds=10))

        response = _client(_app()).get(path, headers=_cookie(token))

        assert response.status_code == 200
        assert _session_updates(db) == []

    def test_session_management_api_long_idle_timeout_is_honoured(self, db: FakeDb) -> None:
        """A 480-minute session last seen 7h59 ago still works."""
        token = db.open_session(
            _member(db), idle_timeout_minutes=480, last_seen_ago=timedelta(hours=7, minutes=59)
        )

        response = _client(_app()).get("/api/auth/me", headers=_cookie(token))

        assert response.status_code == 200

    def test_session_management_api_activity_keeps_a_session_alive(self, db: FakeDb) -> None:
        """A 15-minute session used after 14 minutes is touched, so two minutes later (16
        minutes after the previous touch) it still works."""
        token = db.open_session(
            _member(db), idle_timeout_minutes=15, last_seen_ago=timedelta(minutes=14)
        )
        client = _client(_app())
        assert client.get("/api/auth/me", headers=_cookie(token)).status_code == 200

        db.session(token)["last_seen_at"] -= timedelta(minutes=2)

        assert client.get("/api/auth/me", headers=_cookie(token)).status_code == 200


# ---------------------------------------------------------------------------
# 5. GET /api/me/sessions
# ---------------------------------------------------------------------------


class TestListSessions:
    """The caller's live sessions, the current one flagged."""

    def test_session_management_api_list_shape(self, db: FakeDb) -> None:
        """200 {"sessions": [...]}; each entry has exactly the summary fields."""
        token = db.open_session(_member(db), ip="198.51.100.9", user_agent=_UA)

        response = _list(_client(_app()), token)

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"sessions"}
        assert len(body["sessions"]) == 1
        entry = body["sessions"][0]
        assert set(entry) == _SUMMARY_KEYS
        assert entry["id"] == str(db.session_id_of(token))
        assert (entry["ip"], entry["user_agent"], entry["current"]) == (
            "198.51.100.9",
            _UA,
            True,
        )

    def test_session_management_api_list_is_the_callers_live_sessions_only(
        self, db: FakeDb
    ) -> None:
        """Expired and idle rows (not purged yet) and another user's sessions are left out;
        newest activity first; current exactly for the cookie's session."""
        caller = _member(db)
        other = _member(db)
        current = db.open_session(caller, last_seen_ago=timedelta(seconds=5))
        older = db.open_session(caller, last_seen_ago=timedelta(minutes=40))
        newest = db.open_session(caller)
        db.open_session(caller, expires_in=timedelta(seconds=-1))
        db.open_session(caller, idle_timeout_minutes=15, last_seen_ago=timedelta(minutes=20))
        db.open_session(other)

        response = _list(_client(_app()), current)

        sessions = response.json()["sessions"]
        assert [entry["id"] for entry in sessions] == [
            str(db.session_id_of(newest)),
            str(db.session_id_of(current)),
            str(db.session_id_of(older)),
        ]
        assert [entry["current"] for entry in sessions] == [False, True, False]

    @pytest.mark.parametrize("who", ["org_admin", "editor", "viewer", "super_admin"])
    def test_session_management_api_list_works_for_every_role(self, db: FakeDb, who: str) -> None:
        """Account management is for everyone, the Super Admin included."""
        user_id = _super_admin(db) if who == "super_admin" else _member(db, role=who)
        token = db.open_session(user_id)

        response = _list(_client(_app()), token)

        assert response.status_code == 200
        assert [entry["current"] for entry in response.json()["sessions"]] == [True]

    def test_session_management_api_list_query_is_bound_to_the_caller(self, db: FakeDb) -> None:
        """The list query's only bind parameter is the caller's own user id."""
        caller = _member(db)
        token = db.open_session(caller)

        _list(_client(_app()), token)

        lists = [
            call for call in db.calls if call.method == "fetch" and "sessions" in call.normalized
        ]
        assert len(lists) == 1
        assert lists[0].args == (caller,)

    def test_session_management_api_list_never_shows_a_token_or_hash(self, db: FakeDb) -> None:
        """No raw token and no hash (hex) in the response."""
        caller = _member(db)
        tokens = [db.open_session(caller), db.open_session(caller)]

        response = _list(_client(_app()), tokens[0])

        assert response.status_code == 200
        assert len(response.json()["sessions"]) == 2
        for token in tokens:
            assert token not in response.text
            assert sha256(token).hex() not in response.text
        assert "token" not in response.text

    def test_session_management_api_list_rate_limit_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One user spending the bucket gets 429; another user is unaffected; the bucket is
        ("/api/me/sessions/get", "user:<id>")."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/me/sessions/get", (0.001, 2))
        first = _member(db)
        token_a = db.open_session(first)
        token_b = db.open_session(_member(db))
        client = _client(app)

        statuses = [_list(client, token_a).status_code for _ in range(3)]
        other = _list(client, token_b)

        assert statuses == [200, 200, 429]
        assert _list(client, token_a).json() == _RATE_LIMITED
        assert other.status_code == 200
        assert ("/api/me/sessions/get", f"user:{first}") in server._rate_buckets


# ---------------------------------------------------------------------------
# 6. DELETE /api/me/sessions/{session_id}
# ---------------------------------------------------------------------------


class TestDeleteOwnSession:
    """A user deletes one of their own sessions."""

    def test_session_management_api_delete_own_session(self, db: FakeDb) -> None:
        """204 with an empty body; that row is gone, the caller's current session stays."""
        caller = _member(db)
        current = db.open_session(caller)
        target = db.open_session(caller)

        response = _client(_app()).delete(
            _delete_url(db.session_id_of(target)), headers=_cookie(current)
        )

        assert response.status_code == 204
        assert response.content == b""
        assert db.session_revoked(target)
        assert not db.session_revoked(current)

    def test_session_management_api_delete_other_session_keeps_the_cookie(self, db: FakeDb) -> None:
        """Deleting another of one's sessions sets no admino_session cookie."""
        caller = _member(db)
        current = db.open_session(caller)
        target = db.open_session(caller)

        response = _client(_app()).delete(
            _delete_url(db.session_id_of(target)), headers=_cookie(current)
        )

        assert response.status_code == 204
        assert _session_cookie_headers(response) == []

    def test_session_management_api_delete_current_session_clears_the_cookie(
        self, db: FakeDb
    ) -> None:
        """Deleting the request's own session: 204, Set-Cookie admino_session with
        Max-Age=0, and the cookie no longer works."""
        caller = _member(db)
        current = db.open_session(caller)
        client = _client(_app())

        response = client.delete(_delete_url(db.session_id_of(current)), headers=_cookie(current))

        assert response.status_code == 204
        value, attributes = _session_set_cookie(response)
        assert value in {"", '""'}
        assert attributes.get("max-age") == "0"
        assert attributes.get("path") == "/"
        assert db.session_revoked(current)
        assert client.get("/api/auth/me", headers=_cookie(current)).status_code == 401

    @pytest.mark.parametrize("who", ["member", "super_admin"])
    def test_session_management_api_delete_is_audited(self, db: FakeDb, who: str) -> None:
        """One session.revoke row: the caller, their org (none for a Super Admin), target
        the caller, the client IP, metadata {"session_id": <id>}."""
        caller = _member(db) if who == "member" else _super_admin(db)
        current = db.open_session(caller)
        target = db.open_session(caller)
        session_id = db.session_id_of(target)

        _client(_app(), ip=_IP_B).delete(_delete_url(session_id), headers=_cookie(current))

        rows = db.audit_rows("session.revoke")
        assert len(rows) == 1
        row = rows[0]
        assert (row["actor_kind"], row["actor_user_id"]) == (who, caller)
        assert row["org_id"] == (ORG_ID if who == "member" else None)
        assert (row["target_type"], row["target_ids"]) == ("user", [str(caller)])
        assert row["ip"] == _IP_B
        assert row["metadata"] == {"session_id": str(session_id)}

    @pytest.mark.parametrize("case", ["other-user", "other-org", "unknown"])
    def test_session_management_api_delete_foreign_or_unknown_is_404(
        self, db: FakeDb, case: str
    ) -> None:
        """Another user's session (any org) or an id that matches nothing → 404 {"detail":
        "Session not found"}; nothing deleted, nothing audited."""
        caller = _member(db, role="org_admin")
        current = db.open_session(caller)
        if case == "unknown":
            victim_token = None
            session_id = uuid.uuid4()
        else:
            owner = _member(db, org_id=OTHER_ORG_ID) if case == "other-org" else _member(db)
            victim_token = db.open_session(owner)
            session_id = db.session_id_of(victim_token)

        response = _client(_app()).delete(_delete_url(session_id), headers=_cookie(current))

        assert response.status_code == 404
        assert response.json() == _SESSION_NOT_FOUND
        assert victim_token is None or not db.session_revoked(victim_token)
        assert not db.session_revoked(current)
        assert db.audit_rows() == []

    def test_session_management_api_delete_404_bodies_are_identical(self, db: FakeDb) -> None:
        """Another user's session and an unknown id are indistinguishable."""
        caller = _member(db)
        current = db.open_session(caller)
        foreign = db.session_id_of(db.open_session(_member(db)))
        client = _client(_app())

        responses = [
            client.delete(_delete_url(foreign), headers=_cookie(current)),
            client.delete(_delete_url(uuid.uuid4()), headers=_cookie(current)),
        ]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize(
        "bad_id", ["not-a-uuid-ECHOMARK42", "12345", "ECHOMARK42" + "0" * 26, "x" * 200]
    )
    def test_session_management_api_delete_non_uuid_is_422_without_echo(
        self, db: FakeDb, bad_id: str
    ) -> None:
        """A path id that isn't a UUID → 422; the input isn't echoed and nothing is deleted."""
        _route(_app(), "DELETE", "/api/me/sessions/{session_id}")
        token = db.open_session(_member(db))

        response = _client(_app()).delete(_delete_url(bad_id), headers=_cookie(token))

        assert response.status_code == 422
        assert "ECHOMARK42" not in response.text
        assert "x" * 20 not in response.text
        assert db.matching(r"^delete from sessions\b") == []

    def test_session_management_api_delete_audit_failure_is_500_and_keeps_the_row(
        self, db: FakeDb
    ) -> None:
        """Fail closed: the audit write fails → 500, the row is still there."""
        caller = _member(db)
        current = db.open_session(caller)
        target = db.open_session(caller)
        db.fail_audit = True

        response = _client(_app(), raise_server_exceptions=False).delete(
            _delete_url(db.session_id_of(target)), headers=_cookie(current)
        )

        assert response.status_code == 500
        assert not db.session_revoked(target)

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
        ],
    )
    def test_session_management_api_delete_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        """CSRF: a cross-origin DELETE is 403 before anything runs; the row survives."""
        _route(_app(), "DELETE", "/api/me/sessions/{session_id}")
        caller = _member(db)
        current = db.open_session(caller)
        target = db.open_session(caller)

        response = _client(_app()).delete(
            _delete_url(db.session_id_of(target)), headers=_cookie(current, **headers)
        )

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert not db.session_revoked(target)
        assert db.audit_rows() == []

    def test_session_management_api_delete_rate_limit_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bucket is ("/api/me/sessions/delete", "user:<id>"); one user spending it
        doesn't throttle another."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/me/sessions/delete", (0.001, 1))
        first = _member(db)
        token_a = db.open_session(first)
        token_b = db.open_session(_member(db))
        client = _client(app)

        client.delete(_delete_url(uuid.uuid4()), headers=_cookie(token_a))
        exhausted = client.delete(_delete_url(uuid.uuid4()), headers=_cookie(token_a))
        other = client.delete(_delete_url(uuid.uuid4()), headers=_cookie(token_b))

        assert exhausted.status_code == 429
        assert other.status_code == 404
        assert ("/api/me/sessions/delete", f"user:{first}") in server._rate_buckets


# ---------------------------------------------------------------------------
# 7. POST /api/org/users/{user_id}/logout
# ---------------------------------------------------------------------------


class TestForceLogoutRoute:
    """An Org Admin logs a user of their org out of every device."""

    def test_session_management_api_force_logout(self, db: FakeDb) -> None:
        """204 with an empty body; every session of the target is gone; the admin's and a
        bystander's sessions stay."""
        admin = _member(db, role="org_admin")
        admin_token = db.open_session(admin)
        target = _member(db)
        targets = [db.open_session(target), db.open_session(target)]
        bystander = db.open_session(_member(db))
        outsider = db.open_session(_member(db, org_id=OTHER_ORG_ID))

        response = _client(_app()).post(_logout_url(target), headers=_cookie(admin_token))

        assert response.status_code == 204
        assert response.content == b""
        assert all(db.session_revoked(token) for token in targets)
        assert not any(db.session_revoked(token) for token in (admin_token, bystander, outsider))

    def test_session_management_api_force_logout_is_immediate(self, db: FakeDb) -> None:
        """The target's cookie is refused on its very next request."""
        admin_token = db.open_session(_member(db, role="org_admin"))
        target = _member(db)
        target_token = db.open_session(target)
        client = _client(_app())
        assert client.get("/api/auth/me", headers=_cookie(target_token)).status_code == 200

        client.post(_logout_url(target), headers=_cookie(admin_token))

        assert client.get("/api/auth/me", headers=_cookie(target_token)).status_code == 401

    def test_session_management_api_force_logout_is_audited(self, db: FakeDb) -> None:
        """One session.force_logout row: the admin, their org, target the user, the client
        IP, metadata {"sessions_revoked": n}."""
        admin = _member(db, role="org_admin")
        admin_token = db.open_session(admin)
        target = _member(db)
        for _ in range(3):
            db.open_session(target)

        _client(_app(), ip=_IP_B).post(_logout_url(target), headers=_cookie(admin_token))

        rows = db.audit_rows("session.force_logout")
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

    def test_session_management_api_force_logout_without_sessions(self, db: FakeDb) -> None:
        """A target with no session: 204, audited with sessions_revoked 0."""
        admin_token = db.open_session(_member(db, role="org_admin"))
        target = _member(db)

        response = _client(_app()).post(_logout_url(target), headers=_cookie(admin_token))

        assert response.status_code == 204
        assert [row["metadata"] for row in db.audit_rows("session.force_logout")] == [
            {"sessions_revoked": 0}
        ]

    def test_session_management_api_force_logout_of_oneself(self, db: FakeDb) -> None:
        """An Org Admin targeting themselves: 204 and their own sessions are gone."""
        admin = _member(db, role="org_admin")
        admin_token = db.open_session(admin)
        other_device = db.open_session(admin)
        client = _client(_app())

        response = client.post(_logout_url(admin), headers=_cookie(admin_token))

        assert response.status_code == 204
        assert db.session_revoked(admin_token)
        assert db.session_revoked(other_device)
        assert client.get("/api/auth/me", headers=_cookie(admin_token)).status_code == 401

    @pytest.mark.parametrize("who", ["editor", "viewer", "super_admin"])
    def test_session_management_api_force_logout_forbidden_without_org_users_manage(
        self, db: FakeDb, who: str
    ) -> None:
        """An Editor, a Viewer and a Super Admin get 403 {"detail": "Forbidden"}; the target
        keeps its sessions and nothing is audited."""
        _route(_app(), "POST", "/api/org/users/{user_id}/logout")
        actor = _super_admin(db) if who == "super_admin" else _member(db, role=who)
        actor_token = db.open_session(actor)
        target = _member(db)
        target_token = db.open_session(target)

        response = _client(_app()).post(_logout_url(target), headers=_cookie(actor_token))

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        assert not db.session_revoked(target_token)
        assert db.audit_rows() == []

    @pytest.mark.parametrize("case", ["other-org", "unknown", "deleted", "super-admin"])
    def test_session_management_api_force_logout_outside_the_org_is_404(
        self, db: FakeDb, case: str
    ) -> None:
        """A user of another org, an unknown id, a deleted user or a Super Admin → 404
        {"detail": "User not found"}; nothing deleted, nothing audited."""
        admin_token = db.open_session(_member(db, role="org_admin"))
        if case == "other-org":
            target = _member(db, org_id=OTHER_ORG_ID)
        elif case == "deleted":
            target = _member(db, deleted_at=datetime.now(UTC) - timedelta(days=1))
        elif case == "super-admin":
            target = _super_admin(db)
        else:
            target = uuid.uuid4()
        target_token = db.open_session(target) if target in db.users else None

        response = _client(_app()).post(_logout_url(target), headers=_cookie(admin_token))

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND
        assert target_token is None or not db.session_revoked(target_token)
        assert db.audit_rows() == []

    def test_session_management_api_force_logout_404_bodies_are_identical(self, db: FakeDb) -> None:
        """Another org's user, a deleted user and an unknown id answer the same bytes."""
        admin_token = db.open_session(_member(db, role="org_admin"))
        targets = [
            _member(db, org_id=OTHER_ORG_ID),
            _member(db, deleted_at=datetime.now(UTC) - timedelta(days=1)),
            uuid.uuid4(),
        ]
        client = _client(_app())

        responses = [
            client.post(_logout_url(target), headers=_cookie(admin_token)) for target in targets
        ]

        assert {response.status_code for response in responses} == {404}
        assert len({response.content for response in responses}) == 1

    @pytest.mark.parametrize("bad_id", ["not-a-uuid-ECHOMARK42", "1", "x" * 200])
    def test_session_management_api_force_logout_non_uuid_is_422_without_echo(
        self, db: FakeDb, bad_id: str
    ) -> None:
        """A path id that isn't a UUID → 422 without echo; nothing is deleted."""
        _route(_app(), "POST", "/api/org/users/{user_id}/logout")
        admin_token = db.open_session(_member(db, role="org_admin"))

        response = _client(_app()).post(_logout_url(bad_id), headers=_cookie(admin_token))

        assert response.status_code == 422
        assert "ECHOMARK42" not in response.text
        assert "x" * 20 not in response.text
        assert db.matching(r"^delete from sessions\b") == []

    def test_session_management_api_force_logout_audit_failure_is_500(self, db: FakeDb) -> None:
        """Fail closed: the audit write fails → 500 and the target's sessions survive."""
        admin_token = db.open_session(_member(db, role="org_admin"))
        target = _member(db)
        target_token = db.open_session(target)
        db.fail_audit = True

        response = _client(_app(), raise_server_exceptions=False).post(
            _logout_url(target), headers=_cookie(admin_token)
        )

        assert response.status_code == 500
        assert not db.session_revoked(target_token)

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
        ],
    )
    def test_session_management_api_force_logout_cross_origin_is_refused(
        self, db: FakeDb, headers: dict[str, str]
    ) -> None:
        """CSRF: a cross-origin POST is 403 before anything runs; the sessions survive."""
        _route(_app(), "POST", "/api/org/users/{user_id}/logout")
        admin_token = db.open_session(_member(db, role="org_admin"))
        target = _member(db)
        target_token = db.open_session(target)

        response = _client(_app()).post(
            _logout_url(target), headers=_cookie(admin_token, **headers)
        )

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert not db.session_revoked(target_token)
        assert db.audit_rows() == []

    def test_session_management_api_force_logout_rate_limit_is_per_user(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bucket is ("/api/org/users/logout", "user:<id>"); one admin spending it
        doesn't throttle another."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/org/users/logout", (0.001, 1))
        first = _member(db, role="org_admin")
        token_a = db.open_session(first)
        token_b = db.open_session(_member(db, role="org_admin"))
        target = _member(db)
        client = _client(app)

        client.post(_logout_url(target), headers=_cookie(token_a))
        exhausted = client.post(_logout_url(target), headers=_cookie(token_a))
        other = client.post(_logout_url(target), headers=_cookie(token_b))

        assert exhausted.status_code == 429
        assert other.status_code == 204
        assert ("/api/org/users/logout", f"user:{first}") in server._rate_buckets


# ---------------------------------------------------------------------------
# 8. Authorization goes through admino.access.can()
# ---------------------------------------------------------------------------


class TestAuthorizationThroughCan:
    """/api/me/* checks account.manage, /api/org/* checks org.users.manage."""

    def test_session_management_api_list_asks_for_account_manage(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _CanSpy(monkeypatch)
        token = db.open_session(_member(db))

        assert _list(_client(_app()), token).status_code == 200
        assert Capability.ACCOUNT_MANAGE in spy.capabilities

    def test_session_management_api_delete_asks_for_account_manage(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _CanSpy(monkeypatch)
        caller = _member(db)
        current = db.open_session(caller)
        target = db.open_session(caller)

        response = _client(_app()).delete(
            _delete_url(db.session_id_of(target)), headers=_cookie(current)
        )

        assert response.status_code == 204
        assert Capability.ACCOUNT_MANAGE in spy.capabilities

    def test_session_management_api_force_logout_asks_for_org_users_manage(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _CanSpy(monkeypatch)
        admin_token = db.open_session(_member(db, role="org_admin"))

        response = _client(_app()).post(_logout_url(_member(db)), headers=_cookie(admin_token))

        assert response.status_code == 204
        assert Capability.ORG_USERS_MANAGE in spy.capabilities

    def test_session_management_api_account_manage_refused_is_403(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When can() refuses account.manage, listing and deleting are 403 and nothing is
        deleted."""
        _route(_app(), "GET", _ME_SESSIONS)
        _CanSpy(monkeypatch, deny=frozenset({Capability.ACCOUNT_MANAGE}))
        caller = _member(db)
        current = db.open_session(caller)
        target = db.open_session(caller)
        client = _client(_app())

        listed = _list(client, current)
        deleted = client.delete(_delete_url(db.session_id_of(target)), headers=_cookie(current))

        assert (listed.status_code, listed.json()) == (403, _FORBIDDEN)
        assert (deleted.status_code, deleted.json()) == (403, _FORBIDDEN)
        assert not db.session_revoked(target)

    def test_session_management_api_org_users_manage_refused_is_403(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When can() refuses org.users.manage even an Org Admin gets 403; nothing goes."""
        _route(_app(), "POST", "/api/org/users/{user_id}/logout")
        _CanSpy(monkeypatch, deny=frozenset({Capability.ORG_USERS_MANAGE}))
        admin_token = db.open_session(_member(db, role="org_admin"))
        target = _member(db)
        target_token = db.open_session(target)

        response = _client(_app()).post(_logout_url(target), headers=_cookie(admin_token))

        assert (response.status_code, response.json()) == (403, _FORBIDDEN)
        assert not db.session_revoked(target_token)


# ---------------------------------------------------------------------------
# 9. No content in logs
# ---------------------------------------------------------------------------


class TestNoContentInLogs:
    """Tokens, hashes, IPs, user agents and emails never reach a log line."""

    def test_session_management_api_logs_nothing_identifying(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        admin = _member(db, role="org_admin", email="log.marker.admin@example.test")
        target = _member(db, email="log.marker.target@example.test")
        client = _client(_app())
        login_token, _ = _session_set_cookie(
            client.post(
                "/api/auth/login",
                json={"email": "log.marker.admin@example.test", "password": _PASSWORD},
                headers={"User-Agent": _UA},
            )
        )
        client.cookies.clear()
        spare = db.open_session(admin, last_seen_ago=timedelta(minutes=5))
        target_token = db.open_session(target, ip="198.51.100.99", user_agent=_UA)

        _list(client, login_token)
        client.delete(_delete_url(db.session_id_of(spare)), headers=_cookie(login_token))
        client.post(_logout_url(target), headers=_cookie(login_token))
        client.post("/api/auth/logout", headers=_cookie(login_token))

        text = caplog.text
        for token in (login_token, spare, target_token):
            assert token not in text
            assert hashlib.sha256(token.encode()).hexdigest() not in text
        assert "log.marker" not in text
        assert _IP_A not in text
        assert "198.51.100.99" not in text
        assert "ua-marker-4411" not in text


# ---------------------------------------------------------------------------
# 10. The lifespan runs the purge job
# ---------------------------------------------------------------------------


def _make_app_config() -> MagicMock:
    """A minimal mock AppConfig for create_app (no ``auth`` section)."""
    config = MagicMock()
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    return config


class _LifespanProbe:
    """Fakes for the lifespan's pool and background jobs; records what happens when."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.pool: Any = MagicMock(name="pool")
        self.purge_pools: list[Any] = []
        self.purge_tasks: list[asyncio.Task[Any]] = []
        self.throttle_purge_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.throttle_purge_tasks: list[asyncio.Task[Any]] = []

    async def _blocking(self, name: str) -> None:
        """Block until cancelled, then finish after one more loop turn."""
        self.events.append(f"{name}-started")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.events.append(f"{name}-cancelled")
            await _REAL_SLEEP(0)
            self.events.append(f"{name}-finished")
            raise

    async def session_purge(self, pool: Any, *_args: Any, **_kwargs: Any) -> None:
        """The fake run_session_purge_job."""
        task = asyncio.current_task()
        assert task is not None
        self.purge_tasks.append(task)
        self.purge_pools.append(pool)
        await self._blocking("purge")

    async def retention(self, *_args: Any, **_kwargs: Any) -> None:
        """The fake run_retention_job."""
        await self._blocking("retention")

    async def org_purge(self, *_args: Any, **_kwargs: Any) -> None:
        """The fake run_org_purge_job (GH-154)."""
        await self._blocking("org-purge")

    async def throttle_purge(self, *args: Any, **kwargs: Any) -> None:
        """The fake login_throttle.run_purge_job (GH-157)."""
        task = asyncio.current_task()
        assert task is not None
        self.throttle_purge_tasks.append(task)
        self.throttle_purge_calls.append((args, kwargs))
        await self._blocking("throttle-purge")


@contextlib.contextmanager
def _patched_lifespan(probe: _LifespanProbe) -> Iterator[None]:
    """Patch the lifespan's database calls and background jobs. get_pool() raises until
    init_pool() ran, like the real one. ``create=True``: run_session_purge_job is new in
    GH-152, so before it exists the patch adds it and the tests fail on their
    assertions, not on the patch. GH-154's org purge job is stubbed too, so it never
    runs against the MagicMock pool."""
    state: dict[str, Any] = {"pool": None}

    async def fake_init_pool(*_args: Any, **_kwargs: Any) -> Any:
        probe.events.append("init_pool")
        state["pool"] = probe.pool
        return probe.pool

    def fake_get_pool() -> Any:
        if state["pool"] is None:
            msg = "Database pool not initialised"
            raise RuntimeError(msg)
        return state["pool"]

    async def fake_close_pool() -> None:
        probe.events.append("close_pool")
        state["pool"] = None

    with (
        patch("admino.database.init_pool", fake_init_pool),
        patch("admino.database.close_pool", fake_close_pool),
        patch("admino.database.get_pool", fake_get_pool),
        patch("admino.database.load_permissions_from_db", AsyncMock(return_value={})),
        # GH-159: the tools gate reload never reads the MagicMock pool.
        patch_tools_gate(),
        patch("admino.audit_events.run_retention_job", probe.retention),
        patch("admino.mailer.load_smtp_config", MagicMock(return_value=None)),
        patch("admino.sessions.run_session_purge_job", probe.session_purge, create=True),
        patch_org_purge_job(probe.org_purge),
        # GH-157: a no-op until admino.login_throttle exists (see lifespan_stubs).
        patch_login_throttle_purge_job(probe.throttle_purge),
    ):
        yield


async def _let_tasks_run() -> None:
    """Give scheduled tasks a few loop turns to start."""
    for _ in range(5):
        await _REAL_SLEEP(0)


class TestLifespanRunsThePurge:
    """The purge job runs while the app is up, like the audit retention job."""

    async def test_session_management_api_lifespan_starts_the_purge_with_the_pool(self) -> None:
        """After startup, run_session_purge_job(get_pool()) runs as a task."""
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()
                assert probe.purge_pools == [probe.pool]

    async def test_session_management_api_lifespan_starts_the_purge_after_init_pool(
        self,
    ) -> None:
        """The job starts only once the pool exists."""
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert "purge-started" in probe.events
        assert probe.events.index("init_pool") < probe.events.index("purge-started")

    async def test_session_management_api_lifespan_cancels_the_purge_on_shutdown(self) -> None:
        """On shutdown the job's task is cancelled."""
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert len(probe.purge_tasks) == 1
        assert probe.purge_tasks[0].cancelled()

    async def test_session_management_api_lifespan_awaits_the_purge_before_closing_the_pool(
        self,
    ) -> None:
        """The cancelled job finishes before the pool closes, so it never runs against a
        closed pool."""
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert "purge-finished" in probe.events
        assert probe.events.index("purge-finished") < probe.events.index("close_pool")

    async def test_session_management_api_lifespan_keeps_the_retention_job(self) -> None:
        """The audit retention job still starts next to the purge."""
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert "retention-started" in probe.events
        assert "purge-started" in probe.events


class TestLifespanRunsTheThrottlePurge:
    """GH-157: expired login_throttle rows are purged while the app is up, like the
    sessions: ``login_throttle.run_purge_job(get_pool())`` in its own task, looked up at
    call time, started after the pool exists, cancelled and awaited before it closes."""

    async def test_session_management_api_lifespan_starts_the_throttle_purge(self) -> None:
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()
                assert len(probe.throttle_purge_calls) == 1
                args, kwargs = probe.throttle_purge_calls[0]
                assert (args[0] if args else kwargs.get("pool")) is probe.pool
                assert len(probe.throttle_purge_tasks) == 1
                assert probe.throttle_purge_tasks[0] is not asyncio.current_task()
                assert not probe.throttle_purge_tasks[0].done()

    async def test_session_management_api_lifespan_throttle_purge_uses_the_default_interval(
        self,
    ) -> None:
        import admino.login_throttle as throttle

        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        ((args, kwargs),) = probe.throttle_purge_calls
        assert args[1:] == ()
        assert set(kwargs) <= {"pool", "interval_seconds"}
        assert kwargs.get("interval_seconds", throttle.PURGE_INTERVAL_SECONDS) == (
            throttle.PURGE_INTERVAL_SECONDS
        )

    async def test_session_management_api_lifespan_starts_the_throttle_purge_after_init_pool(
        self,
    ) -> None:
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert "throttle-purge-started" in probe.events
        assert probe.events.index("init_pool") < probe.events.index("throttle-purge-started")

    async def test_session_management_api_lifespan_stops_the_throttle_purge_before_the_pool(
        self,
    ) -> None:
        """Cancelled on shutdown and finished before the pool closes."""
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert len(probe.throttle_purge_tasks) == 1
        assert probe.throttle_purge_tasks[0].cancelled()
        assert "throttle-purge-finished" in probe.events
        assert probe.events.index("throttle-purge-finished") < probe.events.index("close_pool")

    async def test_session_management_api_lifespan_keeps_the_session_purge_next_to_it(
        self,
    ) -> None:
        probe = _LifespanProbe()
        app = create_app(agent=MagicMock(), config=_make_app_config())

        with _patched_lifespan(probe):
            async with asyncio.timeout(5), _lifespan(app):
                await _let_tasks_run()

        assert "purge-started" in probe.events
        assert "throttle-purge-started" in probe.events
