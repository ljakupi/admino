"""HTTP-layer spec for email/password login, sessions, CSRF and per-caller rate limits
(GH-149, GH-152).

The FastAPI app from ``create_app()`` runs against a fake database (the pool
``admino.database.get_pool`` returns is an in-memory stand-in for the users,
organizations and sessions tables) and a fake agent. The real ``admino.auth``
and ``admino.sessions`` code runs; only Argon2 is replaced by a fast fake.

What these tests pin down:
- ``POST /api/auth/login`` → 204 and the ``admino_session`` cookie (HttpOnly,
  SameSite=Strict, Path=/, Max-Age=43200, Secure iff ``server.cookie_secure``);
  every failure → 401 with one identical body and no cookie; 422 on a bad body;
  nothing the caller sent is echoed back.
- ``POST /api/auth/logout`` deletes the session row (GH-152) and clears the
  cookie; ``GET /api/auth/me`` returns the resolved principal and languages.
- Every route except ``/health``, the login, the password reset endpoints
  (GH-151) and the OAuth callback requires a valid session (a route-enumeration
  test walks ``app.routes``), and the session is re-checked on every request: a
  deactivated user or org, a deleted (revoked) session, an expired one and one
  idle past its timeout (GH-152) are refused at once.
- The chat routes need ``chat.send``: 403 for a Super Admin and a Viewer.
- CSRF: state-changing requests pass only when ``Sec-Fetch-Site`` is
  ``same-origin``/``none`` or, without it, when ``Origin`` matches ``Host``;
  refusals are 403 before authentication runs, the login included.
- Rate limits are per caller (user id on session routes, client IP on public
  ones), idle buckets are evicted and the bucket map is bounded.
- Critical promotions answer 403 until #161; the agent receives the caller's
  Principal.

All database and LLM calls are faked. No network, no real PostgreSQL.

Security notes:
- No user enumeration: identical 401 bodies for unknown email, wrong password
  and inactive accounts.
- No input echo, and no email, password or token in any log line.
- Login CSRF is refused like any other cross-origin write.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import logging
import re
import secrets
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import asyncpg
import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811
from fastapi import HTTPException
from fastapi.dependencies.utils import get_dependant
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.routing import Route

from admino import models, server
from admino.access import Principal
from admino.models import AgentResult, LLMMessage, PendingConfirmation, ToolCall
from admino.server import create_app
from tests.db_fakes import NowPlus, insert_values

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    import httpx
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COOKIE = "admino_session"
_PASSWORD = "violet-Anchor-93-quartz"
_WRONG_PASSWORD = "violet-Anchor-93-quartzz"
_ORG_ID = uuid.UUID("c3d4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e6f")
_IP_A = "203.0.113.5"
_IP_B = "198.51.100.23"
_CSRF_REFUSED = {"detail": "Cross-origin request refused"}
_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}
_LOGIN_FAILED = {"detail": "Invalid email or password"}
_PROMOTE_REFUSED = {"detail": "Critical permission promotions are temporarily unavailable."}
_CHAT_BODY = {"message": "hello", "session_id": "chat-1"}

# Routes that answer without a session: the health check, the login, the
# password reset request and confirm (GH-151), opening and accepting an
# invitation link (GH-153), and the OAuth provider's cross-site redirect
# (protected by its state token).
_PUBLIC_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/health"),
        ("POST", "/api/auth/login"),
        ("POST", "/api/auth/password-reset"),
        ("POST", "/api/auth/password-reset/confirm"),
        # GH-153: the invitee has no account yet when opening and accepting the link.
        ("GET", "/api/auth/invitations/{token}"),
        ("POST", "/api/auth/invitations/{token}/accept"),
        ("GET", "/api/oauth/callback"),
    }
)

# Routes that exist today (or are added by #149, #152 and #153) and must require a session.
_KNOWN_PROTECTED_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/message"),
        ("GET", "/api/events"),
        ("POST", "/api/confirm/{confirmation_id}"),
        ("GET", "/api/settings"),
        ("PATCH", "/api/settings"),
        ("GET", "/api/permissions"),
        ("PATCH", "/api/permissions"),
        ("GET", "/api/critical-permissions"),
        ("PATCH", "/api/critical-permissions/{tool}/{action}"),
        ("DELETE", "/api/critical-permissions/{tool}/{action}/pending"),
        ("GET", "/api/oauth/google/authorize"),
        ("GET", "/api/oauth/microsoft/authorize"),
        ("GET", "/api/oauth/google/status"),
        ("GET", "/api/oauth/microsoft/status"),
        ("DELETE", "/api/oauth/google"),
        ("DELETE", "/api/oauth/microsoft"),
        ("POST", "/api/auth/logout"),
        ("GET", "/api/auth/me"),
        ("GET", "/api/me/sessions"),
        ("DELETE", "/api/me/sessions/{session_id}"),
        ("POST", "/api/org/users/{user_id}/logout"),
        # GH-153: an Org Admin's invitations.
        ("POST", "/api/org/invitations"),
        ("GET", "/api/org/invitations"),
        ("DELETE", "/api/org/invitations/{invitation_id}"),
        ("POST", "/api/org/invitations/{invitation_id}/resend"),
    }
)

# Valid dummy values for path parameters.
_PATH_VALUES: dict[str, str] = {
    "tool": "gmail",
    "action": "send",
    "confirmation_id": "c1",
    "session_id": "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d",
    "user_id": "1c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e",
    "invitation_id": "2d3e4f50-6172-4c8d-9e0f-1a2b3c4d5e6f",
}


def _norm(sql: str) -> str:
    """Collapse whitespace and lowercase, for formatting-tolerant SQL matching."""
    return re.sub(r"\s+", " ", sql).strip().lower()


def _sha256(token: str) -> bytes:
    """The stored form of a session token."""
    return hashlib.sha256(token.encode()).digest()


def _fake_hash(password: str) -> str:
    """The fake 'hash' the fast password stand-in accepts."""
    return "fake$" + hashlib.sha256(password.encode()).hexdigest()


def _plain(value: Any) -> uuid.UUID:
    """A plain uuid.UUID from an asyncpg UUID."""
    return uuid.UUID(int=value.int)


# ---------------------------------------------------------------------------
# The fake database behind admino.database.get_pool()
# ---------------------------------------------------------------------------


class _FakeDb:
    """In-memory users/organizations/sessions behind a pool-shaped object.

    - The account lookup (a users query) returns the account whose email matches
      the str bind parameter, case-insensitively.
    - The session lookup (any query naming sessions) returns the joined session
      row for the bytes bind parameter (the token hash), re-reading the account
      each time, so flipping an account's status takes effect on the next call.
    - The sessions table is the schema after migration 0009 (GH-152): each row
      has its own idle timeout and last_seen_at, and there is no revoked_at
      column (a statement naming it fails like PostgreSQL's
      UndefinedColumnError). INSERT INTO sessions stores a session (without
      idle_timeout_minutes it fails like a NOT NULL violation), DELETE FROM
      sessions ... token_hash deletes one (logout), and UPDATE sessions SET
      last_seen_at touches one by id. Every call is recorded.
    """

    def __init__(self) -> None:
        self.accounts: dict[uuid.UUID, dict[str, Any]] = {}
        self.sessions: dict[bytes, dict[str, Any]] = {}
        self.calls: list[tuple[str, str, tuple[Any, ...]]] = []
        self.session_inserts: list[tuple[str, tuple[Any, ...]]] = []
        self.pool = _FakePool(self)

    # -- fixtures ------------------------------------------------------------

    def add_account(
        self,
        *,
        kind: str = "member",
        role: str | None = "editor",
        status: str = "active",
        org_status: str | None = "active",
        deleted_at: datetime | None = None,
        email: str | None = None,
        password: str = _PASSWORD,
        ui_language: str = "de",
        response_language: str | None = "fr",
    ) -> dict[str, Any]:
        """Add an account (asyncpg UUIDs, as a users row returns them) and return its row."""
        user_id = uuid.uuid4()
        is_member = kind == "member"
        row: dict[str, Any] = {
            "id": PgUUID(str(user_id)),
            "email": email or f"user-{user_id.hex[:8]}@example.test",
            "name": "Some Person",
            "kind": kind,
            "org_id": PgUUID(str(_ORG_ID)) if is_member else None,
            "role": role if is_member else None,
            "status": status,
            "deleted_at": deleted_at,
            "password_hash": _fake_hash(password),
            "org_status": org_status if is_member else None,
            "ui_language": ui_language,
            "response_language": response_language,
        }
        self.accounts[user_id] = row
        return row

    def open_session(
        self,
        account: dict[str, Any],
        *,
        expired: bool = False,
        idle: bool = False,
    ) -> str:
        """Store a session for the account (60-minute idle timeout) and return its raw
        token. ``idle``: last seen 61 minutes ago."""
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        self.sessions[_sha256(token)] = {
            "session_id": PgUUID(str(uuid.uuid4())),
            "user_id": _plain(account["id"]),
            "expires_at": now - timedelta(seconds=1) if expired else now + timedelta(hours=12),
            "last_seen_at": now - timedelta(minutes=61) if idle else now,
            "idle_timeout_minutes": 60,
        }
        return token

    # -- query handling ------------------------------------------------------

    def handle(self, method: str, sql: str, args: tuple[Any, ...]) -> Any:
        self.calls.append((method, sql, args))
        normalized = _norm(sql)
        if re.search(r"\brevoked_at\b", normalized):
            # Migration 0009 dropped the column: revoking deletes the row.
            raise asyncpg.exceptions.UndefinedColumnError('column "revoked_at" does not exist')
        if "insert into sessions" in normalized:
            self._insert_session(sql, args)
            return uuid.uuid4() if method != "execute" else "INSERT 0 1"
        if normalized.startswith("delete from sessions"):
            return self._delete(normalized, args)
        if normalized.startswith("update sessions"):
            return self._touch(normalized, args)
        if method == "fetchrow" and "sessions" in normalized:
            return self._session_row(args)
        if method == "fetchrow" and "users" in normalized and "insert" not in normalized:
            return self._account_by_email(args)
        if method == "fetch":
            return []
        if method in {"fetchrow", "fetchval"}:
            return None
        return "OK"

    def _insert_session(self, sql: str, args: tuple[Any, ...]) -> None:
        self.session_inserts.append((sql, args))
        values = insert_values(sql, args)
        if values.get("idle_timeout_minutes") is None:
            msg = 'null value in column "idle_timeout_minutes" of relation "sessions"'
            raise asyncpg.exceptions.NotNullViolationError(msg)
        now = datetime.now(UTC)
        expires_at = values["expires_at"]
        if isinstance(expires_at, NowPlus):
            expires_at = now + expires_at.interval
        self.sessions[values["token_hash"]] = {
            "session_id": PgUUID(str(uuid.uuid4())),
            "user_id": _plain(values["user_id"]),
            "expires_at": expires_at,
            "last_seen_at": now,
            "idle_timeout_minutes": values["idle_timeout_minutes"],
        }

    def _delete(self, normalized: str, args: tuple[Any, ...]) -> str:
        """Logout: DELETE FROM sessions WHERE token_hash = $1."""
        assert "token_hash" in normalized, normalized
        token_hash = next(arg for arg in args if isinstance(arg, bytes))
        return "DELETE 1" if self.sessions.pop(token_hash, None) is not None else "DELETE 0"

    def _touch(self, normalized: str, args: tuple[Any, ...]) -> str:
        """The throttled UPDATE sessions SET last_seen_at = now() WHERE id = $n."""
        match = re.search(r"(?<![\w.])(?:\w+\.)?id = \$(\d+)", normalized)
        assert match is not None, normalized
        session_id = str(args[int(match.group(1)) - 1])
        count = 0
        for session in self.sessions.values():
            if str(session["session_id"]) == session_id:
                session["last_seen_at"] = datetime.now(UTC)
                count += 1
        return f"UPDATE {count}"

    def _session_row(self, args: tuple[Any, ...]) -> dict[str, Any] | None:
        token_hash = next((arg for arg in args if isinstance(arg, bytes)), None)
        session = self.sessions.get(token_hash) if token_hash is not None else None
        if session is None:
            return None
        account = self.accounts[session["user_id"]]
        return {
            "session_id": session["session_id"],
            "expires_at": session["expires_at"],
            "last_seen_at": session["last_seen_at"],
            "idle_timeout_minutes": session["idle_timeout_minutes"],
            "user_id": account["id"],
            "kind": account["kind"],
            "org_id": account["org_id"],
            "role": account["role"],
            "status": account["status"],
            "deleted_at": account["deleted_at"],
            "org_status": account["org_status"],
            "ui_language": account["ui_language"],
            "response_language": account["response_language"],
        }

    def _account_by_email(self, args: tuple[Any, ...]) -> dict[str, Any] | None:
        email = next((arg for arg in args if isinstance(arg, str)), None)
        if email is None:
            return None
        for account in self.accounts.values():
            if account["email"].casefold() == email.casefold():
                return dict(account)
        return None

    # -- password stand-in ---------------------------------------------------

    def verify(self, password: str, encoded: str) -> bool:
        """Fast stand-in for passwords.verify_password."""
        return encoded == _fake_hash(password)


class _FakeConnection:
    """Pool/connection methods, all routed to the fake database."""

    def __init__(self, db: _FakeDb) -> None:
        self._db = db

    async def execute(self, sql: str, *args: Any) -> Any:
        return self._db.handle("execute", sql, args)

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        return self._db.handle("fetchrow", sql, args)

    async def fetchval(self, sql: str, *args: Any) -> Any:
        return self._db.handle("fetchval", sql, args)

    async def fetch(self, sql: str, *args: Any) -> Any:
        return self._db.handle("fetch", sql, args)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        yield

    def is_in_transaction(self) -> bool:
        return True


class _FakePool(_FakeConnection):
    """The pool: acquire() yields a connection on the same fake database."""

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[_FakeConnection]:
        yield _FakeConnection(self._db)


# ---------------------------------------------------------------------------
# Fake agent, config, app and client helpers
# ---------------------------------------------------------------------------


class _FakeAgent:
    """Records every run; principal is a required keyword, as on the real Agent."""

    def __init__(self) -> None:
        self.run_calls: list[dict[str, Any]] = []

    async def run(
        self,
        user_message: str,
        session_id: str,
        *,
        history: list[LLMMessage],
        principal: Principal,
        pending_confirmation: PendingConfirmation | None = None,
    ) -> AgentResult:
        self.run_calls.append(
            {
                "user_message": user_message,
                "session_id": session_id,
                "principal": principal,
                "pending_confirmation": pending_confirmation,
            }
        )
        return AgentResult(
            status="final",
            response="Hello from the agent.",
            history=[
                LLMMessage(role="user", content="hello"),
                LLMMessage(role="assistant", content="Hello from the agent."),
            ],
            tool_calls=[],
        )


def _config(*, cookie_secure: bool = True) -> MagicMock:
    """A minimal config; the old auth section is gone, so reading it fails."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "127.0.0.1"
    config.server.port = 8000
    config.server.cookie_secure = cookie_secure
    config.llm.provider = "infomaniak"
    config.llm.active_model_name = "test-model"
    return config


def _app(agent: _FakeAgent | None = None, *, cookie_secure: bool = True) -> FastAPI:
    """create_app with the fake agent and config (no lifespan runs under TestClient)."""
    return create_app(agent=agent or _FakeAgent(), config=_config(cookie_secure=cookie_secure))  # type: ignore[arg-type]


def _client(app: FastAPI, ip: str = _IP_A) -> TestClient:
    """A client whose peer address is ``ip``; redirects are not followed."""
    return TestClient(app, client=(ip, 50000), follow_redirects=False)


def _cookie(token: str) -> dict[str, str]:
    """The request header carrying a session cookie."""
    return {"Cookie": f"{_COOKIE}={token}"}


def _session_set_cookie(response: httpx.Response) -> tuple[str, dict[str, str | None]]:
    """Return (value, attributes) of the one admino_session Set-Cookie header."""
    headers = [
        h for h in response.headers.get_list("set-cookie") if h.lower().startswith(f"{_COOKIE}=")
    ]
    assert len(headers) == 1, response.headers.get_list("set-cookie")
    parts = [part.strip() for part in headers[0].split(";")]
    value = parts[0].split("=", 1)[1]
    attributes: dict[str, str | None] = {}
    for part in parts[1:]:
        key, sep, attr_value = part.partition("=")
        attributes[key.strip().lower()] = attr_value.strip() if sep else None
    return value, attributes


def _session_cookie_headers(response: httpx.Response) -> list[str]:
    """Every Set-Cookie header naming admino_session."""
    return [
        h for h in response.headers.get_list("set-cookie") if h.lower().startswith(f"{_COOKIE}=")
    ]


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> _FakeDb:
    """The fake database the server's get_pool() returns."""
    fake = _FakeDb()
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


@pytest.fixture()
def fast_passwords(db: _FakeDb, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Argon2 with a fast fake (the real hashing is covered by test_passwords)."""
    monkeypatch.setattr("admino.passwords.verify_password", db.verify)
    monkeypatch.setattr("admino.passwords.needs_rehash", lambda _encoded: False)
    monkeypatch.setattr("admino.passwords.hash_password", _fake_hash)


def _login(client: TestClient, email: str, password: str = _PASSWORD, **kwargs: Any) -> Any:
    """POST /api/auth/login, then drop whatever cookie the client jar picked up."""
    response = client.post("/api/auth/login", json={"email": email, "password": password}, **kwargs)
    client.cookies.clear()
    return response


# ---------------------------------------------------------------------------
# 1. POST /api/auth/login
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fast_passwords")
class TestLoginSuccess:
    """A valid login answers 204 and sets the session cookie."""

    def test_auth_api_login_returns_204_with_empty_body(self, db: _FakeDb) -> None:
        """204 No Content, no body."""
        account = db.add_account()

        response = _login(_client(_app()), account["email"])

        assert response.status_code == 204
        assert response.content == b""

    @pytest.mark.parametrize("cookie_secure", [True, False])
    def test_auth_api_login_cookie_flags(self, db: _FakeDb, cookie_secure: bool) -> None:
        """HttpOnly, SameSite=Strict, Path=/, Max-Age=43200 (12 h), no Domain, and Secure
        exactly when server.cookie_secure is set."""
        account = db.add_account()

        response = _login(_client(_app(cookie_secure=cookie_secure)), account["email"])

        _, attributes = _session_set_cookie(response)
        assert "httponly" in attributes
        assert (attributes.get("samesite") or "").lower() == "strict"
        assert attributes.get("path") == "/"
        assert attributes.get("max-age") == "43200"
        assert "domain" not in attributes
        assert ("secure" in attributes) is cookie_secure

    def test_auth_api_login_cookie_holds_the_stored_session_token(self, db: _FakeDb) -> None:
        """The cookie value is a token_urlsafe(32) token whose SHA-256 is the stored hash,
        for the account that logged in."""
        account = db.add_account()

        response = _login(_client(_app()), account["email"])

        token, _ = _session_set_cookie(response)
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is not None
        assert db.sessions[_sha256(token)]["user_id"] == _plain(account["id"])

    def test_auth_api_login_cookie_authenticates_the_next_request(self, db: _FakeDb) -> None:
        """The issued cookie resolves to the account on GET /api/auth/me."""
        account = db.add_account()
        client = _client(_app())
        token, _ = _session_set_cookie(_login(client, account["email"]))

        response = client.get("/api/auth/me", headers=_cookie(token))

        assert response.status_code == 200
        assert response.json()["user_id"] == str(_plain(account["id"]))

    def test_auth_api_login_email_is_case_insensitive(self, db: _FakeDb) -> None:
        """The account is found whatever the email's casing."""
        db.add_account(email="Mixed.Case@Example.test")

        response = _login(_client(_app()), "mixed.case@EXAMPLE.test")

        assert response.status_code == 204

    def test_auth_api_login_stores_client_ip_and_user_agent(self, db: _FakeDb) -> None:
        """The session row gets the peer address and the User-Agent header."""
        account = db.add_account()

        _login(
            _client(_app(), ip=_IP_A),
            account["email"],
            headers={"User-Agent": "pytest-browser/1.0"},
        )

        assert len(db.session_inserts) == 1
        _, args = db.session_inserts[0]
        assert any(str(arg) == _IP_A for arg in args)
        assert "pytest-browser/1.0" in args

    def test_auth_api_super_admin_can_log_in(self, db: _FakeDb) -> None:
        """A Super Admin (no org) logs in like anyone else."""
        account = db.add_account(kind="super_admin", role=None, org_status=None)

        assert _login(_client(_app()), account["email"]).status_code == 204


def _failing_logins(db: _FakeDb) -> dict[str, tuple[str, str]]:
    """(email, password) for every failure cause."""
    active = db.add_account()
    return {
        "unknown-email": ("nobody@example.test", _PASSWORD),
        "wrong-password": (active["email"], _WRONG_PASSWORD),
        "invited": (db.add_account(status="invited")["email"], _PASSWORD),
        "deactivated": (db.add_account(status="deactivated")["email"], _PASSWORD),
        "deleted": (db.add_account(deleted_at=datetime.now(UTC))["email"], _PASSWORD),
        "org-deactivated": (db.add_account(org_status="deactivated")["email"], _PASSWORD),
        "org-pending-deletion": (db.add_account(org_status="pending_deletion")["email"], _PASSWORD),
    }


_FAILURE_CAUSES = [
    "unknown-email",
    "wrong-password",
    "invited",
    "deactivated",
    "deleted",
    "org-deactivated",
    "org-pending-deletion",
]


@pytest.mark.usefixtures("fast_passwords")
class TestLoginFailure:
    """Every failure answers the same 401 and sets no cookie."""

    @pytest.mark.parametrize("cause", _FAILURE_CAUSES)
    def test_auth_api_login_failure_is_401_generic(self, db: _FakeDb, cause: str) -> None:
        """401 {"detail": "Invalid email or password"}."""
        email, password = _failing_logins(db)[cause]

        response = _login(_client(_app()), email, password)

        assert response.status_code == 401
        assert response.json() == _LOGIN_FAILED

    def test_auth_api_login_failure_bodies_are_identical(self, db: _FakeDb) -> None:
        """Unknown email, wrong password and inactive accounts are indistinguishable."""
        cases = _failing_logins(db)
        app = _app()

        # One IP per attempt, so the per-IP login limit (burst 5) doesn't interfere.
        responses = [
            _login(_client(app, ip=f"192.0.2.{index}"), email, password)
            for index, (email, password) in enumerate(cases.values(), start=1)
        ]

        assert {r.status_code for r in responses} == {401}
        assert len({r.content for r in responses}) == 1
        assert len({r.headers.get("content-type") for r in responses}) == 1

    @pytest.mark.parametrize("cause", _FAILURE_CAUSES)
    def test_auth_api_login_failure_sets_no_cookie(self, db: _FakeDb, cause: str) -> None:
        """No admino_session cookie on failure, and no session row."""
        email, password = _failing_logins(db)[cause]

        response = _login(_client(_app()), email, password)

        assert _session_cookie_headers(response) == []
        assert db.session_inserts == []

    @pytest.mark.parametrize("cause", _FAILURE_CAUSES)
    def test_auth_api_login_failure_does_not_echo_input(self, db: _FakeDb, cause: str) -> None:
        """The response carries neither the email nor the password."""
        email, password = _failing_logins(db)[cause]

        response = _login(_client(_app()), email, password)

        assert email.casefold() not in response.text.casefold()
        assert password not in response.text

    def test_auth_api_login_logs_no_email_password_or_token(
        self, db: _FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Neither a successful nor a failed login logs the email, password or token."""
        caplog.set_level(logging.DEBUG)
        account = db.add_account(email="log.marker@example.test")
        client = _client(_app())

        ok = _login(client, account["email"])
        _login(client, account["email"], _WRONG_PASSWORD)
        _login(client, "ghost.marker@example.test")

        token, _ = _session_set_cookie(ok)
        text = caplog.text.casefold()
        assert "log.marker" not in text
        assert "ghost.marker" not in text
        assert _PASSWORD.casefold() not in text
        assert token not in caplog.text


_MARKER_PASSWORD = "Zx7SECRETmarkerPw"


@pytest.mark.usefixtures("fast_passwords")
class TestLoginValidation:
    """A malformed body is a 422 that doesn't echo the input."""

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({}, id="empty"),
            pytest.param({"email": "someone@example.test"}, id="no-password"),
            pytest.param({"password": _MARKER_PASSWORD}, id="no-email"),
            pytest.param({"email": "a@", "password": _MARKER_PASSWORD}, id="email-too-short"),
            pytest.param(
                {"email": "a" * 250 + "@x.ch", "password": _MARKER_PASSWORD}, id="email-too-long"
            ),
            pytest.param({"email": "someone@example.test", "password": ""}, id="empty-password"),
            pytest.param(
                {"email": "someone@example.test", "password": _MARKER_PASSWORD * 8},
                id="password-too-long",
            ),
            pytest.param({"email": 12345, "password": _MARKER_PASSWORD}, id="email-not-a-string"),
            pytest.param(
                {"email": "someone@example.test", "password": _MARKER_PASSWORD, "role": "admin"},
                id="extra-field",
            ),
        ],
    )
    def test_auth_api_login_bad_body_is_422_without_echo(
        self, db: _FakeDb, body: dict[str, Any]
    ) -> None:
        """422, the password never repeated, and no account lookup."""
        response = _client(_app()).post("/api/auth/login", json=body)

        assert response.status_code == 422
        assert _MARKER_PASSWORD not in response.text
        assert db.calls == []

    def test_auth_api_login_non_json_body_is_422(self, db: _FakeDb) -> None:
        """A body that isn't JSON is refused."""
        response = _client(_app()).post(
            "/api/auth/login",
            content=b"email=a@b.ch&password=" + _MARKER_PASSWORD.encode(),
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 422
        assert _MARKER_PASSWORD not in response.text

    def test_auth_api_login_request_model_hides_the_password(self) -> None:
        """LoginRequest keeps the password as a SecretStr: repr() doesn't show it."""
        request = models.LoginRequest(email="someone@example.test", password=_MARKER_PASSWORD)  # type: ignore[attr-defined]

        assert _MARKER_PASSWORD not in repr(request)
        assert _MARKER_PASSWORD not in str(request)


# ---------------------------------------------------------------------------
# 2. POST /api/auth/logout and GET /api/auth/me
# ---------------------------------------------------------------------------


class TestLogout:
    """Logout deletes the current session's row and clears the cookie."""

    def test_auth_api_logout_returns_204(self, db: _FakeDb) -> None:
        """204, empty body."""
        token = db.open_session(db.add_account())

        response = _client(_app()).post("/api/auth/logout", headers=_cookie(token))

        assert response.status_code == 204
        assert response.content == b""

    def test_auth_api_logout_deletes_the_session_row(self, db: _FakeDb) -> None:
        """The stored session is deleted through DELETE FROM sessions ... token hash (GH-152:
        rows don't outlive their session)."""
        token = db.open_session(db.add_account())

        _client(_app()).post("/api/auth/logout", headers=_cookie(token))

        assert _sha256(token) not in db.sessions

    def test_auth_api_logout_session_no_longer_works(self, db: _FakeDb) -> None:
        """The same cookie is refused afterwards."""
        token = db.open_session(db.add_account())
        client = _client(_app())

        client.post("/api/auth/logout", headers=_cookie(token))
        response = client.get("/api/auth/me", headers=_cookie(token))

        assert response.status_code == 401

    def test_auth_api_logout_clears_the_cookie(self, db: _FakeDb) -> None:
        """Set-Cookie: admino_session=""; Max-Age=0; Path=/."""
        token = db.open_session(db.add_account())

        response = _client(_app()).post("/api/auth/logout", headers=_cookie(token))

        value, attributes = _session_set_cookie(response)
        assert value in {"", '""'}
        assert attributes.get("max-age") == "0"
        assert attributes.get("path") == "/"

    def test_auth_api_logout_leaves_other_sessions_alone(self, db: _FakeDb) -> None:
        """Only the current session is deleted, not the user's other devices."""
        account = db.add_account()
        current = db.open_session(account)
        other = db.open_session(account)
        client = _client(_app())

        client.post("/api/auth/logout", headers=_cookie(current))

        assert _sha256(other) in db.sessions
        assert client.get("/api/auth/me", headers=_cookie(other)).status_code == 200

    def test_auth_api_logout_requires_a_session(self, db: _FakeDb) -> None:
        """No cookie → 401."""
        response = _client(_app()).post("/api/auth/logout")

        assert response.status_code == 401
        assert response.json() == _UNAUTHORIZED


class TestMe:
    """GET /api/auth/me returns the resolved principal and languages, nothing more."""

    def test_auth_api_me_returns_member_principal(self, db: _FakeDb) -> None:
        """user_id, kind, org_id, role, ui_language, response_language — exactly."""
        account = db.add_account(role="org_admin", ui_language="fr", response_language="it")
        token = db.open_session(account)

        response = _client(_app()).get("/api/auth/me", headers=_cookie(token))

        assert response.status_code == 200
        assert response.json() == {
            "user_id": str(_plain(account["id"])),
            "kind": "member",
            "org_id": str(_ORG_ID),
            "role": "org_admin",
            "ui_language": "fr",
            "response_language": "it",
        }

    def test_auth_api_me_returns_super_admin_principal(self, db: _FakeDb) -> None:
        """A Super Admin has no org and no role."""
        account = db.add_account(
            kind="super_admin", role=None, org_status=None, ui_language="en", response_language=None
        )
        token = db.open_session(account)

        response = _client(_app()).get("/api/auth/me", headers=_cookie(token))

        assert response.json() == {
            "user_id": str(_plain(account["id"])),
            "kind": "super_admin",
            "org_id": None,
            "role": None,
            "ui_language": "en",
            "response_language": None,
        }

    def test_auth_api_me_ignores_request_claims(self, db: _FakeDb) -> None:
        """Query parameters or headers claiming another identity change nothing."""
        account = db.add_account(role="viewer")
        token = db.open_session(account)

        response = _client(_app()).get(
            "/api/auth/me",
            params={"kind": "super_admin", "role": "org_admin", "user_id": str(uuid.uuid4())},
            headers={**_cookie(token), "X-User-Id": str(uuid.uuid4()), "X-Role": "org_admin"},
        )

        body = response.json()
        assert (body["user_id"], body["kind"], body["role"]) == (
            str(_plain(account["id"])),
            "member",
            "viewer",
        )

    def test_auth_api_me_requires_a_session(self, db: _FakeDb) -> None:
        """No cookie → 401."""
        assert _client(_app()).get("/api/auth/me").status_code == 401


# ---------------------------------------------------------------------------
# 3. Every non-public route requires a session (route enumeration)
# ---------------------------------------------------------------------------


def _depends_on(dependant: Dependant, target: Callable[..., Any]) -> bool:
    """True when the dependency tree below ``dependant`` contains ``target``."""
    return any(dep.call is target or _depends_on(dep, target) for dep in dependant.dependencies)


def _query_names(dependant: Dependant) -> list[str]:
    """The query parameter names of a route, including its sub-dependencies'."""
    names = [param.alias for param in dependant.query_params]
    for dep in dependant.dependencies:
        names.extend(_query_names(dep))
    return names


def _api_routes(app: FastAPI) -> list[tuple[str, str, APIRoute]]:
    """(method, path, route) for every APIRoute of the app."""
    return [
        (method, route.path, route)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in sorted(route.methods)
    ]


def _request_route(
    client: TestClient, method: str, route: APIRoute, headers: dict[str, str]
) -> Any:
    """Call a route with valid dummy path/query values and a minimal JSON body."""
    url = re.sub(r"\{(\w+)(?::\w+)?\}", lambda m: _PATH_VALUES.get(m.group(1), "x1"), route.path)
    kwargs: dict[str, Any] = {
        "headers": headers,
        "params": dict.fromkeys(_query_names(route.dependant), "s1"),
    }
    if route.body_field is not None:
        kwargs["json"] = {}
    return client.request(method, url, **kwargs)


def _credentials(db: _FakeDb, variant: str) -> dict[str, str]:
    """Request headers for one kind of missing or unusable session."""
    if variant == "no-cookie":
        return {}
    if variant == "malformed-cookie":
        return _cookie("not-a-session-token")
    if variant == "unknown-token":
        return _cookie(secrets.token_urlsafe(32))
    if variant == "wrong-cookie-name":
        return {"Cookie": f"session={db.open_session(db.add_account())}"}
    if variant == "revoked":
        # Revoking deletes the row (GH-152): the cookie names a session that is gone.
        token = db.open_session(db.add_account())
        del db.sessions[_sha256(token)]
        return _cookie(token)
    if variant == "expired":
        return _cookie(db.open_session(db.add_account(), expired=True))
    if variant == "idle":
        return _cookie(db.open_session(db.add_account(), idle=True))
    if variant == "user-deactivated":
        return _cookie(db.open_session(db.add_account(status="deactivated")))
    if variant == "org-deactivated":
        return _cookie(db.open_session(db.add_account(org_status="deactivated")))
    msg = f"unknown variant {variant}"
    raise AssertionError(msg)


_UNUSABLE_SESSIONS = [
    "no-cookie",
    "malformed-cookie",
    "unknown-token",
    "wrong-cookie-name",
    "revoked",
    "expired",
    "idle",
    "user-deactivated",
    "org-deactivated",
]


class TestRouteEnumeration:
    """Walk app.routes: every route outside the public allowlist requires a session."""

    def test_auth_api_public_routes_exist(self) -> None:
        """/health, the login, the password reset endpoints and the OAuth callback are
        registered."""
        routes = {(method, path) for method, path, _ in _api_routes(_app())}

        assert routes >= _PUBLIC_ROUTES

    def test_auth_api_known_protected_routes_exist(self) -> None:
        """The enumeration isn't vacuous: every known protected route is registered."""
        routes = {(method, path) for method, path, _ in _api_routes(_app())}

        assert routes >= _KNOWN_PROTECTED_ROUTES

    def test_auth_api_every_non_public_route_depends_on_require_session(self) -> None:
        """Each APIRoute outside the allowlist has server.require_session in its
        dependency tree (directly or via require_principal / require_chat_sender)."""
        offenders = [
            f"{method} {path}"
            for method, path, route in _api_routes(_app())
            if (method, path) not in _PUBLIC_ROUTES
            and not _depends_on(route.dependant, server.require_session)
        ]

        assert offenders == []

    def test_auth_api_public_routes_do_not_depend_on_require_session(self) -> None:
        """The OAuth callback is the provider's cross-site redirect (a SameSite=Strict
        cookie isn't sent on it); /health and the login must work logged out."""
        dependent = [
            f"{method} {path}"
            for method, path, route in _api_routes(_app())
            if (method, path) in _PUBLIC_ROUTES
            and _depends_on(route.dependant, server.require_session)
        ]

        assert dependent == []

    @pytest.mark.parametrize("variant", _UNUSABLE_SESSIONS)
    def test_auth_api_every_non_public_route_answers_401(self, db: _FakeDb, variant: str) -> None:
        """Without a usable session every protected route answers 401 Unauthorized."""
        app = _app()
        client = _client(app)
        offenders: list[str] = []
        checked = 0
        for method, path, route in _api_routes(app):
            if (method, path) in _PUBLIC_ROUTES:
                continue
            checked += 1
            # Each route starts from a fresh per-IP budget: this test checks the 401, not
            # the unresolved-cookie throttle (pinned by TestUnresolvedSessionThrottle), which
            # would otherwise answer 429 once the routes outnumber its burst.
            server._rate_buckets.clear()
            response = _request_route(client, method, route, _credentials(db, variant))
            if response.status_code != 401 or response.json() != _UNAUTHORIZED:
                offenders.append(f"{method} {path}: {response.status_code} {response.text[:80]}")

        assert checked >= len(_KNOWN_PROTECTED_ROUTES)
        assert offenders == []

    def test_auth_api_no_plain_route_is_reachable_without_a_session(self, db: _FakeDb) -> None:
        """Non-API routes (e.g. an OpenAPI schema endpoint) don't leak the API surface to
        anonymous callers: each one answers 401 without a session, or doesn't exist.
        Static files are served by a Mount and stay public."""
        app = _app()
        client = _client(app)
        offenders: list[str] = []
        for route in app.routes:
            if not isinstance(route, Route) or isinstance(route, APIRoute):
                continue
            for method in sorted((route.methods or {"GET"}) - {"HEAD"}):
                status = client.request(method, route.path).status_code
                if status != 401:
                    offenders.append(f"{method} {route.path}: {status}")

        assert offenders == []

    def test_auth_api_health_needs_no_session(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GET /health answers without a cookie."""
        monkeypatch.setattr("admino.database.check_health", AsyncMock(return_value=True))

        response = _client(_app()).get("/health")

        assert response.status_code == 200

    def test_auth_api_oauth_callback_needs_no_session(self, db: _FakeDb) -> None:
        """The provider's redirect reaches the callback without a cookie (state-checked)."""
        response = _client(_app()).get("/api/oauth/callback", params={"state": "unknown-state"})

        assert response.status_code == 307
        assert "invalid_state" in response.headers["location"]

    @pytest.mark.parametrize("variant", ["no-cookie", "malformed-cookie"])
    def test_auth_api_missing_or_malformed_cookie_never_queries(
        self, db: _FakeDb, variant: str
    ) -> None:
        """No cookie or a malformed one is refused before any database query."""
        headers = _credentials(db, variant)

        response = _client(_app()).get("/api/auth/me", headers=headers)

        assert response.status_code == 401
        assert db.calls == []


# ---------------------------------------------------------------------------
# 4. The session is re-checked on every request
# ---------------------------------------------------------------------------


class TestOpenSessionRevalidated:
    """A deactivated user or org is refused on an already-open session."""

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("status", "deactivated"),
            ("deleted_at", datetime.now(UTC)),
            ("org_status", "deactivated"),
            ("org_status", "pending_deletion"),
        ],
    )
    def test_auth_api_open_session_refused_after_deactivation(
        self, db: _FakeDb, field: str, value: Any
    ) -> None:
        """200 while active; 401 on the very next request after the change."""
        account = db.add_account()
        token = db.open_session(account)
        client = _client(_app())
        assert client.get("/api/auth/me", headers=_cookie(token)).status_code == 200

        account[field] = value

        assert client.get("/api/auth/me", headers=_cookie(token)).status_code == 401
        assert (
            client.post("/api/message", json=_CHAT_BODY, headers=_cookie(token)).status_code == 401
        )

    def test_auth_api_role_change_applies_on_the_next_request(self, db: _FakeDb) -> None:
        """An editor demoted to viewer loses chat on the next request."""
        account = db.add_account(role="editor")
        token = db.open_session(account)
        client = _client(_app())
        assert (
            client.post("/api/message", json=_CHAT_BODY, headers=_cookie(token)).status_code == 200
        )

        account["role"] = "viewer"

        response = client.post("/api/message", json=_CHAT_BODY, headers=_cookie(token))
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# 5. Chat routes need chat.send
# ---------------------------------------------------------------------------


def _chat_request(client: TestClient, route: str, token: str) -> Any:
    """Call one of the chat routes with a valid request."""
    if route == "message":
        return client.post("/api/message", json=_CHAT_BODY, headers=_cookie(token))
    if route == "confirm":
        return client.post(
            "/api/confirm/c1",
            json={"session_id": "chat-1", "confirmation_id": "c1", "approved": True},
            headers=_cookie(token),
        )
    return client.get("/api/events", params={"session_id": "chat-1"}, headers=_cookie(token))


class TestChatRoleGate:
    """POST /api/message, POST /api/confirm/{id} and GET /api/events need chat.send."""

    @pytest.mark.parametrize("route", ["message", "confirm", "events"])
    @pytest.mark.parametrize(
        "who",
        [
            pytest.param(
                {"kind": "super_admin", "role": None, "org_status": None}, id="super-admin"
            ),
            pytest.param({"role": "viewer"}, id="viewer"),
        ],
    )
    def test_auth_api_chat_forbidden_without_chat_send(
        self, db: _FakeDb, route: str, who: dict[str, Any]
    ) -> None:
        """A Super Admin (operator blindness) and a Viewer (read-only) get 403 Forbidden,
        and the agent never runs."""
        agent = _FakeAgent()
        token = db.open_session(db.add_account(**who))

        response = _chat_request(_client(_app(agent)), route, token)

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        assert agent.run_calls == []

    @pytest.mark.parametrize("route", ["message", "confirm", "events"])
    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    def test_auth_api_chat_allowed_for_org_admin_and_editor(
        self, db: _FakeDb, route: str, role: str
    ) -> None:
        """Org Admins and Editors get through the gate (the confirm route then answers
        404 because nothing is pending)."""
        token = db.open_session(db.add_account(role=role))

        response = _chat_request(_client(_app()), route, token)

        assert response.status_code == (404 if route == "confirm" else 200)

    def test_auth_api_message_passes_the_callers_principal_to_the_agent(self, db: _FakeDb) -> None:
        """agent.run(..., principal=<the logged-in member>), with plain uuid.UUID IDs."""
        agent = _FakeAgent()
        account = db.add_account(role="editor")
        token = db.open_session(account)

        response = _client(_app(agent)).post(
            "/api/message", json=_CHAT_BODY, headers=_cookie(token)
        )

        assert response.status_code == 200
        principal = agent.run_calls[0]["principal"]
        assert type(principal) is Principal
        assert principal == Principal(
            user_id=_plain(account["id"]), kind="member", org_id=_ORG_ID, role="editor"
        )
        assert type(principal.user_id) is uuid.UUID
        assert type(principal.org_id) is uuid.UUID

    def test_auth_api_confirm_passes_the_callers_principal_to_the_agent(self, db: _FakeDb) -> None:
        """Resuming a confirmation runs the agent with the caller's principal too."""
        agent = _FakeAgent()
        account = db.add_account(role="org_admin")
        token = db.open_session(account)
        app = _app(agent)
        now = datetime.now(UTC)
        server._pending_confirmations[server._chat_key(_plain(account["id"]), "chat-1")] = (
            PendingConfirmation(
                confirmation_id="c1",
                session_id="chat-1",
                tool_call=ToolCall(tool="google_calendar", action="create", args={}),
                created_at=now,
                expires_at=now + timedelta(minutes=5),
            )
        )

        response = _chat_request(_client(app), "confirm", token)

        assert response.status_code == 200
        assert agent.run_calls[0]["principal"] == Principal(
            user_id=_plain(account["id"]), kind="member", org_id=_ORG_ID, role="org_admin"
        )
        assert agent.run_calls[0]["pending_confirmation"] is not None

    def test_auth_api_require_chat_sender_depends_on_require_principal(self) -> None:
        """The dependency chain: require_chat_sender → require_principal → require_session."""
        chat = get_dependant(path="/", call=server.require_chat_sender)
        principal = get_dependant(path="/", call=server.require_principal)

        assert server.require_principal in [dep.call for dep in chat.dependencies]
        assert server.require_session in [dep.call for dep in principal.dependencies]


# ---------------------------------------------------------------------------
# 6. CSRF (Go CrossOriginProtection algorithm)
# ---------------------------------------------------------------------------

_CSRF_CASES: list[Any] = [
    pytest.param({"Sec-Fetch-Site": "cross-site"}, False, id="sfs-cross-site"),
    pytest.param({"Sec-Fetch-Site": "same-site"}, False, id="sfs-same-site"),
    pytest.param({"Sec-Fetch-Site": "same-origin"}, True, id="sfs-same-origin"),
    pytest.param({"Sec-Fetch-Site": "none"}, True, id="sfs-none"),
    pytest.param({"Origin": "https://evil.example"}, False, id="origin-foreign"),
    pytest.param({"Origin": "null"}, False, id="origin-null"),
    pytest.param({"Origin": "http://testserver"}, True, id="origin-matches-host"),
    pytest.param({"Origin": "https://testserver"}, True, id="origin-matches-host-other-scheme"),
    pytest.param({"Origin": "http://testserver:8443"}, False, id="origin-other-port"),
    pytest.param({"Origin": "http://testserver.evil.example"}, False, id="origin-suffix-trick"),
    pytest.param({"Origin": "http://eviltestserver"}, False, id="origin-prefix-trick"),
    pytest.param({}, True, id="no-browser-headers"),
    pytest.param(
        {"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.example"},
        True,
        id="sfs-decides-over-origin",
    ),
    pytest.param(
        {"Sec-Fetch-Site": "cross-site", "Origin": "http://testserver"},
        False,
        id="sfs-cross-site-wins",
    ),
]


class TestCsrf:
    """State-changing requests must be same-origin; GETs are never blocked."""

    @pytest.mark.parametrize(("headers", "allowed"), _CSRF_CASES)
    def test_auth_api_csrf_matrix_on_post_message(
        self, db: _FakeDb, headers: dict[str, str], allowed: bool
    ) -> None:
        """With a valid session: allowed → 200 and the agent runs; refused → 403 before
        anything else happens."""
        agent = _FakeAgent()
        token = db.open_session(db.add_account())

        response = _client(_app(agent)).post(
            "/api/message", json=_CHAT_BODY, headers={**_cookie(token), **headers}
        )

        if allowed:
            assert response.status_code == 200
            assert len(agent.run_calls) == 1
        else:
            assert response.status_code == 403
            assert response.json() == _CSRF_REFUSED
            assert agent.run_calls == []

    @pytest.mark.parametrize(
        ("method", "path", "body"),
        [
            ("PATCH", "/api/settings", {}),
            (
                "PATCH",
                "/api/permissions",
                {"tool": "memory", "action": "read", "permission": "allow"},
            ),
            ("PATCH", "/api/critical-permissions/gmail/send", None),
            ("DELETE", "/api/critical-permissions/gmail/send/pending", None),
            ("DELETE", "/api/oauth/google", None),
            ("POST", "/api/auth/logout", None),
        ],
    )
    def test_auth_api_csrf_applies_to_every_state_changing_method(
        self, db: _FakeDb, method: str, path: str, body: dict[str, Any] | None
    ) -> None:
        """PATCH, DELETE and POST routes all refuse a cross-site request."""
        token = db.open_session(db.add_account(role="org_admin"))
        kwargs: dict[str, Any] = {"headers": {**_cookie(token), "Sec-Fetch-Site": "cross-site"}}
        if body is not None:
            kwargs["json"] = body

        response = _client(_app()).request(method, path, **kwargs)

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED

    def test_auth_api_csrf_logout_refused_keeps_the_session(self, db: _FakeDb) -> None:
        """A cross-site logout is refused and deletes nothing."""
        token = db.open_session(db.add_account())

        _client(_app()).post(
            "/api/auth/logout", headers={**_cookie(token), "Sec-Fetch-Site": "cross-site"}
        )

        assert _sha256(token) in db.sessions

    def test_auth_api_csrf_runs_before_authentication(self, db: _FakeDb) -> None:
        """A cross-site POST without a cookie is a 403 (CSRF), not a 401."""
        response = _client(_app()).post(
            "/api/message", json=_CHAT_BODY, headers={"Sec-Fetch-Site": "cross-site"}
        )

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED

    @pytest.mark.usefixtures("fast_passwords")
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
            pytest.param({"Origin": "null"}, id="origin-null"),
        ],
    )
    def test_auth_api_csrf_refuses_login_csrf(self, db: _FakeDb, headers: dict[str, str]) -> None:
        """Login CSRF: a cross-origin login is refused before the account lookup and sets
        no cookie, even with valid credentials."""
        account = db.add_account()

        response = _client(_app()).post(
            "/api/auth/login",
            json={"email": account["email"], "password": _PASSWORD},
            headers=headers,
        )

        assert response.status_code == 403
        assert response.json() == _CSRF_REFUSED
        assert _session_cookie_headers(response) == []
        assert db.calls == []

    @pytest.mark.usefixtures("fast_passwords")
    def test_auth_api_csrf_same_origin_login_passes(self, db: _FakeDb) -> None:
        """A same-origin login (what the PWA sends) works."""
        account = db.add_account()

        response = _client(_app()).post(
            "/api/auth/login",
            json={"email": account["email"], "password": _PASSWORD},
            headers={"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver"},
        )

        assert response.status_code == 204

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Sec-Fetch-Site": "cross-site"}, id="sfs-cross-site"),
            pytest.param({"Origin": "https://evil.example"}, id="origin-foreign"),
        ],
    )
    def test_auth_api_csrf_never_blocks_get(self, db: _FakeDb, headers: dict[str, str]) -> None:
        """GET is safe by method: a cross-site GET passes the CSRF check."""
        token = db.open_session(db.add_account())

        response = _client(_app()).get("/api/auth/me", headers={**_cookie(token), **headers})

        assert response.status_code == 200


# ---------------------------------------------------------------------------
# 7. Rate limits per caller
# ---------------------------------------------------------------------------


class _Clock:
    """A controllable time.monotonic (patched in time and, if imported, in server)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = 10_000.0
        monkeypatch.setattr(time, "monotonic", self)
        if hasattr(server, "monotonic"):
            monkeypatch.setattr(server, "monotonic", self)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# Existing per-route rates stay; #149 adds the three auth routes, #152 the three session
# management routes.
_EXPECTED_RATES: dict[str, tuple[float, int]] = {
    "/api/message": (0.5, 5),
    "/api/confirm": (0.5, 5),
    "/api/events": (0.17, 3),
    "/api/settings/get": (1.0, 5),
    "/api/settings/patch": (0.2, 2),
    "/api/permissions/get": (1.0, 5),
    "/api/permissions/patch": (0.2, 2),
    "/api/oauth/google/authorize": (0.2, 2),
    "/api/oauth/microsoft/authorize": (0.2, 2),
    "/api/oauth/callback": (0.2, 2),
    "/api/oauth/google/status": (1.0, 5),
    "/api/oauth/microsoft/status": (1.0, 5),
    "/api/oauth/google/disconnect": (0.2, 2),
    "/api/oauth/microsoft/disconnect": (0.2, 2),
    "/api/critical-permissions/get": (1.0, 5),
    "/api/critical-permissions/promote": (5 / 60, 5),
    "/api/critical-permissions/cancel": (0.5, 5),
    "/api/auth/login": (0.2, 5),
    "/api/auth/logout": (0.5, 5),
    "/api/auth/me": (1.0, 10),
    # Failed session resolutions (a cookie that resolves to no session), per client IP.
    "/api/auth/session": (1.0, 20),
    # GH-152: the session management routes, per user.
    "/api/me/sessions/get": (1.0, 10),
    "/api/me/sessions/delete": (0.5, 5),
    "/api/org/users/logout": (0.5, 5),
}


class TestRateLimitConfiguration:
    """The rate table, the default, the eviction bounds and the bucket map."""

    @pytest.mark.parametrize(("route", "rate"), list(_EXPECTED_RATES.items()))
    def test_auth_api_route_rate_limits(self, route: str, rate: tuple[float, int]) -> None:
        """(tokens per second, burst) per route key."""
        _app()

        assert server._RATE_LIMITS[route] == pytest.approx(rate)

    def test_auth_api_default_rate_limit(self) -> None:
        """Routes without an entry get (1.0/s, burst 10)."""
        assert server._DEFAULT_RATE_LIMIT == (1.0, 10)

    def test_auth_api_bucket_eviction_bounds(self) -> None:
        """Idle buckets go after 15 minutes; at most 10,000 buckets."""
        assert (server._BUCKET_IDLE_TTL_S, server._MAX_RATE_BUCKETS) == (900.0, 10_000)

    def test_auth_api_buckets_are_an_lru_ordered_dict(self) -> None:
        """(route, caller) → bucket, in LRU order."""
        _app()

        assert isinstance(server._rate_buckets, OrderedDict)

    def test_auth_api_create_app_clears_the_buckets(self) -> None:
        """A new app starts with no buckets (test isolation, fresh process state)."""
        _app()
        server._check_rate_limit("/api/message", "user:someone")
        assert server._rate_buckets

        _app()

        assert len(server._rate_buckets) == 0


class TestRateLimitPerCaller:
    """One caller exhausting a route's bucket never throttles another."""

    def test_auth_api_one_user_exhausting_message_does_not_throttle_another(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """User A gets 429 once its burst is spent; user B still gets through."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/message", (0.001, 3))
        client = _client(app)
        token_a = db.open_session(db.add_account())
        token_b = db.open_session(db.add_account())

        statuses_a = [
            client.post("/api/message", json=_CHAT_BODY, headers=_cookie(token_a)).status_code
            for _ in range(4)
        ]
        response_b = client.post("/api/message", json=_CHAT_BODY, headers=_cookie(token_b))

        assert statuses_a == [200, 200, 200, 429]
        assert response_b.status_code == 200

    def test_auth_api_rate_limit_response_body(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """429 {"detail": "Rate limit exceeded"}."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/auth/me", (0.001, 1))
        client = _client(app)
        token = db.open_session(db.add_account())

        client.get("/api/auth/me", headers=_cookie(token))
        response = client.get("/api/auth/me", headers=_cookie(token))

        assert response.status_code == 429
        assert response.json() == {"detail": "Rate limit exceeded"}

    def test_auth_api_session_routes_are_keyed_by_user_id(self, db: _FakeDb) -> None:
        """The bucket key is (route, "user:<user_id>")."""
        app = _app()
        account = db.add_account()
        token = db.open_session(account)

        _client(app).post("/api/message", json=_CHAT_BODY, headers=_cookie(token))

        assert ("/api/message", f"user:{_plain(account['id'])}") in server._rate_buckets

    def test_auth_api_same_user_shares_its_bucket_across_ips(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """On a session route the user id is the key: switching IPs doesn't reset it."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/message", (0.001, 2))
        token = db.open_session(db.add_account())

        first = _client(app, _IP_A).post("/api/message", json=_CHAT_BODY, headers=_cookie(token))
        second = _client(app, _IP_B).post("/api/message", json=_CHAT_BODY, headers=_cookie(token))
        third = _client(app, _IP_A).post("/api/message", json=_CHAT_BODY, headers=_cookie(token))

        assert [first.status_code, second.status_code, third.status_code] == [200, 200, 429]

    @pytest.mark.usefixtures("fast_passwords")
    def test_auth_api_login_is_limited_per_client_ip(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One IP hammering the login gets 429; another IP is unaffected."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/auth/login", (0.001, 3))
        client_a = _client(app, _IP_A)
        client_b = _client(app, _IP_B)

        statuses_a = [_login(client_a, "x@example.test").status_code for _ in range(4)]
        status_b = _login(client_b, "x@example.test").status_code

        assert statuses_a == [401, 401, 401, 429]
        assert status_b == 401

    @pytest.mark.usefixtures("fast_passwords")
    def test_auth_api_login_is_keyed_by_ip(self, db: _FakeDb) -> None:
        """The login bucket key is ("/api/auth/login", "ip:<client ip>")."""
        app = _app()

        _login(_client(app, _IP_A), "x@example.test")

        assert ("/api/auth/login", f"ip:{_IP_A}") in server._rate_buckets


def _session_queries(db: _FakeDb) -> int:
    """How many session lookups reached the database."""
    return sum(1 for _method, sql, _args in db.calls if "from sessions" in _norm(sql))


class TestUnresolvedSessionThrottle:
    """Cookies that resolve to no session are throttled per client IP (security audit).

    Rate limits on session routes are keyed by user, so they only engage once a
    session resolves. Without this bucket, a stream of random session cookies
    would cost one database lookup per request, unthrottled.
    """

    def test_auth_api_unresolved_cookies_are_throttled_per_ip(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Once an IP's failure burst is spent it gets 429, before any session query."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/auth/session", (0.001, 3))
        client = _client(app, _IP_A)

        statuses = [
            client.get("/api/settings", headers=_cookie(secrets.token_urlsafe(32))).status_code
            for _ in range(3)
        ]
        queries_before = _session_queries(db)
        refused = client.get("/api/settings", headers=_cookie(secrets.token_urlsafe(32)))

        assert statuses == [401, 401, 401]
        assert refused.status_code == 429
        assert refused.json() == {"detail": "Rate limit exceeded"}
        assert _session_queries(db) == queries_before

    def test_auth_api_failure_bucket_is_keyed_by_client_ip(self, db: _FakeDb) -> None:
        """The failure bucket key is ("/api/auth/session", "ip:<client ip>")."""
        app = _app()

        _client(app, _IP_A).get("/api/auth/me", headers=_cookie(secrets.token_urlsafe(32)))

        assert ("/api/auth/session", f"ip:{_IP_A}") in server._rate_buckets

    def test_auth_api_throttled_ip_does_not_throttle_another_ip(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """IP A exhausting its failure bucket leaves IP B's unknown cookie at 401."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/auth/session", (0.001, 1))
        client_a = _client(app, _IP_A)
        client_a.get("/api/auth/me", headers=_cookie(secrets.token_urlsafe(32)))
        exhausted = client_a.get("/api/auth/me", headers=_cookie(secrets.token_urlsafe(32)))

        other = _client(app, _IP_B).get("/api/auth/me", headers=_cookie(secrets.token_urlsafe(32)))

        assert exhausted.status_code == 429
        assert other.status_code == 401

    def test_auth_api_resolved_sessions_do_not_consume_the_failure_bucket(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Valid sessions from an IP never spend that IP's failure budget."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/auth/session", (0.001, 1))
        client = _client(app, _IP_A)
        token = db.open_session(db.add_account())

        valid = [client.get("/api/auth/me", headers=_cookie(token)).status_code for _ in range(3)]
        unknown = client.get("/api/auth/me", headers=_cookie(secrets.token_urlsafe(32)))

        assert valid == [200, 200, 200]
        assert unknown.status_code == 401

    def test_auth_api_requests_without_a_cookie_do_not_consume_the_failure_bucket(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No cookie means no database lookup, so nothing is counted."""
        app = _app()
        monkeypatch.setitem(server._RATE_LIMITS, "/api/auth/session", (0.001, 1))
        client = _client(app, _IP_A)

        anonymous = [client.get("/api/auth/me").status_code for _ in range(3)]
        unknown = client.get("/api/auth/me", headers=_cookie(secrets.token_urlsafe(32)))

        assert anonymous == [401, 401, 401]
        assert unknown.status_code == 401
        assert _session_queries(db) == 1

    def test_auth_api_openapi_schema_is_not_served(self, db: _FakeDb) -> None:
        """No anonymous map of the API: /openapi.json is off (tracker #139 §5)."""
        app = _app()

        response = _client(app).get("/openapi.json")

        assert app.openapi_url is None
        assert response.status_code == 404


class TestRateLimitEviction:
    """Idle buckets are dropped and the map is bounded (LRU)."""

    def test_auth_api_idle_bucket_is_evicted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A bucket unused for the idle TTL is gone after a later check."""
        _app()
        clock = _Clock(monkeypatch)
        server._check_rate_limit("/api/message", "user:a")

        clock.advance(server._BUCKET_IDLE_TTL_S + 1)
        server._check_rate_limit("/api/message", "user:b")

        assert ("/api/message", "user:a") not in server._rate_buckets
        assert ("/api/message", "user:b") in server._rate_buckets

    def test_auth_api_recent_bucket_is_kept(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A bucket used within the TTL survives."""
        _app()
        clock = _Clock(monkeypatch)
        server._check_rate_limit("/api/message", "user:a")

        clock.advance(server._BUCKET_IDLE_TTL_S / 2)
        server._check_rate_limit("/api/message", "user:b")

        assert ("/api/message", "user:a") in server._rate_buckets

    def test_auth_api_bucket_map_never_exceeds_the_cap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With the cap at 3, ten callers never leave more than 3 buckets."""
        _app()
        _Clock(monkeypatch)
        monkeypatch.setattr(server, "_MAX_RATE_BUCKETS", 3)
        sizes: list[int] = []

        for index in range(10):
            server._check_rate_limit("/api/message", f"user:{index}")
            sizes.append(len(server._rate_buckets))

        assert max(sizes) <= 3
        assert {key[1] for key in server._rate_buckets} == {"user:7", "user:8", "user:9"}

    def test_auth_api_bucket_map_drops_least_recently_used(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LRU, not FIFO: a bucket used again moves to the back of the queue."""
        _app()
        _Clock(monkeypatch)
        monkeypatch.setattr(server, "_MAX_RATE_BUCKETS", 3)

        for caller in ("user:a", "user:b", "user:c", "user:a", "user:d"):
            server._check_rate_limit("/api/message", caller)

        assert {key[1] for key in server._rate_buckets} == {"user:a", "user:c", "user:d"}

    def test_auth_api_exhausted_default_bucket_raises_429(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unlisted route uses the default (1/s, burst 10): the 11th call is a 429."""
        _app()
        _Clock(monkeypatch)

        for _ in range(10):
            server._check_rate_limit("/api/unlisted", "ip:192.0.2.1")
        with pytest.raises(HTTPException) as exc_info:
            server._check_rate_limit("/api/unlisted", "ip:192.0.2.1")

        assert exc_info.value.status_code == 429
        assert exc_info.value.detail == "Rate limit exceeded"
        server._check_rate_limit("/api/unlisted", "ip:192.0.2.2")  # another caller: fine


# ---------------------------------------------------------------------------
# 8. Critical permissions: promotion disabled until #161
# ---------------------------------------------------------------------------


class TestCriticalPromotionDisabled:
    """PATCH on a non-promoted permission is a 403 and starts no cooldown."""

    @pytest.mark.parametrize(
        "who",
        [
            pytest.param({"role": "org_admin"}, id="org-admin"),
            pytest.param({"role": "editor"}, id="editor"),
            pytest.param({"kind": "super_admin", "role": None, "org_status": None}, id="sa"),
        ],
    )
    def test_auth_api_promote_is_refused(self, db: _FakeDb, who: dict[str, Any]) -> None:
        """Any session reaches the handler, which answers 403 with the fixed message."""
        token = db.open_session(db.add_account(**who))

        response = _client(_app()).patch(
            "/api/critical-permissions/gmail/send", headers=_cookie(token)
        )

        assert response.status_code == 403
        assert response.json() == _PROMOTE_REFUSED
        assert server._pending_promotions == {}

    def test_auth_api_promote_with_an_old_bearer_body_is_refused(self, db: _FakeDb) -> None:
        """The removed re-auth body grants nothing either."""
        token = db.open_session(db.add_account(role="org_admin"))

        response = _client(_app()).patch(
            "/api/critical-permissions/gmail/send",
            json={"bearer_token": "a" * 48},
            headers=_cookie(token),
        )

        assert response.status_code == 403
        assert response.json() == _PROMOTE_REFUSED
        assert server._pending_promotions == {}

    def test_auth_api_demote_still_works(
        self, db: _FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PATCH on a promoted permission demotes it to deny."""
        monkeypatch.setattr("admino.database.update_permission", AsyncMock())
        monkeypatch.setattr(
            "admino.config.load_permissions_config_from_db", AsyncMock(return_value=MagicMock())
        )
        token = db.open_session(db.add_account(role="org_admin"))
        app = _app()
        server._promoted_permissions.add(("gmail", "send"))

        response = _client(app).patch(
            "/api/critical-permissions/gmail/send", headers=_cookie(token)
        )

        assert response.status_code == 200
        assert response.json()["state"] == "deny"
        assert ("gmail", "send") not in server._promoted_permissions

    def test_auth_api_cancel_pending_still_works(self, db: _FakeDb) -> None:
        """DELETE .../pending still cancels a cooldown."""
        token = db.open_session(db.add_account(role="org_admin"))
        app = _app()
        server._pending_promotions[("gmail", "send")] = datetime.now(UTC)

        response = _client(app).delete(
            "/api/critical-permissions/gmail/send/pending", headers=_cookie(token)
        )

        assert response.status_code == 200
        assert server._pending_promotions == {}

    def test_auth_api_promote_model_is_removed(self) -> None:
        """models.CriticalPermissionPromote (and its bearer_token) is gone."""
        assert not hasattr(models, "CriticalPermissionPromote")


# ---------------------------------------------------------------------------
# 9. The old bearer / VPN auth is gone
# ---------------------------------------------------------------------------

_SERVER_SOURCE = inspect.getsource(server)


class TestOldAuthRemoved:
    """No bearer token, no VPN mode, no Authorization header in CORS."""

    def test_auth_api_require_auth_is_gone(self) -> None:
        """require_auth and _get_bearer_token no longer exist."""
        assert not hasattr(server, "require_auth")
        assert not hasattr(server, "_get_bearer_token")

    def test_auth_api_server_no_longer_imports_hmac(self) -> None:
        """The constant-time token comparison went with the token."""
        imported = {
            alias.name
            for node in ast.walk(ast.parse(_SERVER_SOURCE))
            if isinstance(node, ast.Import)
            for alias in node.names
        }

        assert "hmac" not in imported

    def test_auth_api_server_never_reads_config_auth(self) -> None:
        """No config.auth / _config.auth access anywhere in server.py."""
        assert re.search(r"\bconfig\.auth\b", _SERVER_SOURCE) is None

    def test_auth_api_cors_does_not_allow_authorization_header(self) -> None:
        """The Authorization header is no longer an allowed CORS request header."""
        response = _client(_app()).options(
            "/api/message",
            headers={
                "Origin": "http://localhost:8000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization",
            },
        )

        allowed = response.headers.get("access-control-allow-headers", "").lower()
        assert "authorization" not in allowed

    def test_auth_api_bearer_header_authenticates_nothing(self, db: _FakeDb) -> None:
        """An Authorization: Bearer header is not a session."""
        response = _client(_app()).get(
            "/api/auth/me", headers={"Authorization": "Bearer " + "a" * 48}
        )

        assert response.status_code == 401
