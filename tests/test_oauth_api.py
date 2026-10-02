"""HTTP spec for the OAuth routes: per-user connections, roles, residency and the
state binding (GH-18, GH-149, GH-237, GH-162).

The FastAPI app from ``create_app()`` runs with a real ``AppConfig`` against the
in-memory database of tests/db_fakes.py (what ``admino.database.get_pool``
returns). The real ``admino.oauth`` persistence and Fernet encryption, and the
real ``admino.sessions`` and ``admino.scoped_settings`` code, run. Only the
provider calls are patched: ``admino.server.exchange_google_code`` /
``exchange_microsoft_code`` / ``get_google_user_email`` and the revocation
requests (``admino.oauth._revoke_google_token`` / ``_revoke_microsoft_token``).
Session-route callers are logged in with ``tests.auth_helpers.login``, and each
caller's session id is a real FakeDb session's. Two tests use the real cookie
resolution instead: the unknown-cookie 401 and the demotion round trip. Both
orgs start without data residency unless a test turns it on.

What these tests pin down:
- Sessions (GH-149): authorize, status and disconnect answer 401 without a
  session. The callback is public, because it is the provider's cross-site
  redirect.
- Roles (GH-162): every session route checks ``oauth.connect`` through
  access.py. Org Admins and Editors get the route's normal answer. Viewers and
  Super Admins get 403 ``{"detail": "Forbidden"}``: their request stores no
  pending state, sets no cookie and runs no oauth_tokens statement. A demoted
  user's rows stay in the database (403 on every route) and are reported again
  once the role allows ``oauth.connect``.
- Residency: authorize in a residency org is a 403 with
  ``server.OAUTH_RESIDENCY_DETAIL``, with nothing stored and no cookie. Status
  still answers 200 with ``data_residency: true`` and the kept row. Disconnect
  still works.
- Status shape: ``{"connected", "healthy", "email": null, "data_residency",
  "services"}``. ``services`` always lists the provider's three tools in order,
  each ``{"tool", "enabled"}`` with the org's stored switch. Only the caller's
  own row counts. ``healthy`` keeps GH-237's semantics: the row's flag and a
  decryptable ciphertext.
- Authorize binds the state to the caller's session. It stores
  ``server.OAuthPendingState(created_at, provider, redirect_uri, user_id,
  session_id)`` under the URL's state and sets ``admino_oauth_state=<state>``
  (HttpOnly, SameSite=Lax, Path=/api/oauth/callback, Max-Age=600, Secure
  exactly when ``server.cookie_secure`` is true).
- Callback: success stores the Fernet ciphertext for the initiating user only,
  whatever session cookie the request carries. It then awaits
  ``oauth.access_tokens.invalidate(user_id, provider)`` and redirects to
  ``/tools?oauth=success``. Every error redirects to
  ``/tools?oauth=error&reason=<reason>`` and stores nothing:
  - ``invalid_state``: unknown or missing state, a missing or different binding
    cookie, older than 600 s, or the initiating session ended or belongs to
    someone else;
  - ``denied``, ``missing_code``;
  - ``forbidden``: the initiator is now a Viewer;
  - ``residency``, ``exchange_failed``.
  The pending state is one-shot (a replay is invalid_state). The session, role
  and residency checks run before any token-endpoint call. Every redirect
  clears the binding cookie.
- Disconnect deletes only the caller's row. When the caller has none it is a
  404 with the unchanged detail, whoever else has a row. It revokes the
  caller's own refresh token and invalidates only the caller's cached access
  token.
- Rate limits: per user on the session routes (before the role check), per
  client IP on the callback (a 429 consumes no state).

Security notes:
- No real Google/Microsoft call: the provider calls are AsyncMocks, the
  encryption key is a fresh Fernet key per test and every token is a fake
  value.
- Tenant isolation: the oauth_tokens statements bind the caller's user id and
  org id, never another user's.
- CSRF: the binding cookie stops a callback the initiating browser didn't
  start (login CSRF, account mix-up), and the state is consumed on first use.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Final, cast
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

from admino import oauth, server
from admino.config import AppConfig
from admino.oauth import OAuthError, encrypt_refresh_token
from admino.server import create_app
from tests.auth_helpers import (
    login,
    logout,
    member_principal,
    resolved_session,
    session_cookie,
    session_for,
    super_admin_principal,
)
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, PUBLIC_URL, FakeDb, plain

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from fastapi import FastAPI
    from httpx import Response

    from admino.access import MemberRole
    from tests.db_fakes import Call

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UNAUTHORIZED: Final = {"detail": "Unauthorized"}
_FORBIDDEN: Final = {"detail": "Forbidden"}
_RESIDENCY_TEXT: Final = (
    "Your organization's data residency policy doesn't allow Google or Microsoft accounts."
)
_STATE_COOKIE: Final = "admino_oauth_state"
_SESSION_COOKIE: Final = "admino_session"
_CALLBACK: Final = "/api/oauth/callback"
_REDIRECT_URI: Final = f"{PUBLIC_URL}{_CALLBACK}"
_STATE_TTL_S: Final = 600
_IP_A: Final = "203.0.113.162"
_IP_B: Final = "198.51.100.162"
_SUCCESS: Final = "/tools?oauth=success"

_PROVIDERS: Final = ("google", "microsoft")
_ACTIONS: Final = ("authorize", "status", "disconnect")
# GH-162: the provider's services, in PROVIDER_TOOLS order.
_PROVIDER_SERVICES: Final[dict[str, list[str]]] = {
    "google": ["gmail", "google_calendar", "google_drive"],
    "microsoft": ["outlook", "outlook_calendar", "onedrive"],
}
_AUTH_ENDPOINTS: Final = {
    "google": "https://accounts.google.com/o/oauth2/v2/auth",
    "microsoft": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
}
_CLIENT_IDS: Final = {
    "google": "fake-google-client-id-gh162.apps.example",
    "microsoft": "fake-microsoft-client-id-gh162",
}
_NOT_CONNECTED: Final = {
    "google": {"detail": "Google account is not connected."},
    "microsoft": {"detail": "Microsoft account is not connected."},
}

# Obviously fake provider values; only their Fernet ciphertext may reach a row.
_REFRESH_TOKEN: Final = "fake-refresh-token-gh162-initiator"
_OTHER_REFRESH_TOKEN: Final = "fake-refresh-token-gh162-other-user"
_PREVIOUS_REFRESH_TOKEN: Final = "fake-refresh-token-gh162-previous-account"
_ACCESS_TOKEN: Final = "fake-access-token-gh162"
_GOOGLE_EMAIL: Final = "initiator.gh162@gmail.example"
_SCOPES: Final[dict[str, list[str]]] = {
    "google": ["https://www.googleapis.com/auth/gmail.readonly", "openid"],
    "microsoft": ["Mail.Read", "offline_access"],
}
_STATE: Final = "gh162-state-token_0001"
_OTHER_STATE: Final = "gh162-state-token_0002"
_CODE: Final = "4/0Agh162-auth-code"

# (method, path) of every route that needs a session.
_SESSION_OAUTH_ROUTES: Final[list[tuple[str, str]]] = [
    ("GET", "/api/oauth/google/authorize"),
    ("GET", "/api/oauth/microsoft/authorize"),
    ("GET", "/api/oauth/google/status"),
    ("GET", "/api/oauth/microsoft/status"),
    ("DELETE", "/api/oauth/google"),
    ("DELETE", "/api/oauth/microsoft"),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ProviderCalls:
    """The patched provider calls: code exchange, email lookup and revocation."""

    exchange: dict[str, AsyncMock]
    email: AsyncMock
    revoke: dict[str, AsyncMock]

    def assert_no_token_endpoint_call(self) -> None:
        """No code exchange and no email lookup happened."""
        for mock in (*self.exchange.values(), self.email):
            mock.assert_not_awaited()


@pytest.fixture(autouse=True)
def _oauth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh Fernet key, fake client credentials and a fixed redirect URI."""
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GOOGLE_CLIENT_ID", _CLIENT_IDS["google"])
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "fake-google-client-secret-gh162")
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", _CLIENT_IDS["microsoft"])
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "fake-microsoft-client-secret-gh162")
    monkeypatch.setenv("OAUTH_REDIRECT_URI", _REDIRECT_URI)


@pytest.fixture(autouse=True)
def provider_calls(monkeypatch: pytest.MonkeyPatch) -> _ProviderCalls:
    """Patch every provider call, so no test can reach Google or Microsoft."""
    calls = _ProviderCalls(
        exchange={
            "google": AsyncMock(
                return_value=(_ACCESS_TOKEN, _REFRESH_TOKEN, list(_SCOPES["google"]))
            ),
            "microsoft": AsyncMock(
                return_value=(_ACCESS_TOKEN, _REFRESH_TOKEN, list(_SCOPES["microsoft"]))
            ),
        },
        email=AsyncMock(return_value=_GOOGLE_EMAIL),
        revoke={"google": AsyncMock(return_value=None), "microsoft": AsyncMock(return_value=None)},
    )
    monkeypatch.setattr("admino.server.exchange_google_code", calls.exchange["google"])
    monkeypatch.setattr("admino.server.exchange_microsoft_code", calls.exchange["microsoft"])
    monkeypatch.setattr("admino.server.get_google_user_email", calls.email)
    monkeypatch.setattr("admino.oauth._revoke_google_token", calls.revoke["google"])
    monkeypatch.setattr("admino.oauth._revoke_microsoft_token", calls.revoke["microsoft"])
    return calls


@pytest.fixture(autouse=True)
def _roomy_oauth_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Functional tests aren't about rate limits: the OAuth keys get a large bucket."""
    for key in list(server._RATE_LIMITS):
        if key.startswith("/api/oauth/"):
            monkeypatch.setitem(server._RATE_LIMITS, key, (1000.0, 1000))


@pytest.fixture(autouse=True)
def _no_pending_states() -> Iterator[None]:
    """Start and end every test without pending OAuth states."""
    server._oauth_pending_states.clear()
    yield
    server._oauth_pending_states.clear()


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The fake database get_pool() returns: two active orgs without data residency."""
    fake = FakeDb()
    fake.add_org(ORG_ID, data_residency=False)
    fake.add_org(OTHER_ORG_ID, data_residency=False)
    monkeypatch.setattr("admino.database.get_pool", lambda: fake.pool)
    return fake


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Caller:
    """An account with a live FakeDb session."""

    user_id: uuid.UUID
    org_id: uuid.UUID | None
    session_id: uuid.UUID
    token: str


def _config(*, cookie_secure: bool = True) -> AppConfig:
    """A real config. Insecure cookies are only allowed with a loopback http public URL."""
    public_url = PUBLIC_URL if cookie_secure else "http://localhost:8000"
    return AppConfig.model_validate(
        {
            "server": {
                "host": "127.0.0.1",
                "port": 8000,
                "public_url": public_url,
                "cookie_secure": cookie_secure,
            },
            "llm": {"provider": "anthropic", "anthropic_model": "claude-sonnet-4-6"},
        }
    )


def _app(*, cookie_secure: bool = True) -> FastAPI:
    return create_app(agent=MagicMock(), config=_config(cookie_secure=cookie_secure))


def _client(app: FastAPI, ip: str = _IP_A) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app, client=(ip, 50000)),
        base_url="http://test",
        follow_redirects=False,
    )


def _route(action: str, provider: str) -> tuple[str, str]:
    """(method, path) of a session route."""
    return {
        "authorize": ("GET", f"/api/oauth/{provider}/authorize"),
        "status": ("GET", f"/api/oauth/{provider}/status"),
        "disconnect": ("DELETE", f"/api/oauth/{provider}"),
    }[action]


async def _send(
    app: FastAPI,
    action: str,
    provider: str,
    *,
    ip: str = _IP_A,
    headers: dict[str, str] | None = None,
) -> Response:
    method, path = _route(action, provider)
    async with _client(app, ip) as client:
        return await client.request(method, path, headers=headers or {})


def _account(db: FakeDb, role: str = "editor", *, org_id: uuid.UUID = ORG_ID) -> _Caller:
    """A member with this role (or a Super Admin) and a live session; not logged in."""
    if role == "super_admin":
        user_id = db.add_account(kind="super_admin", role=None)
        org: uuid.UUID | None = None
    else:
        user_id = db.add_account(role=role, org_id=org_id)
        org = org_id
    token = db.open_session(user_id)
    return _Caller(user_id=user_id, org_id=org, session_id=db.session_id_of(token), token=token)


def _sign_in(
    app: FastAPI, db: FakeDb, role: str = "editor", *, org_id: uuid.UUID = ORG_ID
) -> _Caller:
    """Create an account with a live session and log it in on ``app``."""
    caller = _account(db, role, org_id=org_id)
    if caller.org_id is None:
        principal = super_admin_principal(user_id=caller.user_id)
    else:
        principal = member_principal(
            cast("MemberRole", role), user_id=caller.user_id, org_id=caller.org_id
        )
    login(app, session_for(principal, session_id=caller.session_id))
    return caller


def _seed_token(
    db: FakeDb,
    user_id: uuid.UUID,
    provider: str,
    refresh_token: str = _REFRESH_TOKEN,
    *,
    healthy: bool = True,
) -> dict[str, Any]:
    """Store a user's connection: the Fernet ciphertext of ``refresh_token``."""
    return db.add_oauth_token(
        user_id,
        provider,
        encrypted_refresh_token=encrypt_refresh_token(refresh_token),
        healthy=healthy,
    )


def _decrypt(ciphertext: str) -> str:
    return Fernet(os.environ["OAUTH_ENCRYPTION_KEY"].encode()).decrypt(ciphertext.encode()).decode()


def _token_rows(db: FakeDb) -> dict[tuple[str, str], str]:
    """Every stored connection: (user id, provider) -> ciphertext."""
    return {
        (str(user_id), provider): row["encrypted_refresh_token"]
        for (user_id, provider), row in db.oauth_tokens.items()
    }


def _token_calls(db: FakeDb) -> list[Call]:
    """Every statement that names oauth_tokens."""
    return db.matching(r"\boauth_tokens\b")


def _binds(call: Call, value: object) -> bool:
    return any(str(arg) == str(value) for arg in call.args)


def _pending(caller: _Caller, provider: str = "google", *, age: float = 0.0) -> Any:
    """A pending state of ``caller``'s session, ``age`` seconds old."""
    return server.OAuthPendingState(
        created_at=time.time() - age,
        provider=provider,
        redirect_uri=_REDIRECT_URI,
        user_id=caller.user_id,
        session_id=caller.session_id,
    )


def _url_state(url: str) -> str:
    """The state query parameter of a consent URL."""
    values = parse_qs(urlsplit(url).query).get("state", [])
    assert len(values) == 1, url
    return values[0]


def _state_cookies(response: Response) -> list[tuple[str, dict[str, str]]]:
    """Every Set-Cookie of the binding cookie: (value, lowercased attribute -> value)."""
    found: list[tuple[str, dict[str, str]]] = []
    for header in response.headers.get_list("set-cookie"):
        first, *attributes = [part.strip() for part in header.split(";")]
        name, _, value = first.partition("=")
        if name.strip() != _STATE_COOKIE:
            continue
        parsed: dict[str, str] = {}
        for attribute in attributes:
            key, _, attribute_value = attribute.partition("=")
            parsed[key.strip().lower()] = attribute_value.strip()
        found.append((value.strip(), parsed))
    return found


def _assert_state_cookie_cleared(response: Response) -> None:
    """The response deletes the binding cookie: empty value, Max-Age=0, the callback path."""
    cookies = _state_cookies(response)
    assert len(cookies) == 1, response.headers.get_list("set-cookie")
    value, attributes = cookies[0]
    assert value in {"", '""'}, value
    assert attributes.get("max-age") == "0", attributes
    assert attributes.get("path") == _CALLBACK, attributes


def _status_body(
    provider: str,
    *,
    connected: bool,
    healthy: bool,
    data_residency: bool = False,
    disabled: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """The full GH-162 status response."""
    return {
        "connected": connected,
        "healthy": healthy,
        "email": None,
        "data_residency": data_residency,
        "services": [
            {"tool": tool, "enabled": tool not in disabled} for tool in _PROVIDER_SERVICES[provider]
        ],
    }


@contextmanager
def _watch_invalidate() -> Iterator[AsyncMock]:
    """Record the per-user access-token cache invalidations."""
    with patch.object(oauth.access_tokens, "invalidate", new_callable=AsyncMock) as invalidate:
        yield invalidate


def _invalidated(invalidate: AsyncMock) -> list[tuple[str, str]]:
    """Every awaited invalidation as (user id, provider), positional or keyword."""
    seen: list[tuple[str, str]] = []
    for awaited in invalidate.await_args_list:
        bound = dict(zip(("user_id", "provider"), awaited.args, strict=False))
        bound.update(awaited.kwargs)
        seen.append((str(bound.get("user_id")), str(bound.get("provider"))))
    return seen


async def _callback(
    app: FastAPI,
    params: dict[str, str],
    *,
    state_cookie: str | None = _STATE,
    session_token: str | None = None,
    ip: str = _IP_A,
) -> Response:
    """GET the callback with the binding cookie (and optionally a session cookie)."""
    cookies: list[str] = []
    if session_token is not None:
        cookies.append(f"{_SESSION_COOKIE}={session_token}")
    if state_cookie is not None:
        cookies.append(f"{_STATE_COOKIE}={state_cookie}")
    headers = {"Cookie": "; ".join(cookies)} if cookies else {}
    async with _client(app, ip) as client:
        return await client.get(_CALLBACK, params=params, headers=headers)


async def _connect(
    app: FastAPI, initiator: _Caller, provider: str = "google", **kwargs: Any
) -> Response:
    """Seed a pending state for ``initiator`` and complete the callback for it."""
    server._oauth_pending_states[_STATE] = _pending(initiator, provider)
    return await _callback(app, {"code": _CODE, "state": _STATE}, **kwargs)


# ---------------------------------------------------------------------------
# GH-149: a session on every OAuth route except the callback
# ---------------------------------------------------------------------------


class TestOAuthSessionRequired:
    """A request without a resolvable session gets a 401; the callback stays public."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize(("method", "path"), _SESSION_OAUTH_ROUTES)
    async def test_oauth_route_unknown_session_returns_401(self, method: str, path: str) -> None:
        """A cookie that resolves to no session (unknown, revoked, expired) gets a 401."""
        app = _app()
        mock_revoke = AsyncMock(return_value=True)
        with (
            resolved_session(None),
            patch("admino.server.revoke_and_delete_token", mock_revoke),
        ):
            async with _client(app) as client:
                resp = await client.request(method, path, headers=session_cookie())

        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED
        mock_revoke.assert_not_awaited()

    @pytest.mark.parametrize(("method", "path"), _SESSION_OAUTH_ROUTES)
    async def test_oauth_route_without_a_cookie_returns_401(
        self, db: FakeDb, method: str, path: str
    ) -> None:
        """No session cookie: 401, no pending state, no oauth_tokens statement."""
        app = _app()
        async with _client(app) as client:
            resp = await client.request(method, path)

        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED
        assert server._oauth_pending_states == {}
        assert _token_calls(db) == []

    async def test_oauth_callback_is_public(self, db: FakeDb) -> None:
        """The callback answers a request without a session with its redirect, not a 401."""
        app = _app()

        resp = await _callback(app, {"code": _CODE, "state": _STATE}, state_cookie=None)

        assert resp.status_code == 307
        assert resp.headers["location"] == "/tools?oauth=error&reason=invalid_state"
        _assert_state_cookie_cleared(resp)


# ---------------------------------------------------------------------------
# GH-162: oauth.connect on every session route
# ---------------------------------------------------------------------------


class TestOAuthRoles:
    """Only Org Admins and Editors connect, read and disconnect accounts."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("provider", _PROVIDERS)
    @pytest.mark.parametrize("action", _ACTIONS)
    @pytest.mark.parametrize("role", ["viewer", "super_admin"])
    async def test_oauth_role_without_oauth_connect_gets_403_and_touches_nothing(
        self,
        db: FakeDb,
        provider_calls: _ProviderCalls,
        role: str,
        action: str,
        provider: str,
    ) -> None:
        """A Viewer or Super Admin: 403 Forbidden, no state, no cookie, no token statement."""
        app = _app()
        caller = _sign_in(app, db, role)
        other = _account(db, "editor")
        _seed_token(db, other.user_id, provider, _OTHER_REFRESH_TOKEN)
        if caller.org_id is not None:
            _seed_token(db, caller.user_id, provider)
        rows = _token_rows(db)

        resp = await _send(app, action, provider)

        assert resp.status_code == 403
        assert resp.json() == _FORBIDDEN
        assert server._oauth_pending_states == {}
        assert _state_cookies(resp) == []
        assert _token_calls(db) == []
        assert _token_rows(db) == rows
        provider_calls.revoke[provider].assert_not_awaited()

    @pytest.mark.parametrize("provider", _PROVIDERS)
    @pytest.mark.parametrize("action", _ACTIONS)
    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    async def test_oauth_role_with_oauth_connect_gets_the_routes_answer(
        self, db: FakeDb, role: str, action: str, provider: str
    ) -> None:
        """An Org Admin or Editor: authorize binds a state, status reports the own row,
        disconnect deletes the own row."""
        app = _app()
        caller = _sign_in(app, db, role)
        _seed_token(db, caller.user_id, provider)

        resp = await _send(app, action, provider)

        assert resp.status_code == 200, resp.text
        if action == "authorize":
            state = _url_state(resp.json()["url"])
            assert [value for value, _ in _state_cookies(resp)] == [state]
            assert server._oauth_pending_states[state].user_id == caller.user_id
        elif action == "status":
            assert resp.json() == _status_body(provider, connected=True, healthy=True)
        else:
            assert resp.json() == {"status": "disconnected"}
            assert db.oauth_token(caller.user_id, provider) is None
            deletes = db.matching(r"^delete from oauth_tokens\b")
            assert deletes
            assert all(_binds(call, caller.user_id) for call in deletes)

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_viewer_in_a_residency_org_gets_forbidden_before_residency(
        self, db: FakeDb, provider: str
    ) -> None:
        """The role check runs first: a Viewer gets Forbidden, not the residency text."""
        db.orgs[ORG_ID]["data_residency"] = True
        app = _app()
        _sign_in(app, db, "viewer")

        resp = await _send(app, "authorize", provider)

        assert resp.status_code == 403
        assert resp.json() == _FORBIDDEN


# ---------------------------------------------------------------------------
# GH-162: the contract's names
# ---------------------------------------------------------------------------


class TestOAuthContractNames:
    """The constants other modules and the frontend rely on."""

    def test_oauth_residency_detail_is_the_contract_text(self) -> None:
        """The 403 explanation of a residency org."""
        assert server.OAUTH_RESIDENCY_DETAIL == _RESIDENCY_TEXT

    def test_oauth_state_cookie_name_is_the_contract_name(self) -> None:
        """The binding cookie's name."""
        assert server.OAUTH_STATE_COOKIE_NAME == _STATE_COOKIE


# ---------------------------------------------------------------------------
# GET /api/oauth/{provider}/authorize
# ---------------------------------------------------------------------------


class TestOAuthAuthorize:
    """The consent URL, the session-bound pending state, the binding cookie, residency."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_authorize_returns_the_providers_consent_url(
        self, db: FakeDb, provider: str
    ) -> None:
        """200 ``{"url": ...}``: the provider's endpoint, client id and redirect URI."""
        app = _app()
        _sign_in(app, db, "org_admin")

        resp = await _send(app, "authorize", provider)

        assert resp.status_code == 200
        url = resp.json()["url"]
        assert resp.json() == {"url": url}
        assert url.startswith(_AUTH_ENDPOINTS[provider] + "?")
        query = parse_qs(urlsplit(url).query)
        assert query["client_id"] == [_CLIENT_IDS[provider]]
        assert query["redirect_uri"] == [_REDIRECT_URI]

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_authorize_stores_the_state_bound_to_the_callers_session(
        self, db: FakeDb, provider: str
    ) -> None:
        """OAuthPendingState(created_at, provider, redirect_uri, user_id, session_id)."""
        app = _app()
        caller = _sign_in(app, db, "editor")

        before = time.time()
        resp = await _send(app, "authorize", provider)
        after = time.time()

        assert resp.status_code == 200
        state = _url_state(resp.json()["url"])
        assert list(server._oauth_pending_states) == [state]
        entry = server._oauth_pending_states[state]
        assert isinstance(entry, server.OAuthPendingState)
        assert entry == server.OAuthPendingState(
            entry.created_at, provider, _REDIRECT_URI, caller.user_id, caller.session_id
        )
        assert before <= entry.created_at <= after

    @pytest.mark.parametrize("cookie_secure", [True, False], ids=["secure", "insecure-dev"])
    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_authorize_sets_the_state_binding_cookie(
        self, db: FakeDb, provider: str, cookie_secure: bool
    ) -> None:
        """admino_oauth_state=<state>; HttpOnly; SameSite=Lax; Path=/api/oauth/callback;
        Max-Age=600; Secure exactly when server.cookie_secure is true."""
        app = _app(cookie_secure=cookie_secure)
        _sign_in(app, db, "editor")

        resp = await _send(app, "authorize", provider)

        assert resp.status_code == 200
        cookies = _state_cookies(resp)
        assert len(cookies) == 1, resp.headers.get_list("set-cookie")
        value, attributes = cookies[0]
        assert value == _url_state(resp.json()["url"])
        assert "httponly" in attributes
        assert attributes.get("samesite", "").lower() == "lax"
        assert attributes.get("path") == _CALLBACK
        assert attributes.get("max-age") == str(_STATE_TTL_S)
        assert ("secure" in attributes) is cookie_secure

    async def test_oauth_authorize_two_users_each_bind_their_own_session(self, db: FakeDb) -> None:
        """Two callers' states map to their own user and session."""
        app = _app()
        first = _sign_in(app, db, "editor")
        first_resp = await _send(app, "authorize", "google")
        second = _sign_in(app, db, "org_admin", org_id=OTHER_ORG_ID)
        second_resp = await _send(app, "authorize", "google")

        first_state = _url_state(first_resp.json()["url"])
        second_state = _url_state(second_resp.json()["url"])
        assert first_state != second_state
        bindings = {
            state: (entry.user_id, entry.session_id)
            for state, entry in server._oauth_pending_states.items()
        }
        assert bindings == {
            first_state: (first.user_id, first.session_id),
            second_state: (second.user_id, second.session_id),
        }

    @pytest.mark.parametrize("provider", _PROVIDERS)
    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    async def test_oauth_authorize_in_a_residency_org_is_403_and_stores_nothing(
        self, db: FakeDb, role: str, provider: str
    ) -> None:
        """Residency on: 403 with the explanation, no pending state, no cookie."""
        db.orgs[ORG_ID]["data_residency"] = True
        app = _app()
        _sign_in(app, db, role)

        resp = await _send(app, "authorize", provider)

        assert resp.status_code == 403
        assert resp.json() == {"detail": server.OAUTH_RESIDENCY_DETAIL}
        assert server._oauth_pending_states == {}
        assert _state_cookies(resp) == []

    async def test_oauth_authorize_reads_the_callers_own_org_residency(self, db: FakeDb) -> None:
        """Another org's residency policy doesn't refuse this org's caller."""
        db.orgs[OTHER_ORG_ID]["data_residency"] = True
        app = _app()
        _sign_in(app, db, "editor", org_id=ORG_ID)

        resp = await _send(app, "authorize", "google")

        assert resp.status_code == 200
        assert len(_state_cookies(resp)) == 1

    @pytest.mark.parametrize(
        ("provider", "variable"),
        [("google", "GOOGLE_CLIENT_ID"), ("microsoft", "MICROSOFT_CLIENT_ID")],
    )
    async def test_oauth_authorize_missing_client_id_returns_500(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, provider: str, variable: str
    ) -> None:
        """No client id configured: 500, no pending state, no cookie."""
        monkeypatch.delenv(variable)
        app = _app()
        _sign_in(app, db, "org_admin")

        resp = await _send(app, "authorize", provider)

        assert resp.status_code == 500
        assert resp.json() == {"detail": "OAuth configuration error."}
        assert server._oauth_pending_states == {}
        assert _state_cookies(resp) == []

    async def test_oauth_authorize_never_evicts_another_users_pending_state(
        self, db: FakeDb
    ) -> None:
        """Security audit (Medium): one user's authorize never removes a fresh pending state
        of another user, however many are pending, so no org can break another org's
        connect flow. Each of 200 other users (another org) keeps their entry."""
        app = _app()
        _sign_in(app, db, "editor")
        others = {
            f"other-state-{index}": server.OAuthPendingState(
                created_at=time.time() - 60 - index,
                provider="google",
                redirect_uri=_REDIRECT_URI,
                user_id=uuid.uuid4(),
                session_id=uuid.uuid4(),
            )
            for index in range(200)
        }
        server._oauth_pending_states.update(others)

        resp = await _send(app, "authorize", "google")

        assert resp.status_code == 200
        new_state = _url_state(resp.json()["url"])
        assert new_state in server._oauth_pending_states
        for state, entry in others.items():
            assert server._oauth_pending_states.get(state) == entry

    async def test_oauth_authorize_replaces_the_callers_own_earlier_pending_state(
        self, db: FakeDb
    ) -> None:
        """A user has at most one pending state: a new authorize (any provider) replaces
        their earlier one (its binding cookie is overwritten anyway) and nobody else's."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        other = _account(db, "org_admin", org_id=OTHER_ORG_ID)
        server._oauth_pending_states["callers-earlier"] = _pending(caller, "google", age=30)
        server._oauth_pending_states["others-state"] = _pending(other, "google", age=30)

        resp = await _send(app, "authorize", "microsoft")

        assert resp.status_code == 200
        new_state = _url_state(resp.json()["url"])
        callers = [
            state
            for state, entry in server._oauth_pending_states.items()
            if entry.user_id == caller.user_id
        ]
        assert callers == [new_state]
        assert server._oauth_pending_states[new_state].provider == "microsoft"
        assert "others-state" in server._oauth_pending_states

    async def test_oauth_authorize_reaps_expired_pending_states(self, db: FakeDb) -> None:
        """Entries older than the 600 s TTL are dropped on authorize, whoever owns them."""
        app = _app()
        _sign_in(app, db, "editor")
        other = _account(db, "org_admin", org_id=OTHER_ORG_ID)
        server._oauth_pending_states["expired"] = _pending(other, age=601)
        server._oauth_pending_states["fresh"] = _pending(other, age=10)

        resp = await _send(app, "authorize", "google")

        assert resp.status_code == 200
        assert "expired" not in server._oauth_pending_states
        assert "fresh" in server._oauth_pending_states


# ---------------------------------------------------------------------------
# GET /api/oauth/callback: success
# ---------------------------------------------------------------------------


class TestOAuthCallbackSuccess:
    """The token is stored for the initiating user only, encrypted, and the state is spent."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_callback_success_stores_for_the_initiator_only(
        self, db: FakeDb, provider: str
    ) -> None:
        """Another user's session cookie on the callback request changes nothing."""
        app = _app()
        initiator = _account(db, "editor")
        bystander = _account(db, "org_admin", org_id=OTHER_ORG_ID)

        resp = await _connect(app, initiator, provider, session_token=bystander.token)

        assert resp.status_code == 307
        assert resp.headers["location"] == _SUCCESS
        row = db.oauth_token(initiator.user_id, provider)
        assert row is not None
        assert plain(row["org_id"]) == ORG_ID
        assert db.oauth_token(bystander.user_id, provider) is None
        assert list(_token_rows(db)) == [(str(initiator.user_id), provider)]

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_callback_success_stores_only_the_fernet_ciphertext(
        self, db: FakeDb, provider: str
    ) -> None:
        """The stored value decrypts to the refresh token; the plaintext is in no column and
        in no statement's arguments."""
        app = _app()
        initiator = _account(db, "editor")

        await _connect(app, initiator, provider)

        row = db.oauth_token(initiator.user_id, provider)
        assert row is not None
        assert _decrypt(row["encrypted_refresh_token"]) == _REFRESH_TOKEN
        assert not [column for column, value in row.items() if _REFRESH_TOKEN in str(value)]
        assert not [call.sql for call in db.calls if _REFRESH_TOKEN in repr(call.args)]

    @pytest.mark.parametrize(
        ("provider", "email"), [("google", _GOOGLE_EMAIL), ("microsoft", None)]
    )
    async def test_oauth_callback_success_stores_email_scopes_and_health(
        self, db: FakeDb, provider: str, email: str | None
    ) -> None:
        """Google's best-effort email (Microsoft: none), the granted scopes, healthy."""
        app = _app()
        initiator = _account(db, "editor")

        await _connect(app, initiator, provider)

        row = db.oauth_token(initiator.user_id, provider)
        assert row is not None
        assert row["email"] == email
        assert json.loads(row["scopes"]) == _SCOPES[provider]
        assert row["healthy"] is True

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_callback_success_invalidates_the_initiators_cached_token(
        self, db: FakeDb, provider: str
    ) -> None:
        """A reconnect never serves the previous account's access token."""
        app = _app()
        initiator = _account(db, "editor")
        bystander = _account(db, "editor")

        with _watch_invalidate() as invalidate:
            resp = await _connect(app, initiator, provider, session_token=bystander.token)

        assert resp.headers["location"] == _SUCCESS
        assert _invalidated(invalidate) == [(str(initiator.user_id), provider)]

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_callback_success_exchanges_the_code_with_the_stored_redirect_uri(
        self, db: FakeDb, provider_calls: _ProviderCalls, provider: str
    ) -> None:
        """The code and the redirect URI of the pending state go to the token endpoint."""
        app = _app()
        initiator = _account(db, "editor")

        await _connect(app, initiator, provider)

        exchange = provider_calls.exchange[provider]
        exchange.assert_awaited_once()
        assert exchange.await_args is not None
        assert exchange.await_args.args[:2] == (_CODE, _REDIRECT_URI)

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_callback_success_clears_the_cookie_and_spends_the_state(
        self, db: FakeDb, provider_calls: _ProviderCalls, provider: str
    ) -> None:
        """The binding cookie is deleted; a replay of the same state is invalid_state."""
        app = _app()
        initiator = _account(db, "editor")

        first = await _connect(app, initiator, provider)
        replay = await _callback(app, {"code": _CODE, "state": _STATE})

        _assert_state_cookie_cleared(first)
        assert _STATE not in server._oauth_pending_states
        assert replay.headers["location"] == "/tools?oauth=error&reason=invalid_state"
        assert provider_calls.exchange[provider].await_count == 1

    async def test_oauth_callback_reconnect_replaces_only_the_users_own_row(
        self, db: FakeDb
    ) -> None:
        """A reconnect upserts the user's row; another user's row of the provider stays."""
        app = _app()
        initiator = _account(db, "editor")
        other = _account(db, "editor")
        _seed_token(db, initiator.user_id, "google", _PREVIOUS_REFRESH_TOKEN)
        other_row = _seed_token(db, other.user_id, "google", _OTHER_REFRESH_TOKEN)

        resp = await _connect(app, initiator, "google")

        assert resp.headers["location"] == _SUCCESS
        row = db.oauth_token(initiator.user_id, "google")
        assert row is not None
        assert _decrypt(row["encrypted_refresh_token"]) == _REFRESH_TOKEN
        assert db.oauth_token(other.user_id, "google") == other_row
        assert len(db.oauth_tokens) == 2

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_authorize_then_callback_round_trip(
        self, db: FakeDb, provider: str
    ) -> None:
        """The cookie from authorize completes the callback, without a session, for the
        user who authorized."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        authorized = await _send(app, "authorize", provider)
        state = _url_state(authorized.json()["url"])
        [(cookie_value, _)] = _state_cookies(authorized)
        logout(app)

        resp = await _callback(app, {"code": _CODE, "state": state}, state_cookie=cookie_value)

        assert resp.headers["location"] == _SUCCESS
        row = db.oauth_token(caller.user_id, provider)
        assert row is not None
        assert _decrypt(row["encrypted_refresh_token"]) == _REFRESH_TOKEN

    @pytest.mark.parametrize(
        "code",
        [
            # Microsoft codes contain ! and * (GH-63)
            "M.C528_SN1.2.U.abc!def*ghi",
            "Du25G1wanmuq65hqd!19x8eYxbjymjltRq2IwX8dYNdl",
            "Alj*yK6ZVKmizXKMYsUvaZ3Dw!6siJLPxCrvqa",
            # Google-style codes (should still work)
            "4/0AanRRrsR2_kkdT0xYQ-J7k_abc123",
            "code-with.dots_and-dashes+plus=equals",
            # Codes with tilde and comma (other providers)
            "oauth~token,value",
        ],
        ids=[
            "microsoft-bang",
            "microsoft-real-prefix",
            "microsoft-bang-and-star",
            "google-slash-style",
            "google-mixed-safe-chars",
            "tilde-and-comma",
        ],
    )
    async def test_oauth_callback_accepts_valid_codes(
        self, db: FakeDb, provider_calls: _ProviderCalls, code: str
    ) -> None:
        """Auth codes with !, *, ~ and , reach the handler and the exchange (GH-63)."""
        app = _app()
        initiator = _account(db, "editor")
        server._oauth_pending_states[_STATE] = _pending(initiator, "microsoft")

        resp = await _callback(app, {"code": code, "state": _STATE})

        assert resp.status_code == 307, f"Code {code!r} rejected with {resp.status_code}"
        assert resp.headers["location"] == _SUCCESS
        assert provider_calls.exchange["microsoft"].await_args is not None
        assert provider_calls.exchange["microsoft"].await_args.args[0] == code

    @pytest.mark.parametrize(
        "code",
        [
            "code<script>alert(1)</script>",
            'code"with"quotes',
            "code'with'single",
            "code&param=injected",
            "code\x00null",
            "code\nnewline",
            "code{braces}",
            "code[brackets]",
            "code with spaces",
        ],
        ids=[
            "xss-angle-brackets",
            "double-quotes",
            "single-quotes",
            "ampersand-injection",
            "null-byte",
            "newline",
            "curly-braces",
            "square-brackets",
            "spaces",
        ],
    )
    async def test_oauth_callback_rejects_malicious_codes(self, code: str) -> None:
        """Codes with dangerous characters are rejected by validation (422)."""
        app = _app()

        async with _client(app) as client:
            resp = await client.get(_CALLBACK, params={"code": code, "state": "some-state"})

        assert resp.status_code == 422, f"Code {code!r} was not rejected"


# ---------------------------------------------------------------------------
# GET /api/oauth/callback: errors
# ---------------------------------------------------------------------------


@dataclass
class _Flow:
    """One callback attempt: the initiator's pending state and the request made for it."""

    db: FakeDb
    initiator: _Caller
    provider: str
    session_id: uuid.UUID
    params: dict[str, str] = field(default_factory=lambda: {"code": _CODE, "state": _STATE})
    cookie: str | None = _STATE
    age: float = 0.0
    seed: bool = True
    exchange_fails: bool = False

    def pending(self) -> Any:
        return server.OAuthPendingState(
            created_at=time.time() - self.age,
            provider=self.provider,
            redirect_uri=_REDIRECT_URI,
            user_id=self.initiator.user_id,
            session_id=self.session_id,
        )


def _unknown_state(flow: _Flow) -> None:
    flow.seed = False


def _missing_state(flow: _Flow) -> None:
    flow.params = {"code": _CODE}


def _missing_binding_cookie(flow: _Flow) -> None:
    flow.cookie = None


def _other_binding_cookie(flow: _Flow) -> None:
    flow.cookie = _OTHER_STATE


def _expired_state(flow: _Flow) -> None:
    flow.age = _STATE_TTL_S + 1


def _provider_error(flow: _Flow) -> None:
    flow.params = {"state": _STATE, "error": "access_denied"}


def _missing_code(flow: _Flow) -> None:
    flow.params = {"state": _STATE}


def _session_ended(flow: _Flow) -> None:
    del flow.db.sessions[flow.db.session(flow.initiator.token)["token_hash"]]


def _session_expired(flow: _Flow) -> None:
    token = flow.db.open_session(flow.initiator.user_id, expires_in=timedelta(seconds=-1))
    flow.session_id = flow.db.session_id_of(token)


def _session_idle(flow: _Flow) -> None:
    token = flow.db.open_session(
        flow.initiator.user_id, idle_timeout_minutes=60, last_seen_ago=timedelta(minutes=61)
    )
    flow.session_id = flow.db.session_id_of(token)


def _session_of_another_user(flow: _Flow) -> None:
    flow.session_id = _account(flow.db, "editor").session_id


def _initiator_deactivated(flow: _Flow) -> None:
    flow.db.users[flow.initiator.user_id]["status"] = "deactivated"


def _initiator_now_viewer(flow: _Flow) -> None:
    flow.db.users[flow.initiator.user_id]["role"] = "viewer"


def _org_residency_on(flow: _Flow) -> None:
    flow.db.orgs[ORG_ID]["data_residency"] = True


def _exchange_fails(flow: _Flow) -> None:
    flow.exchange_fails = True


type _Setup = Callable[[_Flow], None]

# (setup, reason): every way the callback refuses, with the reason it redirects with.
_ERRORS: Final[list[Any]] = [
    pytest.param(_unknown_state, "invalid_state", id="unknown-state"),
    pytest.param(_missing_state, "invalid_state", id="missing-state"),
    pytest.param(_missing_binding_cookie, "invalid_state", id="missing-binding-cookie"),
    pytest.param(_other_binding_cookie, "invalid_state", id="other-binding-cookie"),
    pytest.param(_expired_state, "invalid_state", id="expired"),
    pytest.param(_provider_error, "denied", id="provider-error"),
    pytest.param(_missing_code, "missing_code", id="missing-code"),
    pytest.param(_session_ended, "invalid_state", id="session-ended"),
    pytest.param(_session_expired, "invalid_state", id="session-expired"),
    pytest.param(_session_idle, "invalid_state", id="session-idle"),
    pytest.param(_session_of_another_user, "invalid_state", id="session-of-another-user"),
    pytest.param(_initiator_deactivated, "invalid_state", id="initiator-deactivated"),
    pytest.param(_initiator_now_viewer, "forbidden", id="initiator-now-viewer"),
    pytest.param(_org_residency_on, "residency", id="org-residency-on"),
    pytest.param(_exchange_fails, "exchange_failed", id="exchange-error"),
]
# The errors whose request names the seeded state: that state is spent.
_SPENDING_ERRORS: Final = [
    case for case in _ERRORS if case.id not in {"unknown-state", "missing-state"}
]
# The errors that refuse before the token endpoint is called.
_PRE_EXCHANGE_ERRORS: Final = [case for case in _ERRORS if case.id != "exchange-error"]
# The errors after which the world can be put right for a correct retry of the same state.
_RETRYABLE_ERRORS: Final = [
    case
    for case in _ERRORS
    if case.id
    in {
        "missing-binding-cookie",
        "other-binding-cookie",
        "provider-error",
        "missing-code",
        "initiator-now-viewer",
        "org-residency-on",
        "exchange-error",
    }
]


class TestOAuthCallbackErrors:
    """Every refusal: its exact reason, nothing stored, the state spent, the cookie cleared."""

    pytestmark = pytest.mark.asyncio

    @staticmethod
    async def _attempt(
        db: FakeDb, provider_calls: _ProviderCalls, setup: _Setup, provider: str
    ) -> tuple[FastAPI, _Flow, Response]:
        app = _app()
        initiator = _account(db, "editor")
        flow = _Flow(db=db, initiator=initiator, provider=provider, session_id=initiator.session_id)
        setup(flow)
        if flow.seed:
            server._oauth_pending_states[_STATE] = flow.pending()
        if flow.exchange_fails:
            for mock in provider_calls.exchange.values():
                mock.side_effect = OAuthError("exchange failed")
        resp = await _callback(app, flow.params, state_cookie=flow.cookie)
        return app, flow, resp

    @pytest.mark.parametrize("provider", _PROVIDERS)
    @pytest.mark.parametrize(("setup", "reason"), _ERRORS)
    async def test_oauth_callback_error_redirects_with_its_reason_and_stores_nothing(
        self,
        db: FakeDb,
        provider_calls: _ProviderCalls,
        setup: _Setup,
        reason: str,
        provider: str,
    ) -> None:
        """307 to /tools?oauth=error&reason=<reason>; no oauth_tokens row, no INSERT."""
        _, _, resp = await self._attempt(db, provider_calls, setup, provider)

        assert resp.status_code == 307
        assert resp.headers["location"] == f"/tools?oauth=error&reason={reason}"
        assert db.oauth_tokens == {}
        assert db.matching(r"^insert into oauth_tokens\b") == []

    @pytest.mark.parametrize("provider", _PROVIDERS)
    @pytest.mark.parametrize(("setup", "reason"), _ERRORS)
    async def test_oauth_callback_error_clears_the_binding_cookie(
        self,
        db: FakeDb,
        provider_calls: _ProviderCalls,
        setup: _Setup,
        reason: str,
        provider: str,
    ) -> None:
        """Every error redirect deletes admino_oauth_state."""
        _, _, resp = await self._attempt(db, provider_calls, setup, provider)

        assert resp.headers["location"].endswith(f"reason={reason}")
        _assert_state_cookie_cleared(resp)

    @pytest.mark.parametrize("provider", _PROVIDERS)
    @pytest.mark.parametrize(("setup", "reason"), _SPENDING_ERRORS)
    async def test_oauth_callback_error_spends_the_state(
        self,
        db: FakeDb,
        provider_calls: _ProviderCalls,
        setup: _Setup,
        reason: str,
        provider: str,
    ) -> None:
        """The pending entry is popped before anything else is checked."""
        _, _, resp = await self._attempt(db, provider_calls, setup, provider)

        assert resp.headers["location"].endswith(f"reason={reason}")
        assert _STATE not in server._oauth_pending_states

    @pytest.mark.parametrize("provider", _PROVIDERS)
    @pytest.mark.parametrize(("setup", "reason"), _PRE_EXCHANGE_ERRORS)
    async def test_oauth_callback_error_never_calls_the_token_endpoint(
        self,
        db: FakeDb,
        provider_calls: _ProviderCalls,
        setup: _Setup,
        reason: str,
        provider: str,
    ) -> None:
        """State, cookie, session, role and residency are checked before any exchange."""
        _, _, resp = await self._attempt(db, provider_calls, setup, provider)

        assert resp.headers["location"].endswith(f"reason={reason}")
        provider_calls.assert_no_token_endpoint_call()

    @pytest.mark.parametrize("provider", _PROVIDERS)
    @pytest.mark.parametrize(("setup", "reason"), _RETRYABLE_ERRORS)
    async def test_oauth_callback_retry_after_an_error_is_invalid_state(
        self,
        db: FakeDb,
        provider_calls: _ProviderCalls,
        setup: _Setup,
        reason: str,
        provider: str,
    ) -> None:
        """Once refused, the same state can't complete, even as a correct request."""
        app, flow, first = await self._attempt(db, provider_calls, setup, provider)
        db.users[flow.initiator.user_id]["role"] = "editor"
        db.orgs[ORG_ID]["data_residency"] = False
        for mock in provider_calls.exchange.values():
            mock.side_effect = None
            mock.reset_mock()

        retry = await _callback(app, {"code": _CODE, "state": _STATE}, state_cookie=_STATE)

        assert first.headers["location"].endswith(f"reason={reason}")
        assert retry.headers["location"] == "/tools?oauth=error&reason=invalid_state"
        assert db.oauth_tokens == {}
        provider_calls.assert_no_token_endpoint_call()


# ---------------------------------------------------------------------------
# GET /api/oauth/{provider}/status
# ---------------------------------------------------------------------------


class TestOAuthStatus:
    """The caller's own connection, the org's service switches and residency."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("healthy", [True, False], ids=["healthy-row", "unhealthy-row"])
    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_status_connected_reports_the_rows_healthy_flag(
        self, db: FakeDb, provider: str, healthy: bool
    ) -> None:
        """GH-237: ``healthy`` is the stored flag (the ciphertext decrypts in both cases)."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        _seed_token(db, caller.user_id, provider, healthy=healthy)

        resp = await _send(app, "status", provider)

        assert resp.status_code == 200
        assert resp.json() == _status_body(provider, connected=True, healthy=healthy)

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_status_undecryptable_row_is_connected_but_unhealthy(
        self, db: FakeDb, provider: str
    ) -> None:
        """GH-237: a row whose ciphertext doesn't decrypt is reported unhealthy."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        db.add_oauth_token(
            caller.user_id, provider, encrypted_refresh_token="not-a-fernet-ciphertext"
        )

        resp = await _send(app, "status", provider)

        assert resp.status_code == 200
        assert resp.json() == _status_body(provider, connected=True, healthy=False)

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_status_not_connected_still_lists_the_services(
        self, db: FakeDb, provider: str
    ) -> None:
        """No row: connected and healthy false, the three services listed anyway."""
        app = _app()
        _sign_in(app, db, "org_admin")

        resp = await _send(app, "status", provider)

        assert resp.status_code == 200
        assert resp.json() == _status_body(provider, connected=False, healthy=False)

    @pytest.mark.parametrize(
        ("provider", "disabled"),
        [
            ("google", frozenset({"gmail"})),
            ("google", frozenset({"google_calendar", "google_drive"})),
            ("microsoft", frozenset({"onedrive"})),
            ("microsoft", frozenset({"outlook", "outlook_calendar", "onedrive"})),
        ],
    )
    async def test_oauth_status_services_carry_the_orgs_stored_switches(
        self, db: FakeDb, provider: str, disabled: frozenset[str]
    ) -> None:
        """Each service's ``enabled`` is the caller's org's stored switch, never another
        org's."""
        db.add_org_settings(ORG_ID, **dict.fromkeys(disabled, False))
        db.add_org_settings(
            OTHER_ORG_ID,
            **{tool: False for tool in _PROVIDER_SERVICES[provider] if tool not in disabled},
        )
        app = _app()
        caller = _sign_in(app, db, "editor")
        _seed_token(db, caller.user_id, provider)

        resp = await _send(app, "status", provider)

        assert resp.status_code == 200
        assert resp.json() == _status_body(
            provider, connected=True, healthy=True, disabled=disabled
        )

    @pytest.mark.parametrize("org_id", [ORG_ID, OTHER_ORG_ID], ids=["same-org", "other-org"])
    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_status_another_users_row_never_connects_the_caller(
        self, db: FakeDb, provider: str, org_id: uuid.UUID
    ) -> None:
        """Only the caller's own row counts."""
        app = _app()
        _sign_in(app, db, "editor", org_id=ORG_ID)
        other = _account(db, "editor", org_id=org_id)
        _seed_token(db, other.user_id, provider, _OTHER_REFRESH_TOKEN)

        resp = await _send(app, "status", provider)

        assert resp.status_code == 200
        assert resp.json() == _status_body(provider, connected=False, healthy=False)

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_status_reads_only_the_callers_row(self, db: FakeDb, provider: str) -> None:
        """Every oauth_tokens statement binds the caller's user and org, never another user."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        other = _account(db, "editor")
        _seed_token(db, caller.user_id, provider)
        _seed_token(db, other.user_id, provider, _OTHER_REFRESH_TOKEN)

        resp = await _send(app, "status", provider)

        assert resp.status_code == 200
        calls = _token_calls(db)
        assert calls
        assert all(_binds(call, caller.user_id) and _binds(call, ORG_ID) for call in calls)
        assert not any(_binds(call, other.user_id) for call in calls)

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_status_in_a_residency_org_reports_the_kept_row(
        self, db: FakeDb, provider: str
    ) -> None:
        """Residency on: 200, ``data_residency: true``, the stored row still reported."""
        db.orgs[ORG_ID]["data_residency"] = True
        app = _app()
        caller = _sign_in(app, db, "editor")
        _seed_token(db, caller.user_id, provider)

        resp = await _send(app, "status", provider)

        assert resp.status_code == 200
        assert resp.json() == _status_body(
            provider, connected=True, healthy=True, data_residency=True
        )
        assert db.oauth_token(caller.user_id, provider) is not None


# ---------------------------------------------------------------------------
# DELETE /api/oauth/{provider}
# ---------------------------------------------------------------------------


class TestOAuthDisconnect:
    """Disconnect revokes and deletes the caller's own row and nothing else."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_disconnect_deletes_only_the_callers_row(
        self, db: FakeDb, provider: str
    ) -> None:
        """200 disconnected; another user's row of the same provider stays."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        other = _account(db, "editor")
        _seed_token(db, caller.user_id, provider)
        other_row = _seed_token(db, other.user_id, provider, _OTHER_REFRESH_TOKEN)

        resp = await _send(app, "disconnect", provider)

        assert resp.status_code == 200
        assert resp.json() == {"status": "disconnected"}
        assert db.oauth_token(caller.user_id, provider) is None
        assert db.oauth_token(other.user_id, provider) == other_row

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_disconnect_invalidates_only_the_callers_cached_token(
        self, db: FakeDb, provider: str
    ) -> None:
        """``access_tokens.invalidate(caller, provider)`` is awaited, nobody else's."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        other = _account(db, "editor")
        _seed_token(db, caller.user_id, provider)
        _seed_token(db, other.user_id, provider, _OTHER_REFRESH_TOKEN)

        with _watch_invalidate() as invalidate:
            resp = await _send(app, "disconnect", provider)

        assert resp.status_code == 200
        assert _invalidated(invalidate) == [(str(caller.user_id), provider)]

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_disconnect_revokes_the_callers_own_refresh_token(
        self, db: FakeDb, provider_calls: _ProviderCalls, provider: str
    ) -> None:
        """The provider revocation gets the caller's refresh token, not another user's."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        other = _account(db, "editor")
        _seed_token(db, other.user_id, provider, _OTHER_REFRESH_TOKEN)
        _seed_token(db, caller.user_id, provider)

        await _send(app, "disconnect", provider)

        revoke = provider_calls.revoke[provider]
        revoke.assert_awaited_once()
        assert revoke.await_args is not None
        assert revoke.await_args.args[0] == _REFRESH_TOKEN

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_disconnect_without_an_own_row_is_404_whoever_else_has_one(
        self, db: FakeDb, provider_calls: _ProviderCalls, provider: str
    ) -> None:
        """404 with the unchanged detail; the other row stays, nothing is revoked or
        invalidated for anyone else."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        other = _account(db, "editor")
        other_row = _seed_token(db, other.user_id, provider, _OTHER_REFRESH_TOKEN)

        with _watch_invalidate() as invalidate:
            resp = await _send(app, "disconnect", provider)

        assert resp.status_code == 404
        assert resp.json() == _NOT_CONNECTED[provider]
        assert db.oauth_token(other.user_id, provider) == other_row
        provider_calls.revoke[provider].assert_not_awaited()
        assert all(user == str(caller.user_id) for user, _ in _invalidated(invalidate))

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_disconnect_binds_the_callers_user_and_org(
        self, db: FakeDb, provider: str
    ) -> None:
        """Every oauth_tokens statement binds the caller's user and org, never another user."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        other = _account(db, "editor")
        _seed_token(db, caller.user_id, provider)
        _seed_token(db, other.user_id, provider, _OTHER_REFRESH_TOKEN)

        await _send(app, "disconnect", provider)

        calls = _token_calls(db)
        assert db.matching(r"^delete from oauth_tokens\b")
        assert all(_binds(call, caller.user_id) and _binds(call, ORG_ID) for call in calls)
        assert not any(_binds(call, other.user_id) for call in calls)

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_disconnect_delete_failure_returns_500(
        self, db: FakeDb, provider: str
    ) -> None:
        """A failing DELETE is an OAuthError: 500 with the unchanged detail, the row kept."""
        app = _app()
        caller = _sign_in(app, db, "editor")
        _seed_token(db, caller.user_id, provider)
        db.fail_sql = r"^delete from oauth_tokens\b"

        resp = await _send(app, "disconnect", provider)

        assert resp.status_code == 500
        assert resp.json() == {"detail": "Failed to disconnect."}
        assert db.oauth_token(caller.user_id, provider) is not None

    @pytest.mark.parametrize("provider", _PROVIDERS)
    async def test_oauth_disconnect_in_a_residency_org_still_works(
        self, db: FakeDb, provider: str
    ) -> None:
        """Residency keeps connections inactive; the user may still remove theirs (and only
        theirs: a colleague's kept row stays)."""
        db.orgs[ORG_ID]["data_residency"] = True
        app = _app()
        caller = _sign_in(app, db, "editor")
        colleague = _account(db, "editor")
        _seed_token(db, caller.user_id, provider)
        colleague_row = _seed_token(db, colleague.user_id, provider, _OTHER_REFRESH_TOKEN)

        resp = await _send(app, "disconnect", provider)

        assert resp.status_code == 200
        assert resp.json() == {"status": "disconnected"}
        assert db.oauth_token(caller.user_id, provider) is None
        assert db.oauth_token(colleague.user_id, provider) == colleague_row


# ---------------------------------------------------------------------------
# Demotion keeps connections, inactive
# ---------------------------------------------------------------------------


class TestOAuthDemotion:
    """A demoted user's rows stay; the routes refuse until the role allows oauth.connect."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_demoted_viewer_is_refused_everywhere_and_keeps_the_rows(
        self, db: FakeDb
    ) -> None:
        """Real session resolution: the Viewer role read from the database gets 403 on every
        session route; no row is touched."""
        app = _app()
        caller = _account(db, "editor")
        for provider in _PROVIDERS:
            _seed_token(db, caller.user_id, provider)
        rows = _token_rows(db)
        db.users[caller.user_id]["role"] = "viewer"

        async with _client(app) as client:
            responses = [
                await client.request(method, path, headers=session_cookie(caller.token))
                for method, path in _SESSION_OAUTH_ROUTES
            ]

        assert [(resp.status_code, resp.json()) for resp in responses] == [(403, _FORBIDDEN)] * len(
            _SESSION_OAUTH_ROUTES
        )
        assert _token_rows(db) == rows
        assert server._oauth_pending_states == {}

    async def test_oauth_promoted_back_to_editor_sees_the_kept_rows(self, db: FakeDb) -> None:
        """Viewer, then Editor again: both connections are reported connected."""
        app = _app()
        caller = _account(db, "editor")
        for provider in _PROVIDERS:
            _seed_token(db, caller.user_id, provider)
        db.users[caller.user_id]["role"] = "viewer"

        async with _client(app) as client:
            refused = [
                await client.get(
                    f"/api/oauth/{provider}/status", headers=session_cookie(caller.token)
                )
                for provider in _PROVIDERS
            ]
            db.users[caller.user_id]["role"] = "editor"
            restored = [
                await client.get(
                    f"/api/oauth/{provider}/status", headers=session_cookie(caller.token)
                )
                for provider in _PROVIDERS
            ]

        assert [resp.status_code for resp in refused] == [403, 403]
        assert [resp.json() for resp in restored] == [
            _status_body(provider, connected=True, healthy=True) for provider in _PROVIDERS
        ]


# ---------------------------------------------------------------------------
# Rate limits (unchanged keys)
# ---------------------------------------------------------------------------


class TestOAuthRateLimits:
    """Per user on the session routes, per client IP on the callback."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_session_route_bucket_is_per_user_and_before_the_role_check(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A Viewer spends its own bucket (403, 403, then 429); an Editor is unaffected."""
        monkeypatch.setitem(server._RATE_LIMITS, "/api/oauth/google/status", (0.001, 2))
        app = _app()
        viewer = _sign_in(app, db, "viewer")

        async with _client(app) as client:
            statuses = [
                (await client.get("/api/oauth/google/status")).status_code for _ in range(3)
            ]
            _sign_in(app, db, "editor")
            editor = await client.get("/api/oauth/google/status")

        assert statuses == [403, 403, 429]
        assert editor.status_code == 200
        assert ("/api/oauth/google/status", f"user:{viewer.user_id}") in server._rate_buckets

    async def test_oauth_callback_bucket_is_per_client_ip_and_spends_no_state(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """IP A's 429 leaves the state pending; IP B completes it."""
        monkeypatch.setitem(server._RATE_LIMITS, "/api/oauth/callback", (0.001, 1))
        app = _app()
        initiator = _account(db, "editor")
        server._oauth_pending_states[_STATE] = _pending(initiator, "google")

        first = await _callback(app, {"state": _OTHER_STATE}, state_cookie=_OTHER_STATE, ip=_IP_A)
        limited = await _callback(app, {"code": _CODE, "state": _STATE}, ip=_IP_A)
        other_ip = await _callback(app, {"code": _CODE, "state": _STATE}, ip=_IP_B)

        assert first.status_code == 307
        assert limited.status_code == 429
        assert other_ip.headers["location"] == _SUCCESS
        assert db.oauth_token(initiator.user_id, "google") is not None
