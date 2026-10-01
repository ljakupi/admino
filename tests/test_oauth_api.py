"""Tests for the Google OAuth UI flow endpoints (GitHub issue #18).

TDD tests — these are written BEFORE implementation and will fail until
the endpoints and supporting functions are implemented.

Covers:
- GET /api/oauth/google/authorize: returns consent URL with CSRF state
- GET /api/oauth/callback: exchanges code for tokens, redirects on success/failure
- GET /api/oauth/google/status: returns connection status
- DELETE /api/oauth/google: disconnects Google OAuth
- GH-149: every OAuth route but the callback needs a session (401 without a
  valid ``admino_session`` cookie). The callback stays public: it is the
  provider's cross-site redirect (SameSite=Strict cookies are not sent on it)
  and is protected by the OAuth state token, so its tests run with no session.
- GH-237: GET /api/oauth/{google,microsoft}/status report ``healthy`` from the
  stored token (``get_connection_status``): true for a working connection,
  false after a terminal refresh failure (the row's ``healthy`` flag is false)
  and false when not connected. The status is not admin-only: an Editor and a
  Viewer get the same answer as the Org Admin.

Security notes:
- All tests use mocked OAuth functions — no real Google API calls.
- Callers are logged in with tests.auth_helpers (an Org Admin by default); the
  session token is a known fake value, never a real secret.
- CSRF state validation tested for invalid/expired/missing cases.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

from admino.oauth import OAuthError, OAuthToken, encrypt_refresh_token
from admino.server import create_app
from tests.auth_helpers import login, member_session, resolved_session, session_cookie

if TYPE_CHECKING:
    from admino.access import MemberRole

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UNAUTHORIZED = {"detail": "Unauthorized"}

# GH-237: the services each status route lists for a connected account (as today).
_GOOGLE_SERVICES: list[str] = ["gmail", "google_calendar", "google_drive"]
_MICROSOFT_SERVICES: list[str] = ["outlook", "outlook_calendar", "onedrive"]
_PROVIDER_SERVICES: dict[str, list[str]] = {
    "google": _GOOGLE_SERVICES,
    "microsoft": _MICROSOFT_SERVICES,
}

# An obviously fake refresh token; only its Fernet ciphertext is put in a token row.
_FAKE_REFRESH_TOKEN = "fake-refresh-token-for-gh237-tests-only"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> MagicMock:
    """Build a minimal mock AppConfig.

    GH-86: tokens live in PostgreSQL, so there is no ``paths.tokens_dir``.
    GH-149: there is no ``auth`` section either.
    """
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    return config


def _make_app(agent: Any = None, *, anonymous: bool = False) -> Any:
    """Create a FastAPI app with mock agent and config; log an Org Admin in unless anonymous."""
    if agent is None:
        agent = MagicMock()
    app = create_app(agent=agent, config=_make_config())
    if not anonymous:
        login(app, member_session("org_admin"))
    return app


def _status_fields(data: dict[str, Any]) -> dict[str, Any]:
    """The GH-237 fields of a status response: connected, healthy and services."""
    return {key: data.get(key) for key in ("connected", "healthy", "services")}


@pytest.fixture()
def oauth_encryption_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set OAUTH_ENCRYPTION_KEY to a fresh Fernet key, so a stored token really decrypts."""
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", Fernet.generate_key().decode())


def _stored_token(provider: str, *, healthy: bool) -> OAuthToken:
    """A token row of ``provider`` as ``load_token`` returns it (GH-237).

    The refresh token is real Fernet ciphertext of a fake value under the
    ``oauth_encryption_key`` key, so the row decrypts and only its ``healthy``
    flag decides the health.
    """
    stamp = datetime(2026, 1, 1, tzinfo=UTC)
    return OAuthToken(
        provider=provider,
        scopes=[f"fake.{provider}.scope.read"],
        encrypted_refresh_token=encrypt_refresh_token(_FAKE_REFRESH_TOKEN),
        email=None,
        healthy=healthy,
        created_at=stamp,
        last_refreshed_at=stamp,
    )


def _load_token_returning(token: OAuthToken) -> AsyncMock:
    """A ``load_token`` stand-in: ``token`` for its own provider, no row for any other."""

    def _load(pool: Any, provider: str = "google") -> OAuthToken | None:
        return token if provider == token.provider else None

    return AsyncMock(side_effect=_load)


# ---------------------------------------------------------------------------
# GH-149: session required on every OAuth route except the callback
# ---------------------------------------------------------------------------

_SESSION_OAUTH_ROUTES: list[tuple[str, str]] = [
    ("GET", "/api/oauth/google/authorize"),
    ("GET", "/api/oauth/microsoft/authorize"),
    ("GET", "/api/oauth/google/status"),
    ("GET", "/api/oauth/microsoft/status"),
    ("DELETE", "/api/oauth/google"),
    ("DELETE", "/api/oauth/microsoft"),
]


class TestOAuthSessionRequired:
    """A cookie that resolves to no session (unknown, revoked, expired) gets a 401."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize(("method", "path"), _SESSION_OAUTH_ROUTES)
    async def test_oauth_route_unknown_session_returns_401(self, method: str, path: str) -> None:
        app = _make_app(anonymous=True)
        mock_revoke = AsyncMock(return_value=True)
        with (
            resolved_session(None),
            patch("admino.server.revoke_and_delete_token", mock_revoke),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.request(method, path, headers=session_cookie())

        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED
        mock_revoke.assert_not_awaited()


# ---------------------------------------------------------------------------
# GET /api/oauth/google/authorize
# ---------------------------------------------------------------------------


class TestOAuthAuthorize:
    """GET /api/oauth/google/authorize — returns Google consent URL."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_authorize_returns_consent_url(self) -> None:
        """Returns 200 with a consent URL containing the Google auth endpoint."""
        fake_url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=test&state=abc"
        fake_state = "abc123"

        app = _make_app()
        with patch(
            "admino.server.build_google_consent_url",
            return_value=(fake_url, fake_state),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/google/authorize")

        assert resp.status_code == 200
        data = resp.json()
        assert "url" in data
        assert data["url"] == fake_url

    async def test_oauth_authorize_requires_auth(self) -> None:
        """Returns 401 when no session cookie is sent."""
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/oauth/google/authorize")

        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    async def test_oauth_authorize_missing_env_vars(self) -> None:
        """Returns 500 when build_google_consent_url raises OAuthError."""
        app = _make_app()
        with patch(
            "admino.server.build_google_consent_url",
            side_effect=OAuthError("GOOGLE_CLIENT_ID environment variable is not set."),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/google/authorize")

        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# GET /api/oauth/callback
# ---------------------------------------------------------------------------


class TestOAuthCallback:
    """GET /api/oauth/callback — exchanges auth code for tokens."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_callback_success_redirects(self) -> None:
        """Valid code+state exchanges tokens, saves, and redirects to settings."""
        import admino.server as srv

        app = _make_app(anonymous=True)

        # Pre-populate CSRF state.
        state_token = "valid-state-token"
        srv._oauth_pending_states[state_token] = (
            time.time(),
            "google",
            "http://test/api/oauth/callback",
        )

        with (
            patch(
                "admino.server.exchange_google_code",
                new=AsyncMock(
                    return_value=("access-tok", "refresh-tok", ["scope1", "scope2"]),
                ),
            ),
            patch("admino.server.encrypt_refresh_token", return_value="encrypted-tok"),
            patch("admino.server.save_token", new=AsyncMock()),
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch(
                "admino.server.get_google_user_email",
                new=AsyncMock(return_value="user@gmail.com"),
            ),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
                follow_redirects=False,
            ) as c:
                resp = await c.get(
                    "/api/oauth/callback",
                    params={"code": "auth-code-123", "state": state_token},
                )

        assert resp.status_code == 307
        assert "/tools" in resp.headers["location"]
        assert "oauth=success" in resp.headers["location"]

    async def test_oauth_callback_invalid_state_redirects_error(self) -> None:
        """Unknown state token redirects to settings with error."""
        app = _make_app(anonymous=True)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            follow_redirects=False,
        ) as c:
            resp = await c.get(
                "/api/oauth/callback",
                params={"code": "auth-code-123", "state": "bogus-state"},
            )

        assert resp.status_code == 307
        location = resp.headers["location"]
        assert "oauth=error" in location
        assert "invalid_state" in location

    async def test_oauth_callback_expired_state_redirects_error(self) -> None:
        """State older than 10 minutes redirects to settings with error."""
        import admino.server as srv

        app = _make_app(anonymous=True)

        # Insert state that expired 11 minutes ago.
        state_token = "expired-state"
        srv._oauth_pending_states[state_token] = (
            time.time() - 660,
            "google",
            "http://test/api/oauth/callback",
        )

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            follow_redirects=False,
        ) as c:
            resp = await c.get(
                "/api/oauth/callback",
                params={"code": "auth-code-123", "state": state_token},
            )

        assert resp.status_code == 307
        location = resp.headers["location"]
        assert "oauth=error" in location
        assert "invalid_state" in location

    async def test_oauth_callback_missing_code_redirects_error(self) -> None:
        """Missing code parameter redirects to settings with error."""
        import admino.server as srv

        app = _make_app(anonymous=True)

        state_token = "valid-state-no-code"
        srv._oauth_pending_states[state_token] = (
            time.time(),
            "google",
            "http://test/api/oauth/callback",
        )

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            follow_redirects=False,
        ) as c:
            resp = await c.get(
                "/api/oauth/callback",
                params={"state": state_token},
            )

        assert resp.status_code == 307
        location = resp.headers["location"]
        assert "oauth=error" in location
        assert "missing_code" in location

    async def test_oauth_callback_exchange_failure_redirects_error(self) -> None:
        """OAuthError during code exchange redirects to settings with error."""
        import admino.server as srv

        app = _make_app(anonymous=True)

        state_token = "valid-state-exchange-fail"
        srv._oauth_pending_states[state_token] = (
            time.time(),
            "google",
            "http://test/api/oauth/callback",
        )

        with patch(
            "admino.server.exchange_google_code",
            new=AsyncMock(side_effect=OAuthError("exchange failed")),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
                follow_redirects=False,
            ) as c:
                resp = await c.get(
                    "/api/oauth/callback",
                    params={"code": "bad-code", "state": state_token},
                )

        assert resp.status_code == 307
        location = resp.headers["location"]
        assert "oauth=error" in location
        assert "exchange_failed" in location

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
    async def test_oauth_callback_accepts_valid_codes(self, code: str) -> None:
        """Auth codes with !, *, ~, and , characters must be accepted (GH-63)."""
        import admino.server as srv

        app = _make_app(anonymous=True)

        state_token = f"state-for-test-{id(code)}"
        srv._oauth_pending_states[state_token] = (
            time.time(),
            "microsoft",
            "http://test/api/oauth/callback",
        )

        with (
            patch(
                "admino.server.exchange_microsoft_code",
                new=AsyncMock(
                    return_value=("access-tok", "refresh-tok", ["Mail.ReadWrite"]),
                ),
            ),
            patch("admino.server.encrypt_refresh_token", return_value="encrypted"),
            patch("admino.server.save_token", new=AsyncMock()),
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
                follow_redirects=False,
            ) as c:
                resp = await c.get(
                    "/api/oauth/callback",
                    params={"code": code, "state": state_token},
                )

        # Must reach the handler (not 422 validation error)
        assert resp.status_code == 307, f"Code {code!r} rejected with {resp.status_code}"
        assert "oauth=success" in resp.headers["location"]

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
        """Codes with dangerous characters must be rejected by validation."""
        app = _make_app(anonymous=True)

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            follow_redirects=False,
        ) as c:
            resp = await c.get(
                "/api/oauth/callback",
                params={"code": code, "state": "some-state"},
            )

        assert resp.status_code == 422, f"Code {code!r} was not rejected"


# ---------------------------------------------------------------------------
# GET /api/oauth/google/status
# ---------------------------------------------------------------------------


class TestOAuthStatus:
    """GET /api/oauth/google/status — returns connection status."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_status_connected(self) -> None:
        """Returns connected=True with services when a DB token row exists."""
        app = _make_app()

        with (
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch("admino.server.get_connection_status", new=AsyncMock(return_value=(True, True))),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/google/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is True
        assert "gmail" in data["services"]
        assert "google_calendar" in data["services"]
        assert "google_drive" in data["services"]

    async def test_oauth_status_not_connected(self) -> None:
        """Returns connected=False with empty services when no DB token row."""
        app = _make_app()

        with (
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch(
                "admino.server.get_connection_status", new=AsyncMock(return_value=(False, False))
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/google/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is False
        assert data["services"] == []

    async def test_oauth_status_requires_auth(self) -> None:
        """Returns 401 when no session cookie is sent."""
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/oauth/google/status")

        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    @pytest.mark.parametrize(
        ("connected", "healthy", "expected"),
        [
            pytest.param(
                True,
                True,
                {"connected": True, "healthy": True, "services": _GOOGLE_SERVICES},
                id="connected-healthy",
            ),
            pytest.param(
                True,
                False,
                {"connected": True, "healthy": False, "services": _GOOGLE_SERVICES},
                id="connected-unhealthy",
            ),
            pytest.param(
                False,
                False,
                {"connected": False, "healthy": False, "services": []},
                id="not-connected",
            ),
        ],
    )
    async def test_oauth_status_connection_state_returns_stored_healthy_flag(
        self, connected: bool, healthy: bool, expected: dict[str, Any]
    ) -> None:
        """GH-237: ``healthy`` mirrors the stored token's health, services listed as today."""
        app = _make_app()

        with (
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch(
                "admino.server.get_connection_status",
                new=AsyncMock(return_value=(connected, healthy)),
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/google/status")

        assert resp.status_code == 200
        assert _status_fields(resp.json()) == expected

    @pytest.mark.usefixtures("oauth_encryption_key")
    @pytest.mark.parametrize(
        "healthy",
        [pytest.param(True, id="healthy-token"), pytest.param(False, id="unhealthy-token")],
    )
    async def test_oauth_status_stored_token_returns_its_healthy_flag(self, healthy: bool) -> None:
        """GH-237: through the real get_connection_status, the row's healthy flag is reported.

        The token decrypts in both cases, so a false ``healthy`` comes only from
        the row's flag (set by a terminal refresh failure, #64).
        """
        app = _make_app()

        with (
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch(
                "admino.oauth.load_token",
                new=_load_token_returning(_stored_token("google", healthy=healthy)),
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/google/status")

        assert resp.status_code == 200
        assert _status_fields(resp.json()) == {
            "connected": True,
            "healthy": healthy,
            "services": _GOOGLE_SERVICES,
        }


# ---------------------------------------------------------------------------
# DELETE /api/oauth/google
# ---------------------------------------------------------------------------


class TestOAuthDisconnect:
    """DELETE /api/oauth/google — disconnects Google OAuth."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_disconnect_success(self) -> None:
        """Returns 200 when revoke_and_delete_token returns True."""
        app = _make_app()
        mock_revoke = AsyncMock(return_value=True)
        mock_gmail = AsyncMock()
        mock_gcal = AsyncMock()
        mock_gdrive = AsyncMock()
        with (
            patch("admino.server.revoke_and_delete_token", mock_revoke),
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch("admino.server._clear_gmail_cache", mock_gmail),
            patch("admino.server._clear_gcal_cache", mock_gcal),
            patch("admino.server._clear_gdrive_cache", mock_gdrive),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.delete("/api/oauth/google")

        assert resp.status_code == 200
        mock_gmail.assert_awaited_once()
        mock_gcal.assert_awaited_once()
        mock_gdrive.assert_awaited_once()

    async def test_oauth_disconnect_not_connected(self) -> None:
        """Returns 404 when revoke_and_delete_token returns False (no token)."""
        app = _make_app()
        mock_revoke = AsyncMock(return_value=False)
        with (
            patch("admino.server.revoke_and_delete_token", mock_revoke),
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.delete("/api/oauth/google")

        assert resp.status_code == 404

    async def test_oauth_disconnect_requires_auth(self) -> None:
        """Returns 401 when no session cookie is sent."""
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete("/api/oauth/google")

        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    async def test_oauth_disconnect_oauth_error(self) -> None:
        """Returns 500 when revoke_and_delete_token raises OAuthError."""
        app = _make_app()
        mock_revoke = AsyncMock(side_effect=OAuthError("fail"))
        with (
            patch("admino.server.revoke_and_delete_token", mock_revoke),
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.delete("/api/oauth/google")

        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# DELETE /api/oauth/microsoft
# ---------------------------------------------------------------------------


class TestMicrosoftOAuthDisconnect:
    """DELETE /api/oauth/microsoft — disconnects Microsoft OAuth."""

    pytestmark = pytest.mark.asyncio

    async def test_microsoft_disconnect_success(self) -> None:
        """Returns 200 and clears all Microsoft caches on success."""
        app = _make_app()
        mock_revoke = AsyncMock(return_value=True)
        mock_outlook = AsyncMock()
        mock_outcal = AsyncMock()
        mock_onedrive = AsyncMock()
        with (
            patch("admino.server.revoke_and_delete_token", mock_revoke),
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch("admino.server._clear_outlook_cache", mock_outlook),
            patch("admino.server._clear_outcal_cache", mock_outcal),
            patch("admino.server._clear_onedrive_cache", mock_onedrive),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.delete("/api/oauth/microsoft")

        assert resp.status_code == 200
        assert resp.json() == {"status": "disconnected"}
        mock_outlook.assert_awaited_once()
        mock_outcal.assert_awaited_once()
        mock_onedrive.assert_awaited_once()

    async def test_microsoft_disconnect_not_connected(self) -> None:
        """Returns 404 when revoke_and_delete_token returns False (no token)."""
        app = _make_app()
        mock_revoke = AsyncMock(return_value=False)
        with (
            patch("admino.server.revoke_and_delete_token", mock_revoke),
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.delete("/api/oauth/microsoft")

        assert resp.status_code == 404

    async def test_microsoft_disconnect_requires_auth(self) -> None:
        """Returns 401 when no session cookie is sent."""
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete("/api/oauth/microsoft")

        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    async def test_microsoft_disconnect_oauth_error(self) -> None:
        """Returns 500 when revoke_and_delete_token raises OAuthError."""
        app = _make_app()
        mock_revoke = AsyncMock(side_effect=OAuthError("fail"))
        with (
            patch("admino.server.revoke_and_delete_token", mock_revoke),
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.delete("/api/oauth/microsoft")

        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# GET /api/oauth/microsoft/authorize
# ---------------------------------------------------------------------------


class TestMicrosoftOAuthAuthorize:
    """GET /api/oauth/microsoft/authorize — returns Microsoft consent URL."""

    pytestmark = pytest.mark.asyncio

    async def test_microsoft_authorize_returns_consent_url(self) -> None:
        """Returns 200 with a consent URL containing the Microsoft auth endpoint."""
        fake_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test&state=abc"
        fake_state = "abc123"

        app = _make_app()
        with patch(
            "admino.server.build_microsoft_consent_url",
            return_value=(fake_url, fake_state),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/microsoft/authorize")

        assert resp.status_code == 200
        data = resp.json()
        assert "url" in data
        assert data["url"] == fake_url

    async def test_microsoft_authorize_requires_auth(self) -> None:
        """Returns 401 when no session cookie is sent."""
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/oauth/microsoft/authorize")

        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    async def test_microsoft_authorize_missing_env_vars(self) -> None:
        """Returns 500 when build_microsoft_consent_url raises OAuthError."""
        app = _make_app()
        with patch(
            "admino.server.build_microsoft_consent_url",
            side_effect=OAuthError("MICROSOFT_CLIENT_ID environment variable is not set."),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/microsoft/authorize")

        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# GET /api/oauth/microsoft/status
# ---------------------------------------------------------------------------


class TestMicrosoftOAuthStatus:
    """GET /api/oauth/microsoft/status — returns connection status."""

    pytestmark = pytest.mark.asyncio

    async def test_microsoft_status_connected(self) -> None:
        """Returns connected=True with services when a DB token row exists."""
        app = _make_app()

        with (
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch("admino.server.get_connection_status", new=AsyncMock(return_value=(True, True))),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/microsoft/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is True
        assert "outlook" in data["services"]
        assert "outlook_calendar" in data["services"]
        assert "onedrive" in data["services"]

    async def test_microsoft_status_not_connected(self) -> None:
        """Returns connected=False with empty services when no DB token row."""
        app = _make_app()

        with (
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch(
                "admino.server.get_connection_status", new=AsyncMock(return_value=(False, False))
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/microsoft/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is False
        assert data["services"] == []

    async def test_microsoft_status_requires_auth(self) -> None:
        """Returns 401 when no session cookie is sent."""
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/oauth/microsoft/status")

        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    @pytest.mark.parametrize(
        ("connected", "healthy", "expected"),
        [
            pytest.param(
                True,
                True,
                {"connected": True, "healthy": True, "services": _MICROSOFT_SERVICES},
                id="connected-healthy",
            ),
            pytest.param(
                True,
                False,
                {"connected": True, "healthy": False, "services": _MICROSOFT_SERVICES},
                id="connected-unhealthy",
            ),
            pytest.param(
                False,
                False,
                {"connected": False, "healthy": False, "services": []},
                id="not-connected",
            ),
        ],
    )
    async def test_microsoft_status_connection_state_returns_stored_healthy_flag(
        self, connected: bool, healthy: bool, expected: dict[str, Any]
    ) -> None:
        """GH-237: ``healthy`` mirrors the stored token's health, services listed as today."""
        app = _make_app()

        with (
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch(
                "admino.server.get_connection_status",
                new=AsyncMock(return_value=(connected, healthy)),
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/microsoft/status")

        assert resp.status_code == 200
        assert _status_fields(resp.json()) == expected

    @pytest.mark.usefixtures("oauth_encryption_key")
    @pytest.mark.parametrize(
        "healthy",
        [pytest.param(True, id="healthy-token"), pytest.param(False, id="unhealthy-token")],
    )
    async def test_microsoft_status_stored_token_returns_its_healthy_flag(
        self, healthy: bool
    ) -> None:
        """GH-237: through the real get_connection_status, the row's healthy flag is reported.

        The token decrypts in both cases, so a false ``healthy`` comes only from
        the row's flag (set by a terminal refresh failure, #64).
        """
        app = _make_app()

        with (
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch(
                "admino.oauth.load_token",
                new=_load_token_returning(_stored_token("microsoft", healthy=healthy)),
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/microsoft/status")

        assert resp.status_code == 200
        assert _status_fields(resp.json()) == {
            "connected": True,
            "healthy": healthy,
            "services": _MICROSOFT_SERVICES,
        }


# ---------------------------------------------------------------------------
# GH-237: the status routes are not admin-only
# ---------------------------------------------------------------------------


class TestOAuthStatusMemberRoles:
    """GET /api/oauth/{provider}/status — every member role reads the same status."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("provider", ["google", "microsoft"])
    @pytest.mark.parametrize("role", ["org_admin", "editor", "viewer"])
    async def test_oauth_status_member_role_returns_same_connection_state(
        self, role: MemberRole, provider: str
    ) -> None:
        """GH-237: an Editor and a Viewer get the Org Admin's connected/healthy answer."""
        app = create_app(agent=MagicMock(), config=_make_config())
        login(app, member_session(role))

        with (
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
            patch("admino.server.get_connection_status", new=AsyncMock(return_value=(True, True))),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get(f"/api/oauth/{provider}/status")

        assert resp.status_code == 200
        assert _status_fields(resp.json()) == {
            "connected": True,
            "healthy": True,
            "services": _PROVIDER_SERVICES[provider],
        }


# ---------------------------------------------------------------------------
# Microsoft path through GET /api/oauth/callback
# ---------------------------------------------------------------------------


class TestMicrosoftOAuthCallback:
    """GET /api/oauth/callback — Microsoft provider branch."""

    pytestmark = pytest.mark.asyncio

    async def test_microsoft_callback_success_redirects(self) -> None:
        """Valid code+state for Microsoft exchanges tokens and redirects to settings."""
        import admino.server as srv

        app = _make_app(anonymous=True)

        state_token = "valid-ms-state"
        srv._oauth_pending_states[state_token] = (
            time.time(),
            "microsoft",
            "http://test/api/oauth/callback",
        )

        with (
            patch(
                "admino.server.exchange_microsoft_code",
                new=AsyncMock(
                    return_value=("ms-access-tok", "ms-refresh-tok", ["Mail.Read"]),
                ),
            ),
            patch("admino.server.encrypt_refresh_token", return_value="encrypted-ms-tok"),
            patch("admino.server.save_token", new=AsyncMock()),
            patch("admino.database.get_pool", MagicMock(return_value=MagicMock())),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
                follow_redirects=False,
            ) as c:
                resp = await c.get(
                    "/api/oauth/callback",
                    params={"code": "ms-auth-code-123", "state": state_token},
                )

        assert resp.status_code == 307
        assert "/tools" in resp.headers["location"]
        assert "oauth=success" in resp.headers["location"]

    async def test_microsoft_callback_exchange_failure(self) -> None:
        """OAuthError during Microsoft code exchange redirects with error."""
        import admino.server as srv

        app = _make_app(anonymous=True)

        state_token = "valid-ms-state-fail"
        srv._oauth_pending_states[state_token] = (
            time.time(),
            "microsoft",
            "http://test/api/oauth/callback",
        )

        with patch(
            "admino.server.exchange_microsoft_code",
            new=AsyncMock(side_effect=OAuthError("exchange failed")),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
                follow_redirects=False,
            ) as c:
                resp = await c.get(
                    "/api/oauth/callback",
                    params={"code": "bad-ms-code", "state": state_token},
                )

        assert resp.status_code == 307
        location = resp.headers["location"]
        assert "oauth=error" in location
        assert "exchange_failed" in location


# ---------------------------------------------------------------------------
# Capacity cap eviction
# ---------------------------------------------------------------------------


class TestOAuthStateCapacityCap:
    """Verify _oauth_pending_states capacity cap eviction works correctly."""

    pytestmark = pytest.mark.asyncio

    async def test_capacity_cap_evicts_oldest_entry(self) -> None:
        """When dict is at capacity, the next authorize call evicts the oldest entry."""
        import admino.server as srv

        app = _make_app()

        # Pre-fill to capacity with fake states.
        srv._oauth_pending_states.clear()
        for i in range(srv._OAUTH_PENDING_STATES_MAX):
            srv._oauth_pending_states[f"state-{i}"] = (
                time.time() - (srv._OAUTH_PENDING_STATES_MAX - i),
                "google",
                "http://test/api/oauth/callback",
            )

        fake_url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=test&state=new"
        with patch(
            "admino.server.build_google_consent_url",
            return_value=(fake_url, "new-state"),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/oauth/google/authorize")

        assert resp.status_code == 200
        # The oldest entry (state-0) should have been evicted.
        assert "state-0" not in srv._oauth_pending_states
        # The new state should be present.
        assert "new-state" in srv._oauth_pending_states
        # Total should not exceed capacity.
        assert len(srv._oauth_pending_states) <= srv._OAUTH_PENDING_STATES_MAX

        # Clean up.
        srv._oauth_pending_states.clear()
