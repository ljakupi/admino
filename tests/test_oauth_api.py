"""Tests for the Google OAuth UI flow endpoints (GitHub issue #18).

TDD tests — these are written BEFORE implementation and will fail until
the endpoints and supporting functions are implemented.

Covers:
- GET /api/oauth/google/authorize: returns consent URL with CSRF state
- GET /api/oauth/callback: exchanges code for tokens, redirects on success/failure
- GET /api/oauth/google/status: returns connection status
- DELETE /api/oauth/google: disconnects Google OAuth

Security notes:
- All tests use mocked OAuth functions — no real Google API calls.
- Auth token is a known test value, never a real secret.
- CSRF state validation tested for invalid/expired/missing cases.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from admino.oauth import OAuthError
from admino.server import create_app

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEST_TOKEN = "a" * 48 + "BcDeFgHiJkLmNoPqRsTuVwXyZ"  # >48 chars, >20 unique
_AUTH_HEADER = {"Authorization": f"Bearer {_TEST_TOKEN}"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    *,
    auth_mode: str = "token",
    token: str | None = _TEST_TOKEN,
    tokens_dir: Path | None = None,
) -> MagicMock:
    """Build a minimal mock AppConfig with configurable tokens_dir."""
    config = MagicMock()
    config.auth.mode = auth_mode
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    if tokens_dir is not None:
        config.paths.tokens_dir = tokens_dir
    else:
        config.paths.tokens_dir = Path("/tmp/test-tokens-oauth")  # noqa: S108
    if token is not None:
        config.auth.token = SecretStr(token)
    else:
        config.auth.token = None
    return config


def _make_app(
    agent: Any = None,
    *,
    auth_mode: str = "token",
    token: str | None = _TEST_TOKEN,
    tokens_dir: Path | None = None,
) -> Any:
    """Create a FastAPI app with mock agent and config."""
    if agent is None:
        agent = MagicMock()
    config = _make_config(auth_mode=auth_mode, token=token, tokens_dir=tokens_dir)
    return create_app(agent=agent, config=config)


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
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/oauth/google/authorize", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        data = resp.json()
        assert "url" in data
        assert data["url"] == fake_url

    async def test_oauth_authorize_requires_auth(self) -> None:
        """Returns 401 when no Authorization header is provided."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/oauth/google/authorize")

        assert resp.status_code == 401

    async def test_oauth_authorize_missing_env_vars(self) -> None:
        """Returns 500 when build_google_consent_url raises OAuthError."""
        app = _make_app()
        with patch(
            "admino.server.build_google_consent_url",
            side_effect=OAuthError("GOOGLE_CLIENT_ID environment variable is not set."),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/oauth/google/authorize", headers=_AUTH_HEADER)

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

        app = _make_app()

        # Pre-populate CSRF state.
        state_token = "valid-state-token"
        srv._oauth_pending_states[state_token] = (time.time(), "google", "http://test/api/oauth/callback")

        with (
            patch(
                "admino.server.exchange_google_code",
                new=AsyncMock(
                    return_value=("access-tok", "refresh-tok", ["scope1", "scope2"]),
                ),
            ),
            patch("admino.server.encrypt_refresh_token", return_value="encrypted-tok"),
            patch("admino.server.save_token"),
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
        app = _make_app()

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

        app = _make_app()

        # Insert state that expired 11 minutes ago.
        state_token = "expired-state"
        srv._oauth_pending_states[state_token] = (time.time() - 660, "google", "http://test/api/oauth/callback")

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

        app = _make_app()

        state_token = "valid-state-no-code"
        srv._oauth_pending_states[state_token] = (time.time(), "google", "http://test/api/oauth/callback")

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

        app = _make_app()

        state_token = "valid-state-exchange-fail"
        srv._oauth_pending_states[state_token] = (time.time(), "google", "http://test/api/oauth/callback")

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


# ---------------------------------------------------------------------------
# GET /api/oauth/google/status
# ---------------------------------------------------------------------------


class TestOAuthStatus:
    """GET /api/oauth/google/status — returns connection status."""

    pytestmark = pytest.mark.asyncio

    async def test_oauth_status_connected(self, tmp_path: Path) -> None:
        """Returns connected=True with services when token file exists."""
        # Create a fake google.json token file.
        token_file = tmp_path / "google.json"
        token_file.write_text("{}")

        app = _make_app(tokens_dir=tmp_path)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/oauth/google/status", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is True
        assert "gmail" in data["services"]
        assert "google_calendar" in data["services"]
        assert "google_drive" in data["services"]

    async def test_oauth_status_not_connected(self, tmp_path: Path) -> None:
        """Returns connected=False with empty services when no token file."""
        app = _make_app(tokens_dir=tmp_path)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/oauth/google/status", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is False
        assert data["services"] == []

    async def test_oauth_status_requires_auth(self) -> None:
        """Returns 401 when no Authorization header is provided."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/oauth/google/status")

        assert resp.status_code == 401


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
            patch("admino.server._clear_gmail_cache", mock_gmail),
            patch("admino.server._clear_gcal_cache", mock_gcal),
            patch("admino.server._clear_gdrive_cache", mock_gdrive),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.delete("/api/oauth/google", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        mock_gmail.assert_awaited_once()
        mock_gcal.assert_awaited_once()
        mock_gdrive.assert_awaited_once()

    async def test_oauth_disconnect_not_connected(self) -> None:
        """Returns 404 when revoke_and_delete_token returns False (no token)."""
        app = _make_app()
        mock_revoke = AsyncMock(return_value=False)
        with patch("admino.server.revoke_and_delete_token", mock_revoke):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.delete("/api/oauth/google", headers=_AUTH_HEADER)

        assert resp.status_code == 404

    async def test_oauth_disconnect_requires_auth(self) -> None:
        """Returns 401 when no Authorization header is provided."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.delete("/api/oauth/google")

        assert resp.status_code == 401

    async def test_oauth_disconnect_oauth_error(self) -> None:
        """Returns 500 when revoke_and_delete_token raises OAuthError."""
        app = _make_app()
        mock_revoke = AsyncMock(side_effect=OAuthError("fail"))
        with patch("admino.server.revoke_and_delete_token", mock_revoke):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.delete("/api/oauth/google", headers=_AUTH_HEADER)

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
            patch("admino.server._clear_outlook_cache", mock_outlook),
            patch("admino.server._clear_outcal_cache", mock_outcal),
            patch("admino.server._clear_onedrive_cache", mock_onedrive),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.delete("/api/oauth/microsoft", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        assert resp.json() == {"status": "disconnected"}
        mock_outlook.assert_awaited_once()
        mock_outcal.assert_awaited_once()
        mock_onedrive.assert_awaited_once()

    async def test_microsoft_disconnect_not_connected(self) -> None:
        """Returns 404 when revoke_and_delete_token returns False (no token)."""
        app = _make_app()
        mock_revoke = AsyncMock(return_value=False)
        with patch("admino.server.revoke_and_delete_token", mock_revoke):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.delete("/api/oauth/microsoft", headers=_AUTH_HEADER)

        assert resp.status_code == 404

    async def test_microsoft_disconnect_requires_auth(self) -> None:
        """Returns 401 when no Authorization header is provided."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.delete("/api/oauth/microsoft")

        assert resp.status_code == 401

    async def test_microsoft_disconnect_oauth_error(self) -> None:
        """Returns 500 when revoke_and_delete_token raises OAuthError."""
        app = _make_app()
        mock_revoke = AsyncMock(side_effect=OAuthError("fail"))
        with patch("admino.server.revoke_and_delete_token", mock_revoke):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.delete("/api/oauth/microsoft", headers=_AUTH_HEADER)

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
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/oauth/microsoft/authorize", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        data = resp.json()
        assert "url" in data
        assert data["url"] == fake_url

    async def test_microsoft_authorize_requires_auth(self) -> None:
        """Returns 401 when no Authorization header is provided."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/oauth/microsoft/authorize")

        assert resp.status_code == 401

    async def test_microsoft_authorize_missing_env_vars(self) -> None:
        """Returns 500 when build_microsoft_consent_url raises OAuthError."""
        app = _make_app()
        with patch(
            "admino.server.build_microsoft_consent_url",
            side_effect=OAuthError("MICROSOFT_CLIENT_ID environment variable is not set."),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/oauth/microsoft/authorize", headers=_AUTH_HEADER)

        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# GET /api/oauth/microsoft/status
# ---------------------------------------------------------------------------


class TestMicrosoftOAuthStatus:
    """GET /api/oauth/microsoft/status — returns connection status."""

    pytestmark = pytest.mark.asyncio

    async def test_microsoft_status_connected(self, tmp_path: Path) -> None:
        """Returns connected=True with services when token file exists."""
        token_file = tmp_path / "microsoft.json"
        token_file.write_text("{}")

        app = _make_app(tokens_dir=tmp_path)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/oauth/microsoft/status", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is True
        assert "outlook" in data["services"]
        assert "outlook_calendar" in data["services"]
        assert "onedrive" in data["services"]

    async def test_microsoft_status_not_connected(self, tmp_path: Path) -> None:
        """Returns connected=False with empty services when no token file."""
        app = _make_app(tokens_dir=tmp_path)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/oauth/microsoft/status", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is False
        assert data["services"] == []

    async def test_microsoft_status_requires_auth(self) -> None:
        """Returns 401 when no Authorization header is provided."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/oauth/microsoft/status")

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Microsoft path through GET /api/oauth/callback
# ---------------------------------------------------------------------------


class TestMicrosoftOAuthCallback:
    """GET /api/oauth/callback — Microsoft provider branch."""

    pytestmark = pytest.mark.asyncio

    async def test_microsoft_callback_success_redirects(self) -> None:
        """Valid code+state for Microsoft exchanges tokens and redirects to settings."""
        import admino.server as srv

        app = _make_app()

        state_token = "valid-ms-state"
        srv._oauth_pending_states[state_token] = (time.time(), "microsoft", "http://test/api/oauth/callback")

        with (
            patch(
                "admino.server.exchange_microsoft_code",
                new=AsyncMock(
                    return_value=("ms-access-tok", "ms-refresh-tok", ["Mail.Read"]),
                ),
            ),
            patch("admino.server.encrypt_refresh_token", return_value="encrypted-ms-tok"),
            patch("admino.server.save_token"),
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

        app = _make_app()

        state_token = "valid-ms-state-fail"
        srv._oauth_pending_states[state_token] = (time.time(), "microsoft", "http://test/api/oauth/callback")

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
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/oauth/google/authorize", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        # The oldest entry (state-0) should have been evicted.
        assert "state-0" not in srv._oauth_pending_states
        # The new state should be present.
        assert "new-state" in srv._oauth_pending_states
        # Total should not exceed capacity.
        assert len(srv._oauth_pending_states) <= srv._OAUTH_PENDING_STATES_MAX

        # Clean up.
        srv._oauth_pending_states.clear()
