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
        srv._oauth_pending_states[state_token] = time.time()

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
        assert "/settings" in resp.headers["location"]
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
        srv._oauth_pending_states[state_token] = time.time() - 660

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
        srv._oauth_pending_states[state_token] = time.time()

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
        srv._oauth_pending_states[state_token] = time.time()

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
        """Returns 200 when delete_token returns True."""
        app = _make_app()
        with patch("admino.server.delete_token", return_value=True):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.delete("/api/oauth/google", headers=_AUTH_HEADER)

        assert resp.status_code == 200

    async def test_oauth_disconnect_not_connected(self) -> None:
        """Returns 404 when delete_token returns False (no token to delete)."""
        app = _make_app()
        with patch("admino.server.delete_token", return_value=False):
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
