"""TDD tests for new oauth.py functions: delete_token() and get_google_user_email().

These tests are written BEFORE implementation (GitHub issue #18) and will fail
with ImportError until the functions are added to admino.oauth.

Covers:
- delete_token: removes token file, returns False if missing, raises on permission error
- get_google_user_email: fetches email from Google userinfo endpoint, never raises

Security notes:
- All tests use mocked HTTP clients — no real Google API calls.
- Token file tests use tmp_path — no real filesystem pollution.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from cryptography.fernet import Fernet

if TYPE_CHECKING:
    from pathlib import Path

from admino.oauth import (
    GOOGLE_SCOPES,
    OAuthError,
    TokenFile,
    delete_token,
    encrypt_refresh_token,
    get_google_user_email,
    save_token,
)

# ---------------------------------------------------------------------------
# Shared helpers and fixtures
# ---------------------------------------------------------------------------

_TEST_FERNET_KEY: str = Fernet.generate_key().decode()
_PLAINTEXT_REFRESH_TOKEN: str = "1//0abc-REFRESH-TOKEN-plaintext"


@pytest.fixture()
def fernet_env(monkeypatch: pytest.MonkeyPatch) -> str:
    """Set OAUTH_ENCRYPTION_KEY to a valid Fernet key. Returns the key."""
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", _TEST_FERNET_KEY)
    return _TEST_FERNET_KEY


@pytest.fixture()
def sample_token_file(fernet_env: str) -> TokenFile:
    """A valid TokenFile with an encrypted refresh token."""
    _ = fernet_env
    encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
    now = datetime.now(UTC)
    return TokenFile(
        provider="google",
        scopes=list(GOOGLE_SCOPES),
        encrypted_refresh_token=encrypted,
        created_at=now,
        last_refreshed_at=now,
    )


def _make_httpx_response(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response."""
    body = json.dumps(json_body or {}).encode()
    return httpx.Response(status_code=status_code, content=body)


# ---------------------------------------------------------------------------
# delete_token()
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fernet_env")
class TestDeleteToken:
    """Tests for delete_token(tokens_dir, provider)."""

    def test_delete_token_removes_existing_file(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Deleting an existing token file returns True and removes the file."""
        save_token(tmp_path, sample_token_file)
        token_path = tmp_path / "google.json"
        assert token_path.exists()

        result = delete_token(tmp_path, "google")

        assert result is True
        assert not token_path.exists()

    def test_delete_token_returns_false_when_no_file(self, tmp_path: Path) -> None:
        """Returns False when no token file exists for the provider."""
        result = delete_token(tmp_path, "google")

        assert result is False

    def test_delete_token_raises_on_permission_error(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Raises OAuthError when the file exists but cannot be deleted."""
        save_token(tmp_path, sample_token_file)

        with (
            patch("os.unlink", side_effect=PermissionError("forbidden")),
            pytest.raises(OAuthError),
        ):
            delete_token(tmp_path, "google")


# ---------------------------------------------------------------------------
# get_google_user_email()
# ---------------------------------------------------------------------------


class TestGetGoogleUserEmail:
    """Tests for get_google_user_email(access_token, http_client)."""

    pytestmark = pytest.mark.asyncio

    async def test_get_google_user_email_success(self) -> None:
        """Returns the email address from the Google userinfo endpoint."""
        response = _make_httpx_response(200, {"email": "user@gmail.com"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get.return_value = response

        result = await get_google_user_email("fake-access-token", mock_client)

        assert result == "user@gmail.com"
        mock_client.get.assert_called_once()

    async def test_get_google_user_email_returns_none_on_http_error(self) -> None:
        """Returns None when the HTTP request raises an error."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get.side_effect = httpx.HTTPError("connection failed")

        result = await get_google_user_email("fake-access-token", mock_client)

        assert result is None

    async def test_get_google_user_email_returns_none_on_bad_status(self) -> None:
        """Returns None when the endpoint returns a non-200 status code."""
        response = _make_httpx_response(401, {"error": "invalid_token"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get.return_value = response

        result = await get_google_user_email("fake-access-token", mock_client)

        assert result is None

    async def test_get_google_user_email_returns_none_on_missing_email(self) -> None:
        """Returns None when the response JSON lacks an email field."""
        response = _make_httpx_response(200, {"name": "Test User"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.get.return_value = response

        result = await get_google_user_email("fake-access-token", mock_client)

        assert result is None
