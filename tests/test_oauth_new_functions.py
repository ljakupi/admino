"""Tests for oauth.py helpers: delete_token() and get_google_user_email().

GH-86: delete_token is now async and DELETEs a row via the asyncpg pool
(returning True/False based on the DELETE status tag). get_google_user_email
is unchanged (network only, never raises).

Covers:
- delete_token: True when a row was removed, False when none existed,
  parameterized DELETE.
- get_google_user_email: fetches email from Google userinfo endpoint,
  never raises.

Security notes:
- All HTTP clients are mocked — no real Google API calls.
- The database pool is mocked (``mock_pool`` fixture) — no real DB.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import httpx
import pytest

from admino.oauth import (
    delete_token,
    get_google_user_email,
)

if TYPE_CHECKING:
    from unittest.mock import MagicMock


def _make_httpx_response(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response."""
    body = json.dumps(json_body or {}).encode()
    return httpx.Response(status_code=status_code, content=body)


# ---------------------------------------------------------------------------
# delete_token() — DB-backed
# ---------------------------------------------------------------------------


class TestDeleteToken:
    """Tests for delete_token(pool, provider)."""

    pytestmark = pytest.mark.asyncio

    def _prime_execute(self, mock_pool: MagicMock, status: str) -> None:
        mock_pool.execute = AsyncMock(return_value=status)
        mock_pool._mock_conn.execute = AsyncMock(return_value=status)

    async def test_delete_token_returns_true_when_row_deleted(self, mock_pool: MagicMock) -> None:
        """A 'DELETE 1' status tag returns True."""
        self._prime_execute(mock_pool, "DELETE 1")

        result = await delete_token(mock_pool, "google")

        assert result is True

    async def test_delete_token_returns_false_when_no_row(self, mock_pool: MagicMock) -> None:
        """A 'DELETE 0' status tag returns False."""
        self._prime_execute(mock_pool, "DELETE 0")

        result = await delete_token(mock_pool, "google")

        assert result is False

    async def test_delete_token_is_parameterized(self, mock_pool: MagicMock) -> None:
        """The DELETE binds the provider as a parameter, not interpolated."""
        self._prime_execute(mock_pool, "DELETE 1")

        await delete_token(mock_pool, "microsoft")

        call = mock_pool.execute.call_args or mock_pool._mock_conn.execute.call_args
        assert call is not None
        assert "$1" in call.args[0]
        assert "microsoft" in call.args[1:]
        assert "microsoft" not in call.args[0]


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
