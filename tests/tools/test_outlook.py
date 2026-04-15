"""Tests for the Outlook mail tool (admino.tools.outlook).

Covers tool registration, happy-path responses, OAuth error handling,
API error handling, empty results, body truncation, and argument validation.
All HTTP calls are mocked; no real API calls are made.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pydantic import ValidationError

if TYPE_CHECKING:
    from collections.abc import Generator

from admino.models import OutlookListArgs, OutlookReadArgs, OutlookSearchArgs
from admino.oauth import OAuthError
from admino.tools import outlook as outlook_mod
from admino.tools.registry import clear_registry, get_registered_tools

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response with JSON body."""
    body = json.dumps(json_body or {}).encode()
    return httpx.Response(status_code=status_code, content=body)


def _sample_message(
    msg_id: str = "msg-1",
    subject: str = "Test Subject",
    from_email: str = "sender@example.com",
    body_content: str = "Hello world",
) -> dict[str, Any]:
    """Build a sample Microsoft Graph message object."""
    return {
        "id": msg_id,
        "subject": subject,
        "from": {"emailAddress": {"address": from_email}},
        "receivedDateTime": "2026-04-12T10:00:00Z",
        "bodyPreview": "preview text",
        "body": {"contentType": "text", "content": body_content},
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Ensure the registry is clean before and after every test."""
    import importlib

    clear_registry()
    importlib.reload(outlook_mod)
    yield
    clear_registry()


@pytest.fixture()
def mock_token() -> Generator[AsyncMock, None, None]:
    """Mock _get_microsoft_token to return a fake token."""
    with patch(
        "admino.tools.outlook._get_microsoft_token",
        new_callable=AsyncMock,
        return_value="fake-token-123",
    ) as m:
        yield m


@pytest.fixture()
def mock_http_client() -> Generator[AsyncMock, None, None]:
    """Mock the module-level _http_client."""
    mock_client = AsyncMock()
    with patch("admino.tools.outlook._http_client", mock_client):
        yield mock_client


# ---------------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------------


class TestOutlookRegistration:
    """Verify tool actions are registered after import."""

    def test_outlook_read_registered(self) -> None:
        """outlook.read is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("outlook", "read") in keys

    def test_outlook_list_registered(self) -> None:
        """outlook.list is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("outlook", "list") in keys

    def test_outlook_search_registered(self) -> None:
        """outlook.search is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("outlook", "search") in keys


# ---------------------------------------------------------------------------
# 2. outlook.read
# ---------------------------------------------------------------------------


class TestOutlookRead:
    """Tests for the outlook.read action."""

    async def test_read_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Read returns formatted message with subject, from, date, body."""
        msg = _sample_message()
        mock_http_client.get.return_value = _make_response(200, msg)

        from admino.tools.outlook import outlook_read

        args = OutlookReadArgs(message_id="msg-1")
        result = await outlook_read(args)

        assert "Subject: Test Subject" in result
        assert "From: sender@example.com" in result
        assert "Body:\nHello world" in result

    async def test_read_oauth_not_configured(self) -> None:
        """When OAuth is not configured, returns setup instructions."""
        with patch(
            "admino.tools.outlook._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook import outlook_read

            args = OutlookReadArgs(message_id="msg-1")
            result = await outlook_read(args)

        assert "OAuth not configured" in result
        assert "oauth_setup" in result

    async def test_read_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 response returns Graph error message."""
        error_body = {"error": {"message": "Item not found"}}
        mock_http_client.get.return_value = _make_response(404, error_body)

        from admino.tools.outlook import outlook_read

        args = OutlookReadArgs(message_id="bad-id")
        result = await outlook_read(args)

        assert "Microsoft Graph error" in result
        assert "Item not found" in result

    async def test_read_body_truncation(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Body content exceeding 10000 chars is truncated."""
        long_body = "x" * 15_000
        msg = _sample_message(body_content=long_body)
        mock_http_client.get.return_value = _make_response(200, msg)

        from admino.tools.outlook import outlook_read

        args = OutlookReadArgs(message_id="msg-1")
        result = await outlook_read(args)

        assert "[Truncated]" in result
        # Body portion should be at most 10000 chars + truncation marker
        body_start = result.index("Body:\n") + len("Body:\n")
        body_text = result[body_start:]
        assert len(body_text) < 15_000

    async def test_read_http_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """httpx.HTTPError returns connection failure message."""
        mock_http_client.get.side_effect = httpx.ConnectError("connection failed")

        from admino.tools.outlook import outlook_read

        args = OutlookReadArgs(message_id="msg-1")
        result = await outlook_read(args)

        assert "Failed to connect" in result


# ---------------------------------------------------------------------------
# 3. outlook.list
# ---------------------------------------------------------------------------


class TestOutlookList:
    """Tests for the outlook.list action."""

    async def test_list_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """List returns formatted message summaries."""
        messages = [
            _sample_message(msg_id="m1", subject="First"),
            _sample_message(msg_id="m2", subject="Second"),
        ]
        mock_http_client.get.return_value = _make_response(200, {"value": messages})

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=10)
        result = await outlook_list(args)

        assert "Subject: First" in result
        assert "Subject: Second" in result
        assert "---" in result

    async def test_list_empty_results(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Empty message list returns appropriate message."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=10)
        result = await outlook_list(args)

        assert "No messages found" in result

    async def test_list_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.outlook._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook import outlook_list

            args = OutlookListArgs(max_results=10)
            result = await outlook_list(args)

        assert "OAuth not configured" in result

    async def test_list_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 status returns Graph error."""
        mock_http_client.get.return_value = _make_response(
            403, {"error": {"message": "Access denied"}}
        )

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=10)
        result = await outlook_list(args)

        assert "Microsoft Graph error" in result
        assert "Access denied" in result

    async def test_list_url_contains_top_and_orderby(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Request URL includes $top and $orderby params."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=5)
        await outlook_list(args)

        call_args = mock_http_client.get.call_args
        url = call_args[0][0]
        assert "$top=5" in url
        assert "$orderby=receivedDateTime" in url


# ---------------------------------------------------------------------------
# 4. outlook.search
# ---------------------------------------------------------------------------


class TestOutlookSearch:
    """Tests for the outlook.search action."""

    async def test_search_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Search returns formatted results."""
        messages = [_sample_message(msg_id="s1", subject="Match")]
        mock_http_client.get.return_value = _make_response(200, {"value": messages})

        from admino.tools.outlook import outlook_search

        args = OutlookSearchArgs(query="important")
        result = await outlook_search(args)

        assert "Subject: Match" in result

    async def test_search_empty_results(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Empty search results return appropriate message."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_search

        args = OutlookSearchArgs(query="nonexistent")
        result = await outlook_search(args)

        assert "No messages found" in result

    async def test_search_url_contains_search_param(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Request URL includes $search param with query."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_search

        args = OutlookSearchArgs(query="budget report")
        await outlook_search(args)

        call_args = mock_http_client.get.call_args
        url = call_args[0][0]
        assert "$search=" in url
        assert "budget report" in url

    async def test_search_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.outlook._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook import outlook_search

            args = OutlookSearchArgs(query="test")
            result = await outlook_search(args)

        assert "OAuth not configured" in result

    async def test_search_api_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Non-200 status returns Graph error."""
        mock_http_client.get.return_value = _make_response(
            500, {"error": {"message": "Internal error"}}
        )

        from admino.tools.outlook import outlook_search

        args = OutlookSearchArgs(query="test")
        result = await outlook_search(args)

        assert "Microsoft Graph error" in result


# ---------------------------------------------------------------------------
# 5. Argument validation
# ---------------------------------------------------------------------------


class TestOutlookArgValidation:
    """Pydantic validation rejects invalid arguments."""

    def test_read_valid_message_id_accepted(self) -> None:
        """Valid message_id is accepted."""
        args = OutlookReadArgs(message_id="AAMkAGI2TG93")
        assert args.message_id == "AAMkAGI2TG93"

    def test_read_overly_long_message_id_rejected(self) -> None:
        """message_id exceeding max_length is rejected."""
        with pytest.raises(ValidationError):
            OutlookReadArgs(message_id="x" * 201)

    def test_list_max_results_zero_rejected(self) -> None:
        """max_results=0 is rejected (ge=1)."""
        with pytest.raises(ValidationError):
            OutlookListArgs(max_results=0)

    def test_list_max_results_over_limit_rejected(self) -> None:
        """max_results exceeding le=50 is rejected."""
        with pytest.raises(ValidationError):
            OutlookListArgs(max_results=51)

    def test_search_valid_query_accepted(self) -> None:
        """Valid search query is accepted."""
        args = OutlookSearchArgs(query="budget")
        assert args.query == "budget"

    def test_search_overly_long_query_rejected(self) -> None:
        """Query exceeding max_length is rejected."""
        with pytest.raises(ValidationError):
            OutlookSearchArgs(query="x" * 501)

    def test_search_max_results_zero_rejected(self) -> None:
        """max_results=0 is rejected for search."""
        with pytest.raises(ValidationError):
            OutlookSearchArgs(query="test", max_results=0)

    def test_list_default_max_results(self) -> None:
        """Default max_results is 10."""
        args = OutlookListArgs()
        assert args.max_results == 10

    def test_search_default_max_results(self) -> None:
        """Default max_results is 10."""
        args = OutlookSearchArgs(query="test")
        assert args.max_results == 10
