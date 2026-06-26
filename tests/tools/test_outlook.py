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

from admino.models import OutlookListArgs, OutlookReadArgs, OutlookSearchArgs, OutlookSendArgs
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

        assert "OAuth error" in result
        assert "oauth_setup" not in result
        assert "python" not in result.lower()
        assert "Tools" in result

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

        assert "OAuth error" in result

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

    async def test_list_top_passed_via_params_not_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """$top is passed in the httpx params dict as an int, not in the URL string."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=5)
        await outlook_list(args)

        call_args = mock_http_client.get.call_args
        params = call_args.kwargs.get("params") or {}
        assert params["$top"] == 5

    async def test_list_top_absent_from_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """$top must NOT be interpolated into the URL string anymore."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=5)
        await outlook_list(args)

        url = mock_http_client.get.call_args.args[0]
        assert "$top" not in url

    async def test_list_orderby_passed_via_params(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """$orderby is passed in the params dict and orders by receivedDateTime."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=5)
        await outlook_list(args)

        params = mock_http_client.get.call_args.kwargs.get("params") or {}
        assert params["$orderby"].startswith("receivedDateTime")


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

    async def test_search_query_passed_via_params_not_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """$search is passed in the params dict, not the URL string.

        httpx replaces an existing URL query string when params= is supplied
        (rather than merging), so $search must live in params or it is dropped.
        """
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_search

        args = OutlookSearchArgs(query="budget report")
        await outlook_search(args)

        call_args = mock_http_client.get.call_args
        params = call_args.kwargs.get("params") or {}
        assert params["$search"] == '"budget report"'
        url = call_args.args[0]
        assert "$search" not in url

    async def test_search_top_passed_via_params_not_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """$top is passed in the params dict as an int and absent from the URL.

        $search, $top and the static $select all live in the params dict so
        httpx encodes them correctly and none are dropped.
        """
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_search

        args = OutlookSearchArgs(query="budget", max_results=7)
        await outlook_search(args)

        call_args = mock_http_client.get.call_args
        params = call_args.kwargs.get("params") or {}
        assert params["$top"] == 7
        url = call_args.args[0]
        assert "$top" not in url

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

        assert "OAuth error" in result

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


# ---------------------------------------------------------------------------
# 6. outlook.send registration
# ---------------------------------------------------------------------------


class TestOutlookSendRegistration:
    """Verify outlook.send is registered after import."""

    def test_outlook_send_registered(self) -> None:
        """outlook.send action is present in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("outlook", "send") in keys


# ---------------------------------------------------------------------------
# 7. outlook.send handler
# ---------------------------------------------------------------------------


class TestOutlookSend:
    """Tests for the outlook.send handler."""

    async def test_send_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Successful send (202 Accepted) returns confirmation with recipients."""
        mock_http_client.post.return_value = _make_response(202)

        from admino.tools.outlook import outlook_send

        args = OutlookSendArgs(
            to=["recipient@example.com"],
            subject="Test Email",
            body="Hello from test!",
        )
        result = await outlook_send(args)

        assert "sent" in result.lower()
        assert "recipient@example.com" in result

    async def test_send_oauth_error(self) -> None:
        """OAuthError returns setup instructions."""
        with patch(
            "admino.tools.outlook._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook import outlook_send

            args = OutlookSendArgs(
                to=["user@example.com"],
                subject="Hi",
                body="test",
            )
            result = await outlook_send(args)

        assert "OAuth error" in result

    async def test_send_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-2xx response returns Graph error message."""
        error_body = {"error": {"message": "Bad Request"}}
        mock_http_client.post.return_value = _make_response(400, error_body)

        from admino.tools.outlook import outlook_send

        args = OutlookSendArgs(
            to=["user@example.com"],
            subject="Hi",
            body="test",
        )
        result = await outlook_send(args)

        assert "Microsoft Graph error" in result

    async def test_send_http_connection_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """httpx.ConnectError returns connection failure message."""
        mock_http_client.post.side_effect = httpx.ConnectError("connection failed")

        from admino.tools.outlook import outlook_send

        args = OutlookSendArgs(
            to=["user@example.com"],
            subject="Hi",
            body="test",
        )
        result = await outlook_send(args)

        assert "Failed to connect" in result

    async def test_send_payload_structure(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """JSON payload posted to Graph has the correct sendMail structure."""
        mock_http_client.post.return_value = _make_response(202)

        from admino.tools.outlook import outlook_send

        args = OutlookSendArgs(
            to=["to@example.com"],
            cc=["cc@example.com"],
            bcc=["bcc@example.com"],
            subject="Structured Test",
            body="body content",
        )
        await outlook_send(args)

        call_kwargs = mock_http_client.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json", {})

        message = payload["message"]
        assert len(message["toRecipients"]) == 1
        assert message["toRecipients"][0]["emailAddress"]["address"] == "to@example.com"
        assert len(message["ccRecipients"]) == 1
        assert message["ccRecipients"][0]["emailAddress"]["address"] == "cc@example.com"
        assert len(message["bccRecipients"]) == 1
        assert message["bccRecipients"][0]["emailAddress"]["address"] == "bcc@example.com"
        assert message["subject"] == "Structured Test"
        assert "body content" in message["body"]["content"]

    async def test_send_response_omits_body_content(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Response summary does not include email body content (audit safety)."""
        mock_http_client.post.return_value = _make_response(202)

        from admino.tools.outlook import outlook_send

        body = "Sensitive medical information here"
        args = OutlookSendArgs(
            to=["user@example.com"],
            subject="Long body",
            body=body,
        )
        result = await outlook_send(args)

        assert body not in result
        assert "Email sent to" in result


# ---------------------------------------------------------------------------
# 8. outlook.send argument validation
# ---------------------------------------------------------------------------


class TestOutlookSendArgValidation:
    """Pydantic validation for OutlookSendArgs."""

    def test_send_empty_to_rejected(self) -> None:
        """Empty recipient list is rejected."""
        with pytest.raises(ValidationError):
            OutlookSendArgs(to=[], subject="Hi", body="test")

    def test_send_invalid_email_rejected(self) -> None:
        """Invalid email address is rejected."""
        with pytest.raises(ValidationError):
            OutlookSendArgs(to=["not-an-email"], subject="Hi", body="test")

    def test_send_header_injection_email_rejected(self) -> None:
        """Email with CRLF header injection is rejected."""
        with pytest.raises(ValidationError):
            OutlookSendArgs(to=["evil@test.com\r\nBcc: spam@evil.com"], subject="Hi", body="test")

    def test_send_too_many_recipients_rejected(self) -> None:
        """More than 20 recipients is rejected."""
        recipients = [f"user{i}@example.com" for i in range(21)]
        with pytest.raises(ValidationError):
            OutlookSendArgs(to=recipients, subject="Hi", body="test")

    def test_send_subject_too_long_rejected(self) -> None:
        """Subject exceeding 500 chars is rejected."""
        with pytest.raises(ValidationError):
            OutlookSendArgs(to=["user@example.com"], subject="x" * 501, body="test")

    def test_send_body_too_long_rejected(self) -> None:
        """Body exceeding 50000 chars is rejected."""
        with pytest.raises(ValidationError):
            OutlookSendArgs(to=["user@example.com"], subject="Hi", body="x" * 50001)

    def test_send_valid_args_accepted(self) -> None:
        """Valid send arguments pass validation."""
        args = OutlookSendArgs(
            to=["user@example.com"],
            subject="Hello",
            body="This is a test email.",
        )
        assert args.to == ["user@example.com"]
        assert args.subject == "Hello"

    def test_send_subject_with_crlf_rejected(self) -> None:
        """Subject containing CRLF is rejected (header injection prevention)."""
        with pytest.raises(ValidationError):
            OutlookSendArgs(
                to=["user@example.com"],
                subject="Legit\r\nBcc: attacker@evil.com",
                body="test",
            )

    def test_send_body_with_null_byte_rejected(self) -> None:
        """Body containing null byte is rejected."""
        with pytest.raises(ValidationError):
            OutlookSendArgs(
                to=["user@example.com"],
                subject="Hi",
                body="test\x00payload",
            )

    def test_send_empty_subject_allowed(self) -> None:
        """Empty subject is allowed."""
        args = OutlookSendArgs(
            to=["user@example.com"],
            subject="",
            body="No subject email",
        )
        assert args.subject == ""
