"""Tests for the Gmail tool module (admino.tools.gmail).

Covers tool registration, happy-path responses, OAuth errors, API errors,
empty results, body truncation, base64 decoding, and argument validation.
All HTTP calls are mocked -- no real API requests are made.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pydantic import ValidationError

if TYPE_CHECKING:
    from collections.abc import Generator

from admino.models import GmailListArgs, GmailReadArgs, GmailSearchArgs, GmailSendArgs
from admino.oauth import OAuthError
from admino.tools import gmail
from admino.tools.registry import clear_registry, get_registered_tools

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_TOKEN = "fake-access-token-xyz"


def _make_response(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response with JSON body."""
    body = json.dumps(json_body or {}).encode()
    return httpx.Response(status_code=status_code, content=body)


def _b64_encode(text: str) -> str:
    """URL-safe base64 encode a string (no padding fix needed for test data)."""
    return base64.urlsafe_b64encode(text.encode()).decode()


def _message_payload(
    subject: str = "Test Subject",
    from_addr: str = "alice@example.com",
    date: str = "Mon, 1 Jan 2024 12:00:00 +0000",
    body_text: str = "Hello, world!",
) -> dict[str, Any]:
    """Build a realistic Gmail message payload dict."""
    return {
        "id": "msg123",
        "snippet": "Hello, world!",
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [
                {"name": "Subject", "value": subject},
                {"name": "From", "value": from_addr},
                {"name": "Date", "value": date},
            ],
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": _b64_encode(body_text)},
                },
                {
                    "mimeType": "text/html",
                    "body": {"data": _b64_encode("<p>Hello</p>")},
                },
            ],
        },
    }


def _metadata_response(
    msg_id: str = "msg123",
    subject: str = "Test Subject",
    from_addr: str = "alice@example.com",
    date: str = "Mon, 1 Jan 2024 12:00:00 +0000",
) -> dict[str, Any]:
    """Build a Gmail metadata-format response for _fetch_message_headers."""
    return {
        "id": msg_id,
        "payload": {
            "headers": [
                {"name": "Subject", "value": subject},
                {"name": "From", "value": from_addr},
                {"name": "Date", "value": date},
            ],
        },
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Ensure the registry is clean before and after every test."""
    clear_registry()
    import importlib

    importlib.reload(gmail)
    yield
    clear_registry()


@pytest.fixture()
def mock_token() -> Generator[AsyncMock, None, None]:
    """Patch _get_google_token to return a fake token."""
    with patch.object(gmail, "_get_google_token", new_callable=AsyncMock) as m:
        m.return_value = _FAKE_TOKEN
        yield m


@pytest.fixture()
def mock_http(mock_token: AsyncMock) -> Generator[AsyncMock, None, None]:
    """Patch the module-level _http_client with an AsyncMock."""
    client = AsyncMock(spec=httpx.AsyncClient)
    with patch.object(gmail, "_http_client", client):
        yield client


# ---------------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------------


class TestGmailRegistration:
    """Gmail tool actions are registered after import."""

    def test_gmail_read_registered(self) -> None:
        """gmail.read action is present in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("gmail", "read") in keys

    def test_gmail_list_registered(self) -> None:
        """gmail.list action is present in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("gmail", "list") in keys

    def test_gmail_search_registered(self) -> None:
        """gmail.search action is present in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("gmail", "search") in keys


# ---------------------------------------------------------------------------
# 2. gmail.read
# ---------------------------------------------------------------------------


class TestGmailRead:
    """Tests for the gmail.read handler."""

    async def test_happy_path_returns_formatted_message(self, mock_http: AsyncMock) -> None:
        """Successful read returns subject, from, date, and decoded body."""
        payload = _message_payload(body_text="Hello from test!")
        mock_http.get.return_value = _make_response(200, payload)

        args = GmailReadArgs(message_id="msg123")
        result = await gmail.gmail_read(args)

        assert "Subject: Test Subject" in result
        assert "From: alice@example.com" in result
        assert "Hello from test!" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError from token retrieval returns setup instructions."""
        with patch.object(
            gmail, "_get_google_token", new_callable=AsyncMock, side_effect=OAuthError("no token")
        ):
            args = GmailReadArgs(message_id="msg123")
            result = await gmail.gmail_read(args)

        assert "OAuth error" in result
        assert "oauth_setup" not in result
        assert "python" not in result.lower()
        assert "Tools" in result

    async def test_api_error_non_200(self, mock_http: AsyncMock) -> None:
        """Non-200 status returns a formatted API error."""
        error_body = {"error": {"code": 404, "message": "Not Found"}}
        mock_http.get.return_value = _make_response(404, error_body)

        args = GmailReadArgs(message_id="msg123")
        result = await gmail.gmail_read(args)

        assert "Google API error 404" in result

    async def test_body_truncation_at_limit(self, mock_http: AsyncMock) -> None:
        """Body exceeding 10000 chars is truncated."""
        long_body = "x" * 15000
        payload = _message_payload(body_text=long_body)
        mock_http.get.return_value = _make_response(200, payload)

        args = GmailReadArgs(message_id="msg123")
        result = await gmail.gmail_read(args)

        assert "Truncated at 10000 characters" in result

    async def test_base64_decoded_body(self, mock_http: AsyncMock) -> None:
        """Body part is correctly base64-decoded."""
        original = "Decoded content with special chars: ae oe ue"
        payload = _message_payload(body_text=original)
        mock_http.get.return_value = _make_response(200, payload)

        args = GmailReadArgs(message_id="msg123")
        result = await gmail.gmail_read(args)

        assert original in result

    async def test_http_error_returns_message(self) -> None:
        """httpx.HTTPError returns a friendly error message."""
        with patch.object(
            gmail, "_get_google_token", new_callable=AsyncMock, return_value=_FAKE_TOKEN
        ):
            client = AsyncMock(spec=httpx.AsyncClient)
            client.get.side_effect = httpx.ConnectError("connection refused")
            with patch.object(gmail, "_http_client", client):
                args = GmailReadArgs(message_id="msg123")
                result = await gmail.gmail_read(args)

        assert "HTTP request failed" in result


# ---------------------------------------------------------------------------
# 3. gmail.list
# ---------------------------------------------------------------------------


class TestGmailList:
    """Tests for the gmail.list handler."""

    async def test_happy_path_lists_messages(self, mock_http: AsyncMock) -> None:
        """Successful list returns formatted message headers."""
        # First call: list message IDs
        list_response = _make_response(200, {"messages": [{"id": "m1"}, {"id": "m2"}]})
        # Subsequent calls: fetch metadata for each message
        meta1 = _make_response(200, _metadata_response("m1", "Subject 1", "bob@example.com"))
        meta2 = _make_response(200, _metadata_response("m2", "Subject 2", "carol@example.com"))
        mock_http.get.side_effect = [list_response, meta1, meta2]

        args = GmailListArgs(max_results=10)
        result = await gmail.gmail_list(args)

        assert "Subject 1" in result
        assert "Subject 2" in result
        assert "bob@example.com" in result

    async def test_empty_messages_list(self, mock_http: AsyncMock) -> None:
        """Empty messages list returns appropriate message."""
        mock_http.get.return_value = _make_response(200, {"messages": []})

        args = GmailListArgs(max_results=10)
        result = await gmail.gmail_list(args)

        assert "No messages found" in result

    async def test_no_messages_key(self, mock_http: AsyncMock) -> None:
        """Response without messages key returns no-messages message."""
        mock_http.get.return_value = _make_response(200, {})

        args = GmailListArgs(max_results=10)
        result = await gmail.gmail_list(args)

        assert "No messages found" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 on list call returns API error."""
        mock_http.get.return_value = _make_response(
            403, {"error": {"code": 403, "message": "Forbidden"}}
        )

        args = GmailListArgs(max_results=5)
        result = await gmail.gmail_list(args)

        assert "Google API error 403" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            gmail, "_get_google_token", new_callable=AsyncMock, side_effect=OAuthError("no token")
        ):
            args = GmailListArgs(max_results=5)
            result = await gmail.gmail_list(args)

        assert "OAuth error" in result


# ---------------------------------------------------------------------------
# 4. gmail.search
# ---------------------------------------------------------------------------


class TestGmailSearch:
    """Tests for the gmail.search handler."""

    async def test_happy_path_search(self, mock_http: AsyncMock) -> None:
        """Successful search returns matching messages."""
        list_response = _make_response(200, {"messages": [{"id": "s1"}]})
        meta = _make_response(200, _metadata_response("s1", "Invoice from SBB"))
        mock_http.get.side_effect = [list_response, meta]

        args = GmailSearchArgs(query="from:sbb.ch subject:invoice")
        result = await gmail.gmail_search(args)

        assert "Invoice from SBB" in result

    async def test_search_query_passed_to_api(self, mock_http: AsyncMock) -> None:
        """The search query is forwarded as the q param."""
        mock_http.get.return_value = _make_response(200, {"messages": []})

        args = GmailSearchArgs(query="is:unread from:boss")
        await gmail.gmail_search(args)

        call_kwargs = mock_http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert params.get("q") == "is:unread from:boss"

    async def test_no_matching_messages(self, mock_http: AsyncMock) -> None:
        """Empty search results return appropriate message."""
        mock_http.get.return_value = _make_response(200, {"messages": []})

        args = GmailSearchArgs(query="nonexistent-query")
        result = await gmail.gmail_search(args)

        assert "No messages found matching" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            gmail, "_get_google_token", new_callable=AsyncMock, side_effect=OAuthError("no token")
        ):
            args = GmailSearchArgs(query="test")
            result = await gmail.gmail_search(args)

        assert "OAuth error" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 on search call returns API error."""
        mock_http.get.return_value = _make_response(
            500, {"error": {"code": 500, "message": "Internal"}}
        )

        args = GmailSearchArgs(query="test")
        result = await gmail.gmail_search(args)

        assert "Google API error 500" in result


# ---------------------------------------------------------------------------
# 5. Argument validation
# ---------------------------------------------------------------------------


class TestGmailArgValidation:
    """Pydantic validation rejects invalid arguments."""

    def test_read_invalid_message_id_chars(self) -> None:
        """message_id with non-alphanumeric chars is rejected."""
        with pytest.raises(ValidationError):
            GmailReadArgs(message_id="msg/../hack")

    def test_read_empty_message_id(self) -> None:
        """Empty message_id is rejected."""
        with pytest.raises(ValidationError):
            GmailReadArgs(message_id="")

    def test_read_message_id_too_long(self) -> None:
        """message_id exceeding 64 chars is rejected."""
        with pytest.raises(ValidationError):
            GmailReadArgs(message_id="a" * 65)

    def test_list_max_results_zero(self) -> None:
        """max_results=0 is rejected (min is 1)."""
        with pytest.raises(ValidationError):
            GmailListArgs(max_results=0)

    def test_list_max_results_exceeds_limit(self) -> None:
        """max_results=100 exceeds the max of 50."""
        with pytest.raises(ValidationError):
            GmailListArgs(max_results=100)

    def test_search_query_too_long(self) -> None:
        """Query exceeding 500 chars is rejected."""
        with pytest.raises(ValidationError):
            GmailSearchArgs(query="x" * 501)

    def test_search_max_results_negative(self) -> None:
        """Negative max_results is rejected."""
        with pytest.raises(ValidationError):
            GmailSearchArgs(query="test", max_results=-1)

    def test_valid_args_accepted(self) -> None:
        """Valid arguments pass validation."""
        args = GmailReadArgs(message_id="abc123")
        assert args.message_id == "abc123"

        list_args = GmailListArgs(max_results=25)
        assert list_args.max_results == 25

        search_args = GmailSearchArgs(query="from:test", max_results=10)
        assert search_args.query == "from:test"


# ---------------------------------------------------------------------------
# 6. Internal helpers
# ---------------------------------------------------------------------------


class TestGmailHelpers:
    """Tests for internal helper functions."""

    def test_extract_header_case_insensitive(self) -> None:
        """_extract_header finds headers case-insensitively."""
        headers = [{"name": "Subject", "value": "Test"}]
        assert gmail._extract_header(headers, "subject") == "Test"
        assert gmail._extract_header(headers, "SUBJECT") == "Test"

    def test_extract_header_missing_returns_empty(self) -> None:
        """_extract_header returns empty string for missing headers."""
        headers = [{"name": "Subject", "value": "Test"}]
        assert gmail._extract_header(headers, "From") == ""

    def test_extract_text_body_direct_plain(self) -> None:
        """_extract_text_body extracts text/plain from a direct part."""
        payload = {
            "mimeType": "text/plain",
            "body": {"data": _b64_encode("Direct text")},
        }
        assert gmail._extract_text_body(payload) == "Direct text"

    def test_extract_text_body_multipart(self) -> None:
        """_extract_text_body recurses into multipart to find text/plain."""
        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                {"mimeType": "text/html", "body": {"data": _b64_encode("<p>html</p>")}},
                {"mimeType": "text/plain", "body": {"data": _b64_encode("plain text")}},
            ],
        }
        assert gmail._extract_text_body(payload) == "plain text"

    def test_extract_text_body_no_plain_returns_empty(self) -> None:
        """_extract_text_body returns empty string when no text/plain part exists."""
        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                {"mimeType": "text/html", "body": {"data": _b64_encode("<p>html</p>")}},
            ],
        }
        assert gmail._extract_text_body(payload) == ""

    def test_format_message_list_empty(self) -> None:
        """_format_message_list returns 'No messages found' for empty list."""
        assert gmail._format_message_list([]) == "No messages found."

    def test_format_api_error_with_json(self) -> None:
        """_format_api_error extracts code and message from error JSON."""
        resp = _make_response(403, {"error": {"code": 403, "message": "Forbidden"}})
        result = gmail._format_api_error(resp)
        assert "403" in result
        assert "Forbidden" in result

    def test_format_api_error_without_json(self) -> None:
        """_format_api_error falls back to status code."""
        resp = httpx.Response(status_code=500, content=b"not json")
        result = gmail._format_api_error(resp)
        assert "500" in result


# ---------------------------------------------------------------------------
# 7. gmail.send registration
# ---------------------------------------------------------------------------


class TestGmailSendRegistration:
    """Verify gmail.send is registered after import."""

    def test_gmail_send_registered(self) -> None:
        """gmail.send action is present in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("gmail", "send") in keys


# ---------------------------------------------------------------------------
# 8. gmail.send handler
# ---------------------------------------------------------------------------


class TestGmailSend:
    """Tests for the gmail.send handler."""

    async def test_send_happy_path(self, mock_http: AsyncMock) -> None:
        """Successful send returns confirmation with recipient and subject."""
        mock_http.post.return_value = _make_response(200, {"id": "sent123"})

        args = GmailSendArgs(
            to=["recipient@example.com"],
            subject="Test Email",
            body="Hello from test!",
        )
        result = await gmail.gmail_send(args)

        assert "sent" in result.lower()
        assert "recipient@example.com" in result
        assert "Test Email" in result

    async def test_send_oauth_error(self) -> None:
        """OAuthError from token retrieval returns setup instructions."""
        with patch.object(
            gmail, "_get_google_token", new_callable=AsyncMock, side_effect=OAuthError("no token")
        ):
            args = GmailSendArgs(
                to=["user@example.com"],
                subject="Hi",
                body="test",
            )
            result = await gmail.gmail_send(args)

        assert "OAuth error" in result
        assert "oauth_setup" not in result
        assert "python" not in result.lower()
        assert "Tools" in result

    async def test_send_api_error_non_200(self, mock_http: AsyncMock) -> None:
        """Non-200 status returns a formatted API error."""
        error_body = {"error": {"code": 400, "message": "Bad Request"}}
        mock_http.post.return_value = _make_response(400, error_body)

        args = GmailSendArgs(
            to=["user@example.com"],
            subject="Hi",
            body="test",
        )
        result = await gmail.gmail_send(args)

        assert "Google API error" in result

    async def test_send_http_connection_error(self) -> None:
        """httpx.ConnectError returns a friendly error message."""
        with patch.object(
            gmail, "_get_google_token", new_callable=AsyncMock, return_value=_FAKE_TOKEN
        ):
            client = AsyncMock(spec=httpx.AsyncClient)
            client.post.side_effect = httpx.ConnectError("connection refused")
            with patch.object(gmail, "_http_client", client):
                args = GmailSendArgs(
                    to=["user@example.com"],
                    subject="Hi",
                    body="test",
                )
                result = await gmail.gmail_send(args)

        assert "HTTP request failed" in result

    async def test_send_includes_cc_bcc(self, mock_http: AsyncMock) -> None:
        """When cc/bcc are provided, they appear in the RFC 2822 message body."""
        mock_http.post.return_value = _make_response(200, {"id": "sent456"})

        args = GmailSendArgs(
            to=["to@example.com"],
            cc=["cc@example.com"],
            bcc=["bcc@example.com"],
            subject="With CC",
            body="test body",
        )
        await gmail.gmail_send(args)

        # Inspect the raw POST body sent to the API (json={"raw": base64url_message})
        call_kwargs = mock_http.post.call_args
        post_json = call_kwargs.kwargs.get("json", {})
        raw_b64 = post_json["raw"]

        # Pad base64url and decode the RFC 2822 message
        padded = raw_b64 + "=" * (4 - len(raw_b64) % 4)
        raw_message = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        assert "cc@example.com" in raw_message
        assert "bcc@example.com" in raw_message

    async def test_send_response_omits_body_content(self, mock_http: AsyncMock) -> None:
        """Response summary does not include email body content (audit safety)."""
        mock_http.post.return_value = _make_response(200, {"id": "sent789"})

        body = "Sensitive medical information here"
        args = GmailSendArgs(
            to=["user@example.com"],
            subject="Long body",
            body=body,
        )
        result = await gmail.gmail_send(args)

        assert body not in result
        assert "Email sent to" in result


# ---------------------------------------------------------------------------
# 9. gmail.send argument validation
# ---------------------------------------------------------------------------


class TestGmailSendArgValidation:
    """Pydantic validation for GmailSendArgs."""

    def test_send_empty_to_rejected(self) -> None:
        """Empty recipient list is rejected."""
        with pytest.raises(ValidationError):
            GmailSendArgs(to=[], subject="Hi", body="test")

    def test_send_invalid_email_rejected(self) -> None:
        """Invalid email address is rejected."""
        with pytest.raises(ValidationError):
            GmailSendArgs(to=["not-an-email"], subject="Hi", body="test")

    def test_send_header_injection_email_rejected(self) -> None:
        """Email with CRLF header injection is rejected."""
        with pytest.raises(ValidationError):
            GmailSendArgs(to=["evil@test.com\r\nBcc: spam@evil.com"], subject="Hi", body="test")

    def test_send_too_many_recipients_rejected(self) -> None:
        """More than 20 recipients is rejected."""
        recipients = [f"user{i}@example.com" for i in range(21)]
        with pytest.raises(ValidationError):
            GmailSendArgs(to=recipients, subject="Hi", body="test")

    def test_send_subject_too_long_rejected(self) -> None:
        """Subject exceeding 500 chars is rejected."""
        with pytest.raises(ValidationError):
            GmailSendArgs(to=["user@example.com"], subject="x" * 501, body="test")

    def test_send_body_too_long_rejected(self) -> None:
        """Body exceeding 50000 chars is rejected."""
        with pytest.raises(ValidationError):
            GmailSendArgs(to=["user@example.com"], subject="Hi", body="x" * 50001)

    def test_send_valid_args_accepted(self) -> None:
        """Valid send arguments pass validation."""
        args = GmailSendArgs(
            to=["user@example.com"],
            subject="Hello",
            body="This is a test email.",
        )
        assert args.to == ["user@example.com"]
        assert args.subject == "Hello"

    def test_send_subject_with_crlf_rejected(self) -> None:
        """Subject containing CRLF is rejected (header injection prevention)."""
        with pytest.raises(ValidationError):
            GmailSendArgs(
                to=["user@example.com"],
                subject="Legit\r\nBcc: attacker@evil.com",
                body="test",
            )

    def test_send_body_with_null_byte_rejected(self) -> None:
        """Body containing null byte is rejected."""
        with pytest.raises(ValidationError):
            GmailSendArgs(
                to=["user@example.com"],
                subject="Hi",
                body="test\x00payload",
            )

    def test_send_empty_subject_allowed(self) -> None:
        """Empty subject is allowed."""
        args = GmailSendArgs(
            to=["user@example.com"],
            subject="",
            body="No subject email",
        )
        assert args.subject == ""
