"""Tests for the Gmail tool module (admino.tools.gmail).

Covers tool registration, happy-path responses, OAuth errors, API errors,
empty results, body truncation, base64 decoding, and argument validation.
All HTTP calls are mocked -- no real API requests are made.

GH-162: every handler takes the caller's ``TenantContext`` as a required
``tenant`` keyword and loads that user's token through the shared per-user
cache (``oauth.access_tokens``); the module keeps no token state of its own.

Security notes: user A's access token is never sent on user B's requests,
including under concurrent calls (the concurrency tests interleave two users'
calls on purpose). Fake tokens only; no real API requests are made.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Iterator

    from pydantic import BaseModel

from admino.access import Principal
from admino.models import GmailListArgs, GmailReadArgs, GmailSearchArgs, GmailSendArgs
from admino.oauth import OAuthError
from admino.tenancy import TenantContext
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
# Per-user token helpers (GH-162)
# ---------------------------------------------------------------------------

_ORG_ID = UUID("00000000-0000-4000-8000-0000000000a1")
_USER_A_ID = UUID("00000000-0000-4000-8000-00000000000a")
_USER_B_ID = UUID("00000000-0000-4000-8000-00000000000b")
_TOKEN_A = "access-token-of-user-a"
_TOKEN_B = "access-token-of-user-b"

# The module-level token state GH-162 replaces with the shared per-user cache.
_REMOVED_TOKEN_STATE = (
    "_cached_token",
    "_cached_expires_at",
    "_token_lock",
    "clear_token_cache",
    "get_valid_access_token",
)

# Which concurrent handler call a request belongs to (each gather task has its own copy).
_CALLER: ContextVar[str] = ContextVar("_CALLER", default="none")


def _tenant_for(user_id: UUID) -> TenantContext:
    """An editor's tool context in the shared test organization."""
    return TenantContext.from_principal(
        Principal(user_id=user_id, kind="member", org_id=_ORG_ID, role="editor")
    )


_TENANT = _tenant_for(_USER_A_ID)
_TENANT_B = _tenant_for(_USER_B_ID)


def _tenant_arg(args: tuple[object, ...], kwargs: dict[str, object]) -> object:
    """The tenant a token getter was awaited with (positional or keyword)."""
    return args[0] if args else kwargs.get("tenant")


def _assert_token_loaded_for(mock_token: AsyncMock, tenant: TenantContext) -> None:
    """The token getter ran, and only ever for ``tenant``."""
    assert mock_token.await_count >= 1
    assert all(_tenant_arg(c.args, c.kwargs) == tenant for c in mock_token.await_args_list)


def _cache_get_arguments(args: tuple[object, ...], kwargs: dict[str, object]) -> dict[str, object]:
    """Bind one ``oauth.access_tokens.get`` call to the contract's parameter names."""

    def contract(pool: object, tenant: object, provider: object, http_client: object) -> None:
        """AccessTokenCache.get(pool, tenant, provider, http_client), without self."""

    return dict(inspect.signature(contract).bind(*args, **kwargs).arguments)


@contextmanager
def _pool_patched(pool: object) -> Iterator[None]:
    """Make ``get_pool()`` return ``pool`` however the tool module imports it."""
    with ExitStack() as stack:
        stack.enter_context(patch("admino.database.get_pool", return_value=pool))
        if hasattr(gmail, "get_pool"):
            stack.enter_context(patch.object(gmail, "get_pool", return_value=pool))
        yield


class _Api:
    """A mocked httpx.AsyncClient that answers every request with a plausible 2xx body.

    Logs each request's Authorization header under the calling task's ``_CALLER``.
    """

    def __init__(self) -> None:
        self.bearers: dict[str, list[str]] = {}
        self.client = AsyncMock(spec=httpx.AsyncClient)
        self.client.get.side_effect = self._answer(
            200, {**_message_payload(), "messages": [{"id": "m1"}, {"id": "m2"}]}
        )
        self.client.post.side_effect = self._answer(200, {"id": "sent1"})
        self.client.patch.side_effect = self._answer(200, {})

    def _answer(
        self, status: int, body: dict[str, Any] | None
    ) -> Callable[..., Awaitable[httpx.Response]]:
        async def answer(url: str, *args: object, **kwargs: object) -> httpx.Response:
            headers = kwargs.get("headers")
            bearer = headers.get("Authorization") if isinstance(headers, dict) else None
            self.bearers.setdefault(_CALLER.get(), []).append(str(bearer))
            return _make_response(status, body)

        return answer

    def all_bearers(self) -> list[str]:
        """Every request's Authorization header, whoever made it."""
        return [bearer for bearers in self.bearers.values() for bearer in bearers]


class _TwoUsers:
    """User A's and user B's handler calls, interleaved so B runs entirely inside A's.

    A's token load waits until B's whole call has finished; each user gets their
    own token. ``refresh`` stands in for ``oauth.get_valid_access_token`` behind
    the real shared cache and records what the cache handed it.
    """

    def __init__(self) -> None:
        self.b_done = asyncio.Event()
        self.refreshes: list[tuple[object, object, object]] = []

    async def token_for(self, *args: object, **kwargs: object) -> str:
        """The caller's own token (A's load blocks until B is done)."""
        user_id = getattr(_tenant_arg(args, kwargs), "user_id", None)
        if user_id == _USER_A_ID:
            await self.b_done.wait()
            return _TOKEN_A
        if user_id == _USER_B_ID:
            return _TOKEN_B
        return "access-token-of-nobody"

    async def refresh(
        self,
        pool: object,
        tenant: object,
        provider: object,
        cached_token: object,
        cached_expires_at: object,
        http_client: object,
    ) -> tuple[str, datetime]:
        """Stand-in for get_valid_access_token: the tenant's own token, valid 1 h."""
        self.refreshes.append((getattr(tenant, "user_id", None), provider, cached_token))
        return await self.token_for(tenant), datetime.now(UTC) + timedelta(hours=1)

    async def run(
        self,
        call_a: Callable[[], Awaitable[str]],
        call_b: Callable[[], Awaitable[str]],
    ) -> tuple[str, str]:
        """Run both calls concurrently; a call that waits on the other one times out."""

        async def as_a() -> str:
            _CALLER.set("A")
            return await call_a()

        async def as_b() -> str:
            _CALLER.set("B")
            try:
                return await call_b()
            finally:
                self.b_done.set()

        result_a, result_b = await asyncio.wait_for(asyncio.gather(as_a(), as_b()), timeout=5)
        return result_a, result_b


async def _call_as(caller: str, call: Callable[[], Awaitable[str]]) -> str:
    """Run one handler call with its requests logged under ``caller``."""
    reset_token = _CALLER.set(caller)
    try:
        return await call()
    finally:
        _CALLER.reset(reset_token)


def _assert_bearers_isolated(api: _Api) -> None:
    """Every request of A's calls carried A's token; every request of B's, B's token."""
    assert api.bearers.get("A"), "user A's call made no API request"
    assert api.bearers.get("B"), "user B's call made no API request"
    assert set(api.bearers["A"]) == {f"Bearer {_TOKEN_A}"}
    assert set(api.bearers["B"]) == {f"Bearer {_TOKEN_B}"}


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
        result = await gmail.gmail_read(args, tenant=_TENANT)

        assert "Subject: Test Subject" in result
        assert "From: alice@example.com" in result
        assert "Hello from test!" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError from token retrieval returns setup instructions."""
        with patch.object(
            gmail, "_get_google_token", new_callable=AsyncMock, side_effect=OAuthError("no token")
        ):
            args = GmailReadArgs(message_id="msg123")
            result = await gmail.gmail_read(args, tenant=_TENANT)

        assert "OAuth error" in result
        assert "python" not in result.lower()
        assert "Tools" in result

    async def test_api_error_non_200(self, mock_http: AsyncMock) -> None:
        """Non-200 status returns a formatted API error."""
        error_body = {"error": {"code": 404, "message": "Not Found"}}
        mock_http.get.return_value = _make_response(404, error_body)

        args = GmailReadArgs(message_id="msg123")
        result = await gmail.gmail_read(args, tenant=_TENANT)

        assert "Google API error 404" in result

    async def test_body_truncation_at_limit(self, mock_http: AsyncMock) -> None:
        """Body exceeding 10000 chars is truncated."""
        long_body = "x" * 15000
        payload = _message_payload(body_text=long_body)
        mock_http.get.return_value = _make_response(200, payload)

        args = GmailReadArgs(message_id="msg123")
        result = await gmail.gmail_read(args, tenant=_TENANT)

        assert "Truncated at 10000 characters" in result

    async def test_base64_decoded_body(self, mock_http: AsyncMock) -> None:
        """Body part is correctly base64-decoded."""
        original = "Decoded content with special chars: ae oe ue"
        payload = _message_payload(body_text=original)
        mock_http.get.return_value = _make_response(200, payload)

        args = GmailReadArgs(message_id="msg123")
        result = await gmail.gmail_read(args, tenant=_TENANT)

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
                result = await gmail.gmail_read(args, tenant=_TENANT)

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
        result = await gmail.gmail_list(args, tenant=_TENANT)

        assert "Subject 1" in result
        assert "Subject 2" in result
        assert "bob@example.com" in result

    async def test_empty_messages_list(self, mock_http: AsyncMock) -> None:
        """Empty messages list returns appropriate message."""
        mock_http.get.return_value = _make_response(200, {"messages": []})

        args = GmailListArgs(max_results=10)
        result = await gmail.gmail_list(args, tenant=_TENANT)

        assert "No messages found" in result

    async def test_no_messages_key(self, mock_http: AsyncMock) -> None:
        """Response without messages key returns no-messages message."""
        mock_http.get.return_value = _make_response(200, {})

        args = GmailListArgs(max_results=10)
        result = await gmail.gmail_list(args, tenant=_TENANT)

        assert "No messages found" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 on list call returns API error."""
        mock_http.get.return_value = _make_response(
            403, {"error": {"code": 403, "message": "Forbidden"}}
        )

        args = GmailListArgs(max_results=5)
        result = await gmail.gmail_list(args, tenant=_TENANT)

        assert "Google API error 403" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            gmail, "_get_google_token", new_callable=AsyncMock, side_effect=OAuthError("no token")
        ):
            args = GmailListArgs(max_results=5)
            result = await gmail.gmail_list(args, tenant=_TENANT)

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
        result = await gmail.gmail_search(args, tenant=_TENANT)

        assert "Invoice from SBB" in result

    async def test_search_query_passed_to_api(self, mock_http: AsyncMock) -> None:
        """The search query is forwarded as the q param."""
        mock_http.get.return_value = _make_response(200, {"messages": []})

        args = GmailSearchArgs(query="is:unread from:boss")
        await gmail.gmail_search(args, tenant=_TENANT)

        call_kwargs = mock_http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert params.get("q") == "is:unread from:boss"

    async def test_no_matching_messages(self, mock_http: AsyncMock) -> None:
        """Empty search results return appropriate message."""
        mock_http.get.return_value = _make_response(200, {"messages": []})

        args = GmailSearchArgs(query="nonexistent-query")
        result = await gmail.gmail_search(args, tenant=_TENANT)

        assert "No messages found matching" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            gmail, "_get_google_token", new_callable=AsyncMock, side_effect=OAuthError("no token")
        ):
            args = GmailSearchArgs(query="test")
            result = await gmail.gmail_search(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 on search call returns API error."""
        mock_http.get.return_value = _make_response(
            500, {"error": {"code": 500, "message": "Internal"}}
        )

        args = GmailSearchArgs(query="test")
        result = await gmail.gmail_search(args, tenant=_TENANT)

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
        result = await gmail.gmail_send(args, tenant=_TENANT)

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
            result = await gmail.gmail_send(args, tenant=_TENANT)

        assert "OAuth error" in result
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
        result = await gmail.gmail_send(args, tenant=_TENANT)

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
                result = await gmail.gmail_send(args, tenant=_TENANT)

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
        await gmail.gmail_send(args, tenant=_TENANT)

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
        result = await gmail.gmail_send(args, tenant=_TENANT)

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


# ---------------------------------------------------------------------------
# 10. Per-user tokens (GH-162)
# ---------------------------------------------------------------------------

_HANDLER_CASES = [
    pytest.param("gmail_read", GmailReadArgs(message_id="msg123"), id="read"),
    pytest.param("gmail_list", GmailListArgs(max_results=10), id="list"),
    pytest.param("gmail_search", GmailSearchArgs(query="from:boss"), id="search"),
    pytest.param(
        "gmail_send", GmailSendArgs(to=["user@example.com"], subject="Hi", body="test"), id="send"
    ),
]


class TestGmailPerUserTokens:
    """GH-162: every handler call loads and sends the token of its own tenant.

    The module keeps no token state of its own: ``_get_google_token(tenant)`` reads the
    process-wide per-user cache (``oauth.access_tokens``), and the tenant always
    comes from the handler's server-side context, never from tool arguments.
    """

    @pytest.mark.parametrize("name", _REMOVED_TOKEN_STATE)
    def test_gmail_module_level_token_state_removed(self, name: str) -> None:
        """The module-level token cache, its lock, its clear function and the old
        direct ``get_valid_access_token`` call are gone."""
        assert not hasattr(gmail, name)

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_gmail_handler_without_tenant_raises_type_error(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """``tenant`` is a required keyword: no call runs without a tool context."""
        api = _Api()
        handler = getattr(gmail, handler_name)
        with (
            patch.object(gmail, "_http_client", api.client),
            pytest.raises(TypeError, match="tenant"),
        ):
            await handler(args)
        mock_token.assert_not_awaited()
        assert api.all_bearers() == []

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_gmail_handler_loads_and_sends_token_of_its_tenant(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """Each action awaits ``_get_google_token`` with the call's tenant and sends exactly
        the token it returned (extra context keywords such as session_id are accepted)."""
        api = _Api()
        handler = getattr(gmail, handler_name)
        with patch.object(gmail, "_http_client", api.client):
            await handler(args, session_id="sess-1", tenant=_TENANT_B)
        _assert_token_loaded_for(mock_token, _TENANT_B)
        assert api.all_bearers()
        assert set(api.all_bearers()) == {f"Bearer {mock_token.return_value}"}

    async def test_gmail_get_token_reads_shared_per_user_cache(self) -> None:
        """``_get_google_token(tenant)`` returns
        ``await oauth.access_tokens.get(get_pool(), tenant, "google", <module http client>)``,
        per call and per tenant (no module-level memo)."""
        from admino import oauth

        pool = object()
        client = AsyncMock(spec=httpx.AsyncClient)

        async def per_user(*args: object, **kwargs: object) -> str:
            tenant = _cache_get_arguments(args, kwargs)["tenant"]
            return f"cached-token-of-{getattr(tenant, 'user_id', None)}"

        with (
            patch.object(
                oauth.access_tokens, "get", new_callable=AsyncMock, side_effect=per_user
            ) as cache_get,
            _pool_patched(pool),
            patch.object(gmail, "_http_client", client),
        ):
            tokens = [
                await gmail._get_google_token(_TENANT),
                await gmail._get_google_token(_TENANT_B),
                await gmail._get_google_token(_TENANT),
            ]

        assert tokens == [
            f"cached-token-of-{_USER_A_ID}",
            f"cached-token-of-{_USER_B_ID}",
            f"cached-token-of-{_USER_A_ID}",
        ]
        calls = [_cache_get_arguments(c.args, c.kwargs) for c in cache_get.await_args_list]
        assert calls == [
            {"pool": pool, "tenant": _TENANT, "provider": "google", "http_client": client},
            {"pool": pool, "tenant": _TENANT_B, "provider": "google", "http_client": client},
            {"pool": pool, "tenant": _TENANT, "provider": "google", "http_client": client},
        ]

    async def test_gmail_concurrent_users_each_request_carries_own_token(
        self, mock_token: AsyncMock
    ) -> None:
        """User A's token is never sent for user B: B's whole call runs while A's
        token load is still pending, and every request carries its own caller's token."""
        users = _TwoUsers()
        mock_token.side_effect = users.token_for
        api = _Api()
        with patch.object(gmail, "_http_client", api.client):
            result_a, result_b = await users.run(
                lambda: gmail.gmail_list(GmailListArgs(max_results=10), tenant=_TENANT),
                lambda: gmail.gmail_list(GmailListArgs(max_results=10), tenant=_TENANT_B),
            )

        _assert_bearers_isolated(api)
        assert "Test Subject" in result_a
        assert "Test Subject" in result_b

    async def test_gmail_shared_cache_never_serves_one_users_token_to_another(self) -> None:
        """Through the real per-user cache (only the refresh is faked): concurrent calls
        don't wait on each other, repeated calls keep each user's token, and the cache
        never hands one user's cached token to the other user's refresh."""
        from admino import oauth

        users = _TwoUsers()
        api = _Api()
        oauth.access_tokens.clear()
        try:
            with (
                patch("admino.oauth.get_valid_access_token", new=users.refresh),
                _pool_patched(object()),
                patch.object(gmail, "_http_client", api.client),
            ):
                await users.run(
                    lambda: gmail.gmail_list(GmailListArgs(max_results=10), tenant=_TENANT),
                    lambda: gmail.gmail_list(GmailListArgs(max_results=10), tenant=_TENANT_B),
                )
                await _call_as(
                    "A", lambda: gmail.gmail_list(GmailListArgs(max_results=10), tenant=_TENANT)
                )
                await _call_as(
                    "B", lambda: gmail.gmail_list(GmailListArgs(max_results=10), tenant=_TENANT_B)
                )
        finally:
            oauth.access_tokens.clear()

        _assert_bearers_isolated(api)
        own: dict[object, str] = {_USER_A_ID: _TOKEN_A, _USER_B_ID: _TOKEN_B}
        assert {user for user, _, _ in users.refreshes} == {_USER_A_ID, _USER_B_ID}
        assert all(provider == "google" for _, provider, _ in users.refreshes)
        assert all(cached in (None, own[user]) for user, _, cached in users.refreshes)
