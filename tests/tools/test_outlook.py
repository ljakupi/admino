"""Tests for the Outlook mail tool (admino.tools.outlook).

Covers tool registration, happy-path responses, OAuth error handling,
API error handling, empty results, body truncation, and argument validation.
All HTTP calls are mocked; no real API calls are made.

GH-162: every handler takes the caller's ``TenantContext`` as a required
``tenant`` keyword and loads that user's token through the shared per-user
cache (``oauth.access_tokens``); the module keeps no token state of its own.

Security notes: user A's access token is never sent on user B's requests,
including under concurrent calls (the concurrency tests interleave two users'
calls on purpose). Fake tokens only; no real API requests are made.
"""

from __future__ import annotations

import asyncio
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
from admino.models import OutlookListArgs, OutlookReadArgs, OutlookSearchArgs, OutlookSendArgs
from admino.oauth import OAuthError
from admino.tenancy import TenantContext
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
        if hasattr(outlook_mod, "get_pool"):
            stack.enter_context(patch.object(outlook_mod, "get_pool", return_value=pool))
        yield


class _Api:
    """A mocked httpx.AsyncClient that answers every request with a plausible 2xx body.

    Logs each request's Authorization header under the calling task's ``_CALLER``.
    """

    def __init__(self) -> None:
        self.bearers: dict[str, list[str]] = {}
        self.client = AsyncMock(spec=httpx.AsyncClient)
        self.client.get.side_effect = self._answer(
            200, {**_sample_message(), "value": [_sample_message()]}
        )
        self.client.post.side_effect = self._answer(202, None)
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
        result = await outlook_read(args, tenant=_TENANT)

        assert "Subject: Test Subject" in result
        assert "From: sender@example.com" in result
        assert "Body:\nHello world" in result

    async def test_read_url_encodes_message_id(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Graph message IDs (base64: = + /) are percent-encoded into the path."""
        mock_http_client.get.return_value = _make_response(200, _sample_message())

        from admino.tools.outlook import outlook_read

        args = OutlookReadArgs(message_id="AA+/=BB")
        await outlook_read(args, tenant=_TENANT)

        called_url = mock_http_client.get.call_args.args[0]
        assert "AA%2B%2F%3DBB" in called_url
        assert "/messages/AA+/=BB" not in called_url

    async def test_read_oauth_not_configured(self) -> None:
        """When OAuth is not configured, returns setup instructions."""
        with patch(
            "admino.tools.outlook._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook import outlook_read

            args = OutlookReadArgs(message_id="msg-1")
            result = await outlook_read(args, tenant=_TENANT)

        assert "OAuth error" in result
        assert "python" not in result.lower()
        assert "Tools" in result

    async def test_read_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 response returns Graph error message."""
        error_body = {"error": {"message": "Item not found"}}
        mock_http_client.get.return_value = _make_response(404, error_body)

        from admino.tools.outlook import outlook_read

        args = OutlookReadArgs(message_id="bad-id")
        result = await outlook_read(args, tenant=_TENANT)

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
        result = await outlook_read(args, tenant=_TENANT)

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
        result = await outlook_read(args, tenant=_TENANT)

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
        result = await outlook_list(args, tenant=_TENANT)

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
        result = await outlook_list(args, tenant=_TENANT)

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
            result = await outlook_list(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_list_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 status returns Graph error."""
        mock_http_client.get.return_value = _make_response(
            403, {"error": {"message": "Access denied"}}
        )

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=10)
        result = await outlook_list(args, tenant=_TENANT)

        assert "Microsoft Graph error" in result
        assert "Access denied" in result

    async def test_list_top_passed_via_params_not_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """$top is passed in the httpx params dict as an int, not in the URL string."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=5)
        await outlook_list(args, tenant=_TENANT)

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
        await outlook_list(args, tenant=_TENANT)

        url = mock_http_client.get.call_args.args[0]
        assert "$top" not in url

    async def test_list_orderby_passed_via_params(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """$orderby is passed in the params dict and orders by receivedDateTime."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_list

        args = OutlookListArgs(max_results=5)
        await outlook_list(args, tenant=_TENANT)

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
        result = await outlook_search(args, tenant=_TENANT)

        assert "Subject: Match" in result

    async def test_search_empty_results(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Empty search results return appropriate message."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook import outlook_search

        args = OutlookSearchArgs(query="nonexistent")
        result = await outlook_search(args, tenant=_TENANT)

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
        await outlook_search(args, tenant=_TENANT)

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
        await outlook_search(args, tenant=_TENANT)

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
            result = await outlook_search(args, tenant=_TENANT)

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
        result = await outlook_search(args, tenant=_TENANT)

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

    def test_read_graph_message_id_with_special_chars_accepted(self) -> None:
        """Base64 Graph message IDs (containing = + /) are accepted."""
        mid = "AAMkAGI2TG93AAA=+/xYz"
        args = OutlookReadArgs(message_id=mid)
        assert args.message_id == mid

    def test_read_message_id_with_dot_or_traversal_rejected(self) -> None:
        """IDs containing '.' (e.g. traversal sequences) are rejected."""
        with pytest.raises(ValidationError):
            OutlookReadArgs(message_id="../secret")

    def test_read_message_id_with_space_rejected(self) -> None:
        """IDs containing spaces or control chars are rejected."""
        with pytest.raises(ValidationError):
            OutlookReadArgs(message_id="bad id")

    def test_read_message_id_leading_slash_rejected(self) -> None:
        """IDs beginning with '/' are rejected (defense-in-depth)."""
        with pytest.raises(ValidationError):
            OutlookReadArgs(message_id="/etc/passwd")

    def test_read_overly_long_message_id_rejected(self) -> None:
        """message_id exceeding max_length (512) is rejected."""
        with pytest.raises(ValidationError):
            OutlookReadArgs(message_id="x" * 513)

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
        result = await outlook_send(args, tenant=_TENANT)

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
            result = await outlook_send(args, tenant=_TENANT)

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
        result = await outlook_send(args, tenant=_TENANT)

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
        result = await outlook_send(args, tenant=_TENANT)

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
        await outlook_send(args, tenant=_TENANT)

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
        result = await outlook_send(args, tenant=_TENANT)

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


# ---------------------------------------------------------------------------
# 9. Per-user tokens (GH-162)
# ---------------------------------------------------------------------------

_HANDLER_CASES = [
    pytest.param("outlook_read", OutlookReadArgs(message_id="msg-1"), id="read"),
    pytest.param("outlook_list", OutlookListArgs(), id="list"),
    pytest.param("outlook_search", OutlookSearchArgs(query="budget"), id="search"),
    pytest.param(
        "outlook_send",
        OutlookSendArgs(to=["user@example.com"], subject="Hi", body="test"),
        id="send",
    ),
]


class TestOutlookPerUserTokens:
    """GH-162: every handler call loads and sends the token of its own tenant.

    The module keeps no token state of its own: ``_get_microsoft_token(tenant)`` reads the
    process-wide per-user cache (``oauth.access_tokens``), and the tenant always
    comes from the handler's server-side context, never from tool arguments.
    """

    @pytest.mark.parametrize("name", _REMOVED_TOKEN_STATE)
    def test_outlook_module_level_token_state_removed(self, name: str) -> None:
        """The module-level token cache, its lock, its clear function and the old
        direct ``get_valid_access_token`` call are gone."""
        assert not hasattr(outlook_mod, name)

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_outlook_handler_without_tenant_raises_type_error(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """``tenant`` is a required keyword: no call runs without a tool context."""
        api = _Api()
        handler = getattr(outlook_mod, handler_name)
        with (
            patch.object(outlook_mod, "_http_client", api.client),
            pytest.raises(TypeError, match="tenant"),
        ):
            await handler(args)
        mock_token.assert_not_awaited()
        assert api.all_bearers() == []

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_outlook_handler_loads_and_sends_token_of_its_tenant(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """Each action awaits ``_get_microsoft_token`` with the call's tenant and sends exactly
        the token it returned (extra context keywords such as session_id are accepted)."""
        api = _Api()
        handler = getattr(outlook_mod, handler_name)
        with patch.object(outlook_mod, "_http_client", api.client):
            await handler(args, session_id="sess-1", tenant=_TENANT_B)
        _assert_token_loaded_for(mock_token, _TENANT_B)
        assert api.all_bearers()
        assert set(api.all_bearers()) == {f"Bearer {mock_token.return_value}"}

    async def test_outlook_get_token_reads_shared_per_user_cache(self) -> None:
        """``_get_microsoft_token(tenant)`` returns
        ``await oauth.access_tokens.get(get_pool(), tenant, "microsoft", <module http client>)``,
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
            patch.object(outlook_mod, "_http_client", client),
        ):
            tokens = [
                await outlook_mod._get_microsoft_token(_TENANT),
                await outlook_mod._get_microsoft_token(_TENANT_B),
                await outlook_mod._get_microsoft_token(_TENANT),
            ]

        assert tokens == [
            f"cached-token-of-{_USER_A_ID}",
            f"cached-token-of-{_USER_B_ID}",
            f"cached-token-of-{_USER_A_ID}",
        ]
        calls = [_cache_get_arguments(c.args, c.kwargs) for c in cache_get.await_args_list]
        assert calls == [
            {"pool": pool, "tenant": _TENANT, "provider": "microsoft", "http_client": client},
            {"pool": pool, "tenant": _TENANT_B, "provider": "microsoft", "http_client": client},
            {"pool": pool, "tenant": _TENANT, "provider": "microsoft", "http_client": client},
        ]

    async def test_outlook_concurrent_users_each_request_carries_own_token(
        self, mock_token: AsyncMock
    ) -> None:
        """User A's token is never sent for user B: B's whole call runs while A's
        token load is still pending, and every request carries its own caller's token."""
        users = _TwoUsers()
        mock_token.side_effect = users.token_for
        api = _Api()
        with patch.object(outlook_mod, "_http_client", api.client):
            result_a, result_b = await users.run(
                lambda: outlook_mod.outlook_list(OutlookListArgs(), tenant=_TENANT),
                lambda: outlook_mod.outlook_list(OutlookListArgs(), tenant=_TENANT_B),
            )

        _assert_bearers_isolated(api)
        assert "Test Subject" in result_a
        assert "Test Subject" in result_b

    async def test_outlook_shared_cache_never_serves_one_users_token_to_another(self) -> None:
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
                patch.object(outlook_mod, "_http_client", api.client),
            ):
                await users.run(
                    lambda: outlook_mod.outlook_list(OutlookListArgs(), tenant=_TENANT),
                    lambda: outlook_mod.outlook_list(OutlookListArgs(), tenant=_TENANT_B),
                )
                await _call_as(
                    "A", lambda: outlook_mod.outlook_list(OutlookListArgs(), tenant=_TENANT)
                )
                await _call_as(
                    "B", lambda: outlook_mod.outlook_list(OutlookListArgs(), tenant=_TENANT_B)
                )
        finally:
            oauth.access_tokens.clear()

        _assert_bearers_isolated(api)
        own: dict[object, str] = {_USER_A_ID: _TOKEN_A, _USER_B_ID: _TOKEN_B}
        assert {user for user, _, _ in users.refreshes} == {_USER_A_ID, _USER_B_ID}
        assert all(provider == "microsoft" for _, provider, _ in users.refreshes)
        assert all(cached in (None, own[user]) for user, _, cached in users.refreshes)
