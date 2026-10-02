"""Tests for the OneDrive tool (admino.tools.onedrive).

Covers tool registration, happy-path responses, OAuth error handling,
API error handling, empty results, and argument validation. All HTTP calls
are mocked. GH-143: onedrive.download is unregistered (its handler, helpers
and args model are deleted) until attachments restore it (#192).

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
from pathlib import Path
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
from admino.models import (
    OneDriveListArgs,
    OneDriveReadArgs,
    OneDriveSearchArgs,
)
from admino.oauth import OAuthError
from admino.tenancy import TenantContext
from admino.tools import onedrive as onedrive_mod
from admino.tools.registry import clear_registry, get_registered_tools, get_tool_entry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
    content: bytes | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response."""
    if content is not None:
        return httpx.Response(status_code=status_code, content=content)
    body = json.dumps(json_body or {}).encode()
    return httpx.Response(status_code=status_code, content=body)


def _sample_item(
    item_id: str = "item-1",
    name: str = "report.pdf",
    size: int = 1024,
    is_folder: bool = False,
) -> dict[str, Any]:
    """Build a sample Microsoft Graph drive item object."""
    item: dict[str, Any] = {
        "id": item_id,
        "name": name,
        "size": size,
        "lastModifiedDateTime": "2026-04-12T10:00:00Z",
        "createdDateTime": "2026-04-01T08:00:00Z",
        "webUrl": "https://onedrive.live.com/item/123",
    }
    if is_folder:
        item["folder"] = {"childCount": 3}
    else:
        item["file"] = {"mimeType": "application/pdf"}
    return item


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
        if hasattr(onedrive_mod, "get_pool"):
            stack.enter_context(patch.object(onedrive_mod, "get_pool", return_value=pool))
        yield


class _Api:
    """A mocked httpx.AsyncClient that answers every request with a plausible 2xx body.

    Logs each request's Authorization header under the calling task's ``_CALLER``.
    """

    def __init__(self) -> None:
        self.bearers: dict[str, list[str]] = {}
        self.client = AsyncMock(spec=httpx.AsyncClient)
        self.client.get.side_effect = self._answer(
            200, {**_sample_item(), "value": [_sample_item()]}
        )
        self.client.post.side_effect = self._answer(200, {})
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
    importlib.reload(onedrive_mod)
    yield
    clear_registry()


@pytest.fixture()
def mock_token() -> Generator[AsyncMock, None, None]:
    """Mock _get_microsoft_token to return a fake token."""
    with patch(
        "admino.tools.onedrive._get_microsoft_token",
        new_callable=AsyncMock,
        return_value="fake-token-789",
    ) as m:
        yield m


@pytest.fixture()
def mock_http_client() -> Generator[AsyncMock, None, None]:
    """Mock the module-level _http_client."""
    mock_client = AsyncMock()
    with patch("admino.tools.onedrive._http_client", mock_client):
        yield mock_client


# ---------------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------------


class TestOneDriveRegistration:
    """Verify tool actions are registered after import."""

    def test_read_registered(self) -> None:
        """onedrive.read is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("onedrive", "read") in keys

    def test_list_registered(self) -> None:
        """onedrive.list is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("onedrive", "list") in keys

    def test_search_registered(self) -> None:
        """onedrive.search is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("onedrive", "search") in keys

    def test_download_not_registered(self) -> None:
        """onedrive.download is NOT registered until attachments land (GH-143, #192)."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("onedrive", "download") not in keys
        assert get_tool_entry("onedrive", "download") is None

    def test_registers_exactly_read_list_search(self) -> None:
        """The module registers only read, list and search."""
        keys = {(t.tool, t.action) for t in get_registered_tools()}
        assert keys == {("onedrive", "read"), ("onedrive", "list"), ("onedrive", "search")}

    @pytest.mark.parametrize(
        "symbol",
        [
            "onedrive_download",
            "_sync_write_download",
            "_MAX_DOWNLOAD_SIZE",
            "_SAFE_REDIRECT_SUFFIXES",
        ],
    )
    def test_download_code_removed(self, symbol: str) -> None:
        """The download handler, its write helper and download-only constants are deleted."""
        assert not hasattr(onedrive_mod, symbol)

    def test_module_does_not_import_files_tool(self) -> None:
        """onedrive no longer depends on the removed files tool module."""
        import ast

        source = Path(onedrive_mod.__file__).read_text(encoding="utf-8")
        modules = {
            node.module
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        assert "admino.tools.files" not in modules


# ---------------------------------------------------------------------------
# 2. onedrive.read
# ---------------------------------------------------------------------------


class TestOneDriveRead:
    """Tests for the onedrive.read action."""

    async def test_read_happy_path_file(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Read returns formatted file metadata."""
        item = _sample_item()
        mock_http_client.get.return_value = _make_response(200, item)

        from admino.tools.onedrive import onedrive_read

        args = OneDriveReadArgs(item_id="item-1")
        result = await onedrive_read(args, tenant=_TENANT)

        assert "Name: report.pdf" in result
        assert "Type: file" in result
        assert "Web URL:" in result

    async def test_read_happy_path_folder(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Read returns 'folder' type for folder items."""
        item = _sample_item(name="Documents", is_folder=True)
        mock_http_client.get.return_value = _make_response(200, item)

        from admino.tools.onedrive import onedrive_read

        args = OneDriveReadArgs(item_id="item-1")
        result = await onedrive_read(args, tenant=_TENANT)

        assert "Type: folder" in result

    async def test_read_url_encodes_item_id(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Item IDs with special chars (= + / !) are percent-encoded into the path."""
        mock_http_client.get.return_value = _make_response(200, _sample_item())

        from admino.tools.onedrive import onedrive_read

        args = OneDriveReadArgs(item_id="i+/=d!x")
        await onedrive_read(args, tenant=_TENANT)

        called_url = mock_http_client.get.call_args.args[0]
        assert "i%2B%2F%3Dd%21x" in called_url
        assert "items/i+/=d!x" not in called_url

    async def test_read_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.onedrive._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.onedrive import onedrive_read

            args = OneDriveReadArgs(item_id="item-1")
            result = await onedrive_read(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_read_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 returns Graph error."""
        mock_http_client.get.return_value = _make_response(
            404, {"error": {"message": "Item not found"}}
        )

        from admino.tools.onedrive import onedrive_read

        args = OneDriveReadArgs(item_id="bad-id")
        result = await onedrive_read(args, tenant=_TENANT)

        assert "Microsoft Graph error" in result

    async def test_read_http_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """httpx.HTTPError returns connection failure."""
        mock_http_client.get.side_effect = httpx.ConnectError("fail")

        from admino.tools.onedrive import onedrive_read

        args = OneDriveReadArgs(item_id="item-1")
        result = await onedrive_read(args, tenant=_TENANT)

        assert "Failed to connect" in result


# ---------------------------------------------------------------------------
# 3. onedrive.list
# ---------------------------------------------------------------------------


class TestOneDriveList:
    """Tests for the onedrive.list action."""

    async def test_list_root_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """List root folder returns formatted items."""
        items = [
            _sample_item(item_id="i1", name="file1.txt"),
            _sample_item(item_id="i2", name="Photos", is_folder=True),
        ]
        mock_http_client.get.return_value = _make_response(200, {"value": items})

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs()  # folder_path=None means root
        result = await onedrive_list(args, tenant=_TENANT)

        assert "Name: file1.txt" in result
        assert "Name: Photos" in result
        assert "---" in result

    async def test_list_root_url_uses_root_children(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """When folder_path is None, URL uses /root/children (not /root:/ path form)."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs(folder_path=None)
        await onedrive_list(args, tenant=_TENANT)

        url = mock_http_client.get.call_args[0][0]
        assert "/me/drive/root/children" in url
        # Should NOT use the /root:/{path}:/children form
        assert "root:/" not in url

    async def test_list_root_top_passed_via_params_not_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Root listing passes $top in the params dict as an int, absent from URL."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs(folder_path=None, max_results=15)
        await onedrive_list(args, tenant=_TENANT)

        call_args = mock_http_client.get.call_args
        params = call_args.kwargs.get("params") or {}
        assert params["$top"] == 15
        assert "$top" not in call_args.args[0]

    async def test_list_subfolder_url_uses_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """When folder_path is set, URL uses /root:/{path}:/children."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs(folder_path="Documents/Work")
        await onedrive_list(args, tenant=_TENANT)

        url = mock_http_client.get.call_args[0][0]
        assert "/root:/Documents/Work:/children" in url

    async def test_list_subfolder_top_passed_via_params_not_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Subfolder listing passes $top in the params dict, absent from URL.

        The /root:/{path}:/children path fragment stays in the URL string.
        """
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs(folder_path="Documents/Work", max_results=12)
        await onedrive_list(args, tenant=_TENANT)

        call_args = mock_http_client.get.call_args
        params = call_args.kwargs.get("params") or {}
        assert params["$top"] == 12
        url = call_args.args[0]
        assert "$top" not in url
        assert "/root:/Documents/Work:/children" in url

    async def test_list_empty_results(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Empty list returns appropriate message."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs()
        result = await onedrive_list(args, tenant=_TENANT)

        assert "No items found" in result

    async def test_list_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.onedrive._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.onedrive import onedrive_list

            args = OneDriveListArgs()
            result = await onedrive_list(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_list_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 returns Graph error."""
        mock_http_client.get.return_value = _make_response(
            500, {"error": {"message": "Server error"}}
        )

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs()
        result = await onedrive_list(args, tenant=_TENANT)

        assert "Microsoft Graph error" in result


# ---------------------------------------------------------------------------
# 4. onedrive.search
# ---------------------------------------------------------------------------


class TestOneDriveSearch:
    """Tests for the onedrive.search action."""

    async def test_search_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Search returns formatted results."""
        items = [_sample_item(item_id="s1", name="budget.xlsx")]
        mock_http_client.get.return_value = _make_response(200, {"value": items})

        from admino.tools.onedrive import onedrive_search

        args = OneDriveSearchArgs(query="budget")
        result = await onedrive_search(args, tenant=_TENANT)

        assert "Name: budget.xlsx" in result

    async def test_search_empty_results(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Empty search returns appropriate message."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_search

        args = OneDriveSearchArgs(query="nonexistent")
        result = await onedrive_search(args, tenant=_TENANT)

        assert "No files found" in result

    async def test_search_url_contains_query(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Request URL includes the search query."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_search

        args = OneDriveSearchArgs(query="quarterly report")
        await onedrive_search(args, tenant=_TENANT)

        url = mock_http_client.get.call_args[0][0]
        assert "search(q='quarterly report')" in url

    async def test_search_top_passed_via_params_not_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Search passes $top in the params dict, absent from URL.

        The search(q='...') query fragment stays in the URL string.
        """
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_search

        args = OneDriveSearchArgs(query="budget", max_results=9)
        await onedrive_search(args, tenant=_TENANT)

        call_args = mock_http_client.get.call_args
        params = call_args.kwargs.get("params") or {}
        assert params["$top"] == 9
        url = call_args.args[0]
        assert "$top" not in url
        assert "search(q='budget')" in url

    async def test_search_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.onedrive._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.onedrive import onedrive_search

            args = OneDriveSearchArgs(query="test")
            result = await onedrive_search(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_search_api_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Non-200 returns Graph error."""
        mock_http_client.get.return_value = _make_response(
            403, {"error": {"message": "Access denied"}}
        )

        from admino.tools.onedrive import onedrive_search

        args = OneDriveSearchArgs(query="test")
        result = await onedrive_search(args, tenant=_TENANT)

        assert "Microsoft Graph error" in result


# ---------------------------------------------------------------------------
# 6. Argument validation
# ---------------------------------------------------------------------------


class TestOneDriveArgValidation:
    """Pydantic validation rejects invalid arguments."""

    def test_read_valid_item_id_accepted(self) -> None:
        """Valid item_id is accepted."""
        args = OneDriveReadArgs(item_id="abc123")
        assert args.item_id == "abc123"

    def test_read_graph_item_id_with_special_chars_accepted(self) -> None:
        """OneDrive item IDs (base64 + '!') are accepted."""
        iid = "01BYE5RZ=+/AAA!107"
        args = OneDriveReadArgs(item_id=iid)
        assert args.item_id == iid

    def test_read_item_id_with_dot_or_traversal_rejected(self) -> None:
        """IDs containing '.' (e.g. traversal sequences) are rejected."""
        with pytest.raises(ValidationError):
            OneDriveReadArgs(item_id="../secret")

    def test_read_item_id_leading_slash_rejected(self) -> None:
        """IDs beginning with '/' are rejected (defense-in-depth)."""
        with pytest.raises(ValidationError):
            OneDriveReadArgs(item_id="/etc/passwd")

    def test_read_overly_long_item_id_rejected(self) -> None:
        """item_id exceeding max_length (512) is rejected."""
        with pytest.raises(ValidationError):
            OneDriveReadArgs(item_id="x" * 513)

    def test_list_max_results_zero_rejected(self) -> None:
        """max_results=0 is rejected (ge=1)."""
        with pytest.raises(ValidationError):
            OneDriveListArgs(max_results=0)

    def test_list_max_results_over_limit_rejected(self) -> None:
        """max_results exceeding le=100 is rejected."""
        with pytest.raises(ValidationError):
            OneDriveListArgs(max_results=101)

    def test_search_valid_query_accepted(self) -> None:
        """Valid search query is accepted."""
        args = OneDriveSearchArgs(query="budget")
        assert args.query == "budget"

    def test_search_overly_long_query_rejected(self) -> None:
        """Query exceeding max_length is rejected."""
        with pytest.raises(ValidationError):
            OneDriveSearchArgs(query="x" * 501)

    def test_search_max_results_zero_rejected(self) -> None:
        """max_results=0 is rejected for search."""
        with pytest.raises(ValidationError):
            OneDriveSearchArgs(query="test", max_results=0)

    def test_list_default_max_results(self) -> None:
        """Default max_results is 20."""
        args = OneDriveListArgs()
        assert args.max_results == 20

    def test_list_default_folder_path_is_none(self) -> None:
        """Default folder_path is None (root)."""
        args = OneDriveListArgs()
        assert args.folder_path is None

    def test_search_default_max_results(self) -> None:
        """Default max_results is 10."""
        args = OneDriveSearchArgs(query="test")
        assert args.max_results == 10


# ---------------------------------------------------------------------------
# 7. Helper function: _human_readable_size
# ---------------------------------------------------------------------------


class TestHumanReadableSize:
    """Tests for the _human_readable_size helper."""

    def test_bytes(self) -> None:
        """Small values return bytes."""
        from admino.tools.onedrive import _human_readable_size

        assert _human_readable_size(500) == "500 B"

    def test_kilobytes(self) -> None:
        """Values >= 1024 return KB."""
        from admino.tools.onedrive import _human_readable_size

        result = _human_readable_size(2048)
        assert "KB" in result

    def test_megabytes(self) -> None:
        """Values >= 1MB return MB."""
        from admino.tools.onedrive import _human_readable_size

        result = _human_readable_size(5 * 1024 * 1024)
        assert "MB" in result

    def test_zero_bytes(self) -> None:
        """Zero bytes returns '0 B'."""
        from admino.tools.onedrive import _human_readable_size

        assert _human_readable_size(0) == "0 B"


# ---------------------------------------------------------------------------
# 8. Per-user tokens (GH-162)
# ---------------------------------------------------------------------------

_HANDLER_CASES = [
    pytest.param("onedrive_read", OneDriveReadArgs(item_id="item-1"), id="read"),
    pytest.param("onedrive_list", OneDriveListArgs(), id="list"),
    pytest.param("onedrive_search", OneDriveSearchArgs(query="budget"), id="search"),
]


class TestOneDrivePerUserTokens:
    """GH-162: every handler call loads and sends the token of its own tenant.

    The module keeps no token state of its own: ``_get_microsoft_token(tenant)`` reads the
    process-wide per-user cache (``oauth.access_tokens``), and the tenant always
    comes from the handler's server-side context, never from tool arguments.
    """

    @pytest.mark.parametrize("name", _REMOVED_TOKEN_STATE)
    def test_onedrive_module_level_token_state_removed(self, name: str) -> None:
        """The module-level token cache, its lock, its clear function and the old
        direct ``get_valid_access_token`` call are gone."""
        assert not hasattr(onedrive_mod, name)

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_onedrive_handler_without_tenant_raises_type_error(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """``tenant`` is a required keyword: no call runs without a tool context."""
        api = _Api()
        handler = getattr(onedrive_mod, handler_name)
        with (
            patch.object(onedrive_mod, "_http_client", api.client),
            pytest.raises(TypeError, match="tenant"),
        ):
            await handler(args)
        mock_token.assert_not_awaited()
        assert api.all_bearers() == []

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_onedrive_handler_loads_and_sends_token_of_its_tenant(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """Each action awaits ``_get_microsoft_token`` with the call's tenant and sends exactly
        the token it returned (extra context keywords such as session_id are accepted)."""
        api = _Api()
        handler = getattr(onedrive_mod, handler_name)
        with patch.object(onedrive_mod, "_http_client", api.client):
            await handler(args, session_id="sess-1", tenant=_TENANT_B)
        _assert_token_loaded_for(mock_token, _TENANT_B)
        assert api.all_bearers()
        assert set(api.all_bearers()) == {f"Bearer {mock_token.return_value}"}

    async def test_onedrive_get_token_reads_shared_per_user_cache(self) -> None:
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
            patch.object(onedrive_mod, "_http_client", client),
        ):
            tokens = [
                await onedrive_mod._get_microsoft_token(_TENANT),
                await onedrive_mod._get_microsoft_token(_TENANT_B),
                await onedrive_mod._get_microsoft_token(_TENANT),
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

    async def test_onedrive_concurrent_users_each_request_carries_own_token(
        self, mock_token: AsyncMock
    ) -> None:
        """User A's token is never sent for user B: B's whole call runs while A's
        token load is still pending, and every request carries its own caller's token."""
        users = _TwoUsers()
        mock_token.side_effect = users.token_for
        api = _Api()
        with patch.object(onedrive_mod, "_http_client", api.client):
            result_a, result_b = await users.run(
                lambda: onedrive_mod.onedrive_list(OneDriveListArgs(), tenant=_TENANT),
                lambda: onedrive_mod.onedrive_list(OneDriveListArgs(), tenant=_TENANT_B),
            )

        _assert_bearers_isolated(api)
        assert "report.pdf" in result_a
        assert "report.pdf" in result_b

    async def test_onedrive_shared_cache_never_serves_one_users_token_to_another(self) -> None:
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
                patch.object(onedrive_mod, "_http_client", api.client),
            ):
                await users.run(
                    lambda: onedrive_mod.onedrive_list(OneDriveListArgs(), tenant=_TENANT),
                    lambda: onedrive_mod.onedrive_list(OneDriveListArgs(), tenant=_TENANT_B),
                )
                await _call_as(
                    "A", lambda: onedrive_mod.onedrive_list(OneDriveListArgs(), tenant=_TENANT)
                )
                await _call_as(
                    "B", lambda: onedrive_mod.onedrive_list(OneDriveListArgs(), tenant=_TENANT_B)
                )
        finally:
            oauth.access_tokens.clear()

        _assert_bearers_isolated(api)
        own: dict[object, str] = {_USER_A_ID: _TOKEN_A, _USER_B_ID: _TOKEN_B}
        assert {user for user, _, _ in users.refreshes} == {_USER_A_ID, _USER_B_ID}
        assert all(provider == "microsoft" for _, provider, _ in users.refreshes)
        assert all(cached in (None, own[user]) for user, _, cached in users.refreshes)
