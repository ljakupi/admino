"""Tests for the Google Drive tool module (admino.tools.google_drive).

Covers tool registration, happy-path responses, OAuth errors, API errors,
empty results, and argument validation. GH-143: google_drive.download is
unregistered (its handler, helpers and args model are deleted) until
attachments restore it (#192).
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
from admino.models import (
    GoogleDriveListArgs,
    GoogleDriveReadArgs,
    GoogleDriveSearchArgs,
)
from admino.oauth import OAuthError
from admino.tenancy import TenantContext
from admino.tools import google_drive
from admino.tools.registry import clear_registry, get_registered_tools, get_tool_entry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_TOKEN = "fake-access-token-drive"


def _make_response(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
    content: bytes | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response."""
    if content is not None:
        resp = httpx.Response(status_code=status_code, content=content)
        return resp
    body = json.dumps(json_body or {}).encode()
    return httpx.Response(status_code=status_code, content=body)


def _sample_file(
    file_id: str = "file123",
    name: str = "document.pdf",
    mime_type: str = "application/pdf",
    size: str = "1024",
    modified_time: str = "2026-04-12T08:00:00Z",
) -> dict[str, str]:
    """Build a Drive file resource dict."""
    return {
        "id": file_id,
        "name": name,
        "mimeType": mime_type,
        "size": size,
        "modifiedTime": modified_time,
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
        if hasattr(google_drive, "get_pool"):
            stack.enter_context(patch.object(google_drive, "get_pool", return_value=pool))
        yield


class _Api:
    """A mocked httpx.AsyncClient that answers every request with a plausible 2xx body.

    Logs each request's Authorization header under the calling task's ``_CALLER``.
    """

    def __init__(self) -> None:
        self.bearers: dict[str, list[str]] = {}
        self.client = AsyncMock(spec=httpx.AsyncClient)
        self.client.get.side_effect = self._answer(
            200, {**_sample_file(), "files": [_sample_file()]}
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
    clear_registry()
    import importlib

    importlib.reload(google_drive)
    yield
    clear_registry()


@pytest.fixture()
def mock_token() -> Generator[AsyncMock, None, None]:
    """Patch _get_google_token to return a fake token."""
    with patch.object(google_drive, "_get_google_token", new_callable=AsyncMock) as m:
        m.return_value = _FAKE_TOKEN
        yield m


@pytest.fixture()
def mock_http(mock_token: AsyncMock) -> Generator[AsyncMock, None, None]:
    """Patch the module-level _http_client with an AsyncMock."""
    client = AsyncMock(spec=httpx.AsyncClient)
    with patch.object(google_drive, "_http_client", client):
        yield client


# ---------------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------------


class TestDriveRegistration:
    """Google Drive tool actions are registered after import."""

    def test_drive_read_registered(self) -> None:
        """google_drive.read is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("google_drive", "read") in keys

    def test_drive_list_registered(self) -> None:
        """google_drive.list is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("google_drive", "list") in keys

    def test_drive_search_registered(self) -> None:
        """google_drive.search is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("google_drive", "search") in keys

    def test_drive_download_not_registered(self) -> None:
        """google_drive.download is NOT registered until attachments land (GH-143, #192)."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("google_drive", "download") not in keys
        assert get_tool_entry("google_drive", "download") is None

    def test_drive_registers_exactly_read_list_search(self) -> None:
        """The module registers only read, list and search."""
        keys = {(t.tool, t.action) for t in get_registered_tools()}
        assert keys == {
            ("google_drive", "read"),
            ("google_drive", "list"),
            ("google_drive", "search"),
        }

    @pytest.mark.parametrize(
        "symbol",
        [
            "google_drive_download",
            "_sync_write_download",
            "_MAX_DOWNLOAD_SIZE",
            "_EXPORT_MIME_TYPES",
        ],
    )
    def test_drive_download_code_removed(self, symbol: str) -> None:
        """The download handler, its write helper and download-only constants are deleted."""
        assert not hasattr(google_drive, symbol)

    def test_drive_module_does_not_import_files_tool(self) -> None:
        """google_drive no longer depends on the removed files tool module."""
        import ast
        from pathlib import Path

        source = Path(google_drive.__file__).read_text(encoding="utf-8")
        modules = {
            node.module
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        assert "admino.tools.files" not in modules


# ---------------------------------------------------------------------------
# 2. google_drive.read
# ---------------------------------------------------------------------------


class TestDriveRead:
    """Tests for the google_drive.read handler."""

    async def test_happy_path(self, mock_http: AsyncMock) -> None:
        """Successful read returns file metadata."""
        file_data = {
            "id": "file123",
            "name": "report.pdf",
            "mimeType": "application/pdf",
            "size": "2048",
            "createdTime": "2026-04-01T09:00:00Z",
            "modifiedTime": "2026-04-12T08:00:00Z",
            "webViewLink": "https://drive.google.com/file/d/file123/view",
        }
        mock_http.get.return_value = _make_response(200, file_data)

        args = GoogleDriveReadArgs(file_id="file123")
        result = await google_drive.google_drive_read(args, tenant=_TENANT)

        assert "Name: report.pdf" in result
        assert "ID: file123" in result
        assert "Type: application/pdf" in result
        assert "Size: 2048" in result
        assert "Link:" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            google_drive,
            "_get_google_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("no token"),
        ):
            args = GoogleDriveReadArgs(file_id="file123")
            result = await google_drive.google_drive_read(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns API error."""
        mock_http.get.return_value = _make_response(
            404, {"error": {"code": 404, "message": "File not found"}}
        )

        args = GoogleDriveReadArgs(file_id="nonexistent")
        result = await google_drive.google_drive_read(args, tenant=_TENANT)

        assert "Google API error 404" in result

    async def test_http_error(self) -> None:
        """httpx.HTTPError returns a friendly message."""
        with patch.object(
            google_drive, "_get_google_token", new_callable=AsyncMock, return_value=_FAKE_TOKEN
        ):
            client = AsyncMock(spec=httpx.AsyncClient)
            client.get.side_effect = httpx.ConnectError("refused")
            with patch.object(google_drive, "_http_client", client):
                args = GoogleDriveReadArgs(file_id="file123")
                result = await google_drive.google_drive_read(args, tenant=_TENANT)

        assert "HTTP request failed" in result


# ---------------------------------------------------------------------------
# 3. google_drive.list
# ---------------------------------------------------------------------------


class TestDriveList:
    """Tests for the google_drive.list handler."""

    async def test_happy_path_root(self, mock_http: AsyncMock) -> None:
        """List root folder returns files."""
        files = {"files": [_sample_file("f1", "file1.txt"), _sample_file("f2", "file2.txt")]}
        mock_http.get.return_value = _make_response(200, files)

        args = GoogleDriveListArgs()
        result = await google_drive.google_drive_list(args, tenant=_TENANT)

        assert "file1.txt" in result
        assert "file2.txt" in result

    async def test_folder_id_in_query(self, mock_http: AsyncMock) -> None:
        """folder_id is included in the API query param."""
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveListArgs(folder_id="folder_abc")
        await google_drive.google_drive_list(args, tenant=_TENANT)

        call_kwargs = mock_http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert "'folder_abc' in parents" in params.get("q", "")

    async def test_folder_id_single_quote_escaped_in_query(self, mock_http: AsyncMock) -> None:
        """folder_id single quotes are escaped before embedding in the q param.

        Defence-in-depth: the model pattern rejects quotes at the Pydantic layer,
        so we bypass validation with model_construct to verify the handler ALSO
        escapes them (matching google_drive_search's behavior). A raw embedding
        of ``a'b`` would break out of the quoted ``'...' in parents`` clause and
        allow Drive query injection.
        """
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveListArgs.model_construct(folder_id="a'b", max_results=10)
        await google_drive.google_drive_list(args, tenant=_TENANT)

        call_kwargs = mock_http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        q = params.get("q", "")
        assert "a\\'b" in q
        # The unescaped single quote must not appear adjacent (no raw 'a'b').
        assert "'a'b'" not in q

    async def test_root_when_no_folder_id(self, mock_http: AsyncMock) -> None:
        """When folder_id is None, query uses 'root'."""
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveListArgs(folder_id=None)
        await google_drive.google_drive_list(args, tenant=_TENANT)

        call_kwargs = mock_http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert "'root' in parents" in params.get("q", "")

    async def test_empty_files(self, mock_http: AsyncMock) -> None:
        """Empty files list returns appropriate message."""
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveListArgs()
        result = await google_drive.google_drive_list(args, tenant=_TENANT)

        assert "No files found" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns API error."""
        mock_http.get.return_value = _make_response(
            403, {"error": {"code": 403, "message": "Forbidden"}}
        )

        args = GoogleDriveListArgs()
        result = await google_drive.google_drive_list(args, tenant=_TENANT)

        assert "Google API error 403" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            google_drive,
            "_get_google_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("no token"),
        ):
            args = GoogleDriveListArgs()
            result = await google_drive.google_drive_list(args, tenant=_TENANT)

        assert "OAuth error" in result


# ---------------------------------------------------------------------------
# 4. google_drive.search
# ---------------------------------------------------------------------------


class TestDriveSearch:
    """Tests for the google_drive.search handler."""

    async def test_happy_path(self, mock_http: AsyncMock) -> None:
        """Successful search returns matching files."""
        files = {"files": [_sample_file("s1", "budget.xlsx", "application/vnd.ms-excel")]}
        mock_http.get.return_value = _make_response(200, files)

        args = GoogleDriveSearchArgs(query="budget")
        result = await google_drive.google_drive_search(args, tenant=_TENANT)

        assert "budget.xlsx" in result

    async def test_query_in_fulltext_param(self, mock_http: AsyncMock) -> None:
        """The search query is wrapped in fullText contains."""
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveSearchArgs(query="report 2026")
        await google_drive.google_drive_search(args, tenant=_TENANT)

        call_kwargs = mock_http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert "fullText contains" in params.get("q", "")
        assert "report 2026" in params.get("q", "")

    async def test_no_results(self, mock_http: AsyncMock) -> None:
        """Empty search results return appropriate message."""
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveSearchArgs(query="nonexistent")
        result = await google_drive.google_drive_search(args, tenant=_TENANT)

        assert "No files found matching" in result

    async def test_single_quote_rejected_by_model(self, mock_http: AsyncMock) -> None:
        """Single quotes in query are rejected at validation to prevent injection."""
        with pytest.raises(ValidationError, match="string_pattern_mismatch"):
            GoogleDriveSearchArgs(query="it's a test")

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns API error."""
        mock_http.get.return_value = _make_response(
            500, {"error": {"code": 500, "message": "Server Error"}}
        )

        args = GoogleDriveSearchArgs(query="test")
        result = await google_drive.google_drive_search(args, tenant=_TENANT)

        assert "Google API error 500" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            google_drive,
            "_get_google_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("no token"),
        ):
            args = GoogleDriveSearchArgs(query="test")
            result = await google_drive.google_drive_search(args, tenant=_TENANT)

        assert "OAuth error" in result


# ---------------------------------------------------------------------------
# 6. Argument validation
# ---------------------------------------------------------------------------


class TestDriveArgValidation:
    """Pydantic validation rejects invalid arguments."""

    def test_read_missing_file_id(self) -> None:
        """Missing file_id is rejected."""
        with pytest.raises(ValidationError):
            GoogleDriveReadArgs()  # type: ignore[call-arg]

    def test_read_file_id_too_long(self) -> None:
        """file_id exceeding 200 chars is rejected."""
        with pytest.raises(ValidationError):
            GoogleDriveReadArgs(file_id="x" * 201)

    def test_list_max_results_zero(self) -> None:
        """max_results=0 is rejected."""
        with pytest.raises(ValidationError):
            GoogleDriveListArgs(max_results=0)

    def test_list_max_results_exceeds_limit(self) -> None:
        """max_results exceeding 100 is rejected."""
        with pytest.raises(ValidationError):
            GoogleDriveListArgs(max_results=200)

    def test_search_query_too_long(self) -> None:
        """Query exceeding 500 chars is rejected."""
        with pytest.raises(ValidationError):
            GoogleDriveSearchArgs(query="x" * 501)

    def test_search_max_results_negative(self) -> None:
        """Negative max_results is rejected."""
        with pytest.raises(ValidationError):
            GoogleDriveSearchArgs(query="test", max_results=-1)

    def test_valid_args_accepted(self) -> None:
        """Valid arguments pass validation."""
        read_args = GoogleDriveReadArgs(file_id="abc123")
        assert read_args.file_id == "abc123"

        list_args = GoogleDriveListArgs(folder_id="folder1", max_results=50)
        assert list_args.folder_id == "folder1"

        search_args = GoogleDriveSearchArgs(query="budget", max_results=10)
        assert search_args.query == "budget"

    def test_list_folder_id_optional(self) -> None:
        """folder_id defaults to None."""
        args = GoogleDriveListArgs()
        assert args.folder_id is None


# ---------------------------------------------------------------------------
# 7. Internal helpers
# ---------------------------------------------------------------------------


class TestDriveHelpers:
    """Tests for internal helper functions."""

    def test_format_file_entry(self) -> None:
        """_format_file_entry includes name, id, type, size, modified."""
        file = _sample_file()
        result = google_drive._format_file_entry(file)
        assert "document.pdf" in result
        assert "file123" in result
        assert "application/pdf" in result

    def test_format_api_error_with_json(self) -> None:
        """_format_api_error extracts code and message."""
        resp = _make_response(403, {"error": {"code": 403, "message": "Rate limit"}})
        result = google_drive._format_api_error(resp)
        assert "403" in result
        assert "Rate limit" in result

    def test_format_api_error_fallback(self) -> None:
        """_format_api_error falls back to status code for non-JSON."""
        resp = httpx.Response(status_code=503, content=b"unavailable")
        result = google_drive._format_api_error(resp)
        assert "503" in result


# ---------------------------------------------------------------------------
# 8. Per-user tokens (GH-162)
# ---------------------------------------------------------------------------

_HANDLER_CASES = [
    pytest.param("google_drive_read", GoogleDriveReadArgs(file_id="file123"), id="read"),
    pytest.param("google_drive_list", GoogleDriveListArgs(), id="list"),
    pytest.param("google_drive_search", GoogleDriveSearchArgs(query="budget"), id="search"),
]


class TestDrivePerUserTokens:
    """GH-162: every handler call loads and sends the token of its own tenant.

    The module keeps no token state of its own: ``_get_google_token(tenant)`` reads the
    process-wide per-user cache (``oauth.access_tokens``), and the tenant always
    comes from the handler's server-side context, never from tool arguments.
    """

    @pytest.mark.parametrize("name", _REMOVED_TOKEN_STATE)
    def test_google_drive_module_level_token_state_removed(self, name: str) -> None:
        """The module-level token cache, its lock, its clear function and the old
        direct ``get_valid_access_token`` call are gone."""
        assert not hasattr(google_drive, name)

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_google_drive_handler_without_tenant_raises_type_error(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """``tenant`` is a required keyword: no call runs without a tool context."""
        api = _Api()
        handler = getattr(google_drive, handler_name)
        with (
            patch.object(google_drive, "_http_client", api.client),
            pytest.raises(TypeError, match="tenant"),
        ):
            await handler(args)
        mock_token.assert_not_awaited()
        assert api.all_bearers() == []

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_google_drive_handler_loads_and_sends_token_of_its_tenant(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """Each action awaits ``_get_google_token`` with the call's tenant and sends exactly
        the token it returned (extra context keywords such as session_id are accepted)."""
        api = _Api()
        handler = getattr(google_drive, handler_name)
        with patch.object(google_drive, "_http_client", api.client):
            await handler(args, session_id="sess-1", tenant=_TENANT_B)
        _assert_token_loaded_for(mock_token, _TENANT_B)
        assert api.all_bearers()
        assert set(api.all_bearers()) == {f"Bearer {mock_token.return_value}"}

    async def test_google_drive_get_token_reads_shared_per_user_cache(self) -> None:
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
            patch.object(google_drive, "_http_client", client),
        ):
            tokens = [
                await google_drive._get_google_token(_TENANT),
                await google_drive._get_google_token(_TENANT_B),
                await google_drive._get_google_token(_TENANT),
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

    async def test_google_drive_concurrent_users_each_request_carries_own_token(
        self, mock_token: AsyncMock
    ) -> None:
        """User A's token is never sent for user B: B's whole call runs while A's
        token load is still pending, and every request carries its own caller's token."""
        users = _TwoUsers()
        mock_token.side_effect = users.token_for
        api = _Api()
        with patch.object(google_drive, "_http_client", api.client):
            result_a, result_b = await users.run(
                lambda: google_drive.google_drive_list(GoogleDriveListArgs(), tenant=_TENANT),
                lambda: google_drive.google_drive_list(GoogleDriveListArgs(), tenant=_TENANT_B),
            )

        _assert_bearers_isolated(api)
        assert "document.pdf" in result_a
        assert "document.pdf" in result_b

    async def test_google_drive_shared_cache_never_serves_one_users_token_to_another(self) -> None:
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
                patch.object(google_drive, "_http_client", api.client),
            ):
                await users.run(
                    lambda: google_drive.google_drive_list(GoogleDriveListArgs(), tenant=_TENANT),
                    lambda: google_drive.google_drive_list(GoogleDriveListArgs(), tenant=_TENANT_B),
                )
                await _call_as(
                    "A",
                    lambda: google_drive.google_drive_list(GoogleDriveListArgs(), tenant=_TENANT),
                )
                await _call_as(
                    "B",
                    lambda: google_drive.google_drive_list(GoogleDriveListArgs(), tenant=_TENANT_B),
                )
        finally:
            oauth.access_tokens.clear()

        _assert_bearers_isolated(api)
        own: dict[object, str] = {_USER_A_ID: _TOKEN_A, _USER_B_ID: _TOKEN_B}
        assert {user for user, _, _ in users.refreshes} == {_USER_A_ID, _USER_B_ID}
        assert all(provider == "google" for _, provider, _ in users.refreshes)
        assert all(cached in (None, own[user]) for user, _, cached in users.refreshes)
