"""Tests for the OneDrive tool (admino.tools.onedrive).

Covers tool registration, happy-path responses, OAuth error handling,
API error handling, empty results, download with path validation,
and argument validation. All HTTP calls are mocked.
"""

from __future__ import annotations

import json
from pathlib import Path  # noqa: TC003
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pydantic import ValidationError

if TYPE_CHECKING:
    from collections.abc import Generator

from admino.models import (
    OneDriveDownloadArgs,
    OneDriveListArgs,
    OneDriveReadArgs,
    OneDriveSearchArgs,
)
from admino.oauth import OAuthError
from admino.tools import onedrive as onedrive_mod
from admino.tools.registry import clear_registry, get_registered_tools

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

    def test_download_registered(self) -> None:
        """onedrive.download is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("onedrive", "download") in keys


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
        result = await onedrive_read(args)

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
        result = await onedrive_read(args)

        assert "Type: folder" in result

    async def test_read_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.onedrive._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.onedrive import onedrive_read

            args = OneDriveReadArgs(item_id="item-1")
            result = await onedrive_read(args)

        assert "OAuth not configured" in result

    async def test_read_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 returns Graph error."""
        mock_http_client.get.return_value = _make_response(
            404, {"error": {"message": "Item not found"}}
        )

        from admino.tools.onedrive import onedrive_read

        args = OneDriveReadArgs(item_id="bad-id")
        result = await onedrive_read(args)

        assert "Microsoft Graph error" in result

    async def test_read_http_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """httpx.HTTPError returns connection failure."""
        mock_http_client.get.side_effect = httpx.ConnectError("fail")

        from admino.tools.onedrive import onedrive_read

        args = OneDriveReadArgs(item_id="item-1")
        result = await onedrive_read(args)

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
        result = await onedrive_list(args)

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
        await onedrive_list(args)

        url = mock_http_client.get.call_args[0][0]
        assert "/me/drive/root/children" in url
        # Should NOT use the /root:/{path}:/children form
        assert "root:/" not in url

    async def test_list_subfolder_url_uses_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """When folder_path is set, URL uses /root:/{path}:/children."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs(folder_path="Documents/Work")
        await onedrive_list(args)

        url = mock_http_client.get.call_args[0][0]
        assert "/root:/Documents/Work:/children" in url

    async def test_list_empty_results(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Empty list returns appropriate message."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs()
        result = await onedrive_list(args)

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
            result = await onedrive_list(args)

        assert "OAuth not configured" in result

    async def test_list_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 returns Graph error."""
        mock_http_client.get.return_value = _make_response(
            500, {"error": {"message": "Server error"}}
        )

        from admino.tools.onedrive import onedrive_list

        args = OneDriveListArgs()
        result = await onedrive_list(args)

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
        result = await onedrive_search(args)

        assert "Name: budget.xlsx" in result

    async def test_search_empty_results(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Empty search returns appropriate message."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_search

        args = OneDriveSearchArgs(query="nonexistent")
        result = await onedrive_search(args)

        assert "No files found" in result

    async def test_search_url_contains_query(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Request URL includes the search query."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.onedrive import onedrive_search

        args = OneDriveSearchArgs(query="quarterly report")
        await onedrive_search(args)

        url = mock_http_client.get.call_args[0][0]
        assert "search(q='quarterly report')" in url

    async def test_search_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.onedrive._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.onedrive import onedrive_search

            args = OneDriveSearchArgs(query="test")
            result = await onedrive_search(args)

        assert "OAuth not configured" in result

    async def test_search_api_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Non-200 returns Graph error."""
        mock_http_client.get.return_value = _make_response(
            403, {"error": {"message": "Access denied"}}
        )

        from admino.tools.onedrive import onedrive_search

        args = OneDriveSearchArgs(query="test")
        result = await onedrive_search(args)

        assert "Microsoft Graph error" in result


# ---------------------------------------------------------------------------
# 5. onedrive.download
# ---------------------------------------------------------------------------


class TestOneDriveDownload:
    """Tests for the onedrive.download action."""

    async def test_download_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock, tmp_path: Path
    ) -> None:
        """Successful download writes file and returns size message."""
        file_content = b"PDF content here"
        mock_http_client.get.return_value = _make_response(200, content=file_content)
        dest = tmp_path / "downloaded.pdf"

        with (
            patch("admino.tools.onedrive._validate_path", return_value=dest),
            patch("admino.tools.onedrive._revalidate_resolved"),
        ):
            from admino.tools.onedrive import onedrive_download

            args = OneDriveDownloadArgs(item_id="item-1", destination=str(dest))
            result = await onedrive_download(args)

        assert "Downloaded" in result
        assert dest.exists()
        assert dest.read_bytes() == file_content

    async def test_download_path_validation_rejected(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Invalid destination path is rejected."""
        with patch(
            "admino.tools.onedrive._validate_path",
            side_effect=PermissionError("outside allowed paths"),
        ):
            from admino.tools.onedrive import onedrive_download

            args = OneDriveDownloadArgs(item_id="item-1", destination="/etc/passwd")
            result = await onedrive_download(args)

        assert "Destination path rejected" in result

    async def test_download_existing_file_rejected(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock, tmp_path: Path
    ) -> None:
        """Download to existing file path is rejected."""
        existing = tmp_path / "existing.txt"
        existing.write_text("already here")

        with patch("admino.tools.onedrive._validate_path", return_value=existing):
            from admino.tools.onedrive import onedrive_download

            args = OneDriveDownloadArgs(item_id="item-1", destination=str(existing))
            result = await onedrive_download(args)

        assert "already exists" in result

    async def test_download_oauth_not_configured(self, tmp_path: Path) -> None:
        """OAuth not configured returns setup instructions."""
        dest = tmp_path / "new_file.pdf"
        with (
            patch("admino.tools.onedrive._validate_path", return_value=dest),
            patch(
                "admino.tools.onedrive._get_microsoft_token",
                new_callable=AsyncMock,
                side_effect=OAuthError("not configured"),
            ),
        ):
            from admino.tools.onedrive import onedrive_download

            args = OneDriveDownloadArgs(item_id="item-1", destination=str(dest))
            result = await onedrive_download(args)

        assert "OAuth not configured" in result

    async def test_download_api_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock, tmp_path: Path
    ) -> None:
        """Non-200 returns Graph error."""
        dest = tmp_path / "fail.pdf"
        mock_http_client.get.return_value = _make_response(
            404, {"error": {"message": "Item not found"}}
        )

        with patch("admino.tools.onedrive._validate_path", return_value=dest):
            from admino.tools.onedrive import onedrive_download

            args = OneDriveDownloadArgs(item_id="bad-id", destination=str(dest))
            result = await onedrive_download(args)

        assert "Microsoft Graph error" in result

    async def test_download_http_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock, tmp_path: Path
    ) -> None:
        """httpx.HTTPError returns connection failure."""
        dest = tmp_path / "fail.pdf"
        mock_http_client.get.side_effect = httpx.ConnectError("fail")

        with patch("admino.tools.onedrive._validate_path", return_value=dest):
            from admino.tools.onedrive import onedrive_download

            args = OneDriveDownloadArgs(item_id="item-1", destination=str(dest))
            result = await onedrive_download(args)

        assert "Failed to connect" in result


# ---------------------------------------------------------------------------
# 6. Argument validation
# ---------------------------------------------------------------------------


class TestOneDriveArgValidation:
    """Pydantic validation rejects invalid arguments."""

    def test_read_valid_item_id_accepted(self) -> None:
        """Valid item_id is accepted."""
        args = OneDriveReadArgs(item_id="abc123")
        assert args.item_id == "abc123"

    def test_read_overly_long_item_id_rejected(self) -> None:
        """item_id exceeding max_length is rejected."""
        with pytest.raises(ValidationError):
            OneDriveReadArgs(item_id="x" * 201)

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

    def test_download_valid_args_accepted(self) -> None:
        """Valid download args are accepted."""
        args = OneDriveDownloadArgs(item_id="item-1", destination="/data/file.pdf")
        assert args.item_id == "item-1"
        assert args.destination == "/data/file.pdf"

    def test_download_overly_long_destination_rejected(self) -> None:
        """Destination exceeding max_length is rejected."""
        with pytest.raises(ValidationError):
            OneDriveDownloadArgs(item_id="item-1", destination="x" * 501)

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
