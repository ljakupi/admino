"""Tests for the Google Drive tool module (admino.tools.google_drive).

Covers tool registration, happy-path responses, OAuth errors, API errors,
empty results, file download (binary and Google Workspace export), path
validation, and argument validation.
All HTTP calls are mocked -- no real API requests are made.
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
    from pathlib import Path

from admino.models import (
    GoogleDriveDownloadArgs,
    GoogleDriveListArgs,
    GoogleDriveReadArgs,
    GoogleDriveSearchArgs,
)
from admino.oauth import OAuthError
from admino.tools import google_drive
from admino.tools.registry import clear_registry, get_registered_tools

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

    def test_drive_download_registered(self) -> None:
        """google_drive.download is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("google_drive", "download") in keys


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
        result = await google_drive.google_drive_read(args)

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
            result = await google_drive.google_drive_read(args)

        assert "OAuth error" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns API error."""
        mock_http.get.return_value = _make_response(
            404, {"error": {"code": 404, "message": "File not found"}}
        )

        args = GoogleDriveReadArgs(file_id="nonexistent")
        result = await google_drive.google_drive_read(args)

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
                result = await google_drive.google_drive_read(args)

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
        result = await google_drive.google_drive_list(args)

        assert "file1.txt" in result
        assert "file2.txt" in result

    async def test_folder_id_in_query(self, mock_http: AsyncMock) -> None:
        """folder_id is included in the API query param."""
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveListArgs(folder_id="folder_abc")
        await google_drive.google_drive_list(args)

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
        await google_drive.google_drive_list(args)

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
        await google_drive.google_drive_list(args)

        call_kwargs = mock_http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert "'root' in parents" in params.get("q", "")

    async def test_empty_files(self, mock_http: AsyncMock) -> None:
        """Empty files list returns appropriate message."""
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveListArgs()
        result = await google_drive.google_drive_list(args)

        assert "No files found" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns API error."""
        mock_http.get.return_value = _make_response(
            403, {"error": {"code": 403, "message": "Forbidden"}}
        )

        args = GoogleDriveListArgs()
        result = await google_drive.google_drive_list(args)

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
            result = await google_drive.google_drive_list(args)

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
        result = await google_drive.google_drive_search(args)

        assert "budget.xlsx" in result

    async def test_query_in_fulltext_param(self, mock_http: AsyncMock) -> None:
        """The search query is wrapped in fullText contains."""
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveSearchArgs(query="report 2026")
        await google_drive.google_drive_search(args)

        call_kwargs = mock_http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert "fullText contains" in params.get("q", "")
        assert "report 2026" in params.get("q", "")

    async def test_no_results(self, mock_http: AsyncMock) -> None:
        """Empty search results return appropriate message."""
        mock_http.get.return_value = _make_response(200, {"files": []})

        args = GoogleDriveSearchArgs(query="nonexistent")
        result = await google_drive.google_drive_search(args)

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
        result = await google_drive.google_drive_search(args)

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
            result = await google_drive.google_drive_search(args)

        assert "OAuth error" in result


# ---------------------------------------------------------------------------
# 5. google_drive.download
# ---------------------------------------------------------------------------


class TestDriveDownload:
    """Tests for the google_drive.download handler."""

    async def test_happy_path_binary(self, mock_http: AsyncMock, tmp_path: Path) -> None:
        """Successful binary file download writes to destination."""
        dest = tmp_path / "downloaded.pdf"
        meta_resp = _make_response(
            200, {"id": "f1", "name": "report.pdf", "mimeType": "application/pdf", "size": "100"}
        )
        content_resp = _make_response(200, content=b"PDF binary content here")
        mock_http.get.side_effect = [meta_resp, content_resp]

        with (
            patch.object(google_drive, "_validate_path", return_value=dest),
            patch.object(google_drive, "_revalidate_resolved"),
        ):
            args = GoogleDriveDownloadArgs(file_id="f1", destination=str(dest))
            result = await google_drive.google_drive_download(args)

        assert "Downloaded" in result
        assert "report.pdf" in result
        assert dest.exists()
        assert dest.read_bytes() == b"PDF binary content here"

    async def test_google_workspace_export_as_pdf(
        self, mock_http: AsyncMock, tmp_path: Path
    ) -> None:
        """Google Docs files are exported as PDF."""
        dest = tmp_path / "doc.pdf"
        meta_resp = _make_response(
            200,
            {
                "id": "d1",
                "name": "My Doc",
                "mimeType": "application/vnd.google-apps.document",
                "size": "0",
            },
        )
        export_resp = _make_response(200, content=b"PDF export content")
        mock_http.get.side_effect = [meta_resp, export_resp]

        with (
            patch.object(google_drive, "_validate_path", return_value=dest),
            patch.object(google_drive, "_revalidate_resolved"),
        ):
            args = GoogleDriveDownloadArgs(file_id="d1", destination=str(dest))
            result = await google_drive.google_drive_download(args)

        assert "exported as PDF" in result
        assert dest.exists()

    async def test_path_validation_failure(self, mock_http: AsyncMock) -> None:
        """Invalid destination path returns error."""
        with patch.object(
            google_drive, "_validate_path", side_effect=PermissionError("outside allowed paths")
        ):
            args = GoogleDriveDownloadArgs(file_id="f1", destination="/etc/passwd")
            result = await google_drive.google_drive_download(args)

        assert "not allowed" in result

    async def test_destination_already_exists(self, mock_http: AsyncMock, tmp_path: Path) -> None:
        """Existing file at destination returns error (no overwrite)."""
        dest = tmp_path / "existing.txt"
        dest.write_text("existing content")

        with patch.object(google_drive, "_validate_path", return_value=dest):
            args = GoogleDriveDownloadArgs(file_id="f1", destination=str(dest))
            result = await google_drive.google_drive_download(args)

        assert "already exists" in result

    async def test_file_too_large(self, mock_http: AsyncMock, tmp_path: Path) -> None:
        """File exceeding 100 MB limit returns error."""
        dest = tmp_path / "huge.bin"
        meta_resp = _make_response(
            200, {"id": "f1", "name": "huge.bin", "mimeType": "application/octet-stream"}
        )
        # Content larger than 100 MB -- we mock len(content) > limit
        large_content = b"x" * (100 * 1024 * 1024 + 1)
        content_resp = _make_response(200, content=large_content)
        mock_http.get.side_effect = [meta_resp, content_resp]

        with patch.object(google_drive, "_validate_path", return_value=dest):
            args = GoogleDriveDownloadArgs(file_id="f1", destination=str(dest))
            result = await google_drive.google_drive_download(args)

        assert "too large" in result

    async def test_oauth_not_configured_on_metadata(self, tmp_path: Path) -> None:
        """OAuthError on metadata fetch returns setup instructions."""
        dest = tmp_path / "test.pdf"
        with (
            patch.object(google_drive, "_validate_path", return_value=dest),
            patch.object(
                google_drive,
                "_get_google_token",
                new_callable=AsyncMock,
                side_effect=OAuthError("no token"),
            ),
        ):
            args = GoogleDriveDownloadArgs(file_id="f1", destination=str(dest))
            result = await google_drive.google_drive_download(args)

        assert "OAuth error" in result

    async def test_api_error_on_metadata(self, mock_http: AsyncMock, tmp_path: Path) -> None:
        """Non-200 on metadata fetch returns API error."""
        dest = tmp_path / "test.pdf"
        mock_http.get.return_value = _make_response(
            404, {"error": {"code": 404, "message": "Not Found"}}
        )

        with (
            patch.object(google_drive, "_validate_path", return_value=dest),
            patch("os.path.lexists", return_value=False),
        ):
            args = GoogleDriveDownloadArgs(file_id="f1", destination=str(dest))
            result = await google_drive.google_drive_download(args)

        assert "Google API error 404" in result


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

    def test_download_file_id_too_long(self) -> None:
        """file_id exceeding 200 chars in download args is rejected."""
        with pytest.raises(ValidationError):
            GoogleDriveDownloadArgs(file_id="x" * 201, destination="/data/test")

    def test_download_destination_too_long(self) -> None:
        """destination exceeding 500 chars is rejected."""
        with pytest.raises(ValidationError):
            GoogleDriveDownloadArgs(file_id="f1", destination="/" + "x" * 500)

    def test_valid_args_accepted(self) -> None:
        """Valid arguments pass validation."""
        read_args = GoogleDriveReadArgs(file_id="abc123")
        assert read_args.file_id == "abc123"

        list_args = GoogleDriveListArgs(folder_id="folder1", max_results=50)
        assert list_args.folder_id == "folder1"

        search_args = GoogleDriveSearchArgs(query="budget", max_results=10)
        assert search_args.query == "budget"

        download_args = GoogleDriveDownloadArgs(file_id="f1", destination="/data/file.pdf")
        assert download_args.destination == "/data/file.pdf"

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

    def test_export_mime_types_defined(self) -> None:
        """Google Workspace MIME types map to PDF export."""
        for mime_type, export_type in google_drive._EXPORT_MIME_TYPES.items():
            assert export_type == "application/pdf"
            assert "google-apps" in mime_type
