"""Google Drive tool for reading, listing, searching, and downloading files via Drive API v3.

Provides read (metadata), list, search, and download actions for Google Drive
files using the authenticated user's account. OAuth tokens are managed by
admino.oauth.

Security notes:
- No delete capability. google_drive.delete is a hardcoded denial in
  permissions.py.
- Download destination paths are validated against operator-configured
  allowed_paths via the files tool's path validation.
- For Google Workspace documents (Docs, Sheets, Slides), export is used
  with PDF mime type to avoid arbitrary code execution from native formats.
- OAuth tokens are cached in module-level state; refresh tokens never appear
  in memory outside oauth.py.
- No eval, exec, shell=True, or importlib.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from datetime import datetime

from admino.models import (
    GoogleDriveDownloadArgs,
    GoogleDriveListArgs,
    GoogleDriveReadArgs,
    GoogleDriveSearchArgs,
)
from admino.oauth import OAuthError, get_valid_access_token
from admino.tools.files import _revalidate_resolved, _validate_path
from admino.tools.registry import register_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state for OAuth token caching and HTTP client
# ---------------------------------------------------------------------------

_TOKENS_DIR = Path(os.environ.get("TOKENS_DIR", "/app/data/tokens"))
_http_client: httpx.AsyncClient | None = None
_cached_token: str | None = None
_cached_expires_at: datetime | None = None
_token_lock = asyncio.Lock()

_DRIVE_API_BASE = "https://www.googleapis.com/drive/v3"

# Google Workspace MIME types that require export instead of direct download.
# Export as PDF to avoid executing arbitrary macros/scripts in native formats.
_EXPORT_MIME_TYPES: dict[str, str] = {
    "application/vnd.google-apps.document": "application/pdf",
    "application/vnd.google-apps.spreadsheet": "application/pdf",
    "application/vnd.google-apps.presentation": "application/pdf",
    "application/vnd.google-apps.drawing": "application/pdf",
}

_MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024  # 100 MB


async def _get_google_token() -> str:
    """Obtain a valid Google OAuth access token, refreshing if needed.

    Returns:
        A valid access token string.

    Raises:
        OAuthError: If no token file exists or refresh fails.
    """
    async with _token_lock:
        global _http_client, _cached_token, _cached_expires_at
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        _cached_token, _cached_expires_at = await get_valid_access_token(
            _TOKENS_DIR, "google", _cached_token, _cached_expires_at, _http_client
        )
        return _cached_token


def _auth_headers(token: str) -> dict[str, str]:
    """Build Authorization header for Google API requests."""
    return {"Authorization": f"Bearer {token}"}


def _format_api_error(response: httpx.Response) -> str:
    """Format a human-readable error message from a Google API error response.

    Args:
        response: The error response from the Google API.

    Returns:
        A user-friendly error string.
    """
    try:
        data = response.json()
        if isinstance(data, dict):
            error = data.get("error", {})
            if isinstance(error, dict):
                message = error.get("message", "Unknown error")
                code = error.get("code", response.status_code)
                return f"Google API error {code}: {str(message)[:500]}"
    except (ValueError, KeyError):
        pass
    return f"Google API error {response.status_code}"


def _format_file_entry(file: dict[str, object]) -> str:
    """Format a single Drive file dict into a readable string.

    Args:
        file: File resource dict from the Drive API.

    Returns:
        Formatted single-line file description.
    """
    name = file.get("name", "Untitled")
    file_id = file.get("id", "unknown")
    mime_type = file.get("mimeType", "unknown")
    size = file.get("size", "N/A")
    modified = file.get("modifiedTime", "N/A")
    return (
        f"  Name: {name}\n"
        f"  ID: {file_id}\n"
        f"  Type: {mime_type}\n"
        f"  Size: {size}\n"
        f"  Modified: {modified}"
    )


def _sync_write_download(path: Path, content: bytes) -> None:
    """Write downloaded content to a file, creating parent dirs if needed.

    Refuses to overwrite existing files (create-only, matching files.py
    security policy).

    Args:
        path: Validated destination path.
        content: File content bytes.

    Raises:
        FileExistsError: If the destination already exists.
    """
    # TOCTOU defence: re-validate path hasn't changed since async validation.
    _revalidate_resolved(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
    )
    try:
        os.write(fd, content)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@register_tool(
    tool="google_drive",
    action="read",
    description=(
        "Read file metadata from Google Drive by file ID. "
        "Returns name, type, size, dates, and link."
    ),
    args_schema=GoogleDriveReadArgs,
)
async def google_drive_read(args: GoogleDriveReadArgs, **kwargs: object) -> str:
    """Read metadata for a single Google Drive file.

    Args:
        args: Validated read arguments (file_id).

    Returns:
        Formatted file metadata string.
    """
    fields = "id,name,mimeType,size,createdTime,modifiedTime,webViewLink"
    try:
        global _http_client
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        token = await _get_google_token()
        response = await _http_client.get(
            f"{_DRIVE_API_BASE}/files/{args.file_id}",
            params={"fields": fields},
            headers=_auth_headers(token),
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc}. Re-run: python -m admino.oauth_setup google"
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    data = response.json()
    if not isinstance(data, dict):
        return "Unexpected response format from Google Drive API."

    return (
        f"Name: {data.get('name', 'Untitled')}\n"
        f"ID: {data.get('id', 'unknown')}\n"
        f"Type: {data.get('mimeType', 'unknown')}\n"
        f"Size: {data.get('size', 'N/A')}\n"
        f"Created: {data.get('createdTime', 'N/A')}\n"
        f"Modified: {data.get('modifiedTime', 'N/A')}\n"
        f"Link: {data.get('webViewLink', 'N/A')}"
    )


@register_tool(
    tool="google_drive",
    action="list",
    description="List files in a Google Drive folder. If no folder ID given, lists root.",
    args_schema=GoogleDriveListArgs,
)
async def google_drive_list(args: GoogleDriveListArgs, **kwargs: object) -> str:
    """List files in a Google Drive folder.

    Args:
        args: Validated list arguments (folder_id, max_results).

    Returns:
        Formatted list of files in the folder.
    """
    parent = f"'{args.folder_id}'" if args.folder_id else "'root'"
    query = f"{parent} in parents"
    fields = "files(id,name,mimeType,size,modifiedTime)"

    try:
        global _http_client
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        token = await _get_google_token()
        response = await _http_client.get(
            f"{_DRIVE_API_BASE}/files",
            params={"q": query, "pageSize": str(args.max_results), "fields": fields},
            headers=_auth_headers(token),
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc}. Re-run: python -m admino.oauth_setup google"
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    data = response.json()
    files = data.get("files", [])
    if not isinstance(files, list) or not files:
        return "No files found in the specified folder."

    lines: list[str] = []
    for file in files:
        if not isinstance(file, dict):
            continue
        lines.append(_format_file_entry(file))
        lines.append("")  # blank line separator

    return "\n".join(lines).rstrip()


@register_tool(
    tool="google_drive",
    action="search",
    description="Search for files in Google Drive by text query.",
    args_schema=GoogleDriveSearchArgs,
)
async def google_drive_search(args: GoogleDriveSearchArgs, **kwargs: object) -> str:
    """Search Google Drive files by full-text query.

    Args:
        args: Validated search arguments (query, max_results).

    Returns:
        Formatted list of matching files.
    """
    # Model-level pattern validation rejects single quotes and backslashes.
    # Defence-in-depth: escape any that slip through.
    safe_query = args.query.replace("\\", "\\\\").replace("'", "\\'")
    query = f"fullText contains '{safe_query}'"
    fields = "files(id,name,mimeType,size,modifiedTime)"

    try:
        global _http_client
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        token = await _get_google_token()
        response = await _http_client.get(
            f"{_DRIVE_API_BASE}/files",
            params={"q": query, "pageSize": str(args.max_results), "fields": fields},
            headers=_auth_headers(token),
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc}. Re-run: python -m admino.oauth_setup google"
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    data = response.json()
    files = data.get("files", [])
    if not isinstance(files, list) or not files:
        return "No files found matching the search query."

    lines: list[str] = []
    for file in files:
        if not isinstance(file, dict):
            continue
        lines.append(_format_file_entry(file))
        lines.append("")  # blank line separator

    return "\n".join(lines).rstrip()


@register_tool(
    tool="google_drive",
    action="download",
    description=(
        "Download a file from Google Drive to a local path. "
        "Destination must be in an allowed writable directory."
    ),
    args_schema=GoogleDriveDownloadArgs,
)
async def google_drive_download(args: GoogleDriveDownloadArgs, **kwargs: object) -> str:
    """Download a file from Google Drive to a local path.

    For Google Workspace documents (Docs, Sheets, Slides), exports as PDF.
    For binary files, downloads directly. The destination path is validated
    against allowed_paths from the files tool.

    Args:
        args: Validated download arguments (file_id, destination).

    Returns:
        Confirmation message with destination path and file size.
    """
    # Validate destination path against allowed paths (require write access)
    try:
        validated_dest = _validate_path(args.destination, require_write=True)
    except PermissionError as exc:
        return f"Destination path not allowed: {exc}"
    except ValueError as exc:
        return f"Path validation error: {exc}"

    # Refuse to overwrite existing files (matching files.py policy)
    if os.path.lexists(str(validated_dest)):
        return (
            f"Cannot download to {validated_dest}: a file or directory already "
            "exists at that path. Please choose a different destination."
        )

    # First, get file metadata to determine mime type
    try:
        global _http_client
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=60.0)
        token = await _get_google_token()
        meta_response = await _http_client.get(
            f"{_DRIVE_API_BASE}/files/{args.file_id}",
            params={"fields": "id,name,mimeType,size"},
            headers=_auth_headers(token),
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc}. Re-run: python -m admino.oauth_setup google"
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if meta_response.status_code != 200:
        return _format_api_error(meta_response)

    meta = meta_response.json()
    if not isinstance(meta, dict):
        return "Unexpected response format from Google Drive API."

    mime_type = str(meta.get("mimeType", ""))
    file_name = str(meta.get("name", "unknown"))

    # Determine download method
    try:
        token = await _get_google_token()

        if mime_type in _EXPORT_MIME_TYPES:
            # Google Workspace document: export as PDF
            export_mime = _EXPORT_MIME_TYPES[mime_type]
            response = await _http_client.get(
                f"{_DRIVE_API_BASE}/files/{args.file_id}/export",
                params={"mimeType": export_mime},
                headers=_auth_headers(token),
            )
        else:
            # Binary file: direct download
            response = await _http_client.get(
                f"{_DRIVE_API_BASE}/files/{args.file_id}",
                params={"alt": "media"},
                headers=_auth_headers(token),
            )
    except OAuthError as exc:
        return f"Google OAuth error: {exc}. Re-run: python -m admino.oauth_setup google"
    except httpx.HTTPError as exc:
        return f"HTTP request failed during download: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    # Check Content-Length header before buffering to prevent OOM on huge files
    content_length = response.headers.get("content-length")
    try:
        cl_int = int(content_length) if content_length else None
    except (ValueError, TypeError):
        cl_int = None
    if cl_int is not None and cl_int > _MAX_DOWNLOAD_SIZE:
        return (
            f"File '{file_name}' is too large to download "
            f"({cl_int} bytes, limit is {_MAX_DOWNLOAD_SIZE} bytes)."
        )

    content = response.content
    if len(content) > _MAX_DOWNLOAD_SIZE:
        return (
            f"File '{file_name}' is too large to download "
            f"({len(content)} bytes, limit is {_MAX_DOWNLOAD_SIZE} bytes)."
        )

    # Write to destination
    try:
        await asyncio.to_thread(_sync_write_download, validated_dest, content)
    except FileExistsError:
        return (
            f"Cannot download to {validated_dest}: a file was created at that "
            "path concurrently. Please choose a different destination."
        )
    except OSError as exc:
        return f"Failed to write downloaded file: {type(exc).__name__}"

    size_str = f"{len(content)} bytes"
    export_note = " (exported as PDF)" if mime_type in _EXPORT_MIME_TYPES else ""
    return f"Downloaded '{file_name}'{export_note} to {validated_dest} ({size_str})"
