"""Google Drive tool for reading, listing, and searching files via Drive API v3.

Provides read (metadata), list, and search actions for Google Drive files using
the authenticated user's account. OAuth tokens are managed by admino.oauth.

The download action is not registered: it wrote into the removed local files
tool's host directories (GH-143) and returns as chat attachments with #192. Its
``google_drive.download`` permission row stays at ``confirm`` for that reason;
until then, dispatch rejects the call as an unknown tool.

Security notes:
- No delete capability. google_drive.delete is a hardcoded denial in
  permissions.py.
- Read-only: no action writes to the local filesystem or to Drive.
- OAuth tokens are cached in module-level state; refresh tokens never appear
  in memory outside oauth.py.
- No eval, exec, shell=True, or importlib.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from datetime import datetime

from admino.models import (
    GoogleDriveListArgs,
    GoogleDriveReadArgs,
    GoogleDriveSearchArgs,
)
from admino.oauth import OAuthError, get_valid_access_token
from admino.tools.registry import register_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state for OAuth token caching and HTTP client
# ---------------------------------------------------------------------------

_http_client: httpx.AsyncClient | None = None
_cached_token: str | None = None
_cached_expires_at: datetime | None = None
_token_lock = asyncio.Lock()

_DRIVE_API_BASE = "https://www.googleapis.com/drive/v3"


async def _get_google_token() -> str:
    """Obtain a valid Google OAuth access token, refreshing if needed.

    Returns:
        A valid access token string.

    Raises:
        OAuthError: If no token file exists or refresh fails.
    """
    from admino.database import get_pool

    async with _token_lock:
        global _http_client, _cached_token, _cached_expires_at
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        _cached_token, _cached_expires_at = await get_valid_access_token(
            get_pool(), "google", _cached_token, _cached_expires_at, _http_client
        )
        return _cached_token


async def clear_token_cache() -> None:
    """Reset the in-memory cached access token.

    Acquires ``_token_lock`` to avoid clearing the cache while a
    concurrent tool call is mid-refresh. Called by the OAuth disconnect
    endpoint to ensure stale tokens are not reused after the user
    disconnects their Google account.
    """
    async with _token_lock:
        global _cached_token, _cached_expires_at
        _cached_token = None
        _cached_expires_at = None


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
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
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
    if args.folder_id:
        # Model-level pattern validation rejects single quotes and backslashes.
        # Defence-in-depth: escape any that slip through.
        safe_folder_id = args.folder_id.replace("\\", "\\\\").replace("'", "\\'")
        parent = f"'{safe_folder_id}'"
    else:
        parent = "'root'"
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
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
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
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
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
