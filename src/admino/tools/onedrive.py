"""OneDrive tool using Microsoft Graph API.

Provides read, list, search, and download actions for OneDrive files via
the Microsoft Graph ``/me/drive`` endpoints. Authentication is handled
via OAuth tokens managed by ``admino.oauth``.

Security notes:
- No delete capability. onedrive.delete is a hardcoded denial in permissions.py.
- Download destination paths are validated against allowed_paths via the
  files tool's ``_validate_path`` function.
- OAuth tokens are cached in-memory only; refresh tokens stay encrypted on disk.
- No eval, exec, shell=True, or importlib.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING, Final
from urllib.parse import quote, urlparse

import httpx

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

from admino.models import (
    OneDriveDownloadArgs,
    OneDriveListArgs,
    OneDriveReadArgs,
    OneDriveSearchArgs,
)
from admino.oauth import OAuthError, get_valid_access_token
from admino.tools.files import _revalidate_resolved, _validate_path
from admino.tools.registry import register_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GRAPH_BASE: Final[str] = "https://graph.microsoft.com/v1.0"
_MAX_DOWNLOAD_SIZE: Final[int] = 100 * 1024 * 1024  # 100 MB
# Safe redirect hosts for OneDrive /content 302 responses (Azure blob CDN).
_SAFE_REDIRECT_SUFFIXES: Final[tuple[str, ...]] = (
    ".windows.net",
    ".microsoftonline.com",
    ".azure.com",
    ".sharepoint.com",
)

# ---------------------------------------------------------------------------
# Module-level token cache
# ---------------------------------------------------------------------------

_http_client: httpx.AsyncClient | None = None
_cached_token: str | None = None
_cached_expires_at: datetime | None = None
_token_lock = asyncio.Lock()


async def _get_microsoft_token() -> str:
    """Obtain a valid Microsoft access token, refreshing if needed.

    Returns:
        A valid access token string.

    Raises:
        OAuthError: If OAuth is not configured or refresh fails.
    """
    from admino.database import get_pool

    async with _token_lock:
        global _http_client, _cached_token, _cached_expires_at
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        _cached_token, _cached_expires_at = await get_valid_access_token(
            get_pool(), "microsoft", _cached_token, _cached_expires_at, _http_client
        )
        return _cached_token


async def clear_token_cache() -> None:
    """Reset the in-memory cached access token.

    Acquires ``_token_lock`` to avoid clearing the cache while a
    concurrent tool call is mid-refresh. Called by the OAuth disconnect
    endpoint to ensure stale tokens are not reused after the user
    disconnects their Microsoft account.
    """
    async with _token_lock:
        global _cached_token, _cached_expires_at
        _cached_token = None
        _cached_expires_at = None


def _extract_graph_error(response: httpx.Response) -> str:
    """Extract a human-readable error message from a Microsoft Graph error response.

    Args:
        response: The HTTP response from Microsoft Graph.

    Returns:
        A safe error string (no credentials).
    """
    try:
        body = response.json()
        if isinstance(body, dict):
            error = body.get("error", {})
            if isinstance(error, dict):
                message = error.get("message", "Unknown error")
                return str(message)[:500]
    except (ValueError, TypeError):
        pass
    return f"HTTP {response.status_code}"


def _format_item_summary(item: dict[str, object]) -> str:
    """Format a OneDrive item dict into a human-readable summary line.

    Args:
        item: A drive item object from Microsoft Graph.

    Returns:
        A formatted string with item metadata.
    """
    item_id = item.get("id", "unknown")
    name = item.get("name", "(unnamed)")
    size = item.get("size", 0)
    modified = item.get("lastModifiedDateTime", "unknown")

    item_type = "folder" if "folder" in item else "file"
    size_str = _human_readable_size(int(size)) if isinstance(size, int | float) else "unknown"

    return f"ID: {item_id}\nName: {name}\nType: {item_type}\nSize: {size_str}\nModified: {modified}"


def _human_readable_size(size_bytes: int) -> str:
    """Convert byte count to human-readable string.

    Args:
        size_bytes: File size in bytes.

    Returns:
        Human-readable size string (e.g. '1.5 MB').
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    for unit in ("KB", "MB", "GB", "TB"):
        size_bytes_f = size_bytes / 1024
        if size_bytes_f < 1024 or unit == "TB":
            return f"{size_bytes_f:.1f} {unit}"
        size_bytes = int(size_bytes_f)
    return f"{size_bytes} B"


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@register_tool(
    tool="onedrive",
    action="read",
    description="Read OneDrive file or folder metadata by item ID.",
    args_schema=OneDriveReadArgs,
)
async def onedrive_read(args: OneDriveReadArgs, **kwargs: object) -> str:
    """Read metadata for a OneDrive item by ID.

    Args:
        args: Validated read arguments (item_id).

    Returns:
        Formatted item metadata, or an error string.
    """
    try:
        token = await _get_microsoft_token()
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    # URL-encode the ID: Graph item IDs contain =, +, /, ! and must not alter
    # the request path. safe="" encodes every reserved character.
    item_id = quote(args.item_id, safe="")
    url = (
        f"{_GRAPH_BASE}/me/drive/items/{item_id}"
        "?$select=id,name,size,createdDateTime,lastModifiedDateTime,webUrl,file,folder"
    )
    try:
        response = await _http_client.get(  # type: ignore[union-attr]
            url,
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error reading OneDrive item: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        item = response.json()
    except (ValueError, TypeError):
        return "Failed to parse Microsoft Graph response."

    item_type = "folder" if "folder" in item else "file"
    size = item.get("size", 0)
    size_str = _human_readable_size(int(size)) if isinstance(size, int | float) else "unknown"

    return (
        f"Name: {item.get('name', '(unnamed)')}\n"
        f"Type: {item_type}\n"
        f"Size: {size_str}\n"
        f"Created: {item.get('createdDateTime', 'unknown')}\n"
        f"Modified: {item.get('lastModifiedDateTime', 'unknown')}\n"
        f"Web URL: {item.get('webUrl', '')}"
    )


@register_tool(
    tool="onedrive",
    action="list",
    description="List items in a OneDrive folder. Lists root if no folder path is given.",
    args_schema=OneDriveListArgs,
)
async def onedrive_list(args: OneDriveListArgs, **kwargs: object) -> str:
    """List items in a OneDrive folder.

    Args:
        args: Validated list arguments (folder_path, max_results).

    Returns:
        Formatted list of items, or an error string.
    """
    try:
        token = await _get_microsoft_token()
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    if args.folder_path:
        # Reject path traversal attempts before any URL construction
        if ".." in args.folder_path.split("/"):
            return "Folder path rejected: '..' path components are not allowed."
        # URL-encode folder_path to prevent path traversal and query injection.
        # safe="/" preserves path separators; all other special chars are encoded.
        safe_path = quote(args.folder_path, safe="/")
        url = f"{_GRAPH_BASE}/me/drive/root:/{safe_path}:/children"
    else:
        url = f"{_GRAPH_BASE}/me/drive/root/children"

    params: dict[str, str | int] = {
        "$top": args.max_results,
        "$select": "id,name,size,lastModifiedDateTime,file,folder",
    }
    try:
        response = await _http_client.get(  # type: ignore[union-attr]
            url,
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error listing OneDrive items: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        data = response.json()
    except (ValueError, TypeError):
        return "Failed to parse Microsoft Graph response."

    items = data.get("value", [])
    if not isinstance(items, list) or not items:
        return "No items found in this folder."

    parts: list[str] = []
    for item in items:
        if isinstance(item, dict):
            parts.append(_format_item_summary(item))
    if not parts:
        return "No items found in this folder."
    return "\n---\n".join(parts)


@register_tool(
    tool="onedrive",
    action="search",
    description="Search for files in OneDrive by query string.",
    args_schema=OneDriveSearchArgs,
)
async def onedrive_search(args: OneDriveSearchArgs, **kwargs: object) -> str:
    """Search for files in OneDrive.

    Args:
        args: Validated search arguments (query, max_results).

    Returns:
        Formatted list of matching items, or an error string.
    """
    try:
        token = await _get_microsoft_token()
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    # Model-level pattern validation rejects single quotes and backslashes.
    # Defence-in-depth: escape any that slip through.
    safe_query = args.query.replace("\\", "\\\\").replace("'", "\\'")
    url = f"{_GRAPH_BASE}/me/drive/root/search(q='{safe_query}')"
    params: dict[str, str | int] = {
        "$top": args.max_results,
        "$select": "id,name,size,lastModifiedDateTime,file,folder",
    }
    try:
        response = await _http_client.get(  # type: ignore[union-attr]
            url,
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error searching OneDrive: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        data = response.json()
    except (ValueError, TypeError):
        return "Failed to parse Microsoft Graph response."

    items = data.get("value", [])
    if not isinstance(items, list) or not items:
        return "No files found matching the search query."

    parts: list[str] = []
    for item in items:
        if isinstance(item, dict):
            parts.append(_format_item_summary(item))
    if not parts:
        return "No files found matching the search query."
    return "\n---\n".join(parts)


def _sync_write_download(destination: Path, content: bytes) -> None:
    """Write downloaded content to a validated destination path.

    Creates parent directories if needed. Uses O_EXCL to prevent
    overwriting existing files (create-only, matching files.write behavior).

    Args:
        destination: The validated destination path.
        content: The file content bytes.

    Raises:
        FileExistsError: If the destination file already exists.
    """
    # TOCTOU defence: re-validate path hasn't changed since async validation.
    _revalidate_resolved(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        str(destination),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
    )
    try:
        os.write(fd, content)
    finally:
        os.close(fd)


@register_tool(
    tool="onedrive",
    action="download",
    description=(
        "Download a OneDrive file to a local path. Destination must be in "
        "an allowed writable directory. Requires user confirmation."
    ),
    args_schema=OneDriveDownloadArgs,
)
async def onedrive_download(args: OneDriveDownloadArgs, **kwargs: object) -> str:
    """Download a OneDrive file to a local path.

    The destination path is validated against the allowed_paths configuration
    from the files tool to prevent writes outside approved directories.

    Args:
        args: Validated download arguments (item_id, destination).

    Returns:
        Confirmation message, or an error string.
    """
    # Validate destination path against allowed paths (requires write access)
    try:
        validated_dest = _validate_path(args.destination, require_write=True)
    except (PermissionError, ValueError) as exc:
        return f"Destination path rejected: {exc}"

    # Refuse to overwrite existing files (consistent with files.write)
    if os.path.lexists(str(validated_dest)):
        return (
            f"Cannot download to {validated_dest}: a file or directory already "
            "exists at that path. Please choose a different destination."
        )

    try:
        token = await _get_microsoft_token()
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    # URL-encode the ID: Graph item IDs contain =, +, /, ! and must not alter
    # the request path. safe="" encodes every reserved character.
    item_id = quote(args.item_id, safe="")
    url = f"{_GRAPH_BASE}/me/drive/items/{item_id}/content"
    try:
        # Do NOT pass Authorization header with follow_redirects=True.
        # Microsoft Graph /content returns a 302 to Azure blob storage;
        # forwarding the Bearer token to a third-party host leaks credentials.
        initial = await _http_client.get(  # type: ignore[union-attr]
            url,
            headers={"Authorization": f"Bearer {token}"},
        )
        if initial.status_code in (301, 302, 303, 307, 308):
            redirect_url = initial.headers.get("location", "")
            if not redirect_url:
                return "Microsoft Graph returned a redirect with no Location header."
            # SSRF defence: only follow redirects to known Azure CDN hosts.
            parsed_redirect = urlparse(redirect_url)
            if parsed_redirect.scheme != "https" or not any(
                parsed_redirect.netloc.endswith(suffix) for suffix in _SAFE_REDIRECT_SUFFIXES
            ):
                logger.warning("Blocked unsafe OneDrive redirect: %s", parsed_redirect.netloc)
                return "OneDrive returned an unsafe redirect location."
            # Follow the redirect WITHOUT the Authorization header
            response = await _http_client.get(redirect_url)  # type: ignore[union-attr]
        else:
            response = initial
    except httpx.HTTPError as exc:
        logger.error("HTTP error downloading OneDrive file: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    # Check Content-Length header before reading body to avoid OOM
    content_length = response.headers.get("content-length")
    try:
        cl_int = int(content_length) if content_length else None
    except (ValueError, TypeError):
        cl_int = None
    if cl_int is not None and cl_int > _MAX_DOWNLOAD_SIZE:
        return (
            f"File is too large to download ({cl_int} bytes, limit is {_MAX_DOWNLOAD_SIZE} bytes)."
        )

    content = response.content
    if len(content) > _MAX_DOWNLOAD_SIZE:
        return (
            f"File is too large to download "
            f"({len(content)} bytes, limit is {_MAX_DOWNLOAD_SIZE} bytes)."
        )

    try:
        await asyncio.to_thread(_sync_write_download, validated_dest, content)
    except FileExistsError:
        return (
            f"Cannot download to {validated_dest}: a file was created at that "
            "path concurrently. Please choose a different destination."
        )
    except OSError as exc:
        logger.error("Failed to write downloaded file: %s", type(exc).__name__)
        return f"Failed to write file to {validated_dest}."

    size_str = _human_readable_size(len(content))
    return f"Downloaded {size_str} to {validated_dest}"
