"""OneDrive tool using Microsoft Graph API.

Provides read, list, and search actions for OneDrive files via the Microsoft
Graph ``/me/drive`` endpoints, in the calling user's own Microsoft account
(per-user connections, GH-162).

The download action is not registered: it wrote into the removed local files
tool's host directories (GH-143) and returns as chat attachments with #192. Its
``onedrive.download`` permission row stays at ``confirm`` for that reason;
until then, dispatch rejects the call as an unknown tool.

Inputs: the validated args (``OneDriveReadArgs``, ``OneDriveListArgs``,
``OneDriveSearchArgs``) and the required keyword ``tenant`` (the run's
``TenantContext``, passed by ``registry.dispatch_tool_call``). Outputs: the
formatted item metadata or listing, or a user-facing error string.

Security notes:
- Per-user tokens: every API request of a handler call carries the access
  token of that call's tenant, from ``_get_microsoft_token(tenant)``, which
  reads the shared per-user cache ``oauth.access_tokens`` (keyed by user and
  provider). The tenant comes from the server-side session, never from LLM
  arguments. The module keeps no token state of its own; refresh tokens
  never leave oauth.py, and no token is logged.
- No delete capability. onedrive.delete is a hardcoded denial in permissions.py.
- Read-only: no action writes to the local filesystem or to OneDrive.
- No eval, exec, shell=True, or importlib.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Final
from urllib.parse import quote

import httpx

from admino import database
from admino.models import (
    OneDriveListArgs,
    OneDriveReadArgs,
    OneDriveSearchArgs,
)
from admino.oauth import OAuthError, access_tokens
from admino.tools.registry import register_tool

if TYPE_CHECKING:
    from admino.tenancy import TenantContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GRAPH_BASE: Final[str] = "https://graph.microsoft.com/v1.0"

# The module's HTTP client (created on first use). It holds no credentials:
# each request sets its own caller's Authorization header.
_http_client: httpx.AsyncClient | None = None


def _client() -> httpx.AsyncClient:
    """Return the module's HTTP client, creating it on first use."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
    return _http_client


async def _get_microsoft_token(tenant: TenantContext) -> str:
    """Obtain a valid Microsoft access token for the tenant's own connection.

    Args:
        tenant: The handler call's tool context; its user's token is used.

    Returns:
        A valid access token string.

    Raises:
        OAuthError: If the user has no Microsoft connection or refresh fails.
    """
    return await access_tokens.get(database.get_pool(), tenant, "microsoft", _client())


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
async def onedrive_read(args: OneDriveReadArgs, *, tenant: TenantContext, **_: object) -> str:
    """Read metadata for a OneDrive item by ID.

    Args:
        args: Validated read arguments (item_id).
        tenant: The caller's tool context (whose OneDrive is read).

    Returns:
        Formatted item metadata, or an error string.
    """
    try:
        token = await _get_microsoft_token(tenant)
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
        response = await _client().get(
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
async def onedrive_list(args: OneDriveListArgs, *, tenant: TenantContext, **_: object) -> str:
    """List items in a OneDrive folder.

    Args:
        args: Validated list arguments (folder_path, max_results).
        tenant: The caller's tool context (whose OneDrive is listed).

    Returns:
        Formatted list of items, or an error string.
    """
    try:
        token = await _get_microsoft_token(tenant)
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
        response = await _client().get(
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
async def onedrive_search(args: OneDriveSearchArgs, *, tenant: TenantContext, **_: object) -> str:
    """Search for files in OneDrive.

    Args:
        args: Validated search arguments (query, max_results).
        tenant: The caller's tool context (whose OneDrive is searched).

    Returns:
        Formatted list of matching items, or an error string.
    """
    try:
        token = await _get_microsoft_token(tenant)
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
        response = await _client().get(
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
