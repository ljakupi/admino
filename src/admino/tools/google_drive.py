"""Google Drive tool for reading, listing, and searching files via Drive API v3.

Provides read (metadata), list, and search actions for Google Drive files in
the calling user's own Google account (per-user connections, GH-162).

The download action is not registered: it wrote into the removed local files
tool's host directories (GH-143) and returns as chat attachments with #192. Its
``google_drive.download`` permission row stays at ``confirm`` for that reason;
until then, dispatch rejects the call as an unknown tool.

Inputs: the validated args (``GoogleDriveReadArgs``, ``GoogleDriveListArgs``,
``GoogleDriveSearchArgs``) and the required keyword ``tenant`` (the run's
``TenantContext``, passed by ``registry.dispatch_tool_call``). Outputs: the
formatted file metadata or listing, wrapped as untrusted file content
(GH-243), or a user-facing error string.

Security notes:
- Per-user tokens: every API request of a handler call carries the access
  token of that call's tenant, from ``_get_google_token(tenant)``, which
  reads the shared per-user cache ``oauth.access_tokens`` (keyed by user and
  provider). The tenant comes from the server-side session, never from LLM
  arguments. The module keeps no token state of its own; refresh tokens
  never leave oauth.py, and no token is logged.
- No delete capability. google_drive.delete is a hardcoded denial in
  permissions.py.
- Read-only: no action writes to the local filesystem or to Drive.
- Untrusted content (GH-243): file names and metadata are third-party text,
  so every read/list/search success result reaches the model only through
  ``untrusted.wrap`` (kind ``file``), and the agent escalates the run's later
  side effects to confirmation. The read label names the validated
  ``file_id`` argument. Error and "nothing found" strings stay unwrapped.
- No eval, exec, shell=True, or importlib.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from admino import database, untrusted
from admino.models import (
    GoogleDriveListArgs,
    GoogleDriveReadArgs,
    GoogleDriveSearchArgs,
)
from admino.oauth import OAuthError, access_tokens
from admino.tools.registry import register_tool

if TYPE_CHECKING:
    from admino.tenancy import TenantContext

logger = logging.getLogger(__name__)

# The module's HTTP client (created on first use). It holds no credentials:
# each request sets its own caller's Authorization header.
_http_client: httpx.AsyncClient | None = None

_DRIVE_API_BASE = "https://www.googleapis.com/drive/v3"


def _client() -> httpx.AsyncClient:
    """Return the module's HTTP client, creating it on first use."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
    return _http_client


async def _get_google_token(tenant: TenantContext) -> str:
    """Obtain a valid Google access token for the tenant's own connection.

    Args:
        tenant: The handler call's tool context; its user's token is used.

    Returns:
        A valid access token string.

    Raises:
        OAuthError: If the user has no Google connection or refresh fails.
    """
    return await access_tokens.get(database.get_pool(), tenant, "google", _client())


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
    side_effect=False,
)
async def google_drive_read(
    args: GoogleDriveReadArgs, *, tenant: TenantContext, **_: object
) -> str:
    """Read metadata for a single Google Drive file.

    Args:
        args: Validated read arguments (file_id).
        tenant: The caller's tool context (whose Drive is read).

    Returns:
        The formatted file metadata, wrapped as untrusted file content, or an
        error string.
    """
    fields = "id,name,mimeType,size,createdTime,modifiedTime,webViewLink"
    try:
        token = await _get_google_token(tenant)
        response = await _client().get(
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

    return untrusted.wrap(
        "file",
        f"google drive file {args.file_id}",
        f"Name: {data.get('name', 'Untitled')}\n"
        f"ID: {data.get('id', 'unknown')}\n"
        f"Type: {data.get('mimeType', 'unknown')}\n"
        f"Size: {data.get('size', 'N/A')}\n"
        f"Created: {data.get('createdTime', 'N/A')}\n"
        f"Modified: {data.get('modifiedTime', 'N/A')}\n"
        f"Link: {data.get('webViewLink', 'N/A')}",
    )


@register_tool(
    tool="google_drive",
    action="list",
    description="List files in a Google Drive folder. If no folder ID given, lists root.",
    args_schema=GoogleDriveListArgs,
    side_effect=False,
)
async def google_drive_list(
    args: GoogleDriveListArgs, *, tenant: TenantContext, **_: object
) -> str:
    """List files in a Google Drive folder.

    Args:
        args: Validated list arguments (folder_id, max_results).
        tenant: The caller's tool context (whose Drive is listed).

    Returns:
        The formatted list of files in the folder, wrapped as untrusted file
        content, a "nothing found" message or an error string.
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
        token = await _get_google_token(tenant)
        response = await _client().get(
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

    return untrusted.wrap("file", "google drive files", "\n".join(lines).rstrip())


@register_tool(
    tool="google_drive",
    action="search",
    description="Search for files in Google Drive by text query.",
    args_schema=GoogleDriveSearchArgs,
    side_effect=False,
)
async def google_drive_search(
    args: GoogleDriveSearchArgs, *, tenant: TenantContext, **_: object
) -> str:
    """Search Google Drive files by full-text query.

    Args:
        args: Validated search arguments (query, max_results).
        tenant: The caller's tool context (whose Drive is searched).

    Returns:
        The formatted list of matching files, wrapped as untrusted file
        content, a "nothing found" message or an error string.
    """
    # Model-level pattern validation rejects single quotes and backslashes.
    # Defence-in-depth: escape any that slip through.
    safe_query = args.query.replace("\\", "\\\\").replace("'", "\\'")
    query = f"fullText contains '{safe_query}'"
    fields = "files(id,name,mimeType,size,modifiedTime)"

    try:
        token = await _get_google_token(tenant)
        response = await _client().get(
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

    return untrusted.wrap("file", "google drive search results", "\n".join(lines).rstrip())
