"""Outlook mail tool using Microsoft Graph API.

Provides read, list, and search actions for Outlook messages via the
Microsoft Graph ``/me/messages`` endpoints. Authentication is handled
via OAuth tokens managed by ``admino.oauth``.

Security notes:
- No send or delete capabilities. outlook.send and outlook.delete are
  hardcoded denials in permissions.py.
- Message body content is truncated to 10 000 characters before returning.
- OAuth tokens are cached in-memory only; refresh tokens stay encrypted on disk.
- No eval, exec, shell=True, or importlib.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Final

import httpx

if TYPE_CHECKING:
    from datetime import datetime

from admino.models import OutlookListArgs, OutlookReadArgs, OutlookSearchArgs
from admino.oauth import OAuthError, get_valid_access_token
from admino.tools.registry import register_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GRAPH_BASE: Final[str] = "https://graph.microsoft.com/v1.0"
_MAX_BODY_CHARS: Final[int] = 10_000

# ---------------------------------------------------------------------------
# Module-level token cache
# ---------------------------------------------------------------------------

_TOKENS_DIR = Path(os.environ.get("TOKENS_DIR", "/app/data/tokens"))
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
    async with _token_lock:
        global _http_client, _cached_token, _cached_expires_at
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        _cached_token, _cached_expires_at = await get_valid_access_token(
            _TOKENS_DIR, "microsoft", _cached_token, _cached_expires_at, _http_client
        )
        return _cached_token


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


def _format_message_summary(msg: dict[str, object]) -> str:
    """Format a message dict into a human-readable summary line.

    Args:
        msg: A message object from Microsoft Graph.

    Returns:
        A formatted string with message metadata.
    """
    msg_id = msg.get("id", "unknown")
    subject = msg.get("subject", "(no subject)")
    received = msg.get("receivedDateTime", "unknown date")
    from_field = msg.get("from", {})
    from_email = ""
    if isinstance(from_field, dict):
        email_addr = from_field.get("emailAddress", {})
        if isinstance(email_addr, dict):
            from_email = str(email_addr.get("address", "unknown"))
    preview = msg.get("bodyPreview", "")
    preview_str = str(preview)[:200] if preview else ""
    return (
        f"ID: {msg_id}\n"
        f"Subject: {subject}\n"
        f"From: {from_email}\n"
        f"Date: {received}\n"
        f"Preview: {preview_str}"
    )


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@register_tool(
    tool="outlook",
    action="read",
    description=(
        "Read a single Outlook email message by ID. Returns subject, sender, date, and body."
    ),
    args_schema=OutlookReadArgs,
)
async def outlook_read(args: OutlookReadArgs, **kwargs: object) -> str:
    """Read a single Outlook message by ID.

    Args:
        args: Validated read arguments (message_id).

    Returns:
        Formatted message content, or an error string.
    """
    try:
        token = await _get_microsoft_token()
    except OAuthError:
        return "OAuth not configured. Run: python -m admino.oauth_setup microsoft"

    url = (
        f"{_GRAPH_BASE}/me/messages/{args.message_id}"
        "?$select=id,subject,from,receivedDateTime,bodyPreview,body"
    )
    try:
        response = await _http_client.get(  # type: ignore[union-attr]
            url,
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error reading Outlook message: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        msg = response.json()
    except (ValueError, TypeError):
        return "Failed to parse Microsoft Graph response."

    subject = msg.get("subject", "(no subject)")
    received = msg.get("receivedDateTime", "unknown date")
    from_field = msg.get("from", {})
    from_email = ""
    if isinstance(from_field, dict):
        email_addr = from_field.get("emailAddress", {})
        if isinstance(email_addr, dict):
            from_email = str(email_addr.get("address", "unknown"))

    body_obj = msg.get("body", {})
    body_content = ""
    if isinstance(body_obj, dict):
        body_content = str(body_obj.get("content", ""))
    if len(body_content) > _MAX_BODY_CHARS:
        body_content = body_content[:_MAX_BODY_CHARS] + "\n\n[Truncated]"

    return f"Subject: {subject}\nFrom: {from_email}\nDate: {received}\nBody:\n{body_content}"


@register_tool(
    tool="outlook",
    action="list",
    description="List recent Outlook email messages, ordered by date descending.",
    args_schema=OutlookListArgs,
)
async def outlook_list(args: OutlookListArgs, **kwargs: object) -> str:
    """List recent Outlook messages.

    Args:
        args: Validated list arguments (max_results).

    Returns:
        Formatted list of messages, or an error string.
    """
    try:
        token = await _get_microsoft_token()
    except OAuthError:
        return "OAuth not configured. Run: python -m admino.oauth_setup microsoft"

    url = (
        f"{_GRAPH_BASE}/me/messages"
        f"?$top={args.max_results}"
        "&$select=id,subject,from,receivedDateTime,bodyPreview"
        "&$orderby=receivedDateTime desc"
    )
    try:
        response = await _http_client.get(  # type: ignore[union-attr]
            url,
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error listing Outlook messages: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        data = response.json()
    except (ValueError, TypeError):
        return "Failed to parse Microsoft Graph response."

    messages = data.get("value", [])
    if not isinstance(messages, list) or not messages:
        return "No messages found."

    parts: list[str] = []
    for msg in messages:
        if isinstance(msg, dict):
            parts.append(_format_message_summary(msg))
    if not parts:
        return "No messages found."
    return "\n---\n".join(parts)


@register_tool(
    tool="outlook",
    action="search",
    description="Search Outlook email messages using KQL query syntax.",
    args_schema=OutlookSearchArgs,
)
async def outlook_search(args: OutlookSearchArgs, **kwargs: object) -> str:
    """Search Outlook messages using KQL.

    Args:
        args: Validated search arguments (query, max_results).

    Returns:
        Formatted list of matching messages, or an error string.
    """
    try:
        token = await _get_microsoft_token()
    except OAuthError:
        return "OAuth not configured. Run: python -m admino.oauth_setup microsoft"

    # $search uses KQL syntax; the query is wrapped in double quotes in the URL.
    # Escape double-quotes and backslashes to prevent KQL injection / OData
    # query option injection via crafted query strings.
    safe_query = args.query.replace("\\", "\\\\").replace('"', '\\"')
    url = (
        f"{_GRAPH_BASE}/me/messages"
        f'?$search="{safe_query}"'
        f"&$top={args.max_results}"
        "&$select=id,subject,from,receivedDateTime,bodyPreview"
    )
    try:
        response = await _http_client.get(  # type: ignore[union-attr]
            url,
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error searching Outlook messages: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        data = response.json()
    except (ValueError, TypeError):
        return "Failed to parse Microsoft Graph response."

    messages = data.get("value", [])
    if not isinstance(messages, list) or not messages:
        return "No messages found matching the search query."

    parts: list[str] = []
    for msg in messages:
        if isinstance(msg, dict):
            parts.append(_format_message_summary(msg))
    if not parts:
        return "No messages found matching the search query."
    return "\n---\n".join(parts)
