"""Gmail tool for reading, listing, searching, and sending emails via Google Gmail API v1.

Provides read, list, search, and send actions for Gmail messages using the
authenticated user's account. OAuth tokens are managed by admino.oauth.

Security notes:
- gmail.send is a tier-2 promotable denial in permissions.py. It is denied
  by default and requires explicit user promotion + cooldown before use.
  gmail.delete remains a hardcoded immutable denial.
- OAuth tokens are cached in module-level state; refresh tokens never appear
  in memory outside oauth.py.
- Email body content is truncated to 10000 characters to prevent LLM context
  overflow.
- RFC 2822 message construction uses stdlib email.message.EmailMessage to
  prevent header injection.
- No eval, exec, shell=True, or importlib.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from datetime import datetime

from admino.models import GmailListArgs, GmailReadArgs, GmailSearchArgs, GmailSendArgs
from admino.oauth import OAuthError, get_valid_access_token
from admino.tools.registry import register_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state for OAuth token caching and HTTP client
# NOTE: Each Google tool module (gmail, google_calendar, google_drive) maintains
# its own token cache. Under concurrent requests, multiple modules may refresh
# the same token independently. This is a known design limitation; each refresh
# is individually correct but may produce redundant refreshes. A shared token
# cache module would eliminate this but is deferred for simplicity.
# ---------------------------------------------------------------------------

_TOKENS_DIR = Path(os.environ.get("TOKENS_DIR", "/app/data/tokens"))
_http_client: httpx.AsyncClient | None = None
_cached_token: str | None = None
_cached_expires_at: datetime | None = None
_token_lock = asyncio.Lock()

_GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
_MAX_BODY_CHARS = 10_000


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


async def _google_get(url: str, params: dict[str, str] | None = None) -> httpx.Response:
    """Perform an authenticated GET request to the Google API.

    Args:
        url: Full URL to request.
        params: Optional query parameters.

    Returns:
        The httpx Response object.

    Raises:
        OAuthError: If token retrieval fails.
    """
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
    token = await _get_google_token()
    return await _http_client.get(url, params=params, headers=_auth_headers(token))


def _extract_header(headers: list[dict[str, str]], name: str) -> str:
    """Extract a header value from a Gmail message headers list.

    Args:
        headers: List of {"name": ..., "value": ...} dicts from the API.
        name: Header name to find (case-insensitive).

    Returns:
        The header value, or empty string if not found.
    """
    name_lower = name.lower()
    for header in headers:
        if header.get("name", "").lower() == name_lower:
            return header.get("value", "")
    return ""


def _extract_text_body(payload: dict[str, object]) -> str:
    """Extract text/plain body from a Gmail message payload.

    Recursively searches multipart payloads for a text/plain part.
    Falls back to empty string if no text/plain part is found.

    Args:
        payload: The message payload dict from the Gmail API.

    Returns:
        The decoded text body, or empty string.
    """
    mime_type = payload.get("mimeType", "")

    # Direct text/plain part
    if mime_type == "text/plain":
        body = payload.get("body", {})
        if isinstance(body, dict):
            data = body.get("data", "")
            if isinstance(data, str) and data:
                try:
                    return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
                except (ValueError, UnicodeDecodeError):
                    return ""
        return ""

    # Multipart: recurse into parts
    parts = payload.get("parts")
    if isinstance(parts, list):
        for part in parts:
            if isinstance(part, dict):
                text = _extract_text_body(part)
                if text:
                    return text

    return ""


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


async def _fetch_message_headers(message_id: str) -> dict[str, str]:
    """Fetch subject, from, and date headers for a single message.

    Args:
        message_id: Gmail message ID.

    Returns:
        Dict with keys 'id', 'subject', 'from', 'date'.
    """
    url = f"{_GMAIL_API_BASE}/messages/{message_id}"
    params = {
        "format": "metadata",
        "metadataHeaders": ["Subject", "From", "Date"],
    }
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
    token = await _get_google_token()
    response = await _http_client.get(url, params=params, headers=_auth_headers(token))

    if response.status_code != 200:
        return {"id": message_id, "subject": "[error]", "from": "", "date": ""}

    data = response.json()
    headers = data.get("payload", {}).get("headers", [])
    if not isinstance(headers, list):
        headers = []

    return {
        "id": message_id,
        "subject": _extract_header(headers, "Subject"),
        "from": _extract_header(headers, "From"),
        "date": _extract_header(headers, "Date"),
    }


def _format_message_list(messages: list[dict[str, str]]) -> str:
    """Format a list of message header dicts into a readable string.

    Args:
        messages: List of dicts with keys 'id', 'subject', 'from', 'date'.

    Returns:
        Formatted string with one message per block.
    """
    if not messages:
        return "No messages found."

    lines: list[str] = []
    for msg in messages:
        lines.append(
            f"ID: {msg['id']}\n"
            f"  From: {msg['from']}\n"
            f"  Subject: {msg['subject']}\n"
            f"  Date: {msg['date']}"
        )
    return "\n\n".join(lines)


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@register_tool(
    tool="gmail",
    action="read",
    description="Read a single email by message ID. Returns subject, from, date, and body text.",
    args_schema=GmailReadArgs,
)
async def gmail_read(args: GmailReadArgs, **kwargs: object) -> str:
    """Read a single Gmail message by ID.

    Fetches the full message and extracts subject, from, date, snippet,
    and text/plain body. Body is truncated to 10000 characters.

    Args:
        args: Validated read arguments (message_id).

    Returns:
        Formatted message content string.
    """
    try:
        response = await _google_get(
            f"{_GMAIL_API_BASE}/messages/{args.message_id}",
            params={"format": "full"},
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    data = response.json()
    payload = data.get("payload", {})
    headers = payload.get("headers", [])
    if not isinstance(headers, list):
        headers = []

    subject = _extract_header(headers, "Subject")
    from_addr = _extract_header(headers, "From")
    date = _extract_header(headers, "Date")
    snippet = data.get("snippet", "")

    # Extract body text, preferring text/plain
    body = _extract_text_body(payload) if isinstance(payload, dict) else ""
    if not body:
        body = str(snippet)

    # Truncate body to limit
    if len(body) > _MAX_BODY_CHARS:
        body = body[:_MAX_BODY_CHARS] + f"\n\n[Truncated at {_MAX_BODY_CHARS} characters]"

    return (
        f"Subject: {subject}\nFrom: {from_addr}\nDate: {date}\nSnippet: {snippet}\n\nBody:\n{body}"
    )


@register_tool(
    tool="gmail",
    action="list",
    description="List recent emails. Returns subject, from, and date for each message.",
    args_schema=GmailListArgs,
)
async def gmail_list(args: GmailListArgs, **kwargs: object) -> str:
    """List recent Gmail messages.

    Fetches message IDs, then batch-fetches headers for each.

    Args:
        args: Validated list arguments (max_results).

    Returns:
        Formatted list of messages with headers.
    """
    try:
        response = await _google_get(
            f"{_GMAIL_API_BASE}/messages",
            params={"maxResults": str(args.max_results)},
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    data = response.json()
    message_refs = data.get("messages", [])
    if not isinstance(message_refs, list) or not message_refs:
        return "No messages found."

    # Fetch headers for each message
    messages: list[dict[str, str]] = []
    for ref in message_refs:
        if isinstance(ref, dict) and "id" in ref:
            try:
                msg = await _fetch_message_headers(str(ref["id"]))
                messages.append(msg)
            except (OAuthError, httpx.HTTPError):
                continue

    return _format_message_list(messages)


@register_tool(
    tool="gmail",
    action="search",
    description="Search emails by query. Returns subject, from, and date for matching messages.",
    args_schema=GmailSearchArgs,
)
async def gmail_search(args: GmailSearchArgs, **kwargs: object) -> str:
    """Search Gmail messages by query.

    Uses Gmail's search query syntax (same as the Gmail web UI search bar).
    Fetches matching message IDs, then batch-fetches headers for each.

    Args:
        args: Validated search arguments (query, max_results).

    Returns:
        Formatted list of matching messages with headers.
    """
    try:
        response = await _google_get(
            f"{_GMAIL_API_BASE}/messages",
            params={"q": args.query, "maxResults": str(args.max_results)},
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    data = response.json()
    message_refs = data.get("messages", [])
    if not isinstance(message_refs, list) or not message_refs:
        return "No messages found matching the query."

    # Fetch headers for each message
    messages: list[dict[str, str]] = []
    for ref in message_refs:
        if isinstance(ref, dict) and "id" in ref:
            try:
                msg = await _fetch_message_headers(str(ref["id"]))
                messages.append(msg)
            except (OAuthError, httpx.HTTPError):
                continue

    return _format_message_list(messages)


# ---------------------------------------------------------------------------
# gmail.send
# ---------------------------------------------------------------------------


def _build_rfc2822(args: GmailSendArgs) -> str:
    """Build an RFC 2822 email message and return it as base64url-encoded string.

    Uses stdlib ``email.message.EmailMessage`` which safely encodes headers
    and prevents header injection.

    Args:
        args: Validated send arguments.

    Returns:
        Base64url-encoded RFC 2822 message string (no padding).
    """
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["To"] = ", ".join(args.to)
    if args.cc:
        msg["Cc"] = ", ".join(args.cc)
    if args.bcc:
        msg["Bcc"] = ", ".join(args.bcc)
    msg["Subject"] = args.subject
    msg.set_content(args.body)

    raw_bytes = msg.as_bytes()
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")


def _send_summary(args: GmailSendArgs) -> str:
    """Build a confirmation-friendly summary of a sent email.

    Args:
        args: The send arguments used.

    Returns:
        Human-readable summary with recipients, subject, and body preview.
    """
    recipients = ", ".join(args.to)
    parts = [f"Email sent to: {recipients}"]
    if args.cc:
        parts.append(f"CC: {', '.join(args.cc)}")
    if args.bcc:
        parts.append(f"BCC: {len(args.bcc)} recipient(s)")
    parts.append(f"Subject: {args.subject}")
    return "\n".join(parts)


@register_tool(
    tool="gmail",
    action="send",
    description=(
        "Send an email via Gmail. Requires promotion from deny to confirm "
        "via Critical Permissions. Returns a confirmation summary."
    ),
    args_schema=GmailSendArgs,
)
async def gmail_send(args: GmailSendArgs, **kwargs: object) -> str:
    """Send an email via the Gmail API.

    Constructs an RFC 2822 message, base64url-encodes it, and POSTs to the
    Gmail API ``messages.send`` endpoint.

    Args:
        args: Validated send arguments (to, subject, body, cc, bcc).

    Returns:
        Confirmation summary string, or an error message.
    """
    try:
        token = await _get_google_token()
    except OAuthError as exc:
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."

    raw_message = _build_rfc2822(args)

    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)

    try:
        response = await _http_client.post(
            f"{_GMAIL_API_BASE}/messages/send",
            headers=_auth_headers(token),
            json={"raw": raw_message},
        )
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    return _send_summary(args)
