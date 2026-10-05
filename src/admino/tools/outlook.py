"""Outlook mail tool using Microsoft Graph API.

Provides read, list, search, and send actions for Outlook messages via the
Microsoft Graph ``/me/messages`` and ``/me/sendMail`` endpoints, in the
calling user's own Microsoft account (per-user connections, GH-162).

Inputs: the validated args (``OutlookReadArgs``, ``OutlookListArgs``,
``OutlookSearchArgs``, ``OutlookSendArgs``) and the required keyword
``tenant`` (the run's ``TenantContext``, passed by
``registry.dispatch_tool_call``). Outputs: the formatted message(s), wrapped
as untrusted email content (GH-243), a send summary, or a user-facing error
string.

Security notes:
- Per-user tokens: every API request of a handler call carries the access
  token of that call's tenant, from ``_get_microsoft_token(tenant)``, which
  reads the shared per-user cache ``oauth.access_tokens`` (keyed by user and
  provider). The tenant comes from the server-side session, never from LLM
  arguments. The module keeps no token state of its own; refresh tokens
  never leave oauth.py, and no token is logged.
- outlook.send is a tier-2 promotable denial in permissions.py. It is denied
  by default and requires explicit user promotion + cooldown before use.
  outlook.delete remains a hardcoded immutable denial.
- Message body content is truncated to 10 000 characters before returning.
- Untrusted content (GH-243): every read/list/search success result is
  third-party text and reaches the model only through ``untrusted.wrap``
  (kind ``email``), so the agent escalates the run's later side effects to
  confirmation. The read label names the validated ``message_id`` argument,
  never its URL-encoded form. Error and "nothing found" strings, and the
  send summary (the LLM's own arguments), stay unwrapped.
- JSON payload structure of Microsoft Graph prevents header injection by design.
- No eval, exec, shell=True, or importlib.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Final
from urllib.parse import quote

import httpx

from admino import database, untrusted
from admino.models import OutlookListArgs, OutlookReadArgs, OutlookSearchArgs, OutlookSendArgs
from admino.oauth import OAuthError, access_tokens
from admino.tools.registry import register_tool

if TYPE_CHECKING:
    from admino.tenancy import TenantContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GRAPH_BASE: Final[str] = "https://graph.microsoft.com/v1.0"
_MAX_BODY_CHARS: Final[int] = 10_000

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
    side_effect=False,
)
async def outlook_read(args: OutlookReadArgs, *, tenant: TenantContext, **_: object) -> str:
    """Read a single Outlook message by ID.

    Args:
        args: Validated read arguments (message_id).
        tenant: The caller's tool context (whose mailbox is read).

    Returns:
        The formatted message content, wrapped as untrusted email content, or
        an error string.
    """
    try:
        token = await _get_microsoft_token(tenant)
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    # URL-encode the ID: Graph message IDs are base64 (=, +, /) and must not
    # alter the request path. safe="" encodes every reserved character.
    message_id = quote(args.message_id, safe="")
    url = (
        f"{_GRAPH_BASE}/me/messages/{message_id}"
        "?$select=id,subject,from,receivedDateTime,bodyPreview,body"
    )
    try:
        response = await _client().get(
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

    return untrusted.wrap(
        "email",
        f"outlook message {args.message_id}",
        f"Subject: {subject}\nFrom: {from_email}\nDate: {received}\nBody:\n{body_content}",
    )


@register_tool(
    tool="outlook",
    action="list",
    description="List recent Outlook email messages, ordered by date descending.",
    args_schema=OutlookListArgs,
    side_effect=False,
)
async def outlook_list(args: OutlookListArgs, *, tenant: TenantContext, **_: object) -> str:
    """List recent Outlook messages.

    Args:
        args: Validated list arguments (max_results).
        tenant: The caller's tool context (whose mailbox is read).

    Returns:
        The formatted list of messages, wrapped as untrusted email content,
        "No messages found." or an error string.
    """
    try:
        token = await _get_microsoft_token(tenant)
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    url = f"{_GRAPH_BASE}/me/messages"
    params: dict[str, str | int] = {
        "$top": args.max_results,
        "$select": "id,subject,from,receivedDateTime,bodyPreview",
        "$orderby": "receivedDateTime desc",
    }
    try:
        response = await _client().get(
            url,
            params=params,
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
    return untrusted.wrap("email", "outlook messages", "\n---\n".join(parts))


@register_tool(
    tool="outlook",
    action="search",
    description="Search Outlook email messages using KQL query syntax.",
    args_schema=OutlookSearchArgs,
    side_effect=False,
)
async def outlook_search(args: OutlookSearchArgs, *, tenant: TenantContext, **_: object) -> str:
    """Search Outlook messages using KQL.

    Args:
        args: Validated search arguments (query, max_results).
        tenant: The caller's tool context (whose mailbox is searched).

    Returns:
        The formatted list of matching messages, wrapped as untrusted email
        content, a "nothing found" message or an error string.
    """
    try:
        token = await _get_microsoft_token(tenant)
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    # $search uses KQL syntax; the query value is wrapped in double quotes.
    # It is passed via params= (not the URL string) so httpx percent-encodes it
    # and so it is not dropped: httpx replaces an existing URL query string when
    # params= is supplied, rather than merging. Escape double-quotes and
    # backslashes as defence-in-depth against KQL / OData option injection.
    safe_query = args.query.replace("\\", "\\\\").replace('"', '\\"')
    params: dict[str, str | int] = {
        "$search": f'"{safe_query}"',
        "$top": args.max_results,
        "$select": "id,subject,from,receivedDateTime,bodyPreview",
    }
    try:
        response = await _client().get(
            f"{_GRAPH_BASE}/me/messages",
            params=params,
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
    return untrusted.wrap("email", "outlook search results", "\n---\n".join(parts))


# ---------------------------------------------------------------------------
# outlook.send
# ---------------------------------------------------------------------------


def _build_sendmail_payload(args: OutlookSendArgs) -> dict[str, object]:
    """Build the Microsoft Graph ``sendMail`` JSON payload.

    Args:
        args: Validated send arguments.

    Returns:
        Dict suitable for ``json=`` in an httpx POST.
    """

    def _recipients(addrs: list[str]) -> list[dict[str, dict[str, str]]]:
        return [{"emailAddress": {"address": a}} for a in addrs]

    message: dict[str, object] = {
        "subject": args.subject,
        "body": {
            "contentType": "text",
            "content": args.body,
        },
        "toRecipients": _recipients(args.to),
    }
    if args.cc:
        message["ccRecipients"] = _recipients(args.cc)
    if args.bcc:
        message["bccRecipients"] = _recipients(args.bcc)

    return {"message": message}


def _outlook_send_summary(args: OutlookSendArgs) -> str:
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
    tool="outlook",
    action="send",
    description=(
        "Send an email via Outlook (Microsoft Graph). Requires promotion from "
        "deny to confirm via Critical Permissions. Returns a confirmation summary."
    ),
    args_schema=OutlookSendArgs,
    side_effect=True,
)
async def outlook_send(args: OutlookSendArgs, *, tenant: TenantContext, **_: object) -> str:
    """Send an email via the Microsoft Graph ``sendMail`` endpoint.

    Args:
        args: Validated send arguments (to, subject, body, cc, bcc).
        tenant: The caller's tool context (whose mailbox sends).

    Returns:
        Confirmation summary string, or an error message.
    """
    try:
        token = await _get_microsoft_token(tenant)
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    payload = _build_sendmail_payload(args)

    try:
        response = await _client().post(
            f"{_GRAPH_BASE}/me/sendMail",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error sending Outlook email: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 202:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    return _outlook_send_summary(args)
