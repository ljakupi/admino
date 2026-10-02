"""Outlook Calendar tool using Microsoft Graph API.

Provides read, list, create, and update actions for Outlook Calendar events via
the Microsoft Graph ``/me/events`` and ``/me/calendarView`` endpoints, in the
calling user's own Microsoft account (per-user connections, GH-162).

Inputs: the validated args (``OutlookCalendarReadArgs``,
``OutlookCalendarListArgs``, ``OutlookCalendarCreateArgs``,
``OutlookCalendarUpdateArgs``) and the required keyword ``tenant`` (the run's
``TenantContext``, passed by ``registry.dispatch_tool_call``). Outputs: the
formatted event(s), a confirmation, or a user-facing error string.

Security notes:
- Per-user tokens: every API request of a handler call carries the access
  token of that call's tenant, from ``_get_microsoft_token(tenant)``, which
  reads the shared per-user cache ``oauth.access_tokens`` (keyed by user and
  provider). The tenant comes from the server-side session, never from LLM
  arguments. The module keeps no token state of its own; refresh tokens
  never leave oauth.py, and no token is logged.
- No delete capability. outlook_calendar.delete is an immutable hardcoded denial.
- outlook_calendar.update is a tier-2 promotable denial: denied by default,
  usable only after explicit user promotion (plus per-call confirmation) via the
  Critical Permissions UI. event_id and attendee addresses are validated in
  models.py to prevent path traversal and injection.
- Event body content is truncated to 10 000 characters before returning.
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
    OutlookCalendarCreateArgs,
    OutlookCalendarListArgs,
    OutlookCalendarReadArgs,
    OutlookCalendarUpdateArgs,
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


def _format_event_summary(event: dict[str, object]) -> str:
    """Format an event dict into a human-readable summary line.

    Args:
        event: An event object from Microsoft Graph.

    Returns:
        A formatted string with event metadata.
    """
    event_id = event.get("id", "unknown")
    subject = event.get("subject", "(no subject)")

    start_obj = event.get("start", {})
    start_str = ""
    if isinstance(start_obj, dict):
        start_str = str(start_obj.get("dateTime", "unknown"))

    end_obj = event.get("end", {})
    end_str = ""
    if isinstance(end_obj, dict):
        end_str = str(end_obj.get("dateTime", "unknown"))

    location_obj = event.get("location", {})
    location_str = ""
    if isinstance(location_obj, dict):
        location_str = str(location_obj.get("displayName", ""))

    preview = event.get("bodyPreview", "")
    preview_str = str(preview)[:200] if preview else ""

    return (
        f"ID: {event_id}\n"
        f"Subject: {subject}\n"
        f"Start: {start_str}\n"
        f"End: {end_str}\n"
        f"Location: {location_str}\n"
        f"Preview: {preview_str}"
    )


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@register_tool(
    tool="outlook_calendar",
    action="read",
    description=(
        "Read a single Outlook Calendar event by ID. "
        "Returns subject, times, body, location, and attendees."
    ),
    args_schema=OutlookCalendarReadArgs,
)
async def outlook_calendar_read(
    args: OutlookCalendarReadArgs, *, tenant: TenantContext, **_: object
) -> str:
    """Read a single Outlook Calendar event by ID.

    Args:
        args: Validated read arguments (event_id).
        tenant: The caller's tool context (whose calendar is read).

    Returns:
        Formatted event details, or an error string.
    """
    try:
        token = await _get_microsoft_token(tenant)
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    # Graph event IDs contain '=', '/', '+'; percent-encode before path use.
    event_id = quote(args.event_id, safe="")
    url = (
        f"{_GRAPH_BASE}/me/events/{event_id}"
        "?$select=id,subject,start,end,body,location,attendees,webLink"
    )
    try:
        response = await _client().get(
            url,
            headers={"Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error reading Outlook Calendar event: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        event = response.json()
    except (ValueError, TypeError):
        return "Failed to parse Microsoft Graph response."

    subject = event.get("subject", "(no subject)")

    start_obj = event.get("start", {})
    start_str = ""
    if isinstance(start_obj, dict):
        start_str = str(start_obj.get("dateTime", "unknown"))

    end_obj = event.get("end", {})
    end_str = ""
    if isinstance(end_obj, dict):
        end_str = str(end_obj.get("dateTime", "unknown"))

    location_obj = event.get("location", {})
    location_str = ""
    if isinstance(location_obj, dict):
        location_str = str(location_obj.get("displayName", ""))

    web_link = event.get("webLink", "")

    # Attendees
    attendees = event.get("attendees", [])
    attendee_list: list[str] = []
    if isinstance(attendees, list):
        for att in attendees:
            if isinstance(att, dict):
                email_obj = att.get("emailAddress", {})
                if isinstance(email_obj, dict):
                    name = str(email_obj.get("name", ""))
                    addr = str(email_obj.get("address", ""))
                    attendee_list.append(f"{name} <{addr}>" if name else addr)

    # Body
    body_obj = event.get("body", {})
    body_content = ""
    if isinstance(body_obj, dict):
        body_content = str(body_obj.get("content", ""))
    if len(body_content) > _MAX_BODY_CHARS:
        body_content = body_content[:_MAX_BODY_CHARS] + "\n\n[Truncated]"

    attendees_str = ", ".join(attendee_list) if attendee_list else "none"

    return (
        f"Subject: {subject}\n"
        f"Start: {start_str}\n"
        f"End: {end_str}\n"
        f"Location: {location_str}\n"
        f"Attendees: {attendees_str}\n"
        f"Web link: {web_link}\n"
        f"Body:\n{body_content}"
    )


@register_tool(
    tool="outlook_calendar",
    action="list",
    description="List Outlook Calendar events in a time range, ordered by start time.",
    args_schema=OutlookCalendarListArgs,
)
async def outlook_calendar_list(
    args: OutlookCalendarListArgs, *, tenant: TenantContext, **_: object
) -> str:
    """List Outlook Calendar events in a time range.

    Args:
        args: Validated list arguments (time_min, time_max, max_results).
        tenant: The caller's tool context (whose calendar is read).

    Returns:
        Formatted list of events, or an error string.
    """
    try:
        token = await _get_microsoft_token(tenant)
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    start_iso = args.time_min.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = args.time_max.strftime("%Y-%m-%dT%H:%M:%SZ")

    url = f"{_GRAPH_BASE}/me/calendarView"
    params: dict[str, str | int] = {
        "startDateTime": start_iso,
        "endDateTime": end_iso,
        "$top": args.max_results,
        "$select": "id,subject,start,end,location,bodyPreview",
        "$orderby": "start/dateTime",
    }
    try:
        response = await _client().get(
            url,
            params=params,
            headers={
                "Authorization": f"Bearer {token}",
                "Prefer": 'outlook.timezone="UTC"',
            },
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error listing Outlook Calendar events: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        data = response.json()
    except (ValueError, TypeError):
        return "Failed to parse Microsoft Graph response."

    events = data.get("value", [])
    if not isinstance(events, list) or not events:
        return "No events found in the specified time range."

    parts: list[str] = []
    for event in events:
        if isinstance(event, dict):
            parts.append(_format_event_summary(event))
    if not parts:
        return "No events found in the specified time range."
    return "\n---\n".join(parts)


@register_tool(
    tool="outlook_calendar",
    action="create",
    description="Create a new Outlook Calendar event. Requires user confirmation.",
    args_schema=OutlookCalendarCreateArgs,
)
async def outlook_calendar_create(
    args: OutlookCalendarCreateArgs, *, tenant: TenantContext, **_: object
) -> str:
    """Create a new Outlook Calendar event.

    Args:
        args: Validated create arguments (subject, start, end, body, location).
        tenant: The caller's tool context (whose calendar gets the event).

    Returns:
        Confirmation message with event ID and web link, or an error string.
    """
    try:
        token = await _get_microsoft_token(tenant)
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    event_payload: dict[str, object] = {
        "subject": args.subject,
        "start": {
            "dateTime": args.start.strftime("%Y-%m-%dT%H:%M:%S"),
            "timeZone": "UTC",
        },
        "end": {
            "dateTime": args.end.strftime("%Y-%m-%dT%H:%M:%S"),
            "timeZone": "UTC",
        },
        "body": {
            "contentType": "text",
            "content": args.body,
        },
        "location": {
            "displayName": args.location,
        },
    }

    try:
        response = await _client().post(
            f"{_GRAPH_BASE}/me/events",
            json=event_payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error creating Outlook Calendar event: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code not in (200, 201):
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        created = response.json()
    except (ValueError, TypeError):
        return "Event may have been created but failed to parse the response."

    event_id = created.get("id", "unknown")
    web_link = created.get("webLink", "")

    return (
        f"Event created successfully.\n"
        f"ID: {event_id}\n"
        f"Subject: {args.subject}\n"
        f"Start: {args.start.isoformat()}\n"
        f"End: {args.end.isoformat()}\n"
        f"Web link: {web_link}"
    )


@register_tool(
    tool="outlook_calendar",
    action="update",
    description=(
        "Update an existing Outlook Calendar event by ID. Only the provided "
        "fields are changed (partial update). Requires user confirmation."
    ),
    args_schema=OutlookCalendarUpdateArgs,
)
async def outlook_calendar_update(
    args: OutlookCalendarUpdateArgs, *, tenant: TenantContext, **_: object
) -> str:
    """Update an existing Outlook Calendar event (partial PATCH).

    Args:
        args: Validated update arguments (event_id plus optional fields).
        tenant: The caller's tool context (whose calendar is updated).

    Returns:
        Confirmation message with the updated event summary, or an error string.
    """
    event_payload: dict[str, object] = {}
    if args.subject is not None:
        event_payload["subject"] = args.subject
    if args.body is not None:
        event_payload["body"] = {"contentType": "text", "content": args.body}
    if args.location is not None:
        event_payload["location"] = {"displayName": args.location}
    if args.start is not None:
        event_payload["start"] = {
            "dateTime": args.start.strftime("%Y-%m-%dT%H:%M:%S"),
            "timeZone": "UTC",
        }
    if args.end is not None:
        event_payload["end"] = {
            "dateTime": args.end.strftime("%Y-%m-%dT%H:%M:%S"),
            "timeZone": "UTC",
        }
    if args.attendees is not None:
        event_payload["attendees"] = [
            {"emailAddress": {"address": email}, "type": "required"} for email in args.attendees
        ]

    if not event_payload:
        return "No fields provided to update. Specify at least one field to change."

    try:
        token = await _get_microsoft_token(tenant)
    except OAuthError as exc:
        return (
            f"Microsoft OAuth error: {exc} Open the Tools page to reconnect your Microsoft account."
        )

    # Graph event IDs contain '=', '/', '+'; percent-encode before path use.
    event_id = quote(args.event_id, safe="")
    try:
        response = await _client().patch(
            f"{_GRAPH_BASE}/me/events/{event_id}",
            json=event_payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error updating Outlook Calendar event: %s", type(exc).__name__)
        return "Failed to connect to Microsoft Graph API."

    if response.status_code != 200:
        return f"Microsoft Graph error: {_extract_graph_error(response)}"

    try:
        updated = response.json()
    except (ValueError, TypeError):
        return "Event may have been updated but failed to parse the response."

    if not isinstance(updated, dict):
        updated = {}
    event_id = updated.get("id", args.event_id)
    subject = updated.get("subject", "(no subject)")
    web_link = updated.get("webLink", "")

    result = f"Event updated successfully.\nID: {event_id}\nSubject: {subject}"
    if web_link:
        result += f"\nWeb link: {web_link}"

    return result
