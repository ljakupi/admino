"""Google Calendar tool for reading, listing, creating, and updating events via Calendar API v3.

Provides read, list, create, and update actions for Google Calendar events on
the authenticated user's primary calendar. OAuth tokens are managed by admino.oauth.

Security notes:
- No delete capability. google_calendar.delete is an immutable hardcoded denial.
- google_calendar.update is a tier-2 promotable denial: it is denied by default
  and can only be used after explicit user promotion (plus per-call confirmation)
  via the Critical Permissions UI. event_id and attendee addresses are validated
  in models.py to prevent path traversal and injection.
- google_calendar.create requires user confirmation via the permission engine.
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
    GoogleCalendarCreateArgs,
    GoogleCalendarListArgs,
    GoogleCalendarReadArgs,
    GoogleCalendarUpdateArgs,
)
from admino.oauth import OAuthError, get_valid_access_token
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

_CALENDAR_API_BASE = "https://www.googleapis.com/calendar/v3/calendars/primary"


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


def _format_datetime(dt_info: dict[str, str] | str | None) -> str:
    """Format a Google Calendar dateTime or date object to a readable string.

    Args:
        dt_info: Either a dict with 'dateTime' or 'date' key, or a string.

    Returns:
        Human-readable datetime string.
    """
    if dt_info is None:
        return "N/A"
    if isinstance(dt_info, str):
        return dt_info
    if isinstance(dt_info, dict):
        return str(dt_info.get("dateTime", dt_info.get("date", "N/A")))
    return "N/A"


def _format_attendees(attendees: list[dict[str, str]] | None) -> str:
    """Format a list of attendees into a readable string.

    Args:
        attendees: List of attendee dicts from the Calendar API.

    Returns:
        Comma-separated list of attendee emails, or 'None'.
    """
    if not attendees or not isinstance(attendees, list):
        return "None"
    emails: list[str] = []
    for attendee in attendees:
        if isinstance(attendee, dict):
            email = attendee.get("email", "")
            if email:
                emails.append(str(email))
    return ", ".join(emails) if emails else "None"


def _format_event(event: dict[str, object]) -> str:
    """Format a single calendar event dict into a readable string.

    Args:
        event: Event dict from the Calendar API.

    Returns:
        Formatted event string.
    """
    summary = event.get("summary", "No title")
    start = _format_datetime(event.get("start"))  # type: ignore[arg-type]
    end = _format_datetime(event.get("end"))  # type: ignore[arg-type]
    location = event.get("location", "")
    description = event.get("description", "")

    lines = [
        f"  Summary: {summary}",
        f"  Start: {start}",
        f"  End: {end}",
    ]
    if location:
        lines.append(f"  Location: {location}")
    if description:
        # Truncate long descriptions
        desc_str = str(description)[:500]
        lines.append(f"  Description: {desc_str}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@register_tool(
    tool="google_calendar",
    action="read",
    description=(
        "Read a single calendar event by event ID. "
        "Returns summary, times, description, location, and attendees."
    ),
    args_schema=GoogleCalendarReadArgs,
)
async def google_calendar_read(args: GoogleCalendarReadArgs, **kwargs: object) -> str:
    """Read a single Google Calendar event by ID.

    Args:
        args: Validated read arguments (event_id).

    Returns:
        Formatted event details string.
    """
    try:
        global _http_client
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        token = await _get_google_token()
        response = await _http_client.get(
            f"{_CALENDAR_API_BASE}/events/{args.event_id}",
            headers=_auth_headers(token),
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    event = response.json()
    if not isinstance(event, dict):
        return "Unexpected response format from Google Calendar API."

    summary = event.get("summary", "No title")
    start = _format_datetime(event.get("start"))
    end = _format_datetime(event.get("end"))
    description = str(event.get("description", ""))[:1000]
    location = event.get("location", "")
    attendees = _format_attendees(event.get("attendees"))
    html_link = event.get("htmlLink", "")

    result = (
        f"Summary: {summary}\n"
        f"Start: {start}\n"
        f"End: {end}\n"
        f"Location: {location}\n"
        f"Description: {description}\n"
        f"Attendees: {attendees}"
    )
    if html_link:
        result += f"\nLink: {html_link}"

    return result


@register_tool(
    tool="google_calendar",
    action="list",
    description=(
        "List calendar events in a time range. Returns summary, start, and end for each event."
    ),
    args_schema=GoogleCalendarListArgs,
)
async def google_calendar_list(args: GoogleCalendarListArgs, **kwargs: object) -> str:
    """List Google Calendar events in a time range.

    Args:
        args: Validated list arguments (time_min, time_max, max_results).

    Returns:
        Formatted list of events.
    """
    params = {
        "timeMin": args.time_min.isoformat(),
        "timeMax": args.time_max.isoformat(),
        "maxResults": str(args.max_results),
        "singleEvents": "true",
        "orderBy": "startTime",
    }

    try:
        global _http_client
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        token = await _get_google_token()
        response = await _http_client.get(
            f"{_CALENDAR_API_BASE}/events",
            params=params,
            headers=_auth_headers(token),
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    data = response.json()
    events = data.get("items", [])
    if not isinstance(events, list) or not events:
        return "No events found in the specified time range."

    lines: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        event_id = event.get("id", "unknown")
        lines.append(f"ID: {event_id}")
        lines.append(_format_event(event))
        lines.append("")  # blank line separator

    return "\n".join(lines).rstrip()


@register_tool(
    tool="google_calendar",
    action="create",
    description="Create a new calendar event. Returns the event ID and link on success.",
    args_schema=GoogleCalendarCreateArgs,
)
async def google_calendar_create(args: GoogleCalendarCreateArgs, **kwargs: object) -> str:
    """Create a new Google Calendar event.

    Args:
        args: Validated create arguments (summary, start, end, description, location).

    Returns:
        Confirmation message with event ID and link.
    """
    event_body: dict[str, object] = {
        "summary": args.summary,
        "start": {"dateTime": args.start.isoformat(), "timeZone": "UTC"},
        "end": {"dateTime": args.end.isoformat(), "timeZone": "UTC"},
    }
    if args.description:
        event_body["description"] = args.description
    if args.location:
        event_body["location"] = args.location

    try:
        global _http_client
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        token = await _get_google_token()
        response = await _http_client.post(
            f"{_CALENDAR_API_BASE}/events",
            json=event_body,
            headers={
                **_auth_headers(token),
                "Content-Type": "application/json",
            },
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code not in (200, 201):
        return _format_api_error(response)

    data = response.json()
    if not isinstance(data, dict):
        return "Event created but received unexpected response format."

    event_id = data.get("id", "unknown")
    html_link = data.get("htmlLink", "")

    result = f"Event created successfully.\nEvent ID: {event_id}"
    if html_link:
        result += f"\nLink: {html_link}"

    return result


@register_tool(
    tool="google_calendar",
    action="update",
    description=(
        "Update an existing calendar event by ID. Only the provided fields are "
        "changed (partial update). Requires user confirmation."
    ),
    args_schema=GoogleCalendarUpdateArgs,
)
async def google_calendar_update(args: GoogleCalendarUpdateArgs, **kwargs: object) -> str:
    """Update an existing Google Calendar event (partial PATCH).

    Args:
        args: Validated update arguments (event_id plus optional fields).

    Returns:
        Confirmation message with the updated event summary, or an error string.
    """
    event_body: dict[str, object] = {}
    if args.summary is not None:
        event_body["summary"] = args.summary
    if args.description is not None:
        event_body["description"] = args.description
    if args.location is not None:
        event_body["location"] = args.location
    if args.start is not None:
        event_body["start"] = {"dateTime": args.start.isoformat(), "timeZone": "UTC"}
    if args.end is not None:
        event_body["end"] = {"dateTime": args.end.isoformat(), "timeZone": "UTC"}
    if args.attendees is not None:
        event_body["attendees"] = [{"email": email} for email in args.attendees]

    if not event_body:
        return "No fields provided to update. Specify at least one field to change."

    try:
        global _http_client
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        token = await _get_google_token()
        response = await _http_client.patch(
            f"{_CALENDAR_API_BASE}/events/{args.event_id}",
            json=event_body,
            headers={
                **_auth_headers(token),
                "Content-Type": "application/json",
            },
        )
    except OAuthError as exc:
        return f"Google OAuth error: {exc} Open the Tools page to reconnect your Google account."
    except httpx.HTTPError as exc:
        return f"HTTP request failed: {type(exc).__name__}"

    if response.status_code != 200:
        return _format_api_error(response)

    data = response.json()
    if not isinstance(data, dict):
        return "Event updated but received unexpected response format."

    event_id = data.get("id", args.event_id)
    summary = data.get("summary", "(no title)")
    html_link = data.get("htmlLink", "")

    result = f"Event updated successfully.\nEvent ID: {event_id}\nSummary: {summary}"
    if html_link:
        result += f"\nLink: {html_link}"

    return result
