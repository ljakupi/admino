"""Tests for the Google Calendar tool module (admino.tools.google_calendar).

Covers tool registration, happy-path responses, OAuth errors, API errors,
empty results, event creation, and argument validation.
All HTTP calls are mocked -- no real API requests are made.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pydantic import ValidationError

if TYPE_CHECKING:
    from collections.abc import Generator

from admino.models import (
    GoogleCalendarCreateArgs,
    GoogleCalendarListArgs,
    GoogleCalendarReadArgs,
)
from admino.oauth import OAuthError
from admino.tools import google_calendar
from admino.tools.registry import clear_registry, get_registered_tools

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_TOKEN = "fake-access-token-calendar"

_NOW = datetime(2026, 4, 12, 10, 0, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(hours=1)


def _make_response(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response with JSON body."""
    body = json.dumps(json_body or {}).encode()
    return httpx.Response(status_code=status_code, content=body)


def _sample_event(
    event_id: str = "evt123",
    summary: str = "Team Standup",
    start: str = "2026-04-12T10:00:00Z",
    end: str = "2026-04-12T11:00:00Z",
    location: str = "Room A",
    description: str = "Daily standup meeting",
    attendees: list[dict[str, str]] | None = None,
    html_link: str = "https://calendar.google.com/event?eid=evt123",
) -> dict[str, Any]:
    """Build a realistic Calendar event dict."""
    event: dict[str, Any] = {
        "id": event_id,
        "summary": summary,
        "start": {"dateTime": start},
        "end": {"dateTime": end},
        "htmlLink": html_link,
    }
    if location:
        event["location"] = location
    if description:
        event["description"] = description
    if attendees is not None:
        event["attendees"] = attendees
    return event


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Ensure the registry is clean before and after every test."""
    clear_registry()
    import importlib

    importlib.reload(google_calendar)
    yield
    clear_registry()


@pytest.fixture()
def mock_token() -> Generator[AsyncMock, None, None]:
    """Patch _get_google_token to return a fake token."""
    with patch.object(google_calendar, "_get_google_token", new_callable=AsyncMock) as m:
        m.return_value = _FAKE_TOKEN
        yield m


@pytest.fixture()
def mock_http(mock_token: AsyncMock) -> Generator[AsyncMock, None, None]:
    """Patch the module-level _http_client with an AsyncMock."""
    client = AsyncMock(spec=httpx.AsyncClient)
    with patch.object(google_calendar, "_http_client", client):
        yield client


# ---------------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------------


class TestCalendarRegistration:
    """Google Calendar tool actions are registered after import."""

    def test_calendar_read_registered(self) -> None:
        """google_calendar.read is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("google_calendar", "read") in keys

    def test_calendar_list_registered(self) -> None:
        """google_calendar.list is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("google_calendar", "list") in keys

    def test_calendar_create_registered(self) -> None:
        """google_calendar.create is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("google_calendar", "create") in keys


# ---------------------------------------------------------------------------
# 2. google_calendar.read
# ---------------------------------------------------------------------------


class TestCalendarRead:
    """Tests for the google_calendar.read handler."""

    async def test_happy_path(self, mock_http: AsyncMock) -> None:
        """Successful read returns event details."""
        event = _sample_event(
            attendees=[{"email": "alice@example.com"}, {"email": "bob@example.com"}]
        )
        mock_http.get.return_value = _make_response(200, event)

        args = GoogleCalendarReadArgs(event_id="evt123")
        result = await google_calendar.google_calendar_read(args)

        assert "Summary: Team Standup" in result
        assert "Location: Room A" in result
        assert "alice@example.com" in result
        assert "bob@example.com" in result
        assert "Link:" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            google_calendar,
            "_get_google_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("no token"),
        ):
            args = GoogleCalendarReadArgs(event_id="evt123")
            result = await google_calendar.google_calendar_read(args)

        assert "OAuth not configured" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns API error."""
        mock_http.get.return_value = _make_response(
            404, {"error": {"code": 404, "message": "Not Found"}}
        )

        args = GoogleCalendarReadArgs(event_id="evt123")
        result = await google_calendar.google_calendar_read(args)

        assert "Google API error 404" in result

    async def test_event_without_optional_fields(self, mock_http: AsyncMock) -> None:
        """Event without location/description still formats correctly."""
        event = {
            "id": "evt456",
            "summary": "Quick Chat",
            "start": {"dateTime": "2026-04-12T10:00:00Z"},
            "end": {"dateTime": "2026-04-12T10:30:00Z"},
        }
        mock_http.get.return_value = _make_response(200, event)

        args = GoogleCalendarReadArgs(event_id="evt456")
        result = await google_calendar.google_calendar_read(args)

        assert "Summary: Quick Chat" in result

    async def test_http_error(self) -> None:
        """httpx.HTTPError returns a friendly message."""
        with patch.object(
            google_calendar, "_get_google_token", new_callable=AsyncMock, return_value=_FAKE_TOKEN
        ):
            client = AsyncMock(spec=httpx.AsyncClient)
            client.get.side_effect = httpx.ConnectError("refused")
            with patch.object(google_calendar, "_http_client", client):
                args = GoogleCalendarReadArgs(event_id="evt123")
                result = await google_calendar.google_calendar_read(args)

        assert "HTTP request failed" in result


# ---------------------------------------------------------------------------
# 3. google_calendar.list
# ---------------------------------------------------------------------------


class TestCalendarList:
    """Tests for the google_calendar.list handler."""

    async def test_happy_path(self, mock_http: AsyncMock) -> None:
        """Successful list returns formatted events."""
        events = {
            "items": [
                _sample_event("e1", "Meeting 1"),
                _sample_event("e2", "Meeting 2"),
            ]
        }
        mock_http.get.return_value = _make_response(200, events)

        args = GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER, max_results=10)
        result = await google_calendar.google_calendar_list(args)

        assert "Meeting 1" in result
        assert "Meeting 2" in result

    async def test_time_range_in_params(self, mock_http: AsyncMock) -> None:
        """timeMin and timeMax are passed as query parameters."""
        mock_http.get.return_value = _make_response(200, {"items": []})

        args = GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER, max_results=5)
        await google_calendar.google_calendar_list(args)

        call_kwargs = mock_http.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert "timeMin" in params
        assert "timeMax" in params
        assert params["singleEvents"] == "true"
        assert params["orderBy"] == "startTime"

    async def test_empty_events(self, mock_http: AsyncMock) -> None:
        """Empty items list returns appropriate message."""
        mock_http.get.return_value = _make_response(200, {"items": []})

        args = GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER)
        result = await google_calendar.google_calendar_list(args)

        assert "No events found" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns API error."""
        mock_http.get.return_value = _make_response(
            401, {"error": {"code": 401, "message": "Unauthorized"}}
        )

        args = GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER)
        result = await google_calendar.google_calendar_list(args)

        assert "Google API error 401" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            google_calendar,
            "_get_google_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("no token"),
        ):
            args = GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER)
            result = await google_calendar.google_calendar_list(args)

        assert "OAuth not configured" in result


# ---------------------------------------------------------------------------
# 4. google_calendar.create
# ---------------------------------------------------------------------------


class TestCalendarCreate:
    """Tests for the google_calendar.create handler."""

    async def test_happy_path(self, mock_http: AsyncMock) -> None:
        """Successful create returns event ID and link."""
        response_data = {
            "id": "new_evt_789",
            "htmlLink": "https://calendar.google.com/event?eid=new_evt_789",
        }
        mock_http.post.return_value = _make_response(200, response_data)

        args = GoogleCalendarCreateArgs(
            summary="New Meeting",
            start=_NOW,
            end=_LATER,
            description="Planning session",
            location="Room B",
        )
        result = await google_calendar.google_calendar_create(args)

        assert "Event created successfully" in result
        assert "new_evt_789" in result
        assert "Link:" in result

    async def test_create_201_status(self, mock_http: AsyncMock) -> None:
        """201 Created status is also accepted."""
        response_data = {
            "id": "evt_201",
            "htmlLink": "https://calendar.google.com/event?eid=evt_201",
        }
        mock_http.post.return_value = _make_response(201, response_data)

        args = GoogleCalendarCreateArgs(summary="Event", start=_NOW, end=_LATER)
        result = await google_calendar.google_calendar_create(args)

        assert "Event created successfully" in result

    async def test_create_without_optional_fields(self, mock_http: AsyncMock) -> None:
        """Create without description/location works."""
        mock_http.post.return_value = _make_response(200, {"id": "evt_min"})

        args = GoogleCalendarCreateArgs(summary="Min Event", start=_NOW, end=_LATER)
        result = await google_calendar.google_calendar_create(args)

        assert "Event created successfully" in result
        assert "evt_min" in result

    async def test_create_sends_correct_body(self, mock_http: AsyncMock) -> None:
        """The POST body includes summary, start, end, description, location."""
        mock_http.post.return_value = _make_response(200, {"id": "evt_body"})

        args = GoogleCalendarCreateArgs(
            summary="Test Event",
            start=_NOW,
            end=_LATER,
            description="A description",
            location="Office",
        )
        await google_calendar.google_calendar_create(args)

        call_kwargs = mock_http.post.call_args
        json_body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json", {})
        assert json_body["summary"] == "Test Event"
        assert json_body["description"] == "A description"
        assert json_body["location"] == "Office"
        assert "dateTime" in json_body["start"]

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200/201 returns API error."""
        mock_http.post.return_value = _make_response(
            400, {"error": {"code": 400, "message": "Bad Request"}}
        )

        args = GoogleCalendarCreateArgs(summary="Bad", start=_NOW, end=_LATER)
        result = await google_calendar.google_calendar_create(args)

        assert "Google API error 400" in result

    async def test_oauth_not_configured(self) -> None:
        """OAuthError returns setup instructions."""
        with patch.object(
            google_calendar,
            "_get_google_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("no token"),
        ):
            args = GoogleCalendarCreateArgs(summary="Test", start=_NOW, end=_LATER)
            result = await google_calendar.google_calendar_create(args)

        assert "OAuth not configured" in result


# ---------------------------------------------------------------------------
# 5. Argument validation
# ---------------------------------------------------------------------------


class TestCalendarArgValidation:
    """Pydantic validation rejects invalid arguments."""

    def test_read_missing_event_id(self) -> None:
        """Missing event_id is rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarReadArgs()  # type: ignore[call-arg]

    def test_read_event_id_too_long(self) -> None:
        """event_id exceeding 200 chars is rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarReadArgs(event_id="x" * 201)

    def test_list_max_results_zero(self) -> None:
        """max_results=0 is rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER, max_results=0)

    def test_list_max_results_exceeds_limit(self) -> None:
        """max_results exceeding 50 is rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER, max_results=100)

    def test_create_summary_too_long(self) -> None:
        """Summary exceeding 200 chars is rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarCreateArgs(summary="x" * 201, start=_NOW, end=_LATER)

    def test_create_description_too_long(self) -> None:
        """Description exceeding 1000 chars is rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarCreateArgs(
                summary="Event", start=_NOW, end=_LATER, description="d" * 1001
            )

    def test_create_location_too_long(self) -> None:
        """Location exceeding 200 chars is rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarCreateArgs(summary="Event", start=_NOW, end=_LATER, location="l" * 201)

    def test_valid_args_accepted(self) -> None:
        """Valid arguments pass validation."""
        read_args = GoogleCalendarReadArgs(event_id="evt123")
        assert read_args.event_id == "evt123"

        list_args = GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER, max_results=25)
        assert list_args.max_results == 25

        create_args = GoogleCalendarCreateArgs(summary="Meeting", start=_NOW, end=_LATER)
        assert create_args.summary == "Meeting"


# ---------------------------------------------------------------------------
# 6. Internal helpers
# ---------------------------------------------------------------------------


class TestCalendarHelpers:
    """Tests for internal helper functions."""

    def test_format_datetime_dict_with_datetime(self) -> None:
        """_format_datetime extracts dateTime from dict."""
        result = google_calendar._format_datetime({"dateTime": "2026-04-12T10:00:00Z"})
        assert result == "2026-04-12T10:00:00Z"

    def test_format_datetime_dict_with_date(self) -> None:
        """_format_datetime falls back to date key."""
        result = google_calendar._format_datetime({"date": "2026-04-12"})
        assert result == "2026-04-12"

    def test_format_datetime_string(self) -> None:
        """_format_datetime returns a string as-is."""
        result = google_calendar._format_datetime("2026-04-12T10:00:00Z")
        assert result == "2026-04-12T10:00:00Z"

    def test_format_datetime_none(self) -> None:
        """_format_datetime returns 'N/A' for None."""
        assert google_calendar._format_datetime(None) == "N/A"

    def test_format_attendees_with_emails(self) -> None:
        """_format_attendees joins emails."""
        attendees = [{"email": "a@example.com"}, {"email": "b@example.com"}]
        result = google_calendar._format_attendees(attendees)
        assert "a@example.com" in result
        assert "b@example.com" in result

    def test_format_attendees_none(self) -> None:
        """_format_attendees returns 'None' for None input."""
        assert google_calendar._format_attendees(None) == "None"

    def test_format_attendees_empty(self) -> None:
        """_format_attendees returns 'None' for empty list."""
        assert google_calendar._format_attendees([]) == "None"

    def test_format_event_basic(self) -> None:
        """_format_event includes summary, start, end."""
        event = _sample_event()
        result = google_calendar._format_event(event)
        assert "Team Standup" in result
        assert "Start:" in result
        assert "End:" in result

    def test_format_api_error_with_json(self) -> None:
        """_format_api_error extracts code and message."""
        resp = _make_response(403, {"error": {"code": 403, "message": "Forbidden"}})
        result = google_calendar._format_api_error(resp)
        assert "403" in result
        assert "Forbidden" in result

    def test_format_api_error_fallback(self) -> None:
        """_format_api_error falls back to status code for non-JSON."""
        resp = httpx.Response(status_code=502, content=b"bad gateway")
        result = google_calendar._format_api_error(resp)
        assert "502" in result
