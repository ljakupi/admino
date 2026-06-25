"""Tests for the Outlook Calendar tool (admino.tools.outlook_calendar).

Covers tool registration, happy-path responses, OAuth error handling,
API error handling, empty results, body truncation, event creation,
and argument validation. All HTTP calls are mocked.
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
    OutlookCalendarCreateArgs,
    OutlookCalendarListArgs,
    OutlookCalendarReadArgs,
    OutlookCalendarUpdateArgs,
)
from admino.oauth import OAuthError
from admino.tools import outlook_calendar as cal_mod
from admino.tools.registry import clear_registry, get_registered_tools

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response with JSON body."""
    body = json.dumps(json_body or {}).encode()
    return httpx.Response(status_code=status_code, content=body)


def _sample_event(
    event_id: str = "evt-1",
    subject: str = "Team Meeting",
    body_content: str = "Agenda: discuss Q3",
) -> dict[str, Any]:
    """Build a sample Microsoft Graph event object."""
    return {
        "id": event_id,
        "subject": subject,
        "start": {"dateTime": "2026-04-15T10:00:00", "timeZone": "UTC"},
        "end": {"dateTime": "2026-04-15T11:00:00", "timeZone": "UTC"},
        "location": {"displayName": "Room 42"},
        "bodyPreview": "preview text",
        "body": {"contentType": "text", "content": body_content},
        "webLink": "https://outlook.live.com/event/123",
        "attendees": [
            {
                "emailAddress": {
                    "name": "Alice",
                    "address": "alice@example.com",
                }
            }
        ],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Ensure the registry is clean before and after every test."""
    import importlib

    clear_registry()
    importlib.reload(cal_mod)
    yield
    clear_registry()


@pytest.fixture()
def mock_token() -> Generator[AsyncMock, None, None]:
    """Mock _get_microsoft_token to return a fake token."""
    with patch(
        "admino.tools.outlook_calendar._get_microsoft_token",
        new_callable=AsyncMock,
        return_value="fake-token-456",
    ) as m:
        yield m


@pytest.fixture()
def mock_http_client() -> Generator[AsyncMock, None, None]:
    """Mock the module-level _http_client."""
    mock_client = AsyncMock()
    with patch("admino.tools.outlook_calendar._http_client", mock_client):
        yield mock_client


# ---------------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------------


class TestOutlookCalendarRegistration:
    """Verify tool actions are registered after import."""

    def test_read_registered(self) -> None:
        """outlook_calendar.read is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("outlook_calendar", "read") in keys

    def test_list_registered(self) -> None:
        """outlook_calendar.list is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("outlook_calendar", "list") in keys

    def test_create_registered(self) -> None:
        """outlook_calendar.create is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("outlook_calendar", "create") in keys

    def test_update_registered(self) -> None:
        """outlook_calendar.update is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("outlook_calendar", "update") in keys


# ---------------------------------------------------------------------------
# 2. outlook_calendar.read
# ---------------------------------------------------------------------------


class TestOutlookCalendarRead:
    """Tests for the outlook_calendar.read action."""

    async def test_read_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Read returns formatted event with subject, times, attendees."""
        event = _sample_event()
        mock_http_client.get.return_value = _make_response(200, event)

        from admino.tools.outlook_calendar import outlook_calendar_read

        args = OutlookCalendarReadArgs(event_id="evt-1")
        result = await outlook_calendar_read(args)

        assert "Subject: Team Meeting" in result
        assert "Start: 2026-04-15T10:00:00" in result
        assert "End: 2026-04-15T11:00:00" in result
        assert "Location: Room 42" in result
        assert "Alice <alice@example.com>" in result
        assert "Web link:" in result

    async def test_read_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.outlook_calendar._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook_calendar import outlook_calendar_read

            args = OutlookCalendarReadArgs(event_id="evt-1")
            result = await outlook_calendar_read(args)

        assert "OAuth error" in result

    async def test_read_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 returns Graph error message."""
        mock_http_client.get.return_value = _make_response(
            404, {"error": {"message": "Event not found"}}
        )

        from admino.tools.outlook_calendar import outlook_calendar_read

        args = OutlookCalendarReadArgs(event_id="bad-id")
        result = await outlook_calendar_read(args)

        assert "Microsoft Graph error" in result
        assert "Event not found" in result

    async def test_read_body_truncation(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Event body exceeding 10000 chars is truncated."""
        long_body = "y" * 15_000
        event = _sample_event(body_content=long_body)
        mock_http_client.get.return_value = _make_response(200, event)

        from admino.tools.outlook_calendar import outlook_calendar_read

        args = OutlookCalendarReadArgs(event_id="evt-1")
        result = await outlook_calendar_read(args)

        assert "[Truncated]" in result

    async def test_read_http_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """httpx.HTTPError returns connection failure message."""
        mock_http_client.get.side_effect = httpx.ConnectError("fail")

        from admino.tools.outlook_calendar import outlook_calendar_read

        args = OutlookCalendarReadArgs(event_id="evt-1")
        result = await outlook_calendar_read(args)

        assert "Failed to connect" in result

    async def test_read_no_attendees(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Event with no attendees shows 'none'."""
        event = _sample_event()
        event["attendees"] = []
        mock_http_client.get.return_value = _make_response(200, event)

        from admino.tools.outlook_calendar import outlook_calendar_read

        args = OutlookCalendarReadArgs(event_id="evt-1")
        result = await outlook_calendar_read(args)

        assert "Attendees: none" in result


# ---------------------------------------------------------------------------
# 3. outlook_calendar.list
# ---------------------------------------------------------------------------


class TestOutlookCalendarList:
    """Tests for the outlook_calendar.list action."""

    async def test_list_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """List returns formatted event summaries."""
        events = [
            _sample_event(event_id="e1", subject="Meeting 1"),
            _sample_event(event_id="e2", subject="Meeting 2"),
        ]
        mock_http_client.get.return_value = _make_response(200, {"value": events})

        from admino.tools.outlook_calendar import outlook_calendar_list

        now = datetime.now(UTC)
        args = OutlookCalendarListArgs(
            time_min=now, time_max=now + timedelta(days=7), max_results=10
        )
        result = await outlook_calendar_list(args)

        assert "Subject: Meeting 1" in result
        assert "Subject: Meeting 2" in result
        assert "---" in result

    async def test_list_empty_results(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Empty event list returns appropriate message."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook_calendar import outlook_calendar_list

        now = datetime.now(UTC)
        args = OutlookCalendarListArgs(time_min=now, time_max=now + timedelta(days=1))
        result = await outlook_calendar_list(args)

        assert "No events found" in result

    async def test_list_url_contains_calendar_view_params(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Request URL includes startDateTime, endDateTime, $top."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook_calendar import outlook_calendar_list

        now = datetime.now(UTC)
        args = OutlookCalendarListArgs(
            time_min=now, time_max=now + timedelta(days=7), max_results=5
        )
        await outlook_calendar_list(args)

        call_args = mock_http_client.get.call_args
        url = call_args[0][0]
        assert "calendarView" in url
        assert "startDateTime=" in url
        assert "endDateTime=" in url
        assert "$top=5" in url

    async def test_list_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.outlook_calendar._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook_calendar import outlook_calendar_list

            now = datetime.now(UTC)
            args = OutlookCalendarListArgs(time_min=now, time_max=now + timedelta(days=1))
            result = await outlook_calendar_list(args)

        assert "OAuth error" in result

    async def test_list_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 status returns Graph error."""
        mock_http_client.get.return_value = _make_response(403, {"error": {"message": "Forbidden"}})

        from admino.tools.outlook_calendar import outlook_calendar_list

        now = datetime.now(UTC)
        args = OutlookCalendarListArgs(time_min=now, time_max=now + timedelta(days=1))
        result = await outlook_calendar_list(args)

        assert "Microsoft Graph error" in result


# ---------------------------------------------------------------------------
# 4. outlook_calendar.create
# ---------------------------------------------------------------------------


class TestOutlookCalendarCreate:
    """Tests for the outlook_calendar.create action."""

    async def test_create_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Successful create returns event ID and web link."""
        created_event = {
            "id": "new-evt-1",
            "webLink": "https://outlook.live.com/event/new-evt-1",
        }
        mock_http_client.post.return_value = _make_response(201, created_event)

        from admino.tools.outlook_calendar import outlook_calendar_create

        now = datetime.now(UTC)
        args = OutlookCalendarCreateArgs(
            subject="New Meeting",
            start=now + timedelta(hours=1),
            end=now + timedelta(hours=2),
            body="Discuss roadmap",
            location="Office",
        )
        result = await outlook_calendar_create(args)

        assert "Event created successfully" in result
        assert "ID: new-evt-1" in result
        assert "Subject: New Meeting" in result
        assert "Web link:" in result

    async def test_create_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.outlook_calendar._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook_calendar import outlook_calendar_create

            now = datetime.now(UTC)
            args = OutlookCalendarCreateArgs(
                subject="Meeting",
                start=now + timedelta(hours=1),
                end=now + timedelta(hours=2),
            )
            result = await outlook_calendar_create(args)

        assert "OAuth error" in result

    async def test_create_api_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Non-200/201 status returns Graph error."""
        mock_http_client.post.return_value = _make_response(
            400, {"error": {"message": "Bad request"}}
        )

        from admino.tools.outlook_calendar import outlook_calendar_create

        now = datetime.now(UTC)
        args = OutlookCalendarCreateArgs(
            subject="Meeting",
            start=now + timedelta(hours=1),
            end=now + timedelta(hours=2),
        )
        result = await outlook_calendar_create(args)

        assert "Microsoft Graph error" in result

    async def test_create_http_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """httpx.HTTPError returns connection failure."""
        mock_http_client.post.side_effect = httpx.ConnectError("fail")

        from admino.tools.outlook_calendar import outlook_calendar_create

        now = datetime.now(UTC)
        args = OutlookCalendarCreateArgs(
            subject="Meeting",
            start=now + timedelta(hours=1),
            end=now + timedelta(hours=2),
        )
        result = await outlook_calendar_create(args)

        assert "Failed to connect" in result

    async def test_create_200_also_accepted(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Status 200 (not just 201) is accepted for create."""
        created_event = {"id": "evt-200", "webLink": "https://outlook.live.com/evt-200"}
        mock_http_client.post.return_value = _make_response(200, created_event)

        from admino.tools.outlook_calendar import outlook_calendar_create

        now = datetime.now(UTC)
        args = OutlookCalendarCreateArgs(
            subject="Meeting",
            start=now + timedelta(hours=1),
            end=now + timedelta(hours=2),
        )
        result = await outlook_calendar_create(args)

        assert "Event created successfully" in result


# ---------------------------------------------------------------------------
# 4b. outlook_calendar.update
# ---------------------------------------------------------------------------


class TestOutlookCalendarUpdate:
    """Tests for the outlook_calendar.update action."""

    async def test_update_happy_path(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Successful update returns the updated event summary."""
        updated = {
            "id": "evt-1",
            "subject": "Renamed Meeting",
            "webLink": "https://outlook.live.com/event/evt-1",
        }
        mock_http_client.patch.return_value = _make_response(200, updated)

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(event_id="evt-1", subject="Renamed Meeting")
        result = await outlook_calendar_update(args)

        assert "Renamed Meeting" in result
        assert "evt-1" in result

    async def test_update_uses_patch_to_correct_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Update issues a PATCH to /me/events/{id}."""
        mock_http_client.patch.return_value = _make_response(
            200, {"id": "evt-1", "subject": "X"}
        )

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(event_id="evt-1", subject="X")
        await outlook_calendar_update(args)

        mock_http_client.patch.assert_called_once()
        url = mock_http_client.patch.call_args[0][0]
        assert url.endswith("/me/events/evt-1")

    async def test_update_partial_body_only_provided_fields(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Only supplied fields are sent in the PATCH body."""
        mock_http_client.patch.return_value = _make_response(
            200, {"id": "evt-1", "subject": "New"}
        )

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(event_id="evt-1", subject="New")
        await outlook_calendar_update(args)

        json_body = mock_http_client.patch.call_args.kwargs["json"]
        assert json_body == {"subject": "New"}
        assert "start" not in json_body
        assert "body" not in json_body

    async def test_update_body_and_location_structured(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """body and location are sent as Graph structured objects."""
        mock_http_client.patch.return_value = _make_response(
            200, {"id": "evt-1", "subject": "S"}
        )

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(
            event_id="evt-1", body="New agenda", location="Room 9"
        )
        await outlook_calendar_update(args)

        json_body = mock_http_client.patch.call_args.kwargs["json"]
        assert json_body["body"]["content"] == "New agenda"
        assert json_body["location"]["displayName"] == "Room 9"

    async def test_update_start_end_structured(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """start/end are sent as Graph dateTime/timeZone objects."""
        mock_http_client.patch.return_value = _make_response(
            200, {"id": "evt-1", "subject": "S"}
        )

        from admino.tools.outlook_calendar import outlook_calendar_update

        now = datetime.now(UTC)
        args = OutlookCalendarUpdateArgs(
            event_id="evt-1", start=now, end=now + timedelta(hours=1)
        )
        await outlook_calendar_update(args)

        json_body = mock_http_client.patch.call_args.kwargs["json"]
        assert "dateTime" in json_body["start"]
        assert json_body["start"]["timeZone"] == "UTC"

    async def test_update_attendees_structured(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Attendees are sent as Graph emailAddress objects."""
        mock_http_client.patch.return_value = _make_response(
            200, {"id": "evt-1", "subject": "S"}
        )

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(
            event_id="evt-1", attendees=["a@example.com", "b@example.com"]
        )
        await outlook_calendar_update(args)

        json_body = mock_http_client.patch.call_args.kwargs["json"]
        addresses = [a["emailAddress"]["address"] for a in json_body["attendees"]]
        assert addresses == ["a@example.com", "b@example.com"]

    async def test_update_oauth_not_configured(self) -> None:
        """OAuth not configured returns reconnect instructions."""
        with patch(
            "admino.tools.outlook_calendar._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook_calendar import outlook_calendar_update

            args = OutlookCalendarUpdateArgs(event_id="evt-1", subject="X")
            result = await outlook_calendar_update(args)

        assert "OAuth error" in result

    async def test_update_api_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Non-200 returns a Graph error."""
        mock_http_client.patch.return_value = _make_response(
            404, {"error": {"message": "Not found"}}
        )

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(event_id="missing", subject="X")
        result = await outlook_calendar_update(args)

        assert "Microsoft Graph error" in result

    async def test_update_http_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """A transport error reports a connection failure."""
        mock_http_client.patch.side_effect = httpx.ConnectError("fail")

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(event_id="evt-1", subject="X")
        result = await outlook_calendar_update(args)

        assert "Failed to connect" in result


# ---------------------------------------------------------------------------
# 5. Argument validation
# ---------------------------------------------------------------------------


class TestOutlookCalendarArgValidation:
    """Pydantic validation rejects invalid arguments."""

    def test_read_valid_event_id_accepted(self) -> None:
        """Valid event_id is accepted."""
        args = OutlookCalendarReadArgs(event_id="AAMkAGI2")
        assert args.event_id == "AAMkAGI2"

    def test_read_overly_long_event_id_rejected(self) -> None:
        """event_id exceeding max_length is rejected."""
        with pytest.raises(ValidationError):
            OutlookCalendarReadArgs(event_id="x" * 201)

    def test_list_max_results_zero_rejected(self) -> None:
        """max_results=0 is rejected (ge=1)."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            OutlookCalendarListArgs(time_min=now, time_max=now + timedelta(days=1), max_results=0)

    def test_list_max_results_over_limit_rejected(self) -> None:
        """max_results exceeding le=50 is rejected."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            OutlookCalendarListArgs(time_min=now, time_max=now + timedelta(days=1), max_results=51)

    def test_create_subject_too_long_rejected(self) -> None:
        """Subject exceeding max_length=200 is rejected."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            OutlookCalendarCreateArgs(
                subject="x" * 201,
                start=now + timedelta(hours=1),
                end=now + timedelta(hours=2),
            )

    def test_create_body_too_long_rejected(self) -> None:
        """Body exceeding max_length=1000 is rejected."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            OutlookCalendarCreateArgs(
                subject="Meeting",
                start=now + timedelta(hours=1),
                end=now + timedelta(hours=2),
                body="x" * 1001,
            )

    def test_create_location_too_long_rejected(self) -> None:
        """Location exceeding max_length=200 is rejected."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            OutlookCalendarCreateArgs(
                subject="Meeting",
                start=now + timedelta(hours=1),
                end=now + timedelta(hours=2),
                location="x" * 201,
            )

    def test_create_defaults(self) -> None:
        """Default body and location are empty strings."""
        now = datetime.now(UTC)
        args = OutlookCalendarCreateArgs(
            subject="Meeting",
            start=now + timedelta(hours=1),
            end=now + timedelta(hours=2),
        )
        assert args.body == ""
        assert args.location == ""

    def test_list_default_max_results(self) -> None:
        """Default max_results is 10."""
        now = datetime.now(UTC)
        args = OutlookCalendarListArgs(time_min=now, time_max=now + timedelta(days=1))
        assert args.max_results == 10

    def test_update_requires_event_id(self) -> None:
        """Missing event_id is rejected."""
        with pytest.raises(ValidationError):
            OutlookCalendarUpdateArgs(subject="X")  # type: ignore[call-arg]

    def test_update_rejects_unsafe_event_id(self) -> None:
        """Path-traversal characters in event_id are rejected."""
        with pytest.raises(ValidationError):
            OutlookCalendarUpdateArgs(event_id="../../secrets")

    def test_update_rejects_invalid_attendee(self) -> None:
        """Malformed attendee addresses are rejected."""
        with pytest.raises(ValidationError):
            OutlookCalendarUpdateArgs(event_id="evt-1", attendees=["bad"])

    def test_update_rejects_attendee_with_newline(self) -> None:
        """Attendee header-injection attempts are rejected."""
        with pytest.raises(ValidationError):
            OutlookCalendarUpdateArgs(
                event_id="evt-1", attendees=["a@example.com\r\nBcc: x@y.com"]
            )

    def test_update_subject_too_long_rejected(self) -> None:
        """subject exceeding 200 chars is rejected."""
        with pytest.raises(ValidationError):
            OutlookCalendarUpdateArgs(event_id="evt-1", subject="x" * 201)

    def test_update_all_optional_default_none(self) -> None:
        """Only event_id is required; everything else defaults to None."""
        args = OutlookCalendarUpdateArgs(event_id="evt-1")
        assert args.subject is None
        assert args.start is None
        assert args.attendees is None
