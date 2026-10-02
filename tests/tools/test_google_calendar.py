"""Tests for the Google Calendar tool module (admino.tools.google_calendar).

Covers tool registration, happy-path responses, OAuth errors, API errors,
empty results, event creation, and argument validation.
All HTTP calls are mocked -- no real API requests are made.

GH-162: every handler takes the caller's ``TenantContext`` as a required
``tenant`` keyword and loads that user's token through the shared per-user
cache (``oauth.access_tokens``); the module keeps no token state of its own.

Security notes: user A's access token is never sent on user B's requests,
including under concurrent calls (the concurrency tests interleave two users'
calls on purpose). Fake tokens only; no real API requests are made.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Iterator

    from pydantic import BaseModel

from admino.access import Principal
from admino.models import (
    GoogleCalendarCreateArgs,
    GoogleCalendarListArgs,
    GoogleCalendarReadArgs,
    GoogleCalendarUpdateArgs,
)
from admino.oauth import OAuthError
from admino.tenancy import TenantContext
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
# Per-user token helpers (GH-162)
# ---------------------------------------------------------------------------

_ORG_ID = UUID("00000000-0000-4000-8000-0000000000a1")
_USER_A_ID = UUID("00000000-0000-4000-8000-00000000000a")
_USER_B_ID = UUID("00000000-0000-4000-8000-00000000000b")
_TOKEN_A = "access-token-of-user-a"
_TOKEN_B = "access-token-of-user-b"

# The module-level token state GH-162 replaces with the shared per-user cache.
_REMOVED_TOKEN_STATE = (
    "_cached_token",
    "_cached_expires_at",
    "_token_lock",
    "clear_token_cache",
    "get_valid_access_token",
)

# Which concurrent handler call a request belongs to (each gather task has its own copy).
_CALLER: ContextVar[str] = ContextVar("_CALLER", default="none")


def _tenant_for(user_id: UUID) -> TenantContext:
    """An editor's tool context in the shared test organization."""
    return TenantContext.from_principal(
        Principal(user_id=user_id, kind="member", org_id=_ORG_ID, role="editor")
    )


_TENANT = _tenant_for(_USER_A_ID)
_TENANT_B = _tenant_for(_USER_B_ID)


def _tenant_arg(args: tuple[object, ...], kwargs: dict[str, object]) -> object:
    """The tenant a token getter was awaited with (positional or keyword)."""
    return args[0] if args else kwargs.get("tenant")


def _assert_token_loaded_for(mock_token: AsyncMock, tenant: TenantContext) -> None:
    """The token getter ran, and only ever for ``tenant``."""
    assert mock_token.await_count >= 1
    assert all(_tenant_arg(c.args, c.kwargs) == tenant for c in mock_token.await_args_list)


def _cache_get_arguments(args: tuple[object, ...], kwargs: dict[str, object]) -> dict[str, object]:
    """Bind one ``oauth.access_tokens.get`` call to the contract's parameter names."""

    def contract(pool: object, tenant: object, provider: object, http_client: object) -> None:
        """AccessTokenCache.get(pool, tenant, provider, http_client), without self."""

    return dict(inspect.signature(contract).bind(*args, **kwargs).arguments)


@contextmanager
def _pool_patched(pool: object) -> Iterator[None]:
    """Make ``get_pool()`` return ``pool`` however the tool module imports it."""
    with ExitStack() as stack:
        stack.enter_context(patch("admino.database.get_pool", return_value=pool))
        if hasattr(google_calendar, "get_pool"):
            stack.enter_context(patch.object(google_calendar, "get_pool", return_value=pool))
        yield


class _Api:
    """A mocked httpx.AsyncClient that answers every request with a plausible 2xx body.

    Logs each request's Authorization header under the calling task's ``_CALLER``.
    """

    def __init__(self) -> None:
        self.bearers: dict[str, list[str]] = {}
        self.client = AsyncMock(spec=httpx.AsyncClient)
        self.client.get.side_effect = self._answer(
            200, {**_sample_event(), "items": [_sample_event()]}
        )
        self.client.post.side_effect = self._answer(
            200, {"id": "evt_new", "htmlLink": "https://calendar.google.com/event?eid=evt_new"}
        )
        self.client.patch.side_effect = self._answer(200, {"id": "evt123", "summary": "Updated"})

    def _answer(
        self, status: int, body: dict[str, Any] | None
    ) -> Callable[..., Awaitable[httpx.Response]]:
        async def answer(url: str, *args: object, **kwargs: object) -> httpx.Response:
            headers = kwargs.get("headers")
            bearer = headers.get("Authorization") if isinstance(headers, dict) else None
            self.bearers.setdefault(_CALLER.get(), []).append(str(bearer))
            return _make_response(status, body)

        return answer

    def all_bearers(self) -> list[str]:
        """Every request's Authorization header, whoever made it."""
        return [bearer for bearers in self.bearers.values() for bearer in bearers]


class _TwoUsers:
    """User A's and user B's handler calls, interleaved so B runs entirely inside A's.

    A's token load waits until B's whole call has finished; each user gets their
    own token. ``refresh`` stands in for ``oauth.get_valid_access_token`` behind
    the real shared cache and records what the cache handed it.
    """

    def __init__(self) -> None:
        self.b_done = asyncio.Event()
        self.refreshes: list[tuple[object, object, object]] = []

    async def token_for(self, *args: object, **kwargs: object) -> str:
        """The caller's own token (A's load blocks until B is done)."""
        user_id = getattr(_tenant_arg(args, kwargs), "user_id", None)
        if user_id == _USER_A_ID:
            await self.b_done.wait()
            return _TOKEN_A
        if user_id == _USER_B_ID:
            return _TOKEN_B
        return "access-token-of-nobody"

    async def refresh(
        self,
        pool: object,
        tenant: object,
        provider: object,
        cached_token: object,
        cached_expires_at: object,
        http_client: object,
    ) -> tuple[str, datetime]:
        """Stand-in for get_valid_access_token: the tenant's own token, valid 1 h."""
        self.refreshes.append((getattr(tenant, "user_id", None), provider, cached_token))
        return await self.token_for(tenant), datetime.now(UTC) + timedelta(hours=1)

    async def run(
        self,
        call_a: Callable[[], Awaitable[str]],
        call_b: Callable[[], Awaitable[str]],
    ) -> tuple[str, str]:
        """Run both calls concurrently; a call that waits on the other one times out."""

        async def as_a() -> str:
            _CALLER.set("A")
            return await call_a()

        async def as_b() -> str:
            _CALLER.set("B")
            try:
                return await call_b()
            finally:
                self.b_done.set()

        result_a, result_b = await asyncio.wait_for(asyncio.gather(as_a(), as_b()), timeout=5)
        return result_a, result_b


async def _call_as(caller: str, call: Callable[[], Awaitable[str]]) -> str:
    """Run one handler call with its requests logged under ``caller``."""
    reset_token = _CALLER.set(caller)
    try:
        return await call()
    finally:
        _CALLER.reset(reset_token)


def _assert_bearers_isolated(api: _Api) -> None:
    """Every request of A's calls carried A's token; every request of B's, B's token."""
    assert api.bearers.get("A"), "user A's call made no API request"
    assert api.bearers.get("B"), "user B's call made no API request"
    assert set(api.bearers["A"]) == {f"Bearer {_TOKEN_A}"}
    assert set(api.bearers["B"]) == {f"Bearer {_TOKEN_B}"}


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

    def test_calendar_update_registered(self) -> None:
        """google_calendar.update is in the registry."""
        tools = get_registered_tools()
        keys = [(t.tool, t.action) for t in tools]
        assert ("google_calendar", "update") in keys


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
        result = await google_calendar.google_calendar_read(args, tenant=_TENANT)

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
            result = await google_calendar.google_calendar_read(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns API error."""
        mock_http.get.return_value = _make_response(
            404, {"error": {"code": 404, "message": "Not Found"}}
        )

        args = GoogleCalendarReadArgs(event_id="evt123")
        result = await google_calendar.google_calendar_read(args, tenant=_TENANT)

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
        result = await google_calendar.google_calendar_read(args, tenant=_TENANT)

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
                result = await google_calendar.google_calendar_read(args, tenant=_TENANT)

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
        result = await google_calendar.google_calendar_list(args, tenant=_TENANT)

        assert "Meeting 1" in result
        assert "Meeting 2" in result

    async def test_time_range_in_params(self, mock_http: AsyncMock) -> None:
        """timeMin and timeMax are passed as query parameters."""
        mock_http.get.return_value = _make_response(200, {"items": []})

        args = GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER, max_results=5)
        await google_calendar.google_calendar_list(args, tenant=_TENANT)

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
        result = await google_calendar.google_calendar_list(args, tenant=_TENANT)

        assert "No events found" in result

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns API error."""
        mock_http.get.return_value = _make_response(
            401, {"error": {"code": 401, "message": "Unauthorized"}}
        )

        args = GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER)
        result = await google_calendar.google_calendar_list(args, tenant=_TENANT)

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
            result = await google_calendar.google_calendar_list(args, tenant=_TENANT)

        assert "OAuth error" in result


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
        result = await google_calendar.google_calendar_create(args, tenant=_TENANT)

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
        result = await google_calendar.google_calendar_create(args, tenant=_TENANT)

        assert "Event created successfully" in result

    async def test_create_without_optional_fields(self, mock_http: AsyncMock) -> None:
        """Create without description/location works."""
        mock_http.post.return_value = _make_response(200, {"id": "evt_min"})

        args = GoogleCalendarCreateArgs(summary="Min Event", start=_NOW, end=_LATER)
        result = await google_calendar.google_calendar_create(args, tenant=_TENANT)

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
        await google_calendar.google_calendar_create(args, tenant=_TENANT)

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
        result = await google_calendar.google_calendar_create(args, tenant=_TENANT)

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
            result = await google_calendar.google_calendar_create(args, tenant=_TENANT)

        assert "OAuth error" in result


# ---------------------------------------------------------------------------
# 4b. google_calendar.update
# ---------------------------------------------------------------------------


class TestCalendarUpdate:
    """Tests for the google_calendar.update handler."""

    async def test_happy_path(self, mock_http: AsyncMock) -> None:
        """Successful update returns the updated event summary."""
        response_data = {
            "id": "evt123",
            "summary": "Updated Title",
            "htmlLink": "https://calendar.google.com/event?eid=evt123",
        }
        mock_http.patch.return_value = _make_response(200, response_data)

        args = GoogleCalendarUpdateArgs(event_id="evt123", summary="Updated Title")
        result = await google_calendar.google_calendar_update(args, tenant=_TENANT)

        assert "Updated Title" in result
        assert "evt123" in result

    async def test_uses_patch_to_correct_url(self, mock_http: AsyncMock) -> None:
        """Update issues a PATCH to the primary calendar event endpoint."""
        mock_http.patch.return_value = _make_response(200, {"id": "evt123", "summary": "X"})

        args = GoogleCalendarUpdateArgs(event_id="evt123", summary="X")
        await google_calendar.google_calendar_update(args, tenant=_TENANT)

        mock_http.patch.assert_called_once()
        url = mock_http.patch.call_args[0][0]
        assert url.endswith("/events/evt123")

    async def test_partial_body_only_includes_provided_fields(self, mock_http: AsyncMock) -> None:
        """Only the supplied fields are sent in the PATCH body."""
        mock_http.patch.return_value = _make_response(200, {"id": "evt123", "summary": "New"})

        args = GoogleCalendarUpdateArgs(event_id="evt123", summary="New", location="Room C")
        await google_calendar.google_calendar_update(args, tenant=_TENANT)

        json_body = mock_http.patch.call_args.kwargs["json"]
        assert json_body == {"summary": "New", "location": "Room C"}
        assert "description" not in json_body
        assert "start" not in json_body

    async def test_start_end_are_formatted_objects(self, mock_http: AsyncMock) -> None:
        """start/end are sent as Calendar dateTime objects."""
        mock_http.patch.return_value = _make_response(200, {"id": "evt123", "summary": "S"})

        args = GoogleCalendarUpdateArgs(event_id="evt123", start=_NOW, end=_LATER)
        await google_calendar.google_calendar_update(args, tenant=_TENANT)

        json_body = mock_http.patch.call_args.kwargs["json"]
        assert "dateTime" in json_body["start"]
        assert "dateTime" in json_body["end"]

    async def test_attendees_sent_as_email_dicts(self, mock_http: AsyncMock) -> None:
        """Attendees are sent as a list of {email: ...} dicts."""
        mock_http.patch.return_value = _make_response(200, {"id": "evt123", "summary": "S"})

        args = GoogleCalendarUpdateArgs(
            event_id="evt123", attendees=["a@example.com", "b@example.com"]
        )
        await google_calendar.google_calendar_update(args, tenant=_TENANT)

        json_body = mock_http.patch.call_args.kwargs["json"]
        assert json_body["attendees"] == [
            {"email": "a@example.com"},
            {"email": "b@example.com"},
        ]

    async def test_api_error(self, mock_http: AsyncMock) -> None:
        """Non-200 returns a formatted API error."""
        mock_http.patch.return_value = _make_response(
            404, {"error": {"code": 404, "message": "Not Found"}}
        )

        args = GoogleCalendarUpdateArgs(event_id="missing", summary="X")
        result = await google_calendar.google_calendar_update(args, tenant=_TENANT)

        assert "Google API error 404" in result

    async def test_oauth_error(self) -> None:
        """OAuthError returns reconnect instructions."""
        with patch.object(
            google_calendar,
            "_get_google_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("no token"),
        ):
            args = GoogleCalendarUpdateArgs(event_id="evt123", summary="X")
            result = await google_calendar.google_calendar_update(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_http_error(self, mock_http: AsyncMock) -> None:
        """A transport error is reported without leaking details."""
        mock_http.patch.side_effect = httpx.ConnectError("boom")

        args = GoogleCalendarUpdateArgs(event_id="evt123", summary="X")
        result = await google_calendar.google_calendar_update(args, tenant=_TENANT)

        assert "HTTP request failed" in result


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

    def test_update_requires_event_id(self) -> None:
        """Missing event_id is rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarUpdateArgs(summary="X")  # type: ignore[call-arg]

    def test_update_rejects_unsafe_event_id(self) -> None:
        """Path-traversal characters in event_id are rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarUpdateArgs(event_id="../../etc/passwd")

    def test_update_rejects_invalid_attendee(self) -> None:
        """Malformed attendee addresses are rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarUpdateArgs(event_id="evt123", attendees=["not-an-email"])

    def test_update_rejects_attendee_with_newline(self) -> None:
        """Attendee header-injection attempts are rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarUpdateArgs(event_id="evt123", attendees=["a@example.com\r\nBcc: x@y.com"])

    def test_update_summary_too_long(self) -> None:
        """summary exceeding 200 chars is rejected."""
        with pytest.raises(ValidationError):
            GoogleCalendarUpdateArgs(event_id="evt123", summary="x" * 201)

    def test_update_all_optional_fields_default_none(self) -> None:
        """Only event_id is required; everything else defaults to None."""
        args = GoogleCalendarUpdateArgs(event_id="evt123")
        assert args.summary is None
        assert args.start is None
        assert args.attendees is None


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


# ---------------------------------------------------------------------------
# 7. Per-user tokens (GH-162)
# ---------------------------------------------------------------------------

_HANDLER_CASES = [
    pytest.param("google_calendar_read", GoogleCalendarReadArgs(event_id="evt123"), id="read"),
    pytest.param(
        "google_calendar_list", GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER), id="list"
    ),
    pytest.param(
        "google_calendar_create",
        GoogleCalendarCreateArgs(summary="New", start=_NOW, end=_LATER),
        id="create",
    ),
    pytest.param(
        "google_calendar_update",
        GoogleCalendarUpdateArgs(event_id="evt123", summary="Updated"),
        id="update",
    ),
]


class TestCalendarPerUserTokens:
    """GH-162: every handler call loads and sends the token of its own tenant.

    The module keeps no token state of its own: ``_get_google_token(tenant)`` reads the
    process-wide per-user cache (``oauth.access_tokens``), and the tenant always
    comes from the handler's server-side context, never from tool arguments.
    """

    @pytest.mark.parametrize("name", _REMOVED_TOKEN_STATE)
    def test_google_calendar_module_level_token_state_removed(self, name: str) -> None:
        """The module-level token cache, its lock, its clear function and the old
        direct ``get_valid_access_token`` call are gone."""
        assert not hasattr(google_calendar, name)

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_google_calendar_handler_without_tenant_raises_type_error(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """``tenant`` is a required keyword: no call runs without a tool context."""
        api = _Api()
        handler = getattr(google_calendar, handler_name)
        with (
            patch.object(google_calendar, "_http_client", api.client),
            pytest.raises(TypeError, match="tenant"),
        ):
            await handler(args)
        mock_token.assert_not_awaited()
        assert api.all_bearers() == []

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_google_calendar_handler_loads_and_sends_token_of_its_tenant(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """Each action awaits ``_get_google_token`` with the call's tenant and sends exactly
        the token it returned (extra context keywords such as session_id are accepted)."""
        api = _Api()
        handler = getattr(google_calendar, handler_name)
        with patch.object(google_calendar, "_http_client", api.client):
            await handler(args, session_id="sess-1", tenant=_TENANT_B)
        _assert_token_loaded_for(mock_token, _TENANT_B)
        assert api.all_bearers()
        assert set(api.all_bearers()) == {f"Bearer {mock_token.return_value}"}

    async def test_google_calendar_get_token_reads_shared_per_user_cache(self) -> None:
        """``_get_google_token(tenant)`` returns
        ``await oauth.access_tokens.get(get_pool(), tenant, "google", <module http client>)``,
        per call and per tenant (no module-level memo)."""
        from admino import oauth

        pool = object()
        client = AsyncMock(spec=httpx.AsyncClient)

        async def per_user(*args: object, **kwargs: object) -> str:
            tenant = _cache_get_arguments(args, kwargs)["tenant"]
            return f"cached-token-of-{getattr(tenant, 'user_id', None)}"

        with (
            patch.object(
                oauth.access_tokens, "get", new_callable=AsyncMock, side_effect=per_user
            ) as cache_get,
            _pool_patched(pool),
            patch.object(google_calendar, "_http_client", client),
        ):
            tokens = [
                await google_calendar._get_google_token(_TENANT),
                await google_calendar._get_google_token(_TENANT_B),
                await google_calendar._get_google_token(_TENANT),
            ]

        assert tokens == [
            f"cached-token-of-{_USER_A_ID}",
            f"cached-token-of-{_USER_B_ID}",
            f"cached-token-of-{_USER_A_ID}",
        ]
        calls = [_cache_get_arguments(c.args, c.kwargs) for c in cache_get.await_args_list]
        assert calls == [
            {"pool": pool, "tenant": _TENANT, "provider": "google", "http_client": client},
            {"pool": pool, "tenant": _TENANT_B, "provider": "google", "http_client": client},
            {"pool": pool, "tenant": _TENANT, "provider": "google", "http_client": client},
        ]

    async def test_google_calendar_concurrent_users_each_request_carries_own_token(
        self, mock_token: AsyncMock
    ) -> None:
        """User A's token is never sent for user B: B's whole call runs while A's
        token load is still pending, and every request carries its own caller's token."""
        users = _TwoUsers()
        mock_token.side_effect = users.token_for
        api = _Api()
        with patch.object(google_calendar, "_http_client", api.client):
            result_a, result_b = await users.run(
                lambda: google_calendar.google_calendar_list(
                    GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER), tenant=_TENANT
                ),
                lambda: google_calendar.google_calendar_list(
                    GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER), tenant=_TENANT_B
                ),
            )

        _assert_bearers_isolated(api)
        assert "Team Standup" in result_a
        assert "Team Standup" in result_b

    async def test_google_calendar_shared_cache_never_serves_one_users_token_to_another(
        self,
    ) -> None:
        """Through the real per-user cache (only the refresh is faked): concurrent calls
        don't wait on each other, repeated calls keep each user's token, and the cache
        never hands one user's cached token to the other user's refresh."""
        from admino import oauth

        users = _TwoUsers()
        api = _Api()
        oauth.access_tokens.clear()
        try:
            with (
                patch("admino.oauth.get_valid_access_token", new=users.refresh),
                _pool_patched(object()),
                patch.object(google_calendar, "_http_client", api.client),
            ):
                await users.run(
                    lambda: google_calendar.google_calendar_list(
                        GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER), tenant=_TENANT
                    ),
                    lambda: google_calendar.google_calendar_list(
                        GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER), tenant=_TENANT_B
                    ),
                )
                await _call_as(
                    "A",
                    lambda: google_calendar.google_calendar_list(
                        GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER), tenant=_TENANT
                    ),
                )
                await _call_as(
                    "B",
                    lambda: google_calendar.google_calendar_list(
                        GoogleCalendarListArgs(time_min=_NOW, time_max=_LATER), tenant=_TENANT_B
                    ),
                )
        finally:
            oauth.access_tokens.clear()

        _assert_bearers_isolated(api)
        own: dict[object, str] = {_USER_A_ID: _TOKEN_A, _USER_B_ID: _TOKEN_B}
        assert {user for user, _, _ in users.refreshes} == {_USER_A_ID, _USER_B_ID}
        assert all(provider == "google" for _, provider, _ in users.refreshes)
        assert all(cached in (None, own[user]) for user, _, cached in users.refreshes)
