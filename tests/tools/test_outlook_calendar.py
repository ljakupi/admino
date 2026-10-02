"""Tests for the Outlook Calendar tool (admino.tools.outlook_calendar).

Covers tool registration, happy-path responses, OAuth error handling,
API error handling, empty results, body truncation, event creation,
and argument validation. All HTTP calls are mocked.

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
    OutlookCalendarCreateArgs,
    OutlookCalendarListArgs,
    OutlookCalendarReadArgs,
    OutlookCalendarUpdateArgs,
)
from admino.oauth import OAuthError
from admino.tenancy import TenantContext
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


_WINDOW_START = datetime(2026, 4, 15, 9, 0, tzinfo=UTC)
_WINDOW_END = _WINDOW_START + timedelta(days=7)


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
        if hasattr(cal_mod, "get_pool"):
            stack.enter_context(patch.object(cal_mod, "get_pool", return_value=pool))
        yield


class _Api:
    """A mocked httpx.AsyncClient that answers every request with a plausible 2xx body.

    Logs each request's Authorization header under the calling task's ``_CALLER``.
    """

    def __init__(self) -> None:
        self.bearers: dict[str, list[str]] = {}
        self.client = AsyncMock(spec=httpx.AsyncClient)
        self.client.get.side_effect = self._answer(
            200, {**_sample_event(), "value": [_sample_event()]}
        )
        self.client.post.side_effect = self._answer(
            201, {"id": "new-evt-1", "webLink": "https://outlook.live.com/event/new-evt-1"}
        )
        self.client.patch.side_effect = self._answer(200, {"id": "evt-1", "subject": "Renamed"})

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
        result = await outlook_calendar_read(args, tenant=_TENANT)

        assert "Subject: Team Meeting" in result
        assert "Start: 2026-04-15T10:00:00" in result
        assert "End: 2026-04-15T11:00:00" in result
        assert "Location: Room 42" in result
        assert "Alice <alice@example.com>" in result
        assert "Web link:" in result

    async def test_read_url_encodes_graph_event_id(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Real Graph IDs (=, /, +) must be percent-encoded in the request path."""
        mock_http_client.get.return_value = _make_response(200, _sample_event())

        from admino.tools.outlook_calendar import outlook_calendar_read

        args = OutlookCalendarReadArgs(event_id="AAMkAGI1AB/Cd+Ef9=")
        await outlook_calendar_read(args, tenant=_TENANT)

        url = mock_http_client.get.call_args[0][0]
        assert "/me/events/AAMkAGI1AB%2FCd%2BEf9%3D" in url
        assert "AAMkAGI1AB/Cd+Ef9=" not in url

    async def test_read_oauth_not_configured(self) -> None:
        """OAuth not configured returns setup instructions."""
        with patch(
            "admino.tools.outlook_calendar._get_microsoft_token",
            new_callable=AsyncMock,
            side_effect=OAuthError("not configured"),
        ):
            from admino.tools.outlook_calendar import outlook_calendar_read

            args = OutlookCalendarReadArgs(event_id="evt-1")
            result = await outlook_calendar_read(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_read_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 returns Graph error message."""
        mock_http_client.get.return_value = _make_response(
            404, {"error": {"message": "Event not found"}}
        )

        from admino.tools.outlook_calendar import outlook_calendar_read

        args = OutlookCalendarReadArgs(event_id="bad-id")
        result = await outlook_calendar_read(args, tenant=_TENANT)

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
        result = await outlook_calendar_read(args, tenant=_TENANT)

        assert "[Truncated]" in result

    async def test_read_http_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """httpx.HTTPError returns connection failure message."""
        mock_http_client.get.side_effect = httpx.ConnectError("fail")

        from admino.tools.outlook_calendar import outlook_calendar_read

        args = OutlookCalendarReadArgs(event_id="evt-1")
        result = await outlook_calendar_read(args, tenant=_TENANT)

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
        result = await outlook_calendar_read(args, tenant=_TENANT)

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
        result = await outlook_calendar_list(args, tenant=_TENANT)

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
        result = await outlook_calendar_list(args, tenant=_TENANT)

        assert "No events found" in result

    async def test_list_url_uses_calendar_view_endpoint(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """The calendarView endpoint path stays in the URL string."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook_calendar import outlook_calendar_list

        now = datetime.now(UTC)
        args = OutlookCalendarListArgs(
            time_min=now, time_max=now + timedelta(days=7), max_results=5
        )
        await outlook_calendar_list(args, tenant=_TENANT)

        url = mock_http_client.get.call_args.args[0]
        assert "calendarView" in url

    async def test_list_query_options_passed_via_params(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """startDateTime, endDateTime, and $top are passed in the params dict."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook_calendar import outlook_calendar_list

        now = datetime.now(UTC)
        args = OutlookCalendarListArgs(
            time_min=now, time_max=now + timedelta(days=7), max_results=5
        )
        await outlook_calendar_list(args, tenant=_TENANT)

        params = mock_http_client.get.call_args.kwargs.get("params") or {}
        assert params["$top"] == 5
        assert "startDateTime" in params
        assert "endDateTime" in params

    async def test_list_top_absent_from_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """$top and the time-range options must NOT be in the URL string anymore."""
        mock_http_client.get.return_value = _make_response(200, {"value": []})

        from admino.tools.outlook_calendar import outlook_calendar_list

        now = datetime.now(UTC)
        args = OutlookCalendarListArgs(
            time_min=now, time_max=now + timedelta(days=7), max_results=5
        )
        await outlook_calendar_list(args, tenant=_TENANT)

        url = mock_http_client.get.call_args.args[0]
        assert "$top" not in url
        assert "startDateTime=" not in url
        assert "endDateTime=" not in url

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
            result = await outlook_calendar_list(args, tenant=_TENANT)

        assert "OAuth error" in result

    async def test_list_api_error(self, mock_token: AsyncMock, mock_http_client: AsyncMock) -> None:
        """Non-200 status returns Graph error."""
        mock_http_client.get.return_value = _make_response(403, {"error": {"message": "Forbidden"}})

        from admino.tools.outlook_calendar import outlook_calendar_list

        now = datetime.now(UTC)
        args = OutlookCalendarListArgs(time_min=now, time_max=now + timedelta(days=1))
        result = await outlook_calendar_list(args, tenant=_TENANT)

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
        result = await outlook_calendar_create(args, tenant=_TENANT)

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
            result = await outlook_calendar_create(args, tenant=_TENANT)

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
        result = await outlook_calendar_create(args, tenant=_TENANT)

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
        result = await outlook_calendar_create(args, tenant=_TENANT)

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
        result = await outlook_calendar_create(args, tenant=_TENANT)

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
        result = await outlook_calendar_update(args, tenant=_TENANT)

        assert "Renamed Meeting" in result
        assert "evt-1" in result

    async def test_update_uses_patch_to_correct_url(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Update issues a PATCH to /me/events/{id}."""
        mock_http_client.patch.return_value = _make_response(200, {"id": "evt-1", "subject": "X"})

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(event_id="evt-1", subject="X")
        await outlook_calendar_update(args, tenant=_TENANT)

        mock_http_client.patch.assert_called_once()
        url = mock_http_client.patch.call_args[0][0]
        assert url.endswith("/me/events/evt-1")

    async def test_update_url_encodes_graph_event_id(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Real Graph IDs contain =, /, + — they must be percent-encoded in the URL
        path, never interpolated raw (which would break the path / allow traversal)."""
        mock_http_client.patch.return_value = _make_response(200, {"id": "x", "subject": "X"})

        from admino.tools.outlook_calendar import outlook_calendar_update

        raw_id = "AAMkAGI1AB/Cd+Ef9="
        args = OutlookCalendarUpdateArgs(event_id=raw_id, subject="X")
        await outlook_calendar_update(args, tenant=_TENANT)

        url = mock_http_client.patch.call_args[0][0]
        assert "/me/events/AAMkAGI1AB%2FCd%2BEf9%3D" in url
        # The raw special characters must not appear unencoded in the path.
        assert "AAMkAGI1AB/Cd+Ef9=" not in url

    async def test_update_partial_body_only_provided_fields(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Only supplied fields are sent in the PATCH body."""
        mock_http_client.patch.return_value = _make_response(200, {"id": "evt-1", "subject": "New"})

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(event_id="evt-1", subject="New")
        await outlook_calendar_update(args, tenant=_TENANT)

        json_body = mock_http_client.patch.call_args.kwargs["json"]
        assert json_body == {"subject": "New"}
        assert "start" not in json_body
        assert "body" not in json_body

    async def test_update_body_and_location_structured(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """body and location are sent as Graph structured objects."""
        mock_http_client.patch.return_value = _make_response(200, {"id": "evt-1", "subject": "S"})

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(event_id="evt-1", body="New agenda", location="Room 9")
        await outlook_calendar_update(args, tenant=_TENANT)

        json_body = mock_http_client.patch.call_args.kwargs["json"]
        assert json_body["body"]["content"] == "New agenda"
        assert json_body["location"]["displayName"] == "Room 9"

    async def test_update_start_end_structured(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """start/end are sent as Graph dateTime/timeZone objects."""
        mock_http_client.patch.return_value = _make_response(200, {"id": "evt-1", "subject": "S"})

        from admino.tools.outlook_calendar import outlook_calendar_update

        now = datetime.now(UTC)
        args = OutlookCalendarUpdateArgs(event_id="evt-1", start=now, end=now + timedelta(hours=1))
        await outlook_calendar_update(args, tenant=_TENANT)

        json_body = mock_http_client.patch.call_args.kwargs["json"]
        assert "dateTime" in json_body["start"]
        assert json_body["start"]["timeZone"] == "UTC"

    async def test_update_attendees_structured(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """Attendees are sent as Graph emailAddress objects."""
        mock_http_client.patch.return_value = _make_response(200, {"id": "evt-1", "subject": "S"})

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(
            event_id="evt-1", attendees=["a@example.com", "b@example.com"]
        )
        await outlook_calendar_update(args, tenant=_TENANT)

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
            result = await outlook_calendar_update(args, tenant=_TENANT)

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
        result = await outlook_calendar_update(args, tenant=_TENANT)

        assert "Microsoft Graph error" in result

    async def test_update_http_error(
        self, mock_token: AsyncMock, mock_http_client: AsyncMock
    ) -> None:
        """A transport error reports a connection failure."""
        mock_http_client.patch.side_effect = httpx.ConnectError("fail")

        from admino.tools.outlook_calendar import outlook_calendar_update

        args = OutlookCalendarUpdateArgs(event_id="evt-1", subject="X")
        result = await outlook_calendar_update(args, tenant=_TENANT)

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

    def test_read_accepts_real_graph_event_id(self) -> None:
        """Real Microsoft Graph event IDs are base64 and contain =, /, + — accept them."""
        real_id = "AAMkAGI1AAAt9AHj/Ab+Cd9Ef=="
        args = OutlookCalendarReadArgs(event_id=real_id)
        assert args.event_id == real_id

    def test_update_accepts_real_graph_event_id(self) -> None:
        """Update must accept the same base64 Graph IDs (=, /, +)."""
        real_id = "AAMkAGI1AAAt9AHj/Ab+Cd9Ef=="
        args = OutlookCalendarUpdateArgs(event_id=real_id, subject="X")
        assert args.event_id == real_id

    def test_read_overly_long_event_id_rejected(self) -> None:
        """event_id exceeding max_length is rejected."""
        with pytest.raises(ValidationError):
            OutlookCalendarReadArgs(event_id="x" * 513)

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
            OutlookCalendarUpdateArgs(event_id="evt-1", attendees=["a@example.com\r\nBcc: x@y.com"])

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


# ---------------------------------------------------------------------------
# 6. Per-user tokens (GH-162)
# ---------------------------------------------------------------------------

_HANDLER_CASES = [
    pytest.param("outlook_calendar_read", OutlookCalendarReadArgs(event_id="evt-1"), id="read"),
    pytest.param(
        "outlook_calendar_list",
        OutlookCalendarListArgs(time_min=_WINDOW_START, time_max=_WINDOW_END),
        id="list",
    ),
    pytest.param(
        "outlook_calendar_create",
        OutlookCalendarCreateArgs(subject="New", start=_WINDOW_START, end=_WINDOW_END),
        id="create",
    ),
    pytest.param(
        "outlook_calendar_update",
        OutlookCalendarUpdateArgs(event_id="evt-1", subject="Renamed"),
        id="update",
    ),
]


class TestOutlookCalendarPerUserTokens:
    """GH-162: every handler call loads and sends the token of its own tenant.

    The module keeps no token state of its own: ``_get_microsoft_token(tenant)`` reads the
    process-wide per-user cache (``oauth.access_tokens``), and the tenant always
    comes from the handler's server-side context, never from tool arguments.
    """

    @pytest.mark.parametrize("name", _REMOVED_TOKEN_STATE)
    def test_outlook_calendar_module_level_token_state_removed(self, name: str) -> None:
        """The module-level token cache, its lock, its clear function and the old
        direct ``get_valid_access_token`` call are gone."""
        assert not hasattr(cal_mod, name)

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_outlook_calendar_handler_without_tenant_raises_type_error(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """``tenant`` is a required keyword: no call runs without a tool context."""
        api = _Api()
        handler = getattr(cal_mod, handler_name)
        with (
            patch.object(cal_mod, "_http_client", api.client),
            pytest.raises(TypeError, match="tenant"),
        ):
            await handler(args)
        mock_token.assert_not_awaited()
        assert api.all_bearers() == []

    @pytest.mark.parametrize(("handler_name", "args"), _HANDLER_CASES)
    async def test_outlook_calendar_handler_loads_and_sends_token_of_its_tenant(
        self, handler_name: str, args: BaseModel, mock_token: AsyncMock
    ) -> None:
        """Each action awaits ``_get_microsoft_token`` with the call's tenant and sends exactly
        the token it returned (extra context keywords such as session_id are accepted)."""
        api = _Api()
        handler = getattr(cal_mod, handler_name)
        with patch.object(cal_mod, "_http_client", api.client):
            await handler(args, session_id="sess-1", tenant=_TENANT_B)
        _assert_token_loaded_for(mock_token, _TENANT_B)
        assert api.all_bearers()
        assert set(api.all_bearers()) == {f"Bearer {mock_token.return_value}"}

    async def test_outlook_calendar_get_token_reads_shared_per_user_cache(self) -> None:
        """``_get_microsoft_token(tenant)`` returns
        ``await oauth.access_tokens.get(get_pool(), tenant, "microsoft", <module http client>)``,
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
            patch.object(cal_mod, "_http_client", client),
        ):
            tokens = [
                await cal_mod._get_microsoft_token(_TENANT),
                await cal_mod._get_microsoft_token(_TENANT_B),
                await cal_mod._get_microsoft_token(_TENANT),
            ]

        assert tokens == [
            f"cached-token-of-{_USER_A_ID}",
            f"cached-token-of-{_USER_B_ID}",
            f"cached-token-of-{_USER_A_ID}",
        ]
        calls = [_cache_get_arguments(c.args, c.kwargs) for c in cache_get.await_args_list]
        assert calls == [
            {"pool": pool, "tenant": _TENANT, "provider": "microsoft", "http_client": client},
            {"pool": pool, "tenant": _TENANT_B, "provider": "microsoft", "http_client": client},
            {"pool": pool, "tenant": _TENANT, "provider": "microsoft", "http_client": client},
        ]

    async def test_outlook_calendar_concurrent_users_each_request_carries_own_token(
        self, mock_token: AsyncMock
    ) -> None:
        """User A's token is never sent for user B: B's whole call runs while A's
        token load is still pending, and every request carries its own caller's token."""
        users = _TwoUsers()
        mock_token.side_effect = users.token_for
        api = _Api()
        with patch.object(cal_mod, "_http_client", api.client):
            result_a, result_b = await users.run(
                lambda: cal_mod.outlook_calendar_list(
                    OutlookCalendarListArgs(time_min=_WINDOW_START, time_max=_WINDOW_END),
                    tenant=_TENANT,
                ),
                lambda: cal_mod.outlook_calendar_list(
                    OutlookCalendarListArgs(time_min=_WINDOW_START, time_max=_WINDOW_END),
                    tenant=_TENANT_B,
                ),
            )

        _assert_bearers_isolated(api)
        assert "Team Meeting" in result_a
        assert "Team Meeting" in result_b

    async def test_outlook_calendar_shared_cache_never_serves_one_users_token_to_another(
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
                patch.object(cal_mod, "_http_client", api.client),
            ):
                await users.run(
                    lambda: cal_mod.outlook_calendar_list(
                        OutlookCalendarListArgs(time_min=_WINDOW_START, time_max=_WINDOW_END),
                        tenant=_TENANT,
                    ),
                    lambda: cal_mod.outlook_calendar_list(
                        OutlookCalendarListArgs(time_min=_WINDOW_START, time_max=_WINDOW_END),
                        tenant=_TENANT_B,
                    ),
                )
                await _call_as(
                    "A",
                    lambda: cal_mod.outlook_calendar_list(
                        OutlookCalendarListArgs(time_min=_WINDOW_START, time_max=_WINDOW_END),
                        tenant=_TENANT,
                    ),
                )
                await _call_as(
                    "B",
                    lambda: cal_mod.outlook_calendar_list(
                        OutlookCalendarListArgs(time_min=_WINDOW_START, time_max=_WINDOW_END),
                        tenant=_TENANT_B,
                    ),
                )
        finally:
            oauth.access_tokens.clear()

        _assert_bearers_isolated(api)
        own: dict[object, str] = {_USER_A_ID: _TOKEN_A, _USER_B_ID: _TOKEN_B}
        assert {user for user, _, _ in users.refreshes} == {_USER_A_ID, _USER_B_ID}
        assert all(provider == "microsoft" for _, provider, _ in users.refreshes)
        assert all(cached in (None, own[user]) for user, _, cached in users.refreshes)
