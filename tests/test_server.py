"""Comprehensive test suite for admino.server — HTTP layer, auth, SSE, confirmations.

Tests the FastAPI application created by ``create_app()``, covering:
- Health check (no session required)
- Session-cookie authentication (GH-149): every chat route answers 401
  ``{"detail": "Unauthorized"}`` without a valid ``admino_session`` cookie; the
  old bearer token / vpn mode is gone (an ``Authorization`` header authenticates
  nothing, ``config.auth`` is never read, no VPN warning).
- The ``chat.send`` role gate: Org Admins and Editors may chat; Viewers and
  Super Admins get 403 ``{"detail": "Forbidden"}`` on POST /api/message,
  POST /api/confirm/{id} and GET /api/events.
- POST /api/message and POST /api/confirm/{id} pass the logged-in principal to
  ``agent.run(principal=...)`` (and, through a real Agent, to the tool-call
  recorder).
- POST /api/message (happy path, agent status variants, input validation)
- SSE streaming via GET /api/events
- Confirmation flow via POST /api/confirm/{confirmation_id}
- Session management and isolation
- CORS middleware (``Authorization`` is no longer an allowed header)
- Per-caller rate limits (GH-149): ``_check_rate_limit(route, caller)`` keeps
  one token bucket per (route, caller) in ``_rate_buckets``; one user (or IP)
  exhausting a bucket never throttles another; idle buckets are evicted and
  the map is capped (LRU).
- Error handling (validation errors, agent exceptions, malformed JSON)
- Security invariants (AST scans, no forbidden imports)
- Static file serving

Callers are logged in through ``tests.auth_helpers.login`` (a dependency
override of ``server.require_session``); ``resolved_session`` drives the real
cookie dependency with a patched ``admino.sessions.resolve_session``.

Security notes:
- All tests use mocked Agent and config — no real LLM, database or external calls.
- The session token is a known fake value, never a real secret.
"""

from __future__ import annotations

import ast
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest
import pytest_asyncio
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, Field

from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
)
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.server import create_app
from admino.tools.registry import clear_registry, register_tool
from tests.auth_helpers import (
    TEST_MEMBER_ID,
    TEST_SESSION_TOKEN,
    login,
    member_session,
    resolved_session,
    session_cookie,
    super_admin_session,
)

if TYPE_CHECKING:
    from collections.abc import Generator

    from admino.access import MemberRole, Principal
    from admino.sessions import AuthenticatedSession


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# A second member of the same organization, for per-user isolation tests.
_OTHER_USER_ID = UUID("22222222-3333-4444-8555-666666666666")

_UNAUTHORIZED = {"detail": "Unauthorized"}
_FORBIDDEN = {"detail": "Forbidden"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> Any:
    """Build a minimal mock AppConfig.

    It has no ``auth`` attribute at all (GH-149): the server must never read
    ``config.auth`` again, so touching it raises AttributeError.
    """
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    return config


def _make_agent_result(
    *,
    status: str = "final",
    response: str = "Hello from the agent.",
    history: list[LLMMessage] | None = None,
    tool_calls: list[ToolCallRecord] | None = None,
    pending_confirmation: PendingConfirmation | None = None,
) -> AgentResult:
    """Build an AgentResult with sensible defaults."""
    if history is None:
        history = [
            LLMMessage(role="user", content="hi"),
            LLMMessage(role="assistant", content=response),
        ]
    if tool_calls is None:
        tool_calls = []
    return AgentResult(
        status=status,
        response=response,
        history=history,
        tool_calls=tool_calls,
        pending_confirmation=pending_confirmation,
    )


class FakeAgent:
    """A fake Agent that returns scripted AgentResult values in sequence."""

    def __init__(self, results: list[AgentResult]) -> None:
        self._results = list(results)
        self._call_index = 0
        self.run_calls: list[dict[str, Any]] = []

    async def run(
        self,
        user_message: str,
        session_id: str,
        *,
        history: list[LLMMessage],
        principal: Principal,
        pending_confirmation: PendingConfirmation | None = None,
    ) -> AgentResult:
        """Record the call (GH-149: ``principal`` is a required keyword) and reply."""
        self.run_calls.append(
            {
                "user_message": user_message,
                "session_id": session_id,
                "history": history,
                "principal": principal,
                "pending_confirmation": pending_confirmation,
            }
        )
        if self._call_index >= len(self._results):
            return _make_agent_result()
        result = self._results[self._call_index]
        self._call_index += 1
        return result


def _make_app(
    agent: Any = None,
    *,
    session: AuthenticatedSession | None = None,
    anonymous: bool = False,
    config: Any = None,
) -> Any:
    """Create a FastAPI app with the given agent and config, and log a caller in.

    The caller is ``session`` (default: an Editor member, who may chat). With
    ``anonymous=True`` nobody is logged in, so the real cookie dependency runs.
    """
    if agent is None:
        agent = FakeAgent([_make_agent_result()])
    app = create_app(agent=agent, config=config if config is not None else _make_config())
    if not anonymous:
        login(app, session if session is not None else member_session("editor"))
    return app


def _make_pending_confirmation(
    *,
    confirmation_id: str = "confirm-abc-123",
    session_id: str = "test-session",
    tool: str = "calendar",
    action: str = "create",
    expired: bool = False,
) -> PendingConfirmation:
    """Build a PendingConfirmation for testing."""
    now = datetime.now(UTC)
    if expired:
        expires_at = now - timedelta(seconds=1)
        created_at = now - timedelta(seconds=60)
    else:
        created_at = now
        expires_at = now + timedelta(seconds=300)
    return PendingConfirmation(
        confirmation_id=confirmation_id,
        session_id=session_id,
        tool_call=ToolCall(tool=tool, action=action, args={}),
        created_at=created_at,
        expires_at=expires_at,
    )


# ---------------------------------------------------------------------------
# Test Classes
# ---------------------------------------------------------------------------


def _set_health_config(
    *, provider: str = "vllm", model: str = "mlx-community/gemma-4-12B-it-4bit"
) -> None:
    """Give server._config real (JSON-serializable) LLM identity fields for /health.

    The default _make_config returns a MagicMock, whose attributes are not
    JSON-serializable. The /health payload now echoes the active provider and
    model (issue #134), so these must be concrete strings.
    """
    from admino import server

    assert server._config is not None
    server._config.llm.provider = provider
    server._config.llm.active_model_name = model


class TestHealthCheck:
    """GET /health — no auth required. Reports DB + active LLM provider/model/reachability."""

    pytestmark = pytest.mark.asyncio

    async def test_server_health_returns_200_ok(self) -> None:
        """A healthy DB + reachable LLM returns 200 with status ok."""
        app = _make_app()
        _set_health_config()
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    async def test_server_health_reports_active_provider_and_model(self) -> None:
        """/health echoes the active provider and model (issue #134)."""
        app = _make_app()
        _set_health_config(provider="vllm", model="mlx-community/gemma-4-12B-it-4bit")
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        body = resp.json()
        assert body["provider"] == "vllm"
        assert body["model"] == "mlx-community/gemma-4-12B-it-4bit"

    async def test_server_health_reports_llm_reachable_true(self) -> None:
        """llm_reachable is True (bool) when the LLM probe succeeds (issue #134)."""
        app = _make_app()
        _set_health_config()
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.json()["llm_reachable"] is True

    async def test_server_health_reports_llm_reachable_false(self) -> None:
        """llm_reachable is False when the LLM probe fails, but the DB is up → still 200."""
        app = _make_app()
        _set_health_config()
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=False)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200
        assert resp.json()["llm_reachable"] is False

    async def test_server_health_no_auth_required(self) -> None:
        """Health check is public: it succeeds with no session cookie."""
        app = _make_app(anonymous=True)
        _set_health_config()
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200

    async def test_server_health_returns_503_when_db_unreachable(self) -> None:
        """Health check returns 503 when check_health() returns False (unchanged)."""
        app = _make_app()
        _set_health_config()
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=False)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 503
        assert resp.json()["detail"] == "Database unreachable"


_MESSAGE_BODY: dict[str, Any] = {"message": "hello", "session_id": "sess1"}
_CONFIRM_BODY: dict[str, Any] = {
    "session_id": "sess1",
    "confirmation_id": "some-id",
    "approved": True,
}


async def _call_chat_route(client: AsyncClient, route: str, **kwargs: Any) -> Any:
    """Send a well-formed request to one of the three chat routes."""
    if route == "message":
        return await client.post("/api/message", json=_MESSAGE_BODY, **kwargs)
    if route == "confirm":
        return await client.post("/api/confirm/some-id", json=_CONFIRM_BODY, **kwargs)
    return await client.get("/api/events", params={"session_id": "sess1"}, **kwargs)


_CHAT_ROUTES = ["message", "confirm", "events"]


class TestAuth:
    """Session-cookie authentication (GH-149): no valid admino_session cookie -> 401."""

    pytestmark = pytest.mark.asyncio

    async def test_server_post_message_no_auth_returns_401(self) -> None:
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Unauthorized"

    async def test_server_post_message_unknown_session_cookie_returns_401(self) -> None:
        """A cookie that resolves to no session (unknown, revoked, expired) -> 401."""
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent, anonymous=True)
        with resolved_session(None):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.post(
                    "/api/message",
                    json={"message": "hello", "session_id": "sess1"},
                    headers=session_cookie(),
                )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Unauthorized"
        assert agent.run_calls == []

    async def test_server_post_message_valid_session_cookie_succeeds(self) -> None:
        """A cookie that resolves to an Editor's session is let through."""
        app = _make_app(anonymous=True)
        with resolved_session(member_session("editor")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.post(
                    "/api/message",
                    json={"message": "hello", "session_id": "sess1"},
                    headers=session_cookie(),
                )
        assert resp.status_code == 200

    async def test_server_session_cookie_value_is_what_gets_resolved(self) -> None:
        """require_session looks up exactly the admino_session cookie's token."""
        app = _make_app(anonymous=True)
        with resolved_session(member_session("editor")) as resolve:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                await c.post(
                    "/api/message",
                    json={"message": "hello", "session_id": "sess1"},
                    headers=session_cookie(),
                )
        resolve.assert_awaited_once()
        call = resolve.await_args
        assert call is not None
        assert TEST_SESSION_TOKEN in (*call.args, *call.kwargs.values())

    async def test_server_session_cookie_principal_reaches_agent(self) -> None:
        """The principal comes from the resolved session, never from the request."""
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent, anonymous=True)
        session = member_session("org_admin", user_id=_OTHER_USER_ID)
        with resolved_session(session):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                await c.post(
                    "/api/message",
                    json={"message": "hello", "session_id": "sess1"},
                    headers=session_cookie(),
                )
        assert [call["principal"] for call in agent.run_calls] == [session.principal]

    async def test_server_cookie_with_another_name_returns_401(self) -> None:
        """Only the admino_session cookie counts; another cookie name is no session."""
        app = _make_app(anonymous=True)
        with resolved_session(member_session("editor")) as resolve:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.post(
                    "/api/message",
                    json={"message": "hello", "session_id": "sess1"},
                    headers={"Cookie": f"session={TEST_SESSION_TOKEN}"},
                )
        assert resp.status_code == 401
        resolve.assert_not_awaited()

    async def test_server_get_events_no_auth_returns_401(self) -> None:
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/events", params={"session_id": "sess1"})
        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    async def test_server_post_confirm_no_auth_returns_401(self) -> None:
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/confirm/some-id",
                json={
                    "session_id": "sess1",
                    "confirmation_id": "some-id",
                    "approved": True,
                },
            )
        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    async def test_server_auth_401_body_no_internal_details(self) -> None:
        """401 response body must be exactly {"detail": "Unauthorized"}."""
        app = _make_app(anonymous=True)
        with resolved_session(None):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.post(
                    "/api/message",
                    json={"message": "hello", "session_id": "sess1"},
                    headers=session_cookie("bad-token"),
                )
        body = resp.json()
        assert body == {"detail": "Unauthorized"}

    @pytest.mark.parametrize(
        "authorization",
        [
            "Bearer " + "a" * 48 + "BcDeFgHiJkLmNoPqRsTuVwXyZ",
            f"Bearer {TEST_SESSION_TOKEN}",
        ],
        ids=["old-auth-token", "session-token-as-bearer"],
    )
    async def test_server_bearer_authorization_header_does_not_authenticate(
        self, authorization: str
    ) -> None:
        """The bearer token auth is gone: an Authorization header alone gets a 401."""
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent, anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
                headers={"Authorization": authorization},
            )
        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED
        assert agent.run_calls == []


class TestChatRoleGate:
    """The chat routes additionally need chat.send (Org Admin / Editor), GH-149."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    async def test_server_post_message_chat_sender_role_succeeds(self, role: MemberRole) -> None:
        app = _make_app(session=member_session(role))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/message", json=_MESSAGE_BODY)
        assert resp.status_code == 200

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    async def test_server_get_events_chat_sender_role_succeeds(self, role: MemberRole) -> None:
        app = _make_app(session=member_session(role))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/events", params={"session_id": "sess1"})
        assert resp.status_code == 200

    @pytest.mark.parametrize("route", _CHAT_ROUTES)
    async def test_server_chat_route_viewer_returns_403(self, route: str) -> None:
        """A Viewer is read-only: no chat."""
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent, session=member_session("viewer"))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await _call_chat_route(c, route)
        assert resp.status_code == 403
        assert resp.json() == _FORBIDDEN
        assert agent.run_calls == []

    @pytest.mark.parametrize("route", _CHAT_ROUTES)
    async def test_server_chat_route_super_admin_returns_403(self, route: str) -> None:
        """Operator blindness: the Super Admin has no chat capability."""
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent, session=super_admin_session())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await _call_chat_route(c, route)
        assert resp.status_code == 403
        assert resp.json() == _FORBIDDEN
        assert agent.run_calls == []

    @pytest.mark.parametrize("route", _CHAT_ROUTES)
    async def test_server_chat_route_without_session_returns_401_not_403(self, route: str) -> None:
        """Authentication comes before the role check."""
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await _call_chat_route(c, route)
        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED


class TestAgentReceivesPrincipal:
    """post_message / post_confirm pass the logged-in principal to agent.run (GH-149)."""

    pytestmark = pytest.mark.asyncio

    async def test_server_post_message_passes_logged_in_principal(self) -> None:
        agent = FakeAgent([_make_agent_result()])
        session = member_session("editor", user_id=_OTHER_USER_ID)
        app = _make_app(agent, session=session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/message", json=_MESSAGE_BODY)
        assert resp.status_code == 200
        assert len(agent.run_calls) == 1
        assert agent.run_calls[0]["principal"] == session.principal

    async def test_server_post_confirm_passes_logged_in_principal(self) -> None:
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting, _make_agent_result(response="Done.")])
        session = member_session("org_admin", user_id=_OTHER_USER_ID)
        app = _make_app(agent, session=session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "create", "session_id": "sess1"})
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
            )
        assert resp.status_code == 200
        assert len(agent.run_calls) == 2
        assert agent.run_calls[1]["pending_confirmation"] is not None
        assert agent.run_calls[1]["principal"] == session.principal

    async def test_server_each_request_passes_its_own_principal(self) -> None:
        """Two users on one app: each agent run gets the principal of its own request."""
        agent = FakeAgent([_make_agent_result(), _make_agent_result()])
        first = member_session("editor")
        second = member_session("org_admin", user_id=_OTHER_USER_ID)
        app = _make_app(agent, session=first)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "a", "session_id": "sess-a"})
            login(app, second)
            await c.post("/api/message", json={"message": "b", "session_id": "sess-b"})
        assert [call["principal"] for call in agent.run_calls] == [
            first.principal,
            second.principal,
        ]


class TestPostMessage:
    """POST /api/message — happy path and agent status variants."""

    pytestmark = pytest.mark.asyncio

    async def test_server_message_final_status_returns_200(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "sess1"
        assert data["response"] == "Hello from the agent."
        assert isinstance(data["tool_calls"], list)

    async def test_server_message_awaiting_confirmation_includes_pending(self) -> None:
        pending = _make_pending_confirmation(session_id="sess1")
        result = _make_agent_result(
            status="awaiting_confirmation",
            response="Calendar event requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([result])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "confirmation" in data["response"].lower() or data["response"]

    async def test_server_message_limit_reached_returns_200(self) -> None:
        result = _make_agent_result(
            status="limit_reached",
            response="Tool call limit reached.",
        )
        agent = FakeAgent([result])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "do many things", "session_id": "sess1"},
            )
        assert resp.status_code == 200
        assert "limit" in resp.json()["response"].lower()

    async def test_server_message_error_status_returns_200(self) -> None:
        result = _make_agent_result(
            status="error",
            response="Something went wrong.",
        )
        agent = FakeAgent([result])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "fail", "session_id": "sess1"},
            )
        assert resp.status_code == 200

    async def test_server_message_agent_exception_returns_500(self) -> None:
        """Unexpected agent exception yields 500 with generic message."""
        agent = MagicMock()
        agent.run = AsyncMock(side_effect=RuntimeError("boom"))
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "fail", "session_id": "sess1"},
            )
        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"] == "Internal error"
        # Must NOT contain the actual exception message
        assert "boom" not in json.dumps(data)

    async def test_server_message_with_tool_calls_in_response(self) -> None:
        tc = ToolCallRecord(tool="gmail", action="read", permission="allow", success=True)
        result = _make_agent_result(
            response="Here are your emails.",
            tool_calls=[tc],
        )
        agent = FakeAgent([result])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "read emails", "session_id": "sess1"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["tool_calls"]) == 1
        assert data["tool_calls"][0]["tool"] == "gmail"


class TestInputValidation:
    """POST /api/message — input validation (Pydantic)."""

    pytestmark = pytest.mark.asyncio

    async def test_server_message_missing_message_field_returns_422(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"session_id": "sess1"},
            )
        assert resp.status_code == 422

    async def test_server_message_missing_session_id_returns_422(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello"},
            )
        assert resp.status_code == 422

    async def test_server_message_empty_message_returns_422(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "", "session_id": "sess1"},
            )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "session_id",
        [
            "invalid session!@#",
            "session with spaces",
            "../traversal",
            "a" * 65,  # exceeds max_length=64
            "<script>alert(1)</script>",
        ],
    )
    async def test_server_message_invalid_session_id_returns_422(self, session_id: str) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": session_id},
            )
        assert resp.status_code == 422

    async def test_server_message_oversized_message_returns_422(self) -> None:
        app = _make_app()
        oversized = "x" * 32769  # exceeds max_length=32768
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": oversized, "session_id": "sess1"},
            )
        assert resp.status_code == 422

    async def test_server_validation_error_no_raw_input_leakage(self) -> None:
        """422 response must not contain the raw invalid input values."""
        app = _make_app()
        bad_session = "EVIL_INPUT!@#$%^&*()"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": bad_session},
            )
        assert resp.status_code == 422
        body_text = resp.text
        assert bad_session not in body_text

    async def test_server_malformed_json_body_returns_422(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                content=b"not valid json{{{",
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 422


class TestSSE:
    """GET /api/events — SSE streaming endpoint."""

    pytestmark = pytest.mark.asyncio

    async def test_server_events_returns_event_stream_content_type(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/api/events",
                params={"session_id": "sess1"},
            )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]

    async def test_server_events_empty_session_streams_done(self) -> None:
        """Empty session streams just a done event."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/api/events",
                params={"session_id": "sess1"},
            )
        assert resp.status_code == 200
        body = resp.text
        assert "event: done" in body

    async def test_server_events_with_session_history_streams_status_and_done(self) -> None:
        """Session with history streams status and done events."""
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)
        # First, create a session by posting a message
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
            # Now get events for that session
            resp = await c.get(
                "/api/events",
                params={"session_id": "sess1"},
            )
        assert resp.status_code == 200
        body = resp.text
        assert "event: status" in body
        assert "event: done" in body

    async def test_server_events_sse_frame_format(self) -> None:
        """Each SSE frame must be properly formatted: event: ...\\ndata: ...\\n\\n."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/api/events",
                params={"session_id": "empty-sess"},
            )
        body = resp.text
        # Split into frames by double newline
        frames = [f.strip() for f in body.split("\n\n") if f.strip()]
        for frame in frames:
            lines = frame.split("\n")
            assert any(line.startswith("event: ") for line in lines)
            assert any(line.startswith("data: ") for line in lines)

    async def test_server_events_invalid_session_id_returns_422(self) -> None:
        """Oversized session_id returns 422 (Pydantic Query validation)."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/api/events",
                params={"session_id": "x" * 65},
            )
        assert resp.status_code == 422

    async def test_server_events_empty_session_id_returns_422(self) -> None:
        """Empty session_id returns 422 (Pydantic Query validation)."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/api/events",
                params={"session_id": ""},
            )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "session_id",
        [
            "invalid session!@#",
            "../traversal",
            "<script>alert(1)</script>",
        ],
    )
    async def test_server_events_invalid_session_id_pattern_returns_422(
        self, session_id: str
    ) -> None:
        """Session IDs with invalid characters return 422."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/api/events",
                params={"session_id": session_id},
            )
        assert resp.status_code == 422


class TestConfirmation:
    """POST /api/confirm/{confirmation_id} — confirmation flow."""

    pytestmark = pytest.mark.asyncio

    async def test_server_confirm_no_pending_returns_404(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/confirm/some-id",
                json={
                    "session_id": "sess1",
                    "confirmation_id": "some-id",
                    "approved": True,
                },
            )
        assert resp.status_code == 404

    async def test_server_confirm_approved_resumes_agent(self) -> None:
        """Approve a pending confirmation -> agent resumes -> final response."""
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Calendar event requires confirmation.",
            pending_confirmation=pending,
        )
        resumed_result = _make_agent_result(
            status="final",
            response="Event created successfully.",
        )
        agent = FakeAgent([awaiting_result, resumed_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Step 1: send message that triggers confirmation
            resp1 = await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
            assert resp1.status_code == 200

            # Step 2: confirm
            resp2 = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
            )
        assert resp2.status_code == 200
        data = resp2.json()
        assert data["response"] == "Event created successfully."

    async def test_server_confirm_denied_returns_denial_message(self) -> None:
        """Deny a pending confirmation -> pending removed, denial message."""
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Calendar event requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": False,
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "denied" in data["response"].lower()

    async def test_server_confirm_mismatched_confirmation_id_returns_404(self) -> None:
        """Confirmation ID in URL doesn't match pending -> 404."""
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
            resp = await c.post(
                "/api/confirm/wrong-id",
                json={
                    "session_id": "sess1",
                    "confirmation_id": "wrong-id",
                    "approved": True,
                },
            )
        assert resp.status_code == 404

    async def test_server_confirm_body_id_mismatch_returns_400(self) -> None:
        """Body confirmation_id doesn't match URL path -> 400."""
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": "different-id-in-body",
                    "approved": True,
                },
            )
        assert resp.status_code == 400

    async def test_server_confirm_double_confirm_returns_404(self) -> None:
        """After confirming once, same confirmation_id yields 404."""
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        resumed_result = _make_agent_result(
            status="final",
            response="Done.",
        )
        agent = FakeAgent([awaiting_result, resumed_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
            # First confirm
            resp1 = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
            )
            assert resp1.status_code == 200

            # Second confirm — already consumed
            resp2 = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
            )
        assert resp2.status_code == 404

    async def test_server_confirm_wrong_session_returns_404(self) -> None:
        """Confirm with session_id that has no pending returns 404."""
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess2",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
            )
        assert resp.status_code == 404

    async def test_server_confirm_agent_exception_returns_500(self) -> None:
        """Agent raises during resume -> 500 with generic message."""
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        agent = MagicMock()
        agent.run = AsyncMock(side_effect=[awaiting_result, RuntimeError("boom")])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
            )
        assert resp.status_code == 500
        assert resp.json()["detail"] == "Internal error"


class TestSessionManagement:
    """Session creation, reuse, and isolation."""

    pytestmark = pytest.mark.asyncio

    async def test_server_session_created_on_first_message(self) -> None:
        """First message creates a session; agent receives empty history."""
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "new-sess"},
            )
        assert resp.status_code == 200
        # Agent was called with empty history (new session)
        assert len(agent.run_calls) == 1
        assert agent.run_calls[0]["history"] == []

    async def test_server_session_reuses_history(self) -> None:
        """Second message to same session_id builds on returned history."""
        history1 = [
            LLMMessage(role="user", content="hello"),
            LLMMessage(role="assistant", content="hi"),
        ]
        result1 = _make_agent_result(response="hi", history=history1)
        result2 = _make_agent_result(response="how can I help?")
        agent = FakeAgent([result1, result2])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
            await c.post(
                "/api/message",
                json={"message": "help me", "session_id": "sess1"},
            )
        # Second call should receive the history from the first result
        assert len(agent.run_calls) == 2
        assert agent.run_calls[1]["history"] == history1

    async def test_server_sessions_are_isolated(self) -> None:
        """Messages to session A do not appear in session B."""
        history_a = [LLMMessage(role="user", content="session-a-msg")]
        result_a = _make_agent_result(response="a-reply", history=history_a)
        result_b = _make_agent_result(response="b-reply")
        agent = FakeAgent([result_a, result_b])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "msg-a", "session_id": "sessA"},
            )
            await c.post(
                "/api/message",
                json={"message": "msg-b", "session_id": "sessB"},
            )
        # Session B should receive empty history (new session)
        assert agent.run_calls[1]["history"] == []

    async def test_server_new_session_creates_new_history(self) -> None:
        """A different session_id creates a new, empty session."""
        agent = FakeAgent([_make_agent_result(), _make_agent_result()])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
            await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess2"},
            )
        assert agent.run_calls[0]["history"] == []
        assert agent.run_calls[1]["history"] == []


class TestChatSessionsArePerUser:
    """In-memory chat state is keyed per user, so a session_id never crosses users (GH-149).

    Chat session ids are client-generated until #176. With several users logged
    in, user B reusing user A's session_id must neither read A's history nor
    confirm A's pending tool call.
    """

    pytestmark = pytest.mark.asyncio

    async def test_server_chat_key_pairs_user_and_session(self) -> None:
        """The key is the (user_id, session_id) pair."""
        import admino.server as srv

        assert srv._chat_key(TEST_MEMBER_ID, "sess1") == (TEST_MEMBER_ID, "sess1")
        assert srv._chat_key(TEST_MEMBER_ID, "sess1") != srv._chat_key(_OTHER_USER_ID, "sess1")

    async def test_server_other_user_with_same_session_id_gets_empty_history(self) -> None:
        """User B posting with A's session_id starts from an empty history."""
        history_a = [
            LLMMessage(role="user", content="a-secret"),
            LLMMessage(role="assistant", content="a-reply"),
        ]
        agent = FakeAgent(
            [
                _make_agent_result(response="a-reply", history=history_a),
                _make_agent_result(response="b-reply"),
            ]
        )
        app = _make_app(agent, session=member_session("editor"))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "a", "session_id": "shared"})
            login(app, member_session("editor", user_id=_OTHER_USER_ID))
            await c.post("/api/message", json={"message": "b", "session_id": "shared"})

        assert agent.run_calls[1]["history"] == []

    async def test_server_other_user_does_not_overwrite_history(self) -> None:
        """B's turn on the same session_id leaves A's stored history intact."""
        import admino.server as srv

        history_a = [LLMMessage(role="user", content="a-secret")]
        history_b = [LLMMessage(role="user", content="b-msg")]
        agent = FakeAgent(
            [
                _make_agent_result(response="a", history=history_a),
                _make_agent_result(response="b", history=history_b),
                _make_agent_result(response="a2"),
            ]
        )
        app = _make_app(agent, session=member_session("editor"))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "a", "session_id": "shared"})
            login(app, member_session("editor", user_id=_OTHER_USER_ID))
            await c.post("/api/message", json={"message": "b", "session_id": "shared"})
            login(app, member_session("editor"))
            await c.post("/api/message", json={"message": "a2", "session_id": "shared"})

        assert agent.run_calls[2]["history"] == history_a
        assert srv._sessions[srv._chat_key(_OTHER_USER_ID, "shared")] == history_b

    async def test_server_other_user_cannot_confirm_a_pending_call(self) -> None:
        """B can't resolve A's pending confirmation: 404, and A's stays pending."""
        import admino.server as srv

        pending = _make_pending_confirmation(session_id="shared")
        awaiting = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting, _make_agent_result(response="Done.")])
        app = _make_app(agent, session=member_session("editor"))
        confirm_body = {
            "session_id": "shared",
            "confirmation_id": pending.confirmation_id,
            "approved": True,
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "create", "session_id": "shared"})
            login(app, member_session("editor", user_id=_OTHER_USER_ID))
            stolen = await c.post(f"/api/confirm/{pending.confirmation_id}", json=confirm_body)
            assert stolen.status_code == 404
            assert len(agent.run_calls) == 1
            assert srv._chat_key(TEST_MEMBER_ID, "shared") in srv._pending_confirmations

            login(app, member_session("editor"))
            own = await c.post(f"/api/confirm/{pending.confirmation_id}", json=confirm_body)

        assert own.status_code == 200
        assert agent.run_calls[1]["pending_confirmation"] is not None

    async def test_server_other_users_message_does_not_cancel_a_pending_call(self) -> None:
        """B's message on the same session_id doesn't drop A's pending confirmation."""
        import admino.server as srv

        pending = _make_pending_confirmation(session_id="shared")
        awaiting = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting, _make_agent_result()])
        app = _make_app(agent, session=member_session("editor"))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "create", "session_id": "shared"})
            login(app, member_session("editor", user_id=_OTHER_USER_ID))
            await c.post("/api/message", json={"message": "hi", "session_id": "shared"})

        assert srv._chat_key(TEST_MEMBER_ID, "shared") in srv._pending_confirmations


class TestCORS:
    """CORS middleware configuration."""

    pytestmark = pytest.mark.asyncio

    async def test_server_cors_allows_localhost_origin(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.options(
                "/api/message",
                headers={
                    "Origin": "http://localhost:8000",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type",
                },
            )
        assert resp.status_code == 200
        assert "http://localhost:8000" in resp.headers.get("access-control-allow-origin", "")

    async def test_server_cors_rejects_unknown_origin(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.options(
                "/api/message",
                headers={
                    "Origin": "http://evil.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type",
                },
            )
        # CORSMiddleware returns 400 or omits the allow-origin header
        allow_origin = resp.headers.get("access-control-allow-origin", "")
        assert "evil.com" not in allow_origin

    async def test_server_cors_no_longer_allows_authorization_header(self) -> None:
        """GH-149: no bearer auth any more, so CORS stops allowing Authorization."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.options(
                "/api/message",
                headers={
                    "Origin": "http://localhost:8000",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization",
                },
            )
        allowed = resp.headers.get("access-control-allow-headers", "").lower()
        assert "authorization" not in allowed


class TestErrorHandling:
    """Error handling — validation errors, agent exceptions, malformed input."""

    pytestmark = pytest.mark.asyncio

    async def test_server_agent_exception_500_generic_message(self) -> None:
        agent = MagicMock()
        agent.run = AsyncMock(side_effect=ValueError("secret details"))
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert resp.status_code == 500
        body = resp.json()
        assert body["detail"] == "Internal error"
        assert "secret" not in json.dumps(body)

    async def test_server_invalid_json_body_returns_422(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                content=b"{invalid json",
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 422

    async def test_server_wrong_content_type_returns_422(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                content=b"message=hello&session_id=sess1",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        assert resp.status_code == 422


class TestSecurityInvariants:
    """AST scans and security checks on server.py source code."""

    def _get_server_ast(self) -> ast.Module:
        import inspect

        import admino.server as server_module

        source = inspect.getsource(server_module)
        return ast.parse(source)

    def test_server_does_not_import_check_permission(self) -> None:
        """server.py must not import check_permission from permissions."""
        tree = self._get_server_ast()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "permissions" in node.module:
                names = [alias.name for alias in node.names]
                assert "check_permission" not in names, "server.py must NOT import check_permission"

    @pytest.mark.parametrize("forbidden", ["eval", "exec", "compile", "importlib"])
    def test_server_does_not_use_forbidden_builtins(self, forbidden: str) -> None:
        """server.py must not contain eval, exec, compile, or importlib usage."""
        tree = self._get_server_ast()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Name)
                and node.id == forbidden
                and isinstance(node.ctx, ast.Load)
            ):
                pytest.fail(f"server.py must not use {forbidden}()")
            if isinstance(node, ast.ImportFrom) and node.module == forbidden:
                pytest.fail(f"server.py must not import {forbidden}")

    def test_server_does_not_use_shell_true(self) -> None:
        """server.py must not contain shell=True."""
        import inspect

        import admino.server as server_module

        source = inspect.getsource(server_module)
        assert "shell=True" not in source

    def test_server_does_not_import_hmac(self) -> None:
        """GH-149: the bearer-token compare is gone, and with it the hmac import."""
        tree = self._get_server_ast()
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert "hmac" not in imported

    @pytest.mark.parametrize("removed", ["require_auth", "_get_bearer_token"])
    def test_server_bearer_auth_helpers_removed(self, removed: str) -> None:
        """The bearer-token dependency and its header parser no longer exist."""
        import admino.server as server_module

        assert not hasattr(server_module, removed)

    @pytest.mark.parametrize("dependency", ["require_session", "require_principal"])
    def test_server_exposes_session_dependencies(self, dependency: str) -> None:
        """GH-149: routes depend on require_session / require_principal."""
        import admino.server as server_module

        assert callable(getattr(server_module, dependency, None))

    def test_server_never_reads_config_auth(self) -> None:
        """No ``<something>.auth`` attribute read on the config any more (auth.mode is gone)."""
        tree = self._get_server_ast()
        offenders = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and node.attr == "auth"
            and isinstance(node.value, ast.Name)
            and node.value.id in {"_config", "config"}
        ]
        assert offenders == []


class TestStaticFiles:
    """Static file serving — API routes take priority."""

    pytestmark = pytest.mark.asyncio

    async def test_server_health_route_takes_priority_over_static(self, tmp_path: Any) -> None:
        """Even if a static dir exists, /health still works as an API route."""
        # Create a static directory with an index.html
        static_dir = tmp_path / "static"
        static_dir.mkdir()
        (static_dir / "index.html").write_text("<html>static</html>")

        app = _make_app()
        _set_health_config()
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200
        # Route priority is what matters here: the JSON health payload wins over
        # the static index.html. The full payload shape is asserted in TestHealthCheck.
        assert resp.json()["status"] == "ok"

    async def test_server_api_routes_override_static(self) -> None:
        """/api/message still works even if static mount is present."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert resp.status_code == 200


class TestSSEStreamHelper:
    """Test the SSE formatting helpers via the streaming endpoint."""

    pytestmark = pytest.mark.asyncio

    async def test_server_stream_agent_result_includes_tool_calls(self) -> None:
        """Stream from an AgentResult with tool calls includes tool_call events."""
        from admino.server import _stream_agent_result

        tc = ToolCallRecord(tool="gmail", action="read", permission="allow", success=True)
        result = _make_agent_result(
            response="Done reading.",
            tool_calls=[tc],
        )
        frames: list[str] = []
        async for frame in _stream_agent_result(result):
            frames.append(frame)

        combined = "".join(frames)
        assert "event: status" in combined
        assert "event: tool_call" in combined
        assert "event: message" in combined
        assert "event: done" in combined

    async def test_server_stream_agent_result_error_status(self) -> None:
        """Error status result streams an error event."""
        from admino.server import _stream_agent_result

        result = _make_agent_result(status="error", response="Something failed.")
        frames: list[str] = []
        async for frame in _stream_agent_result(result):
            frames.append(frame)

        combined = "".join(frames)
        assert "event: error" in combined
        assert "event: done" in combined

    async def test_server_stream_agent_result_awaiting_confirmation(self) -> None:
        """Awaiting confirmation result streams a confirm event."""
        from admino.server import _stream_agent_result

        pending = _make_pending_confirmation()
        result = _make_agent_result(
            status="awaiting_confirmation",
            response="Needs confirmation.",
            pending_confirmation=pending,
        )
        frames: list[str] = []
        async for frame in _stream_agent_result(result):
            frames.append(frame)

        combined = "".join(frames)
        assert "event: confirm" in combined
        assert "event: done" in combined


class TestSSEHelperFunctions:
    """Sync helper function tests for SSE formatting (no event loop needed)."""

    def test_server_format_sse_wire_format(self) -> None:
        """_format_sse produces correct wire format."""
        from admino.models import SSEEvent
        from admino.server import _format_sse

        event = SSEEvent(event="message", data='{"content":"hello"}')
        result = _format_sse(event)
        assert result == 'event: message\ndata: {"content":"hello"}\n\n'

    def test_server_make_sse_event_serializes_payload(self) -> None:
        """_make_sse_event creates properly formatted SSE from dict payload."""
        from admino.server import _make_sse_event

        result = _make_sse_event("status", {"status": "processing"})
        assert result.startswith("event: status\n")
        assert "data: " in result
        assert result.endswith("\n\n")
        # Payload should be valid JSON
        data_line = next(line for line in result.split("\n") if line.startswith("data: "))
        payload = json.loads(data_line[6:])
        assert payload["status"] == "processing"


class TestAppFactory:
    """create_app factory behavior."""

    pytestmark = pytest.mark.asyncio

    async def test_server_create_app_clears_sessions(self) -> None:
        """create_app clears session state for test isolation."""
        import admino.server as srv

        agent = FakeAgent([_make_agent_result(), _make_agent_result()])
        config = _make_config()
        app1 = _make_app(agent, config=config)

        # Post a message to populate session state
        async with AsyncClient(transport=ASGITransport(app=app1), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert srv._chat_key(TEST_MEMBER_ID, "sess1") in srv._sessions

        # Create a new app — sessions should be cleared
        create_app(agent=agent, config=config)
        # The module-level _sessions should now be empty
        assert len(srv._sessions) == 0

    async def test_server_create_app_returns_fastapi_instance(self) -> None:
        from fastapi import FastAPI

        app = _make_app()
        assert isinstance(app, FastAPI)

    async def test_server_create_app_docs_disabled(self) -> None:
        """Swagger UI and ReDoc are disabled in the app."""
        app = _make_app()
        assert app.docs_url is None
        assert app.redoc_url is None


class TestConfirmationEdgeCases:
    """Additional confirmation edge cases."""

    pytestmark = pytest.mark.asyncio

    async def test_server_confirm_denied_removes_pending(self) -> None:
        """After denial, the pending confirmation is removed entirely."""
        import admino.server as srv

        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
            await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": False,
                },
            )
        # Pending should be cleared
        assert srv._chat_key(TEST_MEMBER_ID, "sess1") not in srv._pending_confirmations

    async def test_server_confirm_passes_pending_to_agent(self) -> None:
        """On approval, agent.run is called with pending_confirmation."""
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        resumed_result = _make_agent_result(
            status="final",
            response="Done.",
        )
        agent = FakeAgent([awaiting_result, resumed_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "create event", "session_id": "sess1"},
            )
            await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
            )
        # The second run call should include the pending_confirmation
        assert len(agent.run_calls) == 2
        assert agent.run_calls[1]["pending_confirmation"] is not None
        assert agent.run_calls[1]["pending_confirmation"].confirmation_id == pending.confirmation_id

    async def test_server_awaiting_confirmation_response_exposes_pending_summary(
        self,
    ) -> None:
        """When the agent is awaiting confirmation, POST /api/message must
        return ``status='awaiting_confirmation'`` plus a ``pending_confirmation``
        summary carrying the confirmation_id, tool, and action. Without these
        fields the PWA has no way to render its Approve/Deny card.
        """
        pending = _make_pending_confirmation(
            session_id="sess1",
            confirmation_id="confirm-xyz-42",
            tool="google_calendar",
            action="create",
        )
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Action google_calendar.create requires user confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "book the dentist", "session_id": "sess1"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "awaiting_confirmation"
        assert data["pending_confirmation"] is not None
        pc = data["pending_confirmation"]
        assert pc["confirmation_id"] == "confirm-xyz-42"
        assert pc["tool"] == "google_calendar"
        assert pc["action"] == "create"
        assert "expires_at" in pc
        # Args are now included (sanitized) for UI display in the confirmation card.
        assert "args" in pc
        # Internal fields must not leak.
        assert "tool_call" not in pc
        assert "input" not in pc

    async def test_server_final_response_omits_pending_confirmation(self) -> None:
        """A plain final response has status='final' and pending_confirmation=None."""
        agent = FakeAgent([_make_agent_result(status="final", response="Hello!")])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hi", "session_id": "sess1"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "final"
        assert data["pending_confirmation"] is None

    async def test_server_new_message_during_pending_closes_tool_use(self) -> None:
        """Regression: sending a freeform /api/message while a confirmation is
        pending must (a) cancel the pending confirmation and (b) append a
        synthetic cancelled tool_result so the history handed to the next
        agent.run() does not leave a ``tool_use`` dangling — which would
        otherwise make Anthropic reject the next LLM call with HTTP 400.
        """
        import admino.server as srv

        pending = _make_pending_confirmation(session_id="sess1")
        # First turn: agent returns awaiting_confirmation with a history that
        # ends in an assistant message carrying a tool_use block — the exact
        # shape that produced the Anthropic 400 in production.
        awaiting_history = [
            LLMMessage(role="user", content="book the dentist"),
            LLMMessage(
                role="assistant",
                content="I'll create the event.",
                tool_use_blocks=[
                    {
                        "type": "tool_use",
                        "id": "toolu_abc123",
                        "name": "google_calendar.create",
                        "input": {"summary": "Dentist", "start": "2026-10-01T09:00:00Z"},
                    }
                ],
            ),
        ]
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Action google_calendar.create requires user confirmation.",
            history=awaiting_history,
            pending_confirmation=pending,
        )
        followup_result = _make_agent_result(
            status="final",
            response="OK, cancelled. What would you like to do instead?",
        )
        agent = FakeAgent([awaiting_result, followup_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Turn 1: triggers the pending confirmation.
            await c.post(
                "/api/message",
                json={"message": "book the dentist", "session_id": "sess1"},
            )
            assert srv._chat_key(TEST_MEMBER_ID, "sess1") in srv._pending_confirmations

            # Turn 2: user sends a new chat message instead of calling
            # /api/confirm/{id}. Must succeed (no 500) and the pending
            # confirmation must have been cleared.
            resp = await c.post(
                "/api/message",
                json={"message": "I confirm it!", "session_id": "sess1"},
            )

        assert resp.status_code == 200
        assert srv._chat_key(TEST_MEMBER_ID, "sess1") not in srv._pending_confirmations

        # Inspect the history passed to agent.run() on the second call: the
        # dangling tool_use must have been closed with a synthetic tool
        # message referencing the same tool_call_id.
        assert len(agent.run_calls) == 2
        second_history = agent.run_calls[1]["history"]
        trailing_tool = [m for m in second_history if m.role == "tool"]
        assert any(
            m.tool_call_id == "toolu_abc123" and "cancelled" in m.content.lower()
            for m in trailing_tool
        ), "dangling tool_use must be closed by a synthetic cancelled tool_result"

    async def test_server_close_dangling_tool_use_noop_on_clean_history(self) -> None:
        """_close_dangling_tool_use is a no-op on well-formed history."""
        from admino.server import _close_dangling_tool_use

        history = [
            LLMMessage(role="user", content="hi"),
            LLMMessage(role="assistant", content="hello"),
        ]
        assert _close_dangling_tool_use(history) == history

    async def test_server_close_dangling_tool_use_leaves_answered_blocks(self) -> None:
        """Already-answered tool_use blocks are not duplicated."""
        from admino.server import _close_dangling_tool_use

        history = [
            LLMMessage(role="user", content="list my notes"),
            LLMMessage(
                role="assistant",
                content="",
                tool_use_blocks=[
                    {"type": "tool_use", "id": "toolu_1", "name": "memory.list", "input": {}},
                ],
            ),
            LLMMessage(role="tool", content="[]", tool_call_id="toolu_1"),
        ]
        assert _close_dangling_tool_use(history) == history


class TestSessionCap:
    """H-1: Session count is capped with LRU eviction."""

    pytestmark = pytest.mark.asyncio

    async def test_server_session_cap_evicts_oldest(self) -> None:
        """Sessions beyond _MAX_SESSIONS evict the least-recently-used."""
        import admino.server as srv

        original_max = srv._MAX_SESSIONS
        try:
            srv._MAX_SESSIONS = 3
            results = [_make_agent_result() for _ in range(5)]
            agent = FakeAgent(results)
            app = _make_app(agent)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                for i in range(5):
                    await c.post(
                        "/api/message",
                        json={"message": "hi", "session_id": f"sess{i}"},
                    )
            # Only the 3 most recent sessions should remain.
            assert len(srv._sessions) == 3
            assert srv._chat_key(TEST_MEMBER_ID, "sess0") not in srv._sessions
            assert srv._chat_key(TEST_MEMBER_ID, "sess1") not in srv._sessions
            assert srv._chat_key(TEST_MEMBER_ID, "sess4") in srv._sessions
        finally:
            srv._MAX_SESSIONS = original_max

    async def test_server_session_lru_reuse_prevents_eviction(self) -> None:
        """Accessing a session moves it to the end, preventing eviction."""
        import admino.server as srv

        original_max = srv._MAX_SESSIONS
        try:
            srv._MAX_SESSIONS = 3
            results = [_make_agent_result() for _ in range(5)]
            agent = FakeAgent(results)
            app = _make_app(agent)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                # Create 3 sessions
                for i in range(3):
                    await c.post(
                        "/api/message",
                        json={"message": "hi", "session_id": f"sess{i}"},
                    )
                # Reuse sess0 (moves to end)
                await c.post(
                    "/api/message",
                    json={"message": "hi again", "session_id": "sess0"},
                )
                # Add sess3 — should evict sess1 (oldest unreused)
                await c.post(
                    "/api/message",
                    json={"message": "hi", "session_id": "sess3"},
                )
            assert srv._chat_key(TEST_MEMBER_ID, "sess0") in srv._sessions  # reused, not evicted
            assert srv._chat_key(TEST_MEMBER_ID, "sess1") not in srv._sessions  # oldest, evicted
        finally:
            srv._MAX_SESSIONS = original_max


class TestConfirmationExpiry:
    """H-2/M-3: Expired confirmations are reaped and rejected."""

    pytestmark = pytest.mark.asyncio

    async def test_server_expired_confirmation_reaped_returns_404(self) -> None:
        """Expired confirmations are reaped unconditionally at entry, returning 404.

        The unconditional _reap_expired_confirmations() call at the top of
        post_confirm removes expired entries before the per-session lookup.
        The 410 code path remains as defence-in-depth for confirmations that
        expire in the narrow window between reap and the expiry check.
        """
        pending = _make_pending_confirmation(session_id="sess1", expired=True)
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting_result])
        app = _make_app(agent)

        # Manually inject the expired pending (bypassing normal flow)
        import admino.server as srv

        srv._pending_confirmations[srv._chat_key(TEST_MEMBER_ID, "sess1")] = pending
        srv._sessions[srv._chat_key(TEST_MEMBER_ID, "sess1")] = [
            LLMMessage(role="user", content="hi")
        ]

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
            )
        # Expired entry is reaped before lookup, so 404 (not 410).
        assert resp.status_code == 404

    async def test_server_reap_removes_expired_before_lookup(self) -> None:
        """Expired confirmations are reaped before any lookup."""
        import admino.server as srv

        expired_pending = _make_pending_confirmation(session_id="sess-expired", expired=True)
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)

        srv._pending_confirmations[srv._chat_key(TEST_MEMBER_ID, "sess-expired")] = expired_pending

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Query for a different session — the expired one should be reaped
            resp = await c.post(
                "/api/confirm/some-id",
                json={
                    "session_id": "sess-other",
                    "confirmation_id": "some-id",
                    "approved": True,
                },
            )
        assert resp.status_code == 404
        assert srv._chat_key(TEST_MEMBER_ID, "sess-expired") not in srv._pending_confirmations


class TestMaxMessageLength:
    """L-5: max_message_length from config is enforced."""

    pytestmark = pytest.mark.asyncio

    async def test_server_message_exceeds_config_max_length_returns_422(self) -> None:
        """Message longer than config.limits.max_message_length -> 422."""
        agent = FakeAgent([_make_agent_result()])
        config = _make_config()
        config.limits.max_message_length = 100
        app = _make_app(agent, config=config)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "x" * 101, "session_id": "sess1"},
            )
        assert resp.status_code == 422
        assert "maximum length" in resp.json()["detail"].lower()

    async def test_server_message_within_config_max_length_succeeds(self) -> None:
        """Message within config limit succeeds."""
        agent = FakeAgent([_make_agent_result()])
        config = _make_config()
        config.limits.max_message_length = 100
        app = _make_app(agent, config=config)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "x" * 100, "session_id": "sess1"},
            )
        assert resp.status_code == 200


class TestCORSCredentials:
    """H-4: allow_credentials is False."""

    pytestmark = pytest.mark.asyncio

    async def test_server_cors_no_credentials(self) -> None:
        """CORS preflight response does not include allow-credentials: true."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.options(
                "/api/message",
                headers={
                    "Origin": "http://localhost:8000",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type",
                },
            )
        # allow-credentials header should not be present or should be "false"
        cred_header = resp.headers.get("access-control-allow-credentials", "false")
        assert cred_header.lower() != "true"


class TestConfirmationPathValidation:
    """M-1: confirmation_id path parameter is Pydantic-validated."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize(
        "bad_id",
        [
            "a" * 65,  # too long
            "invalid id!@#",  # bad chars
            "",  # empty (would 404 on route match)
        ],
    )
    async def test_server_confirm_invalid_path_id_returns_422(self, bad_id: str) -> None:
        """Invalid confirmation_id in path returns 422."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                f"/api/confirm/{bad_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": bad_id or "x",
                    "approved": True,
                },
            )
        # Empty string would result in 404/405 since route won't match
        if bad_id == "":
            assert resp.status_code in (404, 405, 422)
        else:
            assert resp.status_code == 422


class TestNoVPNModeWarning:
    """GH-149: vpn mode is gone, so create_app logs no VPN warning."""

    def test_server_create_app_logs_no_vpn_warning(self, caplog: Any) -> None:
        with caplog.at_level(logging.WARNING, logger="admino.server"):
            _make_app()
        assert not any("VPN" in record.getMessage() for record in caplog.records)


# ---------------------------------------------------------------------------
# F-11: Canary test — pytest-asyncio is importable
# ---------------------------------------------------------------------------


class TestPytestAsyncioCanary:
    """Canary: verify pytest-asyncio is available and auto mode works."""

    def test_pytest_asyncio_importable(self) -> None:
        """pytest-asyncio must be importable for async tests to execute."""
        assert pytest_asyncio is not None
        assert hasattr(pytest_asyncio, "__version__")


# ---------------------------------------------------------------------------
# F-12: SSE frame injection via hostile LLM response
# ---------------------------------------------------------------------------


class TestSSEFrameInjection:
    """Verify SSE sanitisation blocks frame injection from LLM output."""

    pytestmark = pytest.mark.asyncio

    async def test_server_sse_stream_no_frame_injection(self) -> None:
        """An AgentResult with newlines in response must not inject extra SSE frames."""
        from admino.server import _stream_agent_result

        hostile_response = "line1\n\nevent: injected\ndata: evil\n\n"
        result = _make_agent_result(response=hostile_response)
        frames: list[str] = []
        async for frame in _stream_agent_result(result):
            frames.append(frame)

        # Should be exactly 3 SSE frames: status, message, done
        assert len(frames) == 3, f"Expected 3 SSE frames, got {len(frames)}"

        combined = "".join(frames)
        # Count real SSE frame starts (lines beginning with "event: ")
        real_events = [line for line in combined.split("\n") if line.startswith("event: ")]
        assert len(real_events) == 3, f"Expected 3 real SSE events, got {len(real_events)}"

        # The injected event type must not appear as a real SSE event
        event_types = [line.split("event: ", 1)[1] for line in real_events]
        assert "injected" not in event_types

    async def test_server_sse_stream_control_chars_stripped(self) -> None:
        """Control characters in LLM response are stripped in SSE output."""
        from admino.server import _stream_agent_result

        # U+202E RIGHT-TO-LEFT OVERRIDE — spoofing attack
        hostile_response = "Hello \u202e dlrow"
        result = _make_agent_result(response=hostile_response)
        frames: list[str] = []
        async for frame in _stream_agent_result(result):
            frames.append(frame)

        combined = "".join(frames)
        assert "\u202e" not in combined


# ---------------------------------------------------------------------------
# F-13: Additional confirmation_id path parameter validation
# ---------------------------------------------------------------------------


class TestConfirmationPathInjection:
    """Ensure path traversal and XSS in confirmation_id are rejected."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize(
        "bad_id",
        [
            "../traversal",
            "<script>alert(1)</script>",
            "id with spaces",
            "id;drop table",
        ],
    )
    async def test_server_confirm_path_traversal_and_xss_rejected(self, bad_id: str) -> None:
        """Injection attempts in confirmation_id are rejected (422 or 404)."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                f"/api/confirm/{bad_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": "valid-id",
                    "approved": True,
                },
            )
        # Path traversal/special chars may result in 404 (route mismatch),
        # 422 (Pydantic validation), or 405 (caught by static file mount).
        # All are valid rejections of the malicious input.
        assert resp.status_code in (404, 405, 422), f"Expected 404/405/422, got {resp.status_code}"


# ---------------------------------------------------------------------------
# F-02: ChatResponse.response sanitisation test
# ---------------------------------------------------------------------------


class TestChatResponseSanitisation:
    """Verify ChatResponse.response strips XSS and credentials."""

    pytestmark = pytest.mark.asyncio

    async def test_server_response_script_tags_pass_through_unchanged(self) -> None:
        """Script tags are valid UTF-8 and pass through the sanitizer unchanged.

        HTML tags are NOT stripped by the server — the sanitizer only removes
        control characters and credentials. XSS prevention relies on:
        1. CSP header (script-src 'self') blocks inline script execution.
        2. The PWA must use textContent (not innerHTML) when rendering responses.
        """
        from admino.models import ChatResponse

        resp = ChatResponse(
            session_id="test",
            response="Hello <script>alert(1)</script>",
            tool_calls=[],
        )
        # Script tags survive: they are valid text, not control chars or credentials.
        assert "<script>alert(1)</script>" in resp.response
        assert resp.response == "Hello <script>alert(1)</script>"

    async def test_server_response_credentials_redacted(self) -> None:
        """Bearer tokens in LLM responses are redacted."""
        from admino.models import ChatResponse

        resp = ChatResponse(
            session_id="test",
            response="The token is Bearer sk-proj-abcdefghijklmnopqrstuvwxyz123",
            tool_calls=[],
        )
        assert "sk-proj-" not in resp.response
        assert "[CREDENTIAL_REDACTED]" in resp.response

    async def test_server_response_control_chars_stripped(self) -> None:
        """Unicode direction overrides in LLM response are stripped."""
        from admino.models import ChatResponse

        resp = ChatResponse(
            session_id="test",
            response="Hello \u202e dlrow",
            tool_calls=[],
        )
        assert "\u202e" not in resp.response


# ---------------------------------------------------------------------------
# F-01: Security headers test
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    """Verify security response headers are present on all responses."""

    pytestmark = pytest.mark.asyncio

    async def test_server_health_includes_security_headers(self) -> None:
        """Health check response includes all security headers."""
        app = _make_app()
        with patch("admino.database.check_health", new=AsyncMock(return_value=True)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"
        assert resp.headers["referrer-policy"] == "no-referrer"
        assert "default-src 'self'" in resp.headers["content-security-policy"]
        assert "camera=()" in resp.headers["permissions-policy"]

    async def test_server_api_response_includes_security_headers(self) -> None:
        """POST /api/message response includes security headers."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert resp.status_code == 200
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"

    async def test_server_401_includes_security_headers(self) -> None:
        """Even 401 responses include security headers."""
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert resp.status_code == 401
        assert resp.headers["x-content-type-options"] == "nosniff"


# ---------------------------------------------------------------------------
# F-04: Rate limiting test
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Verify rate limiting on API endpoints."""

    pytestmark = pytest.mark.asyncio

    async def test_server_rate_limit_returns_429_on_burst(self) -> None:
        """Exceeding burst capacity returns 429."""
        results = [_make_agent_result() for _ in range(10)]
        agent = FakeAgent(results)
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            statuses = []
            for i in range(10):
                resp = await c.post(
                    "/api/message",
                    json={"message": "hello", "session_id": f"sess-rl-{i}"},
                )
                statuses.append(resp.status_code)
        # First 5 should succeed (burst capacity), rest should be 429
        assert 429 in statuses, "Rate limiter should return 429 after burst capacity"
        assert statuses[0] == 200, "First request should succeed"

    async def test_server_rate_limit_429_body_is_generic(self) -> None:
        """The 429 body is exactly {"detail": "Rate limit exceeded"}."""
        agent = FakeAgent([_make_agent_result() for _ in range(6)])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            responses = [
                await c.post("/api/message", json={"message": "hi", "session_id": f"s{i}"})
                for i in range(6)
            ]
        assert responses[-1].status_code == 429
        assert responses[-1].json() == {"detail": "Rate limit exceeded"}

    async def test_server_rate_limit_one_user_does_not_throttle_another(self) -> None:
        """GH-149: buckets are per user; user A exhausting /api/message leaves user B alone."""
        agent = FakeAgent([_make_agent_result() for _ in range(8)])
        app = _make_app(agent, session=member_session("editor"))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            first_user = [
                (
                    await c.post("/api/message", json={"message": "hi", "session_id": f"a{i}"})
                ).status_code
                for i in range(6)
            ]
            login(app, member_session("editor", user_id=_OTHER_USER_ID))
            second_user = await c.post("/api/message", json={"message": "hi", "session_id": "b"})
        assert first_user[-1] == 429
        assert second_user.status_code == 200

    async def test_server_rate_limit_session_route_is_keyed_by_user_id(self) -> None:
        """A session route's caller key is ``user:<principal.user_id>``."""
        from admino import server

        app = _make_app(session=member_session("editor", user_id=_OTHER_USER_ID))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json=_MESSAGE_BODY)
        assert ("/api/message", f"user:{_OTHER_USER_ID}") in server._rate_buckets

    async def test_server_rate_limit_public_route_is_keyed_by_client_ip(self) -> None:
        """A public route's caller key is ``ip:<client host>`` (here: the OAuth callback)."""
        from admino import server

        app = _make_app(anonymous=True)
        transport = ASGITransport(app=app, client=("203.0.113.7", 50000))
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            await c.get("/api/oauth/callback")
        assert ("/api/oauth/callback", "ip:203.0.113.7") in server._rate_buckets

    async def test_server_rate_limit_one_ip_does_not_throttle_another(self) -> None:
        """On a public route, one client IP exhausting its bucket leaves another IP alone."""
        app = _make_app(anonymous=True)
        first_ip = ASGITransport(app=app, client=("203.0.113.7", 50000))
        second_ip = ASGITransport(app=app, client=("198.51.100.9", 50000))
        async with AsyncClient(transport=first_ip, base_url="http://test") as c:
            first = [(await c.get("/api/oauth/callback")).status_code for _ in range(3)]
        async with AsyncClient(transport=second_ip, base_url="http://test") as c:
            second = await c.get("/api/oauth/callback")
        assert first[-1] == 429
        assert second.status_code != 429


class _Clock:
    """A settable stand-in for ``time.monotonic()``."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


# The per-route (tokens/s, burst) the server keeps (GH-149 keeps today's rates
# and adds the three auth routes).
_EXPECTED_RATE_LIMITS: list[tuple[str, float, int]] = [
    ("/api/message", 0.5, 5),
    ("/api/confirm", 0.5, 5),
    ("/api/events", 0.17, 3),
    ("/api/settings/get", 1.0, 5),
    ("/api/settings/patch", 0.2, 2),
    ("/api/permissions/get", 1.0, 5),
    ("/api/permissions/patch", 0.2, 2),
    ("/api/oauth/google/authorize", 0.2, 2),
    ("/api/oauth/microsoft/authorize", 0.2, 2),
    ("/api/oauth/callback", 0.2, 2),
    ("/api/oauth/google/status", 1.0, 5),
    ("/api/oauth/microsoft/status", 1.0, 5),
    ("/api/oauth/google/disconnect", 0.2, 2),
    ("/api/oauth/microsoft/disconnect", 0.2, 2),
    ("/api/critical-permissions/get", 1.0, 5),
    ("/api/critical-permissions/promote", 5 / 60, 5),
    ("/api/critical-permissions/cancel", 0.5, 5),
    ("/api/auth/login", 0.2, 5),
    ("/api/auth/logout", 0.5, 5),
    ("/api/auth/me", 1.0, 10),
]


class TestPerCallerRateLimit:
    """GH-149: ``_check_rate_limit(route, caller)`` with one bucket per (route, caller)."""

    @pytest.fixture()
    def clock(self, monkeypatch: pytest.MonkeyPatch) -> _Clock:
        """Freeze the server's monotonic clock and start from a fresh app (empty buckets)."""
        fake = _Clock()
        monkeypatch.setattr("admino.server.time.monotonic", fake)
        _make_app()
        return fake

    @staticmethod
    def _exhaust(route: str, caller: str, burst: int) -> None:
        """Use up ``caller``'s whole burst on ``route``."""
        from admino import server

        for _ in range(burst):
            server._check_rate_limit(route, caller)

    def test_server_check_rate_limit_raises_429_after_burst(self, clock: _Clock) -> None:
        from admino import server

        self._exhaust("/api/message", "user:a", 5)
        with pytest.raises(HTTPException) as exc_info:
            server._check_rate_limit("/api/message", "user:a")
        assert (exc_info.value.status_code, exc_info.value.detail) == (429, "Rate limit exceeded")

    def test_server_check_rate_limit_other_user_keeps_full_burst(self, clock: _Clock) -> None:
        self._exhaust("/api/message", "user:a", 5)
        self._exhaust("/api/message", "user:b", 5)  # must not raise

    def test_server_check_rate_limit_other_ip_keeps_full_burst(self, clock: _Clock) -> None:
        self._exhaust("/api/auth/login", "ip:203.0.113.7", 5)
        self._exhaust("/api/auth/login", "ip:198.51.100.9", 5)  # must not raise

    def test_server_check_rate_limit_same_user_other_route_unaffected(self, clock: _Clock) -> None:
        self._exhaust("/api/message", "user:a", 5)
        self._exhaust("/api/confirm", "user:a", 5)  # must not raise

    def test_server_check_rate_limit_refills_over_time(self, clock: _Clock) -> None:
        """0.5 tokens/s on /api/message: two seconds later one more request passes."""
        from admino import server

        self._exhaust("/api/message", "user:a", 5)
        clock.now += 2.0
        server._check_rate_limit("/api/message", "user:a")
        with pytest.raises(HTTPException):
            server._check_rate_limit("/api/message", "user:a")

    def test_server_check_rate_limit_stores_bucket_per_route_and_caller(
        self, clock: _Clock
    ) -> None:
        from admino import server

        server._check_rate_limit("/api/message", "user:a")
        assert list(server._rate_buckets) == [("/api/message", "user:a")]

    @pytest.mark.parametrize(("route", "rate", "burst"), _EXPECTED_RATE_LIMITS)
    def test_server_rate_limits_per_route(self, route: str, rate: float, burst: int) -> None:
        from admino import server

        assert server._RATE_LIMITS[route] == pytest.approx((rate, burst))

    def test_server_default_rate_limit_is_one_per_second_burst_ten(self) -> None:
        from admino import server

        assert tuple(server._DEFAULT_RATE_LIMIT) == (1.0, 10)

    def test_server_unlisted_route_uses_default_limit(self, clock: _Clock) -> None:
        """A route without its own entry still gets a (default) bucket per caller."""
        from admino import server

        self._exhaust("/api/not-listed", "user:a", 10)
        with pytest.raises(HTTPException):
            server._check_rate_limit("/api/not-listed", "user:a")

    def test_server_create_app_clears_rate_buckets(self, clock: _Clock) -> None:
        from admino import server

        server._check_rate_limit("/api/message", "user:a")
        _make_app()
        assert len(server._rate_buckets) == 0

    def test_server_bucket_eviction_constants(self) -> None:
        from admino import server

        assert (server._BUCKET_IDLE_TTL_S, server._MAX_RATE_BUCKETS) == (900.0, 10_000)

    def test_server_idle_bucket_is_evicted_on_a_later_call(self, clock: _Clock) -> None:
        """A bucket unused for the idle TTL is dropped when any caller is checked later."""
        from admino import server

        server._check_rate_limit("/api/message", "user:a")
        clock.now += server._BUCKET_IDLE_TTL_S + 1.0
        server._check_rate_limit("/api/message", "user:b")
        assert ("/api/message", "user:a") not in server._rate_buckets
        assert ("/api/message", "user:b") in server._rate_buckets

    def test_server_recent_bucket_is_not_evicted(self, clock: _Clock) -> None:
        """A bucket used within the idle TTL survives (its caller stays throttled)."""
        from admino import server

        self._exhaust("/api/message", "user:a", 5)
        clock.now += server._BUCKET_IDLE_TTL_S - 1.0
        server._check_rate_limit("/api/message", "user:b")
        assert ("/api/message", "user:a") in server._rate_buckets

    def test_server_bucket_map_never_exceeds_cap(
        self, clock: _Clock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from admino import server

        monkeypatch.setattr(server, "_MAX_RATE_BUCKETS", 3)
        for i in range(5):
            server._check_rate_limit("/api/message", f"user:{i}")
        assert len(server._rate_buckets) == 3

    def test_server_bucket_cap_drops_least_recently_used_first(
        self, clock: _Clock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from admino import server

        monkeypatch.setattr(server, "_MAX_RATE_BUCKETS", 3)
        for caller in ("user:0", "user:1", "user:2"):
            server._check_rate_limit("/api/message", caller)
        server._check_rate_limit("/api/message", "user:0")  # user:0 is now most recent
        server._check_rate_limit("/api/message", "user:3")
        assert set(server._rate_buckets) == {
            ("/api/message", "user:0"),
            ("/api/message", "user:2"),
            ("/api/message", "user:3"),
        }


# ---------------------------------------------------------------------------
# F-10: Session lock test
# ---------------------------------------------------------------------------


class TestSessionLocks:
    """Verify per-session locks are created and cleared."""

    pytestmark = pytest.mark.asyncio

    async def test_server_session_locks_cleared_on_app_creation(self) -> None:
        """create_app clears session locks."""
        import admino.server as srv

        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert srv._chat_key(TEST_MEMBER_ID, "sess1") in srv._session_locks

        # Creating a new app clears locks
        _make_app()
        assert len(srv._session_locks) == 0


# ---------------------------------------------------------------------------
# GH-140: system prompt must not be duplicated across turns (real Agent)
# ---------------------------------------------------------------------------

_GH140_SESSION = "sess-gh140"
_GH140_SYSTEM_PROMPT = "SYS"


class _RecordingLLM:
    """Scripted LLM stand-in that records every context window it receives."""

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses: list[LLMResponse] = list(responses)
        self.received_messages: list[list[LLMMessage]] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.received_messages.append(list(messages))
        if not self._responses:
            msg = "_RecordingLLM exhausted"
            raise AssertionError(msg)
        return self._responses.pop(0)


class _EchoArgs(BaseModel):
    """Args schema for the confirm-gated echo tool used in the GH-140 tests."""

    text: str = Field(min_length=1, max_length=100)


async def _echo_handler(args: _EchoArgs, *, session_id: str) -> str:
    return f"echo:{args.text}"


def _system_pairs(messages: list[LLMMessage]) -> list[tuple[str, str]]:
    """Return ``(role, content)`` for every system message in ``messages``."""
    return [(m.role, m.content) for m in messages if m.role == "system"]


class TestSystemPromptNotDuplicatedAcrossTurns:
    """GH-140: the server round-trips history without duplicating the system prompt.

    Uses a REAL ``admino.agent.Agent`` (only the LLM is faked) so the
    server's store-and-replay of ``result.history`` through ``_sessions`` is
    exercised end to end. Before the fix, every turn stored the agent's system
    prompt in the session and the next turn prepended it again.
    """

    pytestmark = pytest.mark.asyncio

    @pytest.fixture(autouse=True)
    def _clean_registry(self) -> Generator[None, None, None]:
        clear_registry()
        yield
        clear_registry()

    @pytest.fixture()
    def tool_call_recorder(self) -> AsyncMock:
        """GH-147: the injected tool-call recorder (no NDJSON audit log any more)."""
        return AsyncMock(return_value=None)

    @staticmethod
    def _make_real_agent(llm: _RecordingLLM, tool_call_recorder: AsyncMock) -> Agent:
        return Agent(
            llm_client=llm,  # type: ignore[arg-type]
            tool_call_recorder=tool_call_recorder,
            permissions_config=PermissionsConfig(
                tools={"echo": ToolPermissions(actions={"write": "confirm"})}
            ),
            agent_config=AgentConfig(
                max_tool_calls=5,
                max_context_messages=20,
                confirmation_timeout_s=60.0,
            ),
            system_prompt=_GH140_SYSTEM_PROMPT,
        )

    async def _post_turns(
        self, tool_call_recorder: AsyncMock, *, turns: int = 25
    ) -> tuple[_RecordingLLM, list[int]]:
        """POST ``turns`` messages on one session; return the LLM recorder + statuses."""
        llm = _RecordingLLM(
            [
                LLMResponse(content=f"reply-{i}", tool_calls=[], model="m", done=True)
                for i in range(turns)
            ]
        )
        app = _make_app(self._make_real_agent(llm, tool_call_recorder))
        statuses: list[int] = []
        # /api/message has a burst capacity of 5; the rate limiter is not
        # under test here, so neutralise it for the 25-turn conversation.
        with patch("admino.server._check_rate_limit"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                for i in range(turns):
                    resp = await c.post(
                        "/api/message",
                        json={"message": f"turn-{i}", "session_id": _GH140_SESSION},
                    )
                    statuses.append(resp.status_code)
        return llm, statuses

    async def test_server_message_25_turns_each_llm_call_has_one_system_prompt(
        self, tool_call_recorder: AsyncMock
    ) -> None:
        llm, statuses = await self._post_turns(tool_call_recorder)

        assert statuses == [200] * 25
        assert len(llm.received_messages) == 25
        for i, call in enumerate(llm.received_messages):
            assert _system_pairs(call) == [("system", _GH140_SYSTEM_PROMPT)], f"turn {i}"
            assert call[0].role == "system", f"turn {i}"

    async def test_server_message_25_turns_each_llm_call_ends_with_posted_message(
        self, tool_call_recorder: AsyncMock
    ) -> None:
        llm, _ = await self._post_turns(tool_call_recorder)

        assert len(llm.received_messages) == 25
        for i, call in enumerate(llm.received_messages):
            assert (call[-1].role, call[-1].content) == ("user", f"turn-{i}"), f"turn {i}"

    async def test_server_message_25_turns_session_history_has_no_system_messages(
        self, tool_call_recorder: AsyncMock
    ) -> None:
        from admino import server

        await self._post_turns(tool_call_recorder)

        stored = server._sessions[server._chat_key(TEST_MEMBER_ID, _GH140_SESSION)]
        assert _system_pairs(stored) == []
        assert len(stored) == 50

    async def test_server_confirm_resume_llm_call_has_one_system_prompt(
        self, tool_call_recorder: AsyncMock
    ) -> None:
        """POST /api/message -> awaiting confirmation -> POST /api/confirm (approve)."""
        from admino import server

        register_tool("echo", "write", "Write echo", _EchoArgs)(_echo_handler)
        llm = _RecordingLLM(
            [
                LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCall(
                            tool="echo",
                            action="write",
                            args={"text": "x"},
                            tool_call_id="call_write_1",
                        )
                    ],
                    model="m",
                    done=True,
                ),
                LLMResponse(content="Written.", tool_calls=[], model="m", done=True),
            ]
        )
        app = _make_app(self._make_real_agent(llm, tool_call_recorder))

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp1 = await c.post(
                "/api/message",
                json={"message": "please write x", "session_id": _GH140_SESSION},
            )
            assert resp1.status_code == 200
            assert resp1.json()["status"] == "awaiting_confirmation"
            confirmation_id = resp1.json()["pending_confirmation"]["confirmation_id"]

            resp2 = await c.post(
                f"/api/confirm/{confirmation_id}",
                json={
                    "session_id": _GH140_SESSION,
                    "confirmation_id": confirmation_id,
                    "approved": True,
                },
            )

        assert resp2.status_code == 200
        assert resp2.json()["status"] == "final"
        assert len(llm.received_messages) == 2
        resume_call = llm.received_messages[1]
        assert _system_pairs(resume_call) == [("system", _GH140_SYSTEM_PROMPT)]
        assert resume_call[0].role == "system"
        assert (
            _system_pairs(server._sessions[server._chat_key(TEST_MEMBER_ID, _GH140_SESSION)]) == []
        )

    async def test_server_tool_call_recorder_receives_logged_in_principal(
        self, tool_call_recorder: AsyncMock
    ) -> None:
        """GH-149 end to end: each tool-call record carries the requesting principal."""
        register_tool("echo", "write", "Write echo", _EchoArgs)(_echo_handler)
        llm = _RecordingLLM(
            [
                LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCall(
                            tool="echo",
                            action="write",
                            args={"text": "x"},
                            tool_call_id="call_write_1",
                        )
                    ],
                    model="m",
                    done=True,
                ),
                LLMResponse(content="Written.", tool_calls=[], model="m", done=True),
            ]
        )
        session = member_session("editor", user_id=_OTHER_USER_ID)
        app = _make_app(self._make_real_agent(llm, tool_call_recorder), session=session)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp1 = await c.post(
                "/api/message",
                json={"message": "please write x", "session_id": _GH140_SESSION},
            )
            confirmation_id = resp1.json()["pending_confirmation"]["confirmation_id"]
            await c.post(
                f"/api/confirm/{confirmation_id}",
                json={
                    "session_id": _GH140_SESSION,
                    "confirmation_id": confirmation_id,
                    "approved": True,
                },
            )

        principals = [call.kwargs["principal"] for call in tool_call_recorder.await_args_list]
        assert principals == [session.principal, session.principal]
