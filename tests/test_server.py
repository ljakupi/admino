"""Comprehensive test suite for admino.server — HTTP layer, auth, SSE, confirmations.

Tests the FastAPI application created by ``create_app()``, covering:
- Health check (no auth required)
- Bearer token authentication (constant-time comparison)
- POST /api/message (happy path, agent status variants, input validation)
- SSE streaming via GET /api/events
- Confirmation flow via POST /api/confirm/{confirmation_id}
- Session management and isolation
- CORS middleware
- Error handling (validation errors, agent exceptions, malformed JSON)
- Security invariants (AST scans, no forbidden imports)
- Static file serving

Security notes:
- All tests use mocked Agent and config — no real Ollama or external calls.
- Auth token is a known test value, never a real secret.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from admino.models import (
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
)
from admino.server import create_app

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEST_TOKEN = "a" * 48 + "BcDeFgHiJkLmNoPqRsTuVwXyZ"  # >48 chars, >20 unique
_AUTH_HEADER = {"Authorization": f"Bearer {_TEST_TOKEN}"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(*, auth_mode: str = "token", token: str | None = _TEST_TOKEN) -> Any:
    """Build a minimal mock AppConfig."""
    config = MagicMock()
    config.auth.mode = auth_mode
    config.limits.max_message_length = 4000
    if token is not None:
        config.auth.token = SecretStr(token)
    else:
        config.auth.token = None
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
        pending_confirmation: PendingConfirmation | None = None,
    ) -> AgentResult:
        self.run_calls.append(
            {
                "user_message": user_message,
                "session_id": session_id,
                "history": history,
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
    auth_mode: str = "token",
    token: str | None = _TEST_TOKEN,
) -> Any:
    """Create a FastAPI app with the given agent and config."""
    if agent is None:
        agent = FakeAgent([_make_agent_result()])
    config = _make_config(auth_mode=auth_mode, token=token)
    return create_app(agent=agent, config=config)


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


class TestHealthCheck:
    """GET /health — no auth required, returns status ok. Checks database connectivity."""

    pytestmark = pytest.mark.asyncio

    async def test_server_health_returns_200_ok(self) -> None:
        app = _make_app()
        with patch("admino.database.check_health", new=AsyncMock(return_value=True)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    async def test_server_health_no_auth_required(self) -> None:
        """Health check must succeed even with token auth enabled and no header."""
        app = _make_app(auth_mode="token")
        with patch("admino.database.check_health", new=AsyncMock(return_value=True)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200

    async def test_server_health_returns_503_when_db_unreachable(self) -> None:
        """Health check returns 503 when check_health() returns False."""
        app = _make_app()
        with patch("admino.database.check_health", new=AsyncMock(return_value=False)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 503
        assert resp.json()["detail"] == "Database unreachable"


class TestAuth:
    """Bearer token authentication enforcement."""

    pytestmark = pytest.mark.asyncio

    async def test_server_post_message_no_auth_returns_401(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Unauthorized"

    async def test_server_post_message_wrong_token_returns_401(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
                headers={"Authorization": "Bearer wrong-token-value"},
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Unauthorized"

    async def test_server_post_message_valid_token_succeeds(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 200

    async def test_server_get_events_no_auth_returns_401(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/events", params={"session_id": "sess1"})
        assert resp.status_code == 401

    async def test_server_post_confirm_no_auth_returns_401(self) -> None:
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
        assert resp.status_code == 401

    async def test_server_auth_401_body_no_internal_details(self) -> None:
        """401 response body must be exactly {"detail": "Unauthorized"}."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
                headers={"Authorization": "Bearer bad"},
            )
        body = resp.json()
        assert body == {"detail": "Unauthorized"}

    async def test_server_auth_vpn_mode_no_token_needed(self) -> None:
        """VPN mode skips auth entirely."""
        app = _make_app(auth_mode="vpn")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert resp.status_code == 200

    async def test_server_auth_malformed_header_returns_401(self) -> None:
        """Authorization header without 'Bearer ' prefix returns 401."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
                headers={"Authorization": f"Token {_TEST_TOKEN}"},
            )
        assert resp.status_code == 401


class TestPostMessage:
    """POST /api/message — happy path and agent status variants."""

    pytestmark = pytest.mark.asyncio

    async def test_server_message_final_status_returns_200(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 422

    async def test_server_message_missing_session_id_returns_422(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello"},
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 422

    async def test_server_message_empty_message_returns_422(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "", "session_id": "sess1"},
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 422

    async def test_server_message_oversized_message_returns_422(self) -> None:
        app = _make_app()
        oversized = "x" * 32769  # exceeds max_length=32768
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": oversized, "session_id": "sess1"},
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers={**_AUTH_HEADER, "Content-Type": "application/json"},
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            # Now get events for that session
            resp = await c.get(
                "/api/events",
                params={"session_id": "sess1"},
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 422

    async def test_server_events_empty_session_id_returns_422(self) -> None:
        """Empty session_id returns 422 (Pydantic Query validation)."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/api/events",
                params={"session_id": ""},
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": False,
                },
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            resp = await c.post(
                "/api/confirm/wrong-id",
                json={
                    "session_id": "sess1",
                    "confirmation_id": "wrong-id",
                    "approved": True,
                },
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": "different-id-in-body",
                    "approved": True,
                },
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            # First confirm
            resp1 = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess2",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            await c.post(
                "/api/message",
                json={"message": "help me", "session_id": "sess1"},
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            await c.post(
                "/api/message",
                json={"message": "msg-b", "session_id": "sessB"},
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
            await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess2"},
                headers=_AUTH_HEADER,
            )
        assert agent.run_calls[0]["history"] == []
        assert agent.run_calls[1]["history"] == []


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
                    "Access-Control-Request-Headers": "Authorization,Content-Type",
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
                    "Access-Control-Request-Headers": "Authorization",
                },
            )
        # CORSMiddleware returns 400 or omits the allow-origin header
        allow_origin = resp.headers.get("access-control-allow-origin", "")
        assert "evil.com" not in allow_origin


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
                headers=_AUTH_HEADER,
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
                headers={**_AUTH_HEADER, "Content-Type": "application/json"},
            )
        assert resp.status_code == 422

    async def test_server_wrong_content_type_returns_422(self) -> None:
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                content=b"message=hello&session_id=sess1",
                headers={**_AUTH_HEADER, "Content-Type": "application/x-www-form-urlencoded"},
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

    def test_server_imports_hmac(self) -> None:
        """server.py must import hmac for constant-time token comparison."""
        tree = self._get_server_ast()
        found_hmac = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "hmac":
                        found_hmac = True
        assert found_hmac, "server.py must import hmac"

    def test_server_auth_uses_constant_time_comparison(self) -> None:
        """Verify server.py uses hmac.compare_digest for token comparison."""
        tree = self._get_server_ast()
        found = False
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "hmac"
                and node.attr == "compare_digest"
            ):
                found = True
                break
        assert found, "server.py must use hmac.compare_digest for token comparison"


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
        with patch("admino.database.check_health", new=AsyncMock(return_value=True)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    async def test_server_api_routes_override_static(self) -> None:
        """/api/message still works even if static mount is present."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
                headers=_AUTH_HEADER,
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
        app1 = create_app(agent=agent, config=config)

        # Post a message to populate session state
        async with AsyncClient(transport=ASGITransport(app=app1), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
                headers=_AUTH_HEADER,
            )

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
                headers=_AUTH_HEADER,
            )
            await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": False,
                },
                headers=_AUTH_HEADER,
            )
        # Pending should be cleared
        assert "sess1" not in srv._pending_confirmations

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
                headers=_AUTH_HEADER,
            )
            await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
                headers=_AUTH_HEADER,
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
            tool="files",
            action="write",
        )
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Action files.write requires user confirmation.",
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "write a file", "session_id": "sess1"},
                headers=_AUTH_HEADER,
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "awaiting_confirmation"
        assert data["pending_confirmation"] is not None
        pc = data["pending_confirmation"]
        assert pc["confirmation_id"] == "confirm-xyz-42"
        assert pc["tool"] == "files"
        assert pc["action"] == "write"
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
                headers=_AUTH_HEADER,
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
            LLMMessage(role="user", content="write a file"),
            LLMMessage(
                role="assistant",
                content="I'll write the file.",
                tool_use_blocks=[
                    {
                        "type": "tool_use",
                        "id": "toolu_abc123",
                        "name": "files.write",
                        "input": {"path": "/app/documents/x.txt", "content": "hi"},
                    }
                ],
            ),
        ]
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Action files.write requires user confirmation.",
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
                json={"message": "write a file", "session_id": "sess1"},
                headers=_AUTH_HEADER,
            )
            assert "sess1" in srv._pending_confirmations

            # Turn 2: user sends a new chat message instead of calling
            # /api/confirm/{id}. Must succeed (no 500) and the pending
            # confirmation must have been cleared.
            resp = await c.post(
                "/api/message",
                json={"message": "I confirm it!", "session_id": "sess1"},
                headers=_AUTH_HEADER,
            )

        assert resp.status_code == 200
        assert "sess1" not in srv._pending_confirmations

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
            LLMMessage(role="user", content="list files"),
            LLMMessage(
                role="assistant",
                content="",
                tool_use_blocks=[
                    {"type": "tool_use", "id": "toolu_1", "name": "files.list", "input": {}},
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
                        headers=_AUTH_HEADER,
                    )
            # Only the 3 most recent sessions should remain.
            assert len(srv._sessions) == 3
            assert "sess0" not in srv._sessions
            assert "sess1" not in srv._sessions
            assert "sess4" in srv._sessions
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
                        headers=_AUTH_HEADER,
                    )
                # Reuse sess0 (moves to end)
                await c.post(
                    "/api/message",
                    json={"message": "hi again", "session_id": "sess0"},
                    headers=_AUTH_HEADER,
                )
                # Add sess3 — should evict sess1 (oldest unreused)
                await c.post(
                    "/api/message",
                    json={"message": "hi", "session_id": "sess3"},
                    headers=_AUTH_HEADER,
                )
            assert "sess0" in srv._sessions  # reused, so not evicted
            assert "sess1" not in srv._sessions  # oldest, evicted
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

        srv._pending_confirmations["sess1"] = pending
        srv._sessions["sess1"] = [LLMMessage(role="user", content="hi")]

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
                headers=_AUTH_HEADER,
            )
        # Expired entry is reaped before lookup, so 404 (not 410).
        assert resp.status_code == 404

    async def test_server_reap_removes_expired_before_lookup(self) -> None:
        """Expired confirmations are reaped before any lookup."""
        import admino.server as srv

        expired_pending = _make_pending_confirmation(session_id="sess-expired", expired=True)
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)

        srv._pending_confirmations["sess-expired"] = expired_pending

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            # Query for a different session — the expired one should be reaped
            resp = await c.post(
                "/api/confirm/some-id",
                json={
                    "session_id": "sess-other",
                    "confirmation_id": "some-id",
                    "approved": True,
                },
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 404
        assert "sess-expired" not in srv._pending_confirmations


class TestMaxMessageLength:
    """L-5: max_message_length from config is enforced."""

    pytestmark = pytest.mark.asyncio

    async def test_server_message_exceeds_config_max_length_returns_422(self) -> None:
        """Message longer than config.limits.max_message_length -> 422."""
        agent = FakeAgent([_make_agent_result()])
        config = _make_config()
        config.limits.max_message_length = 100
        app = create_app(agent=agent, config=config)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "x" * 101, "session_id": "sess1"},
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 422
        assert "maximum length" in resp.json()["detail"].lower()

    async def test_server_message_within_config_max_length_succeeds(self) -> None:
        """Message within config limit succeeds."""
        agent = FakeAgent([_make_agent_result()])
        config = _make_config()
        config.limits.max_message_length = 100
        app = create_app(agent=agent, config=config)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "x" * 100, "session_id": "sess1"},
                headers=_AUTH_HEADER,
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
                    "Access-Control-Request-Headers": "Authorization,Content-Type",
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
                headers=_AUTH_HEADER,
            )
        # Empty string would result in 404/405 since route won't match
        if bad_id == "":
            assert resp.status_code in (404, 405, 422)
        else:
            assert resp.status_code == 422


class TestVPNModeWarning:
    """L-1: VPN mode logs a warning at startup."""

    def test_server_vpn_mode_logs_warning(self, caplog: Any) -> None:
        """create_app in VPN mode logs a warning."""
        import logging

        with caplog.at_level(logging.WARNING, logger="admino.server"):
            _make_app(auth_mode="vpn")
        assert any("VPN mode" in record.message for record in caplog.records)


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
                headers=_AUTH_HEADER,
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
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 200
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"

    async def test_server_401_includes_security_headers(self) -> None:
        """Even 401 responses include security headers."""
        app = _make_app()
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
                    headers=_AUTH_HEADER,
                )
                statuses.append(resp.status_code)
        # First 5 should succeed (burst capacity), rest should be 429
        assert 429 in statuses, "Rate limiter should return 429 after burst capacity"
        assert statuses[0] == 200, "First request should succeed"


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
                headers=_AUTH_HEADER,
            )
        assert "sess1" in srv._session_locks

        # Creating a new app clears locks
        _make_app()
        assert len(srv._session_locks) == 0
