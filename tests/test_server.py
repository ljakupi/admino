"""Comprehensive test suite for admino.server — HTTP layer, auth, SSE, confirmations.

Tests the FastAPI application created by ``create_app()``, covering:
- Health check (no session required; GH-158: ``{status}`` only, the provider,
  model and reachability are on the Super Admin diagnostics route, see
  tests/test_health_api.py)
- Session-cookie authentication (GH-149): every chat route answers 401
  ``{"detail": "Unauthorized"}`` without a valid ``admino_session`` cookie; the
  old bearer token / vpn mode is gone (an ``Authorization`` header authenticates
  nothing, ``config.auth`` is never read, no VPN warning).
- The ``chat.send`` role gate: Org Admins and Editors may chat; Viewers and
  Super Admins get 403 ``{"detail": "Forbidden"}`` on POST /api/message and
  POST /api/confirm/{id}.
- POST /api/message and POST /api/confirm/{id} pass the logged-in principal to
  ``agent.run(principal=...)`` (and, through a real Agent, to the tool-call
  recorder).
- POST /api/message (happy path, agent status variants, input validation)
- GH-8: ``GET /api/events`` (handler ``get_events``, its rate-limit entry) and
  ``_stream_agent_result`` are removed: the path answers like any unknown
  ``/api`` path. The SSE frame helpers ``_format_sse`` / ``_make_sse_event``
  stay (the streamed chat routes are pinned in tests/test_chat_stream_api.py).
- Confirmation flow via POST /api/confirm/{confirmation_id}
- GH-176: the legacy ``session_id`` routes are backed by persisted chats (one
  ``chats`` row per (user, session id) through ``legacy_session_id``, here a
  ``tests.db_fakes.FakeDb`` behind ``admino.database.get_pool``). A run's
  history is the chat's stored messages (never an in-memory ``_sessions``
  map, which is gone with ``_pending_confirmations``, ``_session_locks``,
  ``_MAX_SESSIONS``, ``_chat_key``, ``_get_session_lock`` and
  ``_touch_session``); the agent's ``session_id`` is ``str(chat.id)``; the
  turn's new messages are appended to the chat; ``ChatResponse`` carries the
  ``chat_id`` and echoes the legacy ``session_id``. Per-chat run locks and
  pending confirmations live in the bounded ``server._chat_runtime``
  (``ChatRuntime(max_entries=1024, idle_s=900.0)``), keyed by the chat id and
  cleared by ``create_app()`` (a restart). Each user has their own chat per
  session id: another user's turn never reads or changes it, and nobody else
  can confirm, deny or cancel its pending confirmation. A denial persists the
  closing ``tool`` result(s) and the denial message, so the stored history
  stays well-formed. GH-8: a message to a chat whose run is still going is
  ``409 run_active`` (never queued behind it, never run).
- CORS middleware (``Authorization`` is no longer an allowed header)
- Per-caller rate limits (GH-149): ``_check_rate_limit(route, caller)`` keeps
  one token bucket per (route, caller) in ``_rate_buckets``; one user (or IP)
  exhausting a bucket never throttles another; idle buckets are evicted and
  the map is capped (LRU).
- Error handling (validation errors, agent exceptions, malformed JSON)
- Security invariants (AST scans, no forbidden imports)
- Static file serving
- GH-161: each chat run (POST /api/message, POST /api/confirm) gets the
  requesting org's ``tool_policy``, loaded per request through
  ``org_permissions.load_tool_policy`` (stubbed here: the pool is a MagicMock);
  the rate-limit table carries the /api/org/permissions*,
  /api/org/critical-permissions* and /api/permissions/summary keys.
- GH-170: each chat run (POST /api/message, an approved POST /api/confirm) gets
  the caller's ``PromptContext``, loaded on every request through
  ``scoped_settings.load_prompt_context(pool, tenant)`` with the caller's own
  ``TenantContext`` (stubbed here: the pool is a MagicMock) and passed as
  ``agent.run(..., prompt_context=...)``; a failing load is a generic 500. A
  real Agent (fixed clock) sends exactly one system message per LLM call, at
  index 0: ``prompt_assembly.system_prompt(<loaded context>, tools=<the run's
  advertised tools>, now=<the clock>)``, never accumulated over turns or a
  confirmation resume.

Callers are logged in through ``tests.auth_helpers.login`` (a dependency
override of ``server.require_session``); ``resolved_session`` drives the real
cookie dependency with a patched ``admino.sessions.resolve_session``.

Security notes:
- All tests use mocked Agent and config — no real LLM, database or external calls.
- The session token is a known fake value, never a real secret.
"""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import json
import logging
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest
import pytest_asyncio
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, Field

from admino import models, scoped_settings
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
from admino.tenancy import TenantContext
from admino.tools.registry import ToolDescription, clear_registry, register_tool
from tests.auth_helpers import (
    TEST_MEMBER_ID,
    TEST_ORG_ID,
    TEST_SESSION_TOKEN,
    login,
    member_session,
    resolved_session,
    session_cookie,
    super_admin_session,
)
from tests.conftest import default_test_platform_settings
from tests.db_fakes import FakeDb

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator

    from admino.access import MemberRole, Principal
    from admino.models import PromptContext, ToolPolicy
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
    ``config.auth`` again, so touching it raises AttributeError. The server
    section carries the real defaults the app reads (GH-156): CORS allows
    ``public_url`` only, and no proxy is trusted. GH-190 (contract C11): the chat
    routes' context budget reads the output cap (``llm.max_response_tokens``) and
    the ``context`` section, so they carry config.yaml's defaults.
    """
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.public_url = "http://localhost:8000"
    config.server.trusted_proxies = []
    config.llm.max_response_tokens = 4096
    config.context.safety_margin_percent = 10
    config.context.max_attachment_mb_per_turn = 64
    config.context.max_tool_result_tokens = 8000
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
    """A fake Agent that returns scripted AgentResult values in sequence.

    Like the real Agent, the history a run returns is the history it received
    followed by the turn's messages: a scripted result's ``history`` holds only
    what that turn adds (GH-176: the route persists ``result.history[len(loaded):]``).
    """

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
        tool_policy: ToolPolicy,
        pending_confirmation: PendingConfirmation | None = None,
        agent_config: AgentConfig | None = None,
        prompt_context: PromptContext | None = None,
        earlier_external_content: bool = False,
    ) -> AgentResult:
        """Record the call (GH-149: ``principal`` is a required keyword; GH-160: the
        run's ``agent_config`` from the stored platform limits; GH-161: the requesting
        org's ``tool_policy`` is a required keyword too; GH-170: the caller's
        ``prompt_context``, loaded per request; GH-176: ``session_id`` is the chat's
        id and ``earlier_external_content`` the chat's sticky external-content flag)
        and reply."""
        self.run_calls.append(
            {
                "user_message": user_message,
                "session_id": session_id,
                "history": list(history),
                "principal": principal,
                "tool_policy": tool_policy,
                "pending_confirmation": pending_confirmation,
                "agent_config": agent_config,
                "prompt_context": prompt_context,
                "earlier_external_content": earlier_external_content,
            }
        )
        if self._call_index >= len(self._results):
            result = _make_agent_result()
        else:
            result = self._results[self._call_index]
            self._call_index += 1
        return result.model_copy(update={"history": [*history, *result.history]})


# The org policy the stubbed per-run load returns (GH-161): echo.write needs a
# confirmation, every service is on (the real-Agent GH-140 tests rely on it).
_STUB_ORG_PERMISSIONS = PermissionsConfig(
    tools={"echo": ToolPermissions(actions={"write": "confirm"})}
)


@pytest.fixture(autouse=True)
def org_tool_policy(monkeypatch: pytest.MonkeyPatch) -> AsyncMock | None:
    """Stub the per-run org policy load of the chat routes (GH-161).

    POST /api/message and POST /api/confirm load the requesting org's
    ``ToolPolicy`` through ``org_permissions.load_tool_policy(pool, tenant)``;
    this suite's pool is a MagicMock, so the load returns a fixed policy
    (``_STUB_ORG_PERMISSIONS``). Until ``admino.org_permissions`` exists there is
    nothing to stub (None): the chat routes then fail on FakeAgent's required
    ``tool_policy`` keyword.
    """
    if importlib.util.find_spec("admino.org_permissions") is None:
        return None
    from admino.models import ToolPolicy

    load = AsyncMock(return_value=ToolPolicy(permissions=_STUB_ORG_PERMISSIONS))
    monkeypatch.setattr("admino.org_permissions.load_tool_policy", load)
    return load


# What the stubbed prompt context load returns while ``models.PromptContext`` doesn't
# exist yet (GH-170): a distinct object, so "the run got the loaded context" can never
# pass on a None that nobody loaded.
_NO_PROMPT_CONTEXT_YET = object()


def _prompt_context(**fields: Any) -> PromptContext:
    """A ``models.PromptContext`` (GH-170); fails the calling test while it's missing."""
    from admino.models import PromptContext

    return PromptContext(**fields)


@pytest.fixture(autouse=True)
def prompt_context_loader(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Stub the per-run prompt context load of the chat routes (GH-170).

    POST /api/message and POST /api/confirm load the caller's ``PromptContext``
    (org and personal instructions, response languages, timezone) through
    ``scoped_settings.load_prompt_context(pool, tenant)`` on every request; this
    suite's pool is a MagicMock, so the load returns ``PromptContext()`` (no
    instructions, no language, the default timezone). ``raising=False`` and the
    lazy model lookup keep the suite importable before GH-170.
    """
    model = getattr(models, "PromptContext", None)
    load = AsyncMock(return_value=_NO_PROMPT_CONTEXT_YET if model is None else model())
    monkeypatch.setattr(scoped_settings, "load_prompt_context", load, raising=False)
    return load


def _loaded_tenant(call: Any) -> Any:
    """The tenant one ``load_prompt_context(pool, tenant)`` call got."""
    return call.args[1] if len(call.args) > 1 else call.kwargs["tenant"]


@pytest.fixture(autouse=True)
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The chat routes' database (GH-176): a FakeDb behind ``admino.database.get_pool``.

    The legacy chat routes persist one chat per (user, session id) and its
    messages, so the pool is a ``tests.db_fakes.FakeDb`` holding the org and
    the two members this suite logs in with (``TEST_MEMBER_ID`` and
    ``_OTHER_USER_ID``, both of ``TEST_ORG_ID``). The platform limits still come
    from the settings cache the conftest primes (GH-160), the org policy and the
    prompt context from the stubbed loads above.
    """
    fake = FakeDb()
    fake.add_org(TEST_ORG_ID)
    for user_id in (TEST_MEMBER_ID, _OTHER_USER_ID):
        fake.add_account(user_id=user_id, org_id=TEST_ORG_ID, role="editor")
    monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=fake.pool))
    return fake


@contextmanager
def _resolved_on_db(session: AuthenticatedSession | None, db: FakeDb) -> Iterator[AsyncMock]:
    """``auth_helpers.resolved_session`` with the suite's FakeDb pool kept (GH-176).

    ``resolved_session`` patches ``get_pool`` with a MagicMock; the legacy chat
    routes now store the chat on the pool, so it is pointed back at ``db``.
    """
    with (
        resolved_session(session) as resolve,
        patch("admino.database.get_pool", MagicMock(return_value=db.pool)),
    ):
        yield resolve


def _runtime() -> Any:
    """``server._chat_runtime`` (GH-176): the bounded per-chat locks and pending confirmations."""
    from admino import server

    return server._chat_runtime


def _legacy_chat(db: FakeDb, session_id: str, user_id: UUID = TEST_MEMBER_ID) -> dict[str, Any]:
    """The one live chat of ``user_id`` behind the legacy ``session_id`` (GH-176)."""
    rows = [
        row
        for row in db.chats_of(user_id)
        if row["legacy_session_id"] == session_id and row["deleted_at"] is None
    ]
    assert len(rows) == 1, f"expected one live legacy chat of {user_id}, found {len(rows)}"
    return rows[0]


def _legacy_chat_id(db: FakeDb, session_id: str, user_id: UUID = TEST_MEMBER_ID) -> UUID:
    """The id of ``_legacy_chat`` as a plain UUID."""
    return UUID(str(_legacy_chat(db, session_id, user_id)["id"]))


def _rows(db: FakeDb, chat_id: UUID) -> list[tuple[str, str]]:
    """``(role, content)`` of every stored message of a chat, in order."""
    return [(row["role"], row["content"]) for row in db.messages_of(chat_id)]


def _pairs(messages: list[LLMMessage]) -> list[tuple[str, str]]:
    """``(role, content)`` of every message."""
    return [(message.role, message.content) for message in messages]


def _turn(message: str, reply: str, **fields: Any) -> AgentResult:
    """An AgentResult whose turn adds the user ``message`` and the assistant ``reply``."""
    return _make_agent_result(
        response=reply,
        history=[
            LLMMessage(role="user", content=message),
            LLMMessage(role="assistant", content=reply),
        ],
        **fields,
    )


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
    tool_call_id: str | None = None,
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
        tool_call=ToolCall(tool=tool, action=action, args={}, tool_call_id=tool_call_id),
        created_at=created_at,
        expires_at=expires_at,
    )


# ---------------------------------------------------------------------------
# Test Classes
# ---------------------------------------------------------------------------


class TestHealthCheck:
    """GET /health — public, and answers ``{status}`` only (GH-158).

    The active provider, model and LLM reachability moved to
    ``GET /api/platform/diagnostics`` (Super Admin); tests/test_health_api.py pins
    that route, the per-IP rate limit and the request-ID header.
    """

    pytestmark = pytest.mark.asyncio

    async def test_server_health_returns_200_ok(self) -> None:
        """A healthy DB returns 200 with exactly ``{"status": "ok"}``."""
        app = _make_app()
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    async def test_server_health_does_not_report_provider_or_model(self) -> None:
        """GH-158: the public payload names no provider, model or reachability."""
        app = _make_app()
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert set(resp.json()) == {"status"}

    async def test_server_health_never_probes_the_llm(self) -> None:
        """GH-158: /health doesn't await the LLM reachability probe."""
        app = _make_app()
        probe = AsyncMock(return_value=True)
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=probe),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200
        probe.assert_not_awaited()

    async def test_server_health_no_auth_required(self) -> None:
        """Health check is public: it succeeds with no session cookie."""
        app = _make_app(anonymous=True)
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=True)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 200

    async def test_server_health_returns_503_when_db_unreachable(self) -> None:
        """check_health() False: 503 with exactly ``{"status": "degraded"}`` (no detail)."""
        app = _make_app()
        with (
            patch("admino.database.check_health", new=AsyncMock(return_value=False)),
            patch("admino.server._check_llm_reachable", new=AsyncMock(return_value=True)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/health")
        assert resp.status_code == 503
        assert resp.json() == {"status": "degraded"}


_MESSAGE_BODY: dict[str, Any] = {"message": "hello", "session_id": "sess1"}
_CONFIRM_BODY: dict[str, Any] = {
    "session_id": "sess1",
    "confirmation_id": "some-id",
    "approved": True,
}


async def _call_chat_route(client: AsyncClient, route: str, **kwargs: Any) -> Any:
    """Send a well-formed request to one of the two legacy chat routes (GH-8: GET
    /api/events is gone)."""
    if route == "message":
        return await client.post("/api/message", json=_MESSAGE_BODY, **kwargs)
    return await client.post("/api/confirm/some-id", json=_CONFIRM_BODY, **kwargs)


_CHAT_ROUTES = ["message", "confirm"]


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

    async def test_server_post_message_valid_session_cookie_succeeds(self, db: FakeDb) -> None:
        """A cookie that resolves to an Editor's session is let through."""
        app = _make_app(anonymous=True)
        with _resolved_on_db(member_session("editor"), db):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.post(
                    "/api/message",
                    json={"message": "hello", "session_id": "sess1"},
                    headers=session_cookie(),
                )
        assert resp.status_code == 200

    async def test_server_session_cookie_value_is_what_gets_resolved(self, db: FakeDb) -> None:
        """require_session looks up exactly the admino_session cookie's token."""
        app = _make_app(anonymous=True)
        with _resolved_on_db(member_session("editor"), db) as resolve:
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

    async def test_server_session_cookie_principal_reaches_agent(self, db: FakeDb) -> None:
        """The principal comes from the resolved session, never from the request."""
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent, anonymous=True)
        session = member_session("org_admin", user_id=_OTHER_USER_ID)
        with _resolved_on_db(session, db):
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

    async def test_server_post_message_runs_with_the_loaded_org_policy(
        self, org_tool_policy: AsyncMock | None
    ) -> None:
        """GH-161: the run gets the policy loaded for the caller's own org."""
        assert org_tool_policy is not None, "admino.org_permissions.load_tool_policy is missing"
        agent = FakeAgent([_make_agent_result()])
        session = member_session("editor")
        app = _make_app(agent, session=session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/message", json={"message": "hi", "session_id": "sess1"})

        assert resp.status_code == 200
        org_tool_policy.assert_awaited_once()
        tenant = org_tool_policy.await_args.args[1]
        assert tenant.org_id == session.principal.org_id
        assert agent.run_calls[0]["tool_policy"] is org_tool_policy.return_value

    async def test_server_post_confirm_runs_with_the_loaded_org_policy(
        self, org_tool_policy: AsyncMock | None
    ) -> None:
        """GH-161: the resumed run gets the org's policy loaded again (never cached)."""
        assert org_tool_policy is not None, "admino.org_permissions.load_tool_policy is missing"
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
        assert org_tool_policy.await_count == 2
        assert {call.args[1].org_id for call in org_tool_policy.await_args_list} == {
            session.principal.org_id
        }
        assert [call["tool_policy"] for call in agent.run_calls] == [
            org_tool_policy.return_value,
            org_tool_policy.return_value,
        ]


def _awaiting_confirmation() -> tuple[PendingConfirmation, AgentResult]:
    """A pending confirmation on chat ``sess1`` and the run result that awaits it."""
    pending = _make_pending_confirmation(session_id="sess1")
    awaiting = _make_agent_result(
        status="awaiting_confirmation",
        response="Requires confirmation.",
        pending_confirmation=pending,
    )
    return pending, awaiting


async def _approve(client: AsyncClient, pending: PendingConfirmation) -> Any:
    """POST /api/confirm approving ``pending`` on chat ``sess1``."""
    return await client.post(
        f"/api/confirm/{pending.confirmation_id}",
        json={
            "session_id": "sess1",
            "confirmation_id": pending.confirmation_id,
            "approved": True,
        },
    )


class TestPromptContextPerRun:
    """GH-170: every chat run gets the caller's prompt context, loaded per request.

    ``scoped_settings.load_prompt_context(pool, tenant)`` runs on every POST
    /api/message and approved POST /api/confirm with the caller's own
    ``TenantContext``; its result is passed as ``agent.run(prompt_context=...)``.
    A change of the org's instructions or default language, or of the user's
    language, timezone or instructions, applies to the next message (no cache, no
    restart). A failing load is a generic 500 and the run never starts.
    """

    pytestmark = pytest.mark.asyncio

    async def test_server_post_message_runs_with_the_loaded_prompt_context(
        self, prompt_context_loader: AsyncMock
    ) -> None:
        loaded = _prompt_context(org_instructions="Answer formally.", response_language="it")
        prompt_context_loader.return_value = loaded
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/message", json=_MESSAGE_BODY)

        assert resp.status_code == 200
        prompt_context_loader.assert_awaited_once()
        assert agent.run_calls[0]["prompt_context"] is loaded

    async def test_server_post_message_loads_the_prompt_context_for_the_callers_tenant(
        self, prompt_context_loader: AsyncMock
    ) -> None:
        session = member_session("org_admin", user_id=_OTHER_USER_ID)
        app = _make_app(FakeAgent([_make_agent_result()]), session=session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/message", json=_MESSAGE_BODY)

        assert resp.status_code == 200
        prompt_context_loader.assert_awaited_once()
        tenant = _loaded_tenant(prompt_context_loader.await_args)
        assert isinstance(tenant, TenantContext)
        assert (tenant.org_id, tenant.user_id) == (
            session.principal.org_id,
            session.principal.user_id,
        )

    async def test_server_post_confirm_runs_with_its_own_freshly_loaded_prompt_context(
        self, prompt_context_loader: AsyncMock
    ) -> None:
        """The resumed run gets the context the confirm request loaded, for the caller's
        tenant (never the one the message loaded)."""
        at_message = _prompt_context(response_language="de")
        at_confirm = _prompt_context(response_language="fr", timezone="America/New_York")
        prompt_context_loader.side_effect = [at_message, at_confirm]
        pending, awaiting = _awaiting_confirmation()
        agent = FakeAgent([awaiting, _make_agent_result(response="Done.")])
        session = member_session("editor", user_id=_OTHER_USER_ID)
        app = _make_app(agent, session=session)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "create", "session_id": "sess1"})
            resp = await _approve(c, pending)

        assert resp.status_code == 200
        assert agent.run_calls[1]["pending_confirmation"] is not None
        assert [call["prompt_context"] for call in agent.run_calls] == [at_message, at_confirm]
        assert {
            (_loaded_tenant(call).org_id, _loaded_tenant(call).user_id)
            for call in prompt_context_loader.await_args_list
        } == {(session.principal.org_id, session.principal.user_id)}

    async def test_server_each_message_loads_the_prompt_context_again(
        self, prompt_context_loader: AsyncMock
    ) -> None:
        """A changed setting applies to the very next message: nothing is cached."""
        before = _prompt_context(default_response_language="de")
        after = _prompt_context(default_response_language="fr", org_instructions="New rule.")
        prompt_context_loader.side_effect = [before, after]
        agent = FakeAgent([_make_agent_result(), _make_agent_result()])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "a", "session_id": "sess1"})
            await c.post("/api/message", json={"message": "b", "session_id": "sess1"})

        assert prompt_context_loader.await_count == 2
        assert [call["prompt_context"] for call in agent.run_calls] == [before, after]

    async def test_server_each_user_loads_the_prompt_context_of_their_own_tenant(
        self, prompt_context_loader: AsyncMock
    ) -> None:
        """Two users on one app: each load gets the tenant of its own request."""
        agent = FakeAgent([_make_agent_result(), _make_agent_result()])
        first = member_session("editor")
        second = member_session("org_admin", user_id=_OTHER_USER_ID)
        app = _make_app(agent, session=first)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "a", "session_id": "sess-a"})
            login(app, second)
            await c.post("/api/message", json={"message": "b", "session_id": "sess-b"})

        assert [_loaded_tenant(call).user_id for call in prompt_context_loader.await_args_list] == [
            first.principal.user_id,
            second.principal.user_id,
        ]

    @pytest.mark.parametrize("route", ["message", "confirm"])
    async def test_server_prompt_context_load_failure_is_a_generic_500(
        self,
        prompt_context_loader: AsyncMock,
        route: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A failing load answers 500 ``{"detail": "Internal error"}``, the run never
        starts, and nothing of the error reaches the body or a log line."""
        secret = "Org instructions: SECRET-7f3a-never-echoed"
        pending, awaiting = _awaiting_confirmation()
        agent = FakeAgent([awaiting])
        app = _make_app(agent)
        caplog.set_level(logging.DEBUG)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            if route == "message":
                prompt_context_loader.side_effect = RuntimeError(secret)
                resp = await c.post("/api/message", json=_MESSAGE_BODY)
                runs_expected = 0
            else:
                prompt_context_loader.side_effect = [
                    prompt_context_loader.return_value,
                    RuntimeError(secret),
                ]
                await c.post("/api/message", json={"message": "create", "session_id": "sess1"})
                resp = await _approve(c, pending)
                runs_expected = 1

        assert (resp.status_code, resp.json()) == (500, {"detail": "Internal error"})
        assert len(agent.run_calls) == runs_expected
        assert secret not in resp.text
        assert not [r for r in caplog.records if secret in r.getMessage()]


class TestPostMessage:
    """POST /api/message — happy path and agent status variants."""

    pytestmark = pytest.mark.asyncio

    async def test_server_message_final_status_returns_200(self, db: FakeDb) -> None:
        """GH-176: the response carries the legacy chat's id and echoes the session id."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "sess1"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "sess1"
        assert data["chat_id"] == str(_legacy_chat_id(db, "sess1"))
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


class TestEventsRouteRemoved:
    """GH-8 (C5.8): the GET /api/events stub and ``_stream_agent_result`` are gone."""

    pytestmark = pytest.mark.asyncio

    async def test_server_get_events_answers_like_an_unknown_api_path(self) -> None:
        """A logged-in member's ``GET /api/events?session_id=x`` gets exactly what an
        unknown ``/api`` path gets (``404 {"detail": "Not Found"}``, same content type),
        no run; no route serves the path, ``admino.server`` has no ``get_events`` or
        ``_stream_agent_result`` and the rate table no ``/api/events`` entry."""
        from admino import server

        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            unknown = await c.get("/api/nope", params={"session_id": "x"})
            events = await c.get("/api/events", params={"session_id": "x"})

        assert (unknown.status_code, unknown.json()) == (404, {"detail": "Not Found"})
        assert (events.status_code, events.text) == (unknown.status_code, unknown.text)
        assert events.headers.get("content-type") == unknown.headers.get("content-type")
        assert agent.run_calls == []
        assert [r for r in app.routes if getattr(r, "path", None) == "/api/events"] == []
        assert [n for n in ("get_events", "_stream_agent_result") if hasattr(server, n)] == []
        assert "/api/events" not in server._RATE_LIMITS


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

    async def test_server_confirm_approved_resumes_agent(self, db: FakeDb) -> None:
        """Approve a pending confirmation -> agent resumes -> final response.

        GH-176: the resumed run is on the legacy chat (its id as ``session_id``, its
        stored messages as history) and the response carries the chat id and echoes
        the session id.
        """
        pending = _make_pending_confirmation(session_id="sess1")
        awaiting_result = _turn(
            "create event",
            "Calendar event requires confirmation.",
            status="awaiting_confirmation",
            pending_confirmation=pending,
        )
        resumed_result = _make_agent_result(
            status="final",
            response="Event created successfully.",
            history=[LLMMessage(role="assistant", content="Event created successfully.")],
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
        chat_id = _legacy_chat_id(db, "sess1")
        assert (data["chat_id"], data["session_id"]) == (str(chat_id), "sess1")
        resumed = agent.run_calls[1]
        assert resumed["session_id"] == str(chat_id)
        assert _pairs(resumed["history"]) == [
            ("user", "create event"),
            ("assistant", "Calendar event requires confirmation."),
        ]
        assert _rows(db, chat_id) == [
            ("user", "create event"),
            ("assistant", "Calendar event requires confirmation."),
            ("assistant", "Event created successfully."),
        ]

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
    """Legacy session ids are backed by persisted chats (GH-176).

    The first message on a session id creates the caller's chat (``chats`` row
    with that ``legacy_session_id``, in the caller's org); the agent runs with
    ``str(chat.id)`` as its ``session_id`` and the chat's stored messages as its
    history; the turn's new messages are appended to the chat. Another session
    id is another chat.
    """

    pytestmark = pytest.mark.asyncio

    async def test_server_session_created_on_first_message(self, db: FakeDb) -> None:
        """First message creates the caller's chat; the agent runs on it with an empty
        history, and the turn's messages are stored."""
        agent = FakeAgent([_turn("hello", "Hi there.")])
        app = _make_app(agent)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "hello", "session_id": "new-sess"},
            )
        assert resp.status_code == 200
        chat = _legacy_chat(db, "new-sess")
        assert (chat["org_id"], chat["owner_user_id"]) == (TEST_ORG_ID, TEST_MEMBER_ID)
        assert len(agent.run_calls) == 1
        assert agent.run_calls[0]["history"] == []
        assert agent.run_calls[0]["session_id"] == str(chat["id"])
        assert agent.run_calls[0]["earlier_external_content"] is False
        assert _rows(db, chat["id"]) == [("user", "hello"), ("assistant", "Hi there.")]

    async def test_server_session_reuses_history(self, db: FakeDb) -> None:
        """Second message to same session_id runs on the same chat with the stored turn."""
        history1 = [
            LLMMessage(role="user", content="hello"),
            LLMMessage(role="assistant", content="hi"),
        ]
        result1 = _make_agent_result(response="hi", history=history1)
        result2 = _turn("help me", "how can I help?")
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
        # Second call should receive the history stored by the first turn
        assert len(agent.run_calls) == 2
        assert agent.run_calls[1]["history"] == history1
        chat_id = _legacy_chat_id(db, "sess1")
        assert len(db.chats_of(TEST_MEMBER_ID)) == 1
        assert [call["session_id"] for call in agent.run_calls] == [str(chat_id)] * 2
        assert _rows(db, chat_id) == [
            ("user", "hello"),
            ("assistant", "hi"),
            ("user", "help me"),
            ("assistant", "how can I help?"),
        ]

    async def test_server_session_history_is_loaded_from_the_stored_chat(self, db: FakeDb) -> None:
        """A chat stored before this process started (a restart) is the run's history."""
        chat_id = db.add_chat(TEST_MEMBER_ID, legacy_session_id="sess1")
        db.add_chat_message(chat_id, "user", "stored question")
        db.add_chat_message(chat_id, "assistant", "stored answer")
        agent = FakeAgent([_turn("next", "next answer")])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/message", json={"message": "next", "session_id": "sess1"})

        assert resp.status_code == 200
        assert agent.run_calls[0]["session_id"] == str(chat_id)
        assert _pairs(agent.run_calls[0]["history"]) == [
            ("user", "stored question"),
            ("assistant", "stored answer"),
        ]
        assert len(db.chats_of(TEST_MEMBER_ID)) == 1

    async def test_server_session_external_content_flag_reaches_every_run(self, db: FakeDb) -> None:
        """GH-243 via GH-176: a chat stored with external content runs (message and
        approved resume) with ``earlier_external_content=True``."""
        db.add_chat(TEST_MEMBER_ID, legacy_session_id="sess1", external_content=True)
        pending, awaiting = _awaiting_confirmation()
        agent = FakeAgent([awaiting, _make_agent_result(response="Done.")])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "create", "session_id": "sess1"})
            resp = await _approve(c, pending)

        assert resp.status_code == 200
        assert [call["earlier_external_content"] for call in agent.run_calls] == [True, True]

    async def test_server_sessions_are_isolated(self, db: FakeDb) -> None:
        """Messages to session A do not appear in session B."""
        history_a = [LLMMessage(role="user", content="session-a-msg")]
        result_a = _make_agent_result(response="a-reply", history=history_a)
        result_b = _turn("msg-b", "b-reply")
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
        # Session B should receive empty history (new chat)
        assert agent.run_calls[1]["history"] == []
        chat_a, chat_b = _legacy_chat_id(db, "sessA"), _legacy_chat_id(db, "sessB")
        assert [call["session_id"] for call in agent.run_calls] == [str(chat_a), str(chat_b)]
        assert _rows(db, chat_a) == [("user", "session-a-msg")]
        assert _rows(db, chat_b) == [("user", "msg-b"), ("assistant", "b-reply")]

    async def test_server_new_session_creates_new_history(self, db: FakeDb) -> None:
        """A different session_id creates a new, empty chat."""
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
        chats = db.chats_of(TEST_MEMBER_ID)
        assert sorted(chat["legacy_session_id"] for chat in chats) == ["sess1", "sess2"]
        assert {call["session_id"] for call in agent.run_calls} == {
            str(chat["id"]) for chat in chats
        }


class TestChatSessionsArePerUser:
    """Each user has their own persisted chat per session id (GH-149, GH-176).

    Chat session ids are client-generated until #177. With several users logged
    in, user B reusing user A's session_id gets B's own chat: B neither reads
    nor changes A's stored messages, and B can't confirm, deny or cancel A's
    pending tool call (held in ``server._chat_runtime`` under A's chat id).
    """

    pytestmark = pytest.mark.asyncio

    async def test_server_same_session_id_gives_each_user_their_own_chat(self, db: FakeDb) -> None:
        """The legacy chat is keyed by (owner, session id): two users, two chats."""
        agent = FakeAgent([_turn("a", "a-reply"), _turn("b", "b-reply")])
        app = _make_app(agent, session=member_session("editor"))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "a", "session_id": "shared"})
            login(app, member_session("editor", user_id=_OTHER_USER_ID))
            await c.post("/api/message", json={"message": "b", "session_id": "shared"})

        chat_a = _legacy_chat(db, "shared", TEST_MEMBER_ID)
        chat_b = _legacy_chat(db, "shared", _OTHER_USER_ID)
        assert chat_a["id"] != chat_b["id"]
        assert (chat_a["owner_user_id"], chat_b["owner_user_id"]) == (
            TEST_MEMBER_ID,
            _OTHER_USER_ID,
        )
        assert [call["session_id"] for call in agent.run_calls] == [
            str(chat_a["id"]),
            str(chat_b["id"]),
        ]

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

    async def test_server_other_user_does_not_overwrite_history(self, db: FakeDb) -> None:
        """B's turn on the same session_id leaves A's stored chat and messages intact."""
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
            chat_a = _legacy_chat_id(db, "shared", TEST_MEMBER_ID)
            a_before = (db.chat_row(chat_a), db.messages_of(chat_a))
            login(app, member_session("editor", user_id=_OTHER_USER_ID))
            await c.post("/api/message", json={"message": "b", "session_id": "shared"})
            a_after_b = (db.chat_row(chat_a), db.messages_of(chat_a))
            login(app, member_session("editor"))
            await c.post("/api/message", json={"message": "a2", "session_id": "shared"})

        assert a_after_b == a_before
        assert agent.run_calls[2]["history"] == history_a
        assert _rows(db, _legacy_chat_id(db, "shared", _OTHER_USER_ID)) == [("user", "b-msg")]

    @pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
    async def test_server_other_user_cannot_confirm_a_pending_call(
        self, db: FakeDb, approved: bool
    ) -> None:
        """B can't resolve (approve or deny) A's pending confirmation: the same 404 as
        for no pending one, A's stays pending with A's chat untouched, B gets no chat
        (the confirm route never creates one), and A can still approve it."""
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
            chat_a = _legacy_chat_id(db, "shared", TEST_MEMBER_ID)
            a_before = db.messages_of(chat_a)
            login(app, member_session("editor", user_id=_OTHER_USER_ID))
            stolen = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={**confirm_body, "approved": approved},
            )
            assert (stolen.status_code, stolen.json()) == (
                404,
                {"detail": "No pending confirmation for this session"},
            )
            assert len(agent.run_calls) == 1
            assert _runtime().get_pending(chat_a) == pending
            assert db.messages_of(chat_a) == a_before
            assert db.chats_of(_OTHER_USER_ID) == []

            login(app, member_session("editor"))
            own = await c.post(f"/api/confirm/{pending.confirmation_id}", json=confirm_body)

        assert own.status_code == 200
        assert agent.run_calls[1]["pending_confirmation"] is not None

    async def test_server_other_users_message_does_not_cancel_a_pending_call(
        self, db: FakeDb
    ) -> None:
        """B's message on the same session_id doesn't drop A's pending confirmation."""
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
            resp = await c.post("/api/message", json={"message": "hi", "session_id": "shared"})

        assert resp.status_code == 200
        assert _runtime().get_pending(_legacy_chat_id(db, "shared", TEST_MEMBER_ID)) == pending


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

    @pytest.mark.parametrize(
        "removed",
        [
            "_sessions",
            "_pending_confirmations",
            "_session_locks",
            "_MAX_SESSIONS",
            "_chat_key",
            "_get_session_lock",
            "_touch_session",
        ],
    )
    def test_server_in_memory_chat_state_removed(self, removed: str) -> None:
        """GH-176: no in-memory chat histories; locks and pending confirmations moved
        into the bounded ``_chat_runtime``."""
        import admino.server as server_module

        assert not hasattr(server_module, removed)
        assert hasattr(server_module, "_chat_runtime")

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

    async def test_server_create_app_clears_the_chat_runtime_and_keeps_persisted_chats(
        self, db: FakeDb
    ) -> None:
        """create_app is a restart (GH-176): the chat runtime (run locks, pending
        confirmations) starts empty, the persisted chat and its messages stay."""
        pending, awaiting = _awaiting_confirmation()
        agent = FakeAgent([awaiting, _make_agent_result()])
        config = _make_config()
        app1 = _make_app(agent, config=config)

        # Post a message that leaves a pending confirmation on the chat
        async with AsyncClient(transport=ASGITransport(app=app1), base_url="http://test") as c:
            await c.post(
                "/api/message",
                json={"message": "create", "session_id": "sess1"},
            )
        chat_id = _legacy_chat_id(db, "sess1")
        assert _runtime().get_pending(chat_id) == pending
        stored = db.messages_of(chat_id)

        # Create a new app — the runtime is cleared, the chat isn't
        create_app(agent=agent, config=config)
        assert len(_runtime()) == 0
        assert _runtime().get_pending(chat_id) is None
        assert db.messages_of(chat_id) == stored
        assert _legacy_chat_id(db, "sess1") == chat_id

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

    async def test_server_confirm_denied_removes_pending(self, db: FakeDb) -> None:
        """After denial, the chat's pending confirmation is removed from the runtime."""
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
            chat_id = _legacy_chat_id(db, "sess1")
            assert _runtime().get_pending(chat_id) == pending
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": False,
                },
            )
        # Pending should be cleared
        assert resp.status_code == 200
        assert _runtime().get_pending(chat_id) is None

    async def test_server_confirm_denied_persists_the_closing_tool_results_and_the_denial(
        self, db: FakeDb
    ) -> None:
        """GH-176: a denial appends, after the awaiting turn, one ``tool`` result per
        dangling ``tool_use`` block ("Tool call denied by the user." for the pending
        call, the cancelled text for any other) and then the assistant's denial, all
        ``complete`` without tool calls, so the stored history stays well-formed."""
        from admino.server import _CANCELLED_TOOL_RESULT_MSG

        pending = _make_pending_confirmation(session_id="sess1", tool_call_id="call_pending_2")
        awaiting_history = [
            LLMMessage(role="user", content="book it"),
            LLMMessage(
                role="assistant",
                content="",
                tool_use_blocks=[
                    {
                        "type": "tool_use",
                        "id": "call_other_1",
                        "name": "calendar.list",
                        "input": {},
                    },
                    {
                        "type": "tool_use",
                        "id": "call_pending_2",
                        "name": "calendar.create",
                        "input": {},
                    },
                ],
            ),
        ]
        awaiting_result = _make_agent_result(
            status="awaiting_confirmation",
            response="Requires confirmation.",
            history=awaiting_history,
            pending_confirmation=pending,
        )
        agent = FakeAgent([awaiting_result])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await c.post("/api/message", json={"message": "book it", "session_id": "sess1"})
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": False,
                },
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "final"
        rows = db.messages_of(_legacy_chat_id(db, "sess1"))
        assert [row["role"] for row in rows] == ["user", "assistant", "tool", "tool", "assistant"]
        assert {row["tool_call_id"]: row["content"] for row in rows[2:4]} == {
            "call_pending_2": "Tool call denied by the user.",
            "call_other_1": _CANCELLED_TOOL_RESULT_MSG,
        }
        assert rows[4]["content"] == "Action calendar.create was denied."
        assert [(row["status"], row["tool_calls"]) for row in rows[2:]] == [("complete", None)] * 3

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
        self, db: FakeDb
    ) -> None:
        """When the agent is awaiting confirmation, POST /api/message must
        return ``status='awaiting_confirmation'`` plus a ``pending_confirmation``
        summary carrying the confirmation_id, tool, and action. Without these
        fields the PWA has no way to render its Approve/Deny card. GH-176: the
        response names the chat, whose runtime entry holds the pending call.
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
        chat_id = _legacy_chat_id(db, "sess1")
        assert (data["chat_id"], data["session_id"]) == (str(chat_id), "sess1")
        assert _runtime().get_pending(chat_id) == pending

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

    async def test_server_new_message_during_pending_closes_tool_use(self, db: FakeDb) -> None:
        """Regression: sending a freeform /api/message while a confirmation is
        pending must (a) cancel the pending confirmation and (b) append a
        synthetic cancelled tool_result so the history handed to the next
        agent.run() does not leave a ``tool_use`` dangling — which would
        otherwise make Anthropic reject the next LLM call with HTTP 400.
        GH-176: the pending confirmation lives in the chat's runtime entry, and the
        synthetic result is stored with the turn, so the persisted history stays
        well-formed for every later load.
        """
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
            chat_id = _legacy_chat_id(db, "sess1")
            assert _runtime().get_pending(chat_id) == pending

            # Turn 2: user sends a new chat message instead of calling
            # /api/confirm/{id}. Must succeed (no 500) and the pending
            # confirmation must have been cleared.
            resp = await c.post(
                "/api/message",
                json={"message": "I confirm it!", "session_id": "sess1"},
            )

        assert resp.status_code == 200
        assert _runtime().get_pending(chat_id) is None

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
        stored = db.messages_of(chat_id)
        assert [(row["role"], row["tool_call_id"]) for row in stored[:3]] == [
            ("user", None),
            ("assistant", None),
            ("tool", "toolu_abc123"),
        ]
        assert "cancelled" in stored[2]["content"].lower()

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


class TestChatRuntimeBound:
    """GH-176: chat histories are persisted, not capped in memory (``_MAX_SESSIONS`` is gone).

    What stays in memory is ``server._chat_runtime``: one bounded ``ChatRuntime``
    (run locks and pending confirmations per chat, at most
    ``_MAX_CHAT_RUNTIME_ENTRIES`` entries, idle ones evicted after
    ``_CHAT_IDLE_EVICT_S``). Its own eviction rules are unit-tested in
    tests/test_chat_runtime.py.
    """

    pytestmark = pytest.mark.asyncio

    async def test_server_chat_runtime_bound_constants(self) -> None:
        import admino.server as srv

        assert (srv._MAX_CHAT_RUNTIME_ENTRIES, srv._CHAT_IDLE_EVICT_S) == (1024, 900.0)

    async def test_server_chat_runtime_is_one_chat_runtime(self) -> None:
        from admino.chat_runtime import ChatRuntime

        assert isinstance(_runtime(), ChatRuntime)

    async def test_server_evicted_runtime_entry_never_loses_history(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a runtime of two entries, five chats later the first chat's run still
        gets its whole stored history (eviction drops only locks and pending calls)."""
        import admino.server as srv
        from admino.chat_runtime import ChatRuntime

        results = [_turn("hi", f"reply-{i}") for i in range(5)] + [_turn("again", "back")]
        agent = FakeAgent(results)
        app = _make_app(agent)
        monkeypatch.setattr(srv, "_chat_runtime", ChatRuntime(max_entries=2, idle_s=900.0))

        # The rate limiter (burst 5) is not under test here.
        with patch("admino.server._check_rate_limit"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                for i in range(5):
                    await c.post(
                        "/api/message",
                        json={"message": "hi", "session_id": f"sess{i}"},
                    )
                resp = await c.post(
                    "/api/message",
                    json={"message": "again", "session_id": "sess0"},
                )

        assert resp.status_code == 200
        assert len(srv._chat_runtime) <= 2
        assert agent.run_calls[5]["session_id"] == str(_legacy_chat_id(db, "sess0"))
        assert _pairs(agent.run_calls[5]["history"]) == [("user", "hi"), ("assistant", "reply-0")]
        assert len(db.chats_of(TEST_MEMBER_ID)) == 5


class TestConfirmationExpiry:
    """H-2/M-3: Expired confirmations are reaped and rejected (GH-176: in the chat runtime)."""

    pytestmark = pytest.mark.asyncio

    async def test_server_expired_confirmation_reaped_returns_404(self, db: FakeDb) -> None:
        """Expired confirmations are reaped unconditionally at entry, returning 404.

        The unconditional reap (``_chat_runtime.reap_expired``) at the top of
        post_confirm removes expired entries before the per-chat lookup.
        Since GH-24 a confirmation that expires in the narrow window between
        the reap and the expiry check under the chat's lock answers the same 404.
        """
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)

        # Manually store the expired pending on the caller's legacy chat
        # (bypassing normal flow)
        chat_id = db.add_chat(TEST_MEMBER_ID, legacy_session_id="sess1")
        db.add_chat_message(chat_id, "user", "hi")
        pending = _make_pending_confirmation(session_id=str(chat_id), expired=True)
        _runtime().set_pending(chat_id, TEST_MEMBER_ID, pending)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                f"/api/confirm/{pending.confirmation_id}",
                json={
                    "session_id": "sess1",
                    "confirmation_id": pending.confirmation_id,
                    "approved": True,
                },
            )
        # Expired entry is reaped before lookup, so 404 (there is no 410 since GH-24).
        assert (resp.status_code, resp.json()) == (
            404,
            {"detail": "No pending confirmation for this session"},
        )
        assert _runtime().get_pending(chat_id) is None
        assert agent.run_calls == []

    async def test_server_reap_removes_expired_before_lookup(self, db: FakeDb) -> None:
        """Expired confirmations are reaped before any lookup."""
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)

        expired_chat = db.add_chat(TEST_MEMBER_ID, legacy_session_id="sess-expired")
        expired_pending = _make_pending_confirmation(session_id=str(expired_chat), expired=True)
        _runtime().set_pending(expired_chat, TEST_MEMBER_ID, expired_pending)

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
        assert _runtime().get_pending(expired_chat) is None


def _stored_max_message_length(monkeypatch: pytest.MonkeyPatch, max_length: int) -> None:
    """Store a platform max_message_length in the settings cache (GH-160)."""
    stored = default_test_platform_settings()
    limits = stored.limits.model_copy(update={"max_message_length": max_length})
    monkeypatch.setattr(
        scoped_settings, "_platform_cache", stored.model_copy(update={"limits": limits})
    )


class TestMaxMessageLength:
    """L-5: the stored platform max_message_length is enforced.

    GH-160: the limit is read per request through the platform settings cache,
    not from config.limits once at startup.
    """

    pytestmark = pytest.mark.asyncio

    async def test_server_message_exceeds_config_max_length_returns_422(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Message longer than the stored max_message_length -> 422."""
        _stored_max_message_length(monkeypatch, 100)
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/message",
                json={"message": "x" * 101, "session_id": "sess1"},
            )
        assert resp.status_code == 422
        assert "maximum length" in resp.json()["detail"].lower()

    async def test_server_message_within_config_max_length_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Message within the stored limit succeeds."""
        _stored_max_message_length(monkeypatch, 100)
        agent = FakeAgent([_make_agent_result()])
        app = _make_app(agent)

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


# GH-176: ChatResponse requires the chat's id.
_SANITISATION_CHAT_ID = UUID("7c1d2e3f-4a5b-4c6d-8e7f-90a1b2c3d4e5")
# GH-190 (Decision 4): ChatResponse requires the chat's context usage.
_SANITISATION_USAGE: dict[str, int] = {"used": 1200, "max": 9000, "percent": 13}


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
            chat_id=_SANITISATION_CHAT_ID,
            session_id="test",
            context_usage=_SANITISATION_USAGE,
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
            chat_id=_SANITISATION_CHAT_ID,
            session_id="test",
            context_usage=_SANITISATION_USAGE,
            response="The token is Bearer sk-proj-abcdefghijklmnopqrstuvwxyz123",
            tool_calls=[],
        )
        assert "sk-proj-" not in resp.response
        assert "[CREDENTIAL_REDACTED]" in resp.response

    async def test_server_response_control_chars_stripped(self) -> None:
        """Unicode direction overrides in LLM response are stripped."""
        from admino.models import ChatResponse

        resp = ChatResponse(
            chat_id=_SANITISATION_CHAT_ID,
            session_id="test",
            context_usage=_SANITISATION_USAGE,
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
    # GH-159: the settings scopes, per user (the old /api/settings keys are gone).
    ("/api/me/settings/get", 1.0, 10),
    ("/api/me/settings/patch", 0.5, 5),
    # GH-35: reset the caller's own settings, per user.
    ("/api/me/settings/reset", 0.2, 3),
    ("/api/org/settings/get", 1.0, 10),
    ("/api/org/settings/patch", 0.5, 5),
    ("/api/platform/settings/get", 1.0, 10),
    ("/api/platform/settings/patch", 0.2, 5),
    # GH-161: the Org Admin's matrix and the members' read-only summary (the old
    # /api/permissions/* and /api/critical-permissions/* keys are gone).
    ("/api/org/permissions/get", 1.0, 5),
    ("/api/org/permissions/patch", 0.2, 2),
    ("/api/permissions/summary/get", 1.0, 10),
    ("/api/oauth/google/authorize", 0.2, 2),
    ("/api/oauth/microsoft/authorize", 0.2, 2),
    ("/api/oauth/callback", 0.2, 2),
    ("/api/oauth/google/status", 1.0, 5),
    ("/api/oauth/microsoft/status", 1.0, 5),
    ("/api/oauth/google/disconnect", 0.2, 2),
    ("/api/oauth/microsoft/disconnect", 0.2, 2),
    ("/api/org/critical-permissions/get", 1.0, 5),
    ("/api/org/critical-permissions/promote", 5 / 60, 5),
    ("/api/org/critical-permissions/cancel", 0.5, 5),
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
# F-10: Per-chat run locks (GH-176: in the chat runtime)
# ---------------------------------------------------------------------------


def _recording_runtime(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Swap ``server._chat_runtime`` for a ChatRuntime that records each ``hold`` (GH-176).

    Same bound as the server's; ``held`` lists ``(chat_id, owner_user_id)`` per
    ``hold()`` call, recorded when the call is made (before it waits, or refuses a
    busy chat: GH-8's ``wait`` keyword is passed through). Call it after ``_make_app``
    (``create_app`` clears the runtime).
    """
    import admino.server as srv
    from admino.chat_runtime import ChatRuntime

    class _RecordingRuntime(ChatRuntime):
        def __init__(self) -> None:
            super().__init__(
                max_entries=srv._MAX_CHAT_RUNTIME_ENTRIES, idle_s=srv._CHAT_IDLE_EVICT_S
            )
            self.held: list[tuple[UUID, UUID]] = []

        def hold(self, chat_id: UUID, owner_user_id: UUID, **kwargs: Any) -> Any:
            self.held.append((UUID(str(chat_id)), UUID(str(owner_user_id))))
            return super().hold(chat_id, owner_user_id, **kwargs)

    runtime = _RecordingRuntime()
    monkeypatch.setattr(srv, "_chat_runtime", runtime)
    return runtime


class _ParkingAgent(FakeAgent):
    """A FakeAgent whose FIRST run parks until ``release`` is set; counts overlapping runs."""

    def __init__(self, results: list[AgentResult]) -> None:
        super().__init__(results)
        self.release = asyncio.Event()
        self.first_entered = asyncio.Event()
        self.started: list[str] = []
        self.active = 0
        self.max_active = 0

    async def run(self, user_message: str, session_id: str, **kwargs: Any) -> AgentResult:
        self.started.append(user_message)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if len(self.started) == 1:
                self.first_entered.set()
                await asyncio.wait_for(self.release.wait(), timeout=5)
            return await super().run(user_message, session_id, **kwargs)
        finally:
            self.active -= 1


class _BarrierAgent(FakeAgent):
    """A FakeAgent whose runs wait (at most 5 s) until ``parties`` runs have started."""

    def __init__(self, results: list[AgentResult], *, parties: int) -> None:
        super().__init__(results)
        self._parties = parties
        self._arrived = 0
        self._all_in = asyncio.Event()
        self.timed_out = False

    async def run(self, user_message: str, session_id: str, **kwargs: Any) -> AgentResult:
        self._arrived += 1
        if self._arrived >= self._parties:
            self._all_in.set()
        try:
            await asyncio.wait_for(self._all_in.wait(), timeout=5)
        except TimeoutError:
            self.timed_out = True
        return await super().run(user_message, session_id, **kwargs)


class TestChatRunLocks:
    """GH-176: runs of one chat go through ``server._chat_runtime.hold``.

    GH-8: two messages to the same legacy chat never run at once, and the second
    one never waits either: while the first still runs it is ``409 run_active``
    (no run, nothing stored). Messages to different chats run concurrently. The
    run locks live in the bounded chat runtime (``create_app`` clearing it is
    pinned in TestAppFactory).
    """

    pytestmark = pytest.mark.asyncio

    async def test_server_message_to_a_chat_whose_run_is_going_gets_409_run_active(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """m2, sent to the legacy chat while m1's run is parked, answers 409 at once (before
        m1 is released): it never runs and stores nothing; m1 completes and is stored."""
        agent = _ParkingAgent([_turn("m1", "first"), _turn("m2", "second")])
        app = _make_app(agent)
        runtime = _recording_runtime(monkeypatch)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            first = asyncio.create_task(
                c.post("/api/message", json={"message": "m1", "session_id": "sess1"})
            )
            await asyncio.wait_for(agent.first_entered.wait(), timeout=5)
            second = asyncio.create_task(
                c.post("/api/message", json={"message": "m2", "session_id": "sess1"})
            )

            async def second_held_or_answered() -> None:
                while len(runtime.held) < 2 and not second.done():
                    await asyncio.sleep(0.001)

            await asyncio.wait_for(second_held_or_answered(), timeout=5)
            started_while_first_ran = list(agent.started)
            agent.release.set()
            responses = await asyncio.gather(first, second)

        assert [resp.status_code for resp in responses] == [200, 409]
        assert responses[1].json() == {
            "detail": "A message is already running in this chat.",
            "reason": "run_active",
        }
        assert started_while_first_ran == ["m1"]
        assert agent.started == ["m1"]
        chat_id = _legacy_chat_id(db, "sess1")
        assert _rows(db, chat_id) == [("user", "m1"), ("assistant", "first")]
        assert runtime.held == [(chat_id, TEST_MEMBER_ID)] * 2

    async def test_server_messages_to_different_chats_run_concurrently(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A serialising implementation would make the first run wait out the 5 s barrier."""
        agent = _BarrierAgent([_turn("a", "a-reply"), _turn("b", "b-reply")], parties=2)
        app = _make_app(agent)
        runtime = _recording_runtime(monkeypatch)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            responses = await asyncio.gather(
                c.post("/api/message", json={"message": "a", "session_id": "sess-a"}),
                c.post("/api/message", json={"message": "b", "session_id": "sess-b"}),
            )

        assert [resp.status_code for resp in responses] == [200, 200]
        assert agent.timed_out is False
        assert sorted(runtime.held) == sorted(
            [
                (_legacy_chat_id(db, "sess-a"), TEST_MEMBER_ID),
                (_legacy_chat_id(db, "sess-b"), TEST_MEMBER_ID),
            ]
        )


# ---------------------------------------------------------------------------
# GH-140: system prompt must not be duplicated across turns (real Agent)
# ---------------------------------------------------------------------------

_GH140_SESSION = "sess-gh140"
# GH-170: the agent has no static prompt any more; each run's system message is
# prompt_assembly.system_prompt(<the run's prompt context>, tools=<its advertised
# tools>, now=<one clock reading>). The injected clock is fixed, so the expected
# message (ending with this date line) is exact.
_GH140_NOW = datetime(2026, 10, 4, 17, 5, tzinfo=UTC)
_GH140_DATE_LINE = "Current date and time: Sunday, 2026-10-04 19:05 (Europe/Zurich, UTC+02:00)."
_GH140_ECHO_WRITE_LINE = "You have access to the following tools: echo (write)."


def _gh140_system(context: PromptContext | None = None, *, echo_write: bool = False) -> str:
    """The system message of a run: ``prompt_assembly.system_prompt`` over ``context``
    (default ``PromptContext()``, what the stubbed load returns), the advertised tools
    (none, or echo.write, which the stubbed org policy sets to confirm) and the fixed
    clock."""
    from admino.models import PromptContext
    from admino.prompt_assembly import system_prompt

    tools = (
        [
            ToolDescription(
                tool="echo",
                action="write",
                description="Write echo",
                parameters_schema=_EchoArgs.model_json_schema(),
            )
        ]
        if echo_write
        else []
    )
    return system_prompt(
        context if context is not None else PromptContext(), tools=tools, now=_GH140_NOW
    )


class _RecordingLLM:
    """Scripted LLM stand-in that records every context window it receives."""

    provider = "infomaniak"

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


async def _echo_handler(args: _EchoArgs, *, session_id: str, **_: object) -> str:
    return f"echo:{args.text}"


def _system_pairs(messages: list[LLMMessage]) -> list[tuple[str, str]]:
    """Return ``(role, content)`` for every system message in ``messages``."""
    return [(m.role, m.content) for m in messages if m.role == "system"]


class TestSystemPromptNotDuplicatedAcrossTurns:
    """GH-140: the server round-trips history without duplicating the system prompt.

    Uses a REAL ``admino.agent.Agent`` (only the LLM is faked) so the
    server's store-and-replay of ``result.history`` is exercised end to end
    (GH-176: through the persisted chat, a FakeDb here, instead of
    ``_sessions``). Before the fix, every turn stored the agent's system
    prompt in the session and the next turn prepended it again. GH-170: the
    system message is the assembled one (``_gh140_system``) built from the
    prompt context the route loaded for that request, with a fixed clock.
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
        """GH-161: no permission state on the agent; each run gets the org policy the
        ``org_tool_policy`` stub loads (echo.write = confirm). GH-170: no
        ``system_prompt`` (removed); the clock is fixed at ``_GH140_NOW``."""
        return Agent(
            llm_client=llm,  # type: ignore[arg-type]
            tool_call_recorder=tool_call_recorder,
            agent_config=AgentConfig(
                max_tool_calls=5,
                max_context_messages=20,
                confirmation_timeout_s=60.0,
            ),
            clock=lambda: _GH140_NOW,
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
        expected = _gh140_system()

        assert statuses == [200] * 25
        assert len(llm.received_messages) == 25
        for i, call in enumerate(llm.received_messages):
            assert _system_pairs(call) == [("system", expected)], f"turn {i}"
            assert call[0].role == "system", f"turn {i}"
            assert call[0].content.splitlines()[-1] == _GH140_DATE_LINE, f"turn {i}"

    async def test_server_message_each_turn_sends_its_loaded_prompt_context(
        self, tool_call_recorder: AsyncMock, prompt_context_loader: AsyncMock
    ) -> None:
        """GH-170 end to end: the context the route loads for a request is the one in
        that turn's system message, so a changed setting applies to the next turn."""
        first = _prompt_context(
            org_instructions="Sign every answer with: the team.",
            response_language="fr",
            timezone="Asia/Kolkata",
        )
        second = _prompt_context(
            personal_instructions="Use bullet points.", default_response_language="it"
        )
        prompt_context_loader.side_effect = [first, second]

        llm, statuses = await self._post_turns(tool_call_recorder, turns=2)

        assert statuses == [200, 200]
        assert [_system_pairs(call) for call in llm.received_messages] == [
            [("system", _gh140_system(first))],
            [("system", _gh140_system(second))],
        ]

    async def test_server_message_25_turns_each_llm_call_ends_with_posted_message(
        self, tool_call_recorder: AsyncMock
    ) -> None:
        llm, _ = await self._post_turns(tool_call_recorder)

        assert len(llm.received_messages) == 25
        for i, call in enumerate(llm.received_messages):
            assert (call[-1].role, call[-1].content) == ("user", f"turn-{i}"), f"turn {i}"

    async def test_server_message_25_turns_session_history_has_no_system_messages(
        self, tool_call_recorder: AsyncMock, db: FakeDb
    ) -> None:
        """GH-176: the chat stores the 50 user/assistant messages, never a system one."""
        await self._post_turns(tool_call_recorder)

        stored = _rows(db, _legacy_chat_id(db, _GH140_SESSION))
        assert [role for role, _ in stored if role == "system"] == []
        assert len(stored) == 50
        assert stored[:2] == [("user", "turn-0"), ("assistant", "reply-0")]
        assert stored[-2:] == [("user", "turn-24"), ("assistant", "reply-24")]

    async def test_server_confirm_resume_llm_call_has_one_system_prompt(
        self, tool_call_recorder: AsyncMock, db: FakeDb
    ) -> None:
        """POST /api/message -> awaiting confirmation -> POST /api/confirm (approve).

        GH-176: the resume runs on the persisted chat (the real agent's pending
        confirmation names ``str(chat.id)``, which the resumed run must match), and
        the chat stores the paired turns without a system message.
        """
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
        first_call, resume_call = llm.received_messages
        expected = _gh140_system(echo_write=True)
        assert _GH140_ECHO_WRITE_LINE in expected
        assert _system_pairs(first_call) == [("system", expected)]
        assert _system_pairs(resume_call) == [("system", expected)]
        assert resume_call[0].role == "system"
        stored = db.messages_of(_legacy_chat_id(db, _GH140_SESSION))
        assert [row["role"] for row in stored] == ["user", "assistant", "tool", "assistant"]
        assert stored[1]["tool_use_blocks"][0]["id"] == "call_write_1"
        assert stored[2]["tool_call_id"] == "call_write_1"
        assert stored[3]["content"] == "Written."

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

    async def test_server_tool_call_recorder_receives_the_chat_id(
        self, tool_call_recorder: AsyncMock, db: FakeDb
    ) -> None:
        """GH-176 end to end: every tool-call record of the message and of the approved
        resume names the legacy chat's id (``tool.call`` rows target the real chat)."""
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
        chat_id = _legacy_chat_id(db, _GH140_SESSION)
        assert [call.kwargs["session_id"] for call in tool_call_recorder.await_args_list] == [
            str(chat_id),
            str(chat_id),
        ]
