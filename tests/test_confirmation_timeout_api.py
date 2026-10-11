"""Spec of the confirmation timeout end to end (GH-24, contract sections 4 to 6).

A pending confirmation lives in memory (``server._chat_runtime``) and expires
``confirmation_timeout_s`` seconds (the stored platform limit, default 300) after it
was created. An expired one is treated as a denial: it is never dispatched, the chat
shows it as ``expired`` and confirming it is the plain 404 (never 410). Expired
confirmations are reaped at the start of every chat request and by a background task
every 30 seconds, which takes no chat lock and touches no database.

What is pinned:

1. Timeout calculation: ``agent._build_pending_confirmation`` and the real
   ``Agent.run`` with ``AgentConfig(confirmation_timeout_s=T)`` give
   ``expires_at - created_at == timedelta(seconds=T)`` exactly (fractional T too),
   ``created_at`` UTC-aware and taken during the call. A turn runs with the stored
   ``confirmation_timeout_s`` (300.0 by default), and a changed stored value applies to
   the next request (guards: GH-160 already does this).
2. Clock seam: ``server._utc_now()`` is the aware current UTC time and the only clock of
   the reap and of POST /api/confirm's expiry check; ``now >= expires_at`` is expired
   (exactly at ``expires_at`` expired, one microsecond before not).
3. ``server._reap_expired_confirmations`` is a plain function that drops only the
   expired pending confirmations, of every user and org, and completes while another
   task holds that chat's lock.
4. Background reaper: ``server._CONFIRMATION_REAP_INTERVAL_S == 30.0``;
   ``server._run_confirmation_reaper()`` sleeps the interval (read at call time), then
   reaps, repeatedly, without any request, any lock wait or any query; a failing pass
   is logged at WARNING by class name only and the loop goes on; cancelling ends it; a
   pass reaps another chat while a turn is running and the turn then finishes. The app
   lifespan starts it in its own task after the pool exists and cancels it before the
   pool closes.
5. End to end (integration criterion): a turn awaits a confirmation; past
   ``expires_at`` GET /api/chats/{id} answers ``confirmation_status: "expired"`` with
   ``pending_confirmation: null`` and the stored messages unchanged; approving or
   denying it, by ``chat_id`` or by the legacy ``session_id``, is 404
   ``{"detail": "No pending confirmation for this session"}`` with no run, nothing
   stored and nothing left in the runtime; the same when only the background reaper
   dropped it. With the real agent the approved call is never dispatched (the fake
   handler isn't called, no further ``tool.call`` audit row, no LLM call).
6. Race: a confirmation that expires while the request waits for the chat's lock (after
   the request's reap kept it) is the same 404, popped, with no run and nothing stored;
   so is one the reap missed (no 410 anywhere).
7. The next message after an expiry: the run gets the history with every dangling
   ``tool_use`` closed by ``server._CANCELLED_TOOL_RESULT_MSG`` right after its
   results, the turn is 200 and the stored history is well-formed (contract section 6,
   ``_assert_well_formed``).
8. Tracker section 5: the logs of these flows carry no message content, tool argument
   or confirmation id.

New names (``server._utc_now``, ``server._run_confirmation_reaper``,
``server._CONFIRMATION_REAP_INTERVAL_S``) are used lazily, so this file collects
before GH-24 and each test fails on its own.

Security notes:
- Every message, argument, id and session value here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM, no real sleep for a timeout: time moves
  through ``server._utc_now``; every wait is bounded.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic import BaseModel, Field

from admino import main as main_module
from admino import scoped_settings, server
from admino.access import Principal
from admino.agent import Agent, _build_pending_confirmation
from admino.chat_runtime import ChatRuntime
from admino.llm import LLMResponse
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
    ToolPolicy,
)
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.server import _lifespan, create_app
from admino.tools import registry
from tests.conftest import default_test_platform_settings
from tests.db_fakes import FakeDb
from tests.lifespan_stubs import patch_login_throttle_purge_job
from tests.tenancy_world import (
    CLIENT_IP,
    build_world,
    make_app,
    make_client,
    make_config,
    stub_agent,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator, Sequence

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WAIT_S: Final = 5.0
_REAL_SLEEP: Final = asyncio.sleep

_NO_PENDING: Final = {"detail": "No pending confirmation for this session"}
_DENIED_RESULT: Final = "Tool call denied by the user."
_DENIAL_REPLY: Final = "Action google_calendar.create was denied."

_CONFIRMATION_ID: Final = "confirm-24-wren"
_LEGACY_SESSION: Final = "legacy-24-sandpiper"
_MESSAGE: Final = "Book the team sync"
_NEXT_MESSAGE: Final = "What is on my agenda?"
_STUB_REPLY: Final = "Done."
_FINAL_REPLY: Final = "All done."

# The stored platform confirmation_timeout_s of the default test settings.
_DEFAULT_TIMEOUT: Final = timedelta(seconds=300)
# A fixed instant far from the real clock: only the patched server clock reaches it.
_FAR: Final = datetime(2031, 3, 1, 9, 0, tzinfo=UTC)
_MICROSECOND: Final = timedelta(microseconds=1)

# Log canaries (section 8): content, tool arguments and confirmation ids.
_MESSAGE_CANARY: Final = "TIMEOUT-MSG-24-plover"
_NEXT_CANARY: Final = "TIMEOUT-NEXT-24-turnstone"
_ARG_CANARY: Final = "TIMEOUT-ARG-24-dunlin"
_ID_CANARY: Final = "confirm-24-canary-godwit"
_REAPER_CANARY: Final = "REAPER-FAILURE-24-knot"

_PENDING_CALL: Final = ToolCall(
    tool="google_calendar",
    action="create",
    args={"title": "Team sync"},
    tool_call_id="call-t24",
)
_ANSWERED_CALL: Final = ToolCall(
    tool="memory", action="recall", args={"key": "agenda"}, tool_call_id="call-a24"
)
_UNRUN_CALL: Final = ToolCall(tool="memory", action="list", args={}, tool_call_id="call-u24")

# The member of the unit-level Agent.run test (no database involved).
_PRINCIPAL: Final = Principal(
    user_id=uuid.UUID("24242424-2424-4424-8424-242424242424"),
    kind="member",
    org_id=uuid.UUID("24242424-0000-4000-8000-000000000024"),
    role="editor",
)

# ---------------------------------------------------------------------------
# Messages and stored rows
# ---------------------------------------------------------------------------


def _user(content: str) -> LLMMessage:
    return LLMMessage(role="user", content=content)


def _assistant(content: str) -> LLMMessage:
    return LLMMessage(role="assistant", content=content)


def _block(call: ToolCall) -> dict[str, Any]:
    """The tool_use block the agent stores for ``call``."""
    return {
        "type": "tool_use",
        "id": call.tool_call_id,
        "name": f"{call.tool}.{call.action}",
        "input": dict(call.args),
    }


def _tool_use(*calls: ToolCall) -> LLMMessage:
    """An assistant turn asking for ``calls``."""
    return LLMMessage(role="assistant", content="", tool_use_blocks=[_block(c) for c in calls])


def _tool(content: str, call: ToolCall) -> LLMMessage:
    """The tool result answering ``call``."""
    return LLMMessage(role="tool", content=content, tool_call_id=call.tool_call_id)


def _cancelled(call: ToolCall) -> LLMMessage:
    """The existing synthetic result closing a dangling ``call``."""
    return _tool(server._CANCELLED_TOOL_RESULT_MSG, call)


def _dump(messages: Any) -> list[dict[str, Any]]:
    return [message.model_dump() for message in messages]


Row = tuple[str, str, str | None, list[dict[str, Any]] | None, str]


def _row(message: LLMMessage, status: str = "complete") -> Row:
    """How a stored chat_messages row of ``message`` reads (role, content, tool ids, status)."""
    return (
        message.role,
        message.content,
        message.tool_call_id,
        message.tool_use_blocks,
        status,
    )


def _rows(*messages: LLMMessage, last: str = "complete") -> list[Row]:
    """The rows of ``messages`` stored by one turn: the last one with status ``last``."""
    return [
        _row(message, last if index == len(messages) - 1 else "complete")
        for index, message in enumerate(messages)
    ]


def _stored(db: FakeDb, chat_id: uuid.UUID) -> list[Row]:
    """The chat's stored messages by seq, as ``_row`` tuples."""
    return [
        (m["role"], m["content"], m["tool_call_id"], m["tool_use_blocks"], m["status"])
        for m in db.messages_of(chat_id)
    ]


def _shape(message: LLMMessage | dict[str, Any]) -> tuple[str, list[str], str | None, str]:
    """(role, tool_use block ids, tool_call_id, status) of a message or a stored row."""
    if isinstance(message, LLMMessage):
        blocks, status = message.tool_use_blocks, "complete"
        role, call_id = message.role, message.tool_call_id
    else:
        blocks, status = message["tool_use_blocks"], message["status"]
        role, call_id = message["role"], message["tool_call_id"]
    return role, [str(block.get("id")) for block in blocks or []], call_id, status


def _assert_well_formed(messages: Sequence[LLMMessage | dict[str, Any]]) -> None:
    """Contract section 6: every assistant message with n tool_use blocks is directly
    followed by exactly n ``tool`` messages answering the blocks' ids in block order (no
    user/assistant message in between), and no ``tool`` message answers nothing. Only
    the very end of a chat whose latest message is ``awaiting_confirmation`` may hold the
    calls with a prefix of their results."""
    shaped = [_shape(message) for message in messages]
    awaiting_at_end = bool(shaped) and shaped[-1][3] == "awaiting_confirmation"
    answered: set[int] = set()
    for index, (role, ids, _call_id, _status) in enumerate(shaped):
        if role != "assistant" or not ids:
            continue
        results: list[str | None] = []
        for offset, (next_role, _ids, next_call_id, _next_status) in enumerate(
            shaped[index + 1 : index + 1 + len(ids)]
        ):
            if next_role != "tool":
                break
            results.append(next_call_id)
            answered.add(index + 1 + offset)
        if len(results) == len(ids):
            assert results == ids, f"message {index}: results {results} don't answer {ids}"
            continue
        at_end = index + 1 + len(results) == len(shaped)
        assert at_end and awaiting_at_end, (
            f"message {index}: calls {ids} aren't directly followed by their results"
        )
        assert results == ids[: len(results)], f"message {index}: results {results} vs {ids}"
    orphans = [i for i, shape in enumerate(shaped) if shape[0] == "tool" and i not in answered]
    assert orphans == [], f"tool results without their call at {orphans}"


# ---------------------------------------------------------------------------
# The stub agent (bound to Agent.run's signature, like tests/test_chat_turns_api.py)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Reply:
    """What one stub run answers: the new messages after the user message and the outcome."""

    new: tuple[LLMMessage, ...] = (LLMMessage(role="assistant", content=_STUB_REPLY),)
    status: str = "final"
    response: str = _STUB_REPLY
    tool_calls: tuple[ToolCallRecord, ...] = ()
    pending: ToolCall | None = None
    confirmation_id: str = _CONFIRMATION_ID


@dataclass(frozen=True)
class _Run:
    """One stub run: the bound arguments, with the history copied at call time."""

    user_message: str
    session_id: str
    history: tuple[LLMMessage, ...]
    arguments: dict[str, Any]


def _run_signature(
    user_message: str,
    session_id: str,
    *,
    history: list[LLMMessage],
    principal: Any,
    tool_policy: Any,
    pending_confirmation: PendingConfirmation | None = None,
    agent_config: AgentConfig | None = None,
    prompt_context: Any = None,
    earlier_external_content: bool = False,
) -> None:
    """``Agent.run``'s signature; every stub call is bound to it."""


def _awaiting(
    *calls: ToolCall,
    new: tuple[LLMMessage, ...] | None = None,
    confirmation_id: str = _CONFIRMATION_ID,
) -> _Reply:
    """A run that ends asking to confirm the first of ``calls`` (default ``_PENDING_CALL``);
    its new messages are one assistant turn with every call (or ``new``)."""
    asked = calls or (_PENDING_CALL,)
    first = asked[0]
    return _Reply(
        new=(_tool_use(*asked),) if new is None else new,
        status="awaiting_confirmation",
        response=f"Action {first.tool}.{first.action} requires user confirmation.",
        tool_calls=(
            ToolCallRecord(
                tool=first.tool,
                action=first.action,
                args=first.args,
                permission="confirm",
                success=False,
                duration_ms=1,
            ),
        ),
        pending=first,
        confirmation_id=confirmation_id,
    )


class _Script:
    """Scripted replies for the stub agent's ``run``, the record of every call and of every
    pending confirmation it made (``created_at`` now, ``expires_at`` the run's
    ``confirmation_timeout_s`` later, like the real agent)."""

    def __init__(self) -> None:
        self.replies: list[_Reply] = []
        self.runs: list[_Run] = []
        self.pendings: list[PendingConfirmation] = []
        # Awaited once, inside the next run, before it answers (then cleared).
        self.during: Callable[[], Awaitable[None]] | None = None

    def queue(self, *replies: _Reply) -> None:
        self.replies.extend(replies)

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        bound = inspect.signature(_run_signature).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        history = list(arguments["history"])
        self.runs.append(
            _Run(
                user_message=arguments["user_message"],
                session_id=arguments["session_id"],
                history=tuple(message.model_copy(deep=True) for message in history),
                arguments=arguments,
            )
        )
        during, self.during = self.during, None
        if during is not None:
            await during()
        reply = self.replies.pop(0) if self.replies else _Reply()
        base = [message for message in history if message.role != "system"]
        if arguments["pending_confirmation"] is None:
            base.append(_user(arguments["user_message"]))
        pending = None
        if reply.pending is not None:
            config = arguments["agent_config"] or AgentConfig()
            created = datetime.now(UTC)
            pending = PendingConfirmation(
                confirmation_id=reply.confirmation_id,
                session_id=arguments["session_id"],
                tool_call=reply.pending,
                created_at=created,
                expires_at=created + timedelta(seconds=config.confirmation_timeout_s),
            )
            self.pendings.append(pending)
        return AgentResult(
            status=reply.status,  # type: ignore[arg-type]
            response=reply.response,
            history=[*base, *reply.new],
            tool_calls=list(reply.tool_calls),
            pending_confirmation=pending,
        )


# ---------------------------------------------------------------------------
# The real agent: a scripted fake LLM and a fake calendar tool
# ---------------------------------------------------------------------------


class _EventArgs(BaseModel):
    title: str = Field(min_length=1, max_length=100)


@dataclass
class _Calendar:
    """What the fake google_calendar.create handler did: the titles it created."""

    created: list[str] = field(default_factory=list)


class _ScriptLLM:
    """Plays a script per user message (the n-th call of a turn returns the n-th scripted
    tool call, counted by the assistant turns after the user message, then the final
    reply) and records the non-system messages of every call."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self._scripts: dict[str, list[ToolCall]] = {}
        self.calls: list[tuple[str, list[dict[str, Any]]]] = []

    def script(self, message: str, *calls: ToolCall) -> None:
        self._scripts[message] = list(calls)

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        last_user = max(index for index, message in enumerate(messages) if message.role == "user")
        user_message = str(messages[last_user].content)
        self.calls.append((user_message, [m.model_dump() for m in messages if m.role != "system"]))
        steps = self._scripts.get(user_message, [])
        done = sum(1 for message in messages[last_user + 1 :] if message.role == "assistant")
        if done < len(steps):
            return LLMResponse(content="", tool_calls=[steps[done]])
        return LLMResponse(content=_FINAL_REPLY)

    async def close(self) -> None:
        """Nothing to close."""


def _real_app(llm: _ScriptLLM) -> FastAPI:
    """An app around a REAL Agent with the real tool-call recorder. Its construction-time
    timeout (60 s) differs from the stored one (300 s): runs must use the stored one."""
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    app: FastAPI = create_app(agent=agent, config=make_config())
    return app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED each) and a Super Admin, behind the fake database."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture()
def script() -> _Script:
    return _Script()


@pytest.fixture()
def agent(script: _Script) -> MagicMock:
    """A stub agent whose ``run`` (an AsyncMock) plays ``script``."""
    stub = stub_agent()
    stub.run.side_effect = script.run
    return stub


@pytest.fixture()
def client(world: World, agent: MagicMock) -> TestClient:
    """The app around the stub agent; an escaping exception becomes the app's 500."""
    return make_client(make_app(agent), raise_server_exceptions=False)


@pytest.fixture()
def calendar(monkeypatch: pytest.MonkeyPatch) -> _Calendar:
    """An unfrozen registry holding only a fake google_calendar.create (confirm by default);
    the previous registry is restored afterwards."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    seen = _Calendar()

    async def create(args: _EventArgs, **_: Any) -> str:
        seen.created.append(args.title)
        return f"Created event: {args.title}"

    register: Any = registry.register_tool
    register("google_calendar", "create", "Create an event (GH-24)", _EventArgs, side_effect=True)(
        create
    )
    return seen


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set_utc_now(monkeypatch: pytest.MonkeyPatch, when: datetime) -> None:
    """Move the server's clock (``server._utc_now``, contract section 4) to ``when``."""
    monkeypatch.setattr(server, "_utc_now", lambda: when)


class _UtcClock:
    """A movable stand-in for ``server._utc_now``."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _fresh_runtime(monkeypatch: pytest.MonkeyPatch) -> ChatRuntime:
    """Swap an empty roomy ``ChatRuntime`` in as ``server._chat_runtime``."""
    runtime = ChatRuntime(max_entries=64, idle_s=900.0)
    monkeypatch.setattr(server, "_chat_runtime", runtime)
    return runtime


class _WatchedRuntime(ChatRuntime):
    """A ``ChatRuntime`` that records every ``hold()`` call when it is made (before the
    caller waits for the chat's lock; GH-8's ``wait`` keyword is passed through)."""

    def __init__(self) -> None:
        super().__init__(max_entries=64, idle_s=900.0)
        self.holds: list[uuid.UUID] = []

    def hold(self, chat_id: uuid.UUID, owner_user_id: uuid.UUID, **kwargs: Any) -> Any:
        self.holds.append(chat_id)
        return super().hold(chat_id, owner_user_id, **kwargs)


def _pending(
    chat_id: uuid.UUID, tag: str = "a", *, expires_at: datetime, created_at: datetime | None = None
) -> PendingConfirmation:
    """A pending google_calendar.create confirmation of ``chat_id`` expiring at
    ``expires_at`` (created 5 minutes earlier by default)."""
    return PendingConfirmation(
        confirmation_id=f"confirm-24-{tag}",
        session_id=str(chat_id),
        tool_call=_PENDING_CALL,
        created_at=expires_at - timedelta(minutes=5) if created_at is None else created_at,
        expires_at=expires_at,
    )


def _seed_awaiting(
    db: FakeDb,
    runtime: ChatRuntime,
    owner: Account,
    *,
    expires_at: datetime,
    created_at: datetime | None = None,
) -> tuple[uuid.UUID, PendingConfirmation]:
    """A chat of ``owner`` whose stored turn ends with the ``_PENDING_CALL`` tool_use
    (``awaiting_confirmation``), and its pending confirmation in ``runtime``."""
    chat_id = db.add_chat(owner.user_id)
    db.add_chat_message(chat_id, "user", _MESSAGE)
    db.add_chat_message(
        chat_id,
        "assistant",
        "",
        tool_use_blocks=[_block(_PENDING_CALL)],
        status="awaiting_confirmation",
    )
    pending = _pending(chat_id, "seeded", expires_at=expires_at, created_at=created_at)
    runtime.set_pending(chat_id, owner.user_id, pending)
    return chat_id, pending


def _send(
    client: TestClient, account: Account, chat_id: uuid.UUID, message: str = _MESSAGE
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account``."""
    return client.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
    )


def _legacy(client: TestClient, account: Account, message: str = _MESSAGE) -> httpx.Response:
    """POST /api/message (the legacy session id ``_LEGACY_SESSION``) as ``account``."""
    return client.post(
        "/api/message",
        headers=account.cookie,
        json={"message": message, "session_id": _LEGACY_SESSION},
    )


def _confirm(
    client: TestClient,
    account: Account,
    *,
    chat_id: uuid.UUID | None = None,
    session_id: str | None = None,
    approved: bool = True,
    confirmation_id: str = _CONFIRMATION_ID,
) -> httpx.Response:
    """POST /api/confirm/{confirmation_id} with ``chat_id`` or ``session_id``."""
    body: dict[str, Any] = {"confirmation_id": confirmation_id, "approved": approved}
    if chat_id is not None:
        body["chat_id"] = str(chat_id)
    if session_id is not None:
        body["session_id"] = session_id
    return client.post(f"/api/confirm/{confirmation_id}", headers=account.cookie, json=body)


def _detail(client: TestClient, account: Account, chat_id: uuid.UUID) -> dict[str, Any]:
    """GET /api/chats/{chat_id} as its owner (must succeed)."""
    response = client.get(f"/api/chats/{chat_id}", headers=account.cookie)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _awaiting_turn(
    world: World, client: TestClient, script: _Script, account: Account, *, via: str = "chat_id"
) -> uuid.UUID:
    """Run a turn (chat route, or the legacy route for ``via="session_id"``) that ends
    awaiting the ``_PENDING_CALL`` confirmation; the chat's id."""
    script.queue(_awaiting())
    if via == "chat_id":
        response = _send(client, account, world.db.add_chat(account.user_id))
    else:
        response = _legacy(client, account)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "awaiting_confirmation", response.text
    return uuid.UUID(response.json()["chat_id"])


def _stored_limits(monkeypatch: pytest.MonkeyPatch, **limits: int) -> None:
    """Store platform limits in the settings cache (GH-160) for the next requests."""
    stored = default_test_platform_settings()
    updated = stored.limits.model_copy(update=limits)
    monkeypatch.setattr(
        scoped_settings, "_platform_cache", stored.model_copy(update={"limits": updated})
    )


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record, tracebacks included (not the httpx client lines, which
    name request URLs)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the caller's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50024))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _post_turn(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID, message: str = _MESSAGE
) -> httpx.Response:
    return await http.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
    )


async def _post_confirm(
    http: httpx.AsyncClient,
    account: Account,
    chat_id: uuid.UUID,
    confirmation_id: str,
    *,
    approved: bool,
) -> httpx.Response:
    body = {"confirmation_id": confirmation_id, "approved": approved, "chat_id": str(chat_id)}
    return await http.post(f"/api/confirm/{confirmation_id}", headers=account.cookie, json=body)


async def _until(condition: Callable[[], bool]) -> None:
    """Yield to the event loop until ``condition()`` holds (at most ``_WAIT_S`` seconds)."""

    async def poll() -> None:
        while not condition():
            await _REAL_SLEEP(0.001)

    await asyncio.wait_for(poll(), _WAIT_S)


async def _hold(
    runtime: ChatRuntime,
    chat_id: uuid.UUID,
    owner_user_id: uuid.UUID,
    inside: asyncio.Event,
    release: asyncio.Event,
) -> None:
    """Hold the chat's lock (``runtime.hold``) until ``release`` is set (bounded)."""
    async with runtime.hold(chat_id, owner_user_id):
        inside.set()
        await asyncio.wait_for(release.wait(), _WAIT_S)


async def _reaper_until(monkeypatch: pytest.MonkeyPatch, condition: Callable[[], bool]) -> None:
    """Run the real ``server._run_confirmation_reaper()`` with a 1 ms interval until
    ``condition()`` holds, then cancel it (an exception it raised propagates)."""
    monkeypatch.setattr(server, "_CONFIRMATION_REAP_INTERVAL_S", 0.001)
    task = asyncio.create_task(server._run_confirmation_reaper())
    try:
        await _until(condition)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(task, _WAIT_S)


def _park_next_run(script: _Script) -> tuple[asyncio.Event, asyncio.Event]:
    """The next stub run sets the first event, then waits for the second (bounded)."""
    parked, release = asyncio.Event(), asyncio.Event()

    async def park() -> None:
        parked.set()
        await asyncio.wait_for(release.wait(), _WAIT_S)

    script.during = park
    return parked, release


# ---------------------------------------------------------------------------
# 1. The timeout calculation: created_at + timeout_s
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "timeout_s",
    [
        pytest.param(0.5, id="half-second"),
        pytest.param(42.125, id="fractional"),
        pytest.param(300.0, id="default-300"),
        pytest.param(3600.0, id="max-3600"),
    ],
)
def test_confirmation_timeout_build_pending_expires_exactly_timeout_after_creation(
    timeout_s: float,
) -> None:
    """``expires_at - created_at`` is exactly the timeout; ``created_at`` is aware UTC,
    read during the call."""
    before = datetime.now(UTC)
    pending = _build_pending_confirmation(
        tool_call=_PENDING_CALL, session_id="chat-24", timeout_s=timeout_s
    )
    after = datetime.now(UTC)

    assert pending.expires_at - pending.created_at == timedelta(seconds=timeout_s)
    assert pending.created_at.utcoffset() == timedelta(0)
    assert before <= pending.created_at <= after


@pytest.mark.parametrize(
    "timeout_s",
    [pytest.param(42.125, id="fractional"), pytest.param(300.0, id="default-300")],
)
async def test_confirmation_timeout_agent_run_pending_expires_the_runs_timeout_later(
    calendar: _Calendar, timeout_s: float
) -> None:
    """The real ``Agent.run`` on a confirm action, with a run config whose timeout differs
    from the construction-time one: the pending confirmation expires exactly the run's
    timeout after its creation, and nothing is dispatched."""
    llm = _ScriptLLM()
    llm.script(_MESSAGE, _PENDING_CALL)
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=AsyncMock(),
        agent_config=AgentConfig(confirmation_timeout_s=99.0),
    )
    policy = ToolPolicy(
        permissions=PermissionsConfig(
            tools={"google_calendar": ToolPermissions(actions={"create": "confirm"})}
        )
    )
    before = datetime.now(UTC)

    result = await agent.run(
        _MESSAGE,
        "chat-24",
        history=[],
        principal=_PRINCIPAL,
        tool_policy=policy,
        agent_config=AgentConfig(confirmation_timeout_s=timeout_s),
    )

    after = datetime.now(UTC)
    assert result.status == "awaiting_confirmation"
    pending = result.pending_confirmation
    assert pending is not None
    assert pending.expires_at - pending.created_at == timedelta(seconds=timeout_s)
    assert pending.created_at.utcoffset() == timedelta(0)
    assert before <= pending.created_at <= after
    assert calendar.created == []


def test_confirmation_timeout_turn_runs_with_the_stored_timeout_read_per_request(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guard (GH-160): the default stored ``confirmation_timeout_s`` (300) reaches the
    run as 300.0; a changed stored value applies to the next request, and the response
    reports the expiry of the run's confirmation."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting(), _awaiting())
    assert _send(client, editor, chat_id).status_code == 200
    _stored_limits(monkeypatch, confirmation_timeout_s=45)

    response = _send(client, editor, chat_id, "Book it again")

    assert response.status_code == 200, response.text
    timeouts = [run.arguments["agent_config"].confirmation_timeout_s for run in script.runs]
    assert timeouts == [300.0, 45.0]
    expires_at = datetime.fromisoformat(response.json()["pending_confirmation"]["expires_at"])
    assert expires_at == script.pendings[1].expires_at


# ---------------------------------------------------------------------------
# 2. The server clock and the expiry boundary
# ---------------------------------------------------------------------------


def test_confirmation_timeout_utc_now_is_the_aware_current_utc_time() -> None:
    before = datetime.now(UTC)
    now = server._utc_now()
    after = datetime.now(UTC)

    assert now.utcoffset() == timedelta(0)
    assert before <= now <= after


@pytest.mark.parametrize(
    ("offset", "reaped"),
    [
        pytest.param(timedelta(0), True, id="at-expires-at"),
        pytest.param(-_MICROSECOND, False, id="one-microsecond-before"),
    ],
)
def test_confirmation_timeout_reap_expires_at_expires_at_by_the_server_clock(
    world: World, monkeypatch: pytest.MonkeyPatch, offset: timedelta, reaped: bool
) -> None:
    """The reap reads ``server._utc_now`` (a far-future instant the real clock never
    reaches): ``now >= expires_at`` is expired, one microsecond earlier is not."""
    runtime = _fresh_runtime(monkeypatch)
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    runtime.set_pending(chat_id, editor.user_id, _pending(chat_id, expires_at=_FAR))
    _set_utc_now(monkeypatch, _FAR + offset)

    server._reap_expired_confirmations()

    assert (runtime.get_pending(chat_id) is None) is reaped


def test_confirmation_timeout_confirm_check_at_expires_at_gets_404(
    world: World, client: TestClient, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the request's reap skipped, the check under the chat's lock reads the server
    clock: exactly at ``expires_at`` the confirmation is gone (404, popped, no run,
    nothing stored)."""
    editor = world.a["editor"]
    chat_id, pending = _seed_awaiting(world.db, server._chat_runtime, editor, expires_at=_FAR)
    monkeypatch.setattr(server, "_reap_expired_confirmations", lambda: None)
    _set_utc_now(monkeypatch, _FAR)
    before = _stored(world.db, chat_id)

    response = _confirm(
        client, editor, chat_id=chat_id, approved=False, confirmation_id=pending.confirmation_id
    )

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert server._chat_runtime.get_pending(chat_id) is None
    assert agent.run.await_count == 0
    assert _stored(world.db, chat_id) == before


def test_confirmation_timeout_confirm_one_microsecond_before_expires_at_still_resolves(
    world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One microsecond before ``expires_at`` (by the server clock) the confirmation is
    live: the denial is stored and answered."""
    editor = world.a["editor"]
    chat_id, pending = _seed_awaiting(world.db, server._chat_runtime, editor, expires_at=_FAR)
    _set_utc_now(monkeypatch, _FAR - _MICROSECOND)

    response = _confirm(
        client, editor, chat_id=chat_id, approved=False, confirmation_id=pending.confirmation_id
    )

    assert response.status_code == 200, response.text
    assert (response.json()["status"], response.json()["response"]) == ("final", _DENIAL_REPLY)
    assert _stored(world.db, chat_id)[2:] == [
        _row(_tool(_DENIED_RESULT, _PENDING_CALL)),
        _row(_assistant(_DENIAL_REPLY)),
    ]


# ---------------------------------------------------------------------------
# 3. The reap: synchronous, every user's, never waits for a lock
# ---------------------------------------------------------------------------


def test_confirmation_timeout_reap_drops_only_the_expired_confirmations_of_every_user(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plain function (not a coroutine function). Five chats of four users in both
    orgs: the expired confirmations go, whoever owns them; the live ones stay as they
    were."""
    assert not inspect.iscoroutinefunction(server._reap_expired_confirmations)
    runtime = _fresh_runtime(monkeypatch)
    cases = [
        (world.a["editor"], _FAR - timedelta(seconds=1), False),
        (world.a["editor"], _FAR + timedelta(hours=1), True),
        (world.a["org_admin"], _FAR, False),
        (world.b["editor"], _FAR - timedelta(hours=1), False),
        (world.b["org_admin"], _FAR + _MICROSECOND, True),
    ]
    chats: list[tuple[uuid.UUID, PendingConfirmation, bool]] = []
    for index, (owner, expires_at, live) in enumerate(cases):
        chat_id = world.db.add_chat(owner.user_id)
        pending = _pending(chat_id, f"u{index}", expires_at=expires_at)
        runtime.set_pending(chat_id, owner.user_id, pending)
        chats.append((chat_id, pending, live))
    _set_utc_now(monkeypatch, _FAR)

    server._reap_expired_confirmations()

    assert [runtime.get_pending(chat_id) for chat_id, _, _ in chats] == [
        pending if live else None for _, pending, live in chats
    ]


async def test_confirmation_timeout_reap_completes_while_the_chat_is_held(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another task holds the chat's lock: the reap still drops its expired confirmation
    at once, and the holder is undisturbed."""
    runtime = _fresh_runtime(monkeypatch)
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    runtime.set_pending(chat_id, editor.user_id, _pending(chat_id, expires_at=_FAR))
    _set_utc_now(monkeypatch, _FAR)
    inside, release = asyncio.Event(), asyncio.Event()
    holder = asyncio.create_task(_hold(runtime, chat_id, editor.user_id, inside, release))
    try:
        await asyncio.wait_for(inside.wait(), _WAIT_S)

        server._reap_expired_confirmations()

        assert runtime.get_pending(chat_id) is None
        assert not holder.done()
    finally:
        release.set()
        await asyncio.wait_for(holder, _WAIT_S)


# ---------------------------------------------------------------------------
# 4. The background reaper and the lifespan
# ---------------------------------------------------------------------------


def test_confirmation_timeout_reap_interval_is_30_seconds() -> None:
    assert server._CONFIRMATION_REAP_INTERVAL_S == 30.0


async def test_confirmation_timeout_reaper_sleeps_the_interval_then_reaps_until_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``asyncio.sleep`` is replaced by a recorder that blocks on its third call: the
    reaper sleeps 30 s, reaps, sleeps, reaps, sleeps; cancelled there, it ends (cancelled
    or returning) without another pass."""
    events: list[str] = []
    third_sleep = asyncio.Event()

    async def fake_sleep(delay: float, *_args: Any, **_kwargs: Any) -> None:
        events.append(f"sleep {delay!r}")
        if sum(event.startswith("sleep") for event in events) >= 3:
            third_sleep.set()
            await asyncio.Event().wait()
        await _REAL_SLEEP(0)

    monkeypatch.setattr(server, "_reap_expired_confirmations", lambda: events.append("reap"))
    reaper = server._run_confirmation_reaper
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    task = asyncio.create_task(reaper())
    try:
        await asyncio.wait_for(third_sleep.wait(), _WAIT_S)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(task, _WAIT_S)

    assert events == ["sleep 30.0", "reap", "sleep 30.0", "reap", "sleep 30.0"]
    assert task.done()
    assert task.cancelled() or task.exception() is None


async def test_confirmation_timeout_reaper_reaps_without_any_request_lock_wait_or_query(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No request at all: the reaper (interval patched to 1 ms, read at call time) drops
    an expired confirmation of a chat whose lock another task holds, keeps another
    user's live one, and runs no statement."""
    runtime = _fresh_runtime(monkeypatch)
    editor, other = world.a["editor"], world.b["editor"]
    expired_chat = world.db.add_chat(editor.user_id)
    live_chat = world.db.add_chat(other.user_id)
    live = _pending(live_chat, "live", expires_at=_FAR + timedelta(hours=1))
    runtime.set_pending(expired_chat, editor.user_id, _pending(expired_chat, expires_at=_FAR))
    runtime.set_pending(live_chat, other.user_id, live)
    _set_utc_now(monkeypatch, _FAR + timedelta(seconds=1))
    statements = len(world.db.calls)
    inside, release = asyncio.Event(), asyncio.Event()
    holder = asyncio.create_task(_hold(runtime, expired_chat, editor.user_id, inside, release))
    try:
        await asyncio.wait_for(inside.wait(), _WAIT_S)

        await _reaper_until(monkeypatch, lambda: runtime.get_pending(expired_chat) is None)

        assert not holder.done()
    finally:
        release.set()
        await asyncio.wait_for(holder, _WAIT_S)
    assert runtime.get_pending(live_chat) == live
    assert len(world.db.calls) == statements


async def test_confirmation_timeout_reaper_logs_a_failed_pass_by_class_name_and_goes_on(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The first pass raises: one WARNING naming the exception class, never its message
    (nor a traceback carrying it), and the reaper keeps reaping."""
    caplog.set_level(logging.DEBUG)
    passes: list[int] = []

    def flaky() -> None:
        passes.append(len(passes))
        if len(passes) == 1:
            raise RuntimeError(_REAPER_CANARY)

    monkeypatch.setattr(server, "_reap_expired_confirmations", flaky)

    await _reaper_until(monkeypatch, lambda: len(passes) >= 3)

    warnings = [
        record
        for record in caplog.records
        if record.name.startswith("admino") and record.levelno >= logging.WARNING
    ]
    assert [(r.levelno, "RuntimeError" in r.getMessage()) for r in warnings] == [
        (logging.WARNING, True)
    ]
    assert _REAPER_CANARY not in _app_log_text(caplog)


async def test_confirmation_timeout_reaper_pass_during_a_running_turn_reaps_another_chat(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """While the Editor's turn is running (its stub run parked inside the chat's lock), a
    reaper pass drops org B's expired confirmation; the turn then finishes normally."""
    app = make_app(agent)
    runtime = _fresh_runtime(monkeypatch)
    editor, other = world.a["editor"], world.b["editor"]
    busy_chat = world.db.add_chat(editor.user_id)
    created = datetime.now(UTC)
    expired_chat, _pending_b = _seed_awaiting(
        world.db, runtime, other, created_at=created, expires_at=created + timedelta(minutes=5)
    )
    parked, release = _park_next_run(script)
    async with _async_client(app) as http:
        turn = asyncio.create_task(_post_turn(http, editor, busy_chat))
        try:
            await asyncio.wait_for(parked.wait(), _WAIT_S)
            _set_utc_now(monkeypatch, created + timedelta(minutes=6))

            await _reaper_until(monkeypatch, lambda: runtime.get_pending(expired_chat) is None)

            assert not turn.done()
        finally:
            release.set()
            response = await asyncio.wait_for(turn, _WAIT_S)
    assert response.status_code == 200, response.text
    assert _stored(world.db, busy_chat) == _rows(_user(_MESSAGE), _assistant(_STUB_REPLY))


class _LifespanProbe:
    """Fakes for the lifespan's pool and background jobs; records what happens when."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.pool: Any = MagicMock(name="pool")
        self.reaper_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.reaper_tasks: list[asyncio.Task[Any]] = []

    async def _blocking(self, name: str) -> None:
        """Block until cancelled, then finish after one more loop turn."""
        self.events.append(f"{name}-started")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.events.append(f"{name}-cancelled")
            await _REAL_SLEEP(0)
            self.events.append(f"{name}-finished")
            raise

    def job(self, name: str) -> Callable[..., Awaitable[None]]:
        """A fake background job named ``name``."""

        async def run(*_args: Any, **_kwargs: Any) -> None:
            await self._blocking(name)

        return run

    async def reaper(self, *args: Any, **kwargs: Any) -> None:
        """The fake ``server._run_confirmation_reaper``."""
        task = asyncio.current_task()
        assert task is not None
        self.reaper_tasks.append(task)
        self.reaper_calls.append((args, kwargs))
        await self._blocking("reaper")


@contextlib.contextmanager
def _patched_lifespan(probe: _LifespanProbe) -> Iterator[None]:
    """Patch the lifespan's database calls and every background job (no real job or
    query runs). ``server._run_confirmation_reaper`` is patched WITHOUT ``create=True``:
    it must exist. get_pool() raises until init_pool() ran, like the real one."""
    state: dict[str, Any] = {"pool": None}

    async def fake_init_pool(*_args: Any, **_kwargs: Any) -> Any:
        probe.events.append("init_pool")
        state["pool"] = probe.pool
        return probe.pool

    def fake_get_pool() -> Any:
        if state["pool"] is None:
            msg = "Database pool not initialised"
            raise RuntimeError(msg)
        return state["pool"]

    async def fake_close_pool() -> None:
        probe.events.append("close_pool")
        state["pool"] = None

    with (
        patch("admino.database.init_pool", fake_init_pool),
        patch("admino.database.close_pool", fake_close_pool),
        patch("admino.database.get_pool", fake_get_pool),
        patch("admino.audit_events.run_retention_job", probe.job("retention")),
        patch("admino.sessions.run_session_purge_job", probe.job("session-purge")),
        patch("admino.mailer.load_smtp_config", MagicMock(return_value=None)),
        patch("admino.email_outbox.run_outbox_sender", probe.job("sender")),
        patch("admino.organizations.run_org_purge_job", probe.job("org-purge")),
        patch_login_throttle_purge_job(AsyncMock()),
        patch("admino.server._run_confirmation_reaper", probe.reaper),
    ):
        yield


async def _let_tasks_run() -> None:
    """Give scheduled tasks a few loop turns to start."""
    for _ in range(5):
        await _REAL_SLEEP(0)


async def test_confirmation_timeout_lifespan_starts_the_reaper_task_after_the_pool() -> None:
    """Entering the lifespan starts ``_run_confirmation_reaper()`` (no arguments) once, as
    a background task of its own, after the pool exists."""
    probe = _LifespanProbe()
    app = make_app()

    with _patched_lifespan(probe):
        async with asyncio.timeout(_WAIT_S), _lifespan(app):
            await _let_tasks_run()
            assert probe.reaper_calls == [((), {})]
            (task,) = probe.reaper_tasks
            assert task is not asyncio.current_task()
            assert not task.done()

    assert probe.events.index("init_pool") < probe.events.index("reaper-started")


async def test_confirmation_timeout_lifespan_cancels_the_reaper_before_closing_the_pool() -> None:
    """Shutdown cancels the reaper task and waits for it before the pool closes."""
    probe = _LifespanProbe()
    app = make_app()

    with _patched_lifespan(probe):
        async with asyncio.timeout(_WAIT_S), _lifespan(app):
            await _let_tasks_run()

    (task,) = probe.reaper_tasks
    assert task.cancelled()
    assert probe.events.index("reaper-finished") < probe.events.index("close_pool")


# ---------------------------------------------------------------------------
# 5. End to end: create, wait past the timeout, the chat shows expired, confirm is 404
# ---------------------------------------------------------------------------


def test_confirmation_timeout_expired_confirmation_shows_expired_in_the_chat(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One microsecond before ``expires_at`` the chat shows the confirmation as pending;
    at ``expires_at`` it shows ``expired`` with no pending confirmation, the runtime holds
    none and the stored messages are unchanged (and well-formed: the chat ends awaiting)."""
    editor = world.a["editor"]
    chat_id = _awaiting_turn(world, client, script, editor)
    (pending,) = script.pendings
    assert pending.expires_at - pending.created_at == _DEFAULT_TIMEOUT
    before = _stored(world.db, chat_id)
    _set_utc_now(monkeypatch, pending.expires_at - _MICROSECOND)
    assert _detail(client, editor, chat_id)["confirmation_status"] == "pending"
    _set_utc_now(monkeypatch, pending.expires_at)

    detail = _detail(client, editor, chat_id)

    assert (detail["confirmation_status"], detail["pending_confirmation"]) == ("expired", None)
    assert server._chat_runtime.get_pending(chat_id) is None
    assert _stored(world.db, chat_id) == before
    _assert_well_formed(world.db.messages_of(chat_id))


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
@pytest.mark.parametrize("via", ["chat_id", "session_id"])
def test_confirmation_timeout_confirming_an_expired_confirmation_gets_404(
    world: World,
    client: TestClient,
    agent: MagicMock,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    via: str,
    approved: bool,
) -> None:
    """Past ``expires_at``, approving or denying (by ``chat_id``, or by the legacy
    ``session_id`` on a legacy chat) is the plain 404: no run, nothing stored, nothing
    left in the runtime."""
    editor = world.a["editor"]
    chat_id = _awaiting_turn(world, client, script, editor, via=via)
    (pending,) = script.pendings
    before = _stored(world.db, chat_id)
    _set_utc_now(monkeypatch, pending.expires_at + timedelta(seconds=1))

    response = _confirm(
        client,
        editor,
        chat_id=chat_id if via == "chat_id" else None,
        session_id=_LEGACY_SESSION if via == "session_id" else None,
        approved=approved,
        confirmation_id=pending.confirmation_id,
    )

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert agent.run.await_count == 1
    assert _stored(world.db, chat_id) == before
    assert server._chat_runtime.get_pending(chat_id) is None


async def test_confirmation_timeout_expired_by_the_background_reaper_alone_gets_404(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No request after the expiry until the reaper ran: one pass drops the confirmation;
    then the chat shows ``expired`` and confirming is 404 with no run and nothing
    stored."""
    app = make_app(agent)
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting())
    async with _async_client(app) as http:
        turn = await _post_turn(http, editor, chat_id)
        assert turn.json()["status"] == "awaiting_confirmation", turn.text
        (pending,) = script.pendings
        before = _stored(world.db, chat_id)
        _set_utc_now(monkeypatch, pending.expires_at + timedelta(seconds=1))

        await _reaper_until(monkeypatch, lambda: server._chat_runtime.get_pending(chat_id) is None)

        detail = await http.get(f"/api/chats/{chat_id}", headers=editor.cookie)
        confirm = await _post_confirm(http, editor, chat_id, pending.confirmation_id, approved=True)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert (body["confirmation_status"], body["pending_confirmation"]) == ("expired", None)
    assert (confirm.status_code, confirm.json()) == (404, _NO_PENDING)
    assert agent.run.await_count == 1
    assert _stored(world.db, chat_id) == before


def test_confirmation_timeout_approving_an_expired_call_never_dispatches_it_with_the_real_agent(
    world: World, calendar: _Calendar, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real agent asks to confirm google_calendar.create; the confirmation expires the
    stored 300 s (not the agent's construction-time 60 s) after the turn. Approving after
    that is 404: the handler never runs, no further ``tool.call`` row, no LLM call,
    nothing stored."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    llm = _ScriptLLM()
    llm.script(_MESSAGE, _PENDING_CALL)
    client = make_client(_real_app(llm), raise_server_exceptions=False)
    started = datetime.now(UTC)
    turn = _send(client, editor, chat_id)
    finished = datetime.now(UTC)
    assert turn.status_code == 200, turn.text
    pending = turn.json()["pending_confirmation"]
    assert turn.json()["status"] == "awaiting_confirmation"
    expires_at = datetime.fromisoformat(pending["expires_at"])
    assert started + _DEFAULT_TIMEOUT <= expires_at <= finished + _DEFAULT_TIMEOUT
    audit = world.db.audit_rows("tool.call")
    assert [(r["metadata"]["decision"], r["metadata"]["success"]) for r in audit] == [
        ("confirm", False)
    ]
    llm_calls = len(llm.calls)
    stored = _stored(world.db, chat_id)
    _set_utc_now(monkeypatch, expires_at + timedelta(seconds=1))

    response = _confirm(client, editor, chat_id=chat_id, confirmation_id=pending["confirmation_id"])

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert calendar.created == []
    assert world.db.audit_rows("tool.call") == audit
    assert len(llm.calls) == llm_calls
    assert _stored(world.db, chat_id) == stored


# ---------------------------------------------------------------------------
# 6. Expiring while the request waits for the chat's lock: the same 404, never 410
# ---------------------------------------------------------------------------


async def test_confirmation_timeout_expiring_while_waiting_for_the_chat_lock_gets_404(
    world: World, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The approval's reap runs while the confirmation is live (kept); it then waits for
    the chat's lock, held by another task, and the clock reaches ``expires_at`` meanwhile.
    Under the lock: the same 404, the confirmation popped, no run, nothing stored."""
    app = make_app(agent)
    runtime = _WatchedRuntime()
    monkeypatch.setattr(server, "_chat_runtime", runtime)
    editor = world.a["editor"]
    created = datetime.now(UTC)
    chat_id, pending = _seed_awaiting(
        world.db, runtime, editor, created_at=created, expires_at=created + timedelta(minutes=5)
    )
    clock = _UtcClock(pending.expires_at - timedelta(seconds=1))
    monkeypatch.setattr(server, "_utc_now", clock)
    before = _stored(world.db, chat_id)
    inside, release = asyncio.Event(), asyncio.Event()
    holder = asyncio.create_task(_hold(runtime, chat_id, editor.user_id, inside, release))
    async with _async_client(app) as http:
        try:
            await asyncio.wait_for(inside.wait(), _WAIT_S)
            holds = len(runtime.holds)
            confirm = asyncio.create_task(
                _post_confirm(http, editor, chat_id, pending.confirmation_id, approved=True)
            )
            await _until(lambda: len(runtime.holds) > holds)
            assert runtime.get_pending(chat_id) == pending
            clock.now = pending.expires_at
        finally:
            release.set()
            await asyncio.wait_for(holder, _WAIT_S)
        response = await asyncio.wait_for(confirm, _WAIT_S)

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert runtime.get_pending(chat_id) is None
    assert agent.run.await_count == 0
    assert _stored(world.db, chat_id) == before


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
def test_confirmation_timeout_expired_confirmation_the_reap_missed_gets_404_never_410(
    world: World,
    client: TestClient,
    agent: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    """The request's reap is skipped and the confirmation expired five minutes ago by the
    real clock: the check under the lock answers the same 404 (no 410), pops it, runs
    nothing and stores nothing."""
    editor = world.a["editor"]
    now = datetime.now(UTC)
    chat_id, pending = _seed_awaiting(
        world.db,
        server._chat_runtime,
        editor,
        created_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=5),
    )
    monkeypatch.setattr(server, "_reap_expired_confirmations", lambda: None)
    before = _stored(world.db, chat_id)

    response = _confirm(
        client, editor, chat_id=chat_id, approved=approved, confirmation_id=pending.confirmation_id
    )

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert server._chat_runtime.get_pending(chat_id) is None
    assert agent.run.await_count == 0
    assert _stored(world.db, chat_id) == before


# ---------------------------------------------------------------------------
# 7. The next message after an expiry closes the dangling calls: well-formed history
# ---------------------------------------------------------------------------

_BATCHES: Final[dict[str, tuple[tuple[LLMMessage, ...], tuple[LLMMessage, ...]]]] = {
    # The awaiting turn's new messages, and the closing results the next turn adds.
    "single": ((_tool_use(_PENDING_CALL),), (_cancelled(_PENDING_CALL),)),
    "answered-then-pending": (
        (_tool_use(_ANSWERED_CALL, _PENDING_CALL), _tool("Agenda: weekly", _ANSWERED_CALL)),
        (_cancelled(_PENDING_CALL),),
    ),
    "pending-then-unrun": (
        (_tool_use(_PENDING_CALL, _UNRUN_CALL),),
        (_cancelled(_PENDING_CALL), _cancelled(_UNRUN_CALL)),
    ),
}


@pytest.mark.parametrize("batch", list(_BATCHES))
def test_confirmation_timeout_next_message_after_expiry_closes_the_dangling_calls(
    world: World,
    client: TestClient,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    batch: str,
) -> None:
    """After the expiry (the chat shows ``expired``), the next message's run gets the
    history with each dangling call closed by the cancelled result right after the
    batch's results, in block order; the turn is 200, the stored history well-formed and
    the chat shows no confirmation."""
    new, closing = _BATCHES[batch]
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting(_PENDING_CALL, new=new))
    assert _send(client, editor, chat_id).json()["status"] == "awaiting_confirmation"
    (pending,) = script.pendings
    _set_utc_now(monkeypatch, pending.expires_at + timedelta(seconds=1))
    assert _detail(client, editor, chat_id)["confirmation_status"] == "expired"

    response = _send(client, editor, chat_id, _NEXT_MESSAGE)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "final"
    given = list(script.runs[1].history)
    assert _dump(given) == _dump([_user(_MESSAGE), *new, *closing])
    _assert_well_formed(given)
    assert _stored(world.db, chat_id) == [
        *_rows(_user(_MESSAGE), *new, last="awaiting_confirmation"),
        *_rows(*closing),
        *_rows(_user(_NEXT_MESSAGE), _assistant(_STUB_REPLY)),
    ]
    _assert_well_formed(world.db.messages_of(chat_id))
    assert _detail(client, editor, chat_id)["confirmation_status"] == "none"


# ---------------------------------------------------------------------------
# 8. Logs: no content, tool arguments or confirmation ids (tracker section 5)
# ---------------------------------------------------------------------------


def test_confirmation_timeout_logs_carry_no_content_arguments_or_confirmation_ids(
    world: World,
    client: TestClient,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A turn awaiting a confirmation (canary message, argument and confirmation id), its
    expiry, the reap, the chat detail, the late approval (404) and the next turn: the
    server logs these flows, and no app record names a canary."""
    caplog.set_level(logging.DEBUG)
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    call = ToolCall(
        tool="google_calendar",
        action="create",
        args={"title": _ARG_CANARY},
        tool_call_id="call-canary24",
    )
    script.queue(_awaiting(call, confirmation_id=_ID_CANARY))
    assert _send(client, editor, chat_id, _MESSAGE_CANARY).status_code == 200
    (pending,) = script.pendings
    _set_utc_now(monkeypatch, pending.expires_at + timedelta(seconds=1))
    server._reap_expired_confirmations()
    assert _detail(client, editor, chat_id)["confirmation_status"] == "expired"
    late = _confirm(client, editor, chat_id=chat_id, confirmation_id=_ID_CANARY)
    assert late.status_code == 404
    assert _send(client, editor, chat_id, _NEXT_CANARY).status_code == 200

    text = _app_log_text(caplog)

    assert "admino.server" in text
    for canary in (_MESSAGE_CANARY, _NEXT_CANARY, _ARG_CANARY, _ID_CANARY):
        assert canary not in text
