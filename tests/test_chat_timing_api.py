"""The chat routes' timing line and the send path's statement count, over HTTP (GH-244).

Acceptance criteria (#244): "Each chat request logs content-free timings: request
ID, DB ms, ms to the first LLM byte, LLM ms, tool ms and total ms." and "The send
path makes at most 3 database queries before the LLM call (session, org policy with
residency and services, promotions), measured with the timing log." Tests: "The
timing log has no content. The query count on the send path." Tracker #139 §5: no
content in logs; tenant isolation (another org's, a colleague's, a trashed and an
unknown chat stay the identical 404).

Harness: the app from ``create_app()`` on the FakeDb world of tests/tenancy_world.py
(orgs A and B with an Org Admin and an Editor each; fresh sessions, so no
``last_seen_at`` touch; conftest's warm platform settings cache), the REAL
``admino.agent.Agent`` with the real tool-call recorder, fake tools in an isolated
registry and a scripted fake LLM answering ``chat`` (JSON turns, title calls) and
``chat_stream`` (SSE turns). ``admino.database.get_pool`` returns
``database.TimedPool(db.pool)`` (built per call) and ``request_timing._clock`` is a
fake clock moved only by the fakes, so every number of a line is exact:
- every FakeDb statement: 2.0 ms;
- an LLM call asking for a tool: 40.0 ms (streamed: a delta after 12.0 ms, the
  response 28.0 ms later); an answering one: 25.0 ms (streamed: a delta after
  10.0 ms, the response 15.0 ms later); a chat-title call: 500.0 ms;
- a tool handler: 7.0 ms.
So ``db_ms`` is 2.0 x ``db_queries``, ``llm_start_ms`` the time of the statements
before the first LLM call (plus a resumed tool), and ``total_ms`` the request's DB,
LLM and tool time. The agent's ``run`` is wrapped to record its keywords and the
statement count when it starts; a ``ChatRuntime`` subclass records the statement
count at every ``hold()``.

What is pinned:
- C3, POST /api/chats/{chat_id}/messages, JSON and SSE, in a chat with history:
  exactly three statements before the first LLM call, in this order: the session
  lookup, ONE turn-setup statement naming permissions, org_settings, users and
  chats (T1), the chat's hold, ONE statement naming chats and chat_messages (T2).
  The line says ``db_queries_before_llm=3``; ``db_queries`` is every statement of
  the request (the turn's store and the tool-call recorder included). The run gets
  what the old loaders read on the same database (``load_tool_policy``,
  ``load_prompt_context``, ``load_turn``'s history, the chat's
  ``external_content``); a residency org's run isn't offered the blocked tools and
  refuses a non-Swiss provider before any LLM call.
- Refusals keep their order and statements: another org's, a colleague's, a
  trashed and an unknown chat are the identical 404 ``chat_not_found`` after the
  session lookup and T1 only (no hold, no T2, no run), JSON and SSE; a busy chat is
  the 409 ``run_active`` after T1 (its hold refused) with no T2; 401, the Super
  Admin's 403, the CSRF 403, a message over the stored ``max_message_length`` (422) and the
  429 run no statement but the session lookup. Each logs exactly one line with its
  status and ``-`` LLM fields.
- C1.1 / C1.3: one line per request on each turn route (``chat_message`` JSON and
  SSE, the legacy ``message``, ``confirm`` approve and deny), matching the
  contract's regex, ``request_id`` = the response's ``X-Request-ID``; POST
  /api/chats, GET /api/chats, GET /api/chats/{id} and POST /api/chats/{id}/stop
  log none.
- C1.2 values: ``llm_ms`` sums the turn's LLM calls (a tool turn: two),
  ``tool_ms`` is the tool's (a resumed confirmation's too), ``llm_first_byte_ms``
  is the first response (JSON) or the first stream item (SSE); a streamed turn's
  line is written once the turn is stored (before ``done``); the title call of an
  untitled chat's first exchange (JSON: a background task; SSE: before ``done``)
  adds no LLM time, no statement and no line.
- No content: the messages, the chat title, the automatic title, tool arguments
  and output, the replies, the user's email, the org and personal instructions,
  the legacy session id, the confirmation id, the session token, the tool names
  and every chat, user and org id stay out of every record of
  ``admino.request_timing``.

``admino.request_timing`` and ``database.TimedPool`` are new. They are looked up
when a fixture runs, never at import, and until they exist the harness runs on the
plain FakeDb pool without a clock: each test then fails on its own assertion (a
missing line, a statement count) instead of at collection.

Security notes:
- Every message, id, email, token and argument here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from pydantic import BaseModel, Field

from admino import chats, org_permissions, scoped_settings, server
from admino import main as main_module
from admino.agent import Agent
from admino.llm import LLMResponse, LLMStreamDelta
from admino.models import AgentConfig, LLMMessage, ToolCall
from admino.server import create_app
from admino.tenancy import TenantContext
from admino.tools import registry
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb
from tests.log_capture import configured_logging
from tests.tenancy_world import (
    CHAT_NOT_FOUND,
    CLIENT_IP,
    FORBIDDEN,
    UNAUTHORIZED,
    build_world,
    make_client,
    make_config,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.db_fakes import Call
    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOGGER: Final = "admino.request_timing"
# The contract's line regex (C1.3), matched with fullmatch.
_LINE_RE: Final = re.compile(
    r"^chat timings: request_id=([0-9a-f]{32}|-) route=(chat_message|message|confirm) "
    r"status=\d{3} db_queries=\d+ db_queries_before_llm=(\d+|-) db_ms=\d+\.\d "
    r"llm_start_ms=(\d+\.\d|-) llm_first_byte_ms=(\d+\.\d|-) llm_ms=\d+\.\d "
    r"tool_ms=\d+\.\d total_ms=\d+\.\d$"
)
# The tables a statement names (FakeDb's normalized SQL).
_TABLE_RE: Final = re.compile(
    r"\b(sessions|organizations|org_settings|users|chats|chat_messages|permissions)\b"
)
# T1 reads the org policy (permissions, org_settings), the caller (users) and the
# chat's owner check (chats); T2 the chat and its latest messages.
_T1_TABLES: Final = frozenset({"permissions", "org_settings", "users", "chats"})
_T2_TABLES: Final = frozenset({"chats", "chat_messages"})

# What the fake clock moves by (ms).
_STATEMENT_MS: Final = 2.0
_TOOL_STEP_MS: Final = 40.0
_TOOL_STEP_FIRST_MS: Final = 12.0
_ANSWER_MS: Final = 25.0
_ANSWER_FIRST_MS: Final = 10.0
_TITLE_MS: Final = 500.0
_TOOL_MS: Final = 7.0
# The three statements before the LLM call of a send (C3), as a duration.
_SETUP_MS: Final = 3 * _STATEMENT_MS

_WAIT_S: Final = 5.0
_MODES: Final = ("json", "sse")
_SSE: Final = {"Accept": "text/event-stream"}

_RUN_ACTIVE: Final = {
    "detail": "A message is already running in this chat.",
    "reason": "run_active",
}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_TOO_LONG: Final = {"detail": "Message exceeds maximum length of 10 characters"}

# Content canaries: none may reach a record of admino.request_timing.
_MESSAGE: Final = "Quokka canary message w2-244"
_TOOL_MESSAGE: Final = "Recall the walrus canary note w2-244"
_BOOK_MESSAGE: Final = "Book the heron canary offsite w2-244"
_FIRST_MESSAGE: Final = "Run the parked marmot canary turn w2-244"
_ARG_CANARY: Final = "argcanary-walrus-w2"
_EVENT_CANARY: Final = "eventcanary-heron-w2"
_OUTPUT_CANARY: Final = "outputcanary-narwhal-w2"
_REPLY: Final = "Here is the pelican canary reply w2-244."
_PREAMBLE: Final = "Let me look at the lynx canary notes w2."
_CHAT_TITLE: Final = "titlecanary-ibis-w2"
_AUTO_TITLE: Final = "autotitlecanary-otter-w2"
_ORG_INSTRUCTIONS: Final = "orgcanary-instructions-mole-w2"
_PERSONAL_INSTRUCTIONS: Final = "personalcanary-instructions-vole-w2"
_LEGACY_SESSION: Final = "legacycanary-session-w2"

_RECALL: Final = ToolCall(
    tool="memory", action="recall", args={"key": _ARG_CANARY}, tool_call_id="call-w2-recall"
)
_CREATE: Final = ToolCall(
    tool="google_calendar",
    action="create",
    args={"title": _EVENT_CANARY},
    tool_call_id="call-w2-create",
)
_LIST: Final = ToolCall(tool="memory", action="list", args={}, tool_call_id="call-w2-list")


# ---------------------------------------------------------------------------
# The fake clock, the fake LLM, the fake tools
# ---------------------------------------------------------------------------


class _Clock:
    """The fake ``request_timing._clock``: seconds, moved only by ``advance``."""

    def __init__(self) -> None:
        self.now = 64.0

    def __call__(self) -> float:
        return self.now

    def advance(self, ms: float) -> None:
        self.now += ms / 1000


@dataclass(frozen=True)
class _LLMCall:
    """One LLM call: its kind, the turn's user message and what had happened when it began."""

    kind: str  # "chat" (JSON), "stream" (SSE) or "title"
    message: str  # the last user message ("" for a title call)
    statements: int  # FakeDb statements recorded so far
    lines: int  # timing lines logged so far
    tools: tuple[str, ...]  # the offered tool names, sorted


class _TimedLLM:
    """Per user message, the n-th call of a turn asks for the n-th scripted tool call
    (counted by the assistant turns after that message), then answers ``_REPLY``.
    Each call moves the fake clock (see the module docstring) and is recorded; a call
    with ``max_tokens`` is a chat-title call. The first JSON call of ``park_on``'s turn
    sets ``parked`` and waits for ``release`` (bounded)."""

    provider = "infomaniak"

    def __init__(self, clock: _Clock, db: FakeDb, lines: Callable[[], int]) -> None:
        self._clock = clock
        self._db = db
        self._lines = lines
        self._scripts: dict[str, list[ToolCall]] = {}
        self.calls: list[_LLMCall] = []
        self.park_on: str | None = None
        self.parked = asyncio.Event()
        self.release = asyncio.Event()

    def script(self, message: str, *calls: ToolCall) -> None:
        self._scripts[message] = list(calls)

    def kinds(self) -> list[str]:
        return [call.kind for call in self.calls]

    def _begin(
        self, kind: str, messages: list[LLMMessage], tools: list[dict[str, Any]] | None
    ) -> ToolCall | None:
        """Record the call; the scripted tool call it asks for, or None (it answers)."""
        message, step = "", None
        if kind != "title":
            last = max(index for index, m in enumerate(messages) if m.role == "user")
            message = str(messages[last].content)
            done = sum(1 for m in messages[last + 1 :] if m.role == "assistant")
            steps = self._scripts.get(message, [])
            step = steps[done] if done < len(steps) else None
        offered = tuple(sorted(str(tool["function"]["name"]) for tool in tools or []))
        self.calls.append(_LLMCall(kind, message, len(self._db.calls), self._lines(), offered))
        return step

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if max_tokens is not None:
            self._begin("title", messages, tools)
            self._clock.advance(_TITLE_MS)
            return LLMResponse(content=_AUTO_TITLE)
        step = self._begin("chat", messages, tools)
        if self.park_on == self.calls[-1].message and not self.parked.is_set():
            self.parked.set()
            await asyncio.wait_for(self.release.wait(), _WAIT_S)
        if step is not None:
            self._clock.advance(_TOOL_STEP_MS)
            return LLMResponse(content=_PREAMBLE, tool_calls=[step])
        self._clock.advance(_ANSWER_MS)
        return LLMResponse(content=_REPLY)

    def chat_stream(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        return self._play(self._begin("stream", messages, tools))

    async def _play(self, step: ToolCall | None) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        if step is not None:
            self._clock.advance(_TOOL_STEP_FIRST_MS)
            yield LLMStreamDelta(content=_PREAMBLE)
            self._clock.advance(_TOOL_STEP_MS - _TOOL_STEP_FIRST_MS)
            yield LLMResponse(content=_PREAMBLE, tool_calls=[step])
            return
        self._clock.advance(_ANSWER_FIRST_MS)
        yield LLMStreamDelta(content=_REPLY)
        self._clock.advance(_ANSWER_MS - _ANSWER_FIRST_MS)
        yield LLMResponse(content=_REPLY)

    async def close(self) -> None:
        """Nothing to close."""


class _KeyArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)


class _EventArgs(BaseModel):
    title: str = Field(min_length=1, max_length=100)


class _MailArgs(BaseModel):
    message_id: str = Field(min_length=1, max_length=50)


@dataclass
class _Tools:
    """The handlers that ran, in order."""

    ran: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Run:
    """One ``Agent.run`` call: its keywords and the statements recorded when it began."""

    kwargs: dict[str, Any]
    statements: int


# ---------------------------------------------------------------------------
# The harness
# ---------------------------------------------------------------------------


def _timing_module() -> Any:
    """``admino.request_timing``, or None before GH-244 (the line tests then fail)."""
    try:
        from admino import request_timing
    except ImportError:
        return None
    return request_timing


def _timed_pool(db: FakeDb) -> Any:
    """``database.TimedPool(db.pool)``; the plain pool before GH-244 (nothing is timed)."""
    from admino import database

    timed = getattr(database, "TimedPool", None)
    return db.pool if timed is None else timed(db.pool)


def _module_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Every captured record of the timing module (by logger name or source file)."""
    return [
        record
        for record in caplog.records
        if record.name == _LOGGER
        or record.name.startswith(_LOGGER + ".")
        or Path(record.pathname).name == "request_timing.py"
    ]


@dataclass
class _Harness:
    """The app, its client and fakes, and what the test reads back."""

    world: World
    clock: _Clock
    llm: _TimedLLM
    tools: _Tools
    app: FastAPI
    client: TestClient
    runtime: Any
    caplog: pytest.LogCaptureFixture
    runs: list[_Run]

    @property
    def db(self) -> FakeDb:
        return self.world.db

    def records(self) -> list[logging.LogRecord]:
        return _module_records(self.caplog)

    def lines(self) -> list[str]:
        """The module's lines; each is an INFO record of ``admino.request_timing`` that
        fully matches the contract's regex (nothing else of the module logs)."""
        found = []
        for record in self.records():
            message = record.getMessage()
            assert (record.name, record.levelname) == (_LOGGER, "INFO"), (
                record.name,
                record.levelname,
                message,
            )
            assert _LINE_RE.fullmatch(message), message
            found.append(message)
        return found

    def line_of(self, response: httpx.Response) -> str:
        """The one line naming the response's ``X-Request-ID``."""
        request_id = response.headers["x-request-id"]
        prefix = f"chat timings: request_id={request_id} "
        found = [line for line in self.lines() if line.startswith(prefix)]
        assert len(found) == 1, (response.status_code, request_id, self.lines())
        return found[0]


def _watched_runtime(monkeypatch: pytest.MonkeyPatch, db: FakeDb) -> Any:
    """A real ``ChatRuntime`` recording, at every ``hold()`` call, the chat and the
    number of statements recorded so far (before it waits or refuses)."""
    from admino.chat_runtime import ChatRuntime

    class _Watched(ChatRuntime):
        def __init__(self) -> None:
            super().__init__(max_entries=64, idle_s=900.0)
            self.holds: list[tuple[uuid.UUID, int]] = []

        def hold(self, chat_id: uuid.UUID, owner_user_id: uuid.UUID, **kwargs: Any) -> Any:
            self.holds.append((chat_id, len(db.calls)))
            return super().hold(chat_id, owner_user_id, **kwargs)

    runtime = _Watched()
    monkeypatch.setattr(server, "_chat_runtime", runtime)
    return runtime


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
def clock(world: World, monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """The fake clock behind ``request_timing._clock``; every FakeDb statement moves it
    2.0 ms, and ``get_pool()`` answers ``database.TimedPool(db.pool)``."""
    fake = _Clock()
    timing = _timing_module()
    if timing is not None:
        monkeypatch.setattr(timing, "_clock", fake)
    db = world.db
    handle = db.handle

    def timed_handle(*args: Any, **kwargs: Any) -> Any:
        fake.advance(_STATEMENT_MS)
        return handle(*args, **kwargs)

    monkeypatch.setattr(db, "handle", timed_handle)
    monkeypatch.setattr("admino.database.get_pool", lambda: _timed_pool(db))
    return fake


@pytest.fixture()
def tools(clock: _Clock, monkeypatch: pytest.MonkeyPatch) -> _Tools:
    """An unfrozen registry holding memory.recall (allow, 7 ms), google_calendar.create
    (confirm, 7 ms) and gmail.read (allow; residency-blocked); restored afterwards."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    seen = _Tools()

    async def recall(args: _KeyArgs, **_: Any) -> str:
        seen.ran.append("memory.recall")
        clock.advance(_TOOL_MS)
        return _OUTPUT_CANARY

    async def create(args: _EventArgs, **_: Any) -> str:
        seen.ran.append("google_calendar.create")
        clock.advance(_TOOL_MS)
        return f"Created event {_OUTPUT_CANARY}"

    async def read(args: _MailArgs, **_: Any) -> str:
        seen.ran.append("gmail.read")
        return "No new mail."

    register: Any = registry.register_tool
    register("memory", "recall", "Recall a note (GH-244)", _KeyArgs, side_effect=False)(recall)
    register("google_calendar", "create", "Create an event (GH-244)", _EventArgs, side_effect=True)(
        create
    )
    register("gmail", "read", "Read an email (GH-244)", _MailArgs, side_effect=False)(read)
    return seen


@pytest.fixture()
def h(
    world: World,
    clock: _Clock,
    tools: _Tools,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> _Harness:
    """The app around a REAL Agent (real tool-call recorder) and the timed fake LLM."""
    caplog.set_level(logging.DEBUG)

    def count_lines() -> int:
        return sum(1 for record in _module_records(caplog) if record.name == _LOGGER)

    llm = _TimedLLM(clock, world.db, count_lines)
    agent = Agent(
        llm_client=llm,  # type: ignore[arg-type]
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    runs: list[_Run] = []
    real_run = agent.run

    async def run(*args: Any, **kwargs: Any) -> Any:
        runs.append(_Run(dict(kwargs), len(world.db.calls)))
        return await real_run(*args, **kwargs)

    agent.run = run  # type: ignore[method-assign]
    app: FastAPI = create_app(agent=agent, config=make_config())
    runtime = _watched_runtime(monkeypatch, world.db)
    return _Harness(
        world=world,
        clock=clock,
        llm=llm,
        tools=tools,
        app=app,
        client=make_client(app, raise_server_exceptions=False),
        runtime=runtime,
        caplog=caplog,
        runs=runs,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f}"


def _line(
    response: httpx.Response,
    route: str,
    status: int,
    db_queries: int,
    *,
    before: int | None = None,
    llm_start: float | None = None,
    first_byte: float | None = None,
    llm_ms: float = 0.0,
    tool_ms: float = 0.0,
) -> str:
    """The expected line: ``db_ms`` is 2.0 ms per statement and ``total_ms`` the
    request's DB, LLM and tool time (nothing else moves the fake clock)."""
    db_ms = db_queries * _STATEMENT_MS
    total = db_ms + llm_ms + tool_ms
    return (
        f"chat timings: request_id={response.headers['x-request-id']} route={route} "
        f"status={status} db_queries={db_queries} "
        f"db_queries_before_llm={'-' if before is None else before} db_ms={db_ms:.1f} "
        f"llm_start_ms={_ms(llm_start)} llm_first_byte_ms={_ms(first_byte)} "
        f"llm_ms={llm_ms:.1f} tool_ms={tool_ms:.1f} total_ms={total:.1f}"
    )


def _tables(call: Call) -> frozenset[str]:
    return frozenset(_TABLE_RE.findall(call.normalized))


def _kind(call: Call) -> str:
    """``session`` (names sessions), ``turn_setup`` (T1's tables), ``turn_load`` (T2's
    tables) or ``other:<tables>``."""
    tables = _tables(call)
    if "sessions" in tables:
        return "session"
    if tables >= _T1_TABLES:
        return "turn_setup"
    if tables >= _T2_TABLES:
        return "turn_load"
    return "other:" + ",".join(sorted(tables))


def _kinds(calls: list[Call]) -> list[str]:
    return [_kind(call) for call in calls]


def _tenant(account: Account) -> TenantContext:
    assert account.org_id is not None
    return TenantContext(org_id=account.org_id, user_id=account.user_id, role=account.role)  # type: ignore[arg-type]


def _send(
    h: _Harness,
    account: Account | None,
    chat_id: uuid.UUID,
    message: str = _MESSAGE,
    mode: str = "json",
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages (``mode`` "sse": with Accept text/event-stream)."""
    sent = {
        **(account.cookie if account is not None else {}),
        **(_SSE if mode == "sse" else {}),
        **(headers or {}),
    }
    return h.client.post(f"/api/chats/{chat_id}/messages", headers=sent, json={"message": message})


def _legacy(h: _Harness, account: Account, message: str = _MESSAGE) -> httpx.Response:
    """POST /api/message with the legacy session id."""
    return h.client.post(
        "/api/message",
        headers=account.cookie,
        json={"message": message, "session_id": _LEGACY_SESSION},
    )


def _confirm(
    h: _Harness, account: Account, chat_id: uuid.UUID, confirmation_id: str, *, approved: bool
) -> httpx.Response:
    """POST /api/confirm/{confirmation_id} for the chat (JSON)."""
    return h.client.post(
        f"/api/confirm/{confirmation_id}",
        headers=account.cookie,
        json={"confirmation_id": confirmation_id, "approved": approved, "chat_id": str(chat_id)},
    )


def _events(response: httpx.Response) -> list[str]:
    """The event names of a streamed answer (a 200 ``text/event-stream``)."""
    content_type = response.headers.get("content-type", "")
    assert (response.status_code, content_type.split(";")[0]) == (200, "text/event-stream"), (
        response.status_code,
        response.text[:400],
    )
    return [
        line.removeprefix("event:").strip()
        for line in re.split(r"\r\n|\r|\n", response.text)
        if line.startswith("event:")
    ]


def _assert_answered(response: httpx.Response, mode: str) -> None:
    """The turn ran to a final answer (JSON) or streamed to ``done`` without an error."""
    if mode == "json":
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "final", response.text
    else:
        events = _events(response)
        assert (events[0], events[-1], "error" in events) == ("run_started", "done", False), events


def _chat_with_history(
    db: FakeDb, account: Account, *, legacy_session_id: str | None = None
) -> uuid.UUID:
    """A user-titled chat of ``account`` (so no title call) holding an earlier exchange."""
    chat_id = db.add_chat(
        account.user_id,
        title=_CHAT_TITLE,
        title_source="user",
        legacy_session_id=legacy_session_id,
    )
    for role, content in (
        ("user", "Earlier question w2"),
        ("assistant", "Earlier answer w2"),
        ("user", "Another question w2"),
        ("assistant", "Another answer w2"),
    ):
        db.add_chat_message(chat_id, role, content)
    return chat_id


def _block(call: ToolCall) -> dict[str, Any]:
    return {
        "type": "tool_use",
        "id": call.tool_call_id,
        "name": f"{call.tool}.{call.action}",
        "input": dict(call.args),
    }


def _seed_tool_history(db: FakeDb, chat_id: uuid.UUID) -> None:
    """Seven messages: a tool turn (two calls, two results) and two exchanges."""
    db.add_chat_message(chat_id, "user", "First question w2")
    db.add_chat_message(chat_id, "assistant", "", tool_use_blocks=[_block(_RECALL), _block(_LIST)])
    db.add_chat_message(chat_id, "tool", "Recalled w2", tool_call_id=_RECALL.tool_call_id)
    db.add_chat_message(chat_id, "tool", "Listed w2", tool_call_id=_LIST.tool_call_id)
    db.add_chat_message(chat_id, "assistant", "First answer w2")
    db.add_chat_message(chat_id, "user", "Second question w2")
    db.add_chat_message(chat_id, "assistant", "Second answer w2")


def _customise_org_a(db: FakeDb, editor: Account) -> None:
    """Non-default values in every T1 input of org A and the Editor; org B differs."""
    db.add_permissions(ORG_ID, {"memory": {"recall": "confirm"}, "gmail": {"send": "confirm"}})
    db.add_permissions(OTHER_ORG_ID, {"memory": {"recall": "deny"}})
    db.org_settings[ORG_ID]["instructions"] = _ORG_INSTRUCTIONS
    db.org_settings[ORG_ID]["google_drive_enabled"] = False
    db.org_settings[OTHER_ORG_ID]["instructions"] = "Org B instructions w2"
    db.add_org(ORG_ID, default_response_language="fr")
    db.users[editor.user_id].update(
        response_language="de",
        timezone="Europe/Berlin",
        personal_instructions=_PERSONAL_INSTRUCTIONS,
    )


def _dump(messages: Any) -> list[dict[str, Any]]:
    return [message.model_dump() for message in messages]


def _stored_limits(monkeypatch: pytest.MonkeyPatch, **limits: int) -> None:
    """Store platform limits in the settings cache (no statement) for the next requests."""
    stored = default_test_platform_settings()
    updated = stored.limits.model_copy(update=limits)
    monkeypatch.setattr(
        scoped_settings, "_platform_cache", stored.model_copy(update={"limits": updated})
    )


# ---------------------------------------------------------------------------
# 1. The send path: three statements before the LLM call (C3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", _MODES)
def test_chat_timing_send_runs_session_turn_setup_and_turn_load_before_the_llm(
    h: _Harness, mode: str
) -> None:
    """In a chat with history: the session lookup, T1, the chat's hold, T2, then the LLM
    call. The one line of the request says ``db_queries_before_llm=3`` and counts every
    statement (the store included); JSON's first byte is the response, SSE's the first
    stream item."""
    editor = h.world.a["editor"]
    chat_id = _chat_with_history(h.db, editor)
    since = len(h.db.calls)

    response = _send(h, editor, chat_id, mode=mode)

    _assert_answered(response, mode)
    (call,) = h.llm.calls
    assert _kinds(h.db.calls[since : call.statements]) == ["session", "turn_setup", "turn_load"]
    assert [statements for _, statements in h.runtime.holds] == [since + 2]
    first = _ANSWER_MS if mode == "json" else _ANSWER_FIRST_MS
    assert h.lines() == [
        _line(
            response,
            "chat_message",
            200,
            len(h.db.calls) - since,
            before=3,
            llm_start=_SETUP_MS,
            first_byte=_SETUP_MS + first,
            llm_ms=_ANSWER_MS,
        )
    ]


@pytest.mark.parametrize("mode", _MODES)
def test_chat_timing_send_run_gets_what_the_old_loaders_read(
    h: _Harness, mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With non-default values in every T1 input (org A's matrix with a promoted pair, a
    service off, the org's instructions and language, the Editor's language, timezone and
    personal instructions; org B differs) and seven stored messages under a stored
    ``max_context_messages`` of 5: the run gets exactly what ``load_tool_policy``,
    ``load_prompt_context`` and ``load_turn`` (its history; GH-190 removed
    ``load_recent_history``, which read the same) read on the same database and the
    chat's ``external_content`` flag, after three statements."""
    db = h.db
    editor = h.world.a["editor"]
    _stored_limits(monkeypatch, max_context_messages=5)
    _customise_org_a(db, editor)
    chat_id = db.add_chat(
        editor.user_id, title=_CHAT_TITLE, title_source="user", external_content=True
    )
    _seed_tool_history(db, chat_id)
    tenant = _tenant(editor)
    policy = asyncio.run(org_permissions.load_tool_policy(db.pool, tenant))
    context = asyncio.run(scoped_settings.load_prompt_context(db.pool, tenant))
    history = asyncio.run(chats.load_turn(db.pool, tenant, chat_id, limit=5)).history
    # The expectations hold the non-default values (so the comparison means something).
    assert (
        ("gmail", "send") in policy.promoted,
        policy.permissions.tools["memory"].actions["recall"],
        policy.enabled_tools["google_drive"],
        context.org_instructions,
        context.personal_instructions,
        context.timezone,
        [message.content for message in history],
    ) == (
        True,
        "confirm",
        False,
        _ORG_INSTRUCTIONS,
        _PERSONAL_INSTRUCTIONS,
        "Europe/Berlin",
        ["First answer w2", "Second question w2", "Second answer w2"],
    )
    since = len(db.calls)

    response = _send(h, editor, chat_id, mode=mode)

    _assert_answered(response, mode)
    (run,) = h.runs
    assert run.kwargs["tool_policy"] == policy
    assert run.kwargs["prompt_context"] == context
    assert _dump(run.kwargs["history"]) == _dump(history)
    assert run.kwargs["earlier_external_content"] is True
    (call,) = h.llm.calls
    assert call.statements - since == 3


def test_chat_timing_residency_org_send_is_not_offered_the_blocked_tools(h: _Harness) -> None:
    """Org A under data residency (read by T1), the Swiss provider: the run's policy is
    ``load_tool_policy``'s (residency on, gmail and google_calendar off), the LLM is
    offered memory.recall only, after three statements."""
    db = h.db
    editor = h.world.a["editor"]
    db.add_org(ORG_ID, data_residency=True)
    chat_id = _chat_with_history(db, editor)
    policy = asyncio.run(org_permissions.load_tool_policy(db.pool, _tenant(editor)))
    assert (policy.data_residency, policy.enabled_tools["gmail"]) == (True, False)
    since = len(db.calls)

    response = _send(h, editor, chat_id)

    _assert_answered(response, "json")
    (run,) = h.runs
    assert run.kwargs["tool_policy"] == policy
    (call,) = h.llm.calls
    assert call.tools == ("memory.recall",)
    assert h.line_of(response) == _line(
        response,
        "chat_message",
        200,
        len(db.calls) - since,
        before=3,
        llm_start=_SETUP_MS,
        first_byte=_SETUP_MS + _ANSWER_MS,
        llm_ms=_ANSWER_MS,
    )


def test_chat_timing_residency_org_send_refuses_a_non_swiss_provider_without_an_llm_call(
    h: _Harness,
) -> None:
    """Org A under data residency, the Anthropic provider: after the session lookup, T1
    and T2 the run ends ``residency_blocked`` with no LLM call; the line has ``-`` for
    every LLM field."""
    db = h.db
    editor = h.world.a["editor"]
    db.add_org(ORG_ID, data_residency=True)
    h.llm.provider = "anthropic"
    chat_id = _chat_with_history(db, editor)
    since = len(db.calls)

    response = _send(h, editor, chat_id)

    assert response.status_code == 200, response.text
    assert (response.json()["status"], response.json()["error_code"]) == (
        "error",
        "residency_blocked",
    )
    assert h.llm.calls == []
    (run,) = h.runs
    assert run.kwargs["tool_policy"].data_residency is True
    assert _kinds(db.calls[since : run.statements]) == ["session", "turn_setup", "turn_load"]
    assert h.line_of(response) == _line(response, "chat_message", 200, len(db.calls) - since)


# ---------------------------------------------------------------------------
# 2. Refusals keep their order and statements
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", ["unknown", "other_org", "colleague", "trashed"])
def test_chat_timing_unreachable_chat_is_the_identical_404_after_turn_setup_only(
    h: _Harness, case: str
) -> None:
    """Unknown id, another org's chat, a colleague's chat and the caller's trashed chat:
    the identical 404 ``chat_not_found`` in both modes, after the session lookup and T1
    only (no hold, no T2, no run, no LLM call), each with one line of status 404."""
    db = h.db
    editor = h.world.a["editor"]
    if case == "unknown":
        chat_id = uuid.uuid4()
    elif case == "other_org":
        chat_id = _chat_with_history(db, h.world.b["editor"])
    elif case == "colleague":
        chat_id = _chat_with_history(db, h.world.a["org_admin"])
    else:
        chat_id = _chat_with_history(db, editor)
        db.chats[chat_id]["deleted_at"] = datetime.now(UTC)

    for mode in _MODES:
        since = len(db.calls)
        response = _send(h, editor, chat_id, mode=mode)

        assert (response.status_code, response.json()) == (404, CHAT_NOT_FOUND), mode
        assert _kinds(db.calls[since:]) == ["session", "turn_setup"], mode
        assert h.line_of(response) == _line(response, "chat_message", 404, 2), mode
    assert (h.runtime.holds, h.runs, h.llm.calls) == ([], [], [])
    assert len(h.lines()) == len(_MODES)


_REFUSALS: Final[dict[str, tuple[int, dict[str, str], int]]] = {
    # case: (status, body, statements: the session lookup or nothing)
    "no_session": (401, UNAUTHORIZED, 0),
    "super_admin": (403, FORBIDDEN, 1),
    "cross_site": (403, _CSRF_REFUSED, 0),
    "over_stored_length": (422, _TOO_LONG, 1),
    "rate_limited": (429, _RATE_LIMITED, 1),
}


@pytest.mark.parametrize("case", list(_REFUSALS))
def test_chat_timing_refusal_before_the_turn_setup_logs_one_line(
    h: _Harness, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """401 without a session, the Super Admin's 403 (no chat.send), the CSRF 403, a
    message over the stored ``max_message_length`` (422, before the owner check) and the
    429 of a spent bucket: no statement but the session lookup, no run, and exactly one
    line with the status and ``-`` LLM fields."""
    status, body, statements = _REFUSALS[case]
    editor = h.world.a["editor"]
    chat_id = _chat_with_history(h.db, editor)
    account: Account | None = editor
    message, headers = _MESSAGE, {}
    if case == "no_session":
        account = None
    elif case == "super_admin":
        account = h.world.super_admin
    elif case == "cross_site":
        headers = {"Sec-Fetch-Site": "cross-site"}
    elif case == "over_stored_length":
        _stored_limits(monkeypatch, max_message_length=10)
        message = "m" * 11
    else:
        monkeypatch.setitem(server._RATE_LIMITS, "/api/message", (0.0001, 1))
        _assert_answered(_send(h, editor, chat_id), "json")  # spends the bucket's burst
    lines, runs = len(h.lines()), len(h.runs)
    since = len(h.db.calls)

    response = _send(h, account, chat_id, message, headers=headers)

    assert (response.status_code, response.json()) == (status, body)
    assert _kinds(h.db.calls[since:]) == ["session"] * statements
    assert len(h.runs) == runs
    assert len(h.lines()) == lines + 1
    assert h.line_of(response) == _line(response, "chat_message", status, statements)


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the caller's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50002))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _post(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID, message: str
) -> httpx.Response:
    return await http.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
    )


async def _until_parked(llm: _TimedLLM, request: asyncio.Task[httpx.Response]) -> None:
    """Wait until the first turn's LLM call is parked; fail at once if it ended first."""
    parked = asyncio.ensure_future(llm.parked.wait())
    done, _ = await asyncio.wait(
        {parked, request}, timeout=_WAIT_S, return_when=asyncio.FIRST_COMPLETED
    )
    if parked not in done:
        parked.cancel()
        answer = request.result().text if request.done() else "no answer"
        pytest.fail(f"the first turn never reached the LLM: {answer}")


async def test_chat_timing_busy_chat_is_409_after_the_turn_setup_without_the_turn_load(
    h: _Harness,
) -> None:
    """While turn A's LLM call is parked inside the chat's hold, turn B gets the 409
    ``run_active`` after the session lookup and T1 (its hold refused once T1 ran), with
    no T2 and no LLM call; B's line has status 409 and ``-`` LLM fields, A's has 200."""
    db = h.db
    editor = h.world.a["editor"]
    chat_id = _chat_with_history(db, editor)
    h.llm.park_on = _FIRST_MESSAGE

    async with _async_client(h.app) as http:
        first = asyncio.create_task(_post(http, editor, chat_id, _FIRST_MESSAGE))
        try:
            await _until_parked(h.llm, first)
            since = len(db.calls)
            refused = await asyncio.wait_for(_post(http, editor, chat_id, _MESSAGE), _WAIT_S)
            refused_calls = db.calls[since:]
            refused_hold = h.runtime.holds[-1][1]
        finally:
            h.llm.release.set()
        ran = await asyncio.wait_for(first, _WAIT_S)

    assert (refused.status_code, refused.json()) == (409, _RUN_ACTIVE)
    assert _kinds(refused_calls) == ["session", "turn_setup"]
    assert refused_hold == since + 2
    assert [call.message for call in h.llm.calls] == [_FIRST_MESSAGE]
    assert h.line_of(refused) == _line(refused, "chat_message", 409, 2)
    assert ran.status_code == 200, ran.text
    assert " route=chat_message status=200 " in h.line_of(ran)
    assert len(h.lines()) == 2


# ---------------------------------------------------------------------------
# 3. One line per request on each turn route, none elsewhere
# ---------------------------------------------------------------------------


def test_chat_timing_legacy_message_route_logs_one_message_line(h: _Harness) -> None:
    """POST /api/message (its pre-hold reads unchanged): one line, ``route=message``,
    its statements before the LLM call and the answer's times."""
    editor = h.world.a["editor"]
    chat_id = _chat_with_history(h.db, editor, legacy_session_id=_LEGACY_SESSION)
    since = len(h.db.calls)

    response = _legacy(h, editor)

    assert (response.status_code, response.json()["chat_id"]) == (200, str(chat_id)), response.text
    (call,) = h.llm.calls
    before = call.statements - since
    assert h.lines() == [
        _line(
            response,
            "message",
            200,
            len(h.db.calls) - since,
            before=before,
            llm_start=before * _STATEMENT_MS,
            first_byte=before * _STATEMENT_MS + _ANSWER_MS,
            llm_ms=_ANSWER_MS,
        )
    ]


def _awaiting_confirmation(h: _Harness, account: Account, chat_id: uuid.UUID) -> str:
    """Run a turn asking for google_calendar.create (confirm); its confirmation id."""
    h.llm.script(_BOOK_MESSAGE, _CREATE)
    asked = _send(h, account, chat_id, _BOOK_MESSAGE)
    assert (asked.status_code, asked.json()["status"]) == (200, "awaiting_confirmation"), asked.text
    confirmation_id: str = asked.json()["pending_confirmation"]["confirmation_id"]
    return confirmation_id


def test_chat_timing_confirm_approval_logs_one_line_with_the_resumed_tool(h: _Harness) -> None:
    """POST /api/confirm approving: one ``route=confirm`` line whose ``tool_ms`` is the
    resumed dispatch (7.0 ms, before the LLM call) and ``llm_ms`` the follow-up answer."""
    editor = h.world.a["editor"]
    chat_id = _chat_with_history(h.db, editor)
    confirmation_id = _awaiting_confirmation(h, editor, chat_id)
    lines = len(h.lines())
    since = len(h.db.calls)

    response = _confirm(h, editor, chat_id, confirmation_id, approved=True)

    assert (response.status_code, response.json()["status"]) == (200, "final"), response.text
    assert h.tools.ran == ["google_calendar.create"]
    resumed = h.llm.calls[-1]
    before = resumed.statements - since
    started = before * _STATEMENT_MS + _TOOL_MS
    assert len(h.lines()) == lines + 1
    assert h.line_of(response) == _line(
        response,
        "confirm",
        200,
        len(h.db.calls) - since,
        before=before,
        llm_start=started,
        first_byte=started + _ANSWER_MS,
        llm_ms=_ANSWER_MS,
        tool_ms=_TOOL_MS,
    )


def test_chat_timing_confirm_denial_logs_one_line_without_llm_or_tool_time(h: _Harness) -> None:
    """POST /api/confirm denying: one ``route=confirm`` line with ``-`` LLM fields and
    no tool time (nothing is dispatched or asked)."""
    editor = h.world.a["editor"]
    chat_id = _chat_with_history(h.db, editor)
    confirmation_id = _awaiting_confirmation(h, editor, chat_id)
    lines, calls = len(h.lines()), len(h.llm.calls)
    since = len(h.db.calls)

    response = _confirm(h, editor, chat_id, confirmation_id, approved=False)

    assert (response.status_code, response.json()["status"]) == (200, "final"), response.text
    assert (h.tools.ran, len(h.llm.calls)) == ([], calls)
    assert len(h.lines()) == lines + 1
    assert h.line_of(response) == _line(response, "confirm", 200, len(h.db.calls) - since)


def test_chat_timing_other_chat_routes_log_no_line(h: _Harness) -> None:
    """POST /api/chats, GET /api/chats, GET /api/chats/{id} and POST
    /api/chats/{id}/stop log nothing; a send right after logs its one line."""
    editor = h.world.a["editor"]
    chat_id = _chat_with_history(h.db, editor)
    responses = [
        h.client.post("/api/chats", headers=editor.cookie, json={}),
        h.client.get("/api/chats", headers=editor.cookie),
        h.client.get(f"/api/chats/{chat_id}", headers=editor.cookie),
        h.client.post(f"/api/chats/{chat_id}/stop", headers=editor.cookie),
    ]
    assert [response.status_code for response in responses] == [201, 200, 200, 200]
    assert h.lines() == []

    turn = _send(h, editor, chat_id)

    _assert_answered(turn, "json")
    assert len(h.lines()) == 1
    assert h.line_of(turn).startswith("chat timings: ")


# ---------------------------------------------------------------------------
# 4. The values: LLM calls summed, the tool, the first byte, the title not counted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", _MODES)
def test_chat_timing_tool_turn_line_sums_both_llm_calls_and_the_tool(
    h: _Harness, mode: str
) -> None:
    """A turn calling memory.recall: two LLM calls (40.0 + 25.0 ms), one dispatch
    (7.0 ms), the recorder's statement counted; the first byte is the first call's
    response (JSON, 40.0 ms in) or its first stream item (SSE, 12.0 ms in)."""
    editor = h.world.a["editor"]
    chat_id = _chat_with_history(h.db, editor)
    h.llm.script(_TOOL_MESSAGE, _RECALL)
    since = len(h.db.calls)

    response = _send(h, editor, chat_id, _TOOL_MESSAGE, mode)

    _assert_answered(response, mode)
    kind = "chat" if mode == "json" else "stream"
    assert (h.llm.kinds(), h.tools.ran) == ([kind, kind], ["memory.recall"])
    assert len(h.db.audit_rows("tool.call")) == 1
    first = _TOOL_STEP_MS if mode == "json" else _TOOL_STEP_FIRST_MS
    assert h.lines() == [
        _line(
            response,
            "chat_message",
            200,
            len(h.db.calls) - since,
            before=3,
            llm_start=_SETUP_MS,
            first_byte=_SETUP_MS + first,
            llm_ms=_TOOL_STEP_MS + _ANSWER_MS,
            tool_ms=_TOOL_MS,
        )
    ]


@pytest.mark.parametrize("mode", _MODES)
def test_chat_timing_title_call_of_a_first_exchange_is_not_counted(h: _Harness, mode: str) -> None:
    """An untitled chat's first exchange: the title call (JSON: the background task;
    SSE: before ``done``) starts once the turn's line is written, and its 500 ms and
    its statements are in no line; the request logs exactly one line."""
    editor = h.world.a["editor"]
    chat_id = h.db.add_chat(editor.user_id)
    since = len(h.db.calls)

    response = _send(h, editor, chat_id, mode=mode)

    _assert_answered(response, mode)
    turn, title = h.llm.calls
    assert (turn.kind, title.kind) == ("chat" if mode == "json" else "stream", "title")
    chat = h.db.chat_row(chat_id)
    assert chat is not None
    assert chat["title"] == _AUTO_TITLE
    assert title.lines == 1
    first = _ANSWER_MS if mode == "json" else _ANSWER_FIRST_MS
    assert h.lines() == [
        _line(
            response,
            "chat_message",
            200,
            title.statements - since,
            before=3,
            llm_start=_SETUP_MS,
            first_byte=_SETUP_MS + first,
            llm_ms=_ANSWER_MS,
        )
    ]


# ---------------------------------------------------------------------------
# 5. No content in the timing lines
# ---------------------------------------------------------------------------


def test_chat_timing_lines_hold_no_content_and_no_ids(h: _Harness) -> None:
    """A JSON and an SSE tool turn in a titled chat, an untitled chat's first exchange
    (titled automatically), a legacy turn, and a confirmation asked and approved, with
    logging configured as main() does (tests/log_capture.py, JSON lines): six lines,
    and no message, title, tool name, argument or output, reply, instruction, email,
    token, legacy session id, confirmation id or chat/user/org id in any written line
    or raw record of the module."""
    db = h.db
    editor = h.world.a["editor"]
    _customise_org_a(db, editor)
    db.add_permissions(ORG_ID, {"memory": {"recall": "allow"}})
    titled = _chat_with_history(db, editor)
    untitled = db.add_chat(editor.user_id)
    legacy = _chat_with_history(db, editor, legacy_session_id=_LEGACY_SESSION)
    h.llm.script(_TOOL_MESSAGE, _RECALL)

    # Logging configured the way main() does (JSON lines), restored on exit.
    with configured_logging("DEBUG", "json") as logs:
        responses = [
            _send(h, editor, titled, _TOOL_MESSAGE, "json"),
            _send(h, editor, titled, _TOOL_MESSAGE, "sse"),
            _send(h, editor, untitled, _MESSAGE, "json"),
            _legacy(h, editor),
        ]
        confirmation_id = _awaiting_confirmation(h, editor, titled)
        responses.append(_confirm(h, editor, titled, confirmation_id, approved=True))

    assert [response.status_code for response in responses] == [200] * 5
    assert h.tools.ran == ["memory.recall", "memory.recall", "google_calendar.create"]
    untitled_row = db.chat_row(untitled)
    assert untitled_row is not None
    assert untitled_row["title"] == _AUTO_TITLE
    records = [
        record
        for record in logs.records
        if record.name.startswith(_LOGGER) or Path(record.pathname).name == "request_timing.py"
    ]
    lines = [record.getMessage() for record in records]
    assert [bool(_LINE_RE.fullmatch(line)) for line in lines] == [True] * 6, lines
    written = [line for line in logs.json_lines() if line["logger"] == _LOGGER]
    assert [line["message"] for line in written] == lines
    secrets = [
        _MESSAGE,
        _TOOL_MESSAGE,
        _BOOK_MESSAGE,
        _ARG_CANARY,
        _EVENT_CANARY,
        _OUTPUT_CANARY,
        _REPLY,
        _PREAMBLE,
        _CHAT_TITLE,
        _AUTO_TITLE,
        _ORG_INSTRUCTIONS,
        _PERSONAL_INSTRUCTIONS,
        _LEGACY_SESSION,
        confirmation_id,
        editor.email,
        editor.token,
        "memory",
        "recall",
        "google_calendar",
        "gmail",
        *(str(value) for value in (titled, untitled, legacy, editor.user_id, ORG_ID)),
        *(value.hex for value in (titled, untitled, legacy, editor.user_id, ORG_ID)),
    ]
    text = "\n".join(
        [
            *(json.dumps(line, ensure_ascii=False) for line in written),
            *(f"{record.msg!r} {record.args!r}" for record in records),
        ]
    ).casefold()
    assert [secret for secret in secrets if secret.casefold() in text] == []
