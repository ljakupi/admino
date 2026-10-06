"""Server stream plumbing audit fixes (GH-8, contract C12: security-audit-server-stream M-2, M-1).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py with the REAL ``admino.agent.Agent`` (real tool-call
recorder of ``main._build_tool_call_recorder()``) around a scripted streaming
LLM (``_ScriptLLM``: per user message, the first ``chat_stream`` call asks for
the scripted tool calls, every later one answers ``_FINAL_REPLY``). Fake tools
live in an isolated registry: ``memory.store`` (allowed, may park in its
handler until the test releases it) and ``google_calendar.create`` (confirm).

M-2, shutdown (the app's real ``server._lifespan``): ``_Shutdown`` replaces
the pool's ``init_pool``/``close_pool`` (the FakeDb pool stays usable) and every
background job (the reaper, the retention, session, org and throttle purges;
no SMTP, so no sender) with fakes that record each shutdown step and, at that
moment, what the world looks like: the ``tool.call`` audit rows, the watched
chats' stored messages and the fake tool's log. Pinned:
- a detached run whose client left (raw ASGI disconnect, the response already
  ended) while its tool call is parked: the shutdown neither cancels a job nor
  closes the pool while it runs; once the tool is released the run finishes
  (not cancelled), its ``tool.call`` row is written and its turn stored
  (``stopped``) BEFORE every job cancellation and before the pool closes;
- a run whose client is still connected: the shutdown sets the run's stop
  signal (the run makes no follow-up LLM call and is stored ``stopped``, the
  stream ends ``message_saved{stopped}``, ``done``) and still waits for it;
- the bound: ``server._DRAIN_TIMEOUT_S`` (30 seconds, read at shutdown time).
  Patched to 0.3 s with two runs parked in their tools, the shutdown waits
  about that long, then cancels the jobs and closes the pool while the runs
  are still parked, and logs (WARNING or above, an ``admino`` logger) the number
  of unfinished runs, 2, naming neither chat; no record carries a message or a
  tool argument;
- no detached run: the shutdown is today's (the jobs cancelled in today's
  order, then the pool closed), returns at once although the bound is 30 s,
  and logs no warning.

M-1 / L-3 (a frame never raises into the run): ``server._make_sse_event``, the
frame builder ``_RunFrames`` uses, is wrapped so that building one event fails
(a real ``ValidationError`` from ``SSEEvent``'s 65536 cap, by padding the
payload with ASCII-escaped CJK, as in the audit's probe; or a ``ValueError``
whose message carries the payload). A failing ``tool_call`` frame: the run
completes, the tool call is audited and stored with its record, the stream is
``run_started``, the deltas, ``message_saved{complete}``, ``done`` (only the
failed frame is missing). A failing ``confirm`` frame: the confirmation is kept
(GET /api/chats/{id} shows it pending), the stream is ``run_started``, the
gated call's ``tool_call``, ``message_saved{awaiting_confirmation}``, ``done``.
Each logs a record naming
the event and the exception class, and no record holds the payload, a tool
argument, the message or the reply.

Security notes:
- Every message, id and argument here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from pydantic import BaseModel, Field

from admino import event_stream, server
from admino import main as main_module
from admino.agent import Agent
from admino.llm import LLMResponse, LLMStreamDelta
from admino.models import AgentConfig, LLMMessage, ToolCall
from admino.server import create_app
from admino.tools import registry
from tests.tenancy_world import (
    CLIENT_IP,
    SESSION_COOKIE,
    build_world,
    make_config,
    seed_chat,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import AsyncIterator, Callable, Iterator

    from fastapi import FastAPI

    from tests.db_fakes import FakeDb
    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WAIT_S: Final = 5.0
_SSE: Final = {"Accept": "text/event-stream"}
_FINAL_REPLY: Final = "All done."
# The shutdown's bound for the detached runs (C12 M-2), pinned by name and value.
_DRAIN_BOUND: Final = "_DRAIN_TIMEOUT_S"
_DRAIN_BOUND_S: Final = 30.0
_SHORT_BOUND_S: Final = 0.3
# A shutdown that honours the short bound returns well within this.
_SHUTDOWN_LIMIT_S: Final = 3.0
# Loop turns that let a shutdown that doesn't wait run to its end.
_TURNS: Final = 200

_ARG_MARK: Final = "quokka-ledger-w10"
_OTHER_MARK: Final = "wombat-ledger-w10"
_SAVE: Final = "Save the quokka plan w10"
_SAVE_OTHER: Final = "Save the wombat plan w10"
_BOOK: Final = "Book the quokka offsite w10"
_STORE: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": "plan", "value": _ARG_MARK},
    tool_call_id="call-w10-store",
)
_STORE_OTHER: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": "plan", "value": _OTHER_MARK},
    tool_call_id="call-w10-other",
)
_CREATE: Final = ToolCall(
    tool="google_calendar",
    action="create",
    args={"title": _ARG_MARK},
    tool_call_id="call-w10-cal",
)
_STORED: Final = f"Stored memory: plan={_ARG_MARK}"
# 12000 x U+7684: 72000 characters once json.dumps escapes them, over SSEEvent's 65536.
_CJK: Final = chr(0x7684)
_PAD: Final = _CJK * 12000
# The message of the scripted ValueError carries this marker and the payload.
_REFUSAL_MARK: Final = "frame-refused-w10"
# The fake jobs in the order today's shutdown cancels them (no SMTP: no sender).
_JOBS: Final = ("reaper", "retention", "session-purge", "org-purge", "throttle-purge")

Row = tuple[str, str, str | None, str]


def _calls(*calls: ToolCall) -> LLMResponse:
    """An LLM answer asking for ``calls`` (no text)."""
    return LLMResponse(content="", tool_calls=list(calls))


# ---------------------------------------------------------------------------
# The scripted LLM and the fake tools
# ---------------------------------------------------------------------------


def _last_user(messages: list[LLMMessage]) -> str:
    """The content of the last user message (the turn being run)."""
    return next(str(m.content) for m in reversed(messages) if m.role == "user")


class _ScriptLLM:
    """Per user message: the first stream asks for the scripted calls, later ones answer
    ``_FINAL_REPLY`` (one delta, then the final response)."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self._plans: dict[str, list[LLMResponse]] = {}
        self.streams: list[str] = []
        self.title_calls = 0

    def plan(self, message: str, first: LLMResponse) -> None:
        """The answer of the first ``chat_stream`` call of ``message``'s turn."""
        self._plans[message] = [first]

    def _next(self, messages: list[LLMMessage]) -> LLMResponse:
        queued = self._plans.get(_last_user(messages), [])
        return queued.pop(0) if queued else LLMResponse(content=_FINAL_REPLY, done=True)

    def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        self.streams.append(_last_user(messages))
        return self._play(self._next(messages))

    async def _play(self, response: LLMResponse) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        if response.content:
            yield LLMStreamDelta(content=response.content)
        yield response

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if max_tokens is not None:
            self.title_calls += 1
            return LLMResponse(content="Model title w10", done=True)
        return self._next(messages)

    async def close(self) -> None:
        """Nothing to close."""


@dataclass(eq=False)
class _Park:
    """Where a tool waits: sets ``parked``, then waits (bounded) for ``release``."""

    parked: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)


class _StoreArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    value: str = Field(min_length=1, max_length=200)


class _EventArgs(BaseModel):
    title: str = Field(min_length=1, max_length=100)


@dataclass
class _Tools:
    """What the fake tools did, in order; ``park`` (shared by every memory.store call)."""

    log: list[str] = field(default_factory=list)
    park: _Park | None = None

    async def execute(self, label: str, park: _Park | None) -> None:
        """Log the start, wait in ``park`` if there is one, log the end (or the interruption)."""
        self.log.append(f"start {label}")
        if park is not None:
            park.parked.set()
            try:
                await asyncio.wait_for(park.release.wait(), _WAIT_S)
            except TimeoutError:
                self.log.append(f"timeout {label}")
                raise
            except asyncio.CancelledError:
                self.log.append(f"cancelled {label}")
                raise
        self.log.append(f"done {label}")

    def started(self) -> int:
        return sum(entry.startswith("start ") for entry in self.log)


# ---------------------------------------------------------------------------
# The lifespan probe
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Seen:
    """The world at one shutdown step."""

    audited: int
    stored: tuple[tuple[Row, ...], ...]
    tool_log: tuple[str, ...]


def _rows(db: FakeDb, chat_id: uuid.UUID) -> list[Row]:
    """The chat's stored messages by seq: (role, content, tool_call_id, status)."""
    return [
        (m["role"], m["content"], m["tool_call_id"], m["status"]) for m in db.messages_of(chat_id)
    ]


class _Shutdown:
    """Fakes for the lifespan's pool and background jobs; records every shutdown step
    (job cancelled, pool closed) with its time and what the world looked like then."""

    def __init__(self, db: FakeDb, tools: _Tools) -> None:
        self._db = db
        self._tools = tools
        self.chats: list[uuid.UUID] = []
        self.events: list[str] = []
        self.seen: dict[str, _Seen] = {}
        self.at: dict[str, float] = {}

    def record(self, step: str) -> None:
        self.events.append(step)
        self.at[step] = time.monotonic()
        self.seen[step] = _Seen(
            audited=len(self._db.audit_rows("tool.call")),
            stored=tuple(tuple(_rows(self._db, chat_id)) for chat_id in self.chats),
            tool_log=tuple(self._tools.log),
        )

    def job(self, name: str) -> Callable[..., Any]:
        """A fake background job: blocks until cancelled, recording the cancellation."""

        async def run(*_args: Any, **_kwargs: Any) -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.record(f"{name}-cancelled")
                raise

        return run

    async def init_pool(self, *_args: Any, **_kwargs: Any) -> Any:
        self.events.append("init_pool")
        return self._db.pool

    async def close_pool(self) -> None:
        self.record("close_pool")

    def steps(self) -> list[str]:
        """The shutdown steps so far."""
        return [event for event in self.events if event != "init_pool"]


@dataclass
class _Harness:
    """The lifespan of one test: started, shut down, and cleaned up whatever happened."""

    app: FastAPI
    tools: _Tools
    lifespan: Any = None
    shutdown: asyncio.Task[Any] | None = None
    requests: list[asyncio.Task[Any]] = field(default_factory=list)

    async def up(self) -> None:
        """Enter the app's real lifespan and let its background jobs start."""
        self.lifespan = server._lifespan(self.app)
        await asyncio.wait_for(self.lifespan.__aenter__(), _WAIT_S)
        await _turns()

    def shut_down(self) -> asyncio.Task[Any]:
        """Begin the lifespan's shutdown as a task."""
        self.shutdown = asyncio.ensure_future(self.lifespan.__aexit__(None, None, None))
        return self.shutdown

    async def close(self) -> None:
        """Release the tools, let the requests, the shutdown and the detached runs end."""
        if self.tools.park is not None:
            self.tools.park.release.set()
        for request in self.requests:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(asyncio.shield(request), _WAIT_S)
        if self.lifespan is not None and self.shutdown is None:
            self.shut_down()
        if self.shutdown is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(asyncio.shield(self.shutdown), _WAIT_S)
        with contextlib.suppress(TimeoutError):
            await _until(lambda: not getattr(event_stream, "_detached", ()))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin, behind the fake database."""
    from tests.db_fakes import FakeDb

    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture()
def tools(monkeypatch: pytest.MonkeyPatch) -> _Tools:
    """An unfrozen registry holding memory.store (allowed) and google_calendar.create
    (confirm); the previous one is restored."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    seen = _Tools()

    async def store(args: _StoreArgs, **_: Any) -> str:
        await seen.execute(f"store {args.value}", seen.park)
        return f"Stored memory: {args.key}={args.value}"

    async def create(args: _EventArgs, **_: Any) -> str:
        await seen.execute(f"create {args.title}", None)
        return f"Created event: {args.title}"

    register: Any = registry.register_tool
    register("memory", "store", "Store a note (GH-8 W10)", _StoreArgs, side_effect=True)(store)
    register(
        "google_calendar", "create", "Create an event (GH-8 W10)", _EventArgs, side_effect=True
    )(create)
    return seen


@pytest.fixture()
def llm() -> _ScriptLLM:
    return _ScriptLLM()


@pytest.fixture()
def app(world: World, tools: _Tools, llm: _ScriptLLM) -> FastAPI:
    """The app around a REAL Agent (real tool-call recorder) and the scripted LLM."""
    agent = Agent(
        llm_client=llm,  # type: ignore[arg-type]
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    built: FastAPI = create_app(agent=agent, config=make_config())
    return built


@pytest.fixture()
def probe(world: World, tools: _Tools, monkeypatch: pytest.MonkeyPatch) -> _Shutdown:
    """The lifespan's database calls and every background job replaced by ``_Shutdown``'s
    fakes (no real job or query runs; ``get_pool`` stays the FakeDb's)."""
    shutdown = _Shutdown(world.db, tools)
    monkeypatch.setattr("admino.database.init_pool", shutdown.init_pool)
    monkeypatch.setattr("admino.database.close_pool", shutdown.close_pool)
    monkeypatch.setattr("admino.audit_events.run_retention_job", shutdown.job("retention"))
    monkeypatch.setattr("admino.sessions.run_session_purge_job", shutdown.job("session-purge"))
    monkeypatch.setattr("admino.organizations.run_org_purge_job", shutdown.job("org-purge"))
    monkeypatch.setattr("admino.login_throttle.run_purge_job", shutdown.job("throttle-purge"))
    monkeypatch.setattr("admino.mailer.load_smtp_config", lambda *_a, **_k: None)
    monkeypatch.setattr("admino.email_outbox.run_outbox_sender", shutdown.job("sender"))
    monkeypatch.setattr(server, "_run_confirmation_reaper", shutdown.job("reaper"))
    return shutdown


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _turns(count: int = _TURNS) -> None:
    """Give the event loop ``count`` turns."""
    for _ in range(count):
        await asyncio.sleep(0)


async def _until(condition: Callable[[], bool]) -> None:
    """Yield to the event loop until ``condition()`` holds (at most ``_WAIT_S`` seconds)."""

    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(poll(), _WAIT_S)


async def _parked(event: asyncio.Event, request: asyncio.Task[Any]) -> None:
    """Wait until ``event`` is set; fail at once when ``request`` ends first (it never parked)."""
    waiter = asyncio.ensure_future(event.wait())
    done, _ = await asyncio.wait(
        {waiter, request}, timeout=_WAIT_S, return_when=asyncio.FIRST_COMPLETED
    )
    if waiter in done:
        return
    waiter.cancel()
    if request.done() and isinstance(request.result(), httpx.Response):
        answered: httpx.Response = request.result()
        pytest.fail(f"the run never parked: {answered.status_code} {answered.text[:300]}")
    pytest.fail("the run never parked")


async def _set_or_done(event: asyncio.Event, task: asyncio.Task[Any]) -> None:
    """Wait until ``event`` is set or ``task`` ended, whichever comes first (bounded)."""
    waiter = asyncio.ensure_future(event.wait())
    try:
        await asyncio.wait({waiter, task}, timeout=_WAIT_S, return_when=asyncio.FIRST_COMPLETED)
    finally:
        waiter.cancel()


def _http(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the test's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50010))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _stream_turn(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID, message: str
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages asking for the SSE stream."""
    return await http.post(
        f"/api/chats/{chat_id}/messages",
        headers={**account.cookie, **_SSE},
        json={"message": message},
    )


def _frames(body: str) -> list[tuple[str, dict[str, Any]]]:
    """The (event, JSON payload) frames of an SSE body; comment lines are ignored."""
    frames: list[tuple[str, dict[str, Any]]] = []
    for block in body.split("\n\n"):
        lines = [line for line in block.split("\n") if line and not line.startswith(":")]
        if not lines:
            continue
        fields = dict(line.split(": ", 1) for line in lines)
        assert set(fields) == {"event", "data"}, block
        frames.append((fields["event"], json.loads(fields["data"])))
    return frames


def _names(frames: list[tuple[str, dict[str, Any]]]) -> list[str]:
    return [name for name, _ in frames]


def _delta_text(frames: list[tuple[str, dict[str, Any]]]) -> str:
    """The concatenated ``delta`` texts of a stream."""
    return "".join(payload["text"] for name, payload in frames if name == "delta")


def _saved(db: FakeDb, chat_id: uuid.UUID, status: str) -> tuple[str, dict[str, Any]]:
    """The ``message_saved`` frame naming the chat's last stored message."""
    return (
        "message_saved",
        {"message_id": str(db.messages_of(chat_id)[-1]["id"]), "status": status},
    )


def _records(db: FakeDb, chat_id: uuid.UUID) -> list[dict[str, Any]]:
    """Every tool-call record stored with the chat's messages, in order."""
    return [record for m in db.messages_of(chat_id) for record in (m["tool_calls"] or [])]


def _app_records(records: list[logging.LogRecord]) -> list[logging.LogRecord]:
    """The app's records (not the httpx client lines, which name request URLs)."""
    return [r for r in records if not r.name.startswith(("httpx", "httpcore"))]


def _log_text(records: list[logging.LogRecord]) -> str:
    """The app's records as formatted (tracebacks included)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(record) for record in _app_records(records))


def _assert_no_content(records: list[logging.LogRecord], *markers: str) -> None:
    """No formatted app record holds a marker (message, argument, reply, payload)."""
    text = _log_text(records)
    leaked = [marker for marker in markers if marker in text]
    assert leaked == []


def _watch_stops(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Swap in a real ``ChatRuntime`` that records every stop event ``stoppable`` registers."""
    from admino.chat_runtime import ChatRuntime

    class _Watched(ChatRuntime):
        def __init__(self) -> None:
            super().__init__(max_entries=64, idle_s=900.0)
            self.stops: list[asyncio.Event] = []

        @contextlib.contextmanager
        def stoppable(self, chat_id: uuid.UUID) -> Iterator[asyncio.Event]:
            with super().stoppable(chat_id) as event:  # type: ignore[misc]
                self.stops.append(event)
                yield event

    runtime = _Watched()
    monkeypatch.setattr(server, "_chat_runtime", runtime)
    return runtime


@dataclass
class _Wire:
    """The client side of one raw ASGI request: the body once, then a disconnect on demand."""

    body: bytes
    disconnected: asyncio.Event = field(default_factory=asyncio.Event)
    sent: list[dict[str, Any]] = field(default_factory=list)
    body_read: bool = False

    async def receive(self) -> dict[str, Any]:
        if not self.body_read:
            self.body_read = True
            return {"type": "http.request", "body": self.body, "more_body": False}
        await self.disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)

    def status(self) -> int | None:
        """The status of the response start, None before it was sent."""
        starts = [m["status"] for m in self.sent if m["type"] == "http.response.start"]
        return starts[0] if starts else None


def _start_raw_turn(
    app: FastAPI, account: Account, chat_id: uuid.UUID, message: str
) -> tuple[_Wire, asyncio.Task[None]]:
    """Start a streamed turn over raw ASGI (spec 2.4); its wire and the request's task."""
    wire = _Wire(json.dumps({"message": message}).encode())
    path = f"/api/chats/{chat_id}/messages"
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"cookie", f"{SESSION_COOKIE}={account.token}".encode("ascii")),
            (b"accept", b"text/event-stream"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(wire.body)).encode("ascii")),
            (b"sec-fetch-site", b"same-origin"),
        ],
        "client": (CLIENT_IP, 50011),
        "server": ("testserver", 80),
        "state": {},
    }
    return wire, asyncio.ensure_future(app(scope, wire.receive, wire.send))


def _stopped_turn(message: str, stored: str, call: ToolCall) -> tuple[Row, ...]:
    """The stored rows of a turn stopped during its first tool call."""
    return (
        ("user", message, None, "complete"),
        ("assistant", "", None, "complete"),
        ("tool", stored, call.tool_call_id, "stopped"),
    )


def _fail_frames(monkeypatch: pytest.MonkeyPatch, failing_event: str, failure: str) -> None:
    """Make ``server._make_sse_event`` fail for ``failing_event`` only: ``oversized-frame``
    pads the payload past SSEEvent's cap (the real ValidationError), ``value-error`` raises
    a ValueError whose message carries the payload."""
    original = server._make_sse_event

    def build(event_type: str, payload: dict[str, object]) -> str:
        if event_type == failing_event:
            if failure == "oversized-frame":
                return original(event_type, {**payload, "pad": _PAD})
            msg = f"{_REFUSAL_MARK}: {json.dumps(payload)}"
            raise ValueError(msg)
        return original(event_type, payload)

    monkeypatch.setattr(server, "_make_sse_event", build)


def _dropped_lines(records: list[logging.LogRecord], event: str, exc_class: str) -> list[str]:
    """The app's log messages naming the dropped frame's event and the exception class."""
    return [
        r.getMessage()
        for r in _app_records(records)
        if re.search(rf"\b{event}\b", r.getMessage()) and exc_class in r.getMessage()
    ]


# ---------------------------------------------------------------------------
# 1. M-2: the shutdown waits for the detached runs (bounded) before jobs and pool
# ---------------------------------------------------------------------------


async def test_stream_shutdown_waits_for_a_run_whose_client_left_before_jobs_and_pool(
    world: World, llm: _ScriptLLM, tools: _Tools, app: FastAPI, probe: _Shutdown
) -> None:
    """The client left (its response ended) while the run's memory.store call is parked:
    the shutdown cancels no job and leaves the pool open while the run goes on. After the
    release the call finishes (not cancelled); at every job cancellation and at the pool's
    close its tool.call row exists and the turn is stored, stopped."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Plans")
    probe.chats.append(chat_id)
    tools.park = park = _Park()
    llm.plan(_SAVE, _calls(_STORE))
    harness = _Harness(app, tools)
    try:
        await harness.up()
        wire, request = _start_raw_turn(app, editor, chat_id, _SAVE)
        harness.requests.append(request)
        await _parked(park.parked, request)
        wire.disconnected.set()
        await asyncio.wait_for(asyncio.shield(request), _WAIT_S)
        shutdown = harness.shut_down()
        await _turns()
        while_parked = (shutdown.done(), probe.steps(), list(tools.log))
        park.release.set()
        await asyncio.wait_for(asyncio.shield(shutdown), _WAIT_S)
    finally:
        await harness.close()

    assert wire.status() == 200
    assert while_parked == (False, [], [f"start store {_ARG_MARK}"])
    assert sorted(probe.steps()) == sorted([*(f"{job}-cancelled" for job in _JOBS), "close_pool"])
    after = _Seen(
        audited=1,
        stored=(_stopped_turn(_SAVE, _STORED, _STORE),),
        tool_log=(f"start store {_ARG_MARK}", f"done store {_ARG_MARK}"),
    )
    assert {step: probe.seen[step] for step in probe.steps()} == dict.fromkeys(probe.steps(), after)


async def test_stream_shutdown_sets_a_connected_runs_stop_and_waits_for_it(
    world: World,
    llm: _ScriptLLM,
    tools: _Tools,
    app: FastAPI,
    probe: _Shutdown,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client is still connected and nothing asked the run to stop: the shutdown sets
    the run's stop signal and keeps jobs and pool while the tool call is parked. After the
    release the run makes no follow-up LLM call, is stored stopped before the pool closes,
    and its stream ends message_saved{stopped}, done."""
    runtime = _watch_stops(monkeypatch)
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Plans")
    probe.chats.append(chat_id)
    tools.park = park = _Park()
    llm.plan(_SAVE, _calls(_STORE))
    harness = _Harness(app, tools)
    try:
        await harness.up()
        async with _http(app) as http:
            turn = asyncio.ensure_future(_stream_turn(http, editor, chat_id, _SAVE))
            harness.requests.append(turn)
            await _parked(park.parked, turn)
            (stop,) = runtime.stops
            set_before = stop.is_set()
            shutdown = harness.shut_down()
            await _set_or_done(stop, shutdown)
            await _turns()
            while_parked = (stop.is_set(), shutdown.done(), probe.steps(), list(tools.log))
            park.release.set()
            streamed = await asyncio.wait_for(asyncio.shield(turn), _WAIT_S)
        await asyncio.wait_for(asyncio.shield(shutdown), _WAIT_S)
    finally:
        await harness.close()

    assert set_before is False
    assert while_parked == (True, False, [], [f"start store {_ARG_MARK}"])
    assert llm.streams == [_SAVE]
    assert _rows(db, chat_id) == list(_stopped_turn(_SAVE, _STORED, _STORE))
    frames = _frames(streamed.text)
    assert _names(frames) == ["run_started", "tool_call", "message_saved", "done"]
    assert frames[-2] == _saved(db, chat_id, "stopped")
    assert probe.seen["close_pool"].audited == 1
    assert probe.seen["close_pool"].stored == (_stopped_turn(_SAVE, _STORED, _STORE),)


async def test_stream_shutdown_bound_ends_the_wait_and_logs_the_unfinished_count_only(
    world: World,
    llm: _ScriptLLM,
    tools: _Tools,
    app: FastAPI,
    probe: _Shutdown,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """With ``server._DRAIN_TIMEOUT_S`` at 0.3 s and two runs (two orgs) parked in their
    tool calls, the shutdown waits about that long, then cancels the jobs and closes the
    pool while both are still parked, and logs the count 2 at WARNING or above with neither
    chat id; no record holds a message or a tool argument."""
    monkeypatch.setattr(server, _DRAIN_BOUND, _SHORT_BOUND_S)
    caplog.set_level(logging.DEBUG)
    db = world.db
    editor_a, editor_b = world.a["editor"], world.b["editor"]
    chat_a = seed_chat(db, editor_a, title="Plans A")
    chat_b = seed_chat(db, editor_b, title="Plans B")
    tools.park = park = _Park()
    llm.plan(_SAVE, _calls(_STORE))
    llm.plan(_SAVE_OTHER, _calls(_STORE_OTHER))
    harness = _Harness(app, tools)
    try:
        await harness.up()
        async with _http(app) as http:
            for account, chat_id, message in (
                (editor_a, chat_a, _SAVE),
                (editor_b, chat_b, _SAVE_OTHER),
            ):
                turn = asyncio.ensure_future(_stream_turn(http, account, chat_id, message))
                harness.requests.append(turn)
            await _until(lambda: tools.started() == 2)
            caplog.clear()
            began = time.monotonic()
            shutdown = harness.shut_down()
            await asyncio.wait_for(asyncio.shield(shutdown), _SHUTDOWN_LIMIT_S)
            shutdown_records = list(caplog.records)
            still_parked = sorted(tools.log)
            park.release.set()
            for request in harness.requests:
                await asyncio.wait_for(asyncio.shield(request), _WAIT_S)
    finally:
        await harness.close()

    assert still_parked == [f"start store {_ARG_MARK}", f"start store {_OTHER_MARK}"]
    assert sorted(probe.steps()) == sorted([*(f"{job}-cancelled" for job in _JOBS), "close_pool"])
    assert probe.at["close_pool"] - began >= 0.8 * _SHORT_BOUND_S
    counted = [
        r.getMessage()
        for r in shutdown_records
        if r.name.startswith("admino")
        and r.levelno >= logging.WARNING
        and re.search(r"\b2\b", r.getMessage())
    ]
    assert counted, [r.getMessage() for r in _app_records(shutdown_records)]
    assert [line for line in counted if str(chat_a) in line or str(chat_b) in line] == []
    _assert_no_content(
        list(caplog.records), _SAVE, _SAVE_OTHER, _ARG_MARK, _OTHER_MARK, _FINAL_REPLY
    )


async def test_stream_shutdown_without_detached_runs_is_unchanged_under_the_30_second_bound(
    app: FastAPI, tools: _Tools, probe: _Shutdown, caplog: pytest.LogCaptureFixture
) -> None:
    """The bound is ``server._DRAIN_TIMEOUT_S == 30``; with no detached run the shutdown
    does not wait for it: the jobs are cancelled in today's order, then the pool closes,
    at once, and no warning is logged."""
    caplog.set_level(logging.DEBUG)
    harness = _Harness(app, tools)
    try:
        await harness.up()
        caplog.clear()
        shutdown = harness.shut_down()
        await asyncio.wait_for(asyncio.shield(shutdown), _SHUTDOWN_LIMIT_S)
        shutdown_records = list(caplog.records)
    finally:
        await harness.close()

    assert getattr(server, _DRAIN_BOUND) == _DRAIN_BOUND_S
    assert probe.steps() == [*(f"{job}-cancelled" for job in _JOBS), "close_pool"]
    assert [
        r.getMessage() for r in _app_records(shutdown_records) if r.levelno >= logging.WARNING
    ] == []


# ---------------------------------------------------------------------------
# 2. M-1 / L-3: a frame that can't be built is dropped; the run goes on and is stored
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("failure", "exc_class"),
    [("oversized-frame", "ValidationError"), ("value-error", "ValueError")],
    ids=["oversized-frame", "value-error"],
)
async def test_stream_tool_call_frame_that_fails_to_build_is_dropped_and_the_turn_stored(
    world: World,
    llm: _ScriptLLM,
    tools: _Tools,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure: str,
    exc_class: str,
) -> None:
    """Building the ``tool_call`` frame fails: the run still completes, the call is audited
    and stored with its record, the stream ends message_saved{complete}, done with only
    that frame missing, and the log names the event and the exception class, no payload."""
    caplog.set_level(logging.DEBUG)
    _fail_frames(monkeypatch, "tool_call", failure)
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Plans")
    llm.plan(_SAVE, _calls(_STORE))

    async with _http(app) as http:
        streamed = await asyncio.wait_for(_stream_turn(http, editor, chat_id, _SAVE), _WAIT_S)

    assert streamed.status_code == 200, streamed.text
    frames = _frames(streamed.text)
    assert [name for name in _names(frames) if name != "delta"] == [
        "run_started",
        "message_saved",
        "done",
    ]
    assert frames[-2] == _saved(db, chat_id, "complete")
    assert _delta_text(frames) == _FINAL_REPLY
    assert _rows(db, chat_id) == [
        ("user", _SAVE, None, "complete"),
        ("assistant", "", None, "complete"),
        ("tool", _STORED, _STORE.tool_call_id, "complete"),
        ("assistant", _FINAL_REPLY, None, "complete"),
    ]
    (record,) = _records(db, chat_id)
    assert (record["tool"], record["action"], record["permission"], record["success"]) == (
        "memory",
        "store",
        "allow",
        True,
    )
    assert len(db.audit_rows("tool.call")) == 1
    assert _dropped_lines(caplog.records, "tool_call", exc_class) != []
    _assert_no_content(
        caplog.records,
        _SAVE,
        _ARG_MARK,
        _STORED,
        _FINAL_REPLY,
        _REFUSAL_MARK,
        _CJK * 4,
        "\\u7684",
    )


async def test_stream_confirm_frame_that_fails_to_build_is_dropped_and_the_confirmation_kept(
    world: World,
    llm: _ScriptLLM,
    tools: _Tools,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Building the ``confirm`` frame fails (over SSEEvent's cap): the confirmation is kept
    (GET /api/chats/{id} shows it pending, nothing ran), the stream is run_started, the
    gated call's tool_call (permission confirm), message_saved{awaiting_confirmation},
    done, and the log names the event and the exception class, no payload."""
    caplog.set_level(logging.DEBUG)
    _fail_frames(monkeypatch, "confirm", "oversized-frame")
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Offsite")
    llm.plan(_BOOK, _calls(_CREATE))

    async with _http(app) as http:
        streamed = await asyncio.wait_for(_stream_turn(http, editor, chat_id, _BOOK), _WAIT_S)
        detail = await http.get(f"/api/chats/{chat_id}", headers=editor.cookie)

    assert streamed.status_code == 200, streamed.text
    frames = _frames(streamed.text)
    assert _names(frames) == ["run_started", "tool_call", "message_saved", "done"]
    assert (frames[1][1]["tool"], frames[1][1]["permission"]) == ("google_calendar", "confirm")
    assert frames[-2] == _saved(db, chat_id, "awaiting_confirmation")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    pending = body["pending_confirmation"]
    assert (body["confirmation_status"], pending["tool"], pending["action"]) == (
        "pending",
        "google_calendar",
        "create",
    )
    assert server._chat_runtime.get_pending(chat_id) is not None
    assert tools.log == []
    assert _dropped_lines(caplog.records, "confirm", "ValidationError") != []
    _assert_no_content(caplog.records, _BOOK, _ARG_MARK, _CJK * 4, "\\u7684")
