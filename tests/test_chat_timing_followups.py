"""Pins of #244's review notes on the chat turn timing line (GH-278 Decisions 5 and 6).

Acceptance criteria (#278, test gaps): "An SSE client that disconnects mid-run: a
test pins #8's documented behaviour, including the run being detached" and "A test
pins the default status of a detached run record". Both pin behaviour that exists
today (#8, #244): every test here passes on the current code and is proven on the
#244 review mutant it kills (SV2: ``_start_stream`` without
``request_timing.detach()``; RT6: a detached record's default status 500).

Decision 5, an SSE client that disconnects mid-run (#8, and #244 Decision 1). The
app from ``create_app()`` on the FakeDb world of tests/tenancy_world.py, with the
REAL ``admino.agent.Agent`` (real tool-call recorder) around the scripted streaming
LLM of tests/test_chat_stop_api.py, driven over raw ASGI by that file's ``_Wire``
(``httpx`` buffers the body and can't disconnect mid-stream), under ASGI spec 2.3,
2.4 and 2.4 with a send that raises ``OSError`` once the client is gone. The timing
capture of tests/test_chat_timing_api.py: ``admino.database.get_pool`` answers
``database.TimedPool(db.pool)``, every FakeDb statement moves the fake
``request_timing._clock`` 2.0 ms. An untitled chat's first exchange asks for two
``memory.store`` calls; the first one parks in its handler, the client disconnects,
and the test waits until the request coroutine has returned (the response ended)
BEFORE it releases the call. Pinned:
- the disconnect sets the run's stop (the event ``ChatRuntime.stoppable``
  registered for it, as the stop route does; no stop request is made);
- the run ends by the agent's stop rules: the running call finishes, the second
  one is never dispatched, no follow-up LLM call; its turn is stored with nobody
  reading, the tool result last with status ``stopped``; the first exchange gets
  its fallback title (``chat_titles.fallback_title``, no model call);
- no timing line exists when the response has ended (the run is detached from
  it); once the run task is done there is exactly ONE line, with
  ``route=chat_message status=200`` and the response's request ID, written after
  the turn was stored: a logging handler snapshots the stored rows and the
  statement count at the moment the line is emitted (the rows are the final
  turn; ``db_queries`` is every statement of the request up to that moment).

Decision 6, the default status of a detached record: ``TimingMiddleware`` on a turn
path around a tiny ASGI app that calls ``request_timing.detach()`` and then
``request_timing.finish()`` before it sends any response message: the line says
``status=200``. (The other half, a record that isn't detached and is closed
without a response start logs 500, is already pinned by
tests/test_request_timing.py's
``test_request_timing_handler_exception_logs_one_line_with_status_500``.)

Security notes:
- Every message, id and tool argument here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import chat_titles, database, event_stream, request_timing
from admino import main as main_module
from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import AgentConfig
from admino.server import create_app
from admino.tools import registry
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    build_world,
    make_config,
    seed_chat,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)
from tests.test_chat_stop_api import (
    _DISCONNECTS,
    _STORE_A,
    _STORE_B,
    _STORED_A,
    _Park,
    _parked,
    _rows,
    _start_raw_turn,
    _StoreArgs,
    _StreamLLM,
    _Tools,
    _watch_stops,
)

if TYPE_CHECKING:
    import uuid

    from fastapi import FastAPI
    from starlette.types import Message, Receive, Scope, Send

    from tests.tenancy_world import World


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOGGER: Final = "admino.request_timing"
_LINE_PREFIX: Final = "chat timings: "
_WAIT_S: Final = 5.0
_STATEMENT_MS: Final = 2.0
_CHAT_PATH: Final = "/api/chats/3f9c2a51-7d4e-4b8a-9c1d-2e5f6a7b8c9d/messages"


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _Clock:
    """The fake ``request_timing._clock``: seconds, moved only by ``advance``."""

    def __init__(self) -> None:
        self.now = 640.0

    def __call__(self) -> float:
        return self.now

    def advance(self, ms: float) -> None:
        self.now += ms / 1000


@dataclass(frozen=True)
class _Emitted:
    """A timing line and what the database held at the moment it was emitted."""

    line: str
    rows: list[tuple[str, str, str | None, str]]
    statements: int


class _LineWatcher(logging.Handler):
    """A handler on ``admino.request_timing``: snapshots the chat's stored rows and the
    statement count each time a timing line is emitted."""

    def __init__(self, db: FakeDb, chat_id: uuid.UUID) -> None:
        super().__init__(level=logging.DEBUG)
        self.db = db
        self.chat_id = chat_id
        self.emitted: list[_Emitted] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if record.name == _LOGGER and message.startswith(_LINE_PREFIX):
            self.emitted.append(_Emitted(message, _rows(self.db, self.chat_id), len(self.db.calls)))

    def lines(self) -> list[str]:
        return [emitted.line for emitted in self.emitted]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin, behind the fake database."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture()
def clock(world: World, monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """The fake ``request_timing._clock``; every FakeDb statement moves it 2.0 ms, and
    ``get_pool()`` answers ``database.TimedPool(db.pool)`` (statements are counted)."""
    fake = _Clock()
    monkeypatch.setattr(request_timing, "_clock", fake)
    db = world.db
    handle = db.handle

    def timed_handle(*args: Any, **kwargs: Any) -> Any:
        fake.advance(_STATEMENT_MS)
        return handle(*args, **kwargs)

    monkeypatch.setattr(db, "handle", timed_handle)
    monkeypatch.setattr("admino.database.get_pool", lambda: database.TimedPool(db.pool))
    return fake


@pytest.fixture()
def tools(monkeypatch: pytest.MonkeyPatch) -> _Tools:
    """An unfrozen registry holding memory.store (allowed, a side effect, optionally
    parked); the previous registry is restored."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    seen = _Tools()

    async def store(args: _StoreArgs, **_: Any) -> str:
        await seen.execute(f"store {args.value}", seen.store_park)
        return f"Stored memory: {args.key}={args.value}"

    register: Any = registry.register_tool
    register("memory", "store", "Store a note (GH-278)", _StoreArgs, side_effect=True)(store)
    return seen


@pytest.fixture()
def llm() -> _StreamLLM:
    return _StreamLLM()


@pytest.fixture()
def app(world: World, clock: _Clock, tools: _Tools, llm: _StreamLLM) -> FastAPI:
    """The app around a REAL Agent (real tool-call recorder) and the fake streaming LLM."""
    agent = Agent(
        llm_client=llm,  # type: ignore[arg-type]
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    built: FastAPI = create_app(agent=agent, config=make_config())
    return built


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fields(line: str) -> dict[str, str]:
    """The ``name=value`` fields of a timing line."""
    return dict(part.split("=", 1) for part in line.removeprefix(_LINE_PREFIX).split(" "))


def _request_id(sent: list[dict[str, Any]]) -> str | None:
    """The ``X-Request-ID`` of the response start among the sent ASGI messages."""
    for message in sent:
        if message["type"] == "http.response.start":
            headers = dict(message.get("headers", []))
            value = headers.get(b"x-request-id")
            return value.decode("ascii") if value is not None else None
    return None


# ===========================================================================
# 1. An SSE client that disconnects mid-run (Decision 5)
# ===========================================================================


@pytest.mark.parametrize(("spec_version", "oserror"), _DISCONNECTS)
async def test_chat_timing_sse_disconnect_mid_run_stores_the_stopped_turn_then_logs_one_line(
    world: World,
    llm: _StreamLLM,
    tools: _Tools,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    spec_version: str,
    oserror: bool,
) -> None:
    """An untitled chat's first exchange: the client leaves while the first of two
    memory.store calls runs. The response ends with the call still parked, and no line
    is written then; once released, the run stops by the agent's rules, stores the turn
    (tool result last, ``stopped``), and its task writes the one line, after the store."""
    runtime = _watch_stops(monkeypatch)
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor)
    message = "Save both offsite plans"
    expected_title = chat_titles.fallback_title(message)
    tools.store_park = park = _Park()
    llm.plan(message, [LLMResponse(content="", tool_calls=[_STORE_A, _STORE_B])])
    caplog.set_level(logging.INFO, logger=_LOGGER)
    watcher = _LineWatcher(db, chat_id)
    timing_logger = logging.getLogger(_LOGGER)
    timing_logger.addHandler(watcher)
    since = len(db.calls)
    runs_before = set(event_stream._detached)
    try:
        wire, request = _start_raw_turn(
            app, editor, chat_id, message, spec_version, oserror=oserror
        )
        await _parked(park.parked, request)
        new_runs = set(event_stream._detached) - runs_before
        wire.disconnected.set()
        # The response ends while the call is still parked: the run goes on without it.
        await asyncio.wait_for(request, _WAIT_S)
        lines_when_the_response_ended = watcher.lines()
        stop_requested = [stop.is_set() for stop in runtime.stops]
        park.release.set()
        (run_task,) = new_runs
        await asyncio.wait_for(run_task, _WAIT_S)
    finally:
        park.release.set()
        timing_logger.removeHandler(watcher)

    stored = [
        ("user", message, None, "complete"),
        ("assistant", "", None, "complete"),
        ("tool", _STORED_A, _STORE_A.tool_call_id, "stopped"),
    ]
    chat = db.chat_row(chat_id) or {}
    # The disconnect set the run's stop; the run ended by the agent's stop rules.
    assert (wire.status(), stop_requested) == (200, [True])
    assert (tools.log, len(llm.streams)) == (["start store ship", "done store ship"], 1)
    # The turn is stored with nobody reading, and the first exchange is titled.
    assert _rows(db, chat_id) == stored
    assert (chat.get("title"), chat.get("title_source"), llm.title_calls) == (
        expected_title,
        "auto",
        [],
    )
    # No line when the response ended; then exactly one, written after the store.
    assert lines_when_the_response_ended == []
    assert len(watcher.emitted) == 1, watcher.lines()
    (emitted,) = watcher.emitted
    fields = _fields(emitted.line)
    assert (fields["route"], fields["status"], fields["request_id"]) == (
        "chat_message",
        "200",
        _request_id(wire.sent),
    )
    assert emitted.rows == stored
    counted = emitted.statements - since
    assert (fields["db_queries"], fields["db_ms"]) == (
        str(counted),
        f"{counted * _STATEMENT_MS:.1f}",
    )


# ===========================================================================
# 2. The default status of a detached record (Decision 6)
# ===========================================================================


async def test_chat_timing_detached_record_closed_before_the_response_start_logs_status_200(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A turn request whose record is detached and finished before any
    ``http.response.start``: its line says ``status=200`` (a streamed turn's answer),
    never the 500 of a record closed without a response."""
    clock = _Clock()
    monkeypatch.setattr(request_timing, "_clock", clock)
    caplog.set_level(logging.INFO, logger=_LOGGER)
    sent: list[Message] = []

    async def turn(scope: Scope, receive: Receive, send: Send) -> None:
        clock.advance(3)
        request_timing.detach()
        request_timing.finish()
        clock.advance(40)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": _CHAT_PATH,
        "raw_path": _CHAT_PATH.encode("ascii"),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }

    await request_timing.TimingMiddleware(turn)(scope, receive, send)

    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"]
    assert [(r.levelno, r.getMessage()) for r in caplog.records if r.name == _LOGGER] == [
        (
            logging.INFO,
            "chat timings: request_id=- route=chat_message status=200 db_queries=0 "
            "db_queries_before_llm=- db_ms=0.0 llm_start_ms=- llm_first_byte_ms=- "
            "llm_ms=0.0 tool_ms=0.0 total_ms=3.0",
        )
    ]
