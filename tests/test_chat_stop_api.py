"""HTTP spec of stopping a streamed chat run (GH-8: contract C3, C5.4, C5.6, C5.7).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py with the REAL ``admino.agent.Agent`` (real tool-call
recorder of ``main._build_tool_call_recorder()``) around a fake streaming LLM
(``_StreamLLM``, provider "infomaniak"): its ``chat_stream`` plays a scripted
plan per call (deltas, a final ``LLMResponse``, ``_Park`` steps that set an
event and then wait, bounded, for their release), records every call and, in
a ``finally``, that its generator was closed and whether it was parked then;
its ``chat`` answers JSON-mode runs (scripted, optionally parked) and title
requests (``max_tokens`` set: counted, never needed by a stopped turn). Fake
tools live in an isolated registry: ``memory.store`` (allowed, a side effect)
and ``google_calendar.create`` (confirm), each optionally parked in the middle
of its execution.

Two ways to drive requests:
- ``httpx.ASGITransport`` in the test's event loop: the streamed request runs
  as a task, the test waits until the run parks, POSTs the stop, releases
  what must finish, then reads the whole SSE body (the transport returns it
  once the stream ended);
- raw ASGI for client disconnects (``_Wire``): ``receive`` hands over the
  JSON body once, then blocks until the test disconnects and answers
  ``http.disconnect`` from then on; ``send`` records every message and, in
  one variant, raises ``OSError`` for body messages after the disconnect (what
  an ASGI 2.4 server does). ``spec_version`` 2.3 and 2.4: with 2.4 Starlette
  never listens for the disconnect itself, so the server must.

What is pinned:
- POST /api/chats/{chat_id}/stop (C5.7): 401 without a session; the CSRF
  403 (the same request marked same-origin answers); 403 for the Super Admin
  with no chat statement and no runtime entry; 422 for a non-UUID
  id; the identical 404 ``chat_not_found`` for an unknown, another org's, a
  colleague's (an Org Admin on an Editor's chat) and a trashed chat; the
  per-user limit ``(1.0, 10)`` and its 429 (another user still gets through);
  ``{"stopped": false}`` on an idle chat (no runtime entry created, no body
  read, no audit row) and while a JSON run of the chat runs (that run then
  completes and is stored ``complete``); no log record carries message,
  delta or title text.
- A stopped streamed turn (C3, C5.3, C5.4): ``{"stopped": true}``; the LLM's
  stream is closed while it is still parked (never released, never timed
  out); exactly one LLM call; frames ``run_started``, the deltas,
  ``context_usage`` (GH-190, Decision 4), ``message_saved{stopped}``, ``done``;
  stored: the user message, then the forwarded text as the assistant message
  (none without text), the last one with status ``stopped``; the concatenated
  delta frames equal that message as GET /api/chats/{id} shows it; the stop
  writes no audit row.
- C11 (audit core L-1): the stopped reply and its deltas end at the forwarded
  text's last ASCII whitespace (the unfinished last word is dropped, also after
  a disconnect); a stop while the LLM is parked right after a delta ending
  inside a runtime-built key stores the reply up to the key and puts no 8
  characters of it in any frame, stored message or GET body, while the word
  before an earlier ``tool_call`` is still sent whole.
- Stop during a tool dispatch: the running call finishes after its release,
  is audited (one ``tool.call`` row) and sent as ``tool_call``; the second
  call of the batch is never dispatched; no follow-up LLM call; stored: user,
  assistant (both tool_use blocks), the tool result last with ``stopped``.
- Client disconnect (C5.4), spec 2.3, 2.4 and 2.4 with ``OSError`` sends: the
  same outcomes for a parked LLM and a parked tool; the request coroutine
  returns within a bounded wait.
- After a stopped turn: a new stop answers ``{"stopped": false}`` and the
  next message runs (200, not 409) with a well-formed history: the
  undispatched call of the stopped batch gets its cancelled tool result
  before the new user message.
- Title (C5.6): a stopped first exchange of an untitled chat makes no title
  model call, stores the fallback title (``chat_titles.fallback_title`` of
  the message) and sends it as ``title`` after ``message_saved``; after a
  disconnect the fallback is still stored.
- An approval streamed by POST /api/confirm (Accept SSE) stops the same way:
  the approved call always runs and is audited, the turn is stored
  ``stopped``, and no LLM call is made once the stop is in.
- A stop affects its chat only: another streamed chat of the same user keeps
  running and completes.

New names (the stop route, ``ChatRuntime.stoppable``) are used lazily, so the
file collects before GH-8 is implemented.

Security notes:
- Every message, id and tool argument here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from pydantic import BaseModel, Field

from admino import chat_titles, server
from admino import main as main_module
from admino.agent import Agent
from admino.llm import LLMResponse, LLMStreamDelta
from admino.models import AgentConfig, LLMMessage, ToolCall, sanitize_display_text
from admino.server import create_app
from admino.tools import registry
from tests.context_frames import fix_instructions, usage_frame
from tests.credential_keys import GITHUB_FINE_GRAINED, surviving_chunks
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    CHAT_NOT_FOUND,
    CLIENT_IP,
    FORBIDDEN,
    SESSION_COOKIE,
    UNAUTHORIZED,
    build_world,
    make_app,
    make_client,
    make_config,
    seed_chat,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator

    from fastapi import FastAPI

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WAIT_S: Final = 5.0
_SSE: Final = {"Accept": "text/event-stream"}
_STOPPED: Final = {"stopped": True}
_NOT_STOPPED: Final = {"stopped": False}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_FINAL_REPLY: Final = "All done."
_MODEL_TITLE: Final = "Model title GH-8"

# A statement on either chat table (FakeDb's normalized SQL).
_CHAT_SQL: Final = re.compile(r"\bchat(?:s|_messages)\b")

_STORE_A: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": "plan", "value": "ship"},
    tool_call_id="call-stop8-a",
)
_STORE_B: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": "plan", "value": "later"},
    tool_call_id="call-stop8-b",
)
_CREATE: Final = ToolCall(
    tool="google_calendar",
    action="create",
    args={"title": "Offsite"},
    tool_call_id="call-stop8-cal",
)
_STORED_A: Final = "Stored memory: plan=ship"
_CREATED: Final = "Created event: Offsite"

# The disconnect variants: (ASGI spec_version, send raises OSError after the disconnect).
_DISCONNECTS: Final = [
    pytest.param("2.3", False, id="spec-2.3"),
    pytest.param("2.4", False, id="spec-2.4"),
    pytest.param("2.4", True, id="spec-2.4-oserror"),
]


def _block(call: ToolCall) -> dict[str, Any]:
    """The tool_use block the agent stores for ``call``."""
    return {
        "type": "tool_use",
        "id": call.tool_call_id,
        "name": f"{call.tool}.{call.action}",
        "input": dict(call.args),
    }


# ---------------------------------------------------------------------------
# The fake streaming LLM
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class _Park:
    """A point where a stream or a tool waits: sets ``parked``, then waits for ``release``."""

    parked: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)


# One step of a stream plan: a delta's text, a park, or the final response.
Step = str | _Park | LLMResponse


@dataclass
class _StreamCall:
    """One ``chat_stream`` call: what it was fed and how its generator ended."""

    user_message: str
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] | None
    finished: bool = False
    closed: bool = False
    parked_at_close: bool = False
    timed_out: bool = False

    @property
    def closed_while_parked(self) -> bool:
        """Closed by its consumer while waiting in a park (not by a park's timeout)."""
        return self.closed and self.parked_at_close and not self.timed_out


def _last_user(messages: list[LLMMessage]) -> str:
    """The content of the last user message (on a resume: the turn being resumed)."""
    return next(str(m.content) for m in reversed(messages) if m.role == "user")


class _StreamLLM:
    """Scripted per user message: stream plans (one per ``chat_stream`` call of that
    message's turn), JSON-mode replies and parks; title calls answer ``_MODEL_TITLE``."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self._plans: dict[str, list[list[Step]]] = {}
        self._replies: dict[str, list[LLMResponse]] = {}
        self._json_parks: dict[str, _Park] = {}
        self.streams: list[_StreamCall] = []
        self.json_runs: list[str] = []
        self.title_calls: list[int] = []

    def plan(self, message: str, *plans: list[Step]) -> None:
        """The plans of the next ``chat_stream`` calls of ``message``'s turn, in order."""
        self._plans[message] = [list(steps) for steps in plans]

    def reply(self, message: str, *replies: LLMResponse) -> None:
        """The answers of the next JSON-mode ``chat`` calls of ``message``'s turn."""
        self._replies[message] = list(replies)

    def park_json(self, message: str, park: _Park) -> None:
        """The next JSON-mode ``chat`` call of ``message``'s turn waits in ``park`` first."""
        self._json_parks[message] = park

    def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        user_message = _last_user(messages)
        call = _StreamCall(
            user_message=user_message,
            messages=[m.model_dump() for m in messages if m.role != "system"],
            tools=tools,
        )
        self.streams.append(call)
        queued = self._plans.get(user_message, [])
        steps: list[Step] = queued.pop(0) if queued else [_FINAL_REPLY]
        return self._play(call, steps)

    async def _play(
        self, call: _StreamCall, steps: list[Step]
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        text = ""
        waiting = False
        try:
            for step in steps:
                if isinstance(step, _Park):
                    waiting = True
                    step.parked.set()
                    try:
                        await asyncio.wait_for(step.release.wait(), _WAIT_S)
                    except TimeoutError:
                        call.timed_out = True
                        raise
                    waiting = False
                elif isinstance(step, LLMResponse):
                    call.finished = True
                    yield step
                    return
                else:
                    text += step
                    yield LLMStreamDelta(content=step)
            call.finished = True
            yield LLMResponse(content=text, done=True)
        finally:
            call.closed = True
            call.parked_at_close = waiting

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if max_tokens is not None:
            # chat_titles asks with max_tokens: a title request, never an agent run.
            self.title_calls.append(max_tokens)
            return LLMResponse(content=_MODEL_TITLE, done=True)
        user_message = _last_user(messages)
        self.json_runs.append(user_message)
        park = self._json_parks.pop(user_message, None)
        if park is not None:
            park.parked.set()
            await asyncio.wait_for(park.release.wait(), _WAIT_S)
        queued = self._replies.get(user_message, [])
        return queued.pop(0) if queued else LLMResponse(content=_FINAL_REPLY, done=True)

    async def close(self) -> None:
        """Nothing to close."""


# ---------------------------------------------------------------------------
# Fake tools
# ---------------------------------------------------------------------------


class _StoreArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    value: str = Field(min_length=1, max_length=200)


class _EventArgs(BaseModel):
    title: str = Field(min_length=1, max_length=100)


@dataclass
class _Tools:
    """What the fake tools did, in order, and where they park (None: they don't)."""

    log: list[str] = field(default_factory=list)
    store_park: _Park | None = None
    create_park: _Park | None = None

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


@pytest.fixture(autouse=True)
def _fixed_instructions(monkeypatch: pytest.MonkeyPatch) -> None:
    """GH-190: the instructions count a constant (tests/context_frames.py), so every
    ``context_usage`` frame is deterministic."""
    fix_instructions(monkeypatch)


@pytest.fixture()
def tools(monkeypatch: pytest.MonkeyPatch) -> _Tools:
    """An unfrozen registry holding memory.store (allowed, a side effect) and
    google_calendar.create (confirm); the previous one is restored."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    seen = _Tools()

    async def store(args: _StoreArgs, **_: Any) -> str:
        await seen.execute(f"store {args.value}", seen.store_park)
        return f"Stored memory: {args.key}={args.value}"

    async def create(args: _EventArgs, **_: Any) -> str:
        await seen.execute(f"create {args.title}", seen.create_park)
        return f"Created event: {args.title}"

    register: Any = registry.register_tool
    register("memory", "store", "Store a note (GH-8)", _StoreArgs, side_effect=True)(store)
    register("google_calendar", "create", "Create an event (GH-8)", _EventArgs, side_effect=True)(
        create
    )
    return seen


@pytest.fixture()
def llm() -> _StreamLLM:
    return _StreamLLM()


@pytest.fixture()
def app(world: World, tools: _Tools, llm: _StreamLLM) -> FastAPI:
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


def _stop_url(chat_id: uuid.UUID | str) -> str:
    return f"/api/chats/{chat_id}/stop"


def _http(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the test's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50008))
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


async def _json_turn(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID, message: str
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages without an Accept header (the JSON answer)."""
    return await http.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
    )


async def _stream_approval(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID, confirmation_id: str
) -> httpx.Response:
    """POST /api/confirm/{confirmation_id} approving, asking for the SSE stream."""
    return await http.post(
        f"/api/confirm/{confirmation_id}",
        headers={**account.cookie, **_SSE},
        json={"confirmation_id": confirmation_id, "approved": True, "chat_id": str(chat_id)},
    )


async def _stop(http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID) -> httpx.Response:
    """POST /api/chats/{chat_id}/stop (no body)."""
    return await http.post(_stop_url(chat_id), headers=account.cookie)


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


Row = tuple[str, str, str | None, str]


def _rows(db: FakeDb, chat_id: uuid.UUID) -> list[Row]:
    """The chat's stored messages by seq: (role, content, tool_call_id, status)."""
    return [
        (m["role"], m["content"], m["tool_call_id"], m["status"]) for m in db.messages_of(chat_id)
    ]


def _last_status(db: FakeDb, chat_id: uuid.UUID) -> str | None:
    stored = db.messages_of(chat_id)
    return stored[-1]["status"] if stored else None


def _saved(db: FakeDb, chat_id: uuid.UUID, status: str) -> tuple[str, dict[str, Any]]:
    """The ``message_saved`` frame naming the chat's last stored message."""
    return (
        "message_saved",
        {"message_id": str(db.messages_of(chat_id)[-1]["id"]), "status": status},
    )


def _usage(db: FakeDb, chat_id: uuid.UUID) -> tuple[str, dict[str, Any]]:
    """GH-190 (Decision 4): the ``context_usage`` frame right before ``message_saved``: the
    chat as its next turn starts, read now (tests/context_frames.py)."""
    return usage_frame(db, chat_id)


def _chat_calls(db: FakeDb, since: int) -> list[str]:
    """The SQL of every chat-table statement run after the first ``since`` calls."""
    return [call.sql for call in db.calls[since:] if _CHAT_SQL.search(call.normalized)]


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the httpx client lines, which name request URLs)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


def _watch_stops(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Swap in a real ``ChatRuntime`` that records every stop event ``stoppable`` registers,
    so a test can wait until a disconnect has requested the stop."""
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
    oserror_after_disconnect: bool = False
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
        if (
            self.oserror_after_disconnect
            and self.disconnected.is_set()
            and message["type"] == "http.response.body"
        ):
            raise OSError("the client went away")
        self.sent.append(message)

    def status(self) -> int | None:
        """The status of the response start, None before it was sent."""
        starts = [m["status"] for m in self.sent if m["type"] == "http.response.start"]
        return starts[0] if starts else None


def _turn_scope(
    account: Account, chat_id: uuid.UUID, spec_version: str, body: bytes
) -> dict[str, Any]:
    """An ASGI http scope of a streamed POST /api/chats/{chat_id}/messages as ``account``."""
    path = f"/api/chats/{chat_id}/messages"
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": spec_version},
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
            (b"content-length", str(len(body)).encode("ascii")),
            (b"sec-fetch-site", b"same-origin"),
        ],
        "client": (CLIENT_IP, 50009),
        "server": ("testserver", 80),
        "state": {},
    }


def _start_raw_turn(
    app: FastAPI,
    account: Account,
    chat_id: uuid.UUID,
    message: str,
    spec_version: str,
    *,
    oserror: bool,
) -> tuple[_Wire, asyncio.Task[None]]:
    """Start a streamed turn over raw ASGI; its wire and the request coroutine's task."""
    wire = _Wire(json.dumps({"message": message}).encode(), oserror_after_disconnect=oserror)
    scope = _turn_scope(account, chat_id, spec_version, wire.body)
    return wire, asyncio.create_task(app(scope, wire.receive, wire.send))


# ---------------------------------------------------------------------------
# 1. The stop route's gates (C5.7)
# ---------------------------------------------------------------------------


def test_chat_stop_without_session_gets_401(world: World) -> None:
    client = make_client(make_app())
    chat_id = seed_chat(world.db, world.a["editor"])

    response = client.post(_stop_url(chat_id))

    assert (response.status_code, response.json()) == (401, UNAUTHORIZED)


def test_chat_stop_cross_origin_post_is_refused_and_same_origin_answers(world: World) -> None:
    """The CSRF middleware refuses a cross-site stop before the route; the same request
    marked same-origin reaches the route (so the refusal is the middleware's)."""
    client = make_client(make_app())
    editor = world.a["editor"]
    chat_id = seed_chat(world.db, editor)

    refused = client.post(
        _stop_url(chat_id), headers={**editor.cookie, "Sec-Fetch-Site": "cross-site"}
    )
    allowed = client.post(
        _stop_url(chat_id), headers={**editor.cookie, "Sec-Fetch-Site": "same-origin"}
    )

    assert (refused.status_code, refused.json()) == (403, _CSRF_REFUSED)
    assert (allowed.status_code, allowed.json()) == (200, _NOT_STOPPED)


def test_chat_stop_super_admin_gets_403_before_any_chat_statement(world: World) -> None:
    """The Super Admin (no chat.send) on an Editor's chat: 403 ``Forbidden``, no
    statement on either chat table, no runtime entry."""
    client = make_client(make_app())
    account = world.super_admin
    chat_id = seed_chat(world.db, world.a["editor"])
    before = len(world.db.calls)

    response = client.post(_stop_url(chat_id), headers=account.cookie)

    assert (response.status_code, response.json()) == (403, FORBIDDEN)
    assert _chat_calls(world.db, before) == []
    assert len(server._chat_runtime) == 0


def test_chat_stop_non_uuid_chat_id_gets_422_without_echo(world: World) -> None:
    client = make_client(make_app())

    response = client.post(_stop_url("not-a-uuid-8"), headers=world.a["editor"].cookie)

    assert response.status_code == 422
    assert "not-a-uuid-8" not in response.text


@pytest.mark.parametrize("case", ["unknown", "other_org", "colleague", "trashed"])
def test_chat_stop_missing_foreign_or_trashed_chat_gets_identical_404(
    world: World, case: str
) -> None:
    """An unknown id, another org's chat, a colleague's chat (an Org Admin calling on an
    Editor's chat of the same org) and the caller's own trashed chat: the same 404 body,
    and no runtime entry for that chat."""
    client = make_client(make_app())
    db = world.db
    caller = world.a["org_admin"] if case == "colleague" else world.a["editor"]
    if case == "unknown":
        chat_id = uuid.uuid4()
    elif case == "other_org":
        chat_id = seed_chat(db, world.b["editor"])
    elif case == "colleague":
        chat_id = seed_chat(db, world.a["editor"])
    else:
        chat_id = db.add_chat(world.a["editor"].user_id, deleted_at=datetime.now(UTC))

    response = client.post(_stop_url(chat_id), headers=caller.cookie)

    assert (response.status_code, response.json()) == (404, CHAT_NOT_FOUND)
    assert chat_id not in server._chat_runtime


def test_chat_stop_rate_limit_entry_is_one_per_second_with_a_burst_of_ten() -> None:
    assert server._RATE_LIMITS["/api/chats/stop"] == (1.0, 10)


def test_chat_stop_per_user_rate_limit_gets_429_and_spares_other_users(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Burst 2 with no refill to speak of: the Editor's third stop is 429; the Org Admin's
    own bucket is untouched."""
    monkeypatch.setitem(server._RATE_LIMITS, "/api/chats/stop", (0.0001, 2))
    client = make_client(make_app())
    editor, admin = world.a["editor"], world.a["org_admin"]
    chat_id = seed_chat(world.db, editor)

    answers = [client.post(_stop_url(chat_id), headers=editor.cookie) for _ in range(3)]
    other = client.post(_stop_url(seed_chat(world.db, admin)), headers=admin.cookie)

    assert [(a.status_code, a.json()) for a in answers] == [
        (200, _NOT_STOPPED),
        (200, _NOT_STOPPED),
        (429, _RATE_LIMITED),
    ]
    assert (other.status_code, other.json()) == (200, _NOT_STOPPED)


def test_chat_stop_idle_chat_answers_not_stopped_without_runtime_entry_or_audit(
    world: World,
) -> None:
    """Nothing runs: ``{"stopped": false}``; the chat gets no runtime entry, no audit row
    is written, and a junk body is ignored (the route reads none)."""
    client = make_client(make_app())
    editor = world.a["editor"]
    chat_id = seed_chat(world.db, editor)
    audit_before = len(world.db.audit_rows())

    plain = client.post(_stop_url(chat_id), headers=editor.cookie)
    junk = client.post(
        _stop_url(chat_id),
        headers={**editor.cookie, "Content-Type": "application/json"},
        content=b"{not json",
    )

    assert (plain.status_code, plain.json()) == (200, _NOT_STOPPED)
    assert (junk.status_code, junk.json()) == (200, _NOT_STOPPED)
    assert chat_id not in server._chat_runtime
    assert len(server._chat_runtime) == 0
    assert len(world.db.audit_rows()) == audit_before


async def test_chat_stop_during_a_json_run_answers_not_stopped_and_the_run_completes(
    world: World, llm: _StreamLLM, app: FastAPI
) -> None:
    """A JSON request's run can't be stopped: while its LLM call is parked the stop answers
    ``{"stopped": false}``; once released the run answers ``final`` and is stored complete."""
    editor = world.a["editor"]
    chat_id = seed_chat(world.db, editor, title="JSON run")
    park = _Park()
    llm.park_json("Explain the budget", park)

    async with _http(app) as http:
        turn = asyncio.create_task(_json_turn(http, editor, chat_id, "Explain the budget"))
        await _parked(park.parked, turn)
        try:
            stop = await _stop(http, editor, chat_id)
        finally:
            park.release.set()
        answered = await asyncio.wait_for(turn, _WAIT_S)

    assert (stop.status_code, stop.json()) == (200, _NOT_STOPPED)
    assert answered.status_code == 200, answered.text
    assert (answered.json()["status"], answered.json()["response"]) == ("final", _FINAL_REPLY)
    assert _rows(world.db, chat_id) == [
        ("user", "Explain the budget", None, "complete"),
        ("assistant", _FINAL_REPLY, None, "complete"),
    ]
    assert llm.streams == []


# ---------------------------------------------------------------------------
# 2. POST /stop on a streamed turn (C3, C5.3, C5.4)
# ---------------------------------------------------------------------------


async def test_chat_stop_before_the_first_delta_closes_the_parked_stream(
    world: World, llm: _StreamLLM, app: FastAPI
) -> None:
    """The LLM sends nothing yet: the stop closes its stream while it is still parked (never
    released); exactly one LLM call; frames run_started, message_saved{stopped}, done; the
    user message is stored last with status stopped; the stop writes no audit row."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(
        db,
        editor,
        title="Weekly plan",
        messages=[("user", "Earlier question"), ("assistant", "Earlier answer")],
    )
    park = _Park()
    llm.plan("Draft the agenda", [park, "never sent"])
    audit_before = len(db.audit_rows())

    async with _http(app) as http:
        turn = asyncio.create_task(_stream_turn(http, editor, chat_id, "Draft the agenda"))
        await _parked(park.parked, turn)
        stop = await _stop(http, editor, chat_id)
        streamed = await asyncio.wait_for(turn, _WAIT_S)

    assert (stop.status_code, stop.json()) == (200, _STOPPED)
    assert streamed.status_code == 200, streamed.text
    (call,) = llm.streams
    assert call.closed_while_parked
    assert not park.release.is_set()
    assert _rows(db, chat_id) == [
        ("user", "Earlier question", None, "complete"),
        ("assistant", "Earlier answer", None, "complete"),
        ("user", "Draft the agenda", None, "stopped"),
    ]
    assert _frames(streamed.text) == [
        ("run_started", {"chat_id": str(chat_id)}),
        _usage(db, chat_id),
        _saved(db, chat_id, "stopped"),
        ("done", {}),
    ]
    assert len(db.audit_rows()) == audit_before


async def test_chat_stop_after_deltas_stores_the_forwarded_text_as_the_stopped_reply(
    world: World, llm: _StreamLLM, app: FastAPI
) -> None:
    """Four deltas, then the LLM parks: the stored assistant message is their raw
    concatenation up to its last ASCII whitespace (C11: the unfinished last word "mo" is
    dropped, the word split across "ans" and "wer " is kept) with status stopped, the
    frames are run_started, deltas, message_saved{stopped}, done, and the deltas
    concatenate to the message as GET /api/chats/{id} shows it."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Notes")
    park = _Park()
    llm.plan("Summarise the notes", ["Partial ", "ans", "wer ", "and mo", park, "re never sent"])

    async with _http(app) as http:
        turn = asyncio.create_task(_stream_turn(http, editor, chat_id, "Summarise the notes"))
        await _parked(park.parked, turn)
        stop = await _stop(http, editor, chat_id)
        streamed = await asyncio.wait_for(turn, _WAIT_S)
        detail = await http.get(f"/api/chats/{chat_id}", headers=editor.cookie)

    assert (stop.status_code, stop.json()) == (200, _STOPPED)
    assert streamed.status_code == 200, streamed.text
    (call,) = llm.streams
    assert call.closed_while_parked
    assert _rows(db, chat_id) == [
        ("user", "Summarise the notes", None, "complete"),
        ("assistant", "Partial answer and ", None, "stopped"),
    ]
    frames = _frames(streamed.text)
    names = _names(frames)
    assert names[0] == "run_started"
    assert names[-3:] == ["context_usage", "message_saved", "done"]
    assert set(names[1:-3]) == {"delta"}
    assert frames[-3:-1] == [_usage(db, chat_id), _saved(db, chat_id, "stopped")]
    assert _delta_text(frames) == "Partial answer and "
    assert detail.status_code == 200, detail.text
    assert detail.json()["messages"][-1]["content"] == _delta_text(frames)


async def test_chat_stop_inside_a_key_stores_and_streams_no_part_of_it(
    world: World, llm: _StreamLLM, tools: _Tools, app: FastAPI
) -> None:
    """C11 (audit core L-1): the first LLM call says "Checking the vault" (no whitespace
    after "vault") and asks for memory.store; the second one streams "Here is the key "
    and a runtime-built GitHub fine-grained token one character short (which the display
    redaction doesn't match), split over two deltas, and parks. POST /stop: "vault" was
    sent before the ``tool_call`` (that answer was complete), the stored reply is "Here is
    the key " (stopped), its deltas equal it as GET /api/chats/{id} shows it, and no
    frame, stored message or GET body holds any 8 characters of the token's body."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Keys")
    key = GITHUB_FINE_GRAINED.key()
    cut = key.text[:-1]
    assert surviving_chunks(sanitize_display_text(cut), key), "fixture: shown when uncut"
    park = _Park()
    llm.plan(
        "Show the deploy key",
        [
            "Checking the ",
            "vault",
            LLMResponse(content="Checking the vault", tool_calls=[_STORE_A]),
        ],
        ["Here is the key ", cut[:30], cut[30:], park, "1 never sent"],
    )

    async with _http(app) as http:
        turn = asyncio.create_task(_stream_turn(http, editor, chat_id, "Show the deploy key"))
        await _parked(park.parked, turn)
        stop = await _stop(http, editor, chat_id)
        streamed = await asyncio.wait_for(turn, _WAIT_S)
        detail = await http.get(f"/api/chats/{chat_id}", headers=editor.cookie)

    assert (stop.status_code, stop.json()) == (200, _STOPPED)
    assert streamed.status_code == 200, streamed.text
    assert [call.closed_while_parked for call in llm.streams] == [False, True]
    assert tools.log == ["start store ship", "done store ship"]
    assert _rows(db, chat_id) == [
        ("user", "Show the deploy key", None, "complete"),
        ("assistant", "Checking the vault", None, "complete"),
        ("tool", _STORED_A, _STORE_A.tool_call_id, "complete"),
        ("assistant", "Here is the key ", None, "stopped"),
    ]
    (record,) = db.messages_of(chat_id)[-1]["tool_calls"]
    assert _frames(streamed.text) == [
        ("run_started", {"chat_id": str(chat_id)}),
        ("delta", {"text": "Checking the "}),
        ("delta", {"text": "vault"}),
        ("tool_call", record),
        ("delta", {"text": "Here is the key "}),
        _usage(db, chat_id),
        _saved(db, chat_id, "stopped"),
        ("done", {}),
    ]
    assert detail.status_code == 200, detail.text
    assert detail.json()["messages"][-1]["content"] == "Here is the key "
    stored = " ".join(str(message["content"]) for message in db.messages_of(chat_id))
    leaks = [surviving_chunks(text, key) for text in (streamed.text, detail.text, stored)]
    assert leaks == [[], [], []]


async def test_chat_stop_during_a_tool_dispatch_finishes_and_records_it_and_skips_the_rest(
    world: World, llm: _StreamLLM, tools: _Tools, app: FastAPI
) -> None:
    """The LLM asks for two memory.store calls in one batch; the first one parks in its
    handler when the stop comes. After its release it finishes, is audited and sent as
    tool_call; the second call is never dispatched and no follow-up LLM call is made;
    stored: user, assistant (both tool_use blocks), the tool result last, stopped."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Plans")
    tools.store_park = park = _Park()
    llm.plan("Save both plans", [LLMResponse(content="", tool_calls=[_STORE_A, _STORE_B])])

    async with _http(app) as http:
        turn = asyncio.create_task(_stream_turn(http, editor, chat_id, "Save both plans"))
        await _parked(park.parked, turn)
        try:
            stop = await _stop(http, editor, chat_id)
        finally:
            park.release.set()
        streamed = await asyncio.wait_for(turn, _WAIT_S)

    assert (stop.status_code, stop.json()) == (200, _STOPPED)
    assert streamed.status_code == 200, streamed.text
    assert tools.log == ["start store ship", "done store ship"]
    (audit,) = db.audit_rows("tool.call")
    assert (audit["metadata"]["tool"], audit["metadata"]["action"]) == ("memory", "store")
    assert audit["metadata"]["success"] is True
    assert len(llm.streams) == 1
    stored = db.messages_of(chat_id)
    assert _rows(db, chat_id) == [
        ("user", "Save both plans", None, "complete"),
        ("assistant", "", None, "complete"),
        ("tool", _STORED_A, _STORE_A.tool_call_id, "stopped"),
    ]
    assert stored[1]["tool_use_blocks"] == [_block(_STORE_A), _block(_STORE_B)]
    (record,) = stored[-1]["tool_calls"]
    assert (record["tool"], record["action"], record["permission"], record["success"]) == (
        "memory",
        "store",
        "allow",
        True,
    )
    assert _frames(streamed.text) == [
        ("run_started", {"chat_id": str(chat_id)}),
        ("tool_call", record),
        _usage(db, chat_id),
        _saved(db, chat_id, "stopped"),
        ("done", {}),
    ]


async def test_chat_stop_next_message_after_a_stopped_turn_runs_with_a_well_formed_history(
    world: World, llm: _StreamLLM, tools: _Tools, app: FastAPI
) -> None:
    """After the stopped batch the chat is free: a second stop answers ``{"stopped":
    false}`` (the registration is gone) and the next message runs (200, not 409). The LLM
    gets the undispatched call's cancelled tool result before the new user message, and
    that result is stored with the turn."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Plans")
    tools.store_park = park = _Park()
    llm.plan("Save both plans", [LLMResponse(content="", tool_calls=[_STORE_A, _STORE_B])])
    llm.plan("What next?", ["Next ", "steps."])
    cancelled = server._CANCELLED_TOOL_RESULT_MSG

    async with _http(app) as http:
        turn = asyncio.create_task(_stream_turn(http, editor, chat_id, "Save both plans"))
        await _parked(park.parked, turn)
        try:
            stop = await _stop(http, editor, chat_id)
        finally:
            park.release.set()
        stopped = await asyncio.wait_for(turn, _WAIT_S)
        again = await _stop(http, editor, chat_id)
        following = await asyncio.wait_for(
            _stream_turn(http, editor, chat_id, "What next?"), _WAIT_S
        )

    assert (stop.json(), stopped.status_code) == (_STOPPED, 200)
    assert (again.status_code, again.json()) == (200, _NOT_STOPPED)
    assert following.status_code == 200, following.text
    frames = _frames(following.text)
    assert frames[-2:] == [_saved(db, chat_id, "complete"), ("done", {})]
    assert _delta_text(frames) == "Next steps."
    fed = llm.streams[1].messages
    assert [(m["role"], m["content"], m["tool_call_id"]) for m in fed] == [
        ("user", "Save both plans", None),
        ("assistant", "", None),
        ("tool", _STORED_A, _STORE_A.tool_call_id),
        ("tool", cancelled, _STORE_B.tool_call_id),
        ("user", "What next?", None),
    ]
    assert tools.log == ["start store ship", "done store ship"]
    assert _rows(db, chat_id) == [
        ("user", "Save both plans", None, "complete"),
        ("assistant", "", None, "complete"),
        ("tool", _STORED_A, _STORE_A.tool_call_id, "stopped"),
        ("tool", cancelled, _STORE_B.tool_call_id, "complete"),
        ("user", "What next?", None, "complete"),
        ("assistant", "Next steps.", None, "complete"),
    ]


async def test_chat_stop_first_exchange_gets_the_fallback_title_without_a_model_call(
    world: World, llm: _StreamLLM, app: FastAPI
) -> None:
    """An untitled chat's first exchange, stopped: no title request reaches the model, the
    fallback title (the first message) is stored as an ``auto`` title and sent as ``title``
    after message_saved."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor)
    message = "Plan the team offsite in Lucerne"
    expected = chat_titles.fallback_title(message)
    park = _Park()
    llm.plan(message, [park, "never sent"])

    async with _http(app) as http:
        turn = asyncio.create_task(_stream_turn(http, editor, chat_id, message))
        await _parked(park.parked, turn)
        stop = await _stop(http, editor, chat_id)
        streamed = await asyncio.wait_for(turn, _WAIT_S)

    assert (stop.status_code, stop.json()) == (200, _STOPPED)
    assert streamed.status_code == 200, streamed.text
    assert expected
    assert llm.title_calls == []
    chat = db.chat_row(chat_id)
    assert chat is not None
    assert (chat["title"], chat["title_source"]) == (expected, "auto")
    assert _frames(streamed.text) == [
        ("run_started", {"chat_id": str(chat_id)}),
        _usage(db, chat_id),
        _saved(db, chat_id, "stopped"),
        ("title", {"title": expected}),
        ("done", {}),
    ]


async def test_chat_stop_logs_carry_no_message_delta_or_title_text(
    world: World, llm: _StreamLLM, app: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    """A stopped first exchange with deltas (stored, titled with the fallback): no app log
    record holds the message, a delta or the title."""
    caplog.set_level(logging.DEBUG)
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor)
    message = "canary-message-8-osprey needs a plan"
    park = _Park()
    llm.plan(message, ["canary-delta-8-heron ", "canary-tail-8-egret", park])

    async with _http(app) as http:
        turn = asyncio.create_task(_stream_turn(http, editor, chat_id, message))
        await _parked(park.parked, turn)
        stop = await _stop(http, editor, chat_id)
        streamed = await asyncio.wait_for(turn, _WAIT_S)

    assert (stop.json(), streamed.status_code) == (_STOPPED, 200)
    assert _last_status(db, chat_id) == "stopped"
    chat = db.chat_row(chat_id)
    assert chat is not None
    assert chat["title"] == chat_titles.fallback_title(message)
    assert any(record.name.startswith("admino") for record in caplog.records)
    text = _app_log_text(caplog)
    for canary in ("canary-message-8-osprey", "canary-delta-8-heron", "canary-tail-8-egret"):
        assert canary not in text


# ---------------------------------------------------------------------------
# 3. A streamed approval (POST /api/confirm with Accept: text/event-stream)
# ---------------------------------------------------------------------------


async def _ask_to_book(http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID) -> str:
    """A JSON turn whose google_calendar.create waits for confirmation; its confirmation id."""
    asked = await _json_turn(http, account, chat_id, "Book the offsite")
    assert asked.status_code == 200, asked.text
    body = asked.json()
    assert body["status"] == "awaiting_confirmation", asked.text
    confirmation_id: str = body["pending_confirmation"]["confirmation_id"]
    return confirmation_id


async def test_chat_stop_streamed_approval_while_the_follow_up_call_is_parked(
    world: World, llm: _StreamLLM, tools: _Tools, app: FastAPI
) -> None:
    """The approved google_calendar.create runs and is audited; the follow-up LLM call
    parks and the stop closes it; the turn is stored with the tool result last, stopped,
    and the frames are run_started, tool_call, message_saved{stopped}, done."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Offsite")
    llm.reply("Book the offsite", LLMResponse(content="", tool_calls=[_CREATE]))
    park = _Park()
    llm.plan("Book the offsite", [park, "never sent"])

    async with _http(app) as http:
        confirmation_id = await _ask_to_book(http, editor, chat_id)
        approval = asyncio.create_task(_stream_approval(http, editor, chat_id, confirmation_id))
        await _parked(park.parked, approval)
        stop = await _stop(http, editor, chat_id)
        streamed = await asyncio.wait_for(approval, _WAIT_S)

    assert (stop.status_code, stop.json()) == (200, _STOPPED)
    assert streamed.status_code == 200, streamed.text
    assert tools.log == ["start create Offsite", "done create Offsite"]
    assert [row["metadata"]["success"] for row in db.audit_rows("tool.call")] == [False, True]
    (call,) = llm.streams
    assert call.closed_while_parked
    stored = db.messages_of(chat_id)
    assert _rows(db, chat_id) == [
        ("user", "Book the offsite", None, "complete"),
        ("assistant", "", None, "awaiting_confirmation"),
        ("tool", _CREATED, _CREATE.tool_call_id, "stopped"),
    ]
    (record,) = stored[-1]["tool_calls"]
    assert (record["tool"], record["action"], record["success"]) == (
        "google_calendar",
        "create",
        True,
    )
    assert _frames(streamed.text) == [
        ("run_started", {"chat_id": str(chat_id)}),
        ("tool_call", record),
        _usage(db, chat_id),
        _saved(db, chat_id, "stopped"),
        ("done", {}),
    ]


async def test_chat_stop_streamed_approval_during_the_approved_call_finishes_it_without_llm(
    world: World, llm: _StreamLLM, tools: _Tools, app: FastAPI
) -> None:
    """The stop comes while the approved call itself runs: it finishes and is audited, and
    no LLM call follows; the turn is stored with the tool result last, stopped."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Offsite")
    llm.reply("Book the offsite", LLMResponse(content="", tool_calls=[_CREATE]))
    tools.create_park = park = _Park()

    async with _http(app) as http:
        confirmation_id = await _ask_to_book(http, editor, chat_id)
        approval = asyncio.create_task(_stream_approval(http, editor, chat_id, confirmation_id))
        await _parked(park.parked, approval)
        try:
            stop = await _stop(http, editor, chat_id)
        finally:
            park.release.set()
        streamed = await asyncio.wait_for(approval, _WAIT_S)

    assert (stop.status_code, stop.json()) == (200, _STOPPED)
    assert streamed.status_code == 200, streamed.text
    assert tools.log == ["start create Offsite", "done create Offsite"]
    assert [row["metadata"]["success"] for row in db.audit_rows("tool.call")] == [False, True]
    assert llm.streams == []
    assert _rows(db, chat_id)[-1] == ("tool", _CREATED, _CREATE.tool_call_id, "stopped")
    frames = _frames(streamed.text)
    assert _names(frames) == ["run_started", "tool_call", "context_usage", "message_saved", "done"]
    assert frames[2:4] == [_usage(db, chat_id), _saved(db, chat_id, "stopped")]


# ---------------------------------------------------------------------------
# 4. A stop affects its chat only
# ---------------------------------------------------------------------------


async def test_chat_stop_leaves_another_streamed_chat_of_the_user_running(
    world: World, llm: _StreamLLM, app: FastAPI
) -> None:
    """Chats A and B of the Editor stream at once, both parked; stopping A closes A's
    stream only: B is still parked and open afterwards, and completes once released."""
    editor = world.a["editor"]
    db = world.db
    chat_a = seed_chat(db, editor, title="Chat A")
    chat_b = seed_chat(db, editor, title="Chat B")
    park_a, park_b = _Park(), _Park()
    llm.plan("First chat question", [park_a, "never sent"])
    llm.plan("Second chat question", ["Second ", park_b, "answer."])

    async with _http(app) as http:
        turn_a = asyncio.create_task(_stream_turn(http, editor, chat_a, "First chat question"))
        await _parked(park_a.parked, turn_a)
        turn_b = asyncio.create_task(_stream_turn(http, editor, chat_b, "Second chat question"))
        await _parked(park_b.parked, turn_b)
        try:
            stop = await _stop(http, editor, chat_a)
            streamed_a = await asyncio.wait_for(turn_a, _WAIT_S)
            (call_b,) = [call for call in llm.streams if call.user_message.startswith("Second")]
            b_open = (not call_b.closed, not turn_b.done())
        finally:
            park_b.release.set()
        streamed_b = await asyncio.wait_for(turn_b, _WAIT_S)

    assert (stop.status_code, stop.json()) == (200, _STOPPED)
    assert streamed_a.status_code == 200, streamed_a.text
    assert _rows(db, chat_a)[-1] == ("user", "First chat question", None, "stopped")
    assert b_open == (True, True)
    assert call_b.finished
    assert streamed_b.status_code == 200, streamed_b.text
    frames_b = _frames(streamed_b.text)
    assert frames_b[-2:] == [_saved(db, chat_b, "complete"), ("done", {})]
    assert _delta_text(frames_b) == "Second answer."
    assert _rows(db, chat_b) == [
        ("user", "Second chat question", None, "complete"),
        ("assistant", "Second answer.", None, "complete"),
    ]


# ---------------------------------------------------------------------------
# 5. Client disconnect (raw ASGI, spec 2.3 and 2.4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("spec_version", "oserror"), _DISCONNECTS)
async def test_chat_stop_disconnect_while_the_llm_is_parked_stops_and_stores_the_turn(
    world: World, llm: _StreamLLM, app: FastAPI, spec_version: str, oserror: bool
) -> None:
    """The client goes away while the LLM is parked after three deltas: the stream is
    closed while still parked, the forwarded text is stored as the stopped reply (C11: up
    to its last ASCII whitespace, the unfinished "ver" dropped), and the request
    coroutine returns."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Report")
    park = _Park()
    llm.plan("Write the report", ["Report ", "draft ", "ver", park, "sion never sent"])

    wire, request = _start_raw_turn(
        app, editor, chat_id, "Write the report", spec_version, oserror=oserror
    )
    await _parked(park.parked, request)
    wire.disconnected.set()
    await asyncio.wait_for(request, _WAIT_S)
    await _until(lambda: _last_status(db, chat_id) == "stopped")

    assert wire.status() == 200
    (call,) = llm.streams
    assert call.closed_while_parked
    assert not park.release.is_set()
    assert _rows(db, chat_id) == [
        ("user", "Write the report", None, "complete"),
        ("assistant", "Report draft ", None, "stopped"),
    ]


@pytest.mark.parametrize(("spec_version", "oserror"), _DISCONNECTS)
async def test_chat_stop_disconnect_while_a_tool_runs_finishes_it_and_stores_the_turn(
    world: World,
    llm: _StreamLLM,
    tools: _Tools,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    spec_version: str,
    oserror: bool,
) -> None:
    """The client goes away while the first of two memory.store calls runs: once the stop
    is requested the call is released; it finishes and is audited, the second one is never
    dispatched, no follow-up LLM call is made, and the turn is stored with the tool result
    last, stopped."""
    runtime = _watch_stops(monkeypatch)
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor, title="Plans")
    tools.store_park = park = _Park()
    llm.plan("Save both plans", [LLMResponse(content="", tool_calls=[_STORE_A, _STORE_B])])

    wire, request = _start_raw_turn(
        app, editor, chat_id, "Save both plans", spec_version, oserror=oserror
    )
    await _parked(park.parked, request)
    try:
        wire.disconnected.set()
        await _until(lambda: bool(runtime.stops) and runtime.stops[-1].is_set())
    finally:
        park.release.set()
    await asyncio.wait_for(request, _WAIT_S)
    await _until(lambda: _last_status(db, chat_id) == "stopped")

    assert tools.log == ["start store ship", "done store ship"]
    (audit,) = db.audit_rows("tool.call")
    assert audit["metadata"]["success"] is True
    assert len(llm.streams) == 1
    assert _rows(db, chat_id) == [
        ("user", "Save both plans", None, "complete"),
        ("assistant", "", None, "complete"),
        ("tool", _STORED_A, _STORE_A.tool_call_id, "stopped"),
    ]


async def test_chat_stop_disconnect_on_a_first_exchange_still_stores_the_fallback_title(
    world: World, llm: _StreamLLM, app: FastAPI
) -> None:
    """ASGI 2.4 with a send that fails once the client is gone: the stopped first exchange
    is stored and the title step still runs after it, storing the fallback title without a
    model call."""
    editor = world.a["editor"]
    db = world.db
    chat_id = seed_chat(db, editor)
    message = "Sketch the hiking route"
    expected = chat_titles.fallback_title(message)
    park = _Park()
    llm.plan(message, [park, "never sent"])

    wire, request = _start_raw_turn(app, editor, chat_id, message, "2.4", oserror=True)
    await _parked(park.parked, request)
    wire.disconnected.set()
    await asyncio.wait_for(request, _WAIT_S)
    await _until(lambda: (db.chat_row(chat_id) or {}).get("title") == expected)

    assert expected
    assert _rows(db, chat_id) == [("user", message, None, "stopped")]
    assert llm.title_calls == []
