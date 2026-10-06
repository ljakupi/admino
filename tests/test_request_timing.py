"""Per-request chat timings: ``admino.request_timing`` (GH-244, contract C1).

Acceptance criterion: each chat request logs content-free timings (request ID,
DB ms, ms to the first LLM byte, LLM ms, tool ms and total ms). Tracker #139
§5: logs carry IDs, counts, sizes, statuses and durations only.

Pinned here, on a small FastAPI app wrapped exactly like production
(``TimingMiddleware`` inside ``admino.server.RequestIdMiddleware``, so the
request ID is set), with ``request_timing._clock`` replaced by a fake clock the
handlers advance, so every duration is exact:
- One INFO line (logger ``admino.request_timing``) per POST on the three turn
  paths (``/api/chats/{id}/messages`` -> ``chat_message``, ``/api/message`` ->
  ``message``, ``/api/confirm/{id}`` -> ``confirm``; the id segment is any
  non-empty segment, a non-UUID included), whatever the outcome (200, a 4xx,
  500 when the handler raises); nothing for a GET on a turn path, any other
  path or a near miss of a turn path; nothing else is logged by the module.
- The line's exact format (C1.3) and field semantics (C1.2): statement count
  and summed DB time, the statement count and ms at the FIRST ``llm_call``,
  the first ``llm_first_byte`` (later ones change nothing), summed LLM and
  tool time, a duration also counted when the measured block raises, ``-`` and
  ``0.0`` without an LLM call, ``total_ms`` up to the end of the response, and
  ``request_id`` equal to the response's ``X-Request-ID`` (never an incoming
  one; ``-`` without the request-ID middleware).
- ``detach()``: the middleware doesn't write the line; ``finish()`` from the
  task the handler started writes it, once, with status 200.
- Hooks are no-ops without a record and once the record is closed (work in a
  Starlette BackgroundTask or a task resumed after the response changes and
  re-logs nothing); ``finish()`` is idempotent; concurrent requests keep their
  own records.
- The middleware passes every response message and the request's ``receive``
  through unchanged, and leaves a non-HTTP scope alone.
- No content: canary strings in the path, query, cookie, body, response and an
  exception message never reach the module's records.

``admino.request_timing`` is new, so it is imported lazily (in fixtures and
helpers): the file collects before it exists and every test fails on its own.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from admino.server import RequestIdMiddleware

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import Message, Receive, Scope, Send

    # What every route of the test app runs.
    Handler = Callable[[Request], Awaitable[Response]]


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
_HEX32: Final = re.compile(r"[0-9a-f]{32}")
_BOUND_S: Final = 5.0

_CHAT_PATH: Final = "/api/chats/3f9c2a51-7d4e-4b8a-9c1d-2e5f6a7b8c9d/messages"
_MESSAGE_PATH: Final = "/api/message"
_CONFIRM_PATH: Final = "/api/confirm/conf-7Hq2"

# Content canaries: none of them may reach a record of the module.
_CANARY_CHAT_ID: Final = "chatcanary0b7e"
_CANARY_CONFIRM_ID: Final = "confirmcanary5d21"
_CANARY_QUERY: Final = "querycanary9931"
_CANARY_COOKIE: Final = "cookiecanary6620"
_CANARY_TEXT: Final = "Pineapple canary message 4417"
_CANARY_RESPONSE: Final = "responsecanary2741"
_CANARY_ERROR: Final = "errorcanary3108 secret detail"
# A well-formed incoming X-Request-ID: RequestIdMiddleware ignores it, so must the line.
_INCOMING_REQUEST_ID: Final = "c0ffee" * 5 + "ab"


# ---------------------------------------------------------------------------
# Test doubles and helpers
# ---------------------------------------------------------------------------


class _Clock:
    """The fake ``request_timing._clock``: seconds, moved only by ``advance``."""

    def __init__(self) -> None:
        self.now = 500.0

    def __call__(self) -> float:
        return self.now

    def advance(self, ms: float) -> None:
        self.now += ms / 1000


async def _ok(_request: Request) -> Response:
    return JSONResponse({"ok": True})


@dataclass
class _Harness:
    """The test app's client, its fake clock and the handler every route runs."""

    rt: Any
    clock: _Clock
    caplog: pytest.LogCaptureFixture
    handler: Handler = _ok
    client: httpx.AsyncClient | None = None
    handled: list[str] = field(default_factory=list)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        assert self.client is not None
        return await self.client.post(path, **kwargs)

    async def get(self, path: str) -> httpx.Response:
        assert self.client is not None
        return await self.client.get(path)

    def records(self) -> list[tuple[int, str]]:
        """(level, message) of every record of the module, in order."""
        return [
            (record.levelno, record.getMessage())
            for record in self.caplog.records
            if record.name == _LOGGER or record.name.startswith(_LOGGER + ".")
        ]


def _build_app(harness: _Harness, timing_middleware: Any) -> FastAPI:
    """Routes at the turn paths and a few others, all running ``harness.handler``.

    Wrapped like production: TimingMiddleware first, then RequestIdMiddleware
    (``add_middleware`` puts the last one outermost).
    """
    app = FastAPI()

    async def endpoint(request: Request) -> Response:
        harness.handled.append(f"{request.method}:{request.url.path}")
        return await harness.handler(request)

    for path in (
        "/api/chats/{chat_id}/messages",
        "/api/message",
        "/api/confirm/{confirmation_id}",
        "/api/chats/{chat_id}/stop",
        "/api/chats",
        "/api/chats/{chat_id}/messages/{extra}",
        "/x/api/message",
        "/api/chats/{a}/{b}/messages",
    ):
        app.add_route(path, endpoint, methods=["GET", "POST"])
    app.add_middleware(timing_middleware)
    app.add_middleware(RequestIdMiddleware)
    return app


@pytest.fixture()
def rt() -> Any:
    """The new module (imported lazily: it doesn't exist before GH-244)."""
    from admino import request_timing

    return request_timing


@pytest.fixture()
def clock(rt: Any, monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(rt, "_clock", fake)
    return fake


@pytest.fixture()
async def harness(
    rt: Any, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> AsyncIterator[_Harness]:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    harness = _Harness(rt=rt, clock=clock, caplog=caplog)
    app = _build_app(harness, rt.TimingMiddleware)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        harness.client = client
        yield harness


def _line(
    request_id: str,
    route: str,
    status: int = 200,
    *,
    db_queries: int = 0,
    before: str = "-",
    db_ms: str = "0.0",
    llm_start: str = "-",
    first_byte: str = "-",
    llm_ms: str = "0.0",
    tool_ms: str = "0.0",
    total: str = "0.0",
) -> str:
    """The exact C1.3 line for these values."""
    return (
        f"chat timings: request_id={request_id} route={route} status={status} "
        f"db_queries={db_queries} db_queries_before_llm={before} db_ms={db_ms} "
        f"llm_start_ms={llm_start} llm_first_byte_ms={first_byte} llm_ms={llm_ms} "
        f"tool_ms={tool_ms} total_ms={total}"
    )


def _fields(line: str) -> dict[str, str]:
    """The line's ``name=value`` fields (the line must match the contract's regex)."""
    assert _LINE_RE.fullmatch(line), f"not a C1.3 timing line: {line!r}"
    return dict(part.split("=", 1) for part in line.removeprefix("chat timings: ").split(" "))


def _rid(response: httpx.Response) -> str:
    request_id = response.headers.get("x-request-id", "")
    assert _HEX32.fullmatch(request_id), "the response must carry a generated X-Request-ID"
    return request_id


def _http_scope(method: str, path: str) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }


# ===========================================================================
# 1. Which requests log a line
# ===========================================================================


@pytest.mark.parametrize(
    ("path", "route"),
    [
        pytest.param(_CHAT_PATH, "chat_message", id="chat_message"),
        pytest.param(
            "/api/chats/not-a-uuid/messages", "chat_message", id="chat_message-not-a-uuid"
        ),
        pytest.param(_MESSAGE_PATH, "message", id="message"),
        pytest.param(_CONFIRM_PATH, "confirm", id="confirm"),
    ],
)
async def test_request_timing_post_on_a_turn_path_logs_one_line_with_its_route(
    harness: _Harness, path: str, route: str
) -> None:
    response = await harness.post(path, json={"text": "hi"})

    assert response.status_code == 200
    assert harness.records() == [(logging.INFO, _line(_rid(response), route))]
    assert _fields(harness.records()[0][1])["route"] == route  # the contract's regex holds


@pytest.mark.parametrize(
    ("method", "path", "routed"),
    [
        pytest.param("GET", _CHAT_PATH, True, id="GET-chat_message"),
        pytest.param("GET", _MESSAGE_PATH, True, id="GET-message"),
        pytest.param("GET", _CONFIRM_PATH, True, id="GET-confirm"),
        pytest.param("POST", "/api/chats/c-1/stop", True, id="POST-stop"),
        pytest.param("POST", "/api/chats", True, id="POST-chats"),
        pytest.param("POST", "/api/chats/c-1/messages/extra", True, id="POST-suffix"),
        pytest.param("POST", "/x/api/message", True, id="POST-prefix"),
        pytest.param("POST", "/api/chats/a/b/messages", True, id="POST-two-segments"),
        pytest.param("POST", "/api/confirm/", False, id="POST-empty-confirmation-id"),
    ],
)
async def test_request_timing_other_requests_log_nothing_and_get_no_record(
    harness: _Harness, method: str, path: str, routed: bool
) -> None:
    """Even a handler that calls every hook and finish() logs nothing off the turn paths.

    The POST on /api/message afterwards proves the capture works (one line).
    """
    rt, clock = harness.rt, harness.clock

    async def busy(_request: Request) -> Response:
        with rt.db_statement():
            clock.advance(1)
        with rt.llm_call():
            clock.advance(1)
            rt.llm_first_byte()
        with rt.tool_call():
            clock.advance(1)
        rt.finish()
        return JSONResponse({"ok": True})

    harness.handler = busy
    if method == "GET":
        await harness.get(path)
    else:
        await harness.post(path, json={"text": "hi"})
    harness.handler = _ok
    control = await harness.post(_MESSAGE_PATH, json={"text": "hi"})

    assert harness.handled == [f"{method}:{path}"] * routed + ["POST:/api/message"]
    assert harness.records() == [(logging.INFO, _line(_rid(control), "message"))]


# ===========================================================================
# 2. The fields
# ===========================================================================


async def test_request_timing_line_fields_follow_the_requests_hooks_exactly(
    harness: _Harness,
) -> None:
    """Two statements, an LLM call (two first-byte marks), a tool with a statement,
    a second LLM call, a second tool and a last statement: every field exact."""
    rt, clock = harness.rt, harness.clock

    async def turn(_request: Request) -> Response:
        clock.advance(2)
        with rt.db_statement():
            clock.advance(3)
        with rt.db_statement():
            await asyncio.sleep(0)
            clock.advance(4)
        clock.advance(1)
        with rt.llm_call():  # at 10 ms, after 2 statements
            clock.advance(5)
            rt.llm_first_byte()  # at 15 ms
            await asyncio.sleep(0)
            clock.advance(20)
            rt.llm_first_byte()  # later: ignored
        with rt.tool_call():
            clock.advance(2)
            with rt.db_statement():
                clock.advance(3)
            clock.advance(1)
        with rt.llm_call():
            clock.advance(8)
            rt.llm_first_byte()
        with rt.tool_call():
            await asyncio.sleep(0)
            clock.advance(4)
        with rt.db_statement():
            clock.advance(1.5)
        return JSONResponse({"ok": True})

    harness.handler = turn
    response = await harness.post(_CHAT_PATH, json={"text": "hi"})

    assert harness.records() == [
        (
            logging.INFO,
            _line(
                _rid(response),
                "chat_message",
                db_queries=4,
                before="2",
                db_ms="11.5",
                llm_start="10.0",
                first_byte="15.0",
                llm_ms="33.0",
                tool_ms="10.0",
                total="54.5",
            ),
        )
    ]


async def test_request_timing_only_the_first_llm_call_and_first_byte_count_as_firsts(
    harness: _Harness,
) -> None:
    """The first LLM call (which raised, no byte) sets llm_start_ms and the statement
    count; the first byte of the second call sets llm_first_byte_ms; the third call's
    byte changes nothing; every call's time is summed."""
    rt, clock = harness.rt, harness.clock

    async def turn(_request: Request) -> Response:
        clock.advance(1)
        with rt.db_statement():
            clock.advance(2)
        try:
            with rt.llm_call():  # at 3 ms, after 1 statement
                clock.advance(4)
                raise TimeoutError
        except TimeoutError:
            pass
        with rt.db_statement():
            clock.advance(1)
        with rt.llm_call():  # at 8 ms, after 2 statements: no change
            clock.advance(2)
            rt.llm_first_byte()  # at 10 ms
            clock.advance(3)
        with rt.llm_call():
            clock.advance(1)
            rt.llm_first_byte()  # at 14 ms: ignored
        return JSONResponse({"ok": True})

    harness.handler = turn
    response = await harness.post(_MESSAGE_PATH, json={"text": "hi"})

    assert harness.records() == [
        (
            logging.INFO,
            _line(
                _rid(response),
                "message",
                db_queries=2,
                before="1",
                db_ms="3.0",
                llm_start="3.0",
                first_byte="10.0",
                llm_ms="10.0",
                total="14.0",
            ),
        )
    ]


@pytest.mark.parametrize(
    ("hook", "expected"),
    [
        pytest.param("db_statement", {"db_queries": 1, "db_ms": "4.0"}, id="db_statement"),
        pytest.param(
            "llm_call",
            {"before": "0", "llm_start": "1.0", "llm_ms": "4.0"},
            id="llm_call",
        ),
        pytest.param("tool_call", {"tool_ms": "4.0"}, id="tool_call"),
    ],
)
async def test_request_timing_measured_block_that_raises_still_counts_and_reraises(
    harness: _Harness, hook: str, expected: dict[str, Any]
) -> None:
    rt, clock = harness.rt, harness.clock
    boom = LookupError("measured block failed")
    escaped: list[BaseException] = []

    async def turn(_request: Request) -> Response:
        clock.advance(1)
        try:
            with getattr(rt, hook)():
                clock.advance(4)
                raise boom
        except LookupError as exc:
            escaped.append(exc)
        return JSONResponse({"ok": True})

    harness.handler = turn
    response = await harness.post(_CONFIRM_PATH, json={"text": "hi"})

    assert escaped == [boom]
    assert escaped[0] is boom
    assert harness.records() == [
        (logging.INFO, _line(_rid(response), "confirm", total="5.0", **expected))
    ]


async def test_request_timing_without_an_llm_call_logs_dashes_and_zero_llm_ms(
    harness: _Harness,
) -> None:
    rt, clock = harness.rt, harness.clock

    async def turn(_request: Request) -> Response:
        with rt.db_statement():
            clock.advance(2)
        with rt.tool_call():
            clock.advance(3)
        clock.advance(0.25)
        return JSONResponse({"ok": True})

    harness.handler = turn
    response = await harness.post(_CHAT_PATH, json={"text": "hi"})

    assert harness.records() == [
        (
            logging.INFO,
            _line(
                _rid(response),
                "chat_message",
                db_queries=1,
                db_ms="2.0",
                tool_ms="3.0",
                total="5.2",
            ),
        )
    ]


# ===========================================================================
# 3. Status and request ID
# ===========================================================================


async def _returns_409(_request: Request) -> Response:
    return JSONResponse({"detail": {"code": "chat_busy"}}, status_code=409)


async def _raises_404(_request: Request) -> Response:
    raise HTTPException(status_code=404, detail="Chat not found")


@pytest.mark.parametrize(
    ("handler", "status"),
    [
        pytest.param(_returns_409, 409, id="returned-409"),
        pytest.param(_raises_404, 404, id="http-exception-404"),
    ],
)
async def test_request_timing_refusal_logs_one_line_with_the_responses_status(
    harness: _Harness, handler: Handler, status: int
) -> None:
    harness.handler = handler
    response = await harness.post(_CHAT_PATH, json={"text": "hi"})

    assert response.status_code == status
    assert harness.records() == [(logging.INFO, _line(_rid(response), "chat_message", status))]


async def test_request_timing_handler_exception_logs_one_line_with_status_500(
    harness: _Harness,
) -> None:
    rt, clock = harness.rt, harness.clock

    async def turn(_request: Request) -> Response:
        with rt.db_statement():
            clock.advance(2)
        clock.advance(1)
        raise RuntimeError("handler failed")

    harness.handler = turn
    response = await harness.post(_MESSAGE_PATH, json={"text": "hi"})

    assert response.status_code == 500
    assert harness.records() == [
        (
            logging.INFO,
            _line(_rid(response), "message", 500, db_queries=1, db_ms="2.0", total="3.0"),
        )
    ]


async def test_request_timing_request_id_is_the_responses_never_the_incoming_one(
    harness: _Harness,
) -> None:
    response = await harness.post(
        _MESSAGE_PATH, json={"text": "hi"}, headers={"X-Request-ID": _INCOMING_REQUEST_ID}
    )

    [(_, line)] = harness.records()
    assert _fields(line)["request_id"] == response.headers["x-request-id"]
    assert _fields(line)["request_id"] != _INCOMING_REQUEST_ID


async def test_request_timing_without_the_request_id_middleware_logs_a_dash(
    rt: Any, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        clock.advance(2)
        await send({"type": "http.response.start", "status": 201, "headers": []})
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    await rt.TimingMiddleware(app)(_http_scope("POST", _MESSAGE_PATH), receive, send)

    assert [(r.levelno, r.getMessage()) for r in caplog.records if r.name == _LOGGER] == [
        (logging.INFO, _line("-", "message", 201, total="2.0"))
    ]


# ===========================================================================
# 4. Detached (streamed) turns, work after the response, idempotent finish
# ===========================================================================


async def test_request_timing_detached_record_is_logged_once_by_finish_not_the_middleware(
    harness: _Harness,
) -> None:
    """The handler detaches and starts the run task; the response ends without a
    line; the task's finish() writes it (status 200, its request ID), once; hooks
    and a second finish() afterwards change nothing."""
    rt, clock = harness.rt, harness.clock
    release = asyncio.Event()
    tasks: list[asyncio.Task[None]] = []

    async def run() -> None:
        await asyncio.wait_for(release.wait(), _BOUND_S)
        with rt.llm_call():  # at 13 ms, after 1 statement
            clock.advance(4)
            rt.llm_first_byte()  # at 17 ms
            clock.advance(1)
        with rt.tool_call():
            clock.advance(3)
        with rt.db_statement():
            clock.advance(2)
        rt.finish()  # at 23 ms
        clock.advance(50)
        with rt.db_statement():
            clock.advance(50)
        with rt.llm_call():
            clock.advance(50)
            rt.llm_first_byte()
        with rt.tool_call():
            clock.advance(50)
        rt.finish()

    async def turn(_request: Request) -> Response:
        clock.advance(1)
        with rt.db_statement():
            clock.advance(2)
        rt.detach()
        tasks.append(asyncio.create_task(run()))

        async def frames() -> AsyncIterator[bytes]:
            yield b"event: delta\ndata: {}\n\n"

        return StreamingResponse(frames(), media_type="text/event-stream")

    harness.handler = turn
    response = await harness.post(_CHAT_PATH, json={"text": "hi"})
    logged_before_finish = harness.records()
    clock.advance(10)
    release.set()
    await asyncio.wait_for(tasks[0], _BOUND_S)

    assert (response.status_code, logged_before_finish) == (200, [])
    assert harness.records() == [
        (
            logging.INFO,
            _line(
                _rid(response),
                "chat_message",
                db_queries=2,
                before="1",
                db_ms="4.0",
                llm_start="13.0",
                first_byte="17.0",
                llm_ms="5.0",
                tool_ms="3.0",
                total="23.0",
            ),
        )
    ]


async def test_request_timing_background_task_after_the_response_changes_and_relogs_nothing(
    harness: _Harness,
) -> None:
    """A JSON turn's work after the response (e.g. its title call) never counts."""
    rt, clock = harness.rt, harness.clock

    async def after_response() -> None:
        clock.advance(40)
        with rt.db_statement():
            clock.advance(40)
        with rt.llm_call():
            clock.advance(40)
            rt.llm_first_byte()
        with rt.tool_call():
            clock.advance(40)
        rt.finish()

    async def turn(_request: Request) -> Response:
        with rt.db_statement():
            clock.advance(2)
        clock.advance(1)
        return JSONResponse({"ok": True}, background=BackgroundTask(after_response))

    harness.handler = turn
    response = await harness.post(_CHAT_PATH, json={"text": "hi"})

    assert harness.clock.now == pytest.approx(500.163), "the background task must have run"
    assert harness.records() == [
        (
            logging.INFO,
            _line(_rid(response), "chat_message", db_queries=1, db_ms="2.0", total="3.0"),
        )
    ]


async def test_request_timing_task_resumed_after_the_response_changes_and_relogs_nothing(
    harness: _Harness,
) -> None:
    """A task the (not detached) handler started, resumed once the response ended:
    its hooks and its finish() are no-ops on the closed record."""
    rt, clock = harness.rt, harness.clock
    release = asyncio.Event()
    tasks: list[asyncio.Task[None]] = []

    async def later() -> None:
        await asyncio.wait_for(release.wait(), _BOUND_S)
        with rt.db_statement():
            clock.advance(30)
        with rt.llm_call():
            clock.advance(30)
            rt.llm_first_byte()
        with rt.tool_call():
            clock.advance(30)
        rt.finish()

    async def turn(_request: Request) -> Response:
        clock.advance(2)
        tasks.append(asyncio.create_task(later()))
        return JSONResponse({"ok": True})

    harness.handler = turn
    response = await harness.post(_MESSAGE_PATH, json={"text": "hi"})
    release.set()
    await asyncio.wait_for(tasks[0], _BOUND_S)

    assert harness.records() == [(logging.INFO, _line(_rid(response), "message", total="2.0"))]


async def test_request_timing_hooks_without_a_record_do_nothing(harness: _Harness) -> None:
    """Outside any request every hook and finish() are silent no-ops; the next
    request's record starts empty."""
    rt, clock = harness.rt, harness.clock
    with rt.db_statement():
        clock.advance(5)
    with rt.llm_call():
        clock.advance(5)
        rt.llm_first_byte()
    with rt.tool_call():
        clock.advance(5)
    rt.detach()
    rt.finish()
    rt.finish()
    silent = harness.records()

    response = await harness.post(_CONFIRM_PATH, json={"text": "hi"})

    assert silent == []
    assert harness.records() == [(logging.INFO, _line(_rid(response), "confirm"))]


async def test_request_timing_concurrent_requests_keep_their_own_records(
    harness: _Harness,
) -> None:
    """Both requests are inside their handlers before either measures anything, and
    neither leaves before both have: each line counts only its own statements."""
    rt = harness.rt
    entered = {"message": asyncio.Event(), "confirm": asyncio.Event()}
    measured = {"message": asyncio.Event(), "confirm": asyncio.Event()}
    statements = {"message": 1, "confirm": 3}

    async def turn(request: Request) -> Response:
        me = "message" if request.url.path == _MESSAGE_PATH else "confirm"
        other = "confirm" if me == "message" else "message"
        entered[me].set()
        await asyncio.wait_for(entered[other].wait(), _BOUND_S)
        for _ in range(statements[me]):
            with rt.db_statement():
                await asyncio.sleep(0)
        measured[me].set()
        await asyncio.wait_for(measured[other].wait(), _BOUND_S)
        return JSONResponse({"ok": True})

    harness.handler = turn
    await asyncio.gather(
        harness.post(_MESSAGE_PATH, json={"text": "a"}),
        harness.post(_CONFIRM_PATH, json={"text": "b"}),
    )

    counts = sorted(
        (_fields(line)["route"], _fields(line)["db_queries"]) for _, line in harness.records()
    )
    assert counts == [("confirm", "3"), ("message", "1")]


# ===========================================================================
# 5. The middleware never changes the exchange
# ===========================================================================


async def test_request_timing_middleware_passes_response_and_request_messages_through(
    rt: Any, clock: _Clock
) -> None:
    """Every message the app sends reaches the server unchanged and in order, and the
    app reads the request (and a later disconnect) from the server's receive."""
    from_server: list[Message] = [
        {"type": "http.request", "body": b'{"text": "a"}', "more_body": True},
        {"type": "http.request", "body": b"", "more_body": False},
        {"type": "http.disconnect"},
    ]
    app_sends: list[Message] = [
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/event-stream"), (b"x-custom", b"1")],
        },
        {"type": "http.response.body", "body": b"event: delta\ndata: {}\n\n", "more_body": True},
        {"type": "http.response.body", "body": b"event: done\ndata: {}\n\n", "more_body": True},
        {"type": "http.response.body", "body": b"", "more_body": False},
    ]
    app_received: list[Message] = []
    server_got: list[Message] = []
    pending = list(from_server)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        for _ in from_server:
            app_received.append(await receive())
        for message in app_sends:
            await send(message)

    async def receive() -> Message:
        return pending.pop(0)

    async def send(message: Message) -> None:
        server_got.append(message)

    await rt.TimingMiddleware(app)(_http_scope("POST", _CHAT_PATH), receive, send)

    assert (app_received, server_got) == (from_server, app_sends)


async def test_request_timing_non_http_scope_passes_through_without_a_record(
    rt: Any, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    scope: dict[str, Any] = {"type": "lifespan", "asgi": {"version": "3.0"}}
    seen: list[tuple[Any, Any, Any]] = []

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(_message: Message) -> None:
        return None

    async def app(app_scope: Scope, app_receive: Receive, app_send: Send) -> None:
        seen.append((app_scope, app_receive, app_send))
        rt.finish()

    await rt.TimingMiddleware(app)(scope, receive, send)

    assert seen == [(scope, receive, send)]
    assert [r for r in caplog.records if r.name == _LOGGER] == []


# ===========================================================================
# 6. No content
# ===========================================================================


async def test_request_timing_lines_carry_no_content(harness: _Harness) -> None:
    """Canaries in the path, query, cookie, body, response and an exception message
    never reach a record of the module (message or args)."""
    rt, clock = harness.rt, harness.clock

    async def turn(request: Request) -> Response:
        await request.body()
        with rt.db_statement():
            clock.advance(1)
        if request.url.path.startswith("/api/confirm/"):
            raise RuntimeError(_CANARY_ERROR)
        return JSONResponse({"reply": _CANARY_RESPONSE})

    harness.handler = turn
    await harness.post(
        f"/api/chats/{_CANARY_CHAT_ID}/messages?q={_CANARY_QUERY}",
        json={"text": _CANARY_TEXT},
        headers={"Cookie": f"admino_session={_CANARY_COOKIE}"},
    )
    await harness.post(f"/api/confirm/{_CANARY_CONFIRM_ID}", json={"text": _CANARY_TEXT})

    records = [r for r in harness.caplog.records if r.name == _LOGGER]
    text = "\n".join(f"{r.getMessage()} {r.args!r}" for r in records).casefold()
    leaked = [
        canary
        for canary in (
            _CANARY_CHAT_ID,
            _CANARY_CONFIRM_ID,
            _CANARY_QUERY,
            _CANARY_COOKIE,
            _CANARY_TEXT,
            "pineapple",
            _CANARY_RESPONSE,
            _CANARY_ERROR,
            "errorcanary3108",
            "runtimeerror",
        )
        if canary.casefold() in text
    ]
    assert [_fields(r.getMessage())["route"] for r in records] == ["chat_message", "confirm"]
    assert leaked == []
