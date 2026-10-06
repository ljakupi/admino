"""Per-request, content-free timings of the chat turn routes (GH-244).

Measures where a chat turn's time goes between its arrival and the first LLM
byte, and logs one line per turn request. The record of the current request
lives in a ``ContextVar``: a task started by the request (a streamed turn's run
task) copies the context and so updates the same record.

Inputs:
- ``TimingMiddleware`` (installed by the server) opens a record for every
  ``POST`` on a turn path: ``/api/chats/{chat_id}/messages`` (route
  ``chat_message``), ``/api/message`` (``message``) and
  ``/api/confirm/{confirmation_id}`` (``confirm``), and records the status of
  ``http.response.start``. Any other request passes through untouched.
- The measuring hooks: ``db_statement()`` (``database.TimedPool``, each SQL
  statement), ``llm_call()`` and ``llm_first_byte()`` (the agent, each LLM call
  and its first item), ``tool_call()`` (the agent, each tool dispatch), and
  ``detach()`` / ``finish()`` (the server: a streamed turn's line is written by
  its run task once the turn is stored, not when the response ends). Every hook
  is a no-op without a current record and once the record is closed, so work
  after the line (a chat-title call) never counts.

Outputs: one INFO line on the ``admino.request_timing`` logger per turn
request, whatever its outcome (refusals and errors included)::

    chat timings: request_id=<hex|-> route=<route> status=<int> db_queries=<n>
    db_queries_before_llm=<n|-> db_ms=<x.x> llm_start_ms=<x.x|->
    llm_first_byte_ms=<x.x|-> llm_ms=<x.x> tool_ms=<x.x> total_ms=<x.x>

(one line in the log). Times are milliseconds from the request's arrival
(``llm_start_ms``, ``llm_first_byte_ms``, ``total_ms``) or summed durations
(``db_ms``, ``llm_ms``, ``tool_ms``).

Security notes:
- Content-free (tracker #139 §5): the line carries the server-generated
  request ID, a fixed route label, the status, counts and durations only.
  Never a path segment (chat or confirmation id), query, header, body, user,
  org or session id, model name, tool name, SQL, argument, result or error
  text: the hooks receive nothing but the timing of a block, and nothing else
  is logged by this module.
- The middleware never changes the exchange: every request and response
  message passes through unchanged.
- Standard library and ``admino.logs`` only (Starlette's ASGI types are used
  for annotations only).
"""

from __future__ import annotations

import logging
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from admino.logs import request_id_var, safe_log

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

# Seconds. Looked up at call time by every measurement (here and in
# database.TimedPool), so a test can replace it with a fake clock.
_clock: Callable[[], float] = time.perf_counter

# The turn paths (matched in full against a POST's path) and their labels:
# the label, never the path, reaches the line (the path holds an id).
_TURN_ROUTES: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"/api/chats/[^/]+/messages"), "chat_message"),
    (re.compile(r"/api/message"), "message"),
    (re.compile(r"/api/confirm/[^/]+"), "confirm"),
)


@dataclass(slots=True)
class _Record:
    """One turn request's measurements, in seconds (``start`` is a ``_clock`` reading)."""

    route: str
    start: float
    status: int | None = None
    db_queries: int = 0
    db_s: float = 0.0
    db_queries_before_llm: int | None = None
    llm_start_s: float | None = None
    llm_first_byte_s: float | None = None
    llm_s: float = 0.0
    tool_s: float = 0.0
    detached: bool = False
    closed: bool = False


_current: ContextVar[_Record | None] = ContextVar("admino_request_timing", default=None)


def _open_record() -> _Record | None:
    """The current request's record, or None without one or once it is closed."""
    record = _current.get()
    if record is None or record.closed:
        return None
    return record


@contextmanager
def db_statement() -> Iterator[None]:
    """Count one SQL statement and add its duration (also when it raises)."""
    record = _open_record()
    start = _clock()
    try:
        yield
    finally:
        if record is not None:
            record.db_queries += 1
            record.db_s += _clock() - start


@contextmanager
def llm_call() -> Iterator[None]:
    """Measure one LLM call (its retries and their waits included), also when it raises.

    The request's first LLM call also marks the server overhead: the time from
    the request's arrival to the call, and the statements run before it.
    """
    record = _open_record()
    start = _clock()
    if record is not None and record.llm_start_s is None:
        record.llm_start_s = start - record.start
        record.db_queries_before_llm = record.db_queries
    try:
        yield
    finally:
        if record is not None:
            record.llm_s += _clock() - start


def llm_first_byte() -> None:
    """Mark the request's first item from the provider; later calls change nothing."""
    record = _open_record()
    if record is not None and record.llm_first_byte_s is None:
        record.llm_first_byte_s = _clock() - record.start


@contextmanager
def tool_call() -> Iterator[None]:
    """Add one tool dispatch's duration (also when it raises)."""
    record = _open_record()
    start = _clock()
    try:
        yield
    finally:
        if record is not None:
            record.tool_s += _clock() - start


def detach() -> None:
    """Leave the current record's line to ``finish()`` instead of the response's end.

    A streamed turn's response ends before its run does; the run task calls
    ``finish()`` once the turn is stored and reported.
    """
    record = _open_record()
    if record is not None:
        record.detached = True


def finish() -> None:
    """Log the current record's line and close it; without an open record, nothing."""
    record = _open_record()
    if record is not None:
        _close(record)


def _ms(seconds: float | None) -> str:
    """Milliseconds with one decimal, or ``-`` for a moment that never came."""
    return "-" if seconds is None else f"{seconds * 1000:.1f}"


def _close(record: _Record) -> None:
    """Write the record's line, once."""
    if record.closed:
        return
    record.closed = True
    status = record.status
    if status is None:
        # No response started. A detached (streamed) turn's response is a 200
        # stream; otherwise the app raised or never answered, and the outer
        # request-ID middleware answers 500.
        status = 200 if record.detached else 500
    before_llm = record.db_queries_before_llm
    logger.info(
        "chat timings: request_id=%s route=%s status=%d db_queries=%d "
        "db_queries_before_llm=%s db_ms=%.1f llm_start_ms=%s llm_first_byte_ms=%s "
        "llm_ms=%.1f tool_ms=%.1f total_ms=%.1f",
        safe_log(request_id_var.get() or "-"),
        record.route,
        status,
        record.db_queries,
        "-" if before_llm is None else str(before_llm),
        record.db_s * 1000,
        _ms(record.llm_start_s),
        _ms(record.llm_first_byte_s),
        record.llm_s * 1000,
        record.tool_s * 1000,
        (_clock() - record.start) * 1000,
    )


def _turn_route(scope: Scope) -> str | None:
    """The route label of a POST on a turn path; None for every other request."""
    if scope["type"] != "http" or scope["method"] != "POST":
        return None
    for pattern, route in _TURN_ROUTES:
        if pattern.fullmatch(scope["path"]):
            return route
    return None


class TimingMiddleware:
    """Opens a timing record for each turn request and writes its line when it ends.

    A pure ASGI middleware, installed right inside the request-ID middleware
    (the request ID is set) and outside every other one. The line is written
    once the last body message has been sent (not when the app returns: a
    Starlette background task runs after the response and must not count), or
    when the app returns or raises without that, unless the record was
    detached (``detach()``): then ``finish()`` writes it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Run the request inside its record; other requests pass through untouched."""
        route = _turn_route(scope)
        if route is None:
            await self._app(scope, receive, send)
            return
        record = _Record(route=route, start=_clock())
        token = _current.set(record)

        async def send_timed(message: Message) -> None:
            if message["type"] == "http.response.start":
                record.status = message["status"]
            await send(message)
            if (
                message["type"] == "http.response.body"
                and not message.get("more_body", False)
                and not record.detached
            ):
                _close(record)

        try:
            await self._app(scope, receive, send_timed)
        finally:
            if not record.detached:
                _close(record)
            _current.reset(token)
