"""Server-sent event transport of streamed chat runs (GH-8).

What the chat routes use to answer a run as ``text/event-stream``, and the
app's shutdown to end the detached runs:

- ``accepts_event_stream``: the content negotiation. A request streams when
  its ``Accept`` header lists ``text/event-stream`` (in any position, in any
  case, parameters ignored) with a ``q`` above 0; anything else keeps the JSON
  answer.
- ``EventStreamResponse``: relays a run's frames as they are queued. It
  watches the client itself, also while no frame is due: Starlette's
  ``StreamingResponse`` never listens for ``http.disconnect`` under ASGI spec
  2.4, where a send to a gone client raises ``OSError`` instead. When the
  client leaves before the last frame, the relay ends and the run's stop
  signal is set; the run itself goes on and is stored. It sends
  ``Cache-Control: no-store`` (GH-278) and ``X-Accel-Buffering: no``.
- ``detach``: starts a run's task apart from its response and keeps it
  referenced, with its stop signal, until it ends, so a gone client never
  ends (or lets the garbage collector drop) a run.
- ``drain``: the app's shutdown asks every detached run to stop and waits for
  them (bounded) before it closes the database pool, so a run whose client
  left still writes its tool call's audit row and stores its turn.

Inputs: the ``Accept`` header value; frames (SSE text, formatted by the
server); the run's stop event; the shutdown's bound.
Outputs: the response's ASGI messages; whether a request streams; how many
runs a bounded shutdown wait left running.

Security notes:
- Frames carry message text, deltas, titles and tool arguments: nothing here
  logs or reads them.
- Nothing waits on a gone client: the relay ends at the disconnect (or the
  failed send), and the run's remaining frames stay in its own queue, bounded
  by the run's output.
- A run is never cancelled here: ``drain`` only sets its stop signal, so a
  dispatch in progress finishes and is recorded.
- Imports nothing of the server, agent, database, LLM or tool modules.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Final

from starlette.responses import StreamingResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterable, Coroutine

    from starlette.types import Receive, Scope, Send

_EVENT_STREAM: Final = "text/event-stream"
# RFC 9110 qvalue: 0 to 1 with at most three decimals.
_QVALUE: Final = re.compile(r"0(?:\.\d{0,3})?|1(?:\.0{0,3})?")
# A stream holds a user's chat, so no browser or proxy keeps a copy (no-store, like
# every /api answer, GH-278); proxies (nginx) must not buffer it either.
_HEADERS: Final = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}

# The detached run tasks and their stop signals. The event loop keeps only weak
# references to tasks, so this map holds each one until it ends.
_detached: dict[asyncio.Task[None], asyncio.Event] = {}


def accepts_event_stream(accept: str) -> bool:
    """Whether an ``Accept`` header value asks for ``text/event-stream``.

    True when one of its media ranges is ``text/event-stream`` (any case,
    surrounding spaces and parameters ignored) with a ``q`` above 0; a missing
    ``q`` is 1, and a ``q`` that isn't a valid qvalue doesn't count. ``*/*``
    and ``text/*`` don't count: they accept the JSON answer.
    """
    for media_range in accept.split(","):
        media_type, *params = media_range.split(";")
        if media_type.strip().lower() != _EVENT_STREAM:
            continue
        quality = "1"
        for param in params:
            name, _, value = param.partition("=")
            if name.strip().lower() == "q":
                quality = value.strip()
        if _QVALUE.fullmatch(quality) and float(quality) > 0:
            return True
    return False


def detach(run: Coroutine[object, None, None], *, stop: asyncio.Event) -> None:
    """Run ``run`` as a task of its own, referenced until it ends.

    ``run`` must handle its own errors: its task is never awaited. ``stop`` is
    the run's stop signal, which ``drain`` sets.
    """
    task = asyncio.create_task(run)
    _detached[task] = stop
    task.add_done_callback(_detached.pop)


async def drain(timeout: float) -> int:
    """Ask every detached run to stop, then wait for them, at most ``timeout`` seconds.

    Returns:
        The number of runs still going when the wait ended (0 at once when
        none is detached).
    """
    if not _detached:
        return 0
    for stop in _detached.values():
        stop.set()
    _, running = await asyncio.wait(set(_detached), timeout=timeout)
    return len(running)


def _failure(task: asyncio.Task[None]) -> BaseException | None:
    """How a finished task ended (None: it returned), read so asyncio never reports it."""
    return asyncio.CancelledError() if task.cancelled() else task.exception()


class EventStreamResponse(StreamingResponse):
    """A run's ``text/event-stream`` answer: its frames until the last one or the client leaves.

    ``frames`` yields formatted SSE frames and ends after the run's ``done``.
    ``stop`` (None when nothing runs any more) is set when the client leaves
    before the last frame: an ``http.disconnect``, a send failing with
    ``OSError`` (ASGI 2.4) or the request being cancelled.
    """

    media_type = _EVENT_STREAM

    def __init__(self, frames: AsyncIterable[str], *, stop: asyncio.Event | None) -> None:
        """Answer 200 with ``frames``, never stored and unbuffered by proxies."""
        super().__init__(frames, headers=_HEADERS)
        self._stop = stop

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Relay the frames while watching for the client's disconnect, whichever ends first."""
        relay = asyncio.ensure_future(self.stream_response(send))
        listen = asyncio.ensure_future(self.listen_for_disconnect(receive))
        try:
            await asyncio.wait((relay, listen), return_when=asyncio.FIRST_COMPLETED)
        finally:
            relay.cancel()
            listen.cancel()
            await asyncio.wait((relay, listen))
            failure = _failure(relay)
            _failure(listen)
            if failure is not None and self._stop is not None:
                self._stop.set()
        # A gone client (OSError) or a disconnect (the cancelled relay) is not an error.
        if failure is not None and not isinstance(failure, OSError | asyncio.CancelledError):
            raise failure
        # As StreamingResponse does (FastAPI attaches the route's background tasks).
        if self.background is not None:
            await self.background()
