"""Spec for the chat runtime's run control (GH-8, contract section C4).

``admino.chat_runtime.ChatRuntime`` gains, next to the unchanged GH-176/GH-24
behaviour pinned in tests/test_chat_runtime.py:

- ``ChatRunActiveError(RuntimeError)``: "the chat is busy". Distinct from
  ``ChatRuntimeFullError``, ``ChatRuntimeUserLimitError`` and
  ``PendingConfirmationLimitError`` (none is a subclass of another).
- ``hold(chat_id, owner_user_id, *, wait=True)``: ``wait`` is keyword-only and
  defaults to True; ``hold(...)`` and ``hold(..., wait=True)`` serialise the
  callers of one chat exactly as before.
- ``hold(..., wait=False)``: when the chat has an entry whose in-use count is
  above zero (a caller inside ``hold`` OR waiting in it, also in the window
  between a holder's release and the waiter's wake-up, when the lock itself is
  free), it raises ``ChatRunActiveError`` at once: the body never runs, and
  nothing changes (``len()``, the eviction order of the other entries, the
  busy entry's in-use state: still refused while the holder is inside, entered
  once everyone left; its pending confirmation; an idle entry is not evicted; a
  queued waiter still enters after the holder). Otherwise it is exactly
  ``hold``: it creates a missing entry under the same bounds
  (``ChatRuntimeUserLimitError`` / ``ChatRuntimeFullError``, nothing created,
  body never run; a victim evicted like ``hold``), enters an idle entry at
  once, yields None and releases when its body raises.
- ``stoppable(chat_id)``: a (synchronous) context manager yielding a fresh,
  unset ``asyncio.Event`` registered as the chat's stop signal for the block;
  on exit (also when the body raised) the registration goes. A chat without an
  entry raises ``KeyError`` (and gets none).
- ``request_stop(chat_id) -> bool``: a plain (non-async) method that sets the
  registered event and returns True; False when the chat has no entry or no
  registration (after the block, or never registered), never creating an
  entry; an event of an earlier registration is never set by a later call;
  other chats' registrations are unaffected. After ``clear()`` (the entry is
  gone) it returns False and the block still exits cleanly; ``forget_user``
  keeps an entry in use (module docstring), so its registration still works,
  and once the entry is gone it returns False.
- Log lines of these paths carry counts only: no chat id or user id.

Every test injects a fake monotonic clock; every wait is bounded (``_TIMEOUT``),
so a wrong implementation fails instead of hanging. ``admino.chat_runtime`` and
the GH-8 names are looked up inside the tests.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from uuid import UUID

import pytest

from admino.models import PendingConfirmation, ToolCall
from tests.log_capture import configured_logging

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

_TIMEOUT: Final = 5.0
_IDLE_S: Final = 900.0
_USER_A: Final = UUID("5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d")
_USER_B: Final = UUID("6b7c8d9e-0f1a-4b2c-9d3e-4f5a6b7c8d9e")
_NOW: Final = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def _chat(number: int) -> UUID:
    """A fixed chat id per number."""
    return UUID(f"00000000-0000-4000-8000-{number:012d}")


class _Clock:
    """A fake monotonic clock: only the test moves it."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _BoomError(Exception):
    """Raised inside a body."""


def _module() -> Any:
    """``admino.chat_runtime``, with the GH-8 names looked up per test."""
    from admino import chat_runtime

    return chat_runtime


def _runtime(
    clock: _Clock,
    *,
    max_entries: int = 8,
    idle_s: float = _IDLE_S,
    per_user: int | None = None,
) -> Any:
    return _module().ChatRuntime(
        max_entries=max_entries, idle_s=idle_s, max_entries_per_user=per_user, clock=clock
    )


def _pending(chat_id: UUID, tag: str = "a") -> PendingConfirmation:
    expires = _NOW + timedelta(minutes=5)
    return PendingConfirmation(
        confirmation_id=f"conf-{tag}",
        session_id=str(chat_id),
        tool_call=ToolCall(
            tool="memory", action="store", args={"key": "k", "value": "v"}, tool_call_id=f"c-{tag}"
        ),
        created_at=expires - timedelta(minutes=10),
        expires_at=expires,
    )


async def _spin(times: int = 5) -> None:
    """Let every ready task run until it blocks."""
    for _ in range(times):
        await asyncio.sleep(0)


async def _use(runtime: Any, chat_id: UUID, user_id: UUID = _USER_A) -> None:
    """Enter and leave ``hold`` once (a finished run of the chat)."""
    async with runtime.hold(chat_id, user_id):
        pass


async def _no_wait(runtime: Any, chat_id: UUID, ran: list[str], user_id: UUID = _USER_A) -> None:
    """Enter and leave ``hold(..., wait=False)`` within the timeout; the body logs "body"."""
    async with asyncio.timeout(_TIMEOUT), runtime.hold(chat_id, user_id, wait=False):
        ran.append("body")


async def _refused(runtime: Any, chat_id: UUID, ran: list[str], user_id: UUID = _USER_A) -> bool:
    """Whether ``hold(..., wait=False)`` raised ChatRunActiveError (at once: within the
    timeout, while the chat stays busy)."""
    try:
        await _no_wait(runtime, chat_id, ran, user_id)
    except _module().ChatRunActiveError:
        return True
    return False


class _Holder:
    """A task inside ``hold`` (optionally with a stop registration) until released."""

    def __init__(
        self,
        runtime: Any,
        chat_id: UUID,
        name: str,
        log: list[str],
        user_id: UUID = _USER_A,
        *,
        stoppable: bool = False,
    ) -> None:
        self.entered = asyncio.Event()
        self.event: asyncio.Event | None = None
        self._release = asyncio.Event()
        self._log = log
        self._name = name
        self.task = asyncio.create_task(self._run(runtime, chat_id, user_id, stoppable))

    async def _run(self, runtime: Any, chat_id: UUID, user_id: UUID, stoppable: bool) -> None:
        async with runtime.hold(chat_id, user_id):
            self._log.append(f"{self._name}-enter")
            if stoppable:
                with runtime.stoppable(chat_id) as event:
                    self.event = event
                    self.entered.set()
                    await self._release.wait()
            else:
                self.entered.set()
                await self._release.wait()
            self._log.append(f"{self._name}-exit")

    async def wait_inside(self) -> None:
        """Wait until the holder is inside; a holder that failed first re-raises its error."""
        waiter = asyncio.create_task(self.entered.wait())
        try:
            await asyncio.wait(
                {waiter, self.task}, timeout=_TIMEOUT, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            waiter.cancel()
        if self.task.done():
            self.task.result()
        assert self.entered.is_set(), "the holder did not enter in time"

    async def finish(self) -> None:
        self._release.set()
        await asyncio.wait_for(self.task, _TIMEOUT)


# ===========================================================================
# 1. ChatRunActiveError and the wait keyword
# ===========================================================================


class TestApi:
    """The new error and the keyword-only ``wait``."""

    def test_chat_runtime_run_active_error_is_a_runtime_error_distinct_from_the_others(
        self,
    ) -> None:
        module = _module()
        active = module.ChatRunActiveError
        others = (
            module.ChatRuntimeFullError,
            module.ChatRuntimeUserLimitError,
            module.PendingConfirmationLimitError,
        )

        relations = (
            issubclass(active, RuntimeError),
            [issubclass(active, other) for other in others],
            [issubclass(other, active) for other in others],
        )

        assert relations == (True, [False, False, False], [False, False, False])

    def test_chat_runtime_hold_wait_is_keyword_only_and_defaults_to_true(self) -> None:
        parameter = inspect.signature(_module().ChatRuntime.hold).parameters.get("wait")

        assert parameter is not None
        assert (parameter.kind, parameter.default) == (inspect.Parameter.KEYWORD_ONLY, True)

    async def test_chat_runtime_hold_with_wait_still_serialises_callers(self) -> None:
        """``wait=True`` (and the default) queue a second caller instead of refusing it."""
        runtime = _runtime(_Clock())
        log: list[str] = []
        first = _Holder(runtime, _chat(1), "A", log)
        await first.wait_inside()

        async def second() -> None:
            async with runtime.hold(_chat(1), _USER_A, wait=True):
                log.append("B-enter")

        task = asyncio.create_task(second())
        await _spin()
        during = list(log)
        await first.finish()
        await asyncio.wait_for(task, _TIMEOUT)

        assert (during, log) == (["A-enter"], ["A-enter", "A-exit", "B-enter"])


# ===========================================================================
# 2. hold(..., wait=False) on a free chat: exactly hold
# ===========================================================================


class TestNoWaitFree:
    """A chat nobody is in or waiting for: entered at once, like ``hold``."""

    async def test_chat_runtime_hold_no_wait_creates_a_missing_entry_and_enters(self) -> None:
        runtime = _runtime(_Clock())
        seen: list[Any] = []

        async with (
            asyncio.timeout(_TIMEOUT),
            runtime.hold(_chat(1), _USER_A, wait=False) as value,
        ):
            seen.extend((value, _chat(1) in runtime, len(runtime)))

        assert seen == [None, True, 1]
        assert len(runtime) == 1

    async def test_chat_runtime_hold_no_wait_enters_an_idle_entry_at_once(self) -> None:
        runtime = _runtime(_Clock())
        await _use(runtime, _chat(1))
        ran: list[str] = []

        await _no_wait(runtime, _chat(1), ran)
        await _no_wait(runtime, _chat(1), ran)

        assert (ran, len(runtime)) == (["body", "body"], 1)

    async def test_chat_runtime_hold_no_wait_releases_when_the_body_raises(self) -> None:
        """The in-use count drops on the error path: the next wait=False enters."""
        runtime = _runtime(_Clock())
        ran: list[str] = []

        with pytest.raises(_BoomError):
            async with runtime.hold(_chat(1), _USER_A, wait=False):
                raise _BoomError
        await _no_wait(runtime, _chat(1), ran)

        assert ran == ["body"]

    async def test_chat_runtime_hold_no_wait_creation_evicts_like_hold(self) -> None:
        """At capacity the least recently used entry not in use goes (chat 2: chat 1
        was created first but used last)."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=2)
        await _use(runtime, _chat(1))
        clock.advance(1.0)
        await _use(runtime, _chat(2))
        clock.advance(1.0)
        await _use(runtime, _chat(1))
        clock.advance(1.0)

        await _no_wait(runtime, _chat(3), [])

        assert [_chat(n) in runtime for n in (1, 2, 3)] == [True, False, True]

    async def test_chat_runtime_hold_no_wait_creation_raises_the_user_limit_like_hold(
        self,
    ) -> None:
        """A's only allowed entry is busy: the user limit, nothing created, body not run."""
        runtime = _runtime(_Clock(), per_user=1)
        holder = _Holder(runtime, _chat(1), "A", [])
        await holder.wait_inside()
        ran: list[str] = []

        with pytest.raises(_module().ChatRuntimeUserLimitError):
            await _no_wait(runtime, _chat(2), ran)
        state = (ran, _chat(2) in runtime, len(runtime))
        await holder.finish()

        assert state == ([], False, 1)

    async def test_chat_runtime_hold_no_wait_creation_raises_full_like_hold(self) -> None:
        """Every entry is in use at capacity: the full error, nothing created or evicted."""
        runtime = _runtime(_Clock(), max_entries=1)
        holder = _Holder(runtime, _chat(1), "A", [])
        await holder.wait_inside()
        ran: list[str] = []

        with pytest.raises(_module().ChatRuntimeFullError):
            await _no_wait(runtime, _chat(2), ran, _USER_B)
        state = (ran, _chat(1) in runtime, _chat(2) in runtime, len(runtime))
        await holder.finish()

        assert state == ([], True, False, 1)


# ===========================================================================
# 3. hold(..., wait=False) on a busy chat: ChatRunActiveError, nothing changes
# ===========================================================================


class TestNoWaitBusy:
    """In use (a caller inside or waiting): refused at once, the runtime as it was."""

    async def test_chat_runtime_hold_no_wait_while_a_caller_is_inside_is_refused(
        self,
    ) -> None:
        """Refused twice while the holder is inside (the in-use count kept, not
        dropped), entered once it left (not leaked); pending, len and the idle entry
        kept."""
        clock = _Clock()
        runtime = _runtime(clock, idle_s=100.0)
        holder = _Holder(runtime, _chat(1), "A", [])
        await holder.wait_inside()
        pending = _pending(_chat(1), "busy")
        runtime.set_pending(_chat(1), _USER_A, pending)
        clock.advance(1.0)
        await _use(runtime, _chat(2))
        clock.advance(500.0)  # chat 2 is idle now
        ran: list[str] = []

        refusals = [await _refused(runtime, _chat(1), ran), await _refused(runtime, _chat(1), ran)]
        during = (len(runtime), _chat(2) in runtime, runtime.get_pending(_chat(1)), list(ran))
        await holder.finish()
        await _no_wait(runtime, _chat(1), ran)

        assert refusals == [True, True]
        assert during == (2, True, pending, [])
        assert (ran, runtime.get_pending(_chat(1))) == (["body"], pending)

    async def test_chat_runtime_hold_no_wait_refusal_keeps_the_eviction_order(self) -> None:
        """After a refusal on busy chat 1, new entries at capacity evict chat 2 then
        chat 3 (least recently used first), never the busy chat 1."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=3)
        holder = _Holder(runtime, _chat(1), "A", [])
        await holder.wait_inside()
        clock.advance(1.0)
        await _use(runtime, _chat(2))
        clock.advance(1.0)
        await _use(runtime, _chat(3))
        clock.advance(1.0)

        refused = await _refused(runtime, _chat(1), [])
        clock.advance(1.0)
        await _use(runtime, _chat(4))
        after_four = [_chat(n) in runtime for n in (1, 2, 3, 4)]
        clock.advance(1.0)
        await _use(runtime, _chat(5))
        after_five = [_chat(n) in runtime for n in (1, 2, 3, 4, 5)]
        await holder.finish()

        assert refused is True
        assert after_four == [True, False, True, True]
        assert after_five == [True, False, False, True, True]

    async def test_chat_runtime_hold_no_wait_refusal_leaves_a_queued_waiter_in_line(
        self,
    ) -> None:
        """A caller waiting with wait=True still enters after the holder; the refused
        body never runs."""
        runtime = _runtime(_Clock())
        log: list[str] = []
        first = _Holder(runtime, _chat(1), "A", log)
        await first.wait_inside()
        second = _Holder(runtime, _chat(1), "B", log)
        await _spin()
        ran: list[str] = []

        refused = await _refused(runtime, _chat(1), ran)
        await first.finish()
        await second.wait_inside()
        await second.finish()

        assert (refused, ran) == (True, [])
        assert log == ["A-enter", "A-exit", "B-enter", "B-exit"]

    async def test_chat_runtime_hold_no_wait_is_refused_while_only_a_waiter_holds_the_chat(
        self,
    ) -> None:
        """Between a holder's release and its waiter's wake-up the lock is free but the
        waiter keeps the chat in use: refused, and the waiter enters next."""
        runtime = _runtime(_Clock())
        log: list[str] = []
        ran: list[str] = []

        async def waiter() -> None:
            async with runtime.hold(_chat(1), _USER_A):
                log.append("waiter")

        async with runtime.hold(_chat(1), _USER_A):
            task = asyncio.create_task(waiter())
            await _spin()
        # Released: the waiter is woken but hasn't run (nothing awaited since).
        refused = await _refused(runtime, _chat(1), ran)
        await asyncio.wait_for(task, _TIMEOUT)
        await _no_wait(runtime, _chat(1), ran)

        assert (refused, log, ran) == (True, ["waiter"], ["body"])


# ===========================================================================
# 4. stoppable() and request_stop()
# ===========================================================================


class TestStop:
    """A registered stop event per run; request_stop sets it, never blocks or creates."""

    async def test_chat_runtime_stoppable_yields_a_fresh_unset_event(self) -> None:
        runtime = _runtime(_Clock())

        async with runtime.hold(_chat(1), _USER_A):
            manager = runtime.stoppable(_chat(1))
            with manager as event:
                state = (isinstance(event, asyncio.Event), event.is_set())

        assert isinstance(manager, contextlib.AbstractContextManager)
        assert state == (True, False)

    async def test_chat_runtime_request_stop_sets_the_registered_event(self) -> None:
        runtime = _runtime(_Clock())

        async with runtime.hold(_chat(1), _USER_A):
            with runtime.stoppable(_chat(1)) as event:
                results = [runtime.request_stop(_chat(1)), runtime.request_stop(_chat(1))]
                is_set = event.is_set()

        assert (results[0] is True, results[1] is True, is_set) == (True, True, True)

    async def test_chat_runtime_request_stop_after_the_block_returns_false(self) -> None:
        """The registration ends with the block: the old event is never set later."""
        runtime = _runtime(_Clock())

        async with runtime.hold(_chat(1), _USER_A):
            with runtime.stoppable(_chat(1)) as event:
                pass
            inside_hold = runtime.request_stop(_chat(1))
        after_hold = runtime.request_stop(_chat(1))

        assert (inside_hold, after_hold, event.is_set()) == (False, False, False)

    async def test_chat_runtime_stoppable_unregisters_when_the_body_raises(self) -> None:
        runtime = _runtime(_Clock())

        async with runtime.hold(_chat(1), _USER_A):
            with pytest.raises(_BoomError), runtime.stoppable(_chat(1)) as event:
                raise _BoomError
            result = runtime.request_stop(_chat(1))

        assert (result, event.is_set()) == (False, False)

    async def test_chat_runtime_stoppable_registers_a_fresh_event_each_time(self) -> None:
        """The second run's stop sets only its own event, not the first run's."""
        runtime = _runtime(_Clock())

        async with runtime.hold(_chat(1), _USER_A):
            with runtime.stoppable(_chat(1)) as first:
                pass
        async with runtime.hold(_chat(1), _USER_A):
            with runtime.stoppable(_chat(1)) as second:
                fresh = second.is_set()
                result = runtime.request_stop(_chat(1))

        assert second is not first
        assert (fresh, result, second.is_set(), first.is_set()) == (False, True, True, False)

    async def test_chat_runtime_stoppable_on_a_chat_without_an_entry_raises_key_error(
        self,
    ) -> None:
        runtime = _runtime(_Clock())
        await _use(runtime, _chat(1))

        with pytest.raises(KeyError), runtime.stoppable(_chat(9)):
            pass

        assert (_chat(9) in runtime, len(runtime)) == (False, 1)

    async def test_chat_runtime_request_stop_on_an_unknown_chat_returns_false_and_creates_none(
        self,
    ) -> None:
        runtime = _runtime(_Clock())
        await _use(runtime, _chat(1))

        result = runtime.request_stop(_chat(9))

        assert (result, _chat(9) in runtime, len(runtime)) == (False, False, 1)

    async def test_chat_runtime_request_stop_without_a_registration_returns_false(self) -> None:
        """An idle entry and a run inside hold that registered nothing (a JSON run)."""
        runtime = _runtime(_Clock())
        await _use(runtime, _chat(1))
        holder = _Holder(runtime, _chat(2), "A", [])
        await holder.wait_inside()

        results = (runtime.request_stop(_chat(1)), runtime.request_stop(_chat(2)))
        await holder.finish()

        assert results == (False, False)

    async def test_chat_runtime_request_stop_is_a_plain_method_that_never_blocks(self) -> None:
        """Called while the chat's run holds its lock: a bool back at once, no awaitable."""
        runtime = _runtime(_Clock())
        holder = _Holder(runtime, _chat(1), "A", [], stoppable=True)
        await holder.wait_inside()

        result = runtime.request_stop(_chat(1))
        await holder.finish()

        assert not inspect.iscoroutinefunction(_module().ChatRuntime.request_stop)
        assert result is True
        assert holder.event is not None
        assert holder.event.is_set()

    async def test_chat_runtime_request_stop_leaves_other_chats_registrations_alone(
        self,
    ) -> None:
        runtime = _runtime(_Clock())
        one = _Holder(runtime, _chat(1), "A", [], stoppable=True)
        two = _Holder(runtime, _chat(2), "B", [], _USER_B, stoppable=True)
        await one.wait_inside()
        await two.wait_inside()
        assert one.event is not None
        assert two.event is not None

        first = runtime.request_stop(_chat(1))
        between = (one.event.is_set(), two.event.is_set())
        second = runtime.request_stop(_chat(2))
        await one.finish()
        await two.finish()

        assert (first, between, second, two.event.is_set()) == (True, (True, False), True, True)

    async def test_chat_runtime_request_stop_after_clear_returns_false(self) -> None:
        """clear() drops the entry under a running stoppable block: request_stop is
        False, the event stays unset and the block exits without an error."""
        runtime = _runtime(_Clock())
        holder = _Holder(runtime, _chat(1), "A", [], stoppable=True)
        await holder.wait_inside()

        runtime.clear()
        result = runtime.request_stop(_chat(1))
        await holder.finish()

        assert holder.event is not None
        assert (result, holder.event.is_set(), runtime.request_stop(_chat(1))) == (
            False,
            False,
            False,
        )

    async def test_chat_runtime_request_stop_after_forget_user(self) -> None:
        """forget_user keeps an entry in use, so the run's registration still works;
        once the run left and forget_user dropped the entry, request_stop is False."""
        runtime = _runtime(_Clock())
        holder = _Holder(runtime, _chat(1), "A", [], stoppable=True)
        await holder.wait_inside()

        runtime.forget_user(_USER_A)
        while_running = runtime.request_stop(_chat(1))
        await holder.finish()
        runtime.forget_user(_USER_A)
        after = runtime.request_stop(_chat(1))

        assert holder.event is not None
        assert (while_running, holder.event.is_set(), after, len(runtime)) == (True, True, False, 0)


# ===========================================================================
# 5. Log hygiene of the new paths
# ===========================================================================


class TestLogs:
    """Counts only: no chat or user id in any record of the new paths."""

    async def test_chat_runtime_run_control_logs_no_chat_or_user_id(self) -> None:
        clock = _Clock()
        with configured_logging("DEBUG", "text") as logs:
            runtime = _runtime(clock, max_entries=2, per_user=1)
            holder = _Holder(runtime, _chat(1), "A", [], stoppable=True)
            await holder.wait_inside()
            await _refused(runtime, _chat(1), [])
            with pytest.raises(_module().ChatRuntimeUserLimitError):
                await _no_wait(runtime, _chat(2), [])
            runtime.request_stop(_chat(1))
            runtime.request_stop(_chat(3))
            await holder.finish()
            runtime.clear()

        haystacks = [logs.text.casefold()]
        for record in logs.records:
            haystacks.extend((record.getMessage().casefold(), repr(record.args).casefold()))
        ids = [str(value) for value in (_chat(1), _chat(2), _chat(3), _USER_A)]
        hits = [(marker, text) for marker in ids for text in haystacks if marker in text]
        assert hits == []
