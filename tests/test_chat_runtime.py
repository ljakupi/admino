"""Spec for the bounded in-memory chat runtime (GH-176, contract section 3).

``admino.chat_runtime.ChatRuntime`` replaces ``server._sessions``: per chat it holds
the run lock and the chat's pending confirmation (memory only, so after a restart a
chat whose latest message is ``awaiting_confirmation`` shows as expired). Every
test injects a fake monotonic clock; nothing reads the real one.

What is pinned here:

- ``hold(chat_id, owner_user_id)`` is an async context manager (yielding ``None``)
  that serialises the callers of one chat (two tasks on one chat never overlap),
  lets different chats run at the same time, and releases the chat when its body
  raises (the exception propagates and the entry is no longer in use).
- Bound: ``len()`` never exceeds ``max_entries``. Creating an entry (``hold`` or
  ``set_pending`` on an unknown chat) first evicts the idle entries (not in use, no
  pending confirmation, last used ``>= idle_s`` ago by the clock), even below
  capacity; then, at capacity, the least recently used entry that isn't in use,
  together with its pending confirmation (``get_pending`` is ``None`` afterwards).
  An entry in use (a caller inside ``hold`` or waiting to acquire it) is never
  evicted, not even between the holder's release and the waiter's wake-up. A chat
  that already has an entry is served at capacity (``set_pending`` works, ``hold``
  waits). When every entry is in use, creating one raises ``ChatRuntimeFullError``
  (a ``RuntimeError``) and changes nothing.
- Pending confirmations: ``set_pending`` / ``get_pending`` / ``pop_pending``, one
  per chat (``set_pending`` replaces), ``get_pending`` returns the stored one even
  when it has expired, reading an unknown chat creates no entry, and
  ``reap_expired(now)`` drops exactly those with ``now >= expires_at`` and returns
  how many it dropped. An entry with a pending confirmation is never idle.
- ``forget_user`` drops that user's pending confirmations and their entries that
  aren't in use (an entry in use keeps its lock), never another user's; ``clear()``
  empties everything.
- Hygiene (AST of the module file): imports only the standard library and
  ``admino.models`` (no database, server, agent, llm or tools module), has a module
  docstring, logs with literal format strings only, and no tool argument of a
  pending confirmation reaches any log record.

``admino.chat_runtime`` is imported lazily, so this file collects before GH-176 and
each test fails on its own.

No database, network or real clock is used. Every wait is bounded, so a wrong
implementation fails instead of hanging.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import inspect
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final
from uuid import UUID

import pytest

from admino.models import PendingConfirmation, ToolCall
from tests.log_capture import configured_logging

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TIMEOUT: Final = 5.0
_IDLE_S: Final = 900.0
_USER_A: Final = UUID("5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d")
_USER_B: Final = UUID("6b7c8d9e-0f1a-4b2c-9d3e-4f5a6b7c8d9e")
_NOW: Final = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)

# Fake tool arguments of a pending call (content): they must never be logged.
_ARG_KEY: Final = "RUNTIME-KEY-176-osprey"
_ARG_VALUE: Final = "RUNTIME-VALUE-176-kestrel"

_LOG_METHODS: Final = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical"}
)


def _chat(number: int) -> UUID:
    """A fixed chat id per number."""
    return UUID(f"00000000-0000-4000-8000-{number:012d}")


# ---------------------------------------------------------------------------
# Fakes and helpers
# ---------------------------------------------------------------------------


class _Clock:
    """A fake monotonic clock: only the test moves it."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _BoomError(Exception):
    """Raised inside a hold() body."""


def _module() -> Any:
    """``admino.chat_runtime`` (GH-176), imported lazily so this file collects without it."""
    from admino import chat_runtime

    return chat_runtime


def _runtime(clock: _Clock, *, max_entries: int = 8, idle_s: float = _IDLE_S) -> Any:
    return _module().ChatRuntime(max_entries=max_entries, idle_s=idle_s, clock=clock)


def _pending(
    chat_id: UUID, tag: str = "a", *, expires_at: datetime | None = None
) -> PendingConfirmation:
    """A pending confirmation of ``chat_id`` (expires 5 minutes after ``_NOW`` by default)."""
    expires = _NOW + timedelta(minutes=5) if expires_at is None else expires_at
    return PendingConfirmation(
        confirmation_id=f"conf-{tag}",
        session_id=str(chat_id),
        tool_call=ToolCall(
            tool="memory",
            action="store",
            args={"key": _ARG_KEY, "value": _ARG_VALUE},
            tool_call_id=f"call-{tag}",
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


class _Holder:
    """A task that enters ``hold`` and stays inside until released."""

    def __init__(
        self, runtime: Any, chat_id: UUID, name: str, log: list[str], user_id: UUID = _USER_A
    ) -> None:
        self.entered = asyncio.Event()
        self._release = asyncio.Event()
        self._log = log
        self._name = name
        self.task = asyncio.create_task(self._run(runtime, chat_id, user_id))

    async def _run(self, runtime: Any, chat_id: UUID, user_id: UUID) -> None:
        async with runtime.hold(chat_id, user_id):
            self._log.append(f"{self._name}-enter")
            self.entered.set()
            await self._release.wait()
            self._log.append(f"{self._name}-exit")

    async def wait_inside(self) -> None:
        await asyncio.wait_for(self.entered.wait(), _TIMEOUT)

    async def finish(self) -> None:
        self._release.set()
        await asyncio.wait_for(self.task, _TIMEOUT)


def _module_tree() -> ast.Module:
    """The parsed source of the imported module (the file that actually runs)."""
    return ast.parse(Path(inspect.getfile(_module())).read_text(encoding="utf-8"))


# ===========================================================================
# 1. hold(): per-chat serialisation
# ===========================================================================


class TestHold:
    """hold() serialises one chat's callers and releases on every exit path."""

    async def test_chat_runtime_hold_serialises_callers_of_one_chat(self) -> None:
        runtime = _runtime(_Clock())
        log: list[str] = []
        first = _Holder(runtime, _chat(1), "A", log)
        await first.wait_inside()
        second = _Holder(runtime, _chat(1), "B", log)
        await _spin()
        during = list(log)

        await first.finish()
        await second.wait_inside()
        await second.finish()

        assert (during, log) == (["A-enter"], ["A-enter", "A-exit", "B-enter", "B-exit"])

    async def test_chat_runtime_hold_runs_different_chats_concurrently(self) -> None:
        """Both callers are inside at once: a runtime-wide lock times out here."""
        runtime = _runtime(_Clock())
        inside = {1: asyncio.Event(), 2: asyncio.Event()}

        async def run(mine: int, other: int) -> None:
            async with runtime.hold(_chat(mine), _USER_A):
                inside[mine].set()
                await asyncio.wait_for(inside[other].wait(), _TIMEOUT)

        await asyncio.wait_for(asyncio.gather(run(1, 2), run(2, 1)), _TIMEOUT * 2)

        assert inside[1].is_set() and inside[2].is_set()

    async def test_chat_runtime_hold_is_an_async_context_manager_yielding_none(self) -> None:
        runtime = _runtime(_Clock())
        manager = runtime.hold(_chat(1), _USER_A)
        assert isinstance(manager, contextlib.AbstractAsyncContextManager)

        async with manager as value:
            inside = value

        assert inside is None

    async def test_chat_runtime_hold_releases_the_chat_when_the_body_raises(self) -> None:
        runtime = _runtime(_Clock())

        with pytest.raises(_BoomError):
            async with runtime.hold(_chat(1), _USER_A):
                raise _BoomError

        await asyncio.wait_for(_use(runtime, _chat(1)), _TIMEOUT)

    async def test_chat_runtime_hold_that_raised_leaves_the_entry_evictable(self) -> None:
        """The in-use count drops on the error path too: the entry can make room."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=1)
        with pytest.raises(_BoomError):
            async with runtime.hold(_chat(1), _USER_A):
                raise _BoomError
        clock.advance(1.0)

        await _use(runtime, _chat(2))

        assert len(runtime) == 1


# ===========================================================================
# 2. The bound: idle eviction, LRU eviction, in-use entries, full runtime
# ===========================================================================


class TestBound:
    """At most max_entries entries; idle first, then LRU, never an entry in use."""

    async def test_chat_runtime_len_never_exceeds_max_entries(self) -> None:
        """Entries created by hold() and by set_pending() both count."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=3)
        sizes: list[int] = []

        for number in range(1, 9):
            clock.advance(1.0)
            if number % 2:
                await _use(runtime, _chat(number))
            else:
                runtime.set_pending(_chat(number), _USER_A, _pending(_chat(number), str(number)))
            sizes.append(len(runtime))

        assert sizes == [1, 2, 3, 3, 3, 3, 3, 3]

    async def test_chat_runtime_idle_entries_are_evicted_before_a_new_entry_is_created(
        self,
    ) -> None:
        """Below capacity too: the entry idle for idle_s goes, the younger one stays."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=8, idle_s=100.0)
        await _use(runtime, _chat(1))
        clock.advance(50.0)
        await _use(runtime, _chat(2))
        clock.advance(50.0)

        await _use(runtime, _chat(3))

        assert len(runtime) == 2

    @pytest.mark.parametrize(("age", "expected_len"), [(99.5, 2), (100.0, 1)])
    async def test_chat_runtime_idle_means_last_used_at_least_idle_s_ago(
        self, age: float, expected_len: int
    ) -> None:
        clock = _Clock()
        runtime = _runtime(clock, max_entries=8, idle_s=100.0)
        await _use(runtime, _chat(1))
        clock.advance(age)

        await _use(runtime, _chat(2))

        assert len(runtime) == expected_len

    async def test_chat_runtime_entry_with_a_pending_confirmation_is_never_idle(self) -> None:
        clock = _Clock()
        runtime = _runtime(clock, max_entries=8, idle_s=100.0)
        pending = _pending(_chat(1))
        runtime.set_pending(_chat(1), _USER_A, pending)
        clock.advance(10_000.0)

        await _use(runtime, _chat(2))

        assert (len(runtime), runtime.get_pending(_chat(1))) == (2, pending)

    async def test_chat_runtime_entry_in_use_is_never_idle(self) -> None:
        clock = _Clock()
        runtime = _runtime(clock, max_entries=8, idle_s=100.0)
        holder = _Holder(runtime, _chat(1), "A", [])
        await holder.wait_inside()
        clock.advance(10_000.0)

        await _use(runtime, _chat(2))
        size = len(runtime)
        await holder.finish()

        assert size == 2

    async def test_chat_runtime_at_capacity_evicts_the_least_recently_used_with_its_pending(
        self,
    ) -> None:
        """chat 1 was created first but used last: chat 2 goes, and its confirmation."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=2)
        first, second = _pending(_chat(1), "1"), _pending(_chat(2), "2")
        runtime.set_pending(_chat(1), _USER_A, first)
        clock.advance(1.0)
        runtime.set_pending(_chat(2), _USER_A, second)
        clock.advance(1.0)
        await _use(runtime, _chat(1))
        clock.advance(1.0)

        await _use(runtime, _chat(3))

        assert (len(runtime), runtime.get_pending(_chat(1)), runtime.get_pending(_chat(2))) == (
            2,
            first,
            None,
        )

    async def test_chat_runtime_lru_skips_an_entry_whose_caller_is_inside_hold(self) -> None:
        """chat 1 is the least recently used but in use: chat 2 is evicted instead."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=2)
        holder = _Holder(runtime, _chat(1), "A", [])
        await holder.wait_inside()
        held, created = _pending(_chat(1), "1"), _pending(_chat(3), "3")
        runtime.set_pending(_chat(1), _USER_A, held)
        clock.advance(1.0)
        await _use(runtime, _chat(2))
        clock.advance(1.0)

        runtime.set_pending(_chat(3), _USER_A, created)
        state = (len(runtime), runtime.get_pending(_chat(1)), runtime.get_pending(_chat(3)))
        await holder.finish()

        assert state == (2, held, created)

    async def test_chat_runtime_waiting_caller_keeps_the_entry_between_release_and_wake_up(
        self,
    ) -> None:
        """The holder leaves while a waiter is queued; before the waiter runs, two new
        entries force an eviction: the waiter's chat (older) is in use, so chat 2 goes,
        and the waiter finds its confirmation."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=2)
        held = _pending(_chat(1), "1")
        seen: list[PendingConfirmation | None] = []

        async def waiter() -> None:
            async with runtime.hold(_chat(1), _USER_A):
                seen.append(runtime.get_pending(_chat(1)))

        async with runtime.hold(_chat(1), _USER_A):
            runtime.set_pending(_chat(1), _USER_A, held)
            task = asyncio.create_task(waiter())
            await _spin()
        # Released: the waiter is woken but hasn't run (nothing awaited since).
        clock.advance(1000.0)
        runtime.set_pending(_chat(2), _USER_A, _pending(_chat(2), "2"))
        runtime.set_pending(_chat(3), _USER_A, _pending(_chat(3), "3"))
        state = (len(runtime), runtime.get_pending(_chat(2)) is None)
        await asyncio.wait_for(task, _TIMEOUT)

        assert (state, seen) == ((2, True), [held])

    async def test_chat_runtime_waiting_caller_keeps_the_entry_from_idle_eviction(
        self,
    ) -> None:
        """No confirmation, long past idle_s, holder gone: the queued waiter still counts."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=8, idle_s=100.0)
        entered: list[str] = []

        async def waiter() -> None:
            async with runtime.hold(_chat(1), _USER_A):
                entered.append("waiter")

        async with runtime.hold(_chat(1), _USER_A):
            task = asyncio.create_task(waiter())
            await _spin()
        clock.advance(10_000.0)
        runtime.set_pending(_chat(2), _USER_A, _pending(_chat(2), "2"))
        size = len(runtime)
        await asyncio.wait_for(task, _TIMEOUT)

        assert (size, entered) == (2, ["waiter"])

    async def test_chat_runtime_full_runtime_still_serves_a_chat_it_already_holds(
        self,
    ) -> None:
        """Every entry in use: set_pending on a held chat works and a second caller of
        that chat waits for it instead of raising."""
        runtime = _runtime(_Clock(), max_entries=2)
        log: list[str] = []
        first = _Holder(runtime, _chat(1), "A", log)
        other = _Holder(runtime, _chat(2), "X", log)
        await first.wait_inside()
        await other.wait_inside()
        held = _pending(_chat(1), "1")

        runtime.set_pending(_chat(1), _USER_A, held)
        second = _Holder(runtime, _chat(1), "B", log)
        await _spin()
        during = [entry for entry in log if entry[0] in "AB"]
        await first.finish()
        await second.wait_inside()
        await second.finish()
        await other.finish()

        assert (runtime.get_pending(_chat(1)), during) == (held, ["A-enter"])
        assert [entry for entry in log if entry[0] in "AB"] == [
            "A-enter",
            "A-exit",
            "B-enter",
            "B-exit",
        ]

    async def test_chat_runtime_every_entry_in_use_raises_full_and_changes_nothing(
        self,
    ) -> None:
        clock = _Clock()
        runtime = _runtime(clock, max_entries=2)
        full_error = _module().ChatRuntimeFullError
        first = _Holder(runtime, _chat(1), "A", [])
        second = _Holder(runtime, _chat(2), "B", [])
        await first.wait_inside()
        await second.wait_inside()
        held = _pending(_chat(1), "1")
        runtime.set_pending(_chat(1), _USER_A, held)
        clock.advance(10_000.0)
        body_ran = False

        with pytest.raises(full_error):
            runtime.set_pending(_chat(3), _USER_A, _pending(_chat(3), "3"))
        with pytest.raises(full_error):
            async with runtime.hold(_chat(3), _USER_A):
                body_ran = True
        state = (len(runtime), runtime.get_pending(_chat(1)), runtime.get_pending(_chat(3)))
        await first.finish()
        await second.finish()
        clock.advance(1.0)
        await _use(runtime, _chat(3))

        assert issubclass(full_error, RuntimeError)
        assert (state, body_ran) == ((2, held, None), False)
        assert len(runtime) == 2


# ===========================================================================
# 3. Pending confirmations
# ===========================================================================


class TestPending:
    """One pending confirmation per chat, kept in memory only."""

    def test_chat_runtime_set_get_pop_pending(self) -> None:
        runtime = _runtime(_Clock())
        pending = _pending(_chat(1))
        runtime.set_pending(_chat(1), _USER_A, pending)

        got = runtime.get_pending(_chat(1))
        popped = runtime.pop_pending(_chat(1))

        assert (got, popped) == (pending, pending)
        assert (runtime.get_pending(_chat(1)), runtime.pop_pending(_chat(1))) == (None, None)

    def test_chat_runtime_set_pending_replaces_the_chats_confirmation(self) -> None:
        runtime = _runtime(_Clock())
        older, newer = _pending(_chat(1), "old"), _pending(_chat(1), "new")
        runtime.set_pending(_chat(1), _USER_A, older)

        runtime.set_pending(_chat(1), _USER_A, newer)

        assert (runtime.get_pending(_chat(1)), runtime.pop_pending(_chat(1))) == (newer, newer)
        assert (runtime.get_pending(_chat(1)), len(runtime)) == (None, 1)

    def test_chat_runtime_pending_confirmations_are_per_chat(self) -> None:
        runtime = _runtime(_Clock())
        first, second = _pending(_chat(1), "1"), _pending(_chat(2), "2")
        runtime.set_pending(_chat(1), _USER_A, first)
        runtime.set_pending(_chat(2), _USER_A, second)

        popped = runtime.pop_pending(_chat(1))

        assert (popped, runtime.get_pending(_chat(1)), runtime.get_pending(_chat(2))) == (
            first,
            None,
            second,
        )

    def test_chat_runtime_get_pending_returns_an_expired_confirmation(self) -> None:
        """Expiry is the caller's decision (410 or reap_expired), not get_pending's."""
        runtime = _runtime(_Clock())
        expired = _pending(_chat(1), expires_at=datetime(2020, 1, 1, tzinfo=UTC))
        runtime.set_pending(_chat(1), _USER_A, expired)

        assert runtime.get_pending(_chat(1)) == expired

    def test_chat_runtime_reading_an_unknown_chat_creates_no_entry(self) -> None:
        runtime = _runtime(_Clock())

        got, popped = runtime.get_pending(_chat(9)), runtime.pop_pending(_chat(9))

        assert (got, popped, len(runtime)) == (None, None, 0)

    def test_chat_runtime_reap_expired_drops_exactly_the_expired_ones(self) -> None:
        """now >= expires_at is expired: the one due exactly now goes too."""
        runtime = _runtime(_Clock())
        live = _pending(_chat(3), "live", expires_at=_NOW + timedelta(seconds=1))
        runtime.set_pending(
            _chat(1), _USER_A, _pending(_chat(1), "past", expires_at=_NOW - timedelta(seconds=1))
        )
        runtime.set_pending(_chat(2), _USER_B, _pending(_chat(2), "due", expires_at=_NOW))
        runtime.set_pending(_chat(3), _USER_A, live)

        count = runtime.reap_expired(_NOW)

        assert (count, type(count)) == (2, int)
        assert (
            runtime.get_pending(_chat(1)),
            runtime.get_pending(_chat(2)),
            runtime.get_pending(_chat(3)),
        ) == (None, None, live)
        assert runtime.reap_expired(_NOW) == 0

    def test_chat_runtime_set_pending_on_an_unknown_chat_creates_an_entry_under_the_bound(
        self,
    ) -> None:
        clock = _Clock()
        runtime = _runtime(clock, max_entries=1)
        first, second = _pending(_chat(1), "1"), _pending(_chat(2), "2")
        runtime.set_pending(_chat(1), _USER_A, first)
        size_after_first = len(runtime)
        clock.advance(1.0)

        runtime.set_pending(_chat(2), _USER_A, second)

        assert (size_after_first, len(runtime)) == (1, 1)
        assert (runtime.get_pending(_chat(1)), runtime.get_pending(_chat(2))) == (None, second)


# ===========================================================================
# 4. forget_user and clear
# ===========================================================================


class TestForgetAndClear:
    """A deleted user's state goes; nobody else's; clear() is a restart."""

    async def test_chat_runtime_forget_user_drops_only_that_users_state(self) -> None:
        clock = _Clock()
        runtime = _runtime(clock)
        others = _pending(_chat(3), "b")
        runtime.set_pending(_chat(1), _USER_A, _pending(_chat(1), "a"))
        clock.advance(1.0)
        await _use(runtime, _chat(2), _USER_A)
        clock.advance(1.0)
        runtime.set_pending(_chat(3), _USER_B, others)
        clock.advance(1.0)
        await _use(runtime, _chat(4), _USER_B)

        runtime.forget_user(_USER_A)

        assert (len(runtime), runtime.get_pending(_chat(1)), runtime.get_pending(_chat(3))) == (
            2,
            None,
            others,
        )

    async def test_chat_runtime_forget_user_keeps_an_entry_in_use_and_its_lock(self) -> None:
        """The pending confirmation goes, the held entry stays: a second caller of the
        chat still waits for the first."""
        runtime = _runtime(_Clock())
        log: list[str] = []
        first = _Holder(runtime, _chat(1), "A", log)
        await first.wait_inside()
        runtime.set_pending(_chat(1), _USER_A, _pending(_chat(1)))

        runtime.forget_user(_USER_A)
        state = (len(runtime), runtime.get_pending(_chat(1)))
        second = _Holder(runtime, _chat(1), "B", log)
        await _spin()
        during = list(log)
        await first.finish()
        await second.wait_inside()
        await second.finish()

        assert (state, during) == ((1, None), ["A-enter"])
        assert log == ["A-enter", "A-exit", "B-enter", "B-exit"]

    async def test_chat_runtime_clear_empties_everything(self) -> None:
        runtime = _runtime(_Clock())
        runtime.set_pending(_chat(1), _USER_A, _pending(_chat(1)))
        await _use(runtime, _chat(2), _USER_B)

        runtime.clear()

        assert (len(runtime), runtime.get_pending(_chat(1))) == (0, None)


# ===========================================================================
# 5. Hygiene
# ===========================================================================


class TestHygiene:
    """A pure stdlib module: no database, server, agent, llm or tools import."""

    def test_chat_runtime_imports_only_the_standard_library_and_admino_models(self) -> None:
        offenders: list[str] = []
        for node in ast.walk(_module_tree()):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    offenders.append(f"relative import level {node.level}")
                    continue
                module = node.module or ""
                names = (
                    [f"admino.{alias.name}" for alias in node.names]
                    if module == "admino"
                    else [module]
                )
            else:
                continue
            offenders.extend(
                name
                for name in names
                if name != "admino.models" and name.split(".")[0] not in sys.stdlib_module_names
            )

        assert offenders == []

    def test_chat_runtime_has_a_module_docstring(self) -> None:
        docstring = ast.get_docstring(_module_tree())

        assert docstring is not None
        assert docstring.strip()

    def test_chat_runtime_log_calls_use_literal_format_strings(self) -> None:
        """Lazy %-style arguments only: no f-string or pre-formatted message."""
        offenders = [
            ast.unparse(node)
            for node in ast.walk(_module_tree())
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _LOG_METHODS
            and not (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            )
        ]

        assert offenders == []

    async def test_chat_runtime_logs_no_tool_argument_of_a_pending_confirmation(self) -> None:
        """Set, evict, reap, forget, a full runtime and clear: no argument reaches a log."""
        clock = _Clock()
        with configured_logging("DEBUG", "text") as logs:
            runtime = _runtime(clock, max_entries=1)
            runtime.set_pending(_chat(1), _USER_A, _pending(_chat(1), "1"))
            clock.advance(1.0)
            runtime.set_pending(
                _chat(2), _USER_A, _pending(_chat(2), "2", expires_at=_NOW - timedelta(seconds=1))
            )
            runtime.reap_expired(_NOW)
            holder = _Holder(runtime, _chat(2), "A", [])
            await holder.wait_inside()
            runtime.set_pending(_chat(2), _USER_A, _pending(_chat(2), "3"))
            with pytest.raises(_module().ChatRuntimeFullError):
                runtime.set_pending(_chat(3), _USER_B, _pending(_chat(3), "4"))
            runtime.forget_user(_USER_A)
            await holder.finish()
            runtime.clear()

        haystacks = [logs.text.casefold()]
        for record in logs.records:
            haystacks.append(record.getMessage().casefold())
            haystacks.append(repr(record.args).casefold())
        for marker in (_ARG_KEY, _ARG_VALUE):
            hits = [text for text in haystacks if marker.casefold() in text]
            assert hits == [], f"{marker!r} reached the log"
