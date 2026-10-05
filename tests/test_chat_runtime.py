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

GH-24 (contract section 1) adds, pinned in sections 6 to 10 (the at-capacity rule
above is refined there; every GH-176 test stays valid under it, since each one has a
single user, or one whose victim is the same under both rules):

- ``ChatRuntime(..., max_entries_per_user=None)``: keyword-only, default ``None`` =
  no per-user bound (one user may fill the whole runtime, as before).
- ``ChatRuntimeUserLimitError`` and ``PendingConfirmationLimitError``: both
  ``RuntimeError`` subclasses, neither a ``ChatRuntimeFullError`` nor each other.
- Creating an entry runs, in order: idle eviction (unchanged, any owner); the
  per-user bound (an owner at the bound loses their least recently used entry that
  is neither in use nor holding a pending confirmation, else
  ``ChatRuntimeUserLimitError`` from ``hold`` (body never runs) and ``set_pending``,
  with nothing created or evicted; other users are untouched and can still create
  entries; a chat that has an entry is always served); the global bound, whose
  victim is the first of: the requester's own LRU entry without a pending
  confirmation, anyone's LRU entry without one, the requester's own LRU entry with
  one (that confirmation is lost). Another user's pending confirmation is never
  evicted: with no candidate, ``ChatRuntimeFullError`` and nothing changes.
- ``set_pending(..., max_pending_per_user=N)``: when the owner's stored pending
  confirmations in OTHER chats (expired ones too: reaping is the caller's job) are
  ``>= N``, ``PendingConfirmationLimitError`` and nothing changes (no entry created,
  nothing evicted, the chat's earlier confirmation kept). The chat's own and other
  users' confirmations never count; the limit applies only to a call that passes it.
- No chat, user or confirmation id and no tool argument reaches a log record on the
  per-user paths (per-user eviction, the user limit, the pending limit, the eviction
  of the requester's own confirmation, a full runtime).

Entries without a pending confirmation are visible only through ``len()``. The
GH-24 tests tell them apart with ``forget_user`` (it drops exactly a user's entries
not in use), with a later ``hold`` that does or doesn't grow ``len()`` (only while
there is room), or with a later idle eviction (an entry left behind would be idle).

``admino.chat_runtime`` is imported lazily, so this file collects before GH-176 and
each test fails on its own; the GH-24 names (the keyword, the two errors) are looked
up inside the tests too.

No database, network or real clock is used. Every wait is bounded, so a wrong
implementation fails instead of hanging.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import inspect
import logging
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


# ===========================================================================
# GH-24 helpers
# ===========================================================================

_USER_C: Final = UUID("7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f")
_USER_D: Final = UUID("8d9e0f1a-2b3c-4d4e-9f5a-6b7c8d9e0f1a")

# How a new entry is created: a finished run (hold) or a stored confirmation.
_VIAS: Final = ("hold", "set_pending")


def _bounded(
    clock: _Clock, *, per_user: int | None, max_entries: int = 8, idle_s: float = _IDLE_S
) -> Any:
    """A runtime with the GH-24 per-user bound (``max_entries_per_user``)."""
    return _module().ChatRuntime(
        max_entries=max_entries, idle_s=idle_s, max_entries_per_user=per_user, clock=clock
    )


async def _create(
    runtime: Any, chat_id: UUID, user_id: UUID, via: str, ran: list[str] | None = None
) -> PendingConfirmation | None:
    """Create the chat's entry through ``hold`` (one finished run) or ``set_pending``.

    Returns the stored confirmation (``set_pending``) or None (``hold``); a ``hold``
    body that runs appends to ``ran``.
    """
    if via == "hold":
        async with runtime.hold(chat_id, user_id):
            if ran is not None:
                ran.append("body")
        return None
    pending = _pending(chat_id, f"new{chat_id.int}")
    runtime.set_pending(chat_id, user_id, pending)
    return pending


def _forget_count(runtime: Any, user_id: UUID) -> int:
    """How many entries not in use the user had: ``forget_user`` drops exactly those.

    Destructive, so a test calls it last, with no caller of that user inside ``hold``.
    """
    before = len(runtime)
    runtime.forget_user(user_id)
    return before - len(runtime)


async def _has_entry(runtime: Any, chat_id: UUID, user_id: UUID) -> bool:
    """Whether the chat has an entry: a finished run of it then adds none.

    Meaningful only while there is room (globally and under the user's bound) and no
    entry is idle, so that a chat without an entry grows ``len()``.
    """
    before = len(runtime)
    await _use(runtime, chat_id, user_id)
    return len(runtime) == before


# ===========================================================================
# 6. GH-24: the per-user keyword and the new errors
# ===========================================================================


class TestPerUserApi:
    """max_entries_per_user is optional; the two limit errors are their own classes."""

    def test_chat_runtime_max_entries_per_user_is_keyword_only_defaulting_to_none(
        self,
    ) -> None:
        parameter = inspect.signature(_module().ChatRuntime).parameters.get("max_entries_per_user")

        assert parameter is not None
        assert (parameter.kind, parameter.default) == (inspect.Parameter.KEYWORD_ONLY, None)

    async def test_chat_runtime_without_a_per_user_bound_one_user_may_fill_it(self) -> None:
        """None means no per-user bound (not a bound of 0): A holds one chat and stores
        three confirmations in a runtime of four."""
        clock = _Clock()
        runtime = _bounded(clock, per_user=None, max_entries=4)
        holder = _Holder(runtime, _chat(1), "A", [])
        await holder.wait_inside()
        stored: list[PendingConfirmation] = []
        for number in (2, 3, 4):
            clock.advance(1.0)
            pending = _pending(_chat(number), f"a{number}")
            runtime.set_pending(_chat(number), _USER_A, pending)
            stored.append(pending)

        state = (len(runtime), [runtime.get_pending(_chat(number)) for number in (2, 3, 4)])
        await holder.finish()

        assert state == (4, stored)

    def test_chat_runtime_limit_errors_are_runtime_errors_but_not_the_full_error(self) -> None:
        """The server maps each to its own answer (429, the rate_limit turn, 503)."""
        module = _module()
        user_limit = module.ChatRuntimeUserLimitError
        pending_limit = module.PendingConfirmationLimitError
        full = module.ChatRuntimeFullError

        relations = (
            issubclass(user_limit, RuntimeError),
            issubclass(pending_limit, RuntimeError),
            issubclass(user_limit, full),
            issubclass(pending_limit, full),
            issubclass(user_limit, pending_limit),
            issubclass(pending_limit, user_limit),
            issubclass(full, user_limit),
            issubclass(full, pending_limit),
        )

        assert relations == (True, True, False, False, False, False, False, False)


# ===========================================================================
# 7. GH-24: the per-user bound (creation step 2)
# ===========================================================================


class TestPerUserBound:
    """An owner at the bound loses their own LRU lock-only entry, or gets the user limit."""

    @pytest.mark.parametrize("via", _VIAS)
    async def test_chat_runtime_owner_at_the_bound_loses_own_entry_without_pending(
        self, via: str
    ) -> None:
        """Bound 2. A's least recently used entry holds a confirmation, so A's chat 3
        (no confirmation) goes; B's chat 1 is older still (but not idle) and stays."""
        clock = _Clock()
        runtime = _bounded(clock, per_user=2)
        await _use(runtime, _chat(1), _USER_B)
        clock.advance(500.0)
        a_pending, b_pending = _pending(_chat(2), "a2"), _pending(_chat(4), "b4")
        runtime.set_pending(_chat(2), _USER_A, a_pending)
        clock.advance(1.0)
        await _use(runtime, _chat(3), _USER_A)
        clock.advance(1.0)
        runtime.set_pending(_chat(4), _USER_B, b_pending)
        clock.advance(1.0)

        created = await _create(runtime, _chat(5), _USER_A, via)

        state = (
            len(runtime),
            runtime.get_pending(_chat(2)),
            runtime.get_pending(_chat(4)),
            runtime.get_pending(_chat(5)),
        )
        counts = (_forget_count(runtime, _USER_B), _forget_count(runtime, _USER_A))
        assert (state, counts) == ((4, a_pending, b_pending, created), (2, 2))

    async def test_chat_runtime_owner_at_the_bound_never_loses_an_entry_in_use(self) -> None:
        """A's least recently used entry is held: A's chat 2 goes instead, and a second
        caller of the held chat still waits for the first."""
        clock = _Clock()
        runtime = _bounded(clock, per_user=2)
        log: list[str] = []
        first = _Holder(runtime, _chat(1), "A", log)
        await first.wait_inside()
        clock.advance(1.0)
        await _use(runtime, _chat(2), _USER_A)
        clock.advance(1.0)
        created = _pending(_chat(3), "a3")

        runtime.set_pending(_chat(3), _USER_A, created)
        second = _Holder(runtime, _chat(1), "B", log)
        await _spin()
        during = list(log)
        state = (len(runtime), runtime.get_pending(_chat(3)))
        await first.finish()
        await second.wait_inside()
        await second.finish()

        assert (state, during) == ((2, created), ["A-enter"])

    async def test_chat_runtime_owner_at_the_bound_loses_their_least_recently_used_entry(
        self,
    ) -> None:
        """Chat 1 was created first but used last, so chat 2 goes. Seen through a later
        idle eviction: by then a left-over chat 2 would be idle, chat 1 is not."""
        clock = _Clock()
        runtime = _bounded(clock, per_user=2, idle_s=100.0)
        await _use(runtime, _chat(1))
        clock.advance(10.0)
        await _use(runtime, _chat(2))
        clock.advance(10.0)
        await _use(runtime, _chat(1))
        clock.advance(10.0)
        await _use(runtime, _chat(3))
        size = len(runtime)
        clock.advance(82.0)

        await _use(runtime, _chat(4), _USER_B)

        assert (size, len(runtime)) == (2, 3)

    @pytest.mark.parametrize("via", _VIAS)
    async def test_chat_runtime_owner_with_every_entry_busy_gets_the_user_limit_error(
        self, via: str
    ) -> None:
        """A's entries are held or pending: nothing is created or evicted, the hold body
        never runs, A's confirmation and B's entries are untouched."""
        clock = _Clock()
        runtime = _bounded(clock, per_user=2)
        user_limit = _module().ChatRuntimeUserLimitError
        await _use(runtime, _chat(8), _USER_B)
        clock.advance(1.0)
        b_pending = _pending(_chat(9), "b9")
        runtime.set_pending(_chat(9), _USER_B, b_pending)
        clock.advance(1.0)
        holder = _Holder(runtime, _chat(1), "A", [])
        await holder.wait_inside()
        clock.advance(1.0)
        a_pending = _pending(_chat(2), "a2")
        runtime.set_pending(_chat(2), _USER_A, a_pending)
        clock.advance(1.0)
        ran: list[str] = []

        with pytest.raises(user_limit):
            await _create(runtime, _chat(3), _USER_A, via, ran)
        state = (
            len(runtime),
            runtime.get_pending(_chat(2)),
            runtime.get_pending(_chat(9)),
            runtime.get_pending(_chat(3)),
        )
        await holder.finish()

        assert (state, ran, _forget_count(runtime, _USER_B)) == (
            (4, a_pending, b_pending, None),
            [],
            2,
        )

    async def test_chat_runtime_owner_at_the_bound_still_uses_the_chats_they_have(
        self,
    ) -> None:
        """No bound applies to a chat that has an entry: a confirmation in A's held chat
        and a replacement in A's pending chat are stored, and a second caller of the
        held chat waits instead of raising."""
        clock = _Clock()
        runtime = _bounded(clock, per_user=2)
        log: list[str] = []
        first = _Holder(runtime, _chat(1), "A", log)
        await first.wait_inside()
        clock.advance(1.0)
        runtime.set_pending(_chat(2), _USER_A, _pending(_chat(2), "a2"))
        clock.advance(1.0)
        held, replaced = _pending(_chat(1), "a1"), _pending(_chat(2), "a2b")

        runtime.set_pending(_chat(1), _USER_A, held)
        runtime.set_pending(_chat(2), _USER_A, replaced)
        second = _Holder(runtime, _chat(1), "B", log)
        await _spin()
        during = list(log)
        state = (len(runtime), runtime.get_pending(_chat(1)), runtime.get_pending(_chat(2)))
        await first.finish()
        await second.wait_inside()
        await second.finish()

        assert (state, during) == ((2, held, replaced), ["A-enter"])
        assert log == ["A-enter", "A-exit", "B-enter", "B-exit"]

    async def test_chat_runtime_owner_at_the_bound_leaves_other_users_free_to_create(
        self,
    ) -> None:
        """While A gets the user limit, B (same org or not) and C (another org) still
        open chats: the bound counts each owner's own entries only."""
        clock = _Clock()
        runtime = _bounded(clock, per_user=2)
        user_limit = _module().ChatRuntimeUserLimitError
        holder = _Holder(runtime, _chat(1), "A", [])
        await holder.wait_inside()
        clock.advance(1.0)
        a_pending, b_pending = _pending(_chat(2), "a2"), _pending(_chat(5), "b5")
        runtime.set_pending(_chat(2), _USER_A, a_pending)
        clock.advance(1.0)
        with pytest.raises(user_limit):
            runtime.set_pending(_chat(3), _USER_A, _pending(_chat(3), "a3"))
        clock.advance(1.0)

        await _use(runtime, _chat(4), _USER_B)
        clock.advance(1.0)
        runtime.set_pending(_chat(5), _USER_B, b_pending)
        clock.advance(1.0)
        await _use(runtime, _chat(6), _USER_C)
        state = (len(runtime), runtime.get_pending(_chat(2)), runtime.get_pending(_chat(5)))
        await holder.finish()

        assert state == (5, a_pending, b_pending)

    async def test_chat_runtime_idle_eviction_still_runs_before_the_per_user_bound(
        self,
    ) -> None:
        """Idle chats of A and of B both go first, so A is below the bound again and
        A's pending chat stays: two entries are left, not three."""
        clock = _Clock()
        runtime = _bounded(clock, per_user=2, idle_s=100.0)
        await _use(runtime, _chat(1), _USER_B)
        await _use(runtime, _chat(2), _USER_A)
        clock.advance(10.0)
        a_pending, created = _pending(_chat(3), "a3"), _pending(_chat(4), "a4")
        runtime.set_pending(_chat(3), _USER_A, a_pending)
        clock.advance(90.0)

        runtime.set_pending(_chat(4), _USER_A, created)

        assert (len(runtime), runtime.get_pending(_chat(3)), runtime.get_pending(_chat(4))) == (
            2,
            a_pending,
            created,
        )


# ===========================================================================
# 8. GH-24: the victim at global capacity (creation step 3)
# ===========================================================================


class TestGlobalVictim:
    """Own lock-only entry, then anyone's, then own pending; never another's pending."""

    async def test_chat_runtime_at_capacity_evicts_own_lru_before_another_users_older(
        self,
    ) -> None:
        """B's chat 1 is the oldest entry; A's chat 3 is A's least recently used (chat 2
        was created first but used last): chat 3 goes, B's chat stays."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=3)
        await _use(runtime, _chat(1), _USER_B)
        clock.advance(1.0)
        await _use(runtime, _chat(2), _USER_A)
        clock.advance(1.0)
        await _use(runtime, _chat(3), _USER_A)
        clock.advance(1.0)
        await _use(runtime, _chat(2), _USER_A)
        clock.advance(1.0)

        await _use(runtime, _chat(4), _USER_A)

        kept_of_b = _forget_count(runtime, _USER_B)
        presence = (
            await _has_entry(runtime, _chat(2), _USER_A),
            await _has_entry(runtime, _chat(3), _USER_A),
        )
        assert (kept_of_b, presence) == (1, (True, False))

    async def test_chat_runtime_at_capacity_evicts_anyones_lock_before_own_pending(
        self,
    ) -> None:
        """A's only entry holds a confirmation: the least recently used entry without one
        goes (B's chat 3), not B's older pending chat 1 and not A's pending chat 2."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=4)
        b_pending, a_pending = _pending(_chat(1), "b1"), _pending(_chat(2), "a2")
        runtime.set_pending(_chat(1), _USER_B, b_pending)
        clock.advance(1.0)
        runtime.set_pending(_chat(2), _USER_A, a_pending)
        clock.advance(1.0)
        await _use(runtime, _chat(3), _USER_B)
        clock.advance(1.0)
        await _use(runtime, _chat(4), _USER_B)
        clock.advance(1.0)
        created = _pending(_chat(5), "a5")

        runtime.set_pending(_chat(5), _USER_A, created)

        state = (
            len(runtime),
            runtime.get_pending(_chat(1)),
            runtime.get_pending(_chat(2)),
            runtime.get_pending(_chat(5)),
        )
        _forget_count(runtime, _USER_A)
        presence = (
            await _has_entry(runtime, _chat(4), _USER_B),
            await _has_entry(runtime, _chat(3), _USER_B),
        )
        assert (state, presence) == ((4, b_pending, a_pending, created), (True, False))

    async def test_chat_runtime_at_capacity_evicts_own_pending_when_nothing_else_can_go(
        self,
    ) -> None:
        """B's chat 1 holds a confirmation and B's chat 5 is in use: A's least recently
        used pending chat (3: chat 2 was created first but used last) goes, with its
        confirmation."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=4)
        b_pending = _pending(_chat(1), "b1")
        runtime.set_pending(_chat(1), _USER_B, b_pending)
        clock.advance(1.0)
        kept, lost = _pending(_chat(2), "a2"), _pending(_chat(3), "a3")
        runtime.set_pending(_chat(2), _USER_A, kept)
        clock.advance(1.0)
        runtime.set_pending(_chat(3), _USER_A, lost)
        clock.advance(1.0)
        await _use(runtime, _chat(2), _USER_A)
        clock.advance(1.0)
        holder = _Holder(runtime, _chat(5), "H", [], _USER_B)
        await holder.wait_inside()
        clock.advance(1.0)
        created = _pending(_chat(6), "a6")

        runtime.set_pending(_chat(6), _USER_A, created)
        state = (
            len(runtime),
            runtime.get_pending(_chat(1)),
            runtime.get_pending(_chat(2)),
            runtime.get_pending(_chat(3)),
            runtime.get_pending(_chat(6)),
        )
        await holder.finish()

        assert state == (4, b_pending, kept, None, created)

    @pytest.mark.parametrize("via", _VIAS)
    async def test_chat_runtime_at_capacity_never_evicts_another_users_pending(
        self, via: str
    ) -> None:
        """Only B's (old) pending chats and A's held chat are left: A's new chat raises
        ChatRuntimeFullError, the hold body never runs and nothing changes."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=3)
        full_error = _module().ChatRuntimeFullError
        first, second = _pending(_chat(1), "b1"), _pending(_chat(2), "b2")
        runtime.set_pending(_chat(1), _USER_B, first)
        clock.advance(1.0)
        runtime.set_pending(_chat(2), _USER_B, second)
        clock.advance(1.0)
        holder = _Holder(runtime, _chat(3), "A", [])
        await holder.wait_inside()
        clock.advance(10_000.0)
        ran: list[str] = []

        with pytest.raises(full_error):
            await _create(runtime, _chat(4), _USER_A, via, ran)
        state = (
            len(runtime),
            runtime.get_pending(_chat(1)),
            runtime.get_pending(_chat(2)),
            runtime.get_pending(_chat(4)),
        )
        await holder.finish()

        assert (state, ran) == ((3, first, second, None), [])

    async def test_chat_runtime_one_user_filling_it_keeps_another_orgs_pending(self) -> None:
        """The issue's scenario: B (org B) waits for a confirmation while A (org A) opens
        chat after chat in a full runtime. B's confirmation stays actionable, and C
        (another org) can still open a chat afterwards."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=4)
        b_pending = _pending(_chat(1), "b1")
        runtime.set_pending(_chat(1), _USER_B, b_pending)
        for number in range(2, 8):
            clock.advance(1.0)
            if number % 2:
                await _use(runtime, _chat(number), _USER_A)
            else:
                runtime.set_pending(_chat(number), _USER_A, _pending(_chat(number), f"a{number}"))
        clock.advance(1.0)

        await _use(runtime, _chat(20), _USER_C)

        assert (len(runtime), runtime.get_pending(_chat(1))) == (4, b_pending)
        assert runtime.pop_pending(_chat(1)) == b_pending


# ===========================================================================
# 9. GH-24: set_pending(..., max_pending_per_user=N)
# ===========================================================================


class TestPendingLimit:
    """The owner's confirmations in other chats count; the limit refuses, changing nothing."""

    async def test_chat_runtime_pending_limit_refuses_a_new_chat_and_changes_nothing(
        self,
    ) -> None:
        """The runtime is full, so creating chat 4 would evict B's chat 1: it stays."""
        clock = _Clock()
        runtime = _runtime(clock, max_entries=3)
        limit_error = _module().PendingConfirmationLimitError
        await _use(runtime, _chat(1), _USER_B)
        clock.advance(1.0)
        first, second = _pending(_chat(2), "a2"), _pending(_chat(3), "a3")
        runtime.set_pending(_chat(2), _USER_A, first)
        clock.advance(1.0)
        runtime.set_pending(_chat(3), _USER_A, second)
        clock.advance(1.0)

        with pytest.raises(limit_error):
            runtime.set_pending(_chat(4), _USER_A, _pending(_chat(4), "a4"), max_pending_per_user=2)

        state = (
            len(runtime),
            runtime.get_pending(_chat(2)),
            runtime.get_pending(_chat(3)),
            runtime.get_pending(_chat(4)),
        )
        assert (state, _forget_count(runtime, _USER_B)) == ((3, first, second, None), 1)

    @pytest.mark.parametrize("previous", ["entry-without-pending", "entry-with-pending"])
    async def test_chat_runtime_pending_limit_leaves_an_existing_chat_as_it_was(
        self, previous: str
    ) -> None:
        """Two confirmations in other chats, limit 2: chat 3 keeps what it had."""
        clock = _Clock()
        runtime = _runtime(clock)
        limit_error = _module().PendingConfirmationLimitError
        runtime.set_pending(_chat(1), _USER_A, _pending(_chat(1), "a1"))
        clock.advance(1.0)
        runtime.set_pending(_chat(2), _USER_A, _pending(_chat(2), "a2"))
        clock.advance(1.0)
        earlier: PendingConfirmation | None = None
        if previous == "entry-with-pending":
            earlier = _pending(_chat(3), "old")
            runtime.set_pending(_chat(3), _USER_A, earlier)
        else:
            await _use(runtime, _chat(3), _USER_A)
        clock.advance(1.0)

        with pytest.raises(limit_error):
            runtime.set_pending(
                _chat(3), _USER_A, _pending(_chat(3), "new"), max_pending_per_user=2
            )

        assert (len(runtime), runtime.get_pending(_chat(3))) == (3, earlier)

    def test_chat_runtime_pending_limit_stores_the_confirmation_below_the_limit(self) -> None:
        clock = _Clock()
        runtime = _runtime(clock)
        for number in (1, 2):
            runtime.set_pending(_chat(number), _USER_A, _pending(_chat(number), f"a{number}"))
            clock.advance(1.0)
        created = _pending(_chat(3), "a3")

        runtime.set_pending(_chat(3), _USER_A, created, max_pending_per_user=3)

        assert (runtime.get_pending(_chat(3)), len(runtime)) == (created, 3)

    def test_chat_runtime_pending_limit_lets_a_chat_replace_its_own_confirmation(
        self,
    ) -> None:
        """At the limit (2 of 2), chat 2's own confirmation doesn't count: only chat 1 does."""
        clock = _Clock()
        runtime = _runtime(clock)
        first = _pending(_chat(1), "a1")
        runtime.set_pending(_chat(1), _USER_A, first)
        clock.advance(1.0)
        runtime.set_pending(_chat(2), _USER_A, _pending(_chat(2), "a2"))
        clock.advance(1.0)
        newer = _pending(_chat(2), "a2b")

        runtime.set_pending(_chat(2), _USER_A, newer, max_pending_per_user=2)

        assert (runtime.get_pending(_chat(2)), runtime.get_pending(_chat(1)), len(runtime)) == (
            newer,
            first,
            2,
        )

    def test_chat_runtime_pending_limit_ignores_other_users_confirmations(self) -> None:
        """B holds three confirmations, A one: A is below a limit of 2."""
        clock = _Clock()
        runtime = _runtime(clock)
        b_stored: list[PendingConfirmation] = []
        for number in (1, 2, 3):
            pending = _pending(_chat(number), f"b{number}")
            runtime.set_pending(_chat(number), _USER_B, pending)
            b_stored.append(pending)
            clock.advance(1.0)
        runtime.set_pending(_chat(4), _USER_A, _pending(_chat(4), "a4"))
        clock.advance(1.0)
        created = _pending(_chat(5), "a5")

        runtime.set_pending(_chat(5), _USER_A, created, max_pending_per_user=2)

        assert (
            runtime.get_pending(_chat(5)),
            [runtime.get_pending(_chat(number)) for number in (1, 2, 3)],
        ) == (created, b_stored)

    def test_chat_runtime_pending_limit_counts_stored_expired_confirmations(self) -> None:
        """Reaping is the caller's job: expired ones count until reap_expired drops them."""
        clock = _Clock()
        runtime = _runtime(clock)
        limit_error = _module().PendingConfirmationLimitError
        long_ago = datetime(2020, 1, 1, tzinfo=UTC)
        for number in (1, 2):
            runtime.set_pending(
                _chat(number), _USER_A, _pending(_chat(number), f"a{number}", expires_at=long_ago)
            )
            clock.advance(1.0)
        created = _pending(_chat(3), "a3")

        with pytest.raises(limit_error):
            runtime.set_pending(_chat(3), _USER_A, created, max_pending_per_user=2)
        refused = runtime.get_pending(_chat(3))
        reaped = runtime.reap_expired(_NOW)
        runtime.set_pending(_chat(3), _USER_A, created, max_pending_per_user=2)

        assert (refused, reaped, runtime.get_pending(_chat(3))) == (None, 2, created)

    def test_chat_runtime_pending_limit_applies_only_to_calls_that_pass_it(self) -> None:
        """Refused with the keyword, the same call without it stores (no sticky limit)."""
        clock = _Clock()
        runtime = _runtime(clock)
        limit_error = _module().PendingConfirmationLimitError
        for number in (1, 2):
            runtime.set_pending(_chat(number), _USER_A, _pending(_chat(number), f"a{number}"))
            clock.advance(1.0)
        third, fourth = _pending(_chat(3), "a3"), _pending(_chat(4), "a4")

        with pytest.raises(limit_error):
            runtime.set_pending(_chat(3), _USER_A, third, max_pending_per_user=2)
        runtime.set_pending(_chat(3), _USER_A, third)
        clock.advance(1.0)
        runtime.set_pending(_chat(4), _USER_A, fourth)

        assert (runtime.get_pending(_chat(3)), runtime.get_pending(_chat(4)), len(runtime)) == (
            third,
            fourth,
            4,
        )


# ===========================================================================
# 10. GH-24: log hygiene of the per-user paths
# ===========================================================================


class TestPerUserHygiene:
    """The new paths log counts at most: no ids, no tool arguments."""

    async def test_chat_runtime_per_user_paths_log_no_ids_or_tool_arguments(self) -> None:
        """Per-user eviction, the user limit (the server's 429), the pending limit, the
        eviction of the requester's own confirmation and a full runtime (503)."""
        clock = _Clock()
        module = _module()
        with configured_logging("DEBUG", "text") as logs:
            runtime = _bounded(clock, per_user=2, max_entries=4)
            logging.getLogger(module.__name__).debug("hygiene probe %d", 24)
            runtime.set_pending(_chat(1), _USER_A, _pending(_chat(1), "h1"))
            clock.advance(1.0)
            await _use(runtime, _chat(2), _USER_A)
            clock.advance(1.0)
            await _use(runtime, _chat(3), _USER_A)
            clock.advance(1.0)
            runtime.set_pending(_chat(3), _USER_A, _pending(_chat(3), "h3"))
            clock.advance(1.0)
            with pytest.raises(module.ChatRuntimeUserLimitError):
                runtime.set_pending(_chat(4), _USER_A, _pending(_chat(4), "h4"))
            runtime.set_pending(_chat(5), _USER_B, _pending(_chat(5), "h5"))
            clock.advance(1.0)
            with pytest.raises(module.PendingConfirmationLimitError):
                runtime.set_pending(
                    _chat(6), _USER_B, _pending(_chat(6), "h6"), max_pending_per_user=1
                )
            holder = _Holder(runtime, _chat(7), "C", [], _USER_C)
            await holder.wait_inside()
            clock.advance(1.0)
            runtime.set_pending(_chat(8), _USER_B, _pending(_chat(8), "h8"))
            own_pending_evicted = runtime.get_pending(_chat(5)) is None
            with pytest.raises(module.ChatRuntimeFullError):
                await _use(runtime, _chat(9), _USER_D)
            await holder.finish()
            runtime.clear()

        haystacks = [logs.text.casefold()]
        for record in logs.records:
            haystacks.append(record.getMessage().casefold())
            haystacks.append(repr(record.args).casefold())
        ids = [_chat(number) for number in range(1, 10)] + [_USER_A, _USER_B, _USER_C, _USER_D]
        markers = [_ARG_KEY, _ARG_VALUE, "conf-h", "call-h"]
        markers += [str(value) for value in ids] + [value.hex for value in ids]
        hits = [
            marker
            for marker in markers
            if any(marker.casefold() in haystack for haystack in haystacks)
        ]

        assert ("hygiene probe 24" in logs.text, own_pending_evicted, hits) == (True, True, [])
