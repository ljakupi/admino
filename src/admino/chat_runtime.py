"""Bounded in-memory runtime state of persisted chats: run locks and pending confirmations.

Chats and their messages live in PostgreSQL (``admino.chats``, GH-176). What
must not be stored there lives here, one entry per chat:

- the chat's ``asyncio.Lock``, so two runs of one chat never overlap (the
  second waits, or with ``hold(..., wait=False)`` is refused at once with
  ``ChatRunActiveError``, GH-8) while different chats run concurrently;
- the chat's owner, so ``forget_user`` finds a deleted user's state;
- the chat's pending confirmation (at most one; ``set_pending`` replaces it).
  Memory only: after a restart (``clear``) or an eviction it is gone, and the
  server shows the chat's ``awaiting_confirmation`` message as expired;
- the last-used time (the injected monotonic clock) and the in-use count (the
  callers inside or waiting in ``hold``);
- the stop signal of the chat's streamed run (GH-8): ``stoppable`` registers a
  fresh ``asyncio.Event`` for the run's duration and ``request_stop`` sets it
  (``POST /api/chats/{id}/stop``, a client disconnect). It never creates an
  entry and never waits.

Inputs: chat and user ids (server-generated UUIDs), ``PendingConfirmation``
models, the current time for ``reap_expired``.
Outputs: ``hold()`` and ``stoppable()`` context managers, stored
confirmations, counts, whether a stop reached a run, and whether a chat has an
entry (``chat_id in runtime``, which never creates one).
Errors: ``ChatRuntimeFullError``, ``ChatRuntimeUserLimitError``,
``PendingConfirmationLimitError`` and ``ChatRunActiveError`` (see below).

Bound: at most ``max_entries`` entries, and (when ``max_entries_per_user``
is set) at most that many per owner, so one user can't push everyone else's
state out (GH-24). A chat that already has an entry is always served; creating
one (``hold`` or ``set_pending`` on an unknown chat) runs, in order:

1. Idle eviction: every entry not in use, without a pending confirmation and
   last used at least ``idle_s`` ago goes, whoever owns it.
2. Per-user bound: an owner at the bound loses their least recently used
   entry not in use and without a pending confirmation; when none of theirs
   can go, ``ChatRuntimeUserLimitError`` is raised, nothing is created and
   nothing beyond the idle entries is evicted (the server answers 429
   ``rate_limit``).
3. Global bound: at capacity, one victim goes, the first that exists of the
   owner's least recently used entry not in use without a pending
   confirmation, anyone's such entry, then the owner's least recently used
   entry not in use with a pending confirmation (that confirmation is lost).
   Another user's pending confirmation is never evicted, so a user filling
   the runtime can't cancel someone else's confirmation. Without a victim,
   ``ChatRuntimeFullError`` is raised and nothing changes (the server answers
   503 ``chats_busy``).

"Least recently used" is the order of the last ``hold`` entry or exit or
``set_pending``. An entry in use is never evicted.

Pending-confirmation limit: ``set_pending(..., max_pending_per_user=N)``
raises ``PendingConfirmationLimitError`` and changes nothing when the owner
already holds ``N`` stored confirmations (expired ones included: reaping is
the caller's job) in their other chats. Replacing a chat's own confirmation
never counts against it, nor do other users' confirmations.

Single process: the state belongs to one event loop in one process (admino
runs a single uvicorn worker). Several workers would each hold their own
locks and confirmations.

Security notes:
- Imports only the standard library and ``admino.models``: no database,
  server, agent, llm or tools module.
- Nothing here checks ownership: the server resolves the chat through the
  tenant-scoped repository (owner-private, cross-org 404) before calling in,
  so a caller only ever names a chat of its own.
- Log lines carry counts only, never a chat, user or confirmation id, a
  confirmation's tool arguments, a chat title or message content.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator
    from datetime import datetime
    from uuid import UUID

    from admino.models import PendingConfirmation

logger = logging.getLogger(__name__)


class ChatRuntimeFullError(RuntimeError):
    """At capacity and no entry can be evicted, so no entry can be created for another chat."""


class ChatRuntimeUserLimitError(RuntimeError):
    """The owner is at their per-user bound and none of their entries can be evicted."""


class PendingConfirmationLimitError(RuntimeError):
    """The owner already holds the allowed number of pending confirmations in other chats."""


class ChatRunActiveError(RuntimeError):
    """The chat is busy: a caller is inside or waiting in ``hold()``."""


@dataclass(slots=True)
class _Entry:
    """One chat's runtime state."""

    owner_user_id: UUID
    last_used: float
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    pending: PendingConfirmation | None = None
    # Callers inside hold() plus those waiting for its lock: while positive the
    # entry is never evicted, so a queued caller keeps the lock it waits on.
    in_use: int = 0
    # The stop signal of the streamed run inside hold(), while it is registered.
    stop: asyncio.Event | None = None


class ChatRuntime:
    """Per-chat run locks and pending confirmations, bounded globally and per owner."""

    def __init__(
        self,
        *,
        max_entries: int,
        idle_s: float,
        max_entries_per_user: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create an empty runtime.

        Args:
            max_entries: The most entries held at once.
            idle_s: Seconds after its last use from which an entry not in use
                and without a pending confirmation is idle (evicted on the next
                creation).
            max_entries_per_user: The most entries one owner holds at once;
                None for no per-user bound (only ``max_entries`` applies).
            clock: Monotonic seconds; injected so tests control time.
        """
        self._max_entries = max_entries
        self._idle_s = idle_s
        self._max_entries_per_user = max_entries_per_user
        self._clock = clock
        # Least recently used first: every use moves the entry to the end.
        self._entries: OrderedDict[UUID, _Entry] = OrderedDict()

    def __len__(self) -> int:
        """The number of entries."""
        return len(self._entries)

    def __contains__(self, chat_id: UUID) -> bool:
        """Whether the chat has an entry (``chat_id in runtime``); never creates one.

        Synchronous, so a caller that checks it and then enters ``hold`` with no
        ``await`` in between finds the same entry there and creates none.
        """
        return chat_id in self._entries

    @contextlib.asynccontextmanager
    async def hold(
        self, chat_id: UUID, owner_user_id: UUID, *, wait: bool = True
    ) -> AsyncIterator[None]:
        """Serialise the callers of one chat: enter once the chat's earlier callers left.

        Creates the chat's entry when it has none (see the module's bound).
        The lock is released and the entry stops being in use however the
        body exits, an exception included.

        Args:
            chat_id: The chat.
            owner_user_id: The chat's owner.
            wait: False refuses a busy chat instead of queueing behind it
                (GH-8). Busy is the in-use count, not the lock: a caller woken
                but not yet running holds the chat too. With nobody in use the
                lock is free, so the caller never waits.

        Raises:
            ChatRunActiveError: ``wait`` is False and a caller is inside or
                waiting in ``hold`` for this chat; nothing changes.
            ChatRuntimeUserLimitError: The chat has no entry and none of the
                owner's entries can make room under the per-user bound.
            ChatRuntimeFullError: The chat has no entry and none can be evicted
                at capacity.
        """
        entry = self._entries.get(chat_id)
        if entry is None:
            entry = self._create(chat_id, owner_user_id)
        elif not wait and entry.in_use:
            raise ChatRunActiveError
        entry.in_use += 1
        try:
            async with entry.lock:
                self._touch(chat_id, entry)
                yield
        finally:
            entry.in_use -= 1
            self._touch(chat_id, entry)

    @contextlib.contextmanager
    def stoppable(self, chat_id: UUID) -> Iterator[asyncio.Event]:
        """Register a fresh stop signal for the chat's run for the duration of the block.

        Used inside ``hold`` (the entry exists). The registration goes on exit,
        however the block exits, so a later ``request_stop`` never reaches a
        finished run's event.

        Raises:
            KeyError: The chat has no entry (nothing is registered).
        """
        entry = self._entries.get(chat_id)
        if entry is None:
            msg = "The chat has no runtime entry."
            raise KeyError(msg)
        event = asyncio.Event()
        entry.stop = event
        try:
            yield event
        finally:
            if entry.stop is event:
                entry.stop = None

    def request_stop(self, chat_id: UUID) -> bool:
        """Set the chat's registered stop signal; whether one was registered.

        Never creates an entry and never waits: False when the chat has no
        entry or no registered run (nothing running, or a run that can't be
        stopped).
        """
        entry = self._entries.get(chat_id)
        if entry is None or entry.stop is None:
            return False
        entry.stop.set()
        return True

    def set_pending(
        self,
        chat_id: UUID,
        owner_user_id: UUID,
        pending: PendingConfirmation,
        *,
        max_pending_per_user: int | None = None,
    ) -> None:
        """Store the chat's pending confirmation, replacing any earlier one.

        Args:
            chat_id: The chat.
            owner_user_id: The chat's owner.
            pending: The confirmation to store.
            max_pending_per_user: When given, the most pending confirmations
                the owner may hold in their other chats before this one is
                refused; None for no limit.

        Raises:
            PendingConfirmationLimitError: The owner's other chats already hold
                ``max_pending_per_user`` stored confirmations (expired or not).
            ChatRuntimeUserLimitError: The chat has no entry and none of the
                owner's entries can make room under the per-user bound.
            ChatRuntimeFullError: The chat has no entry and none can be evicted
                at capacity.
        """
        if max_pending_per_user is not None:
            held = sum(
                1
                for known_id, known in self._entries.items()
                if known_id != chat_id
                and known.owner_user_id == owner_user_id
                and known.pending is not None
            )
            if held >= max_pending_per_user:
                raise PendingConfirmationLimitError
        entry = self._entries.get(chat_id)
        if entry is None:
            entry = self._create(chat_id, owner_user_id)
        entry.pending = pending
        self._touch(chat_id, entry)

    def get_pending(self, chat_id: UUID) -> PendingConfirmation | None:
        """The chat's stored pending confirmation, expired or not; never creates an entry."""
        entry = self._entries.get(chat_id)
        return None if entry is None else entry.pending

    def pop_pending(self, chat_id: UUID) -> PendingConfirmation | None:
        """Remove and return the chat's pending confirmation (None when it has none)."""
        entry = self._entries.get(chat_id)
        if entry is None:
            return None
        pending, entry.pending = entry.pending, None
        return pending

    def reap_expired(self, now: datetime) -> int:
        """Drop every pending confirmation with ``now >= expires_at``; return how many."""
        reaped = 0
        for entry in self._entries.values():
            if entry.pending is not None and now >= entry.pending.expires_at:
                entry.pending = None
                reaped += 1
        return reaped

    def forget_user(self, user_id: UUID) -> None:
        """Drop a user's pending confirmations and their entries not in use.

        An entry in use keeps its lock (its callers still serialise) but loses
        its pending confirmation. Other users' entries are untouched.
        """
        for chat_id, entry in list(self._entries.items()):
            if entry.owner_user_id != user_id:
                continue
            entry.pending = None
            if entry.in_use == 0:
                del self._entries[chat_id]

    def clear(self) -> None:
        """Drop every entry (a restart)."""
        self._entries.clear()

    def _touch(self, chat_id: UUID, entry: _Entry) -> None:
        """Mark the entry used now, unless it was dropped meanwhile (``clear``)."""
        if self._entries.get(chat_id) is entry:
            entry.last_used = self._clock()
            self._entries.move_to_end(chat_id)

    def _create(self, chat_id: UUID, owner_user_id: UUID) -> _Entry:
        """Make room under the bounds (see the module docstring), then add an entry for the chat."""
        now = self._clock()
        idle: list[UUID] = []
        for known_id, known in self._entries.items():
            if now - known.last_used < self._idle_s:
                # Ordered by last use: every later entry is more recent still.
                break
            if known.in_use == 0 and known.pending is None:
                idle.append(known_id)
        for known_id in idle:
            del self._entries[known_id]
        if self._max_entries_per_user is not None:
            owned = [
                (known_id, known)
                for known_id, known in self._entries.items()
                if known.owner_user_id == owner_user_id
            ]
            if len(owned) >= self._max_entries_per_user:
                victim = next(
                    (
                        known_id
                        for known_id, known in owned
                        if known.in_use == 0 and known.pending is None
                    ),
                    None,
                )
                if victim is None:
                    logger.info(
                        "Chat runtime: a user's %d entries are all in use or pending", len(owned)
                    )
                    raise ChatRuntimeUserLimitError
                del self._entries[victim]
        if len(self._entries) >= self._max_entries:
            self._evict_one(owner_user_id)
        entry = _Entry(owner_user_id=owner_user_id, last_used=now)
        self._entries[chat_id] = entry
        return entry

    def _evict_one(self, owner_user_id: UUID) -> None:
        """Evict one entry not in use, in the module's victim order, for a new entry of the owner.

        Raises:
            ChatRuntimeFullError: No entry can go (nothing is evicted).
        """
        free = [(key, entry) for key, entry in self._entries.items() if entry.in_use == 0]
        own_without_pending = next(
            (
                key
                for key, entry in free
                if entry.owner_user_id == owner_user_id and entry.pending is None
            ),
            None,
        )
        any_without_pending = next((key for key, entry in free if entry.pending is None), None)
        # Chosen only when neither of the above exists: the owner's free entries then all
        # hold a confirmation.
        own_with_pending = next(
            (key for key, entry in free if entry.owner_user_id == owner_user_id), None
        )
        victim = next(
            (
                key
                for key in (own_without_pending, any_without_pending, own_with_pending)
                if key is not None
            ),
            None,
        )
        if victim is None:
            logger.warning(
                "Chat runtime full: none of its %d entries can be evicted", len(self._entries)
            )
            raise ChatRuntimeFullError
        if self._entries.pop(victim).pending is not None:
            logger.info("Chat runtime evicted a chat with a pending confirmation")
