"""Bounded in-memory runtime state of persisted chats: run locks and pending confirmations.

Chats and their messages live in PostgreSQL (``admino.chats``, GH-176). What
must not be stored there lives here, one entry per chat:

- the chat's ``asyncio.Lock``, so two runs of one chat never overlap (the
  second waits) while different chats run concurrently;
- the chat's owner, so ``forget_user`` finds a deleted user's state;
- the chat's pending confirmation (at most one; ``set_pending`` replaces it).
  Memory only: after a restart (``clear``) or an eviction it is gone, and the
  server shows the chat's ``awaiting_confirmation`` message as expired;
- the last-used time (the injected monotonic clock) and the in-use count (the
  callers inside or waiting in ``hold``).

Inputs: chat and user ids (server-generated UUIDs), ``PendingConfirmation``
models, the current time for ``reap_expired``.
Outputs: ``hold()`` context managers, stored confirmations, counts.

Bound: at most ``max_entries`` entries. Creating one (``hold`` or
``set_pending`` on an unknown chat) first evicts the idle entries (not in
use, no pending confirmation, last used at least ``idle_s`` ago), then, at
capacity, the least recently used entry not in use (its pending confirmation
goes with it). An entry in use is never evicted; when every entry is in use,
``ChatRuntimeFullError`` is raised and nothing changes (the server answers
503 ``chats_busy``).

Single process: the state belongs to one event loop in one process (admino
runs a single uvicorn worker). Several workers would each hold their own
locks and confirmations.

Security notes:
- Imports only the standard library and ``admino.models``: no database,
  server, agent, llm or tools module.
- Nothing here checks ownership: the server resolves the chat through the
  tenant-scoped repository (owner-private, cross-org 404) before calling in,
  so a caller only ever names a chat of its own.
- Log lines carry counts only, never a confirmation's tool arguments, a chat
  title or message content.
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
    from collections.abc import AsyncIterator, Callable
    from datetime import datetime
    from uuid import UUID

    from admino.models import PendingConfirmation

logger = logging.getLogger(__name__)


class ChatRuntimeFullError(RuntimeError):
    """Every entry is in use, so no entry can be created for another chat."""


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


class ChatRuntime:
    """Per-chat run locks and pending confirmations, bounded to ``max_entries`` entries."""

    def __init__(
        self,
        *,
        max_entries: int,
        idle_s: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create an empty runtime.

        Args:
            max_entries: The most entries held at once.
            idle_s: Seconds after its last use from which an entry not in use
                and without a pending confirmation is idle (evicted on the next
                creation).
            clock: Monotonic seconds; injected so tests control time.
        """
        self._max_entries = max_entries
        self._idle_s = idle_s
        self._clock = clock
        # Least recently used first: every use moves the entry to the end.
        self._entries: OrderedDict[UUID, _Entry] = OrderedDict()

    def __len__(self) -> int:
        """The number of entries."""
        return len(self._entries)

    @contextlib.asynccontextmanager
    async def hold(self, chat_id: UUID, owner_user_id: UUID) -> AsyncIterator[None]:
        """Serialise the callers of one chat: enter once the chat's earlier callers left.

        Creates the chat's entry when it has none (see the module's bound).
        The lock is released and the entry stops being in use however the
        body exits, an exception included.

        Raises:
            ChatRuntimeFullError: The chat has no entry and every entry is in use.
        """
        entry = self._entries.get(chat_id)
        if entry is None:
            entry = self._create(chat_id, owner_user_id)
        entry.in_use += 1
        try:
            async with entry.lock:
                self._touch(chat_id, entry)
                yield
        finally:
            entry.in_use -= 1
            self._touch(chat_id, entry)

    def set_pending(self, chat_id: UUID, owner_user_id: UUID, pending: PendingConfirmation) -> None:
        """Store the chat's pending confirmation, replacing any earlier one.

        Raises:
            ChatRuntimeFullError: The chat has no entry and every entry is in use.
        """
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
        """Make room under the bound, then add an entry for the chat."""
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
        if len(self._entries) >= self._max_entries:
            self._evict_least_recently_used()
        entry = _Entry(owner_user_id=owner_user_id, last_used=now)
        self._entries[chat_id] = entry
        return entry

    def _evict_least_recently_used(self) -> None:
        """Evict the least recently used entry not in use, with its pending confirmation.

        Raises:
            ChatRuntimeFullError: Every entry is in use (nothing is evicted).
        """
        victim = next((key for key, entry in self._entries.items() if entry.in_use == 0), None)
        if victim is None:
            logger.warning("Chat runtime full: all %d entries are in use", len(self._entries))
            raise ChatRuntimeFullError
        dropped = self._entries.pop(victim).pending is not None
        if dropped:
            logger.info("Chat runtime evicted a chat with a pending confirmation")
