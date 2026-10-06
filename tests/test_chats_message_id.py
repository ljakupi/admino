"""Spec for ``chats.append_messages`` returning the turn's last message id (GH-8, C6).

The stream's ``message_saved`` event names "the uuid of the turn's last stored
message" (contract C5.3), so ``admino.chats.append_messages`` now returns the id
of the LAST message it appended (a ``uuid.UUID``), for one and for several
messages and for every ``final_status``, ``"stopped"`` included: the id of the
row with the highest seq, never an earlier message of the chat or of the turn.
Two turns return their own last ids. Unchanged and pinned in tests/test_chats.py
(not repeated here): an empty list returns None and runs no statement, a
``system`` message is a ValueError, the not-found cases change nothing. Here a
not-found append (another org's, a colleague's, a trashed or an unknown chat)
still raises ``ChatNotFoundError`` and stores nothing, and the caller's next
append to their own chat returns its own last id.

Runs the real repository against tests/db_fakes.py's ``FakeDb`` (its
``chat_messages`` rows carry the generated ``id``; ``INSERT ... RETURNING id``
is supported). ``admino.chats`` is imported per test.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino.access import Principal
from admino.models import LLMMessage, ToolCallRecord
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, plain

if TYPE_CHECKING:
    from types import ModuleType

_STATUSES: Final = ("complete", "stopped", "error", "awaiting_confirmation", "limit_reached")
_NOT_FOUND_CASES: Final = ("other-org", "other-user", "trashed", "unknown")
_UNKNOWN_CHAT: Final = uuid.UUID("7c9e6679-7425-40de-944b-e07fc1f90ae7")
_PAST: Final = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)


@pytest.fixture()
def chats() -> ModuleType:
    """admino.chats, imported per test."""
    from admino import chats as module

    return module


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


def _tenant(db: FakeDb, *, org_id: uuid.UUID = ORG_ID) -> tuple[uuid.UUID, TenantContext]:
    user_id = db.add_account(org_id=org_id, role="editor")
    principal = Principal(user_id=user_id, kind="member", org_id=org_id, role="editor")
    return user_id, TenantContext.from_principal(principal)


def _turn(count: int) -> list[LLMMessage]:
    """``count`` == 1: a lone user message; otherwise a tool turn of four messages."""
    if count == 1:
        return [LLMMessage(role="user", content="Stop right after this")]
    return [
        LLMMessage(role="user", content="Find the invoice"),
        LLMMessage(
            role="assistant",
            content="",
            tool_use_blocks=[
                {"type": "tool_use", "id": "call_1", "name": "gmail.search", "input": {"q": "x"}}
            ],
        ),
        LLMMessage(role="tool", content="1 result", tool_call_id="call_1"),
        LLMMessage(role="assistant", content="I found one invoice, and"),
    ]


def _record() -> ToolCallRecord:
    return ToolCallRecord(
        tool="gmail",
        action="search",
        args={"q": "x"},
        permission="allow",
        success=True,
        duration_ms=7,
    )


def _as_uuid(value: Any) -> uuid.UUID:
    assert isinstance(value, uuid.UUID), type(value)
    return plain(value)


class TestAppendReturnsLastId:
    """The id of the turn's last stored message, as a UUID."""

    @pytest.mark.parametrize("count", [1, 4], ids=["one-message", "several-messages"])
    @pytest.mark.parametrize("status", _STATUSES)
    async def test_chats_append_returns_the_id_of_the_last_stored_message(
        self, chats: ModuleType, db: FakeDb, status: str, count: int
    ) -> None:
        """The chat already holds a message: the id is the new last row's, not it."""
        user_id, tenant = _tenant(db)
        chat_id = db.add_chat(user_id, created_at=_PAST)
        earlier = db.add_chat_message(chat_id, "user", "An earlier question")

        result = await chats.append_messages(
            db.pool, tenant, chat_id, _turn(count), final_status=status, tool_calls=[_record()]
        )

        rows = db.messages_of(chat_id)
        assert len(rows) == 1 + count
        assert _as_uuid(result) == plain(rows[-1]["id"])
        assert (rows[-1]["status"], _as_uuid(result) != plain(earlier)) == (status, True)

    async def test_chats_append_returns_each_turns_own_last_id(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """A stopped turn, then a complete one: two ids, each the last row at its time."""
        user_id, tenant = _tenant(db)
        chat_id = db.add_chat(user_id, created_at=_PAST)

        first = await chats.append_messages(
            db.pool, tenant, chat_id, _turn(4), final_status="stopped"
        )
        first_rows = db.messages_of(chat_id)
        second = await chats.append_messages(db.pool, tenant, chat_id, _turn(1))
        rows = db.messages_of(chat_id)

        assert (_as_uuid(first), _as_uuid(second)) == (
            plain(first_rows[-1]["id"]),
            plain(rows[-1]["id"]),
        )
        assert [row["status"] for row in rows] == [
            "complete",
            "complete",
            "complete",
            "stopped",
            "complete",
        ]
        assert plain(rows[3]["id"]) == _as_uuid(first)

    @pytest.mark.parametrize("case", _NOT_FOUND_CASES)
    async def test_chats_append_not_found_still_raises_and_the_next_own_append_returns_its_id(
        self, chats: ModuleType, db: FakeDb, case: str
    ) -> None:
        """Nothing stored for the refused chat; the caller's own chat gets its own id."""
        alice_id, alice = _tenant(db)
        bob_id, _ = _tenant(db)
        carol_id, _ = _tenant(db, org_id=OTHER_ORG_ID)
        own = db.add_chat(alice_id, created_at=_PAST)
        target = {
            "other-org": db.add_chat(carol_id, created_at=_PAST),
            "other-user": db.add_chat(bob_id, created_at=_PAST),
            "trashed": db.add_chat(
                alice_id, created_at=_PAST, deleted_at=_PAST + timedelta(days=1)
            ),
            "unknown": _UNKNOWN_CHAT,
        }[case]
        before = db.snapshot()

        with pytest.raises(chats.ChatNotFoundError):
            await chats.append_messages(db.pool, alice, target, _turn(4), final_status="stopped")
        unchanged = db.snapshot() == before
        result = await chats.append_messages(db.pool, alice, own, _turn(1))

        assert unchanged
        assert _as_uuid(result) == plain(db.messages_of(own)[-1]["id"])
