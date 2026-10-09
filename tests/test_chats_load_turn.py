"""Tests for admino.chats.load_turn: a chat and its latest messages in one statement (GH-244).

Contract C3 T2: ``chats.load_turn(executor, tenant, chat_id, *, limit)`` reads
the caller's live chat and its latest ``limit`` messages with ONE statement
(the send path's third and last query before the LLM call, run under the
chat's run lock), replacing ``chats.get_chat`` plus the message read (GH-190:
``chats.load_recent_history`` is gone, tests/test_chats_context.py). It runs
against tests/db_fakes.py, which evaluates the contract's T2 statement (``LEFT
JOIN LATERAL`` over chat_messages, ``ORDER BY seq DESC LIMIT``) as PostgreSQL does.

What these tests pin down:
- Surface: ``ChatTurn`` is a frozen dataclass of exactly ``chat``,
  ``history`` and (GH-189, Decision 13, contract C4) ``attachments``; ``limit``
  is keyword-only. The attachments themselves are
  tests/test_chats_turn_attachments.py's.
- One statement: a fetch SELECT naming chats and chat_messages, bound to
  ``(chat_id, tenant.org_id, tenant.user_id, limit)`` in that order, whether
  the chat is found or not ("nothing else read"); it writes nothing and opens
  no transaction.
- The window (the spec): ``chat`` equals ``chats.get_chat`` and ``history`` is
  the literal expectation of each case (GH-190: ``load_recent_history``, the
  former oracle, is removed): a limit below, equal to
  and above the message count; an empty chat (``history == []``); windows that
  start with one or two tool results (dropped) or with the assistant turn that
  called them (kept, its ``tool_use_blocks`` decoded); a window of tool
  results only (``[]``); tool results keep their ``tool_call_id``;
  ``external_content`` true and false; user- and auto-titled chats.
- Tenant isolation (§5): a colleague's chat, another org's chat (with the
  caller's tenant and with a forged tenant org), a trashed and an unknown chat
  raise ``ChatNotFoundError`` (the same error ``get_chat`` raises, no id or
  title in it) after that one statement, and nothing is written.
- No leak between chats: two chats of the same user with interleaved messages
  each get only their own messages, chronological, the window counted per chat.
- No content in logs: the title and message canaries reach no log line.

``chats.load_turn`` and ``chats.ChatTurn`` are looked up when a test runs, so
this file collects before they exist and every test fails on its own.
"""

from __future__ import annotations

import dataclasses
import inspect
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import chats as chats_module
from admino.models import LLMMessage
from admino.tenancy import TenantContext
from tests.db_fakes import FakeDb
from tests.log_capture import configured_logging
from tests.tenancy_world import World, build_world, seed_chat

if TYPE_CHECKING:
    from types import ModuleType

    from tests.db_fakes import Call

TITLE_CANARY: Final = "TITLE-CANARY-4e7b board meeting notes"
MESSAGE_CANARY: Final = "MESSAGE-CANARY-a1c9 the salary of Mr. Muster is 9000"
TOOL_CANARY: Final = "TOOL-CANARY-58fd calendar: dentist at 9:00"
UNKNOWN_CHAT: Final = uuid.UUID("7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f")

# The tool-heavy chat, chronological: a user turn, the assistant's two tool
# calls, their two results, the answer, a follow-up and its answer.
CALENDAR_CALL: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "call_cal_1",
    "name": "google_calendar.list",
    "input": {"days": 7, "zone": "Zürich", "filters": {"busy": True, "tags": ["a", "b"]}},
}
MEMORY_CALL: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "call_mem_2",
    "name": "memory.list",
    "input": {},
}
TOOL_CHAT: Final[tuple[dict[str, Any], ...]] = (
    {"role": "user", "content": MESSAGE_CANARY},
    {
        "role": "assistant",
        "content": "Let me check.",
        "tool_use_blocks": [CALENDAR_CALL, MEMORY_CALL],
    },
    {"role": "tool", "content": TOOL_CANARY, "tool_call_id": "call_cal_1"},
    {"role": "tool", "content": "no notes", "tool_call_id": "call_mem_2"},
    {"role": "assistant", "content": "You see the dentist on Monday."},
    {"role": "user", "content": "Thanks!"},
    {"role": "assistant", "content": "You're welcome."},
)
# A chat whose latest messages are tool results only.
TOOL_TAIL_CHAT: Final[tuple[dict[str, Any], ...]] = (
    {"role": "user", "content": "What's on?"},
    {"role": "assistant", "content": "Checking.", "tool_use_blocks": [CALENDAR_CALL, MEMORY_CALL]},
    {"role": "tool", "content": "busy", "tool_call_id": "call_cal_1"},
    {"role": "tool", "content": "nothing", "tool_call_id": "call_mem_2"},
)
PLAIN_COUNT: Final = 6


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def chats() -> ModuleType:
    """admino.chats (its new names are looked up when a test runs)."""
    return chats_module


@dataclass(frozen=True)
class _Seeded:
    """The world and every chat a test may ask for (ids)."""

    world: World
    plain: uuid.UUID  # org A editor: auto-titled, 6 user/assistant messages
    tooly: uuid.UUID  # org A editor: user-titled, external content, TOOL_CHAT
    tool_tail: uuid.UUID  # org A editor: TOOL_TAIL_CHAT
    empty: uuid.UUID  # org A editor: no messages
    colleague: uuid.UUID  # org A viewer's live chat
    other_org: uuid.UUID  # org B editor's live chat
    trashed: uuid.UUID  # org A editor's trashed chat (with messages)

    @property
    def db(self) -> FakeDb:
        return self.world.db

    @property
    def editor(self) -> TenantContext:
        """The org A editor's own tenant."""
        return _tenant(self.world.org_a, self.world.a["editor"].user_id)


def _tenant(org_id: uuid.UUID, user_id: uuid.UUID) -> TenantContext:
    return TenantContext(org_id=org_id, user_id=user_id, role="editor")


def _add_messages(db: FakeDb, chat_id: uuid.UUID, messages: tuple[dict[str, Any], ...]) -> None:
    for message in messages:
        db.add_chat_message(
            chat_id,
            message["role"],
            message["content"],
            tool_use_blocks=message.get("tool_use_blocks"),
            tool_call_id=message.get("tool_call_id"),
        )


@pytest.fixture()
def seeded() -> _Seeded:
    db = FakeDb()
    world = build_world(db)
    editor = world.a["editor"].user_id
    plain = seed_chat(
        db,
        editor,
        messages=[
            ("user" if index % 2 == 0 else "assistant", f"plain {index}")
            for index in range(PLAIN_COUNT)
        ],
    )
    tooly = seed_chat(db, editor, title=TITLE_CANARY, external_content=True)
    _add_messages(db, tooly, TOOL_CHAT)
    tool_tail = seed_chat(db, editor, title="Tool tail")
    _add_messages(db, tool_tail, TOOL_TAIL_CHAT)
    empty = seed_chat(db, editor)
    colleague = seed_chat(
        db, world.a["viewer"], title=TITLE_CANARY, messages=[("user", MESSAGE_CANARY)]
    )
    other_org = seed_chat(
        db, world.b["editor"], title=TITLE_CANARY, messages=[("user", MESSAGE_CANARY)]
    )
    trashed = db.add_chat(editor, title=TITLE_CANARY, deleted_at=datetime.now(UTC))
    db.add_chat_message(trashed, "user", MESSAGE_CANARY)
    return _Seeded(world, plain, tooly, tool_tail, empty, colleague, other_org, trashed)


def _same_uuid(left: object, right: uuid.UUID) -> bool:
    """A bind argument equal to a UUID (a plain or an asyncpg UUID)."""
    return isinstance(left, uuid.UUID) and uuid.UUID(int=left.int) == right


async def _load(
    chats: ModuleType, db: FakeDb, tenant: TenantContext, chat_id: uuid.UUID, limit: int
) -> tuple[Any, list[Call]]:
    """Run load_turn on the pool; return its result and the statements it ran."""
    before = len(db.calls)
    turn = await chats.load_turn(db.pool, tenant, chat_id, limit=limit)
    return turn, db.calls[before:]


def _messages(*specs: dict[str, Any]) -> list[LLMMessage]:
    """The LLMMessages the history must hold for these seeded messages."""
    return [
        LLMMessage(
            role=spec["role"],
            content=spec["content"],
            tool_call_id=spec.get("tool_call_id"),
            tool_use_blocks=spec.get("tool_use_blocks"),
        )
        for spec in specs
    ]


def _plain(start: int) -> list[LLMMessage]:
    """The plain chat's messages from ``start`` to the end."""
    return _messages(
        *(
            {"role": "user" if index % 2 == 0 else "assistant", "content": f"plain {index}"}
            for index in range(start, PLAIN_COUNT)
        )
    )


# (chat attribute, limit) -> the literal history.
_CASES: Final[dict[str, tuple[str, int, list[LLMMessage]]]] = {
    "limit-below-count": ("plain", 3, _plain(3)),
    "limit-equal-count": ("plain", PLAIN_COUNT, _plain(0)),
    "limit-above-count": ("plain", 50, _plain(0)),
    "empty-chat": ("empty", 20, []),
    "window-starts-with-two-tool-results": ("tooly", 5, _messages(*TOOL_CHAT[4:])),
    "window-starts-with-one-tool-result": ("tooly", 4, _messages(*TOOL_CHAT[4:])),
    "window-starts-with-the-tool-calling-turn": ("tooly", 6, _messages(*TOOL_CHAT[1:])),
    "whole-tool-chat": ("tooly", 50, _messages(*TOOL_CHAT)),
    "window-of-tool-results-only": ("tool_tail", 2, []),
    "tool-tail-whole-chat": ("tool_tail", 4, _messages(*TOOL_TAIL_CHAT)),
}


# ---------------------------------------------------------------------------
# 1. Surface
# ---------------------------------------------------------------------------


def test_chats_load_turn_result_is_a_frozen_dataclass_of_chat_history_and_attachments(
    chats: ModuleType,
) -> None:
    """GH-189 (Decision 13): the turn read also carries the chat's active attachments."""
    cls = chats.ChatTurn

    assert dataclasses.is_dataclass(cls)
    assert {field.name for field in dataclasses.fields(cls)} == {"chat", "history", "attachments"}
    assert cls.__dataclass_params__.frozen is True


def test_chats_load_turn_limit_is_keyword_only(chats: ModuleType) -> None:
    parameters = inspect.signature(chats.load_turn).parameters

    # GH-245 (contract C2): a retry's window ends before the retried message (before_seq).
    assert list(parameters) == ["executor", "tenant", "chat_id", "limit", "before_seq"]
    assert parameters["limit"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["before_seq"].kind is inspect.Parameter.KEYWORD_ONLY


# ---------------------------------------------------------------------------
# 2. One statement, bound to the chat, the tenant and the limit, no writes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("chat", "limit"), [("plain", 3), ("empty", 20), ("tooly", 50), ("colleague", 20)]
)
async def test_chats_load_turn_runs_exactly_one_select_over_chats_and_messages(
    chats: ModuleType, seeded: _Seeded, chat: str, limit: int
) -> None:
    """One statement for a found chat and for a refused one ("nothing else read")."""
    chat_id = getattr(seeded, chat)
    before = len(seeded.db.calls)

    try:
        await chats.load_turn(seeded.db.pool, seeded.editor, chat_id, limit=limit)
    except chats.ChatNotFoundError:
        assert chat == "colleague"

    calls = seeded.db.calls[before:]
    assert len(calls) == 1, [call.normalized for call in calls]
    call = calls[0]
    assert call.method == "fetch"
    assert call.normalized.startswith("select ")
    assert re.search(r"\bchats\b", call.normalized)
    assert re.search(r"\bchat_messages\b", call.normalized)


@pytest.mark.parametrize(("chat", "limit"), [("plain", 3), ("tooly", 50), ("other_org", 7)])
async def test_chats_load_turn_binds_chat_org_owner_and_limit_in_that_order(
    chats: ModuleType, seeded: _Seeded, chat: str, limit: int
) -> None:
    chat_id = getattr(seeded, chat)
    before = len(seeded.db.calls)

    try:
        await chats.load_turn(seeded.db.pool, seeded.editor, chat_id, limit=limit)
    except chats.ChatNotFoundError:
        assert chat == "other_org"

    calls = seeded.db.calls[before:]
    assert len(calls) == 1
    args = calls[0].args
    assert len(args) == 4, args
    assert _same_uuid(args[0], chat_id)
    assert _same_uuid(args[1], seeded.editor.org_id)
    assert _same_uuid(args[2], seeded.editor.user_id)
    assert type(args[3]) is int
    assert args[3] == limit


async def test_chats_load_turn_writes_nothing(chats: ModuleType, seeded: _Seeded) -> None:
    db = seeded.db
    before = db.snapshot()
    transactions = list(db.transactions)

    _, calls = await _load(chats, db, seeded.editor, seeded.tooly, 50)

    assert all(call.normalized.startswith("select ") for call in calls)
    assert db.snapshot() == before
    assert db.transactions == transactions
    assert db.open_transactions == 0


# ---------------------------------------------------------------------------
# 3. Equivalence with get_chat + load_recent_history, case by case
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", list(_CASES))
async def test_chats_load_turn_history_is_the_latest_window(
    chats: ModuleType, seeded: _Seeded, case: str
) -> None:
    """GH-190: the literal expectation only (``load_recent_history`` is removed)."""
    attribute, limit, expected = _CASES[case]
    chat_id = getattr(seeded, attribute)

    turn, _ = await _load(chats, seeded.db, seeded.editor, chat_id, limit)

    assert turn.history == expected
    assert type(turn.history) is list
    assert all(type(message) is LLMMessage for message in turn.history)


@pytest.mark.parametrize("chat", ["plain", "tooly", "tool_tail", "empty"])
async def test_chats_load_turn_chat_equals_get_chat(
    chats: ModuleType, seeded: _Seeded, chat: str
) -> None:
    chat_id = getattr(seeded, chat)

    turn, _ = await _load(chats, seeded.db, seeded.editor, chat_id, 3)

    assert turn.chat == await chats.get_chat(seeded.db.pool, seeded.editor, chat_id)
    assert isinstance(turn.chat, chats.ChatRecord)


async def test_chats_load_turn_chat_carries_title_source_and_external_content(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """A user-titled chat with external content and an auto-titled one without."""
    tooly, _ = await _load(chats, seeded.db, seeded.editor, seeded.tooly, 3)
    plain, _ = await _load(chats, seeded.db, seeded.editor, seeded.plain, 3)

    assert (tooly.chat.title, tooly.chat.title_source, tooly.chat.external_content) == (
        TITLE_CANARY,
        "user",
        True,
    )
    assert (plain.chat.title, plain.chat.title_source, plain.chat.external_content) == (
        "",
        "auto",
        False,
    )
    assert tooly.chat.external_content is True
    assert plain.chat.external_content is False
    assert (tooly.chat.id, tooly.chat.org_id, tooly.chat.owner_user_id) == (
        seeded.tooly,
        seeded.editor.org_id,
        seeded.editor.user_id,
    )


async def test_chats_load_turn_decodes_tool_use_blocks_and_keeps_tool_call_ids(
    chats: ModuleType, seeded: _Seeded
) -> None:
    turn, _ = await _load(chats, seeded.db, seeded.editor, seeded.tooly, 6)

    calling, calendar, memory = turn.history[:3]
    assert calling.tool_use_blocks == [CALENDAR_CALL, MEMORY_CALL]
    assert (calendar.role, calendar.tool_call_id, calendar.content) == (
        "tool",
        "call_cal_1",
        TOOL_CANARY,
    )
    assert (memory.role, memory.tool_call_id) == ("tool", "call_mem_2")
    assert all(message.tool_use_blocks is None for message in turn.history[1:])


# ---------------------------------------------------------------------------
# 4. Not found: one error for every chat the caller doesn't own live
# ---------------------------------------------------------------------------


def _refused(seeded: _Seeded, case: str) -> tuple[TenantContext, uuid.UUID]:
    world = seeded.world
    editor = world.a["editor"].user_id
    return {
        "colleague-chat": (seeded.editor, seeded.colleague),
        "other-org-chat": (seeded.editor, seeded.other_org),
        "forged-org-own-chat": (_tenant(world.org_b, editor), seeded.plain),
        "forged-org-other-org-chat": (_tenant(world.org_b, editor), seeded.other_org),
        "trashed-own-chat": (seeded.editor, seeded.trashed),
        "unknown-chat": (seeded.editor, UNKNOWN_CHAT),
    }[case]


_REFUSED_CASES: Final = (
    "colleague-chat",
    "other-org-chat",
    "forged-org-own-chat",
    "forged-org-other-org-chat",
    "trashed-own-chat",
    "unknown-chat",
)


@pytest.mark.parametrize("case", _REFUSED_CASES)
async def test_chats_load_turn_refuses_any_chat_but_the_callers_own_live_one(
    chats: ModuleType, seeded: _Seeded, case: str
) -> None:
    tenant, chat_id = _refused(seeded, case)
    db = seeded.db
    before = db.snapshot()
    calls_before = len(db.calls)

    with pytest.raises(chats.ChatNotFoundError) as caught:
        await chats.load_turn(db.pool, tenant, chat_id, limit=20)

    assert type(caught.value) is chats.ChatNotFoundError
    assert str(caught.value) == str(chats.ChatNotFoundError())
    assert len(db.calls) - calls_before == 1
    assert db.snapshot() == before
    with pytest.raises(chats.ChatNotFoundError):
        await chats.get_chat(db.pool, tenant, chat_id)


# ---------------------------------------------------------------------------
# 5. No leak between chats
# ---------------------------------------------------------------------------


@pytest.fixture()
def interleaved(seeded: _Seeded) -> tuple[uuid.UUID, uuid.UUID]:
    """Two chats of the org A editor whose messages were stored alternately (seq interleaved)."""
    db = seeded.db
    editor = seeded.world.a["editor"].user_id
    first = seed_chat(db, editor, title="First")
    second = seed_chat(db, editor, title="Second")
    for index in range(5):
        role = "user" if index % 2 == 0 else "assistant"
        db.add_chat_message(first, role, f"first {index}")
        db.add_chat_message(second, role, f"second {index}")
    return first, second


@pytest.mark.parametrize(("limit", "start"), [(3, 2), (50, 0)])
async def test_chats_load_turn_never_mixes_in_another_chats_messages(
    chats: ModuleType,
    seeded: _Seeded,
    interleaved: tuple[uuid.UUID, uuid.UUID],
    limit: int,
    start: int,
) -> None:
    """The window is counted per chat: chat 1's latest messages, never chat 2's newer ones."""
    first, second = interleaved

    turn_first, _ = await _load(chats, seeded.db, seeded.editor, first, limit)
    turn_second, _ = await _load(chats, seeded.db, seeded.editor, second, limit)

    assert [message.content for message in turn_first.history] == [
        f"first {index}" for index in range(start, 5)
    ]
    assert [message.content for message in turn_second.history] == [
        f"second {index}" for index in range(start, 5)
    ]


# ---------------------------------------------------------------------------
# 6. No content in logs
# ---------------------------------------------------------------------------


async def test_chats_load_turn_logs_no_content(chats: ModuleType, seeded: _Seeded) -> None:
    """The title, message and tool-output canaries reach no log line (DEBUG, text)."""
    with configured_logging("DEBUG", "text") as logs:
        await chats.load_turn(seeded.db.pool, seeded.editor, seeded.tooly, limit=50)
        for case in _REFUSED_CASES:
            tenant, chat_id = _refused(seeded, case)
            with pytest.raises(chats.ChatNotFoundError):
                await chats.load_turn(seeded.db.pool, tenant, chat_id, limit=20)
        logged = logs.text + "\n".join(record.getMessage() for record in logs.records)

    canaries = (TITLE_CANARY, MESSAGE_CANARY, TOOL_CANARY)
    assert [canary for canary in canaries if canary in logged] == []
