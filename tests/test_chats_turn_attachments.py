"""Tests for admino.chats: a turn's active attachments and the ids its answers include (GH-189).

Issue #189, Decisions 3, 9, 11 and 13; contract C4. ``chats.load_turn`` (T2')
still reads the caller's chat and its latest messages with ONE statement, and
that statement now also returns the chat's active attachments: sent with one of
its user messages, live, ``ready``, in the order they were sent (Decision 3 as
amended: by the carrying message, oldest first, then within one message by
``created_at``, then ``id``). ``chats.append_messages`` stores the slot's ids on every assistant
message of a run with attachments (S8', migration 0029's
``included_attachment_ids``) and sets the chat's sticky ``external_content``
flag when asked (S7's external form). Everything runs against tests/db_fakes.py,
which evaluates T2', S8' and the column's CHECK as PostgreSQL does.

What these tests pin down:
- Surface: ``ChatTurn`` is a frozen dataclass of exactly ``chat``, ``history``
  and ``attachments``; ``ActiveAttachment`` is a frozen, sealed model of exactly
  ``id``, ``filename``, ``kind``, ``page_count`` and (GH-190, contract C5)
  ``token_estimate`` and ``derived_bytes``, both None by default (an unknown
  kind refused). T2'' itself (the estimates, excluded files, the exact form) is
  tests/test_chats_context.py's.
- Included: the chat's sent, live, ready files in send order: the files of the
  older message first, whenever they were uploaded (a file uploaded before
  every other one but sent with the later message comes last); within one
  message ``created_at`` then ``id`` (two files uploaded at the same instant
  sort by id). Each with its stored name (commas, quotes and braces kept),
  kind and page count (0 stays 0, NULL is None), as a tuple; independent of
  the message window.
- Excluded: an unsent file; a trashed, an ``uploaded``, a ``processing`` and a
  ``failed`` one sent with a message; the caller's other chat's file; a
  colleague's and another org's (tenant isolation, §5). A chat without active
  files gets ``()``.
- One statement: still a single fetch, bound to (chat, org, owner, limit) in
  that order, naming chats, chat_messages and attachments.
- ``append_messages(..., included_attachment_ids=ids)``: every assistant
  message is inserted with S8' (``$9`` the ids in the given order) and gets
  them; every user and tool message is inserted with S8 and stays NULL; a turn
  without an assistant message stores none; the last message id is still
  returned; the files the user message carries are still linked (A9).
  Empty ids (``()``, ``[]``): exactly today's statements, every row NULL.
- ``external_content=True`` runs S7's external form and sets the chat's flag;
  ``False`` leaves it as it was.
- A message whose content is a list of content parts is a ``ValueError``
  before any statement: content parts are never stored (Decision 1).
- No content in logs: file-name, message and title canaries reach no log line.

``chats.ActiveAttachment``, ``ChatTurn.attachments``, the new keywords and
``models.TextContent`` / ``models.ImageContent`` are looked up when a test
runs, so this file collects before they exist and every test fails on its own.
"""

from __future__ import annotations

import dataclasses
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pydantic
import pytest

from admino import chats as chats_module
from admino import models
from admino.models import LLMMessage
from admino.tenancy import TenantContext
from tests.db_fakes import FakeDb
from tests.log_capture import configured_logging
from tests.tenancy_world import World, build_world, seed_chat

if TYPE_CHECKING:
    from types import ModuleType

    from tests.db_fakes import Call

TITLE_CANARY: Final = "TITLE-CANARY-189t board plans"
MESSAGE_CANARY: Final = "MESSAGE-CANARY-189m the salary of Mr. Muster is 9000"
ANSWER_CANARY: Final = "ANSWER-CANARY-189a page 2 says the budget is 4 million"
FILE_CANARY: Final = 'FILE-CANARY-189f Q3, "final" {v2}.pdf'
SCAN_CANARY: Final = "SCAN-CANARY-189s passport scan.png"
HIDDEN_CANARY: Final = "HIDDEN-CANARY-189h unsent draft.pdf"
FOREIGN_CANARY: Final = "FOREIGN-CANARY-189x colleague contract.pdf"

_T0: Final = datetime(2026, 10, 1, 9, 0, 0, 125000, tzinfo=UTC)
_T1: Final = _T0 + timedelta(seconds=1)
_T2: Final = _T0 + timedelta(seconds=2)

# The active files of the main chat (Decision 3 as amended: the order they were
# sent in). The first user message carries FIRST (uploaded T1), then TIE_LOW and
# TIE_HIGH (both T2, so the id decides). The second user message carries
# SENT_LATER, uploaded at T0, before every other file: it still comes last.
# Their ids sort neither way (11.. < 91.. < a1.. < f1..), and they are stored in
# none of these orders, so neither upload order (``created_at, id``), nor
# ``ORDER BY id``, nor the message then id, nor the table's own order passes.
FIRST: Final = uuid.UUID("f1890000-0000-4000-8000-000000000001")
SENT_LATER: Final = uuid.UUID("a1890000-0000-4000-8000-000000000002")
TIE_LOW: Final = uuid.UUID("11890000-0000-4000-8000-000000000003")
TIE_HIGH: Final = uuid.UUID("91890000-0000-4000-8000-000000000004")
FIRST_MESSAGE_FILES: Final = (FIRST, TIE_LOW, TIE_HIGH)
SLOT_ORDER: Final = (*FIRST_MESSAGE_FILES, SENT_LATER)

# Whitespace-free comparison of the contract's statement forms (tokens kept).
_S7: Final = (
    "UPDATE chats SET last_activity_at = now() WHERE id = $1 AND org_id = $2 "
    "AND owner_user_id = $3 AND deleted_at IS NULL RETURNING id"
)
_S7_EXTERNAL: Final = (
    "UPDATE chats SET last_activity_at = now(), external_content = true WHERE id = $1 "
    "AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL RETURNING id"
)
_S8: Final = (
    "INSERT INTO chat_messages (chat_id, org_id, role, content, tool_use_blocks, "
    "tool_call_id, tool_calls, status) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8) "
    "RETURNING id"
)
_S8_INCLUDED: Final = (
    "INSERT INTO chat_messages (chat_id, org_id, role, content, tool_use_blocks, "
    "tool_call_id, tool_calls, status, included_attachment_ids) VALUES ($1, $2, $3, $4, "
    "$5::jsonb, $6, $7::jsonb, $8, $9::uuid[]) RETURNING id"
)


def _canon(sql: str) -> str:
    """Lowercased, whitespace collapsed and dropped around ( ) , = (tokens kept)."""
    text = re.sub(r"\s+", " ", sql.strip().lower()).rstrip(";").strip()
    return re.sub(r"\s*([(),=\[\]])\s*", r"\1", text)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def chats() -> ModuleType:
    """admino.chats (its new names are looked up when a test runs)."""
    return chats_module


@dataclass(frozen=True)
class _Seeded:
    """The world, the editor's chats and every file a test may ask for (ids)."""

    world: World
    chat: uuid.UUID  # the editor's chat with active and inactive files
    first_message: uuid.UUID  # its first user message (carried FIRST, TIE_LOW, TIE_HIGH)
    other_chat: uuid.UUID  # the editor's second chat, one active file
    other_chat_file: uuid.UUID
    plain: uuid.UUID  # the editor's chat with messages and no files
    empty: uuid.UUID  # the editor's chat without messages
    pending_only: uuid.UUID  # the editor's chat whose files are all inactive
    excluded: dict[str, uuid.UUID]  # inactive or foreign files, by case

    @property
    def db(self) -> FakeDb:
        return self.world.db

    @property
    def editor(self) -> TenantContext:
        return TenantContext(
            org_id=self.world.org_a, user_id=self.world.a["editor"].user_id, role="editor"
        )


@pytest.fixture()
def seeded() -> _Seeded:
    db = FakeDb()
    world = build_world(db)
    editor = world.a["editor"].user_id
    chat = seed_chat(db, editor, title=TITLE_CANARY)
    first_message = db.add_chat_message(chat, "user", MESSAGE_CANARY)
    db.add_chat_message(chat, "assistant", ANSWER_CANARY)
    second_message = db.add_chat_message(chat, "user", "And the scan?")
    db.add_chat_message(chat, "assistant", "Here it is.")

    def add(chat_id: uuid.UUID, **values: Any) -> uuid.UUID:
        return db.add_attachment(chat_id, **values)

    # Stored out of slot order on purpose (see SLOT_ORDER).
    add(chat, attachment_id=TIE_HIGH, filename="data.csv", kind="csv", status="ready",
        message_id=first_message, created_at=_T2)  # fmt: skip
    add(chat, attachment_id=SENT_LATER, filename=SCAN_CANARY, kind="png", status="ready",
        message_id=second_message, created_at=_T0)  # fmt: skip
    add(chat, attachment_id=FIRST, filename=FILE_CANARY, kind="pdf", status="ready",
        page_count=3, message_id=first_message, created_at=_T1)  # fmt: skip
    add(chat, attachment_id=TIE_LOW, filename="notes.docx", kind="docx", status="ready",
        page_count=0, message_id=first_message, created_at=_T2)  # fmt: skip

    other_chat = seed_chat(db, editor, title="Other")
    other_message = db.add_chat_message(other_chat, "user", "Another file")
    other_chat_file = add(other_chat, filename=FOREIGN_CANARY, status="ready",
                          message_id=other_message, created_at=_T0)  # fmt: skip
    colleague_chat = seed_chat(db, world.a["viewer"], title=TITLE_CANARY)
    colleague_message = db.add_chat_message(colleague_chat, "user", MESSAGE_CANARY)
    other_org_chat = seed_chat(db, world.b["editor"], title=TITLE_CANARY)
    other_org_message = db.add_chat_message(other_org_chat, "user", MESSAGE_CANARY)
    excluded = {
        "unsent": add(chat, filename=HIDDEN_CANARY, status="ready", created_at=_T0),
        "trashed": add(
            chat,
            filename=HIDDEN_CANARY,
            status="ready",
            message_id=first_message,
            created_at=_T0,
            deleted_at=_T2,
        ),  # fmt: skip
        "uploaded": add(
            chat,
            filename=HIDDEN_CANARY,
            status="uploaded",
            message_id=first_message,
            created_at=_T0,
        ),  # fmt: skip
        "processing": add(
            chat,
            filename=HIDDEN_CANARY,
            status="processing",
            message_id=first_message,
            created_at=_T0,
        ),  # fmt: skip
        "failed": add(
            chat,
            filename=HIDDEN_CANARY,
            status="failed",
            failure_reason="corrupted_file",
            message_id=first_message,
            created_at=_T0,
        ),  # fmt: skip
        "other-chat": other_chat_file,
        "colleague": add(
            colleague_chat,
            filename=FOREIGN_CANARY,
            status="ready",
            message_id=colleague_message,
            created_at=_T0,
        ),  # fmt: skip
        "other-org": add(
            other_org_chat,
            filename=FOREIGN_CANARY,
            status="ready",
            message_id=other_org_message,
            created_at=_T0,
        ),  # fmt: skip
    }
    plain = seed_chat(db, editor, messages=[("user", "hello"), ("assistant", "hi")])
    empty = seed_chat(db, editor)
    pending_only = seed_chat(db, editor)
    pending_message = db.add_chat_message(pending_only, "user", "Files on the way")
    add(pending_only, filename=HIDDEN_CANARY, status="ready", created_at=_T0)
    add(pending_only, filename=HIDDEN_CANARY, status="processing", message_id=pending_message,
        created_at=_T0)  # fmt: skip
    return _Seeded(
        world=world,
        chat=chat,
        first_message=first_message,
        other_chat=other_chat,
        other_chat_file=other_chat_file,
        plain=plain,
        empty=empty,
        pending_only=pending_only,
        excluded=excluded,
    )


async def _load(chats: ModuleType, seeded: _Seeded, chat_id: uuid.UUID, limit: int = 50) -> Any:
    return await chats.load_turn(seeded.db.pool, seeded.editor, chat_id, limit=limit)


def _same_uuid(left: object, right: uuid.UUID) -> bool:
    """A bind argument equal to a UUID (a plain or an asyncpg UUID)."""
    return isinstance(left, uuid.UUID) and uuid.UUID(int=left.int) == right


def _tool_turn() -> list[LLMMessage]:
    """A user message, a tool call, its result and the answer (four stored rows)."""
    block = {"type": "tool_use", "id": "call_189", "name": "memory.list", "input": {}}
    return [
        LLMMessage(role="user", content=MESSAGE_CANARY),
        LLMMessage(role="assistant", content="", tool_use_blocks=[block]),
        LLMMessage(role="tool", content="no notes", tool_call_id="call_189"),
        LLMMessage(role="assistant", content=ANSWER_CANARY),
    ]


def _new_rows(db: FakeDb, chat_id: uuid.UUID, before: int) -> list[dict[str, Any]]:
    """The chat's messages stored after the first ``before`` ones."""
    return db.messages_of(chat_id)[before:]


def _inserts(calls: list[Call]) -> list[Call]:
    return [call for call in calls if call.normalized.startswith("insert into chat_messages")]


# ---------------------------------------------------------------------------
# 1. Surface
# ---------------------------------------------------------------------------


def test_chats_turn_attachments_chat_turn_is_a_frozen_dataclass_of_three_fields(
    chats: ModuleType,
) -> None:
    cls = chats.ChatTurn

    assert dataclasses.is_dataclass(cls)
    assert {field.name for field in dataclasses.fields(cls)} == {"chat", "history", "attachments"}
    assert cls.__dataclass_params__.frozen is True


def test_chats_turn_attachments_active_attachment_has_exactly_the_slot_fields(
    chats: ModuleType,
) -> None:
    """GH-190 (contract C5): the stored estimate and derived bytes join the slot's
    fields, None unless given (a NULL column)."""
    cls = chats.ActiveAttachment
    item = cls(id=FIRST, filename="a.pdf", kind="pdf", page_count=None)

    assert set(cls.model_fields) == {
        "id",
        "filename",
        "kind",
        "page_count",
        "token_estimate",
        "derived_bytes",
    }
    assert (item.token_estimate, item.derived_bytes) == (None, None)
    with pytest.raises(pydantic.ValidationError):
        item.filename = "b.pdf"
    with pytest.raises(pydantic.ValidationError):
        cls(id=FIRST, filename="a.pdf", kind="pdf", page_count=None, size_bytes=1)


def test_chats_turn_attachments_active_attachment_refuses_an_unknown_kind(
    chats: ModuleType,
) -> None:
    with pytest.raises(pydantic.ValidationError):
        chats.ActiveAttachment(id=FIRST, filename="a.exe", kind="exe", page_count=None)


# ---------------------------------------------------------------------------
# 2. Which attachments a turn includes, in which order
# ---------------------------------------------------------------------------


async def test_chats_turn_attachments_load_turn_returns_sent_live_ready_files_in_send_order(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """Decision 3 (amended): by the carrying message (oldest first), then within one
    message by ``created_at``, then ``id``."""
    turn = await _load(chats, seeded, seeded.chat)

    assert [item.id for item in turn.attachments] == list(SLOT_ORDER)


async def test_chats_turn_attachments_load_turn_file_uploaded_earlier_but_sent_later_comes_last(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """SENT_LATER was uploaded before every other file but sent with the second message:
    it comes after all of the first message's files, not first."""
    turn = await _load(chats, seeded, seeded.chat)

    ids = [item.id for item in turn.attachments]
    assert (set(ids[:3]), ids[3:]) == (set(FIRST_MESSAGE_FILES), [SENT_LATER])


async def test_chats_turn_attachments_load_turn_files_of_one_message_by_upload_time_then_id(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """Within the first message: FIRST (T1), then TIE_LOW before TIE_HIGH (both T2, the
    lower id first, though TIE_HIGH is stored first)."""
    turn = await _load(chats, seeded, seeded.chat)

    ids = [item.id for item in turn.attachments]
    assert [item for item in ids if item in FIRST_MESSAGE_FILES] == list(FIRST_MESSAGE_FILES)


async def test_chats_turn_attachments_load_turn_carries_name_kind_and_page_count(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """The stored name as it is, the kind, the page count (0 stays 0, NULL is None)."""
    turn = await _load(chats, seeded, seeded.chat)

    active = chats.ActiveAttachment
    assert type(turn.attachments) is tuple
    assert turn.attachments == (
        active(id=FIRST, filename=FILE_CANARY, kind="pdf", page_count=3),
        active(id=TIE_LOW, filename="notes.docx", kind="docx", page_count=0),
        active(id=TIE_HIGH, filename="data.csv", kind="csv", page_count=None),
        active(id=SENT_LATER, filename=SCAN_CANARY, kind="png", page_count=None),
    )
    assert all(type(item) is active for item in turn.attachments)
    assert all(type(item.id) is uuid.UUID for item in turn.attachments)
    assert [type(item.page_count) for item in turn.attachments] == [
        int,
        int,
        type(None),
        type(None),
    ]


@pytest.mark.parametrize(
    "case",
    [
        "unsent",
        "trashed",
        "uploaded",
        "processing",
        "failed",
        "other-chat",
        "colleague",
        "other-org",
    ],
)
async def test_chats_turn_attachments_load_turn_leaves_out_inactive_and_foreign_files(
    chats: ModuleType, seeded: _Seeded, case: str
) -> None:
    turn = await _load(chats, seeded, seeded.chat)

    ids = [item.id for item in turn.attachments]
    assert ids == list(SLOT_ORDER)
    assert seeded.excluded[case] not in ids


async def test_chats_turn_attachments_load_turn_files_do_not_depend_on_the_message_window(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """Files sent with messages outside the window still belong to the chat's slot."""
    turn = await _load(chats, seeded, seeded.chat, limit=1)

    assert len(turn.history) == 1
    assert [item.id for item in turn.attachments] == list(SLOT_ORDER)


@pytest.mark.parametrize("chat", ["plain", "empty", "pending_only"])
async def test_chats_turn_attachments_load_turn_chat_without_active_files_gets_empty_tuple(
    chats: ModuleType, seeded: _Seeded, chat: str
) -> None:
    turn = await _load(chats, seeded, getattr(seeded, chat))

    assert turn.attachments == ()
    assert type(turn.attachments) is tuple


async def test_chats_turn_attachments_load_turn_other_chat_gets_only_its_own_file(
    chats: ModuleType, seeded: _Seeded
) -> None:
    turn = await _load(chats, seeded, seeded.other_chat)

    assert [item.id for item in turn.attachments] == [seeded.other_chat_file]
    assert turn.attachments[0].filename == FOREIGN_CANARY


# ---------------------------------------------------------------------------
# 3. Still one statement, the same binds
# ---------------------------------------------------------------------------


async def test_chats_turn_attachments_load_turn_is_one_statement_with_the_same_binds(
    chats: ModuleType, seeded: _Seeded
) -> None:
    db = seeded.db
    before = len(db.calls)

    turn = await _load(chats, seeded, seeded.chat, limit=7)

    calls = db.calls[before:]
    assert len(turn.attachments) == len(SLOT_ORDER)
    assert len(calls) == 1, [call.normalized for call in calls]
    call = calls[0]
    assert call.method == "fetch"
    assert call.normalized.startswith("select ")
    for table in ("chats", "chat_messages", "attachments"):
        assert re.search(rf"\b{table}\b", call.normalized), table
    assert len(call.args) == 4, call.args
    assert _same_uuid(call.args[0], seeded.chat)
    assert _same_uuid(call.args[1], seeded.editor.org_id)
    assert _same_uuid(call.args[2], seeded.editor.user_id)
    assert (type(call.args[3]), call.args[3]) == (int, 7)


# ---------------------------------------------------------------------------
# 4. append_messages: included ids on assistant messages, the sticky flag
# ---------------------------------------------------------------------------


async def test_chats_turn_attachments_append_records_included_ids_on_every_answer(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """Every assistant message gets the ids in the given order; the others stay NULL."""
    db = seeded.db
    before = len(db.messages_of(seeded.chat))
    included = [TIE_HIGH, FIRST]

    last = await chats.append_messages(
        db.pool, seeded.editor, seeded.chat, _tool_turn(), included_attachment_ids=included
    )

    rows = _new_rows(db, seeded.chat, before)
    assert [(row["role"], row["included_attachment_ids"]) for row in rows] == [
        ("user", None),
        ("assistant", [TIE_HIGH, FIRST]),
        ("tool", None),
        ("assistant", [TIE_HIGH, FIRST]),
    ]
    assert last == rows[-1]["id"]


async def test_chats_turn_attachments_append_uses_s8_prime_for_assistant_messages_only(
    chats: ModuleType, seeded: _Seeded
) -> None:
    db = seeded.db
    before = len(db.calls)
    included = (SENT_LATER, FIRST, TIE_LOW)

    await chats.append_messages(
        db.pool, seeded.editor, seeded.chat, _tool_turn(), included_attachment_ids=included
    )

    inserts = _inserts(db.calls[before:])
    assert [_canon(call.sql) for call in inserts] == [
        _canon(_S8),
        _canon(_S8_INCLUDED),
        _canon(_S8),
        _canon(_S8_INCLUDED),
    ]
    for call in (inserts[1], inserts[3]):
        assert len(call.args) == 9
        assert [uuid.UUID(str(item)) for item in call.args[8]] == list(included)
    assert all(len(call.args) == 8 for call in (inserts[0], inserts[2]))


@pytest.mark.parametrize("empty", [(), []], ids=["tuple", "list"])
async def test_chats_turn_attachments_append_without_included_ids_runs_todays_statements(
    chats: ModuleType, seeded: _Seeded, empty: tuple[()] | list[uuid.UUID]
) -> None:
    db = seeded.db
    before_calls = len(db.calls)
    before_rows = len(db.messages_of(seeded.chat))

    await chats.append_messages(
        db.pool, seeded.editor, seeded.chat, _tool_turn(), included_attachment_ids=empty
    )

    assert [_canon(call.sql) for call in db.calls[before_calls:]] == [
        _canon(_S7),
        *[_canon(_S8)] * 4,
    ]
    rows = _new_rows(db, seeded.chat, before_rows)
    assert [row["included_attachment_ids"] for row in rows] == [None] * 4


async def test_chats_turn_attachments_append_turn_without_answer_stores_no_ids(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """A turn that stored only the user message (e.g. the run failed before an answer)."""
    db = seeded.db
    before_calls = len(db.calls)
    before_rows = len(db.messages_of(seeded.chat))

    await chats.append_messages(
        db.pool,
        seeded.editor,
        seeded.chat,
        [LLMMessage(role="user", content=MESSAGE_CANARY)],
        final_status="error",
        included_attachment_ids=[FIRST],
    )

    inserts = _inserts(db.calls[before_calls:])
    assert [_canon(call.sql) for call in inserts] == [_canon(_S8)]
    rows = _new_rows(db, seeded.chat, before_rows)
    assert [(row["role"], row["included_attachment_ids"]) for row in rows] == [("user", None)]


async def test_chats_turn_attachments_append_links_sent_files_and_records_them_on_the_answer(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """The real send: the message's new file is linked (A9) and the answer includes it."""
    db = seeded.db
    fresh = db.add_attachment(seeded.chat, filename="fresh.txt", kind="txt", status="ready")
    before = len(db.messages_of(seeded.chat))

    await chats.append_messages(
        db.pool,
        seeded.editor,
        seeded.chat,
        [
            LLMMessage(role="user", content=MESSAGE_CANARY),
            LLMMessage(role="assistant", content=ANSWER_CANARY),
        ],
        attachment_ids=[fresh],
        included_attachment_ids=[FIRST, fresh],
        external_content=True,
    )

    user_row, answer_row = _new_rows(db, seeded.chat, before)
    row = db.attachment_row(fresh)
    assert row is not None
    assert row["message_id"] == user_row["id"]
    assert user_row["included_attachment_ids"] is None
    assert answer_row["included_attachment_ids"] == [FIRST, fresh]
    chat_row = db.chat_row(seeded.chat)
    assert chat_row is not None
    assert chat_row["external_content"] is True


@pytest.mark.parametrize(("external", "touch"), [(True, _S7_EXTERNAL), (False, _S7)])
async def test_chats_turn_attachments_append_external_content_sets_the_sticky_flag(
    chats: ModuleType, seeded: _Seeded, external: bool, touch: str
) -> None:
    db = seeded.db
    chat_before = db.chat_row(seeded.chat)
    assert chat_before is not None
    assert chat_before["external_content"] is False
    before = len(db.calls)

    await chats.append_messages(
        db.pool,
        seeded.editor,
        seeded.chat,
        [
            LLMMessage(role="user", content="What does the file say?"),
            LLMMessage(role="assistant", content=ANSWER_CANARY),
        ],
        external_content=external,
    )

    calls = db.calls[before:]
    assert _canon(calls[0].sql) == _canon(touch)
    chat_after = db.chat_row(seeded.chat)
    assert chat_after is not None
    assert chat_after["external_content"] is external


def _parts_message() -> LLMMessage:
    """A user message holding content parts (the context of one LLM call only)."""
    text = models.TextContent(text=MESSAGE_CANARY)
    image = models.ImageContent(media_type="image/png", data="iVBORw0KGgo=")
    return LLMMessage(role="user", content=[text, image])


_LIST_TURNS: Final = {
    "parts-as-the-first-message": lambda: [
        _parts_message(),
        LLMMessage(role="assistant", content=ANSWER_CANARY),
    ],
    "parts-after-an-answer": lambda: [
        LLMMessage(role="user", content="hello"),
        LLMMessage(role="assistant", content=ANSWER_CANARY),
        _parts_message(),
    ],
}


@pytest.mark.parametrize("case", list(_LIST_TURNS))
async def test_chats_turn_attachments_append_refuses_content_parts_before_any_statement(
    chats: ModuleType, seeded: _Seeded, case: str
) -> None:
    db = seeded.db
    messages = _LIST_TURNS[case]()
    before_state = db.snapshot()
    before_calls = len(db.calls)

    # Any ValueError: its text isn't pinned (only that it carries no content).
    with pytest.raises(ValueError) as caught:
        await chats.append_messages(
            db.pool,
            seeded.editor,
            seeded.chat,
            messages,
            included_attachment_ids=[FIRST],
            external_content=True,
        )

    assert not isinstance(caught.value, pydantic.ValidationError)
    assert MESSAGE_CANARY not in str(caught.value)
    assert db.calls[before_calls:] == []
    assert db.snapshot() == before_state


# ---------------------------------------------------------------------------
# 5. No content in logs
# ---------------------------------------------------------------------------


async def test_chats_turn_attachments_log_no_names_or_content(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """File names, message and answer texts and the title reach no log line (DEBUG)."""
    db = seeded.db
    with configured_logging("DEBUG", "text") as logs:
        await _load(chats, seeded, seeded.chat)
        await chats.append_messages(
            db.pool,
            seeded.editor,
            seeded.chat,
            _tool_turn(),
            included_attachment_ids=list(SLOT_ORDER),
            external_content=True,
        )
        with pytest.raises(ValueError):
            await chats.append_messages(db.pool, seeded.editor, seeded.chat, [_parts_message()])
        logged = logs.text + "\n".join(record.getMessage() for record in logs.records)

    canaries = (
        TITLE_CANARY,
        MESSAGE_CANARY,
        ANSWER_CANARY,
        FILE_CANARY,
        SCAN_CANARY,
        HIDDEN_CANARY,
        FOREIGN_CANARY,
    )
    assert [canary for canary in canaries if canary in logged] == []
