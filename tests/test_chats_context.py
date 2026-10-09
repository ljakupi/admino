"""Tests for admino.chats under GH-190: the turn read with estimates, message attachment ids.

Issue #190, Decisions 10, 12, 13 and 14; contract C5. ``chats.load_turn`` (T2'')
still reads the caller's chat, its latest messages and its active attachments
with ONE statement, and each attachment now also carries its stored
``token_estimate`` and ``derived_bytes`` (NULL as None), so the send path can
check the budget and the byte cap from the stored values before it reads a
file. An excluded file (``attachments.active = false``, migration 0030) is not
an active attachment, whichever message carried it. ``read_chat_detail`` reads
each message's ``attachment_ids`` (S9' / S11': the live attachments linked to
it, excluded ones included, by ``created_at`` then ``id``) and no longer counts
the messages (Decision 13: the interim ``context`` field and its count read are
gone). ``chats.load_recent_history`` is removed (its last caller, the denial,
reads ``load_turn``). Everything runs against tests/db_fakes.py, which evaluates
T2'', S9' and S11' as PostgreSQL does and models migration 0030 once it ships
(until then a statement naming ``active`` and ``add_attachment(active=False)``
are UndefinedColumnError, so the exclusion tests stay RED until the migration
and the code exist).

What these tests pin down:
- T2'': ``ChatTurn.attachments`` items carry ``token_estimate`` and
  ``derived_bytes`` as ints (0 stays 0) or None (NULL), on top of id, name,
  kind and page count; an excluded file carried by the first or a later
  message is left out (and so is an excluded unsent file that a turn then
  sends: A9 links it, the slot never holds it); the read is still one fetch,
  exactly the contract's T2'' form, bound to (chat, org, owner, limit).
- S9' / S11': every ``MessageRecord`` has ``attachment_ids``: the message's
  live attachments in ``created_at`` then ``id`` order (a tie sorts by id
  whatever the stored order), an excluded file included, a trashed one left
  out, ``[]`` for a message without files; plain ``uuid.UUID`` items; the
  same on a cursor page. The page statements are exactly S9' (chat, org,
  limit + 1) and S11' (chat, org, seq, limit + 1).
- ``read_chat_detail`` runs exactly S2, then S9' or S11', then S15: three
  statements, no count; ``ChatDetail`` has exactly ``chat``, ``page`` and
  ``latest_status``.
- ``chats.load_recent_history`` no longer exists.
- No content in logs: file-name and message canaries reach no log line.

New names (the ``ActiveAttachment`` and ``MessageRecord`` fields) are looked up
when a test runs, so this file collects before they exist and every test fails
on its own.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import chats as chats_module
from admino.models import LLMMessage
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from types import ModuleType

    from tests.db_fakes import Call

MESSAGE_CANARY: Final = "MESSAGE-CANARY-190m the salary of Mr. Muster is 9000"
FILE_CANARY: Final = 'FILE-CANARY-190f Q3, "final" {v2}.pdf'
EXCLUDED_CANARY: Final = "EXCLUDED-CANARY-190x passport scan.png"

_T0: Final = datetime(2026, 10, 9, 9, 0, 0, 125000, tzinfo=UTC)
_T1: Final = _T0 + timedelta(seconds=1)
_T2: Final = _T0 + timedelta(seconds=2)
_T3: Final = _T0 + timedelta(seconds=3)

# The turn's active files (T2''): FIRST (m1, T1), NO_ESTIMATE (m1, T2), then
# LATER (m3, T0: uploaded first, sent later, so it still comes last).
FIRST: Final = uuid.UUID("f1900000-0000-4000-8000-000000000001")
NO_ESTIMATE: Final = uuid.UUID("21900000-0000-4000-8000-000000000002")
LATER: Final = uuid.UUID("a1900000-0000-4000-8000-000000000003")
# Excluded files (migration 0030), carried by the first and by the later message.
EXCLUDED_FIRST: Final = uuid.UUID("01900000-0000-4000-8000-000000000004")
EXCLUDED_LATER: Final = uuid.UUID("b1900000-0000-4000-8000-000000000005")

# The detail chat's files on its first message, by created_at then id: OLDEST (T0),
# then TIE_LOW before TIE_HIGH (both T1; stored high first), then EXCLUDED (T2).
OLDEST: Final = uuid.UUID("e1900000-0000-4000-8000-000000000011")
TIE_LOW: Final = uuid.UUID("11900000-0000-4000-8000-000000000012")
TIE_HIGH: Final = uuid.UUID("91900000-0000-4000-8000-000000000013")
EXCLUDED: Final = uuid.UUID("31900000-0000-4000-8000-000000000014")
TRASHED: Final = uuid.UUID("41900000-0000-4000-8000-000000000015")
THIRD_FILE: Final = uuid.UUID("51900000-0000-4000-8000-000000000016")

# Contract C5, as verified on postgres:16.
T2_SECOND: Final = """
    SELECT c.id, c.org_id, c.owner_user_id, c.title, c.title_source, c.external_content,
           c.created_at, c.last_activity_at,
           ARRAY(
               SELECT ARRAY[a.id::text, a.filename, a.kind, a.page_count::text,
                            a.token_estimate::text, a.derived_bytes::text]
               FROM attachments a
               JOIN chat_messages am ON am.id = a.message_id AND am.org_id = a.org_id
               WHERE a.chat_id = c.id AND a.org_id = c.org_id
                 AND a.owner_user_id = c.owner_user_id
                 AND a.status = 'ready' AND a.active AND a.deleted_at IS NULL
               ORDER BY am.seq, a.created_at, a.id
           ) AS attachment_rows,
           m.role, m.content, m.tool_use_blocks, m.tool_call_id
    FROM chats c
    LEFT JOIN LATERAL (
        SELECT seq, role, content, tool_use_blocks, tool_call_id
        FROM chat_messages
        WHERE chat_id = c.id AND org_id = c.org_id
        ORDER BY seq DESC
        LIMIT $4
    ) m ON true
    WHERE c.id = $1 AND c.org_id = $2 AND c.owner_user_id = $3 AND c.deleted_at IS NULL
    ORDER BY m.seq DESC
"""
_S9_HEAD: Final = """
    SELECT m.id, m.seq, m.role, m.content, m.tool_use_blocks, m.tool_call_id, m.tool_calls,
           m.status, m.created_at,
           ARRAY(
               SELECT a.id FROM attachments a
               WHERE a.message_id = m.id AND a.org_id = m.org_id AND a.deleted_at IS NULL
               ORDER BY a.created_at, a.id
           ) AS attachment_ids
    FROM chat_messages m
"""
S9_PRIME: Final = (
    _S9_HEAD
    + """
    WHERE m.chat_id = $1 AND m.org_id = $2
    ORDER BY m.seq DESC
    LIMIT $3
"""
)
S11_PRIME: Final = (
    _S9_HEAD
    + """
    WHERE m.chat_id = $1 AND m.org_id = $2 AND m.seq < $3
    ORDER BY m.seq DESC
    LIMIT $4
"""
)
# GH-176 / GH-266 forms that still hold: the owner check and the latest status.
S2: Final = """
    SELECT id, org_id, owner_user_id, title, title_source, external_content,
        created_at, last_activity_at
    FROM chats
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
"""
S15: Final = """
    SELECT status FROM chat_messages
    WHERE chat_id = $1 AND org_id = $2
    ORDER BY seq DESC
    LIMIT 1
"""


def _canon(sql: str) -> str:
    """Lowercased, whitespace collapsed and dropped around ( ) , = [ ] (tokens kept)."""
    text = re.sub(r"\s+", " ", sql.strip().lower()).rstrip(";").strip()
    return re.sub(r"\s*([(),=\[\]])\s*", r"\1", text)


_FORMS: Final = {
    "S2": _canon(S2),
    "S9'": _canon(S9_PRIME),
    "S11'": _canon(S11_PRIME),
    "S15": _canon(S15),
    "T2''": _canon(T2_SECOND),
}


def _form(call: Call) -> str:
    """The contract form a recorded statement is, else its normalized SQL."""
    text = _canon(call.sql)
    return next((label for label, form in _FORMS.items() if form == text), call.normalized)


def _same_uuid(left: object, right: uuid.UUID) -> bool:
    """A bind argument equal to a UUID (a plain or an asyncpg UUID)."""
    return isinstance(left, uuid.UUID) and uuid.UUID(int=left.int) == right


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def chats() -> ModuleType:
    """admino.chats (its new names are looked up when a test runs)."""
    return chats_module


@dataclass(frozen=True)
class _World:
    db: FakeDb
    member: uuid.UUID
    chat: uuid.UUID  # the turn chat: m1 (user), m2 (assistant), m3 (user)
    m1: uuid.UUID
    m3: uuid.UUID
    detail: uuid.UUID  # the detail chat: d1 (user, four files), d2 (assistant), d3 (user)
    d1: uuid.UUID
    d2: uuid.UUID
    d3: uuid.UUID

    @property
    def tenant(self) -> TenantContext:
        return TenantContext(org_id=ORG_ID, user_id=self.member, role="editor")


@pytest.fixture()
def world() -> _World:
    db = FakeDb()
    member = db.add_account(org_id=ORG_ID)
    colleague = db.add_account(org_id=ORG_ID)
    outsider = db.add_account(org_id=OTHER_ORG_ID)

    chat = db.add_chat(member, title="Turn", created_at=_T0)
    m1 = db.add_chat_message(chat, "user", MESSAGE_CANARY, created_at=_T1)
    db.add_chat_message(chat, "assistant", "Read it.", created_at=_T1)
    m3 = db.add_chat_message(chat, "user", "And this one?", created_at=_T2)
    db.add_chat_message(chat, "assistant", "Done.", created_at=_T2)
    # Stored out of slot order on purpose.
    db.add_attachment(chat, attachment_id=LATER, filename="scan.png", kind="png",
                      status="ready", token_estimate=0, derived_bytes=0, message_id=m3,
                      created_at=_T0)  # fmt: skip
    db.add_attachment(chat, attachment_id=NO_ESTIMATE, filename="notes.txt", kind="txt",
                      status="ready", message_id=m1, created_at=_T2)  # fmt: skip
    db.add_attachment(chat, attachment_id=FIRST, filename=FILE_CANARY, kind="pdf",
                      status="ready", page_count=3, token_estimate=4195, derived_bytes=81920,
                      message_id=m1, created_at=_T1)  # fmt: skip
    # Files of other chats never reach this chat's turn.
    other = db.add_chat(member, title="Other")
    other_message = db.add_chat_message(other, "user", "elsewhere")
    db.add_attachment(other, filename=FILE_CANARY, status="ready", token_estimate=9,
                      message_id=other_message)  # fmt: skip
    for owner in (colleague, outsider):
        foreign = db.add_chat(owner, title="Foreign")
        foreign_message = db.add_chat_message(foreign, "user", "theirs")
        db.add_attachment(foreign, filename=FILE_CANARY, status="ready", token_estimate=7,
                          message_id=foreign_message)  # fmt: skip

    detail = db.add_chat(member, title="Detail", created_at=_T0)
    d1 = db.add_chat_message(detail, "user", "Four files", created_at=_T1)
    d2 = db.add_chat_message(detail, "assistant", "Got them.", created_at=_T1)
    d3 = db.add_chat_message(detail, "user", "One more", created_at=_T2)
    db.add_attachment(detail, attachment_id=TIE_HIGH, filename="b.csv", kind="csv",
                      status="ready", message_id=d1, created_at=_T1)  # fmt: skip
    db.add_attachment(detail, attachment_id=OLDEST, filename="a.pdf", kind="pdf",
                      status="ready", message_id=d1, created_at=_T0)  # fmt: skip
    db.add_attachment(detail, attachment_id=TIE_LOW, filename="c.txt", kind="txt",
                      status="failed", failure_reason="corrupted_file", message_id=d1,
                      created_at=_T1)  # fmt: skip
    db.add_attachment(detail, attachment_id=TRASHED, filename="gone.pdf", status="ready",
                      message_id=d1, created_at=_T0, deleted_at=_T3)  # fmt: skip
    db.add_attachment(detail, attachment_id=THIRD_FILE, filename="d.md", kind="md",
                      status="ready", message_id=d3, created_at=_T2)  # fmt: skip
    # An unsent file of the detail chat belongs to no message.
    db.add_attachment(detail, filename="draft.md", kind="md", status="ready", created_at=_T2)
    return _World(db, member, chat, m1, m3, detail, d1, d2, d3)


def _exclude_in_turn_chat(world: _World) -> None:
    """Excluded ready files carried by the first and by the later message (0030)."""
    db = world.db
    db.add_attachment(world.chat, attachment_id=EXCLUDED_FIRST, filename=EXCLUDED_CANARY,
                      kind="png", status="ready", token_estimate=2, derived_bytes=20,
                      message_id=world.m1, created_at=_T0, active=False)  # fmt: skip
    db.add_attachment(world.chat, attachment_id=EXCLUDED_LATER, filename=EXCLUDED_CANARY,
                      kind="png", status="ready", token_estimate=3, derived_bytes=30,
                      message_id=world.m3, created_at=_T3, active=False)  # fmt: skip


async def _turn(chats: ModuleType, world: _World, limit: int = 50) -> Any:
    return await chats.load_turn(world.db.pool, world.tenant, world.chat, limit=limit)


def _slot(chats: ModuleType) -> tuple[Any, ...]:
    """The turn chat's active attachments as T2'' must return them."""
    active = chats.ActiveAttachment
    return (
        active(
            id=FIRST,
            filename=FILE_CANARY,
            kind="pdf",
            page_count=3,
            token_estimate=4195,
            derived_bytes=81920,
        ),  # fmt: skip
        active(
            id=NO_ESTIMATE,
            filename="notes.txt",
            kind="txt",
            page_count=None,
            token_estimate=None,
            derived_bytes=None,
        ),  # fmt: skip
        active(
            id=LATER,
            filename="scan.png",
            kind="png",
            page_count=None,
            token_estimate=0,
            derived_bytes=0,
        ),  # fmt: skip
    )


# ---------------------------------------------------------------------------
# 1. T2'': the turn's attachments carry their estimate and derived bytes
# ---------------------------------------------------------------------------


async def test_chats_context_load_turn_attachments_carry_estimate_and_derived_bytes(
    chats: ModuleType, world: _World
) -> None:
    """Ints as stored (0 stays 0), NULL as None, in the order the files were sent."""
    turn = await _turn(chats, world)

    assert turn.attachments == _slot(chats)
    assert [(type(item.token_estimate), type(item.derived_bytes)) for item in turn.attachments] == [
        (int, int),
        (type(None), type(None)),
        (int, int),
    ]


async def test_chats_context_load_turn_leaves_out_excluded_files_whatever_their_message(
    chats: ModuleType, world: _World
) -> None:
    """Excluded files sent with the first and with the later message are not active."""
    _exclude_in_turn_chat(world)

    turn = await _turn(chats, world)

    assert [item.id for item in turn.attachments] == [FIRST, NO_ESTIMATE, LATER]


async def test_chats_context_excluded_unsent_file_is_linked_but_never_in_the_slot(
    chats: ModuleType, world: _World
) -> None:
    """Decision 10: sending an excluded unsent file links it (A9 is unchanged), but the
    next turn read leaves it out."""
    db = world.db
    excluded = db.add_attachment(world.chat, filename=EXCLUDED_CANARY, kind="png",
                                 status="ready", token_estimate=5, active=False)  # fmt: skip

    await chats.append_messages(
        db.pool,
        world.tenant,
        world.chat,
        [
            LLMMessage(role="user", content="With the excluded file"),
            LLMMessage(role="assistant", content="Noted."),
        ],
        attachment_ids=[excluded],
    )
    turn = await _turn(chats, world)

    row = db.attachment_row(excluded)
    assert row is not None
    user_row = db.messages_of(world.chat)[-2]
    assert (row["message_id"], row["active"]) == (user_row["id"], False)
    assert excluded not in [item.id for item in turn.attachments]
    assert [item.id for item in turn.attachments] == [FIRST, NO_ESTIMATE, LATER]


async def test_chats_context_load_turn_is_one_t2_second_statement_with_the_same_binds(
    chats: ModuleType, world: _World
) -> None:
    db = world.db
    before = len(db.calls)

    await _turn(chats, world, limit=7)

    calls = db.calls[before:]
    assert [_form(call) for call in calls] == ["T2''"]
    call = calls[0]
    assert call.method == "fetch"
    assert len(call.args) == 4
    assert _same_uuid(call.args[0], world.chat)
    assert _same_uuid(call.args[1], ORG_ID)
    assert _same_uuid(call.args[2], world.member)
    assert (type(call.args[3]), call.args[3]) == (int, 7)


# ---------------------------------------------------------------------------
# 2. S9' / S11': every message carries its attachment ids
# ---------------------------------------------------------------------------


async def test_chats_context_detail_messages_carry_their_live_attachment_ids_in_order(
    chats: ModuleType, world: _World
) -> None:
    """d1: OLDEST, then the T1 tie by id (TIE_LOW stored after TIE_HIGH), its failed file
    too, the trashed one left out; d2 (no files): []; d3: its one file."""
    detail = await chats.read_chat_detail(
        world.db.pool, world.tenant, world.detail, limit=10, cursor=None
    )

    assert [(record.id, record.attachment_ids) for record in detail.page.messages] == [
        (world.d1, [OLDEST, TIE_LOW, TIE_HIGH]),
        (world.d2, []),
        (world.d3, [THIRD_FILE]),
    ]
    assert all(type(record.attachment_ids) is list for record in detail.page.messages)
    assert all(
        type(item) is uuid.UUID for record in detail.page.messages for item in record.attachment_ids
    )


async def test_chats_context_detail_lists_excluded_files_on_their_message(
    chats: ModuleType, world: _World
) -> None:
    """Decision 12: active or not; an excluded file stays linked and listed (0030)."""
    world.db.add_attachment(world.detail, attachment_id=EXCLUDED, filename=EXCLUDED_CANARY,
                            kind="png", status="ready", message_id=world.d1, created_at=_T2,
                            active=False)  # fmt: skip

    detail = await chats.read_chat_detail(
        world.db.pool, world.tenant, world.detail, limit=10, cursor=None
    )

    assert detail.page.messages[0].attachment_ids == [OLDEST, TIE_LOW, TIE_HIGH, EXCLUDED]


async def test_chats_context_detail_chat_without_files_gives_empty_ids(
    chats: ModuleType, world: _World
) -> None:
    db = world.db
    chat_id = db.add_chat(world.member)
    db.add_chat_message(chat_id, "user", "hello")
    db.add_chat_message(chat_id, "assistant", "hi")

    detail = await chats.read_chat_detail(db.pool, world.tenant, chat_id, limit=10, cursor=None)

    assert [record.attachment_ids for record in detail.page.messages] == [[], []]


async def test_chats_context_detail_cursor_page_carries_attachment_ids_too(
    chats: ModuleType, world: _World
) -> None:
    """Walking back one message at a time (S9', then S11' twice)."""
    db = world.db
    pages: list[list[tuple[uuid.UUID, list[uuid.UUID]]]] = []
    cursor: str | None = None
    while True:
        detail = await chats.read_chat_detail(
            db.pool, world.tenant, world.detail, limit=1, cursor=cursor
        )
        pages.append([(record.id, record.attachment_ids) for record in detail.page.messages])
        cursor = detail.page.next_cursor
        if cursor is None:
            break

    assert pages == [
        [(world.d3, [THIRD_FILE])],
        [(world.d2, [])],
        [(world.d1, [OLDEST, TIE_LOW, TIE_HIGH])],
    ]


# ---------------------------------------------------------------------------
# 3. read_chat_detail: S2, S9' or S11', S15; no count
# ---------------------------------------------------------------------------


async def test_chats_context_detail_latest_page_runs_s2_s9_prime_and_s15_only(
    chats: ModuleType, world: _World
) -> None:
    db = world.db
    before = len(db.calls)

    await chats.read_chat_detail(db.pool, world.tenant, world.detail, limit=2, cursor=None)

    calls = db.calls[before:]
    assert [_form(call) for call in calls] == ["S2", "S9'", "S15"]
    page = calls[1]
    assert len(page.args) == 3
    assert _same_uuid(page.args[0], world.detail)
    assert _same_uuid(page.args[1], ORG_ID)
    assert (type(page.args[2]), page.args[2]) == (int, 3)


async def test_chats_context_detail_cursor_page_runs_s2_s11_prime_and_s15_only(
    chats: ModuleType, world: _World
) -> None:
    db = world.db
    first = await chats.read_chat_detail(db.pool, world.tenant, world.detail, limit=1, cursor=None)
    d3_seq = first.page.messages[0].seq
    before = len(db.calls)

    await chats.read_chat_detail(
        db.pool, world.tenant, world.detail, limit=1, cursor=first.page.next_cursor
    )

    calls = db.calls[before:]
    assert [_form(call) for call in calls] == ["S2", "S11'", "S15"]
    page = calls[1]
    assert len(page.args) == 4
    assert _same_uuid(page.args[0], world.detail)
    assert _same_uuid(page.args[1], ORG_ID)
    assert (page.args[2], page.args[3]) == (d3_seq, 2)


async def test_chats_context_detail_has_no_message_count(chats: ModuleType, world: _World) -> None:
    """Decision 13: ChatDetail is exactly the chat, the page and the latest status."""
    detail = await chats.read_chat_detail(
        world.db.pool, world.tenant, world.detail, limit=10, cursor=None
    )

    assert set(type(detail).model_fields) == {"chat", "page", "latest_status"}
    assert detail.latest_status == "complete"
    assert not any(re.search(r"\bcount\(", call.normalized) for call in world.db.calls)


def test_chats_context_message_record_has_attachment_ids(chats: ModuleType) -> None:
    assert set(chats.MessageRecord.model_fields) == {
        "id",
        "seq",
        "role",
        "content",
        "tool_use_blocks",
        "tool_call_id",
        "tool_calls",
        "status",
        "created_at",
        "attachment_ids",
    }


def test_chats_context_load_recent_history_is_gone(chats: ModuleType) -> None:
    """Its last caller (the denial) reads load_turn; keeping it would be dead code."""
    assert callable(chats.load_turn)
    assert not hasattr(chats, "load_recent_history")


# ---------------------------------------------------------------------------
# 4. No content in logs
# ---------------------------------------------------------------------------


async def test_chats_context_reads_log_no_names_or_content(
    chats: ModuleType, world: _World
) -> None:
    db = world.db
    with configured_logging("DEBUG", "text") as logs:
        await _turn(chats, world)
        await chats.read_chat_detail(db.pool, world.tenant, world.detail, limit=1, cursor=None)
        logged = logs.text + "\n".join(record.getMessage() for record in logs.records)
    detail = await chats.read_chat_detail(db.pool, world.tenant, world.detail, limit=1, cursor=None)

    assert detail.page.messages[0].attachment_ids == [THIRD_FILE]
    assert [canary for canary in (MESSAGE_CANARY, FILE_CANARY) if canary in logged] == []
