"""Tests for admino.attachments.check_sendable: the send rules of GH-189 (contract C5).

Issue #189, Decision 7: a message may carry only the caller's live, unsent and
``ready`` attachments of the chat. ``check_sendable`` decides it with ONE
statement (A8'; GH-190 contract C6: A8'', which also reads the estimate, the
derived bytes and the flag) and refuses, in this order, ``AttachmentNotFoundError`` (an id
that isn't the caller's live attachment of this chat: another chat's, a
colleague's, another org's, a trashed or an unknown one; the server's ``404
attachment_not_found``), ``AttachmentAlreadySentError`` (``409
attachment_already_sent``) and the new ``AttachmentNotReadyError`` for a file
whose status is ``uploaded``, ``processing`` or ``failed`` (``409
attachment_not_ready``). On success it returns what the slot needs: the files
as ``chats.ActiveAttachment`` in upload order (``created_at``, then ``id``).
Runs against tests/db_fakes.py, which evaluates A8'' as PostgreSQL does. The
exclusion side of A8'' (refusals over every id, active ones returned) is
tests/test_attachments_active.py's.

What these tests pin down:
- No ids (``[]``, ``()``): ``[]`` and no statement.
- Otherwise exactly one statement, the contract's A8'' (fetch, on the given
  executor), bound to (the ids, the chat, the caller's org, the caller), for an
  accepted and for a refused set alike; nothing is written.
- The result: a list of ``chats.ActiveAttachment`` (id, stored name, kind,
  page count, GH-190: token estimate and derived bytes; 0 stays 0, NULL is
  None) in ``created_at`` then ``id`` order,
  whatever the order of the given ids.
- The error order, each case proved both ways (the faults in either order give
  the winning error, and the losing fault alone gives its own error, so an
  order test never passes on a file that isn't a fault):
  not found (each of the five cases) beats not ready; already sent beats not
  ready; not found beats already sent beats not ready; a file with two faults
  (trashed and processing, sent and processing) gets the earlier error.
- Not ready: each of ``uploaded``, ``processing`` and ``failed``, alone and
  beside a ready file.
- The errors: fixed texts ("Attachment not found.", "Attachment already sent.",
  "Attachment not ready.") with no id or file name in the text or args;
  ``AttachmentNotReadyError`` is neither a not-found nor an already-sent error
  (the server maps each to its own code).
- No content in logs: file-name canaries reach no log line.

``attachments.AttachmentNotReadyError`` and ``chats.ActiveAttachment`` are looked
up when a test runs, so this file collects before they exist and every test
fails on its own.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import attachments as attachments_module
from admino import chats
from admino.tenancy import TenantContext
from tests.db_fakes import FakeDb
from tests.log_capture import configured_logging
from tests.tenancy_world import World, build_world, seed_chat

if TYPE_CHECKING:
    from types import ModuleType

    from tests.db_fakes import Call

READY_CANARY: Final = 'READY-CANARY-189r Q3, "final" {v2}.pdf'
WAITING_CANARY: Final = "WAITING-CANARY-189w board minutes.docx"
SENT_CANARY: Final = "SENT-CANARY-189s salary list.xlsx"
FOREIGN_CANARY: Final = "FOREIGN-CANARY-189f colleague contract.pdf"
UNKNOWN_ID: Final = uuid.UUID("0b890000-0000-4000-8000-0000000000ff")

_T0: Final = datetime(2026, 10, 1, 9, 0, 0, 125000, tzinfo=UTC)
# Ready, unsent files of the chat. Upload order: EARLY (T0), MIDDLE (T1), then
# TIE_LOW and TIE_HIGH (both T2: the id decides); the ids sort another way.
EARLY: Final = uuid.UUID("f1890000-0000-4000-8000-0000000000e1")
MIDDLE: Final = uuid.UUID("a1890000-0000-4000-8000-0000000000e2")
TIE_LOW: Final = uuid.UUID("11890000-0000-4000-8000-0000000000e3")
TIE_HIGH: Final = uuid.UUID("91890000-0000-4000-8000-0000000000e4")

# GH-190 (contract C6): A8'', with the estimate, the derived bytes and the flag.
_A8_PRIME: Final = (
    "SELECT id, message_id, status, filename, kind, page_count, token_estimate, "
    "derived_bytes, active FROM attachments "
    "WHERE id = ANY($1::uuid[]) AND chat_id = $2 AND org_id = $3 AND owner_user_id = $4 "
    "AND deleted_at IS NULL ORDER BY created_at, id"
)
_NOT_FOUND_TEXT: Final = "Attachment not found."
_ALREADY_SENT_TEXT: Final = "Attachment already sent."
_NOT_READY_TEXT: Final = "Attachment not ready."


def _canon(sql: str) -> str:
    """Lowercased, whitespace collapsed and dropped around ( ) , = [ ] (tokens kept)."""
    text = re.sub(r"\s+", " ", sql.strip().lower()).rstrip(";").strip()
    return re.sub(r"\s*([(),=\[\]])\s*", r"\1", text)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def att() -> ModuleType:
    """admino.attachments (its new names are looked up when a test runs)."""
    return attachments_module


@dataclass(frozen=True)
class _Seeded:
    """The world, the editor's chat and every file a test may name (by key)."""

    world: World
    chat: uuid.UUID
    files: dict[str, uuid.UUID]

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
    chat = seed_chat(db, editor, title="Board")
    message = db.add_chat_message(chat, "user", "Earlier, with a file")

    def add(chat_id: uuid.UUID, **values: Any) -> uuid.UUID:
        return db.add_attachment(chat_id, **values)

    # The ready, unsent files, stored out of upload order on purpose.
    add(chat, attachment_id=MIDDLE, filename="scan.png", kind="png", status="ready",
        created_at=_T0 + timedelta(seconds=1))  # fmt: skip
    add(chat, attachment_id=TIE_HIGH, filename="data.csv", kind="csv", status="ready",
        created_at=_T0 + timedelta(seconds=2))  # fmt: skip
    add(chat, attachment_id=EARLY, filename=READY_CANARY, kind="pdf", status="ready",
        page_count=4, token_estimate=4195, derived_bytes=81920, created_at=_T0)  # fmt: skip
    add(chat, attachment_id=TIE_LOW, filename="notes.docx", kind="docx", status="ready",
        page_count=0, token_estimate=0, derived_bytes=0,
        created_at=_T0 + timedelta(seconds=2))  # fmt: skip
    other_chat = seed_chat(db, editor, title="Other")
    colleague_chat = seed_chat(db, world.a["org_admin"], title="Colleague")
    other_org_chat = seed_chat(db, world.b["editor"], title="Other org")
    files = {
        "uploaded": add(chat, filename=WAITING_CANARY, kind="docx", status="uploaded"),
        "processing": add(chat, filename=WAITING_CANARY, kind="docx", status="processing"),
        "failed": add(
            chat,
            filename=WAITING_CANARY,
            kind="docx",
            status="failed",
            failure_reason="corrupted_file",
        ),  # fmt: skip
        "sent": add(chat, filename=SENT_CANARY, kind="xlsx", status="ready", message_id=message),
        "sent-processing": add(
            chat, filename=SENT_CANARY, kind="xlsx", status="processing", message_id=message
        ),  # fmt: skip
        "trashed": add(chat, filename=FOREIGN_CANARY, status="ready", deleted_at=_T0),
        "trashed-processing": add(
            chat, filename=FOREIGN_CANARY, status="processing", deleted_at=_T0
        ),  # fmt: skip
        # Ready and unsent, so only their owner, chat or org makes them unsendable here.
        "other-chat": add(other_chat, filename=FOREIGN_CANARY, status="ready"),
        "colleague": add(colleague_chat, filename=FOREIGN_CANARY, status="ready"),
        "other-org": add(other_org_chat, filename=FOREIGN_CANARY, status="ready"),
        "unknown": UNKNOWN_ID,
    }
    return _Seeded(world=world, chat=chat, files=files)


def _ids(seeded: _Seeded, keys: list[str]) -> list[uuid.UUID]:
    return [seeded.files[key] for key in keys]


async def _check(att: ModuleType, seeded: _Seeded, ids: list[uuid.UUID]) -> Any:
    return await att.check_sendable(seeded.db.pool, seeded.editor, seeded.chat, ids)


def _errors(att: ModuleType) -> dict[str, type[Exception]]:
    """The three refusals by name (the new one looked up now)."""
    return {
        "not_found": att.AttachmentNotFoundError,
        "already_sent": att.AttachmentAlreadySentError,
        "not_ready": att.AttachmentNotReadyError,
    }


def _same_uuid(left: object, right: uuid.UUID) -> bool:
    return isinstance(left, uuid.UUID) and uuid.UUID(int=left.int) == right


def _assert_one_a8_prime(seeded: _Seeded, calls: list[Call], ids: list[uuid.UUID]) -> None:
    """Exactly one A8' fetch, bound to (the ids, the chat, the caller's org, the caller)."""
    assert [_canon(call.sql) for call in calls] == [_canon(_A8_PRIME)]
    call = calls[0]
    assert call.method == "fetch"
    assert {uuid.UUID(str(item)) for item in call.args[0]} == set(ids)
    assert len(call.args) == 4
    assert _same_uuid(call.args[1], seeded.chat)
    assert _same_uuid(call.args[2], seeded.editor.org_id)
    assert _same_uuid(call.args[3], seeded.editor.user_id)


# ---------------------------------------------------------------------------
# 1. Statements
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("empty", [[], ()], ids=["list", "tuple"])
async def test_attachments_sendable_without_ids_returns_empty_list_and_runs_nothing(
    att: ModuleType, seeded: _Seeded, empty: list[uuid.UUID]
) -> None:
    before = len(seeded.db.calls)

    result = await att.check_sendable(seeded.db.pool, seeded.editor, seeded.chat, empty)

    assert (type(result), result) == (list, [])
    assert seeded.db.calls[before:] == []


async def test_attachments_sendable_accepted_files_take_exactly_one_a8_prime_statement(
    att: ModuleType, seeded: _Seeded
) -> None:
    db = seeded.db
    ids = [TIE_HIGH, EARLY]
    before = len(db.calls)
    state = db.snapshot()

    await _check(att, seeded, ids)

    _assert_one_a8_prime(seeded, db.calls[before:], ids)
    assert db.snapshot() == state


@pytest.mark.parametrize(
    ("keys", "error"),
    [
        (["unknown", "processing"], "not_found"),
        (["sent", "uploaded"], "already_sent"),
        (["failed"], "not_ready"),
    ],
    ids=["not-found", "already-sent", "not-ready"],
)
async def test_attachments_sendable_refusal_takes_exactly_one_statement_and_writes_nothing(
    att: ModuleType, seeded: _Seeded, keys: list[str], error: str
) -> None:
    db = seeded.db
    ids = _ids(seeded, keys)
    expected = _errors(att)[error]
    before = len(db.calls)
    state = db.snapshot()

    with pytest.raises(expected):
        await _check(att, seeded, ids)

    _assert_one_a8_prime(seeded, db.calls[before:], ids)
    assert db.snapshot() == state


# ---------------------------------------------------------------------------
# 2. The result: ActiveAttachments in upload order
# ---------------------------------------------------------------------------


async def test_attachments_sendable_returns_active_attachments_in_upload_order(
    att: ModuleType, seeded: _Seeded
) -> None:
    """Given in another order; the result is created_at, then id."""
    result = await _check(att, seeded, [TIE_HIGH, MIDDLE, TIE_LOW, EARLY])

    active = chats.ActiveAttachment
    assert type(result) is list
    assert result == [
        active(
            id=EARLY,
            filename=READY_CANARY,
            kind="pdf",
            page_count=4,
            token_estimate=4195,
            derived_bytes=81920,
        ),  # fmt: skip
        active(id=MIDDLE, filename="scan.png", kind="png", page_count=None),
        active(
            id=TIE_LOW,
            filename="notes.docx",
            kind="docx",
            page_count=0,
            token_estimate=0,
            derived_bytes=0,
        ),  # fmt: skip
        active(id=TIE_HIGH, filename="data.csv", kind="csv", page_count=None),
    ]
    assert all(type(item) is active for item in result)
    # GH-190: ints as stored (0 stays 0), NULL as None.
    assert [(type(item.token_estimate), type(item.derived_bytes)) for item in result] == [
        (int, int),
        (type(None), type(None)),
        (int, int),
        (type(None), type(None)),
    ]


async def test_attachments_sendable_returns_one_file_as_a_one_item_list(
    att: ModuleType, seeded: _Seeded
) -> None:
    result = await _check(att, seeded, [TIE_LOW])

    assert result == [
        chats.ActiveAttachment(
            id=TIE_LOW,
            filename="notes.docx",
            kind="docx",
            page_count=0,
            token_estimate=0,
            derived_bytes=0,
        )
    ]


# ---------------------------------------------------------------------------
# 3. Not ready: uploaded, processing, failed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["uploaded", "processing", "failed"])
@pytest.mark.parametrize("beside_ready", [False, True], ids=["alone", "beside-a-ready-file"])
async def test_attachments_sendable_file_that_is_not_ready_is_refused(
    att: ModuleType, seeded: _Seeded, status: str, beside_ready: bool
) -> None:
    ids = [EARLY, seeded.files[status]] if beside_ready else [seeded.files[status]]

    with pytest.raises(att.AttachmentNotReadyError) as caught:
        await _check(att, seeded, ids)

    assert type(caught.value) is att.AttachmentNotReadyError


# ---------------------------------------------------------------------------
# 4. The error order, each case proved both ways
# ---------------------------------------------------------------------------

# case -> (the winning fault, the losing fault, the winner's error, the loser's error)
_ORDER_CASES: Final[dict[str, tuple[list[str], list[str], str, str]]] = {
    "other-chat-beats-not-ready": (["other-chat"], ["processing"], "not_found", "not_ready"),
    "other-org-beats-not-ready": (["other-org"], ["uploaded"], "not_found", "not_ready"),
    "colleague-beats-not-ready": (["colleague"], ["failed"], "not_found", "not_ready"),
    "trashed-beats-not-ready": (["trashed"], ["processing"], "not_found", "not_ready"),
    "unknown-beats-not-ready": (["unknown"], ["uploaded"], "not_found", "not_ready"),
    "already-sent-beats-not-ready": (["sent"], ["processing"], "already_sent", "not_ready"),
    "not-found-beats-already-sent-and-not-ready": (
        ["colleague"],
        ["sent", "failed"],
        "not_found",
        "already_sent",
    ),
    "trashed-processing-file-is-not-found": (
        ["trashed-processing"],
        ["processing"],
        "not_found",
        "not_ready",
    ),
    "sent-processing-file-is-already-sent": (
        ["sent-processing"],
        ["uploaded"],
        "already_sent",
        "not_ready",
    ),
}


@pytest.mark.parametrize("case", list(_ORDER_CASES))
@pytest.mark.parametrize("reverse", [False, True], ids=["winner-first", "winner-last"])
async def test_attachments_sendable_refusals_come_in_the_contract_order(
    att: ModuleType, seeded: _Seeded, case: str, reverse: bool
) -> None:
    winner, loser, winner_error, loser_error = _ORDER_CASES[case]
    errors = _errors(att)
    ids = _ids(seeded, winner + loser)
    if reverse:
        ids.reverse()

    # Any refusal; the exact type is asserted below.
    with pytest.raises(Exception) as both:
        await _check(att, seeded, ids)
    with pytest.raises(Exception) as alone:
        await _check(att, seeded, _ids(seeded, loser))

    assert type(both.value) is errors[winner_error]
    assert type(alone.value) is errors[loser_error]


async def test_attachments_sendable_three_faults_fall_away_one_by_one(
    att: ModuleType, seeded: _Seeded
) -> None:
    """Not found, then already sent, then not ready, then accepted."""
    errors = _errors(att)
    steps = [
        (["unknown", "sent", "uploaded", "fine"], errors["not_found"]),
        (["sent", "uploaded", "fine"], errors["already_sent"]),
        (["uploaded", "fine"], errors["not_ready"]),
    ]
    files = {**seeded.files, "fine": MIDDLE}

    for keys, expected in steps:
        with pytest.raises(expected) as caught:
            await _check(att, seeded, [files[key] for key in keys])
        assert type(caught.value) is expected, keys

    assert [item.id for item in await _check(att, seeded, [MIDDLE])] == [MIDDLE]


# ---------------------------------------------------------------------------
# 5. The errors themselves
# ---------------------------------------------------------------------------


def test_attachments_sendable_not_ready_error_is_its_own_error(att: ModuleType) -> None:
    """The server maps each refusal to its own code: none is a subclass of another."""
    not_ready = att.AttachmentNotReadyError

    assert issubclass(not_ready, Exception)
    assert not issubclass(not_ready, att.AttachmentNotFoundError | att.AttachmentAlreadySentError)
    assert not issubclass(att.AttachmentNotFoundError, not_ready)
    assert not issubclass(att.AttachmentAlreadySentError, not_ready)


async def test_attachments_sendable_errors_have_fixed_texts_without_ids_or_names(
    att: ModuleType, seeded: _Seeded
) -> None:
    errors = _errors(att)
    cases = [
        (["colleague", "trashed"], errors["not_found"], _NOT_FOUND_TEXT),
        (["sent"], errors["already_sent"], _ALREADY_SENT_TEXT),
        (["processing", "failed"], errors["not_ready"], _NOT_READY_TEXT),
    ]
    names = (READY_CANARY, WAITING_CANARY, SENT_CANARY, FOREIGN_CANARY)

    for keys, expected, text in cases:
        ids = _ids(seeded, keys)
        with pytest.raises(expected) as caught:
            await _check(att, seeded, ids)
        rendered = f"{caught.value} {caught.value.args!r}"
        assert str(caught.value) == text
        assert [str(item) for item in ids if str(item) in rendered] == []
        assert [name for name in names if name in rendered] == []


# ---------------------------------------------------------------------------
# 6. No content in logs
# ---------------------------------------------------------------------------


async def test_attachments_sendable_logs_no_file_names(att: ModuleType, seeded: _Seeded) -> None:
    errors = tuple(_errors(att).values())
    with configured_logging("DEBUG", "text") as logs:
        await _check(att, seeded, [EARLY, MIDDLE])
        for keys in (["colleague"], ["sent"], ["processing"]):
            with pytest.raises(errors):
                await _check(att, seeded, _ids(seeded, keys))
        logged = logs.text + "\n".join(record.getMessage() for record in logs.records)

    canaries = (READY_CANARY, WAITING_CANARY, SENT_CANARY, FOREIGN_CANARY)
    assert [canary for canary in canaries if canary in logged] == []
