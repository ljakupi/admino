"""Tests for admino.chats' retry layer: the failed turn, the history before it, the replacing store.

Issue #245 (retry a failed chat answer), Decisions 1, 2, 3 and 7; contract C2 (C1 for
the database function). Everything runs against tests/db_fakes.py, which evaluates R1
and T2b on its SQL reader and emulates ``delete_failed_turn`` exactly as migration
0031's body does (contract C5), once a shipped migration creates the function.

What these tests pin down:
- Surface: ``RETRYABLE_STATUSES == frozenset({"error", "stopped"})``; ``RetryTarget``
  is a frozen dataclass of exactly ``through_seq``, ``status``, ``user_seq``,
  ``message`` and ``attachment_ids`` (in that order); ``read_retry_target(executor,
  tenant, chat_id)`` is a coroutine; ``load_turn`` gains the keyword-only
  ``before_seq`` and ``append_messages`` the keyword-only ``replace_through`` (both
  default None); the docstrings name what GH-245 adds.
- ``read_retry_target`` (R1): ONE ``fetchrow`` of the contract's exact text bound to
  ``(chat_id, org_id, user_id)``, writing nothing. A target when the chat's latest
  message (highest seq, any role) ended ``error`` or ``stopped`` (Decision 1): an
  ``error`` answer (after a tool loop too), ``stopped`` on an assistant partial, on a
  ``tool`` row and on the USER row itself (``user_seq == through_seq``), and GH-24's
  pending-limit ``error`` turn. None for ``complete`` (after an earlier failed turn
  too), ``awaiting_confirmation``, ``limit_reached``, an empty chat, an ``error``
  answer followed by an org notice and a chat without a user message. The target's
  ``message`` is the latest user row's stored text; ``attachment_ids`` its live linked
  files (excluded ones too) by ``created_at`` then ``id``, as plain UUIDs (another
  message's files, the chat's unsent and trashed files left out).
  ``ChatNotFoundError`` (one error) for a colleague's, another org's (also under a
  forged tenant org), a trashed and an unknown chat, after that one statement.
- ``load_turn(..., before_seq=n)`` (T2b): ONE fetch of T2'' with the lateral's WHERE
  extended by ``seq < $5``, bound to ``(chat_id, org_id, user_id, limit, n)``; the
  history is the latest ``limit`` messages before seq n, chronological, leading orphan
  ``tool`` rows dropped; a retried first message gets ``[]`` and its chat; the active
  attachments are T2'''s whatever the bound (the retried message's files included);
  ``before_seq=None`` (and omitted) sends exactly today's T2'' and its four binds;
  ``ChatNotFoundError`` as T2''.
- ``append_messages(..., replace_through=n)``: on one connection in one committed
  transaction, the touch (S7), then ``SELECT delete_failed_turn($1, $2, $3, $4)`` via
  ``fetchval`` bound to ``(chat_id, org_id, user_id, n)``, then the inserts and the A9
  link as today. Afterwards the failed turn (its user row through n) is gone for each
  failed shape, the re-stored user message and the answer follow the kept messages
  (the run's status and tool calls on the last row), the given files are linked to the
  NEW user row with their rows intact (never deleted), ``last_activity_at`` is bumped,
  ``external_content`` stays set, and an org notice stored after the failed answer is
  kept before the new turn. A refusal (n a ``complete`` row, another chat's failed
  row, an ``error`` row forged after a completed tool turn: C1', security audit M-1)
  raises ``asyncpg.InsufficientPrivilegeError`` and changes nothing (no insert, no
  link, rolled back); a trashed, a colleague's, another org's or an unknown chat is
  ``ChatNotFoundError`` and the function is never called; ``messages`` without a
  ``user`` message is ``ValueError`` before any statement; the default (omitted or
  None) runs exactly today's statements.
- The failed answer's partial (C1'b, Decision 7, GH-25 D9): with ``final_status``
  ``"error"`` every NON-last ``assistant`` message without tool_use blocks (None or
  ``[]``) is stored ``error`` too (a streamed run's text shown before it timed out),
  while non-last assistant messages WITH blocks, ``tool`` and ``user`` messages stay
  ``complete``; with ``complete``, ``stopped``, ``awaiting_confirmation`` or
  ``limit_reached`` every non-last row stays ``complete``. Such a D9 turn
  (``U A(partial, error) A(error)``) is a target and is replaced (3 rows), also when a
  retry itself timed out after text (stored by ``append_messages(..., replace_through=n,
  final_status="error")``, then retried again).
- A retry of a retry through the three functions (Decision 2: V1 keeps nothing of a
  failed turn).
- Tenant isolation (§5): every statement binds the caller's org, every statement on
  the chat or the function binds the caller as owner, and no foreign id is bound.
- No content in logs or errors (§1): message, answer, tool-output, file-name and title
  canaries reach no log line and no error text.

``chats.RETRYABLE_STATUSES``, ``chats.RetryTarget``, ``chats.read_retry_target`` and
the new keywords are looked up when a test runs, so this file collects before they
exist and every test fails on its own.
"""

from __future__ import annotations

import dataclasses
import inspect
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import asyncpg
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

TITLE_CANARY: Final = "TITLE-CANARY-245t merger plans"
MESSAGE_CANARY: Final = "MESSAGE-CANARY-245m the salary of Mr. Muster is 9000"
ANSWER_CANARY: Final = "ANSWER-CANARY-245a the provider failed mid-answer"
TOOL_CANARY: Final = "TOOL-CANARY-245o calendar: dentist at 9:00"
FILE_CANARY: Final = 'FILE-CANARY-245f Q3 "final".pdf'
NOTICE: Final = "Your organization changed a tool permission."
PENDING_LIMIT_RESULT: Final = "Tool call denied: too many confirmations are pending."
UNKNOWN_CHAT: Final = uuid.UUID("7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f")

_PAST: Final = datetime(2026, 9, 1, 8, 0, 0, 250000, tzinfo=UTC)
_T0: Final = datetime(2026, 10, 1, 9, 0, 0, 125000, tzinfo=UTC)
_T1: Final = _T0 + timedelta(seconds=1)
_T2: Final = _T0 + timedelta(seconds=2)

# The files of the main chat's failed user message: FILE_A (T1), then FILE_B and
# FILE_EXCLUDED (both T2, so the id decides; FILE_EXCLUDED is excluded, active false).
# Their ids sort neither way (11.. < 91.. < f1..), and they are stored in none of these
# orders, so neither ``ORDER BY id`` nor the table's own order passes.
FILE_A: Final = uuid.UUID("f2450000-0000-4000-8000-000000000001")
FILE_B: Final = uuid.UUID("12450000-0000-4000-8000-000000000002")
FILE_EXCLUDED: Final = uuid.UUID("92450000-0000-4000-8000-000000000003")
TURN_FILES: Final = (FILE_A, FILE_B, FILE_EXCLUDED)
# The main chat's other files: one carried by its first message, one trashed on the
# failed message, one never sent.
FILE_OLD: Final = uuid.UUID("a2450000-0000-4000-8000-000000000004")
FILE_TRASHED: Final = uuid.UUID("02450000-0000-4000-8000-000000000005")
FILE_UNSENT: Final = uuid.UUID("32450000-0000-4000-8000-000000000006")
# The file of the chat whose stop landed on the user row itself.
FILE_STOPPED: Final = uuid.UUID("42450000-0000-4000-8000-000000000007")

CALENDAR_CALL: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "call_cal_1",
    "name": "google_calendar.list",
    "input": {"days": 7},
}
MEMORY_CALL: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "call_mem_2",
    "name": "memory.list",
    "input": {},
}
CREATE_CALL: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "call_create_3",
    "name": "google_calendar.create",
    "input": {"title": "Dentist"},
}

# A seeded message: (label, role, content, status, extra add_chat_message keywords).
_Spec = tuple[str, str, str, str, dict[str, Any]]

# The main chat: three exchanges, the last one failed after a tool call (error).
_MAIN: Final[tuple[_Spec, ...]] = (
    ("q0", "user", "Plain question", "complete", {}),
    ("a0", "assistant", "Plain answer", "complete", {}),
    ("q1", "user", "What's on?", "complete", {}),
    ("a1", "assistant", "Let me check.", "complete", {"tool_use_blocks": [CALENDAR_CALL]}),
    ("t1", "tool", TOOL_CANARY, "complete", {"tool_call_id": "call_cal_1"}),
    ("a2", "assistant", "You see the dentist on Monday.", "complete", {}),
    ("q2", "user", MESSAGE_CANARY, "complete", {}),
    ("a3", "assistant", "Looking at your notes.", "complete", {"tool_use_blocks": [MEMORY_CALL]}),
    ("t2", "tool", "no notes", "complete", {"tool_call_id": "call_mem_2"}),
    ("a4", "assistant", ANSWER_CANARY, "error", {}),
)
_MAIN_KEPT: Final = ("q0", "a0", "q1", "a1", "t1", "a2")

_U1: Final[_Spec] = ("u1", "user", "First question", "complete", {})
_A1: Final[_Spec] = ("a1", "assistant", "First answer", "complete", {})

# Decision 1: the failed shapes, each (specs, through label, status, user label).
_TARGET_SHAPES: Final[dict[str, tuple[tuple[_Spec, ...], str, str, str]]] = {
    "error-answer": (
        (
            _U1,
            _A1,
            ("u2", "user", MESSAGE_CANARY, "complete", {}),
            ("a2", "assistant", ANSWER_CANARY, "error", {}),
        ),
        "a2",
        "error",
        "u2",
    ),
    "stopped-partial-answer": (
        (
            _U1,
            _A1,
            ("u2", "user", MESSAGE_CANARY, "complete", {}),
            ("a2", "assistant", "A half-written ans", "stopped", {}),
        ),
        "a2",
        "stopped",
        "u2",
    ),
    "stopped-on-a-tool-row": (
        (
            _U1,
            _A1,
            ("u2", "user", MESSAGE_CANARY, "complete", {}),
            ("a2", "assistant", "Checking.", "complete", {"tool_use_blocks": [CALENDAR_CALL]}),
            ("t2", "tool", TOOL_CANARY, "stopped", {"tool_call_id": "call_cal_1"}),
        ),
        "t2",
        "stopped",
        "u2",
    ),
    "stopped-on-the-user-row": (
        (_U1, _A1, ("u2", "user", MESSAGE_CANARY, "stopped", {})),
        "u2",
        "stopped",
        "u2",
    ),
    "pending-limit-error": (
        (
            _U1,
            _A1,
            ("u2", "user", MESSAGE_CANARY, "complete", {}),
            ("a2", "assistant", "I'll add it.", "complete", {"tool_use_blocks": [CREATE_CALL]}),
            ("t2", "tool", PENDING_LIMIT_RESULT, "complete", {"tool_call_id": "call_create_3"}),
            ("a3", "assistant", "Action google_calendar.create was not run.", "error", {}),
        ),
        "a3",
        "error",
        "u2",
    ),
    # C1'b (GH-25 D9): a streamed run that timed out after text, its partial stored error.
    "timeout-partial-error": (
        (
            _U1,
            _A1,
            ("u2", "user", MESSAGE_CANARY, "complete", {}),
            ("a2", "assistant", "Day one: Zurich ", "error", {}),
            ("a3", "assistant", ANSWER_CANARY, "error", {}),
        ),
        "a3",
        "error",
        "u2",
    ),
}
# Decision 1: what the 409 ``not_retryable`` answers.
_NOT_RETRYABLE_SHAPES: Final[dict[str, tuple[_Spec, ...]]] = {
    "complete-after-an-earlier-failed-turn": (
        _U1,
        ("a1", "assistant", ANSWER_CANARY, "error", {}),
        ("u2", "user", MESSAGE_CANARY, "complete", {}),
        ("a2", "assistant", "Second answer", "complete", {}),
    ),
    "awaiting-confirmation": (
        _U1,
        (
            "a1",
            "assistant",
            "I'll add it.",
            "awaiting_confirmation",
            {"tool_use_blocks": [CREATE_CALL]},
        ),
    ),
    "limit-reached": (_U1, ("a1", "assistant", "Partial", "limit_reached", {})),
    "empty-chat": (),
    "error-followed-by-an-org-notice": (
        _U1,
        ("a1", "assistant", ANSWER_CANARY, "error", {}),
        ("n1", "user", NOTICE, "complete", {}),
    ),
    "no-user-message": (("a1", "assistant", ANSWER_CANARY, "error", {}),),
}

# Contract C2, as verified on postgres:16 (compared whitespace-free, tokens kept).
R1: Final = """
    SELECT c.id,
           latest.seq AS through_seq, latest.status,
           turn.seq AS user_seq, turn.content,
           ARRAY(
               SELECT a.id FROM attachments a
               WHERE a.message_id = turn.id AND a.chat_id = c.id AND a.org_id = c.org_id
                 AND a.owner_user_id = c.owner_user_id AND a.deleted_at IS NULL
               ORDER BY a.created_at, a.id
           ) AS attachment_ids
    FROM chats c
    LEFT JOIN LATERAL (
        SELECT seq, status FROM chat_messages
        WHERE chat_id = c.id AND org_id = c.org_id
        ORDER BY seq DESC
        LIMIT 1
    ) latest ON true
    LEFT JOIN LATERAL (
        SELECT id, seq, content FROM chat_messages
        WHERE chat_id = c.id AND org_id = c.org_id AND role = 'user'
        ORDER BY seq DESC
        LIMIT 1
    ) turn ON true
    WHERE c.id = $1 AND c.org_id = $2 AND c.owner_user_id = $3 AND c.deleted_at IS NULL
"""
_T2_HEAD: Final = """
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
"""
_T2_TAIL: Final = """
        ORDER BY seq DESC
        LIMIT $4
    ) m ON true
    WHERE c.id = $1 AND c.org_id = $2 AND c.owner_user_id = $3 AND c.deleted_at IS NULL
    ORDER BY m.seq DESC
"""
# GH-190's T2'' (today's turn read) and GH-245's T2b (the window before the retried row).
T2_SECOND: Final = _T2_HEAD + "WHERE chat_id = c.id AND org_id = c.org_id" + _T2_TAIL
T2B: Final = _T2_HEAD + "WHERE chat_id = c.id AND org_id = c.org_id AND seq < $5" + _T2_TAIL
R2: Final = "SELECT delete_failed_turn($1, $2, $3, $4)"
# Today's append statements (GH-176 / GH-187).
S7: Final = """
    UPDATE chats SET last_activity_at = now()
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    RETURNING id
"""
S8: Final = """
    INSERT INTO chat_messages
        (chat_id, org_id, role, content, tool_use_blocks, tool_call_id, tool_calls, status)
    VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8)
    RETURNING id
"""
A9: Final = """
    UPDATE attachments SET message_id = $1, updated_at = now()
    WHERE id = ANY($2::uuid[]) AND chat_id = $3 AND org_id = $4 AND owner_user_id = $5
        AND message_id IS NULL AND deleted_at IS NULL
"""


def _canon(sql: str) -> str:
    """Lowercased, whitespace collapsed and dropped around ( ) , = [ ] (tokens kept)."""
    text = re.sub(r"\s+", " ", sql.strip().lower()).rstrip(";").strip()
    return re.sub(r"\s*([(),=\[\]])\s*", r"\1", text)


_FORMS: Final = {
    "R1": _canon(R1),
    "R2": _canon(R2),
    "T2''": _canon(T2_SECOND),
    "T2b": _canon(T2B),
    "S7": _canon(S7),
    "S8": _canon(S8),
    "A9": _canon(A9),
}


def _form(call: Call) -> str:
    """The contract form a recorded statement is, else its normalized SQL."""
    text = _canon(call.sql)
    return next((label for label, form in _FORMS.items() if form == text), call.normalized)


def _same_uuid(left: object, right: uuid.UUID) -> bool:
    """A bind argument equal to a UUID (a plain or an asyncpg UUID)."""
    return isinstance(left, uuid.UUID) and uuid.UUID(int=left.int) == right


def _plain(value: Any) -> uuid.UUID:
    return uuid.UUID(int=value.int)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def chats() -> ModuleType:
    """admino.chats (its new names are looked up when a test runs)."""
    return chats_module


@dataclass(frozen=True)
class _Stored:
    """A seeded message: its id and seq."""

    id: uuid.UUID
    seq: int


@dataclass(frozen=True)
class _Seeded:
    """The world, the editor's chats (ids) and their messages by label."""

    world: World
    main: uuid.UUID  # the editor's chat of _MAIN, external content, with files
    main_messages: dict[str, _Stored]
    user_stop: uuid.UUID  # the editor's chat whose stop landed on its user row (a file on it)
    user_stop_messages: dict[str, _Stored]
    first_stop: uuid.UUID  # the editor's chat whose first message was stopped
    first_stop_message: _Stored
    colleague: uuid.UUID  # org A viewer's failed chat
    other_org: uuid.UUID  # org B editor's failed chat
    trashed: uuid.UUID  # the editor's trashed failed chat

    @property
    def db(self) -> FakeDb:
        return self.world.db

    @property
    def editor(self) -> TenantContext:
        """The org A editor's own tenant."""
        return _tenant(self.world.org_a, self.world.a["editor"].user_id)

    def seq(self, label: str) -> int:
        """The seq of one of the main chat's messages."""
        return self.main_messages[label].seq


def _tenant(org_id: uuid.UUID, user_id: uuid.UUID) -> TenantContext:
    return TenantContext(org_id=org_id, user_id=user_id, role="editor")


def _seq_of(db: FakeDb, chat_id: uuid.UUID, message_id: uuid.UUID) -> int:
    return next(
        int(row["seq"]) for row in db.messages_of(chat_id) if _plain(row["id"]) == message_id
    )


def _seed(db: FakeDb, chat_id: uuid.UUID, specs: tuple[_Spec, ...]) -> dict[str, _Stored]:
    """Store the specs in order (as the server stores turns); their ids and seqs by label."""
    stored: dict[str, _Stored] = {}
    for label, role, content, status, extra in specs:
        message_id = db.add_chat_message(chat_id, role, content, status=status, **extra)
        stored[label] = _Stored(message_id, _seq_of(db, chat_id, message_id))
    return stored


def _failed_chat(db: FakeDb, owner: Any, **chat: Any) -> uuid.UUID:
    """A chat of ``owner`` whose last answer failed (a target, were it the caller's)."""
    chat_id = db.add_chat(owner, title=TITLE_CANARY, title_source="user", **chat)
    _seed(db, chat_id, _TARGET_SHAPES["error-answer"][0])
    return chat_id


@pytest.fixture()
def seeded() -> _Seeded:
    db = FakeDb()
    world = build_world(db)
    editor = world.a["editor"].user_id

    main = db.add_chat(
        editor,
        title=TITLE_CANARY,
        title_source="user",
        external_content=True,
        created_at=_PAST,
        last_activity_at=_PAST,
    )
    main_messages = _seed(db, main, _MAIN)
    q2 = main_messages["q2"].id

    def add(chat_id: uuid.UUID, **values: Any) -> None:
        db.add_attachment(chat_id, kind="pdf", status="ready", **values)

    # Stored out of the expected order on purpose (see TURN_FILES).
    add(
        main,
        attachment_id=FILE_EXCLUDED,
        filename="excluded.pdf",
        message_id=q2,
        created_at=_T2,
        active=False,
    )
    add(main, attachment_id=FILE_B, filename="b.pdf", message_id=q2, created_at=_T2)
    add(main, attachment_id=FILE_A, filename=FILE_CANARY, message_id=q2, created_at=_T1)
    add(
        main,
        attachment_id=FILE_OLD,
        filename="old.pdf",
        message_id=main_messages["q0"].id,
        created_at=_T0,
    )
    add(
        main,
        attachment_id=FILE_TRASHED,
        filename="trashed.pdf",
        message_id=q2,
        created_at=_T0,
        deleted_at=_T2,
    )
    add(main, attachment_id=FILE_UNSENT, filename="unsent.pdf", created_at=_T0)

    user_stop = db.add_chat(editor, title="User stop", title_source="user")
    user_stop_messages = _seed(db, user_stop, _TARGET_SHAPES["stopped-on-the-user-row"][0])
    add(
        user_stop,
        attachment_id=FILE_STOPPED,
        filename="stopped.pdf",
        message_id=user_stop_messages["u2"].id,
        created_at=_T0,
    )

    first_stop = seed_chat(db, editor)
    (first_stop_message,) = _seed(
        db, first_stop, (("u1", "user", MESSAGE_CANARY, "stopped", {}),)
    ).values()

    return _Seeded(
        world=world,
        main=main,
        main_messages=main_messages,
        user_stop=user_stop,
        user_stop_messages=user_stop_messages,
        first_stop=first_stop,
        first_stop_message=first_stop_message,
        colleague=_failed_chat(db, world.a["viewer"].user_id),
        other_org=_failed_chat(db, world.b["editor"].user_id),
        trashed=_failed_chat(db, editor, deleted_at=_T0),
    )


def _shape_chat(seeded: _Seeded, specs: tuple[_Spec, ...]) -> tuple[uuid.UUID, dict[str, _Stored]]:
    """A new chat of the editor with these messages."""
    chat_id = seeded.db.add_chat(seeded.world.a["editor"].user_id, title="Shape")
    return chat_id, _seed(seeded.db, chat_id, specs)


_REFUSED_CASES: Final = (
    "colleague-chat",
    "other-org-chat",
    "forged-org-own-chat",
    "trashed-own-chat",
    "unknown-chat",
)


def _refused(seeded: _Seeded, case: str) -> tuple[TenantContext, uuid.UUID]:
    world = seeded.world
    return {
        "colleague-chat": (seeded.editor, seeded.colleague),
        "other-org-chat": (seeded.editor, seeded.other_org),
        "forged-org-own-chat": (_tenant(world.org_b, world.a["editor"].user_id), seeded.main),
        "trashed-own-chat": (seeded.editor, seeded.trashed),
        "unknown-chat": (seeded.editor, UNKNOWN_CHAT),
    }[case]


def _new_turn(message: str = MESSAGE_CANARY, answer: str = "Fresh answer") -> list[LLMMessage]:
    """A retry's new messages: the re-stored user message and a plain answer."""
    return [
        LLMMessage(role="user", content=message),
        LLMMessage(role="assistant", content=answer),
    ]


def _tool_turn() -> list[LLMMessage]:
    """A retry's new messages with a tool call between the user message and the answer."""
    return [
        LLMMessage(role="user", content=MESSAGE_CANARY),
        LLMMessage(role="assistant", content="Checking again.", tool_use_blocks=[MEMORY_CALL]),
        LLMMessage(role="tool", content="one note", tool_call_id="call_mem_2"),
        LLMMessage(role="assistant", content="You have one note."),
    ]


def _history(*specs: _Spec) -> list[LLMMessage]:
    """The LLMMessages a history holds for these seeded messages."""
    return [
        LLMMessage(
            role=role,
            content=content,
            tool_call_id=extra.get("tool_call_id"),
            tool_use_blocks=extra.get("tool_use_blocks"),
        )
        for _, role, content, _, extra in specs
    ]


def _main(*labels: str) -> tuple[_Spec, ...]:
    by_label = {spec[0]: spec for spec in _MAIN}
    return tuple(by_label[label] for label in labels)


def _contents(db: FakeDb, chat_id: uuid.UUID) -> list[tuple[str, str, str]]:
    return [(row["role"], row["content"], row["status"]) for row in db.messages_of(chat_id)]


def _file_rows(db: FakeDb, chat_id: uuid.UUID) -> dict[uuid.UUID, dict[str, Any]]:
    return {_plain(row["id"]): row for row in db.attachments_of(chat_id)}


# ---------------------------------------------------------------------------
# 1. Surface
# ---------------------------------------------------------------------------


def test_chats_retry_retryable_statuses_are_error_and_stopped(chats: ModuleType) -> None:
    statuses = chats.RETRYABLE_STATUSES

    assert type(statuses) is frozenset
    assert statuses == frozenset({"error", "stopped"})


def test_chats_retry_target_is_a_frozen_dataclass_of_the_contract_fields(
    chats: ModuleType,
) -> None:
    cls = chats.RetryTarget

    assert dataclasses.is_dataclass(cls)
    assert [field.name for field in dataclasses.fields(cls)] == [
        "through_seq",
        "status",
        "user_seq",
        "message",
        "attachment_ids",
    ]
    assert cls.__dataclass_params__.frozen is True


def test_chats_retry_read_retry_target_is_a_coroutine_of_executor_tenant_and_chat(
    chats: ModuleType,
) -> None:
    assert inspect.iscoroutinefunction(chats.read_retry_target)
    assert list(inspect.signature(chats.read_retry_target).parameters) == [
        "executor",
        "tenant",
        "chat_id",
    ]


@pytest.mark.parametrize(
    ("function", "keyword"), [("load_turn", "before_seq"), ("append_messages", "replace_through")]
)
def test_chats_retry_new_keyword_is_keyword_only_and_defaults_to_none(
    chats: ModuleType, function: str, keyword: str
) -> None:
    parameter = inspect.signature(getattr(chats, function)).parameters[keyword]

    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is None


def test_chats_retry_docstrings_name_what_gh245_adds(chats: ModuleType) -> None:
    """Contract C2: the module docstring and the touched functions' say what GH-245 adds."""
    assert "GH-245" in (chats.__doc__ or "")
    assert "read_retry_target" in (chats.__doc__ or "")
    assert (chats.read_retry_target.__doc__ or "").strip()
    assert "before_seq" in (chats.load_turn.__doc__ or "")
    assert "replace_through" in (chats.append_messages.__doc__ or "")


# ---------------------------------------------------------------------------
# 2. read_retry_target: one statement (R1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", ["target", "not-retryable", "refused"])
async def test_chats_retry_read_runs_exactly_r1_bound_to_chat_org_and_owner(
    chats: ModuleType, seeded: _Seeded, case: str
) -> None:
    """One fetchrow of R1's exact text, (chat, org, owner) in that order, whatever the answer."""
    db = seeded.db
    chat_id = {
        "target": seeded.main,
        "not-retryable": seed_chat(db, seeded.world.a["editor"]),
        "refused": seeded.colleague,
    }[case]
    before = len(db.calls)

    try:
        await chats.read_retry_target(db.pool, seeded.editor, chat_id)
    except chats.ChatNotFoundError:
        assert case == "refused"

    calls = db.calls[before:]
    assert [(call.method, _form(call)) for call in calls] == [("fetchrow", "R1")]
    args = calls[0].args
    assert len(args) == 3, args
    assert _same_uuid(args[0], chat_id)
    assert _same_uuid(args[1], seeded.editor.org_id)
    assert _same_uuid(args[2], seeded.editor.user_id)


async def test_chats_retry_read_writes_nothing(chats: ModuleType, seeded: _Seeded) -> None:
    db = seeded.db
    before = db.snapshot()
    transactions = list(db.transactions)

    await chats.read_retry_target(db.pool, seeded.editor, seeded.main)

    assert db.snapshot() == before
    assert db.transactions == transactions
    assert db.open_transactions == 0


# ---------------------------------------------------------------------------
# 3. read_retry_target: when a chat can be retried (Decision 1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", list(_TARGET_SHAPES))
async def test_chats_retry_read_failed_latest_message_is_a_target(
    chats: ModuleType, seeded: _Seeded, shape: str
) -> None:
    """The latest message (any role) ended error/stopped: the latest user row is retried."""
    specs, through, status, user = _TARGET_SHAPES[shape]
    chat_id, stored = _shape_chat(seeded, specs)

    target = await chats.read_retry_target(seeded.db.pool, seeded.editor, chat_id)

    assert target == chats.RetryTarget(
        through_seq=stored[through].seq,
        status=status,
        user_seq=stored[user].seq,
        message=MESSAGE_CANARY,
        attachment_ids=(),
    )


@pytest.mark.parametrize("shape", list(_NOT_RETRYABLE_SHAPES))
async def test_chats_retry_read_chat_without_a_failed_last_answer_is_none(
    chats: ModuleType, seeded: _Seeded, shape: str
) -> None:
    chat_id, _ = _shape_chat(seeded, _NOT_RETRYABLE_SHAPES[shape])

    assert await chats.read_retry_target(seeded.db.pool, seeded.editor, chat_id) is None


async def test_chats_retry_read_target_carries_the_failed_messages_files_in_upload_order(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """The latest user row's live files, excluded ones too, by created_at then id; another
    message's, an unsent and a trashed file of the chat are not the turn's."""
    target = await chats.read_retry_target(seeded.db.pool, seeded.editor, seeded.main)

    assert target == chats.RetryTarget(
        through_seq=seeded.seq("a4"),
        status="error",
        user_seq=seeded.seq("q2"),
        message=MESSAGE_CANARY,
        attachment_ids=TURN_FILES,
    )


async def test_chats_retry_read_target_values_are_plain_python_types(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """Contract C2: ints, the status and message strings, a tuple of plain UUIDs."""
    target = await chats.read_retry_target(seeded.db.pool, seeded.editor, seeded.main)

    assert (type(target.through_seq), type(target.user_seq)) == (int, int)
    assert (type(target.status), type(target.message)) == (str, str)
    assert type(target.attachment_ids) is tuple
    assert [type(file_id) for file_id in target.attachment_ids] == [uuid.UUID] * 3


async def test_chats_retry_read_stop_on_the_user_row_carries_its_files(
    chats: ModuleType, seeded: _Seeded
) -> None:
    stored = seeded.user_stop_messages

    target = await chats.read_retry_target(seeded.db.pool, seeded.editor, seeded.user_stop)

    assert target == chats.RetryTarget(
        through_seq=stored["u2"].seq,
        status="stopped",
        user_seq=stored["u2"].seq,
        message=MESSAGE_CANARY,
        attachment_ids=(FILE_STOPPED,),
    )


@pytest.mark.parametrize("case", _REFUSED_CASES)
async def test_chats_retry_read_refuses_any_chat_but_the_callers_own_live_one(
    chats: ModuleType, seeded: _Seeded, case: str
) -> None:
    """One error for all (Decision 4: the 404 chat_not_found), after one statement."""
    tenant, chat_id = _refused(seeded, case)
    db = seeded.db
    before = db.snapshot()
    calls_before = len(db.calls)

    with pytest.raises(chats.ChatNotFoundError) as caught:
        await chats.read_retry_target(db.pool, tenant, chat_id)

    assert type(caught.value) is chats.ChatNotFoundError
    assert str(caught.value) == str(chats.ChatNotFoundError())
    assert len(db.calls) - calls_before == 1
    assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 4. load_turn(before_seq=n): the window before the retried message (T2b)
# ---------------------------------------------------------------------------


async def test_chats_retry_load_turn_before_seq_runs_t2b_with_five_binds(
    chats: ModuleType, seeded: _Seeded
) -> None:
    db = seeded.db
    before = len(db.calls)

    await chats.load_turn(db.pool, seeded.editor, seeded.main, limit=7, before_seq=seeded.seq("q2"))

    calls = db.calls[before:]
    assert [(call.method, _form(call)) for call in calls] == [("fetch", "T2b")]
    args = calls[0].args
    assert len(args) == 5, args
    assert _same_uuid(args[0], seeded.main)
    assert _same_uuid(args[1], seeded.editor.org_id)
    assert _same_uuid(args[2], seeded.editor.user_id)
    assert (type(args[3]), args[3]) == (int, 7)
    assert (type(args[4]), args[4]) == (int, seeded.seq("q2"))


# limit -> the history before q2: the latest ``limit`` messages before it, leading tool
# rows dropped (never q2 or the failed answer, whatever the limit).
_WINDOWS: Final[dict[int, tuple[str, ...]]] = {
    50: _MAIN_KEPT,
    4: ("q1", "a1", "t1", "a2"),
    3: ("a1", "t1", "a2"),
    2: ("a2",),
    1: ("a2",),
}


@pytest.mark.parametrize("limit", list(_WINDOWS))
async def test_chats_retry_load_turn_before_seq_history_is_the_window_before_the_retried_message(
    chats: ModuleType, seeded: _Seeded, limit: int
) -> None:
    turn = await chats.load_turn(
        seeded.db.pool, seeded.editor, seeded.main, limit=limit, before_seq=seeded.seq("q2")
    )

    assert turn.history == _history(*_main(*_WINDOWS[limit]))
    assert turn.chat == await chats.get_chat(seeded.db.pool, seeded.editor, seeded.main)


async def test_chats_retry_load_turn_before_the_first_message_is_an_empty_history(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """A retried first message: no history, and the chat is still found (one NULL row)."""
    turn = await chats.load_turn(
        seeded.db.pool,
        seeded.editor,
        seeded.first_stop,
        limit=50,
        before_seq=seeded.first_stop_message.seq,
    )

    assert turn.history == []
    assert turn.chat == await chats.get_chat(seeded.db.pool, seeded.editor, seeded.first_stop)


async def test_chats_retry_load_turn_before_seq_keeps_the_chats_active_attachments(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """Decision 3: the run gets the chat's active files, the retried message's included
    (T2'''s order and filters: excluded and trashed files left out), whatever the bound."""
    pool, editor = seeded.db.pool, seeded.editor

    bounded = await chats.load_turn(pool, editor, seeded.main, limit=1, before_seq=seeded.seq("q2"))
    unbounded = await chats.load_turn(pool, editor, seeded.main, limit=50)

    assert [attachment.id for attachment in bounded.attachments] == [FILE_OLD, FILE_A, FILE_B]
    assert bounded.attachments == unbounded.attachments


async def test_chats_retry_load_turn_without_before_seq_runs_exactly_t2_second(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """None (explicit or omitted) is today's turn read: T2'' and its four binds."""
    db = seeded.db
    before = len(db.calls)

    explicit = await chats.load_turn(db.pool, seeded.editor, seeded.main, limit=7, before_seq=None)
    omitted = await chats.load_turn(db.pool, seeded.editor, seeded.main, limit=7)

    calls = db.calls[before:]
    assert [(call.method, _form(call)) for call in calls] == [("fetch", "T2''")] * 2
    assert [len(call.args) for call in calls] == [4, 4]
    assert explicit == omitted
    assert [message.content for message in explicit.history][-2:] == ["no notes", ANSWER_CANARY]


@pytest.mark.parametrize("case", _REFUSED_CASES)
async def test_chats_retry_load_turn_before_seq_refuses_any_chat_but_the_callers_own_live_one(
    chats: ModuleType, seeded: _Seeded, case: str
) -> None:
    tenant, chat_id = _refused(seeded, case)
    db = seeded.db
    before = db.snapshot()
    calls_before = len(db.calls)

    with pytest.raises(chats.ChatNotFoundError) as caught:
        await chats.load_turn(db.pool, tenant, chat_id, limit=20, before_seq=seeded.seq("q2"))

    assert type(caught.value) is chats.ChatNotFoundError
    assert str(caught.value) == str(chats.ChatNotFoundError())
    assert len(db.calls) - calls_before == 1
    assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 5. append_messages(replace_through=n): the replacing store (R2, Decision 2)
# ---------------------------------------------------------------------------


async def test_chats_retry_append_runs_touch_then_delete_failed_turn_then_inserts_in_one_tx(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """S7, R2 (fetchval, (chat, org, owner, n)), then the inserts with A9 right after the
    user message, all on one connection inside one committed transaction."""
    db = seeded.db
    before = len(db.calls)

    await chats.append_messages(
        db.pool,
        seeded.editor,
        seeded.main,
        _tool_turn(),
        attachment_ids=TURN_FILES,
        replace_through=seeded.seq("a4"),
    )

    calls = db.calls[before:]
    assert [_form(call) for call in calls] == ["S7", "R2", "S8", "A9", "S8", "S8", "S8"]
    function = calls[1]
    assert function.method == "fetchval"
    assert len(function.args) == 4, function.args
    assert _same_uuid(function.args[0], seeded.main)
    assert _same_uuid(function.args[1], seeded.editor.org_id)
    assert _same_uuid(function.args[2], seeded.editor.user_id)
    assert (type(function.args[3]), function.args[3]) == (int, seeded.seq("a4"))
    assert {(call.via, call.tx) for call in calls} == {(calls[0].via, calls[0].tx)}
    assert calls[0].via != "pool"
    assert calls[0].tx is not None
    assert db.transactions[-1] == (calls[0].tx, "commit")


@pytest.mark.parametrize("shape", list(_TARGET_SHAPES))
async def test_chats_retry_append_replaces_the_failed_turn_with_the_new_one(
    chats: ModuleType, seeded: _Seeded, shape: str
) -> None:
    """Every row from the latest user message through n is gone; the kept rows are as
    they were; the re-stored user message and the answer follow, after the failed turn's
    seqs; the last row's id is returned."""
    specs, through, _, user = _TARGET_SHAPES[shape]
    chat_id, stored = _shape_chat(seeded, specs)
    db = seeded.db
    kept = [row for row in db.messages_of(chat_id) if row["seq"] < stored[user].seq]

    last_id = await chats.append_messages(
        db.pool, seeded.editor, chat_id, _new_turn(), replace_through=stored[through].seq
    )

    rows = db.messages_of(chat_id)
    assert rows[: len(kept)] == kept
    assert [(row["role"], row["content"], row["status"]) for row in rows[len(kept) :]] == [
        ("user", MESSAGE_CANARY, "complete"),
        ("assistant", "Fresh answer", "complete"),
    ]
    assert all(row["seq"] > stored[through].seq for row in rows[len(kept) :])
    assert _plain(last_id) == _plain(rows[-1]["id"])


async def test_chats_retry_append_stores_the_runs_status_and_tool_calls_on_the_last_row(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """A retry that fails again stores like a turn: its status on the last new row."""
    from admino.models import ToolCallRecord

    db = seeded.db
    calls = [
        ToolCallRecord(
            tool="memory", action="list", args={}, permission="allow", success=True, duration_ms=3
        )
    ]

    await chats.append_messages(
        db.pool,
        seeded.editor,
        seeded.main,
        _tool_turn(),
        final_status="stopped",
        tool_calls=calls,
        replace_through=seeded.seq("a4"),
    )

    rows = db.messages_of(seeded.main)
    assert [row["status"] for row in rows[len(_MAIN_KEPT) :]] == ["complete"] * 3 + ["stopped"]
    assert rows[-1]["tool_calls"] == [calls[0].model_dump(mode="json")]
    assert [row["tool_calls"] for row in rows[len(_MAIN_KEPT) : -1]] == [None] * 3


# ---------------------------------------------------------------------------
# 5b. The failed answer's partial is stored with it (C1'b, GH-25 D9)
# ---------------------------------------------------------------------------

_FINAL_STATUSES: Final = ("complete", "stopped", "awaiting_confirmation", "limit_reached")


def _d9_turn(partial_blocks: list[dict[str, Any]] | None = None) -> list[LLMMessage]:
    """A run's new messages ending in an error reply: the user message, a tool call and
    its result, the text a streamed call showed before it timed out (no tool_use blocks:
    None or ``[]``), then the error reply."""
    return [
        LLMMessage(role="user", content=MESSAGE_CANARY),
        LLMMessage(role="assistant", content="Checking again.", tool_use_blocks=[MEMORY_CALL]),
        LLMMessage(role="tool", content="one note", tool_call_id="call_mem_2"),
        LLMMessage(role="assistant", content="Day one: Zurich ", tool_use_blocks=partial_blocks),
        LLMMessage(role="assistant", content=ANSWER_CANARY),
    ]


@pytest.mark.parametrize("blocks", [None, []], ids=["null-blocks", "empty-blocks"])
async def test_chats_retry_append_error_run_stores_its_blockless_partial_as_error(
    chats: ModuleType, seeded: _Seeded, blocks: list[dict[str, Any]] | None
) -> None:
    """C1'b: final_status "error": the non-last assistant message without tool_use blocks
    (the D9 partial) is stored ``error``, part of the failed answer; the user message,
    the assistant message with a tool_use block and the tool result stay ``complete``;
    the error reply (last) carries ``error`` as before."""
    db = seeded.db
    chat_id, _ = _shape_chat(seeded, (_U1, _A1))

    await chats.append_messages(
        db.pool, seeded.editor, chat_id, _d9_turn(blocks), final_status="error"
    )

    rows = db.messages_of(chat_id)[2:]
    assert [(row["role"], row["status"]) for row in rows] == [
        ("user", "complete"),
        ("assistant", "complete"),
        ("tool", "complete"),
        ("assistant", "error"),
        ("assistant", "error"),
    ]


async def test_chats_retry_append_only_an_error_run_marks_a_blockless_partial(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """C1'b: the rule is the error run's alone. The same messages stored with every
    other final status keep every non-last row ``complete`` (the last row gets the
    status); with ``error`` the blockless non-last answer is ``error`` too."""
    db = seeded.db
    stored: dict[str, list[str]] = {}
    for status in ("error", *_FINAL_STATUSES):
        chat_id, _ = _shape_chat(seeded, (_U1, _A1))
        await chats.append_messages(
            db.pool, seeded.editor, chat_id, _d9_turn(), final_status=status
        )
        stored[status] = [row["status"] for row in db.messages_of(chat_id)[2:]]

    assert stored == {
        "error": ["complete", "complete", "complete", "error", "error"],
        **{status: ["complete"] * 4 + [status] for status in _FINAL_STATUSES},
    }


async def test_chats_retry_append_retry_that_timed_out_after_text_can_be_retried_again(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """C1'b with Decision 2: the retry of the main chat's failed turn times out after
    text, so its new turn is stored ``U A(partial, error) A(error)`` in place of the old
    one; that turn is the next target (the error reply, the same message and files) and
    the next retry replaces it, leaving only the kept rows and the newest turn."""
    db, pool, editor = seeded.db, seeded.db.pool, seeded.editor
    kept = [row for row in db.messages_of(seeded.main) if row["seq"] < seeded.seq("q2")]
    timed_out = [
        LLMMessage(role="user", content=MESSAGE_CANARY),
        LLMMessage(role="assistant", content="Day one: Zurich "),
        LLMMessage(role="assistant", content=ANSWER_CANARY),
    ]

    await chats.append_messages(
        pool,
        editor,
        seeded.main,
        timed_out,
        final_status="error",
        attachment_ids=TURN_FILES,
        replace_through=seeded.seq("a4"),
    )
    failed = [(row["role"], row["status"]) for row in db.messages_of(seeded.main)[len(kept) :]]
    target = await chats.read_retry_target(pool, editor, seeded.main)
    await chats.append_messages(
        pool,
        editor,
        seeded.main,
        _new_turn(target.message, "Done."),
        attachment_ids=target.attachment_ids,
        replace_through=target.through_seq,
    )

    rows = db.messages_of(seeded.main)
    assert failed == [("user", "complete"), ("assistant", "error"), ("assistant", "error")]
    assert (target.status, target.message, target.attachment_ids) == (
        "error",
        MESSAGE_CANARY,
        TURN_FILES,
    )
    assert rows[: len(kept)] == kept
    assert [(row["role"], row["content"], row["status"]) for row in rows[len(kept) :]] == [
        ("user", MESSAGE_CANARY, "complete"),
        ("assistant", "Done.", "complete"),
    ]


@pytest.mark.parametrize("chat", ["main", "user_stop"])
async def test_chats_retry_append_moves_the_turns_files_to_the_new_user_message(
    chats: ModuleType, seeded: _Seeded, chat: str
) -> None:
    """Decision 2: the files move to the re-stored user row and are never deleted; no
    column of any file of the chat changes but the link and its stamp, and the first
    message's and the unsent file keep their link."""
    db = seeded.db
    chat_id = getattr(seeded, chat)
    files, through = {
        "main": (TURN_FILES, seeded.seq("a4")),
        "user_stop": ((FILE_STOPPED,), seeded.user_stop_messages["u2"].seq),
    }[chat]
    before = _file_rows(db, chat_id)

    await chats.append_messages(
        db.pool,
        seeded.editor,
        chat_id,
        _new_turn(),
        attachment_ids=files,
        replace_through=through,
    )

    after = _file_rows(db, chat_id)
    new_user = next(row for row in reversed(db.messages_of(chat_id)) if row["role"] == "user")
    assert after.keys() == before.keys()
    assert {file_id: _plain(after[file_id]["message_id"]) for file_id in files} == dict.fromkeys(
        files, _plain(new_user["id"])
    )
    moved = ("message_id", "updated_at")
    assert {
        file_id: {key: value for key, value in row.items() if key not in moved}
        for file_id, row in after.items()
    } == {
        file_id: {key: value for key, value in row.items() if key not in moved}
        for file_id, row in before.items()
    }
    # The first message's file and the unsent one stay where they were.
    untouched = after.keys() & {FILE_OLD, FILE_UNSENT}
    assert {file_id: after[file_id]["message_id"] for file_id in untouched} == {
        file_id: before[file_id]["message_id"] for file_id in untouched
    }


async def test_chats_retry_append_bumps_activity_and_never_clears_external_content(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """Decision 3: the sticky flag (migration 0025) survives the replaced turn."""
    db = seeded.db

    await chats.append_messages(
        db.pool, seeded.editor, seeded.main, _new_turn(), replace_through=seeded.seq("a4")
    )

    chat = db.chat_row(seeded.main)
    assert chat is not None
    assert chat["last_activity_at"] > _PAST
    assert chat["external_content"] is True


async def test_chats_retry_append_keeps_an_org_notice_stored_after_the_failed_answer(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """A notice that landed during the retry run stays, before the new turn."""
    chat_id, stored = _shape_chat(
        seeded, (*_TARGET_SHAPES["error-answer"][0], ("n1", "user", NOTICE, "complete", {}))
    )
    db = seeded.db
    notice = next(row for row in db.messages_of(chat_id) if row["content"] == NOTICE)

    await chats.append_messages(
        db.pool, seeded.editor, chat_id, _new_turn(), replace_through=stored["a2"].seq
    )

    rows = db.messages_of(chat_id)
    assert [(row["role"], row["content"]) for row in rows] == [
        ("user", "First question"),
        ("assistant", "First answer"),
        ("user", NOTICE),
        ("user", MESSAGE_CANARY),
        ("assistant", "Fresh answer"),
    ]
    assert rows[2] == notice


@pytest.mark.parametrize("case", ["complete-row", "another-chats-failed-row"])
async def test_chats_retry_append_refused_turn_raises_and_changes_nothing(
    chats: ModuleType, seeded: _Seeded, case: str
) -> None:
    """The function's refusal propagates and rolls everything back: no row deleted, none
    inserted, no file linked."""
    db = seeded.db
    complete_chat, stored = _shape_chat(seeded, (_U1, _A1))
    chat_id, through = {
        "complete-row": (complete_chat, stored["a1"].seq),
        "another-chats-failed-row": (complete_chat, seeded.seq("a4")),
    }[case]
    before = db.snapshot()
    calls_before = len(db.calls)

    with pytest.raises(asyncpg.InsufficientPrivilegeError) as caught:
        await chats.append_messages(
            db.pool,
            seeded.editor,
            chat_id,
            _new_turn(),
            attachment_ids=(FILE_UNSENT,),
            replace_through=through,
        )

    calls = db.calls[calls_before:]
    assert [_form(call) for call in calls] == ["S7", "R2"]
    assert db.snapshot() == before
    assert db.transactions[-1] == (calls[0].tx, "rollback:InsufficientPrivilegeError")
    assert MESSAGE_CANARY not in str(caught.value)


async def test_chats_retry_append_forged_error_after_a_completed_turn_is_refused(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """C1' (security audit M-1): an ``error`` row stored after a completed tool turn (an
    INSERT is all a compromised runtime role needs) makes the chat's latest row look
    failed, but the replacing store is refused: InsufficientPrivilegeError, the
    transaction rolled back, nothing deleted, inserted or linked (the turn's file stays on
    its user row)."""
    db = seeded.db
    chat_id, stored = _shape_chat(
        seeded,
        (
            _U1,
            _A1,
            ("u2", "user", MESSAGE_CANARY, "complete", {}),
            ("a2", "assistant", "Checking.", "complete", {"tool_use_blocks": [CALENDAR_CALL]}),
            ("t2", "tool", TOOL_CANARY, "complete", {"tool_call_id": "call_cal_1"}),
            ("a3", "assistant", "You see the dentist on Monday.", "complete", {}),
            ("forged", "assistant", ANSWER_CANARY, "error", {}),
        ),
    )
    file_id = db.add_attachment(
        chat_id, kind="pdf", status="ready", message_id=stored["u2"].id, created_at=_T1
    )
    target = await chats.read_retry_target(db.pool, seeded.editor, chat_id)
    before = db.snapshot()
    calls_before = len(db.calls)

    with pytest.raises(asyncpg.InsufficientPrivilegeError) as caught:
        await chats.append_messages(
            db.pool,
            seeded.editor,
            chat_id,
            _new_turn(),
            attachment_ids=(file_id,),
            replace_through=stored["forged"].seq,
        )

    calls = db.calls[calls_before:]
    assert (target.through_seq, target.status) == (stored["forged"].seq, "error")
    assert [_form(call) for call in calls] == ["S7", "R2"]
    assert db.snapshot() == before
    assert db.transactions[-1] == (calls[0].tx, "rollback:InsufficientPrivilegeError")
    assert str(caught.value) == "only a failed turn of a live chat can be deleted"


@pytest.mark.parametrize(
    "case", ["trashed-own-chat", "colleague-chat", "other-org-chat", "unknown-chat"]
)
async def test_chats_retry_append_unreachable_chat_is_not_found_before_the_function(
    chats: ModuleType, seeded: _Seeded, case: str
) -> None:
    """The touch refuses first: delete_failed_turn is never called, nothing is written."""
    tenant, chat_id = _refused(seeded, case)
    db = seeded.db
    before = db.snapshot()
    calls_before = len(db.calls)

    with pytest.raises(chats.ChatNotFoundError):
        await chats.append_messages(
            db.pool, tenant, chat_id, _new_turn(), replace_through=seeded.seq("a4")
        )

    calls = db.calls[calls_before:]
    assert [_form(call) for call in calls] == ["S7"]
    assert db.matching(r"delete_failed_turn") == []
    assert db.snapshot() == before


@pytest.mark.parametrize(
    "messages",
    [
        pytest.param([], id="no-messages"),
        pytest.param([LLMMessage(role="assistant", content="Fresh answer")], id="answer-only"),
        pytest.param(
            [
                LLMMessage(role="tool", content="cancelled", tool_call_id="call_mem_2"),
                LLMMessage(role="assistant", content="Fresh answer"),
            ],
            id="tool-and-answer",
        ),
    ],
)
async def test_chats_retry_append_replacement_without_a_user_message_is_a_value_error(
    chats: ModuleType, seeded: _Seeded, messages: list[LLMMessage]
) -> None:
    """A replaced turn is always re-stored: refused before any statement."""
    db = seeded.db
    before = db.snapshot()
    calls_before = len(db.calls)

    with pytest.raises(ValueError) as caught:
        await chats.append_messages(
            db.pool, seeded.editor, seeded.main, messages, replace_through=seeded.seq("a4")
        )

    assert type(caught.value) is ValueError
    assert db.calls[calls_before:] == []
    assert db.snapshot() == before


async def test_chats_retry_append_without_replace_through_runs_todays_statements(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """None (explicit or omitted) appends as today: no function call, nothing deleted."""
    db = seeded.db
    statements: list[list[tuple[str, str]]] = []
    for keywords in ({"replace_through": None}, {}):
        chat_id = seed_chat(
            db, seeded.world.a["editor"], messages=[("user", "Hi"), ("assistant", "Hello")]
        )
        unsent = db.add_attachment(chat_id, status="ready")
        before = len(db.calls)
        await chats.append_messages(
            db.pool, seeded.editor, chat_id, _new_turn(), attachment_ids=(unsent,), **keywords
        )
        statements.append([(call.method, _form(call)) for call in db.calls[before:]])
        assert [content for _, content, _ in _contents(db, chat_id)] == [
            "Hi",
            "Hello",
            MESSAGE_CANARY,
            "Fresh answer",
        ]

    today = [("fetchval", "S7"), ("fetchval", "S8"), ("execute", "A9"), ("fetchval", "S8")]
    assert statements == [today, today]


# ---------------------------------------------------------------------------
# 6. A retry of a retry, through the three functions
# ---------------------------------------------------------------------------


async def test_chats_retry_retried_turn_can_fail_again_and_be_retried(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """Decision 2: V1 keeps nothing of a failed turn; each retry replaces the last one."""
    db, pool, editor = seeded.db, seeded.db.pool, seeded.editor
    kept = [row for row in db.messages_of(seeded.main) if row["seq"] < seeded.seq("q2")]

    first = await chats.read_retry_target(pool, editor, seeded.main)
    turn = await chats.load_turn(pool, editor, seeded.main, limit=50, before_seq=first.user_seq)
    await chats.append_messages(
        pool,
        editor,
        seeded.main,
        _new_turn(first.message, "Failed again"),
        final_status="error",
        attachment_ids=first.attachment_ids,
        replace_through=first.through_seq,
    )
    second = await chats.read_retry_target(pool, editor, seeded.main)
    await chats.append_messages(
        pool,
        editor,
        seeded.main,
        _new_turn(second.message, "Done."),
        attachment_ids=second.attachment_ids,
        replace_through=second.through_seq,
    )

    rows = db.messages_of(seeded.main)
    assert turn.history == _history(*_main(*_MAIN_KEPT))
    assert (second.status, second.message, second.attachment_ids) == (
        "error",
        MESSAGE_CANARY,
        TURN_FILES,
    )
    assert second.user_seq > first.through_seq
    assert rows[: len(kept)] == kept
    assert [(row["role"], row["content"], row["status"]) for row in rows[len(kept) :]] == [
        ("user", MESSAGE_CANARY, "complete"),
        ("assistant", "Done.", "complete"),
    ]
    assert await chats.read_retry_target(pool, editor, seeded.main) is None
    assert {
        _plain(_file_rows(db, seeded.main)[file_id]["message_id"]) for file_id in TURN_FILES
    } == {_plain(rows[len(kept)]["id"])}


# ---------------------------------------------------------------------------
# 7. Tenant isolation (§5) and no content in logs or errors (§1)
# ---------------------------------------------------------------------------


async def test_chats_retry_every_statement_binds_the_callers_org_and_owner(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """Every statement binds the caller's org; each on the chat (R1, T2b, S7, R2) or a file
    (A9) binds the caller as owner; no colleague, other org or other chat is bound."""
    db, pool, editor = seeded.db, seeded.db.pool, seeded.editor
    world = seeded.world
    before = len(db.calls)

    target = await chats.read_retry_target(pool, editor, seeded.main)
    await chats.load_turn(pool, editor, seeded.main, limit=50, before_seq=target.user_seq)
    await chats.append_messages(
        pool,
        editor,
        seeded.main,
        _new_turn(),
        attachment_ids=target.attachment_ids,
        replace_through=target.through_seq,
    )

    calls = db.calls[before:]
    forms = [_form(call) for call in calls]
    assert forms == ["R1", "T2b", "S7", "R2", "S8", "A9", "S8"]
    bound = [{_plain(arg) for arg in call.args if isinstance(arg, uuid.UUID)} for call in calls]
    assert all(editor.org_id in uuids for uuids in bound)
    assert all(
        editor.user_id in uuids
        for form, uuids in zip(forms, bound, strict=True)
        if form in {"R1", "T2b", "S7", "R2", "A9"}
    )
    foreign = {
        world.org_b,
        world.a["viewer"].user_id,
        world.b["editor"].user_id,
        seeded.colleague,
        seeded.other_org,
        seeded.user_stop,
    }
    assert [uuids & foreign for uuids in bound] == [set()] * len(calls)


async def test_chats_retry_logs_and_errors_carry_no_content(
    chats: ModuleType, seeded: _Seeded
) -> None:
    """The retry's reads, store and refusals log no message, answer, tool output, file name
    or title (DEBUG, text), and no error text carries one."""
    pool, editor = seeded.db.pool, seeded.editor
    complete_chat, stored = _shape_chat(
        seeded, (_U1, ("a1", "assistant", ANSWER_CANARY, "complete", {}))
    )
    errors: list[str] = []
    with configured_logging("DEBUG", "text") as logs:
        target = await chats.read_retry_target(pool, editor, seeded.main)
        await chats.load_turn(pool, editor, seeded.main, limit=50, before_seq=target.user_seq)
        await chats.append_messages(
            pool,
            editor,
            seeded.main,
            _tool_turn(),
            attachment_ids=target.attachment_ids,
            replace_through=target.through_seq,
        )
        try:
            await chats.append_messages(
                pool, editor, complete_chat, _new_turn(), replace_through=stored["a1"].seq
            )
        except asyncpg.InsufficientPrivilegeError as exc:
            errors.append(str(exc))
        for case in _REFUSED_CASES:
            tenant, chat_id = _refused(seeded, case)
            with pytest.raises(chats.ChatNotFoundError) as caught:
                await chats.read_retry_target(pool, tenant, chat_id)
            errors.append(str(caught.value))
        with pytest.raises(ValueError) as refused:
            await chats.append_messages(
                pool, editor, seeded.main, [], replace_through=seeded.seq("a4")
            )
        errors.append(str(refused.value))
        logged = logs.text + "\n".join(record.getMessage() for record in logs.records)

    canaries = (MESSAGE_CANARY, ANSWER_CANARY, TOOL_CANARY, FILE_CANARY, TITLE_CANARY)
    assert len(errors) == len(_REFUSED_CASES) + 2
    assert [canary for canary in canaries if canary in logged] == []
    assert [canary for canary in canaries for error in errors if canary in error] == []
