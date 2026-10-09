"""Tests for admino.chats and attachments (GH-187, contract sections 2 and 3.4).

The real ``admino.chats`` repository runs against the in-memory ``chats``,
``chat_messages`` and ``attachments`` tables of tests/db_fakes.py (migration
0027: the composite chat foreign key, the message foreign key, the column-limited
UPDATE grant, the transaction snapshots). The fake applies only the predicates a
statement states, so an UPDATE without its chat, org, owner, ``message_id IS
NULL`` or ``deleted_at IS NULL`` filter changes rows it must not.

What these tests pin down:
- ``append_messages(..., attachment_ids=[...])`` (A9): the listed attachments
  are linked to the stored ``user`` message that carried them, never to the
  turn's last message, and their ``updated_at`` moves; the function still
  returns the turn's last message id. The link is ONE statement, exactly the
  contract's A9 form, bound to (that message's id, the ids, the chat, the
  caller's org, the caller as owner), run on the turn's connection inside its
  committed transaction, right after that message's INSERT and before the next
  one. Ids of another chat of the caller, a colleague's chat, another org's
  chat, a trashed attachment, one already linked to an earlier message and an
  unknown id are left exactly as they were, without an error (they no longer
  match). A failure after the link (a later INSERT) rolls the link back with
  the turn; a chat the caller can't reach (another org's, a colleague's, a
  trashed one) is ``ChatNotFoundError`` with nothing linked and no A9.
- The user message is the one linked even when the turn's stored messages
  start with the synthetic cancelled tool result of a dangling ``tool_use``
  (the server stores it before the new user message: tests/test_chat_turns_api.py);
  ids with no ``user`` message in the turn are a ``ValueError`` before any
  statement (contract gap, see the hand-back: section 3.4 says "the first
  message", which the server's own dangling-tool_use turn would break).
- No ``attachment_ids`` (left out, ``()``, ``[]``): exactly today's statements,
  none naming attachments.
- ``trash_chat`` (A10, GH-194's A10'): the chat's live attachments get
  ``deleted_at`` and the chat's id as their ``trash_group_id`` in the trash's
  transaction, on its connection, after the chat's UPDATE and before the
  ``chat.delete`` audit INSERT, with exactly GH-194's A10' form bound to (the
  chat, the caller's org). Attachments trashed earlier keep their
  ``deleted_at`` and their own trash group; the caller's other chats', colleagues' and other orgs'
  attachments are untouched; the files on disk stay (trash is ``deleted_at``,
  #194 purges). A failed audit write rolls the attachments back with the chat;
  a chat that isn't the caller's (or is trashed already) is ``ChatNotFoundError``
  with no A10 and no attachment changed.

No real PostgreSQL, no network: every statement goes to ``FakeDb``.

Security notes:
- Owner-private chats: linking and trashing never reach another user's or
  another org's attachment; the isolation lives in the SQL predicates.
- Nothing here reads, writes or names a file: trashing keeps the files.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import asyncpg
import pytest

from admino import organizations
from admino.access import Principal
from admino.audit_events import AuditRecordError
from admino.models import LLMMessage
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, Call, FakeDb, norm, plain

if TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP: Final = "203.0.113.87"
_PAST: Final = datetime(2026, 9, 1, 8, 0, 0, 250000, tzinfo=UTC)
_EARLIER_TRASH: Final = datetime(2026, 9, 2, 9, 30, 0, 125000, tzinfo=UTC)
_UNKNOWN_ATTACHMENT: Final = uuid.UUID("0b7e2f4a-58c1-4d3e-9a6f-1c2d3e4f5a6b")
_CANCELLED: Final = "Tool call cancelled: user sent a new message instead of confirming."

# Contract section 2, exact forms (whitespace free, tokens and order not).
_A9: Final = norm(
    "UPDATE attachments SET message_id = $1, updated_at = now()"
    " WHERE id = ANY($2::uuid[]) AND chat_id = $3 AND org_id = $4 AND owner_user_id = $5"
    " AND message_id IS NULL AND deleted_at IS NULL"
)
# GH-194 (contract section 5, A10'): the files join the chat's trash group.
_A10: Final = norm(
    "UPDATE attachments SET deleted_at = now(), trash_group_id = $1"
    " WHERE chat_id = $1 AND org_id = $2 AND deleted_at IS NULL"
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def chats() -> ModuleType:
    """admino.chats, imported per test."""
    from admino import chats as module

    return module


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


@dataclass(frozen=True)
class _Member:
    """A stored member and the TenantContext of their session."""

    user_id: uuid.UUID
    tenant: TenantContext


def _member(db: FakeDb, *, org_id: uuid.UUID = ORG_ID) -> _Member:
    user_id = db.add_account(org_id=org_id, role="editor")
    principal = Principal(user_id=user_id, kind="member", org_id=org_id, role="editor")
    return _Member(user_id, TenantContext.from_principal(principal))


@dataclass(frozen=True)
class _World:
    """Alice and Bob (ORG_ID), Carol (OTHER_ORG_ID), their chats and attachments.

    Alice's chat holds two unsent attachments (``fresh``, ``second``), one trashed
    earlier (``trashed``) and one sent with an earlier message (``sent``); every
    other chat holds one unsent attachment.
    """

    alice: _Member
    bob: _Member
    carol: _Member
    chat: uuid.UUID
    other_chat: uuid.UUID  # Alice's second live chat
    bob_chat: uuid.UUID
    carol_chat: uuid.UUID
    fresh: uuid.UUID
    second: uuid.UUID
    trashed: uuid.UUID
    sent: uuid.UUID
    earlier_message: uuid.UUID
    other_chat_file: uuid.UUID
    bob_file: uuid.UUID
    carol_file: uuid.UUID


def _world(db: FakeDb) -> _World:
    alice, bob, carol = _member(db), _member(db), _member(db, org_id=OTHER_ORG_ID)
    chat = db.add_chat(alice.user_id, title="Alice plans", created_at=_PAST)
    other_chat = db.add_chat(alice.user_id, title="Alice other", created_at=_PAST)
    bob_chat = db.add_chat(bob.user_id, title="Bob plans", created_at=_PAST)
    carol_chat = db.add_chat(carol.user_id, title="Carol plans", created_at=_PAST)
    earlier_message = db.add_chat_message(chat, "user", "Earlier, with a file")
    db.add_chat_message(chat, "assistant", "Got it")
    return _World(
        alice=alice,
        bob=bob,
        carol=carol,
        chat=chat,
        other_chat=other_chat,
        bob_chat=bob_chat,
        carol_chat=carol_chat,
        fresh=db.add_attachment(chat, created_at=_PAST),
        second=db.add_attachment(chat, kind="png", filename="b.png", created_at=_PAST),
        trashed=db.add_attachment(chat, created_at=_PAST, deleted_at=_EARLIER_TRASH),
        sent=db.add_attachment(chat, created_at=_PAST, message_id=earlier_message),
        earlier_message=earlier_message,
        other_chat_file=db.add_attachment(other_chat, created_at=_PAST),
        bob_file=db.add_attachment(bob_chat, created_at=_PAST),
        carol_file=db.add_attachment(carol_chat, created_at=_PAST),
    )


def _user(content: str = "Here are the files") -> LLMMessage:
    return LLMMessage(role="user", content=content)


def _assistant(content: str = "Thanks, I see them.") -> LLMMessage:
    return LLMMessage(role="assistant", content=content)


def _tool_turn() -> list[LLMMessage]:
    """A user message, a tool call, its result and the reply (four stored rows)."""
    block = {"type": "tool_use", "id": "call_187", "name": "memory.recall", "input": {"key": "k"}}
    return [
        _user(),
        LLMMessage(role="assistant", content="", tool_use_blocks=[block]),
        LLMMessage(role="tool", content="nothing stored", tool_call_id="call_187"),
        _assistant(),
    ]


def _linked_to(db: FakeDb, attachment_id: uuid.UUID) -> uuid.UUID | None:
    """The message an attachment is linked to (None: unsent)."""
    row = db.attachment_row(attachment_id)
    assert row is not None
    return None if row["message_id"] is None else plain(row["message_id"])


def _new_message_ids(db: FakeDb, chat_id: uuid.UUID, before: int) -> list[uuid.UUID]:
    """The ids of the chat's messages stored after its first ``before`` ones, by seq."""
    return [plain(row["id"]) for row in db.messages_of(chat_id)[before:]]


def _kind(call: Call) -> str:
    """A statement's short label for order checks."""
    n = call.normalized
    if n.startswith("update chats"):
        return "chat-update"
    if n.startswith("insert into chat_messages"):
        return "insert"
    if n.startswith("update attachments set message_id"):
        return "link"
    if n.startswith("update attachments set deleted_at"):
        return "trash-attachments"
    if n.startswith("insert into audit_events"):
        return "audit"
    return n


def _attachment_calls(db: FakeDb) -> list[Call]:
    return db.matching(r"\battachments\b")


# ---------------------------------------------------------------------------
# 1. append_messages: linking the message that carried the files (A9)
# ---------------------------------------------------------------------------


class TestAppendLinksAttachments:
    """A9 binds the stored user message, in the turn's transaction."""

    async def test_chats_attachments_append_links_ids_to_the_stored_user_message(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Both listed files carry the user message's id (not the reply's, which the
        function still returns); their updated_at moved; the chat's other unsent file
        stays unsent."""
        world = _world(db)
        stored_before = len(db.messages_of(world.chat))
        started = datetime.now(UTC)
        # A third unsent file of the chat that the message doesn't list.
        unlisted = db.add_attachment(world.chat, created_at=_PAST)

        result = await chats.append_messages(
            db.pool,
            world.alice.tenant,
            world.chat,
            _tool_turn(),
            attachment_ids=[world.fresh, world.second],
        )

        user_id, *_, last_id = _new_message_ids(db, world.chat, stored_before)
        assert plain(result) == last_id
        assert (_linked_to(db, world.fresh), _linked_to(db, world.second)) == (user_id, user_id)
        assert _linked_to(db, unlisted) is None
        for attachment_id in (world.fresh, world.second):
            row = db.attachment_row(attachment_id)
            assert row is not None
            assert started <= row["updated_at"] <= datetime.now(UTC)

    async def test_chats_attachments_append_link_is_a9_right_after_the_user_insert(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """One A9, exactly the contract's form, between the user message's INSERT and the
        next one, bound to (that message, the ids, the chat, ORG_ID, Alice), on the turn's
        connection in its committed transaction."""
        world = _world(db)
        stored_before = len(db.messages_of(world.chat))
        db.calls.clear()

        await chats.append_messages(
            db.pool,
            world.alice.tenant,
            world.chat,
            _tool_turn(),
            attachment_ids=[world.fresh, world.second],
        )

        assert [_kind(call) for call in db.calls] == [
            "chat-update",
            "insert",
            "link",
            "insert",
            "insert",
            "insert",
        ]
        link = db.calls[2]
        assert link.normalized == _A9
        user_id = _new_message_ids(db, world.chat, stored_before)[0]
        message_id, ids, chat_id, org_id, owner = link.args
        assert (plain(message_id), [plain(i) for i in ids], plain(chat_id)) == (
            user_id,
            [world.fresh, world.second],
            world.chat,
        )
        assert (plain(org_id), plain(owner)) == (ORG_ID, world.alice.user_id)
        assert link.tx is not None
        assert {(call.via, call.tx) for call in db.calls} == {(link.via, link.tx)}
        assert (link.tx, "commit") in db.transactions

    async def test_chats_attachments_append_single_user_message_links_it(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """A turn of one user message (an agent that stored nothing else): the link
        follows that INSERT and names the returned id."""
        world = _world(db)
        db.calls.clear()

        result = await chats.append_messages(
            db.pool, world.alice.tenant, world.chat, [_user()], attachment_ids=[world.fresh]
        )

        assert [_kind(call) for call in db.calls] == ["chat-update", "insert", "link"]
        assert _linked_to(db, world.fresh) == plain(result)

    async def test_chats_attachments_append_links_the_user_message_after_synthetic_results(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """A message sent while a tool_use was dangling: the turn stores the synthetic
        cancelled result first, then the user message. The files go with the user
        message (linked right after its INSERT), never with the tool result."""
        world = _world(db)
        stored_before = len(db.messages_of(world.chat))
        db.calls.clear()

        await chats.append_messages(
            db.pool,
            world.alice.tenant,
            world.chat,
            [
                LLMMessage(role="tool", content=_CANCELLED, tool_call_id="call_dangling"),
                _user(),
                _assistant(),
            ],
            attachment_ids=[world.fresh],
        )

        tool_id, user_id, _reply_id = _new_message_ids(db, world.chat, stored_before)
        assert [_kind(call) for call in db.calls] == [
            "chat-update",
            "insert",
            "insert",
            "link",
            "insert",
        ]
        assert _linked_to(db, world.fresh) == user_id != tool_id

    async def test_chats_attachments_append_leaves_ids_that_dont_match_untouched(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Another chat of Alice's, Bob's, Carol's (other org), a trashed, an already sent
        and an unknown id: no error, the turn is stored, only Alice's fresh file in this
        chat is linked and every other row is exactly as it was."""
        world = _world(db)
        others = [
            world.other_chat_file,
            world.bob_file,
            world.carol_file,
            world.trashed,
            world.sent,
        ]
        before = {attachment_id: db.attachment_row(attachment_id) for attachment_id in others}
        stored_before = len(db.messages_of(world.chat))

        await chats.append_messages(
            db.pool,
            world.alice.tenant,
            world.chat,
            [_user(), _assistant()],
            attachment_ids=[world.fresh, *others, _UNKNOWN_ATTACHMENT],
        )

        user_id, _reply_id = _new_message_ids(db, world.chat, stored_before)
        assert _linked_to(db, world.fresh) == user_id
        assert {attachment_id: db.attachment_row(attachment_id) for attachment_id in others} == (
            before
        )
        assert db.attachment_row(_UNKNOWN_ATTACHMENT) is None

    @pytest.mark.parametrize(
        "roles",
        [("assistant",), ("tool", "assistant")],
        ids=["assistant-only", "tool-then-assistant"],
    )
    async def test_chats_attachments_append_ids_without_a_user_message_are_value_error(
        self, chats: ModuleType, db: FakeDb, roles: tuple[str, ...]
    ) -> None:
        """No message carries the files: ValueError before any statement, nothing written."""
        world = _world(db)
        messages = [
            LLMMessage(role="tool", content="result", tool_call_id="call_x")
            if role == "tool"
            else _assistant()
            for role in roles
        ]
        before = db.snapshot()
        db.calls.clear()

        with pytest.raises(ValueError, match=r".") as caught:
            await chats.append_messages(
                db.pool, world.alice.tenant, world.chat, messages, attachment_ids=[world.fresh]
            )

        assert not isinstance(caught.value, chats.InvalidCursorError)
        assert db.calls == []
        assert db.snapshot() == before

    async def test_chats_attachments_append_without_ids_issues_todays_statements(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Left out, ``()`` and ``[]``: the same statements (no A9, nothing naming
        attachments), and the chats' unsent files stay unsent."""
        world = _world(db)
        targets = {
            "left-out": db.add_chat(world.alice.user_id, created_at=_PAST),
            "tuple": db.add_chat(world.alice.user_id, created_at=_PAST),
            "list": db.add_chat(world.alice.user_id, created_at=_PAST),
        }
        files = {name: db.add_attachment(chat_id) for name, chat_id in targets.items()}
        statements: dict[str, list[str]] = {}
        for name, chat_id in targets.items():
            db.calls.clear()
            if name == "left-out":
                await chats.append_messages(db.pool, world.alice.tenant, chat_id, _tool_turn())
            else:
                await chats.append_messages(
                    db.pool,
                    world.alice.tenant,
                    chat_id,
                    _tool_turn(),
                    attachment_ids=() if name == "tuple" else [],
                )
            statements[name] = [call.normalized for call in db.calls]

        assert statements["tuple"] == statements["left-out"] == statements["list"]
        assert not any("attachments" in sql for sql in statements["left-out"])
        assert [_linked_to(db, file_id) for file_id in files.values()] == [None, None, None]

    @pytest.mark.parametrize("case", ["other-org", "other-user", "trashed"])
    async def test_chats_attachments_append_to_a_chat_out_of_reach_links_nothing(
        self, chats: ModuleType, db: FakeDb, case: str
    ) -> None:
        """Carol's chat, Bob's chat, Alice's trashed chat (each holding an unsent file that
        is listed): ChatNotFoundError, no A9, every table as before."""
        world = _world(db)
        trashed_chat = db.add_chat(world.alice.user_id, created_at=_PAST, deleted_at=_PAST)
        target, listed = {
            "other-org": (world.carol_chat, world.carol_file),
            "other-user": (world.bob_chat, world.bob_file),
            "trashed": (trashed_chat, db.add_attachment(trashed_chat, created_at=_PAST)),
        }[case]
        before = db.snapshot()
        db.calls.clear()

        with pytest.raises(chats.ChatNotFoundError):
            await chats.append_messages(
                db.pool, world.alice.tenant, target, [_user()], attachment_ids=[listed]
            )

        assert _attachment_calls(db) == []
        assert db.snapshot() == before

    async def test_chats_attachments_append_failure_after_the_link_rolls_it_back(
        self, chats: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second INSERT fails after A9 ran: the link is rolled back with the turn
        (the files unsent, no message stored, every table as before)."""
        world = _world(db)
        before = db.snapshot()
        inserts: list[str] = []
        original = db.handle

        def failing(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
            if norm(sql).startswith("insert into chat_messages"):
                inserts.append(sql)
                if len(inserts) == 2:
                    raise asyncpg.exceptions.DeadlockDetectedError("deadlock detected")
            return original(method, sql, args, via, tx)

        monkeypatch.setattr(db, "handle", failing)

        with pytest.raises(asyncpg.exceptions.DeadlockDetectedError):
            await chats.append_messages(
                db.pool,
                world.alice.tenant,
                world.chat,
                _tool_turn(),
                attachment_ids=[world.fresh, world.second],
            )

        assert len(db.matching(r"^update attachments set message_id\b")) == 1
        assert db.snapshot() == before


# ---------------------------------------------------------------------------
# 2. trash_chat: the chat's files go to the trash with it (A10)
# ---------------------------------------------------------------------------


def _write_files(root: Path, attachment_id: uuid.UUID) -> dict[Path, bytes]:
    """An original and a derived artifact of an attachment under ``root/ORG_ID``."""
    org_dir = root / str(ORG_ID)
    derived = org_dir / f"{attachment_id}.d"
    derived.mkdir(parents=True)
    files = {
        org_dir / str(attachment_id): b"%PDF-1.7 original bytes",
        derived / "page-1.txt": b"derived text",
    }
    for path, content in files.items():
        path.write_bytes(content)
    return files


class TestTrashChatTrashesAttachments:
    """A10 in the trash's transaction; the files stay on disk."""

    async def test_chats_attachments_trash_sets_deleted_at_on_the_chats_live_files(
        self,
        chats: ModuleType,
        db: FakeDb,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Alice's unsent and sent files get deleted_at now; the one trashed earlier keeps
        its stamp; her other chat's, Bob's and Carol's files are untouched; the files on
        disk are untouched too."""
        root = tmp_path / "attachments"
        monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", root)
        world = _world(db)
        files = _write_files(root, world.fresh)
        untouched = [world.other_chat_file, world.bob_file, world.carol_file, world.trashed]
        before = {attachment_id: db.attachment_row(attachment_id) for attachment_id in untouched}
        started = datetime.now(UTC)

        await chats.trash_chat(db.pool, world.alice.tenant, world.chat, ip=_IP)

        for attachment_id in (world.fresh, world.second, world.sent):
            row = db.attachment_row(attachment_id)
            assert row is not None
            assert row["deleted_at"] is not None
            assert started <= row["deleted_at"] <= datetime.now(UTC)
        assert {attachment_id: db.attachment_row(attachment_id) for attachment_id in untouched} == (
            before
        )
        assert {path: path.read_bytes() for path in files} == files

    async def test_chats_attachments_trash_puts_the_live_files_in_the_chats_group(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """GH-194 (S6' + A10'): the chat is its own trash group and its live files (sent
        or not) carry the chat's id; the file trashed earlier keeps its own group."""
        world = _world(db)
        earlier = db.attachment_row(world.trashed)

        await chats.trash_chat(db.pool, world.alice.tenant, world.chat, ip=_IP)

        chat = db.chat_row(world.chat)
        assert chat is not None
        assert plain(chat["trash_group_id"]) == world.chat
        groups = {}
        for attachment_id in (world.fresh, world.second, world.sent):
            row = db.attachment_row(attachment_id)
            assert row is not None
            groups[attachment_id] = plain(row["trash_group_id"])
        assert groups == dict.fromkeys((world.fresh, world.second, world.sent), world.chat)
        assert db.attachment_row(world.trashed) == earlier
        assert earlier is not None
        assert plain(earlier["trash_group_id"]) == world.trashed

    async def test_chats_attachments_trash_runs_a10_between_the_chat_update_and_the_audit(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Exactly the contract's A10' (GH-194), bound to (the chat, ORG_ID), after the
        chat's UPDATE and before the chat.delete INSERT, on one connection in the committed
        transaction."""
        world = _world(db)
        db.calls.clear()

        await chats.trash_chat(db.pool, world.alice.tenant, world.chat, ip=_IP)

        assert [_kind(call) for call in db.calls] == [
            "chat-update",
            "trash-attachments",
            "audit",
        ]
        trash = db.calls[1]
        assert trash.normalized == _A10
        assert [plain(arg) for arg in trash.args] == [world.chat, ORG_ID]
        assert trash.tx is not None
        assert {(call.via, call.tx) for call in db.calls} == {(trash.via, trash.tx)}
        assert (trash.tx, "commit") in db.transactions

    async def test_chats_attachments_trash_audit_failure_rolls_the_files_back(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """A10 ran, then the audit write failed: AuditRecordError and every table as
        before (the chat's files live again)."""
        world = _world(db)
        before = db.snapshot()
        db.calls.clear()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await chats.trash_chat(db.pool, world.alice.tenant, world.chat, ip=_IP)

        assert len(db.matching(r"^update attachments set deleted_at\b")) == 1
        assert db.snapshot() == before
        row = db.attachment_row(world.fresh)
        assert row is not None
        assert row["deleted_at"] is None

    async def test_chats_attachments_trash_of_a_chat_out_of_reach_changes_no_file(
        self, chats: ModuleType, db: FakeDb
    ) -> None:
        """Bob's chat, Carol's chat and Alice's chat trashed already (holding a live
        file): ChatNotFoundError with no A10 and nothing changed; then Alice's own live
        chat goes to the trash with its files."""
        world = _world(db)
        trashed_chat = db.add_chat(world.alice.user_id, created_at=_PAST, deleted_at=_PAST)
        db.add_attachment(trashed_chat, created_at=_PAST)
        before = db.snapshot()
        db.calls.clear()

        for target in (world.bob_chat, world.carol_chat, trashed_chat):
            with pytest.raises(chats.ChatNotFoundError):
                await chats.trash_chat(db.pool, world.alice.tenant, target, ip=_IP)

        assert _attachment_calls(db) == []
        assert db.snapshot() == before
        await chats.trash_chat(db.pool, world.alice.tenant, world.chat, ip=_IP)
        row = db.attachment_row(world.fresh)
        assert row is not None
        assert row["deleted_at"] is not None
