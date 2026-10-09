"""Tests for attachments.trash_attachment: one file to the trash (GH-194, Decision 3).

Issue #194 Decision 3 and contract sections 2, 4 and 5 (A13): ``DELETE
/api/attachments/{id}`` moves the caller's own live attachment (any status,
sent or not) to the trash as its own trash group and records ``file.delete``.

What these tests pin down:
- One transaction on one connection: exactly the contract's A13 (bound to the
  file, the caller's org and the caller), then the ``file.delete`` event (the
  member, the file, the client IP, no metadata), committed.
- The row gets ``deleted_at`` (the database's now) and ``trash_group_id`` =
  its own id, whatever its status and whether it was sent; its chat and every
  other row stay as they were; the file stays on disk (the purge removes it).
- A trashed file (of its own or with its chat), another org's, a colleague's
  (an Org Admin's tenant on an Editor's file included) and an unknown file are
  ``AttachmentNotFoundError`` with nothing written and no event; a failed
  audit write rolls the trash back.
- Afterwards the file is no longer read (``get_attachment``), listed
  (``list_chat_attachments``) or sendable (``check_sendable``), and its chat's
  later delete leaves it in its own group (A10' only takes live files).

Harness: the real ``admino.attachments`` and ``admino.chats`` over
tests/db_fakes.py's FakeDb (migration 0031's schema once it ships) and a
``tmp_path`` attachments root.

Security notes: owner-only (Decision 1), the isolation lives in A13's
predicates; no audit row carries the file name.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import attachments, chats, organizations
from admino.access import MemberRole, Principal
from admino.audit_events import AuditRecordError
from admino.tenancy import TenantContext
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, norm, plain

if TYPE_CHECKING:
    from pathlib import Path

_IP: Final = "203.0.113.31"
_PAST: Final = datetime(2026, 9, 1, 8, 0, 0, 250000, tzinfo=UTC)
_EARLIER: Final = datetime(2026, 9, 5, 9, 0, 0, 125000, tzinfo=UTC)
_UNKNOWN: Final = uuid.UUID("3f2e1d0c-9b8a-4c7d-a6e5-f4d3c2b1a0f9")
_CANARY_FILE: Final = "canary-file-ibex-194.pdf"
_A13: Final = norm(
    "UPDATE attachments SET deleted_at = now(), trash_group_id = id"
    " WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL"
    " RETURNING id"
)


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


@pytest.fixture()
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty attachments root (``organizations.ATTACHMENTS_ROOT``)."""
    path = tmp_path / "attachments"
    path.mkdir()
    monkeypatch.setattr(organizations, "ATTACHMENTS_ROOT", path)
    return path


@dataclass(frozen=True)
class _Member:
    user_id: uuid.UUID
    tenant: TenantContext


def _member(db: FakeDb, *, org_id: uuid.UUID = ORG_ID, role: MemberRole = "editor") -> _Member:
    user_id = db.add_account(org_id=org_id, role=role)
    principal = Principal(user_id=user_id, kind="member", org_id=org_id, role=role)
    return _Member(user_id, TenantContext.from_principal(principal))


@dataclass(frozen=True)
class _World:
    alice: _Member
    bob: _Member
    admin: _Member
    carol: _Member
    chat: uuid.UUID  # Alice's live chat
    file: uuid.UUID  # its live, unsent file (canary name)
    other_file: uuid.UUID  # its second live file


def _world(db: FakeDb) -> _World:
    alice, bob = _member(db), _member(db)
    admin, carol = _member(db, role="org_admin"), _member(db, org_id=OTHER_ORG_ID)
    chat = db.add_chat(alice.user_id, title="Alice plans", created_at=_PAST)
    return _World(
        alice=alice,
        bob=bob,
        admin=admin,
        carol=carol,
        chat=chat,
        file=db.add_attachment(chat, filename=_CANARY_FILE, created_at=_PAST),
        other_file=db.add_attachment(chat, kind="png", filename="b.png", created_at=_PAST),
    )


def _row(db: FakeDb, attachment_id: uuid.UUID) -> dict[str, Any]:
    row = db.attachment_row(attachment_id)
    assert row is not None
    return row


class TestTrashAttachment:
    """A13 and file.delete in one transaction; the file stays on disk."""

    async def test_attachments_trash_runs_a13_then_file_delete_in_one_transaction(
        self, db: FakeDb
    ) -> None:
        """Exactly A13 bound to (the file, ORG_ID, Alice), then the audit INSERT, on one
        connection in the committed transaction, and nothing else."""
        world = _world(db)
        db.calls.clear()

        result = await attachments.trash_attachment(db.pool, world.alice.tenant, world.file, ip=_IP)

        assert result is None
        assert [call.normalized.split(" ")[0] for call in db.calls] == ["update", "insert"]
        trash, audit = db.calls
        assert trash.normalized == _A13
        assert [plain(arg) for arg in trash.args] == [world.file, ORG_ID, world.alice.user_id]
        assert audit.normalized.startswith("insert into audit_events")
        assert trash.tx is not None
        assert (trash.via, trash.tx) == (audit.via, audit.tx)
        assert (trash.tx, "commit") in db.transactions

    @pytest.mark.parametrize("ip", [_IP, None])
    async def test_attachments_trash_records_one_file_delete_event(
        self, db: FakeDb, ip: str | None
    ) -> None:
        """Member actor, the org, target file [id], the client IP, no metadata."""
        world = _world(db)

        await attachments.trash_attachment(db.pool, world.alice.tenant, world.file, ip=ip)

        (row,) = db.audit
        assert {
            "action": row["action"],
            "actor_kind": row["actor_kind"],
            "actor_user_id": plain(row["actor_user_id"]),
            "org_id": plain(row["org_id"]),
            "target_type": row["target_type"],
            "target_ids": row["target_ids"],
            "ip": row["ip"],
            "metadata": row["metadata"],
        } == {
            "action": "file.delete",
            "actor_kind": "member",
            "actor_user_id": world.alice.user_id,
            "org_id": ORG_ID,
            "target_type": "file",
            "target_ids": [str(world.file)],
            "ip": ip,
            "metadata": {},
        }

    @pytest.mark.parametrize(
        ("status", "sent"),
        [
            ("uploaded", False),
            ("processing", False),
            ("failed", False),
            ("ready", False),
            ("ready", True),
        ],
        ids=["uploaded", "processing", "failed", "ready-unsent", "ready-sent"],
    )
    async def test_attachments_trash_makes_the_file_its_own_group_in_any_state(
        self, db: FakeDb, status: str, sent: bool
    ) -> None:
        """Any status, sent or not: ``deleted_at`` now and ``trash_group_id`` its own id;
        every other column, the chat and the chat's other file stay as they were."""
        world = _world(db)
        message = db.add_chat_message(world.chat, "user", "with a file") if sent else None
        file_id = db.add_attachment(
            world.chat,
            status=status,
            failure_reason="conversion_failed" if status == "failed" else None,
            message_id=message,
            created_at=_PAST,
        )
        columns = {k: v for k, v in _row(db, file_id).items() if k != "deleted_at"}
        chat_before = db.chat_row(world.chat)
        other_before = _row(db, world.other_file)
        started = datetime.now(UTC)

        await attachments.trash_attachment(db.pool, world.alice.tenant, file_id, ip=_IP)

        row = _row(db, file_id)
        assert row["deleted_at"] is not None
        assert started <= row["deleted_at"] <= datetime.now(UTC)
        assert plain(row["trash_group_id"]) == file_id
        assert {k: v for k, v in row.items() if k not in ("deleted_at", "trash_group_id")} == {
            k: v for k, v in columns.items() if k != "trash_group_id"
        }
        assert db.chat_row(world.chat) == chat_before
        assert _row(db, world.other_file) == other_before

    async def test_attachments_trash_keeps_the_file_on_disk(self, db: FakeDb, root: Path) -> None:
        """The original and its derived tree stay (the purge removes them later)."""
        world = _world(db)
        org_dir = root / str(ORG_ID)
        (org_dir / f"{world.file}.d").mkdir(parents=True)
        files = {
            org_dir / str(world.file): b"%PDF-1.7 original",
            org_dir / f"{world.file}.d" / "text.txt": b"extracted",
        }
        for path, content in files.items():
            path.write_bytes(content)

        await attachments.trash_attachment(db.pool, world.alice.tenant, world.file, ip=_IP)

        assert {path: path.read_bytes() for path in files} == files

    @pytest.mark.parametrize(
        "case", ["own-trashed", "chat-trashed", "other-org", "colleague", "org-admin", "unknown"]
    )
    async def test_attachments_trash_out_of_reach_is_not_found_with_nothing_written(
        self, db: FakeDb, case: str
    ) -> None:
        """A file trashed on its own, one trashed with its chat, another org's, a
        colleague's, the Org Admin on Alice's file and an unknown id:
        AttachmentNotFoundError, no audit INSERT, nothing changed."""
        world = _world(db)
        tenant, target = world.alice.tenant, world.file
        if case == "own-trashed":
            target = db.add_attachment(world.chat, created_at=_PAST, deleted_at=_EARLIER)
        elif case == "chat-trashed":
            trashed_chat = db.add_chat(world.alice.user_id, created_at=_PAST, deleted_at=_EARLIER)
            target = db.add_attachment(trashed_chat, created_at=_PAST, deleted_at=_EARLIER)
        elif case == "other-org":
            target = db.add_attachment(db.add_chat(world.carol.user_id), created_at=_PAST)
        elif case == "colleague":
            target = db.add_attachment(db.add_chat(world.bob.user_id), created_at=_PAST)
        elif case == "org-admin":
            tenant = world.admin.tenant
        else:
            target = _UNKNOWN
        before = db.snapshot()
        db.calls.clear()

        with pytest.raises(attachments.AttachmentNotFoundError) as caught:
            await attachments.trash_attachment(db.pool, tenant, target, ip=_IP)

        assert type(caught.value) is attachments.AttachmentNotFoundError
        assert str(caught.value) == "Attachment not found."
        assert db.matching(r"^insert into audit_events\b") == []
        assert db.snapshot() == before

    async def test_attachments_trash_audit_failure_rolls_back(self, db: FakeDb) -> None:
        """A13 ran, then the audit write failed: AuditRecordError and the file live."""
        world = _world(db)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await attachments.trash_attachment(db.pool, world.alice.tenant, world.file, ip=_IP)

        assert len(db.matching(r"^update attachments set deleted_at\b")) == 1
        assert db.snapshot() == before
        assert _row(db, world.file)["deleted_at"] is None


class TestTrashedAttachmentIsGone:
    """After trash_attachment the file is no longer read, listed or sent."""

    async def test_attachments_trashed_file_is_no_longer_read_listed_or_sendable(
        self, db: FakeDb
    ) -> None:
        """``get_attachment`` and ``check_sendable`` refuse it as not found and
        ``list_chat_attachments`` lists only the other file."""
        world = _world(db)
        db.add_attachment(world.chat, status="ready", created_at=_PAST)

        await attachments.trash_attachment(db.pool, world.alice.tenant, world.file, ip=_IP)

        with pytest.raises(attachments.AttachmentNotFoundError):
            await attachments.get_attachment(db.pool, world.alice.tenant, world.file)
        page = await attachments.list_chat_attachments(
            db.pool, world.alice.tenant, world.chat, limit=50, cursor=None, status=None, active=None
        )
        assert world.file not in [plain(record.id) for record in page.attachments]
        assert len(page.attachments) == 2
        with pytest.raises(attachments.AttachmentNotFoundError):
            await attachments.check_sendable(db.pool, world.alice.tenant, world.chat, [world.file])

    async def test_attachments_trashed_file_keeps_its_own_group_when_its_chat_is_deleted(
        self, db: FakeDb
    ) -> None:
        """The chat's later delete (S6' + A10') moves only its live file into the chat's
        group: the file trashed on its own keeps its group and its earlier stamp."""
        world = _world(db)
        await attachments.trash_attachment(db.pool, world.alice.tenant, world.file, ip=_IP)
        trashed_before = _row(db, world.file)

        await chats.trash_chat(db.pool, world.alice.tenant, world.chat, ip=_IP)

        assert _row(db, world.file) == trashed_before
        assert plain(_row(db, world.file)["trash_group_id"]) == world.file
        other = _row(db, world.other_file)
        assert other["deleted_at"] is not None
        assert plain(other["trash_group_id"]) == world.chat
