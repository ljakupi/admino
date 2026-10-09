"""The FakeDb's own spec for migration 0031 and GH-194's SQL forms (tests/db_fakes.py).

Issue #194 (Decisions 2, 5, 8, 10) and its contract (§1 migration, §2 audit
catalog, §5 SQL forms). The fake models the schema the shipped migrations leave
in place (``db_fakes.shipped_schema()``, read from the migrations next to
``admino.database``): until a shipped migration adds ``trash_group_id`` it is
0030's schema; once ``0031_*.sql`` does, it is 0031's. These tests switch it with
a tmp copy of the tree's migrations 0001 to 0030, with or without a 0031: the
tree's own ``0031_*.sql`` when it exists, else ``MIGRATION_0031`` below (the
statements of the contract's migration that the schema reader reads).

What these tests pin down:
- The schema reader: through 0030 there is no trash group column, no CHECK,
  no DELETE on chats and 0025's chats UPDATE grant; with 0031 both tables have
  the column and the CHECK, admino_app may DELETE chats and UPDATE
  trash_group_id on both, and chat.purge / file.purge join the catalog. A 0031
  whose statements are only in comments changes nothing; a later REVOKE or
  DROP CONSTRAINT takes its part back (a table-level REVOKE takes the column
  grants with it). The tree's own migrations give 0031's schema (RED until
  0031 ships).
- Before 0031: no ``trash_group_id`` key in seeded rows, ``trash_group_id=`` on
  ``add_chat`` / ``add_attachment`` and every form naming the column are
  UndefinedColumnError (also on empty tables), ``DELETE FROM chats`` is
  InsufficientPrivilegeError, chat.purge / file.purge are refused.
- After 0031: the column is each table's last (after attachments.active), NULL
  for an INSERT without it; the seed helpers derive it like the backfill (a
  trashed chat: its own id; a trashed file: its trashed chat's id, else its
  own); both CHECKs refuse either column without the other on every INSERT and
  UPDATE path (the pre-0031 S6 / A10 forms included) with the constraint name
  and the "Failing row contains" detail, after the table's other CHECKs; the
  grants; the catalog.
- The forms of contract §5 answer as PostgreSQL did (pg-verify, 2026-10-09):
  R1, S6' + A10', A13, T1c / T1c' / T1a / T1a' (strict cutoff, own-group items
  only, deleted_at then id descending, the keyset across a tie, LIMIT), T2
  (the chat record; expired: no row; the legacy session key:
  UniqueViolationError, nothing changed), T3 (exactly the chat's group), T4,
  T6, T7 / J3 (FOR UPDATE recorded), T8, T9 (the cascade to the chat's
  messages and every attachment row, rolled back with its transaction), T10,
  E1, E2, J1 (UNION: distinct org ids, ordered), J2, J4, J5 (inclusive
  cutoff). Timestamp parameters must be aware datetimes.

Harness: ``FakeDb`` alone (no app code): the forms run on ``db.pool`` or a
connection. Fixed ids and stamps; nothing here is content or a secret.
"""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import asyncpg
import pytest

from tests import db_fakes
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, ShippedSchema, plain

# Contract §1: the statements of migration 0031 that the schema reader reads (the
# backfill and the indexes change nothing it models). Used when the tree has no
# 0031 yet; otherwise the tree's file is the 0031 under test.
MIGRATION_0031: Final = """
-- 0031_trash.sql (GH-194): ALTER TABLE chats ADD COLUMN trash_group_id (comment only).
ALTER TABLE chats ADD COLUMN trash_group_id UUID;
ALTER TABLE attachments ADD COLUMN trash_group_id UUID;
ALTER TABLE chats ADD CONSTRAINT chats_trash_group_check
    CHECK ((deleted_at IS NULL) = (trash_group_id IS NULL));
ALTER TABLE attachments ADD CONSTRAINT attachments_trash_group_check
    CHECK ((deleted_at IS NULL) = (trash_group_id IS NULL));
GRANT DELETE ON chats TO admino_app;
GRANT UPDATE (trash_group_id) ON chats TO admino_app;
GRANT UPDATE (trash_group_id) ON attachments TO admino_app;
ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK (action IN (
    'login.success', 'login.failure', 'login.lockout',
    'password_reset.request', 'password_reset.complete', 'password.change',
    'session.revoke', 'session.force_logout',
    'invitation.create', 'invitation.revoke', 'invitation.accept', 'invitation.resend',
    'invitation.refuse',
    'user.role_change', 'user.activate', 'user.deactivate', 'user.delete',
    'user.profile_change',
    'project.share', 'project.unshare', 'project.member_role_change', 'project.transfer',
    'project.delete', 'project.restore', 'chat.delete', 'chat.restore', 'chat.purge',
    'file.upload', 'file.delete', 'file.restore', 'file.purge', 'file.exclude',
    'file.include',
    'project.admin_access', 'export.create',
    'org.settings_change', 'org.create', 'org.limits_change', 'org.deactivate',
    'org.reactivate', 'org.deletion_schedule', 'org.deletion_cancel', 'org.purge',
    'org.residency_change', 'platform.settings_change', 'model.registry_change',
    'breakglass.start', 'breakglass.end', 'tool.call', 'audit.purge',
    'org.permission_change', 'org.permission_promote', 'org.permission_promote_cancel',
    'org.permission_demote'
));
"""
# A 0031 that only describes its statements in comments.
MIGRATION_COMMENTS_ONLY: Final = """
-- ALTER TABLE chats ADD COLUMN trash_group_id UUID;
-- ALTER TABLE attachments ADD COLUMN trash_group_id UUID;
/* ALTER TABLE chats ADD CONSTRAINT chats_trash_group_check
       CHECK ((deleted_at IS NULL) = (trash_group_id IS NULL));
   GRANT DELETE ON chats TO admino_app;
   GRANT UPDATE (trash_group_id) ON chats TO admino_app; */
SELECT 1;
"""

# A migration that gives chats alone the column and its CHECK.
MIGRATION_CHATS_ONLY: Final = """
ALTER TABLE chats ADD COLUMN trash_group_id UUID;
ALTER TABLE chats ADD CONSTRAINT chats_trash_group_check
    CHECK ((deleted_at IS NULL) = (trash_group_id IS NULL));
"""

GROUP: Final = "trash_group_id"
PURGE_ACTIONS: Final = frozenset({"chat.purge", "file.purge"})
CHECKS: Final = frozenset({"chats_trash_group_check", "attachments_trash_group_check"})

# Contract §5, verbatim. CR / AR: the chat and attachment record columns.
CR_COLUMNS: Final = (
    "id",
    "org_id",
    "owner_user_id",
    "title",
    "title_source",
    "external_content",
    "created_at",
    "last_activity_at",
)
AR_COLUMNS: Final = (
    "id",
    "chat_id",
    "message_id",
    "filename",
    "kind",
    "size_bytes",
    "status",
    "failure_reason",
    "page_count",
    "token_estimate",
    "active",
    "created_at",
)
R1: Final = "SELECT trash_retention_days FROM org_settings WHERE org_id = $1"
S6: Final = """
    UPDATE chats SET deleted_at = now(), trash_group_id = id
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    RETURNING id
"""
A10: Final = """
    UPDATE attachments SET deleted_at = now(), trash_group_id = $1
    WHERE chat_id = $1 AND org_id = $2 AND deleted_at IS NULL
"""
A13: Final = """
    UPDATE attachments SET deleted_at = now(), trash_group_id = id
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    RETURNING id
"""
_T1C_HEAD: Final = """
    SELECT id, title, deleted_at FROM chats
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at > $3 AND trash_group_id = id
"""
T1C: Final = _T1C_HEAD + " ORDER BY deleted_at DESC, id DESC LIMIT $4"
T1C_AFTER: Final = (
    _T1C_HEAD + " AND (deleted_at, id) < ($4, $5) ORDER BY deleted_at DESC, id DESC LIMIT $6"
)
_T1A_HEAD: Final = """
    SELECT id, filename, chat_id, deleted_at FROM attachments
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at > $3 AND trash_group_id = id
"""
T1A: Final = _T1A_HEAD + " ORDER BY deleted_at DESC, id DESC LIMIT $4"
T1A_AFTER: Final = (
    _T1A_HEAD + " AND (deleted_at, id) < ($4, $5) ORDER BY deleted_at DESC, id DESC LIMIT $6"
)
T2: Final = """
    UPDATE chats SET deleted_at = NULL, trash_group_id = NULL
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at > $4
      AND trash_group_id = id
    RETURNING id, org_id, owner_user_id, title, title_source, external_content, created_at,
              last_activity_at
"""
T3: Final = """
    UPDATE attachments SET deleted_at = NULL, trash_group_id = NULL
    WHERE chat_id = $1 AND org_id = $2 AND trash_group_id = $1
"""
T4: Final = """
    SELECT chat_id FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at > $4
      AND trash_group_id = id
"""
T6: Final = """
    UPDATE attachments SET deleted_at = NULL, trash_group_id = NULL
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at > $4
      AND trash_group_id = id
    RETURNING id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
              page_count, token_estimate, active, created_at
"""
T7: Final = """
    SELECT id FROM chats
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NOT NULL
    FOR UPDATE
"""
T8: Final = "SELECT id FROM attachments WHERE chat_id = $1 AND org_id = $2"
T9: Final = "DELETE FROM chats WHERE id = $1 AND org_id = $2"
T10: Final = """
    DELETE FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NOT NULL
      AND trash_group_id = id
    RETURNING id
"""
E1: Final = """
    SELECT id FROM chats
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at IS NOT NULL
    ORDER BY id
"""
E2: Final = """
    SELECT id FROM attachments
    WHERE org_id = $1 AND owner_user_id = $2 AND deleted_at IS NOT NULL
      AND trash_group_id = id
    ORDER BY id
"""
J1: Final = """
    SELECT org_id FROM chats WHERE deleted_at IS NOT NULL
    UNION
    SELECT org_id FROM attachments WHERE deleted_at IS NOT NULL
    ORDER BY org_id
"""
J2: Final = "SELECT id FROM chats WHERE org_id = $1 AND deleted_at <= $2 ORDER BY deleted_at, id"
J3: Final = """
    SELECT id FROM chats WHERE id = $1 AND org_id = $2 AND deleted_at <= $3 FOR UPDATE
"""
J4: Final = """
    SELECT id FROM attachments
    WHERE org_id = $1 AND trash_group_id = id AND deleted_at <= $2
    ORDER BY deleted_at, id
"""
J5: Final = """
    DELETE FROM attachments
    WHERE id = $1 AND org_id = $2 AND trash_group_id = id AND deleted_at <= $3
    RETURNING id
"""
# The pre-0031 trash forms (chats.trash_chat's S6 and A10 as shipped before GH-194).
S6_OLD: Final = """
    UPDATE chats SET deleted_at = now()
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    RETURNING id
"""
A10_OLD: Final = """
    UPDATE attachments SET deleted_at = now()
    WHERE chat_id = $1 AND org_id = $2 AND deleted_at IS NULL
"""
CHAT_INSERT: Final = (
    "INSERT INTO chats (org_id, owner_user_id, title) VALUES ($1, $2, $3) RETURNING id"
)
ATTACHMENT_INSERT: Final = """
    INSERT INTO attachments (id, org_id, chat_id, owner_user_id, filename, kind, size_bytes)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
"""
AUDIT_INSERT: Final = """
    INSERT INTO audit_events
        (org_id, actor_user_id, actor_kind, action, target_type, target_ids, ip, metadata)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::inet, $8::jsonb)
"""

NOW: Final = datetime(2026, 10, 9, 12, 0, 0, 500000, tzinfo=UTC)
D1: Final = NOW - timedelta(days=1)
D2: Final = NOW - timedelta(days=2)
D5: Final = NOW - timedelta(days=5)
D40: Final = NOW - timedelta(days=40)
CUTOFF_30: Final = NOW - timedelta(days=30)

# Two more orgs for J1: one whose only trashed row is a file, one with live rows only.
FILE_ONLY_ORG: Final = uuid.UUID("0194c000-0000-4000-8000-000000000001")
QUIET_ORG: Final = uuid.UUID("f194d000-0000-4000-8000-000000000002")

# The owner's chats. TRASHED and TIE share their stamp; TIE's id sorts after TRASHED's.
LIVE_CHAT: Final = uuid.UUID("c1940000-0000-4000-8000-000000000001")
TRASHED_CHAT: Final = uuid.UUID("21940000-0000-4000-8000-000000000002")  # D1, 3 files
TIE_CHAT: Final = uuid.UUID("a1940000-0000-4000-8000-000000000003")  # D1
SECOND_CHAT: Final = uuid.UUID("51940000-0000-4000-8000-000000000004")  # D2
OLD_CHAT: Final = uuid.UUID("91940000-0000-4000-8000-000000000005")  # D40, expired
# The owner's files.
LIVE_FILE: Final = uuid.UUID("b1940000-0000-4000-8000-000000000011")  # LIVE_CHAT
OWN_FILE: Final = uuid.UUID("31940000-0000-4000-8000-000000000012")  # LIVE_CHAT, D2, own
OLD_FILE: Final = uuid.UUID("e1940000-0000-4000-8000-000000000013")  # LIVE_CHAT, D40, own
GROUP_FILE_A: Final = uuid.UUID("41940000-0000-4000-8000-000000000014")  # TRASHED, D1
GROUP_FILE_B: Final = uuid.UUID("61940000-0000-4000-8000-000000000015")  # TRASHED, D1
EARLIER_FILE: Final = uuid.UUID("71940000-0000-4000-8000-000000000016")  # TRASHED, D5, own
OLD_GROUP_FILE: Final = uuid.UUID("81940000-0000-4000-8000-000000000017")  # OLD_CHAT, D40
# Elsewhere.
COLLEAGUE_CHAT: Final = uuid.UUID("d1940000-0000-4000-8000-000000000021")  # D1
COLLEAGUE_LIVE_CHAT: Final = uuid.UUID("d1940000-0000-4000-8000-000000000022")
COLLEAGUE_FILE: Final = uuid.UUID("d1940000-0000-4000-8000-000000000023")  # D2, own
FOREIGN_CHAT: Final = uuid.UUID("f1940000-0000-4000-8000-000000000031")  # D40
FOREIGN_LIVE_CHAT: Final = uuid.UUID("f1940000-0000-4000-8000-000000000032")
FOREIGN_FILE: Final = uuid.UUID("f1940000-0000-4000-8000-000000000033")  # D40, own
FILE_ONLY_FILE: Final = uuid.UUID("01940000-0000-4000-8000-000000000041")  # D5, own


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _tree_migrations() -> Path:
    from admino import database

    return Path(database.__file__).parent / "migrations"


def _contract_0031() -> str:
    """The tree's own 0031 when it ships one, else the contract's statements."""
    shipped = sorted(_tree_migrations().glob("0031_*.sql"))
    return shipped[0].read_text(encoding="utf-8") if shipped else MIGRATION_0031


def _migrations_copy(target: Path, extra: str | None) -> Path:
    """0001 to 0030 of the tree's migrations in ``target``, plus ``extra`` as 0031."""
    target.mkdir()
    for path in sorted(_tree_migrations().glob("*.sql")):
        match = re.match(r"(\d{4})_", path.name)
        if match is not None and int(match.group(1)) <= 30:
            shutil.copyfile(path, target / path.name)
    if extra is not None:
        (target / "0031_trash.sql").write_text(extra, encoding="utf-8")
    return target


@pytest.fixture()
def read_0030(tmp_path: Path) -> ShippedSchema:
    """What 0001 to 0030 leave in place (unpatched)."""
    return db_fakes.read_shipped_schema(_migrations_copy(tmp_path / "m0030", None))


@pytest.fixture()
def read_0031(tmp_path: Path) -> ShippedSchema:
    """What 0001 to 0030 plus the 0031 under test leave in place (unpatched)."""
    return db_fakes.read_shipped_schema(_migrations_copy(tmp_path / "m0031", _contract_0031()))


def _use(monkeypatch: pytest.MonkeyPatch, schema: ShippedSchema) -> ShippedSchema:
    monkeypatch.setattr(db_fakes, "shipped_schema", lambda: schema)
    return schema


@pytest.fixture()
def schema_0030(monkeypatch: pytest.MonkeyPatch, read_0030: ShippedSchema) -> ShippedSchema:
    """The fake runs 0030's schema."""
    return _use(monkeypatch, read_0030)


@pytest.fixture()
def schema_0031(monkeypatch: pytest.MonkeyPatch, read_0031: ShippedSchema) -> ShippedSchema:
    """The fake runs 0031's schema."""
    return _use(monkeypatch, read_0031)


@dataclass(frozen=True)
class _World:
    db: FakeDb
    owner: uuid.UUID
    colleague: uuid.UUID
    foreigner: uuid.UUID


def _world() -> _World:
    """The owner's live and trashed chats and files, a colleague's, another org's, and
    two orgs for J1 (built on 0031's schema: the seeds derive their trash groups)."""
    db = FakeDb()
    owner = db.add_account(org_id=ORG_ID)
    colleague = db.add_account(org_id=ORG_ID)
    foreigner = db.add_account(org_id=OTHER_ORG_ID)
    file_only = db.add_account(org_id=FILE_ONLY_ORG)
    quiet = db.add_account(org_id=QUIET_ORG)
    # Another org's rows first: J1's rows in storage order are not its ORDER BY's.
    db.add_chat(foreigner, chat_id=FOREIGN_CHAT, deleted_at=D40)
    db.add_chat(foreigner, chat_id=FOREIGN_LIVE_CHAT)
    db.add_attachment(FOREIGN_LIVE_CHAT, attachment_id=FOREIGN_FILE, deleted_at=D40)
    db.add_chat(owner, chat_id=LIVE_CHAT, title="live")
    db.add_chat(owner, chat_id=TRASHED_CHAT, title="trashed", deleted_at=D1)
    db.add_chat(owner, chat_id=TIE_CHAT, title="tie", deleted_at=D1)
    db.add_chat(owner, chat_id=SECOND_CHAT, title="second", deleted_at=D2)
    db.add_chat(owner, chat_id=OLD_CHAT, title="old", deleted_at=D40)
    db.add_chat_message(LIVE_CHAT, "user", "hello")
    db.add_chat_message(TRASHED_CHAT, "user", "question")
    db.add_chat_message(TRASHED_CHAT, "assistant", "answer")
    db.add_attachment(LIVE_CHAT, attachment_id=LIVE_FILE, filename="live.pdf")
    db.add_attachment(LIVE_CHAT, attachment_id=OWN_FILE, filename="own.pdf", deleted_at=D2)
    db.add_attachment(LIVE_CHAT, attachment_id=OLD_FILE, filename="old.pdf", deleted_at=D40)
    db.add_attachment(TRASHED_CHAT, attachment_id=GROUP_FILE_A, filename="a.pdf", deleted_at=D1)
    db.add_attachment(TRASHED_CHAT, attachment_id=GROUP_FILE_B, filename="b.pdf", deleted_at=D1)
    # Deleted on its own before its chat: its own group (0031's backfill can't tell,
    # so the seed names it).
    db.add_attachment(
        TRASHED_CHAT,
        attachment_id=EARLIER_FILE,
        filename="earlier.pdf",
        deleted_at=D5,
        trash_group_id=EARLIER_FILE,
    )
    db.add_attachment(OLD_CHAT, attachment_id=OLD_GROUP_FILE, deleted_at=D40)
    db.add_chat(colleague, chat_id=COLLEAGUE_CHAT, deleted_at=D1)
    db.add_chat(colleague, chat_id=COLLEAGUE_LIVE_CHAT)
    db.add_attachment(COLLEAGUE_LIVE_CHAT, attachment_id=COLLEAGUE_FILE, deleted_at=D2)
    file_only_chat = db.add_chat(file_only)
    db.add_attachment(file_only_chat, attachment_id=FILE_ONLY_FILE, deleted_at=D5)
    quiet_chat = db.add_chat(quiet)
    db.add_attachment(quiet_chat)
    db.add_org_settings(ORG_ID, trash_retention_days=7)
    return _World(db, owner, colleague, foreigner)


def _ids(rows: list[Any], key: str = "id") -> list[uuid.UUID]:
    return [plain(row[key]) for row in rows]


def _chat_group(db: FakeDb, chat_id: uuid.UUID) -> tuple[bool, Any]:
    """A stored chat's (trashed, trash_group_id) pair."""
    row = db.chat_row(chat_id)
    assert row is not None
    return (row["deleted_at"] is not None, row[GROUP])


def _file_group(db: FakeDb, attachment_id: uuid.UUID) -> tuple[bool, Any]:
    """A stored attachment's (trashed, trash_group_id) pair."""
    row = db.attachment_row(attachment_id)
    assert row is not None
    return (row["deleted_at"] is not None, row[GROUP])


async def _outcome(call: Any) -> str:
    """The awaited call's result tag, or its exception's class name."""
    try:
        result = await call
    except asyncpg.PostgresError as exc:
        return type(exc).__name__
    return f"ok:{result!r}" if isinstance(result, str) else "ok"


# ---------------------------------------------------------------------------
# 1. The schema reader
# ---------------------------------------------------------------------------


class TestShippedSchemaReader:
    """``read_shipped_schema`` reads what 0031 leaves in place."""

    def test_fakedb_trash_schema_through_0030_has_no_trash_parts(
        self, read_0030: ShippedSchema
    ) -> None:
        """No column, no CHECK, 0025's chats UPDATE grant, DELETE on attachments only,
        no purge action."""
        assert (
            read_0030.trash_group_tables,
            read_0030.trash_group_checks,
            read_0030.chat_update_columns,
            read_0030.delete_tables,
            read_0030.audit_actions & PURGE_ACTIONS,
        ) == (
            frozenset(),
            frozenset(),
            db_fakes.CHAT_UPDATE_COLUMNS,
            frozenset({"attachments"}),
            frozenset(),
        )

    def test_fakedb_trash_schema_with_0031_adds_the_trash_parts(
        self, read_0030: ShippedSchema, read_0031: ShippedSchema
    ) -> None:
        """Both columns and CHECKs, DELETE on chats, UPDATE (trash_group_id) on both
        tables, the two purge actions; nothing else changes."""
        assert read_0031 == dataclasses.replace(
            read_0030,
            attachment_update_columns=read_0030.attachment_update_columns | {GROUP},
            audit_actions=read_0030.audit_actions | PURGE_ACTIONS,
            trash_group_tables=frozenset({"chats", "attachments"}),
            trash_group_checks=CHECKS,
            chat_update_columns=db_fakes.CHAT_UPDATE_COLUMNS | {GROUP},
            delete_tables=frozenset({"chats", "attachments"}),
        )

    def test_fakedb_trash_schema_ignores_statements_in_comments(
        self, tmp_path: Path, read_0030: ShippedSchema
    ) -> None:
        """A 0031 that only describes its statements in comments changes nothing."""
        directory = _migrations_copy(tmp_path / "comments", MIGRATION_COMMENTS_ONLY)

        assert db_fakes.read_shipped_schema(directory) == read_0030

    def test_fakedb_trash_schema_reads_each_table_on_its_own(
        self, tmp_path: Path, read_0030: ShippedSchema
    ) -> None:
        """A migration giving chats alone the column and its CHECK changes chats only."""
        directory = _migrations_copy(tmp_path / "chats-only", MIGRATION_CHATS_ONLY)

        assert db_fakes.read_shipped_schema(directory) == dataclasses.replace(
            read_0030,
            trash_group_tables=frozenset({"chats"}),
            trash_group_checks=frozenset({"chats_trash_group_check"}),
        )

    @pytest.mark.parametrize(
        ("later", "changes"),
        [
            (
                "REVOKE DELETE ON chats FROM admino_app;",
                {"delete_tables": frozenset({"attachments"})},
            ),
            (
                "REVOKE UPDATE (trash_group_id) ON chats FROM admino_app;",
                {"chat_update_columns": db_fakes.CHAT_UPDATE_COLUMNS},
            ),
            (
                "REVOKE UPDATE ON attachments FROM admino_app;",
                {"attachment_update_columns": frozenset()},
            ),
            (
                "ALTER TABLE chats DROP CONSTRAINT chats_trash_group_check;",
                {"trash_group_checks": frozenset({"attachments_trash_group_check"})},
            ),
            ("GRANT DELETE ON chat_messages TO admino_audit;", {}),
        ],
        ids=["revoke-delete", "revoke-column", "revoke-table-update", "drop-check", "other-role"],
    )
    def test_fakedb_trash_schema_later_statements_take_their_part_back(
        self, tmp_path: Path, read_0031: ShippedSchema, later: str, changes: dict[str, Any]
    ) -> None:
        """A later REVOKE / DROP CONSTRAINT takes back exactly its part (a table-level
        REVOKE UPDATE takes every column grant of that privilege with it); a grant to
        another role changes nothing."""
        directory = _migrations_copy(tmp_path / "later", _contract_0031() + "\n" + later + "\n")

        assert db_fakes.read_shipped_schema(directory) == dataclasses.replace(read_0031, **changes)

    def test_fakedb_trash_shipped_migrations_give_the_0031_schema(
        self, read_0031: ShippedSchema
    ) -> None:
        """The tree's own migrations (what the fake uses unpatched) leave 0031's schema,
        and the import-time attachments UPDATE grant is that one (RED until 0031 ships)."""
        assert (db_fakes.shipped_schema(), db_fakes.ATTACHMENT_UPDATE_COLUMNS) == (
            read_0031,
            read_0031.attachment_update_columns,
        )


# ---------------------------------------------------------------------------
# 2. Before 0031
# ---------------------------------------------------------------------------


class TestBefore0031:
    """0030's schema: no trash group column, no DELETE on chats."""

    async def test_fakedb_before_0031_seeds_have_no_trash_group(
        self, schema_0030: ShippedSchema
    ) -> None:
        """Trashed seeds store no ``trash_group_id`` key; seeding one is refused
        (UndefinedColumnError, None included) and stores nothing."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        chat = db.add_chat(owner, deleted_at=D1)
        attachment = db.add_attachment(chat, deleted_at=D1)
        refused = []
        seeds: list[tuple[uuid.UUID | None, Any]] = [
            (None, uuid.uuid4()),
            (None, None),
            (chat, chat),
            (chat, None),
        ]
        for parent, group in seeds:
            try:
                if parent is None:
                    db.add_chat(owner, deleted_at=D1, trash_group_id=group)
                else:
                    db.add_attachment(parent, trash_group_id=group)
            except asyncpg.PostgresError as exc:
                refused.append(type(exc).__name__)
        chat_row, attachment_row = db.chat_row(chat), db.attachment_row(attachment)
        assert chat_row is not None
        assert attachment_row is not None

        assert (GROUP in chat_row, GROUP in attachment_row, refused) == (
            False,
            False,
            ["UndefinedColumnError"] * 4,
        )
        assert (len(db.chats_of(owner)), len(db.attachments_of(chat))) == (1, 1)

    async def test_fakedb_before_0031_every_form_naming_the_group_is_undefined(
        self, schema_0030: ShippedSchema
    ) -> None:
        """Even on empty tables (refused when parsed, as PostgreSQL does)."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        pool = db.pool
        some = uuid.uuid4()
        calls = {
            "S6'": pool.fetchrow(S6, some, ORG_ID, owner),
            "A10'": pool.execute(A10, some, ORG_ID),
            "A13": pool.fetchrow(A13, some, ORG_ID, owner),
            "T1c": pool.fetch(T1C, ORG_ID, owner, CUTOFF_30, 10),
            "T1c'": pool.fetch(T1C_AFTER, ORG_ID, owner, CUTOFF_30, D1, some, 10),
            "T1a": pool.fetch(T1A, ORG_ID, owner, CUTOFF_30, 10),
            "T1a'": pool.fetch(T1A_AFTER, ORG_ID, owner, CUTOFF_30, D1, some, 10),
            "T2": pool.fetchrow(T2, some, ORG_ID, owner, CUTOFF_30),
            "T3": pool.execute(T3, some, ORG_ID),
            "T4": pool.fetchval(T4, some, ORG_ID, owner, CUTOFF_30),
            "T6": pool.fetchrow(T6, some, ORG_ID, owner, CUTOFF_30),
            "T10": pool.fetchval(T10, some, ORG_ID, owner),
            "E2": pool.fetch(E2, ORG_ID, owner),
            "J4": pool.fetch(J4, ORG_ID, CUTOFF_30),
            "J5": pool.fetchval(J5, some, ORG_ID, CUTOFF_30),
        }
        outcomes = {name: await _outcome(call) for name, call in calls.items()}

        assert outcomes == dict.fromkeys(calls, "UndefinedColumnError")

    async def test_fakedb_before_0031_admino_app_may_not_delete_chats(
        self, schema_0030: ShippedSchema
    ) -> None:
        """T9 is InsufficientPrivilegeError and deletes nothing (no cascade either)."""
        db = FakeDb()
        chat = db.add_chat(db.add_account(org_id=ORG_ID), deleted_at=D1)
        db.add_chat_message(chat, "user", "kept")
        db.add_attachment(chat, deleted_at=D1)
        before = db.snapshot()

        outcome = await _outcome(db.pool.execute(T9, chat, ORG_ID))

        assert (outcome, db.snapshot() == before) == ("InsufficientPrivilegeError", True)


# ---------------------------------------------------------------------------
# 3. The columns, seeds, CHECKs, grants and catalog after 0031
# ---------------------------------------------------------------------------


class TestTrashGroupColumns:
    """0031's ``trash_group_id`` on chats and attachments."""

    async def test_fakedb_trash_group_is_the_last_column_and_null_by_default(
        self, schema_0031: ShippedSchema
    ) -> None:
        """ADD COLUMN appends it (after attachments.active); an INSERT without it and a
        live seed store NULL."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        seeded_chat = db.add_chat(owner)
        inserted_chat = plain(await db.pool.fetchval(CHAT_INSERT, ORG_ID, owner, "t"))
        seeded_file = db.add_attachment(seeded_chat)
        inserted_file = uuid.uuid4()
        await db.pool.execute(
            ATTACHMENT_INSERT, inserted_file, ORG_ID, seeded_chat, owner, "x.txt", "txt", 3
        )
        rows = [
            db.chat_row(seeded_chat),
            db.chat_row(inserted_chat),
            db.attachment_row(seeded_file),
            db.attachment_row(inserted_file),
        ]

        assert [(list(row or {})[-2:], (row or {}).get(GROUP, "missing")) for row in rows] == [
            (["deleted_at", GROUP], None),
            (["deleted_at", GROUP], None),
            (["active", GROUP], None),
            (["active", GROUP], None),
        ]

    async def test_fakedb_trash_group_seeds_follow_the_backfill(
        self, schema_0031: ShippedSchema
    ) -> None:
        """A trashed chat is its own group; a trashed file joins its trashed chat's
        group, else is its own; an explicit group is stored as given."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        live_chat = db.add_chat(owner)
        trashed_chat = db.add_chat(owner, deleted_at=D1)
        given_chat = uuid.uuid4()
        explicit_chat = db.add_chat(owner, deleted_at=D1, trash_group_id=given_chat)
        own_file = db.add_attachment(live_chat, deleted_at=D2)
        joined_file = db.add_attachment(trashed_chat, deleted_at=D1)
        explicit_file = db.add_attachment(trashed_chat, deleted_at=D5, trash_group_id=live_chat)

        assert {
            "live chat": _chat_group(db, live_chat),
            "trashed chat": _chat_group(db, trashed_chat),
            "explicit chat": _chat_group(db, explicit_chat),
            "own file": _file_group(db, own_file),
            "joined file": _file_group(db, joined_file),
            "explicit file": _file_group(db, explicit_file),
        } == {
            "live chat": (False, None),
            "trashed chat": (True, trashed_chat),
            "explicit chat": (True, given_chat),
            "own file": (True, own_file),
            "joined file": (True, trashed_chat),
            "explicit file": (True, live_chat),
        }


class TestTrashGroupChecks:
    """``chats_trash_group_check`` / ``attachments_trash_group_check``."""

    @pytest.mark.parametrize("table", ["chats", "attachments"])
    async def test_fakedb_trash_group_check_refuses_either_column_alone_on_seeds(
        self, schema_0031: ShippedSchema, table: str
    ) -> None:
        """Trashed without a group and a group without the trash: CheckViolationError
        on the table's constraint; nothing stored."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        chat = db.add_chat(owner)
        before = db.snapshot()
        constraints = []
        for deleted_at, group in ((D1, None), (None, uuid.uuid4())):
            with pytest.raises(asyncpg.CheckViolationError) as caught:
                if table == "chats":
                    db.add_chat(owner, deleted_at=deleted_at, trash_group_id=group)
                else:
                    db.add_attachment(chat, deleted_at=deleted_at, trash_group_id=group)
            constraints.append(caught.value.constraint_name)

        assert (constraints, db.snapshot() == before) == ([f"{table}_trash_group_check"] * 2, True)

    @pytest.mark.parametrize(
        ("table", "sql", "tail"),
        [
            ("chats", S6_OLD, ", null)."),
            (
                "chats",
                "UPDATE chats SET trash_group_id = id WHERE id = $1 AND org_id = $2",
                ", null, {chat}).",
            ),
            ("attachments", A10_OLD, ", t, null)."),
            (
                "attachments",
                "UPDATE attachments SET trash_group_id = id WHERE chat_id = $1 AND org_id = $2",
                ", t, {file}).",
            ),
        ],
        ids=["chat-old-s6", "chat-group-only", "file-old-a10", "file-group-only"],
    )
    async def test_fakedb_trash_group_check_refuses_updates_with_the_row_detail(
        self, schema_0031: ShippedSchema, table: str, sql: str, tail: str
    ) -> None:
        """The pre-0031 trash forms (deleted_at without a group) and a group without
        the trash fail on the table's CHECK, the group last in the "Failing row
        contains" detail (after deleted_at for a chat, after active for a file); the
        statement changes nothing."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        chat = db.add_chat(owner)
        attachment = db.add_attachment(chat)
        before = db.snapshot()
        args: tuple[Any, ...] = (chat, ORG_ID, owner) if "$3" in sql else (chat, ORG_ID)
        expected = tail.format(chat=chat, file=attachment)

        with pytest.raises(asyncpg.CheckViolationError) as caught:
            await db.pool.execute(sql, *args)

        assert (
            caught.value.constraint_name,
            str(caught.value)[-len(expected) :],
            db.snapshot() == before,
        ) == (f"{table}_trash_group_check", expected, True)

    async def test_fakedb_trash_group_check_runs_after_the_other_checks(
        self, schema_0031: ShippedSchema
    ) -> None:
        """A row breaking chats_title_check too reports that one first (name order)."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)

        with pytest.raises(asyncpg.CheckViolationError) as caught:
            db.add_chat(owner, title="x" * 201, deleted_at=D1, trash_group_id=None)

        assert caught.value.constraint_name == "chats_title_check"


class TestTrashGrants:
    """0031's grants: DELETE on chats, UPDATE (trash_group_id) on chats and attachments."""

    @pytest.mark.parametrize("granted", [True, False], ids=["granted", "revoked"])
    async def test_fakedb_trash_group_privileges_follow_the_shipped_grants(
        self, monkeypatch: pytest.MonkeyPatch, read_0031: ShippedSchema, granted: bool
    ) -> None:
        """With 0031's grants S6', A13 and T9 run; without them each is
        InsufficientPrivilegeError and changes nothing."""
        schema = read_0031
        if not granted:
            schema = dataclasses.replace(
                read_0031,
                chat_update_columns=db_fakes.CHAT_UPDATE_COLUMNS,
                attachment_update_columns=read_0031.attachment_update_columns - {GROUP},
                delete_tables=frozenset({"attachments"}),
            )
        _use(monkeypatch, schema)
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        chat = db.add_chat(owner)
        attachment = db.add_attachment(chat)
        doomed = db.add_chat(owner, deleted_at=D1)
        outcomes = [
            await _outcome(db.pool.fetchval(S6, chat, ORG_ID, owner)),
            await _outcome(db.pool.fetchval(A13, attachment, ORG_ID, owner)),
            await _outcome(db.pool.execute(T9, doomed, ORG_ID)),
        ]

        expected = ["ok", "ok", "ok:'DELETE 1'"] if granted else ["InsufficientPrivilegeError"] * 3
        assert (outcomes, _chat_group(db, chat)[0], db.chat_row(doomed) is None) == (
            expected,
            granted,
            granted,
        )

    async def test_fakedb_trash_grants_change_no_other_privilege(
        self, schema_0031: ShippedSchema
    ) -> None:
        """After 0031: DELETE chat_messages, UPDATE chats.owner_user_id /
        legacy_session_id and UPDATE attachments.chat_id stay refused (pg-verify)."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        chat = db.add_chat(owner)
        attachment = db.add_attachment(chat)
        before = db.snapshot()
        calls = [
            db.pool.execute("DELETE FROM chat_messages WHERE chat_id = $1", chat),
            db.pool.execute("UPDATE chats SET owner_user_id = $2 WHERE id = $1", chat, owner),
            db.pool.execute("UPDATE chats SET legacy_session_id = $2 WHERE id = $1", chat, "s"),
            db.pool.execute("UPDATE attachments SET chat_id = $2 WHERE id = $1", attachment, chat),
        ]

        outcomes = [await _outcome(call) for call in calls]

        assert (outcomes, db.snapshot() == before) == (["InsufficientPrivilegeError"] * 4, True)

    @pytest.mark.parametrize(
        ("schema", "recorded"),
        [("0030", ["chat.delete"]), ("0031", ["chat.delete", "chat.purge", "file.purge"])],
        ids=["0030", "0031"],
    )
    async def test_fakedb_trash_purge_actions_follow_the_shipped_catalog(
        self,
        monkeypatch: pytest.MonkeyPatch,
        read_0030: ShippedSchema,
        read_0031: ShippedSchema,
        schema: str,
        recorded: list[str],
    ) -> None:
        """chat.purge (with its file_count) and file.purge are refused by
        audit_events_action_check until 0031; chat.purged never."""
        _use(monkeypatch, read_0030 if schema == "0030" else read_0031)
        db = FakeDb()
        actor = db.add_account(org_id=ORG_ID)
        refused = []
        for action, target_type, metadata in (
            ("chat.delete", "chat", "{}"),
            ("chat.purge", "chat", json.dumps({"file_count": 2})),
            ("file.purge", "file", "{}"),
            ("chat.purged", "chat", "{}"),
        ):
            target = json.dumps([str(uuid.uuid4())])
            try:
                await db.pool.execute(
                    AUDIT_INSERT,
                    ORG_ID,
                    actor,
                    "member",
                    action,
                    target_type,
                    target,
                    None,
                    metadata,
                )
            except asyncpg.CheckViolationError as exc:
                refused.append(exc.constraint_name)

        assert ([row["action"] for row in db.audit_rows()], set(refused)) == (
            recorded,
            {"audit_events_action_check"},
        )


# ---------------------------------------------------------------------------
# 4. The SQL forms of contract §5 (0031's schema)
# ---------------------------------------------------------------------------


class TestTrashForms:
    """R1, S6' + A10', A13 (contract §4: the retention read and the two deletes)."""

    async def test_fakedb_r1_reads_the_retention_or_no_row(
        self, schema_0031: ShippedSchema
    ) -> None:
        """The org's stored value; an org without a row: None."""
        world = _world()

        assert [await world.db.pool.fetchval(R1, org) for org in (ORG_ID, OTHER_ORG_ID)] == [
            7,
            None,
        ]

    async def test_fakedb_s6_and_a10_trash_a_chat_with_its_live_files_as_one_group(
        self, schema_0031: ShippedSchema
    ) -> None:
        """The chat becomes its own group, its live files join it; files trashed before
        keep their group and stamp; a colleague's binding trashes nothing."""
        world = _world()
        db = world.db
        own_before = db.attachment_row(OWN_FILE)
        refused = await db.pool.fetchval(S6, LIVE_CHAT, ORG_ID, world.colleague)
        async with db.pool.acquire() as conn, conn.transaction():
            trashed = await conn.fetchval(S6, LIVE_CHAT, ORG_ID, world.owner)
            tag = await conn.execute(A10, LIVE_CHAT, ORG_ID)

        assert (refused, plain(trashed), tag) == (None, LIVE_CHAT, "UPDATE 1")
        assert (_chat_group(db, LIVE_CHAT), _file_group(db, LIVE_FILE)) == (
            (True, LIVE_CHAT),
            (True, LIVE_CHAT),
        )
        assert db.attachment_row(OWN_FILE) == own_before

    async def test_fakedb_a13_trashes_one_live_file_as_its_own_group(
        self, schema_0031: ShippedSchema
    ) -> None:
        """Returns the id once; a trashed file or a colleague's binding: no row."""
        world = _world()
        pool = world.db.pool

        answers = [
            await pool.fetchval(A13, LIVE_FILE, ORG_ID, world.colleague),
            await pool.fetchval(A13, LIVE_FILE, ORG_ID, world.owner),
            await pool.fetchval(A13, LIVE_FILE, ORG_ID, world.owner),
            await pool.fetchval(A13, OWN_FILE, ORG_ID, world.owner),
        ]

        assert (
            [a if a is None else plain(a) for a in answers],
            _file_group(world.db, LIVE_FILE),
        ) == (
            [None, LIVE_FILE, None, None],
            (True, LIVE_FILE),
        )


class TestTrashListForms:
    """T1c, T1c', T1a, T1a' (contract §4 list_trash)."""

    async def test_fakedb_t1c_lists_own_trashed_chats_newest_first_with_ties_by_id(
        self, schema_0031: ShippedSchema
    ) -> None:
        """deleted_at > cutoff, own group, the owner's only; the keyset pages concatenate
        to the full list across the D1 tie; LIMIT applies."""
        world = _world()
        pool = world.db.pool
        full = await pool.fetch(T1C, ORG_ID, world.owner, CUTOFF_30, 10)
        first = await pool.fetch(T1C, ORG_ID, world.owner, CUTOFF_30, 1)
        cursor = first[-1]
        rest = await pool.fetch(
            T1C_AFTER, ORG_ID, world.owner, CUTOFF_30, cursor["deleted_at"], cursor["id"], 10
        )

        assert _ids(full) == [TIE_CHAT, TRASHED_CHAT, SECOND_CHAT]
        assert (_ids(first) + _ids(rest), list(full[0].keys())) == (
            _ids(full),
            ["id", "title", "deleted_at"],
        )

    async def test_fakedb_t1c_cutoff_is_strict(self, schema_0031: ShippedSchema) -> None:
        """A chat deleted exactly at the cutoff is expired (not listed)."""
        world = _world()

        rows = await world.db.pool.fetch(T1C, ORG_ID, world.owner, D2, 10)

        assert _ids(rows) == [TIE_CHAT, TRASHED_CHAT]

    async def test_fakedb_t1a_lists_own_group_files_only(self, schema_0031: ShippedSchema) -> None:
        """Files deleted on their own (even in a trashed chat), not the files of a
        chat's group, not expired ones, not a colleague's; the keyset continues."""
        world = _world()
        pool = world.db.pool
        full = await pool.fetch(T1A, ORG_ID, world.owner, CUTOFF_30, 10)
        cursor = full[0]
        rest = await pool.fetch(
            T1A_AFTER, ORG_ID, world.owner, CUTOFF_30, cursor["deleted_at"], cursor["id"], 1
        )

        assert [(plain(r["id"]), plain(r["chat_id"]), r["filename"]) for r in full] == [
            (OWN_FILE, LIVE_CHAT, "own.pdf"),
            (EARLIER_FILE, TRASHED_CHAT, "earlier.pdf"),
        ]
        assert _ids(rest) == [EARLIER_FILE]

    @pytest.mark.parametrize(
        ("sql", "args"),
        [
            (T1C, (ORG_ID, "OWNER", datetime(2026, 1, 1), 10)),
            (T1C_AFTER, (ORG_ID, "OWNER", CUTOFF_30, "2026-10-08", uuid.uuid4(), 10)),
            (T2, (TRASHED_CHAT, ORG_ID, "OWNER", datetime(2026, 1, 1))),
            (J2, (ORG_ID, "2026-10-08T00:00:00+00:00")),
        ],
        ids=["t1c-naive", "t1c-after-str", "t2-naive", "j2-str"],
    )
    async def test_fakedb_trash_timestamp_parameters_must_be_aware_datetimes(
        self, schema_0031: ShippedSchema, sql: str, args: tuple[Any, ...]
    ) -> None:
        """A naive datetime or a str for a cutoff / cursor stamp is a DataError."""
        world = _world()
        bound = tuple(world.owner if arg == "OWNER" else arg for arg in args)

        assert await _outcome(world.db.pool.fetch(sql, *bound)) == "DataError"


class TestTrashRestoreForms:
    """T2, T3, T4, T6 (contract §4 restore_chat, restore_attachment)."""

    async def test_fakedb_t2_and_t3_restore_a_chat_and_exactly_its_group(
        self, schema_0031: ShippedSchema
    ) -> None:
        """T2 returns the chat record and clears both columns; T3 brings back the two
        files of its group, not the file deleted on its own before it."""
        world = _world()
        db = world.db
        record = await db.pool.fetchrow(T2, TRASHED_CHAT, ORG_ID, world.owner, CUTOFF_30)
        tag = await db.pool.execute(T3, TRASHED_CHAT, ORG_ID)
        assert record is not None

        assert (list(record.keys()), plain(record["id"]), record["title"], tag) == (
            list(CR_COLUMNS),
            TRASHED_CHAT,
            "trashed",
            "UPDATE 2",
        )
        assert {
            "chat": _chat_group(db, TRASHED_CHAT),
            "a": _file_group(db, GROUP_FILE_A),
            "b": _file_group(db, GROUP_FILE_B),
            "earlier": _file_group(db, EARLIER_FILE),
        } == {
            "chat": (False, None),
            "a": (False, None),
            "b": (False, None),
            "earlier": (True, EARLIER_FILE),
        }

    async def test_fakedb_t2_finds_no_expired_live_or_foreign_chat(
        self, schema_0031: ShippedSchema
    ) -> None:
        """Expired (cutoff after deleted_at), live, a colleague's binding: no row,
        nothing changed; a longer retention restores the old chat."""
        world = _world()
        db = world.db
        before = db.snapshot()
        misses = [
            await db.pool.fetchrow(T2, OLD_CHAT, ORG_ID, world.owner, CUTOFF_30),
            await db.pool.fetchrow(T2, LIVE_CHAT, ORG_ID, world.owner, CUTOFF_30),
            await db.pool.fetchrow(T2, TRASHED_CHAT, ORG_ID, world.colleague, CUTOFF_30),
            await db.pool.fetchrow(T2, TRASHED_CHAT, OTHER_ORG_ID, world.owner, CUTOFF_30),
        ]
        unchanged = db.snapshot() == before
        longer = await db.pool.fetchrow(T2, OLD_CHAT, ORG_ID, world.owner, NOW - timedelta(60))

        assert (misses, unchanged, longer is not None) == ([None] * 4, True, True)

    async def test_fakedb_t2_of_a_legacy_chat_whose_session_is_live_is_a_unique_violation(
        self, schema_0031: ShippedSchema
    ) -> None:
        """chats_legacy_session_key (the owner's live chat with the same session):
        UniqueViolationError with the constraint name; nothing changed. A colleague's
        live chat with the same session id doesn't conflict."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        colleague = db.add_account(org_id=ORG_ID)
        trashed = db.add_chat(owner, legacy_session_id="sess-1", deleted_at=D1)
        db.add_chat(owner, legacy_session_id="sess-1")
        free = db.add_chat(owner, legacy_session_id="sess-2", deleted_at=D1)
        db.add_chat(colleague, legacy_session_id="sess-2")
        before = db.snapshot()

        with pytest.raises(asyncpg.UniqueViolationError) as caught:
            await db.pool.fetchrow(T2, trashed, ORG_ID, owner, CUTOFF_30)
        unchanged = db.snapshot() == before
        restored = await db.pool.fetchrow(T2, free, ORG_ID, owner, CUTOFF_30)

        assert (caught.value.constraint_name, unchanged, restored is not None) == (
            "chats_legacy_session_key",
            True,
            True,
        )

    async def test_fakedb_t4_and_t6_restore_an_own_group_file_only(
        self, schema_0031: ShippedSchema
    ) -> None:
        """T4 gives its chat; T6 clears both columns and returns the AR record. A
        file of a chat's group, an expired file and a colleague's binding: no row."""
        world = _world()
        db = world.db
        misses = [
            await db.pool.fetchval(T4, GROUP_FILE_A, ORG_ID, world.owner, CUTOFF_30),
            await db.pool.fetchval(T4, OLD_FILE, ORG_ID, world.owner, CUTOFF_30),
            await db.pool.fetchval(T4, OWN_FILE, ORG_ID, world.colleague, CUTOFF_30),
            await db.pool.fetchrow(T6, GROUP_FILE_A, ORG_ID, world.owner, CUTOFF_30),
            await db.pool.fetchrow(T6, OLD_FILE, ORG_ID, world.owner, CUTOFF_30),
        ]
        chat = await db.pool.fetchval(T4, OWN_FILE, ORG_ID, world.owner, CUTOFF_30)
        record = await db.pool.fetchrow(T6, OWN_FILE, ORG_ID, world.owner, CUTOFF_30)
        assert record is not None

        assert (misses, plain(chat)) == ([None] * 5, LIVE_CHAT)
        assert (list(record.keys()), plain(record["id"]), record["active"]) == (
            list(AR_COLUMNS),
            OWN_FILE,
            True,
        )
        assert (_file_group(db, OWN_FILE), _file_group(db, GROUP_FILE_A)) == (
            (False, None),
            (True, TRASHED_CHAT),
        )


class TestTrashPurgeForms:
    """T7, T8, T9, T10, E1, E2 (contract §4 purge_chat, purge_attachment, empty_trash)."""

    async def test_fakedb_t7_locks_the_owners_trashed_chat_only(
        self, schema_0031: ShippedSchema
    ) -> None:
        """FOR UPDATE is recorded; a trashed chat of the owner: its id (expired too);
        a live chat, a colleague's binding: no row."""
        world = _world()
        pool = world.db.pool

        answers = [
            await pool.fetchval(T7, chat, ORG_ID, owner)
            for chat, owner in (
                (TRASHED_CHAT, world.owner),
                (OLD_CHAT, world.owner),
                (LIVE_CHAT, world.owner),
                (TRASHED_CHAT, world.colleague),
            )
        ]

        assert [a if a is None else plain(a) for a in answers] == [
            TRASHED_CHAT,
            OLD_CHAT,
            None,
            None,
        ]
        assert len(world.db.matching(r"deleted_at is not null for update$")) == 4

    async def test_fakedb_t8_lists_every_attachment_row_of_the_chat(
        self, schema_0031: ShippedSchema
    ) -> None:
        """Any state (the chat's group and a file trashed on its own); another org's
        binding: none."""
        world = _world()

        rows = await world.db.pool.fetch(T8, TRASHED_CHAT, ORG_ID)
        foreign = await world.db.pool.fetch(T8, TRASHED_CHAT, OTHER_ORG_ID)

        assert (sorted(_ids(rows)), foreign) == (
            sorted([GROUP_FILE_A, GROUP_FILE_B, EARLIER_FILE]),
            [],
        )

    async def test_fakedb_t9_deletes_the_chat_with_its_messages_and_files(
        self, schema_0031: ShippedSchema
    ) -> None:
        """ "DELETE 1"; the chat's messages and every attachment row go with it; every
        other chat's rows stay; another org's binding deletes nothing."""
        world = _world()
        db = world.db
        others = {
            "chats": sorted(key for key in db.chats if key != TRASHED_CHAT),
            "messages": sorted(
                m["id"] for m in db.chat_messages.values() if m["chat_id"] != TRASHED_CHAT
            ),
            "files": sorted(
                key for key, a in db.attachments.items() if a["chat_id"] != TRASHED_CHAT
            ),
        }
        foreign = await db.pool.execute(T9, TRASHED_CHAT, OTHER_ORG_ID)

        tag = await db.pool.execute(T9, TRASHED_CHAT, ORG_ID)

        assert (foreign, tag) == ("DELETE 0", "DELETE 1")
        assert {
            "chats": sorted(db.chats),
            "messages": sorted(m["id"] for m in db.chat_messages.values()),
            "files": sorted(db.attachments),
        } == others

    async def test_fakedb_t9_rolls_back_with_its_transaction(
        self, schema_0031: ShippedSchema
    ) -> None:
        """A failure after T9 in the same transaction restores the chat, its messages
        and its files."""
        world = _world()
        db = world.db
        before = db.snapshot()

        with pytest.raises(RuntimeError):
            async with db.pool.acquire() as conn, conn.transaction():
                await conn.execute(T9, TRASHED_CHAT, ORG_ID)
                raise RuntimeError

        assert db.snapshot() == before

    async def test_fakedb_t10_deletes_an_own_group_trashed_file_only(
        self, schema_0031: ShippedSchema
    ) -> None:
        """Returns the id (an expired one too); a file of a chat's group, a live file
        and a colleague's binding: no row, still stored."""
        world = _world()
        db = world.db
        answers = [
            await db.pool.fetch(T10, attachment, ORG_ID, owner)
            for attachment, owner in (
                (GROUP_FILE_A, world.owner),
                (LIVE_FILE, world.owner),
                (OWN_FILE, world.colleague),
                (OWN_FILE, world.owner),
                (OLD_FILE, world.owner),
            )
        ]

        assert [_ids(rows) for rows in answers] == [[], [], [], [OWN_FILE], [OLD_FILE]]
        assert sorted(
            key for key in (GROUP_FILE_A, LIVE_FILE, OWN_FILE, OLD_FILE) if key in db.attachments
        ) == sorted([GROUP_FILE_A, LIVE_FILE])

    async def test_fakedb_e1_and_e2_list_every_trashed_item_by_id(
        self, schema_0031: ShippedSchema
    ) -> None:
        """Expired ones included; E2 only files of their own group; the owner's only."""
        world = _world()
        pool = world.db.pool

        chats = await pool.fetch(E1, ORG_ID, world.owner)
        files = await pool.fetch(E2, ORG_ID, world.owner)

        assert (_ids(chats), _ids(files)) == (
            sorted([TRASHED_CHAT, TIE_CHAT, SECOND_CHAT, OLD_CHAT]),
            sorted([OWN_FILE, OLD_FILE, EARLIER_FILE]),
        )


class TestTrashJobForms:
    """J1 to J5 (contract §4 purge_expired)."""

    async def test_fakedb_j1_is_the_distinct_ordered_union_of_orgs_with_trash(
        self, schema_0031: ShippedSchema
    ) -> None:
        """Orgs with a trashed chat or file (a file alone counts), each once, by id;
        an org with live rows only: absent."""
        world = _world()

        rows = await world.db.pool.fetch(J1)

        assert ([list(row.keys()) for row in rows[:1]], _ids(rows, "org_id")) == (
            [["org_id"]],
            [FILE_ONLY_ORG, ORG_ID, OTHER_ORG_ID],
        )

    async def test_fakedb_j2_and_j3_find_expired_chats_with_an_inclusive_cutoff(
        self, schema_0031: ShippedSchema
    ) -> None:
        """J2: the org's chats with deleted_at <= cutoff (any owner) by deleted_at then
        id; J3: one of them, locked; a chat deleted exactly at the cutoff is
        expired; another org's binding: none."""
        world = _world()
        pool = world.db.pool
        expired = await pool.fetch(J2, ORG_ID, CUTOFF_30)
        at_d1 = await pool.fetch(J2, ORG_ID, D1)
        foreign = await pool.fetch(J2, OTHER_ORG_ID, CUTOFF_30)
        locked = [
            await pool.fetchval(J3, chat, org, cutoff)
            for chat, org, cutoff in (
                (OLD_CHAT, ORG_ID, CUTOFF_30),
                (TRASHED_CHAT, ORG_ID, CUTOFF_30),
                (OLD_CHAT, OTHER_ORG_ID, CUTOFF_30),
                (LIVE_CHAT, ORG_ID, NOW),
            )
        ]

        assert (_ids(expired), _ids(at_d1), _ids(foreign)) == (
            [OLD_CHAT],
            [OLD_CHAT, SECOND_CHAT, *sorted([TRASHED_CHAT, TIE_CHAT, COLLEAGUE_CHAT])],
            [FOREIGN_CHAT],
        )
        assert [a if a is None else plain(a) for a in locked] == [OLD_CHAT, None, None, None]
        assert len(world.db.matching(r"deleted_at <= \$3 for update$")) == 4

    async def test_fakedb_j4_and_j5_find_and_delete_expired_own_group_files(
        self, schema_0031: ShippedSchema
    ) -> None:
        """J4: the org's own-group files with deleted_at <= cutoff (any owner); a
        chat's group file is not one. J5 deletes one and returns its id; a group file
        or an unexpired file: no row."""
        world = _world()
        db = world.db
        expired = await db.pool.fetch(J4, ORG_ID, CUTOFF_30)
        at_d2 = await db.pool.fetch(J4, ORG_ID, D2)
        deleted = [
            await db.pool.fetch(J5, attachment, ORG_ID, CUTOFF_30)
            for attachment in (OLD_GROUP_FILE, OWN_FILE, OLD_FILE)
        ]

        assert (_ids(expired), _ids(at_d2)) == (
            [OLD_FILE],
            [OLD_FILE, EARLIER_FILE, *sorted([OWN_FILE, COLLEAGUE_FILE])],
        )
        assert ([_ids(rows) for rows in deleted], OLD_FILE in db.attachments) == (
            [[], [], [OLD_FILE]],
            False,
        )
