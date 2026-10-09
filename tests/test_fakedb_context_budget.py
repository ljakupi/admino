"""The FakeDb's own spec for migration 0030 and GH-190's SQL forms (tests/db_fakes.py).

Issue #190, Decision 10 and contract C5, C6, C7, C10. The fake models the schema
the shipped migrations leave in place (``db_fakes.shipped_schema()``, read from
the migrations next to ``admino.database``): until a shipped migration adds
``attachments.active`` and replaces the two CHECKs, it is 0029's schema; once
``0030_*.sql`` does, it is 0030's. These tests switch it with a tmp copy of the
migrations (0001 to 0029, with or without the contract's 0030) and
``monkeypatch.setattr(db_fakes, "shipped_schema", ...)``.

What these tests pin down:
- The schema reader: 0001-0029 give no ``active`` column, 0029's eight UPDATE
  columns, max_context_messages 1 to 200 and 0027's action catalog; adding the
  contract's 0030 gives the column, its UPDATE grant, 0 to 200 and the catalog
  plus file.exclude / file.include; a 0030 whose statements are only described
  in comments changes nothing. The tree's own migrations give 0030's schema
  (RED until the migration ships).
- Before 0030: ``add_attachment`` stores no ``active`` key and refuses
  ``active=False`` (UndefinedColumnError); every form naming ``active`` (T2'',
  A8'', A5', A6', A10a, A10b, A11, A11', A12, P6) is UndefinedColumnError even
  on an empty table; 0 is refused for max_context_messages; file.exclude and
  file.include are refused by ``audit_events_action_check``.
- After 0030: ``active`` defaults to true (``add_attachment`` and an INSERT
  without it), ``add_attachment(active=False)`` stores false, a non-bool is a
  DataError and NULL a NotNullViolationError, ``active`` comes last in the
  "Failing row contains" detail, admino_app may UPDATE it (and without the
  grant may not), 0 to 200 are stored for max_context_messages, the two new
  actions are recorded.
- The SQL forms run as PostgreSQL answers them: T2'' (six-element text arrays,
  only sent, live, ready, active files, by the carrying message then upload
  order), A8'' (every live listed file of the chat with its estimate, bytes
  and flag), A5' / A6' (the R list with ``active``), A10a (FOR UPDATE,
  recorded; trashed or a colleague's: no row) and A10b (one row, org-scoped,
  rolled back with its transaction), A11 / A11' (both filters, created_at then
  id, LIMIT, the keyset cursor on a created_at tie, typed filter parameters),
  A12, P6 (an int sum over the chat's other live, ready, active files, 0 when
  there are none), P3'' (failed with reason and estimate, only while
  processing), S9' / S11' (each message's live attachment ids by created_at
  then id, ``[]`` without files; also before 0030).
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

# Contract C10, as verified on postgres:16 (the action list: 0027's, plus the two
# new actions after file.restore).
MIGRATION_0030: Final = """
-- Migration 0030 (GH-190): token-based context budgeting and attachment exclusion.
-- ALTER TABLE attachments ADD COLUMN active (the comment must not count).
ALTER TABLE attachments ADD COLUMN active BOOLEAN NOT NULL DEFAULT true;
GRANT UPDATE (active) ON attachments TO admino_app;
ALTER TABLE platform_settings DROP CONSTRAINT platform_settings_max_context_messages_check;
ALTER TABLE platform_settings ADD CONSTRAINT platform_settings_max_context_messages_check
    CHECK (max_context_messages BETWEEN 0 AND 200);
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
    'project.delete', 'project.restore', 'chat.delete', 'chat.restore',
    'file.upload', 'file.delete', 'file.restore', 'file.exclude', 'file.include',
    'project.admin_access', 'export.create',
    'org.settings_change', 'org.create', 'org.limits_change', 'org.deactivate',
    'org.reactivate', 'org.deletion_schedule', 'org.deletion_cancel', 'org.purge',
    'org.residency_change', 'platform.settings_change', 'model.registry_change',
    'breakglass.start', 'breakglass.end', 'tool.call', 'audit.purge',
    'org.permission_change', 'org.permission_promote', 'org.permission_promote_cancel',
    'org.permission_demote'
));
"""
# A 0030 that only describes the statements in its comments.
MIGRATION_COMMENTS_ONLY: Final = """
-- ALTER TABLE attachments ADD COLUMN active BOOLEAN NOT NULL DEFAULT true;
-- GRANT UPDATE (active) ON attachments TO admino_app;
/* ALTER TABLE platform_settings ADD CONSTRAINT platform_settings_max_context_messages_check
       CHECK (max_context_messages BETWEEN 0 AND 200);
   ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK (action IN (
       'file.exclude')); */
SELECT 1;
"""

UPDATE_COLUMNS_0029: Final = frozenset(
    {
        "message_id",
        "status",
        "failure_reason",
        "page_count",
        "token_estimate",
        "derived_bytes",
        "updated_at",
        "deleted_at",
    }
)
TOGGLE_ACTIONS: Final = frozenset({"file.exclude", "file.include"})

# The R list of contract C6 (A5', A6', A10a, A11, A11'), ``active`` before created_at.
R_COLUMNS: Final = (
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

# Contract C5 (T2'', S9', S11').
T2: Final = """
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
S9: Final = (
    _S9_HEAD
    + """
    WHERE m.chat_id = $1 AND m.org_id = $2
    ORDER BY m.seq DESC
    LIMIT $3
"""
)
S11: Final = (
    _S9_HEAD
    + """
    WHERE m.chat_id = $1 AND m.org_id = $2 AND m.seq < $3
    ORDER BY m.seq DESC
    LIMIT $4
"""
)

# Contract C6 (A5', A6', A8'', A10a, A10b, A11, A11', A12).
A5: Final = """
    INSERT INTO attachments (id, org_id, chat_id, owner_user_id, filename, kind, size_bytes)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
              page_count, token_estimate, active, created_at
"""
A6: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, token_estimate, active, created_at
    FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
"""
A8: Final = """
    SELECT id, message_id, status, filename, kind, page_count, token_estimate, derived_bytes, active
    FROM attachments
    WHERE id = ANY($1::uuid[]) AND chat_id = $2 AND org_id = $3 AND owner_user_id = $4
      AND deleted_at IS NULL
    ORDER BY created_at, id
"""
A10A: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, token_estimate, active, created_at
    FROM attachments
    WHERE id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
    FOR UPDATE
"""
A10B: Final = "UPDATE attachments SET active = $3 WHERE id = $1 AND org_id = $2"
_A11_HEAD: Final = """
    SELECT id, chat_id, message_id, filename, kind, size_bytes, status, failure_reason,
           page_count, token_estimate, active, created_at
    FROM attachments
    WHERE chat_id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
      AND status = coalesce($4, status) AND active = coalesce($5, active)
"""
A11: Final = (
    _A11_HEAD
    + """
    ORDER BY created_at, id
    LIMIT $6
"""
)
A11_AFTER: Final = (
    _A11_HEAD
    + """
      AND (created_at, id) > ($6, $7)
    ORDER BY created_at, id
    LIMIT $8
"""
)
A12: Final = """
    SELECT id, filename, kind, page_count, token_estimate, derived_bytes
    FROM attachments
    WHERE chat_id = $1 AND org_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
      AND status = 'ready' AND active
    ORDER BY created_at, id
"""
# Contract C7 (P6, P3'').
P6: Final = """
    SELECT coalesce(sum(o.token_estimate), 0)
    FROM attachments a
    JOIN attachments o ON o.chat_id = a.chat_id AND o.org_id = a.org_id
        AND o.owner_user_id = a.owner_user_id
    WHERE a.id = $1 AND a.org_id = $2 AND o.id <> a.id
      AND o.status = 'ready' AND o.active AND o.deleted_at IS NULL
"""
P3: Final = """
    UPDATE attachments SET status = 'failed', failure_reason = $3, token_estimate = $4,
        updated_at = now()
    WHERE id = $1 AND org_id = $2 AND status = 'processing'
"""

AUDIT_INSERT: Final = """
    INSERT INTO audit_events
        (org_id, actor_user_id, actor_kind, action, target_type, target_ids, ip, metadata)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::inet, $8::jsonb)
"""
PLATFORM_UPDATE: Final = (
    "UPDATE platform_settings SET max_context_messages = coalesce($1, max_context_messages),"
    " updated_at = now() WHERE id"
)

_T0: Final = datetime(2026, 10, 9, 8, 0, 0, 250000, tzinfo=UTC)
_T1: Final = _T0 + timedelta(seconds=1)
_T2: Final = _T0 + timedelta(seconds=2)
_T3: Final = _T0 + timedelta(seconds=3)

# The main chat's files. Their ids sort against their upload order, and the two
# created_at ties (T1, T2, T3) are stored in reverse id order.
SENT_READY: Final = uuid.UUID("c1900000-0000-4000-8000-000000000001")  # m1, T1
SENT_INACTIVE: Final = uuid.UUID("11900000-0000-4000-8000-000000000002")  # m1, T2, excluded
LATER_READY: Final = uuid.UUID("e1900000-0000-4000-8000-000000000003")  # m3, T0
SENT_PROCESSING: Final = uuid.UUID("a1900000-0000-4000-8000-000000000004")  # m3, T2
UNSENT_READY: Final = uuid.UUID("b1900000-0000-4000-8000-000000000005")  # T3
UNSENT_UPLOADED: Final = uuid.UUID("21900000-0000-4000-8000-000000000006")  # T3
TRASHED: Final = uuid.UUID("01900000-0000-4000-8000-000000000007")  # m1, T0, trashed
FAILED: Final = uuid.UUID("31900000-0000-4000-8000-000000000008")  # T1, context_overflow
# Elsewhere: the owner's other chat, a colleague's chat, another org's chat.
OTHER_CHAT_FILE: Final = uuid.UUID("41900000-0000-4000-8000-000000000009")
COLLEAGUE_FILE: Final = uuid.UUID("51900000-0000-4000-8000-00000000000a")
FOREIGN_FILE: Final = uuid.UUID("61900000-0000-4000-8000-00000000000b")
UNKNOWN: Final = uuid.UUID("71900000-0000-4000-8000-00000000000c")

# Every live file of the main chat, by created_at then id.
LIVE_ORDER: Final = (
    LATER_READY,
    FAILED,
    SENT_READY,
    SENT_INACTIVE,
    SENT_PROCESSING,
    UNSENT_UPLOADED,
    UNSENT_READY,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _migrations_copy(target: Path, extra: str | None, *, through: int = 29) -> Path:
    """0001 to ``through`` (0029) of the shipped migrations in ``target``, plus ``extra``
    as 0030."""
    from admino import database

    source = Path(database.__file__).parent / "migrations"
    target.mkdir()
    for path in sorted(source.glob("*.sql")):
        match = re.match(r"(\d{4})_", path.name)
        if match is not None and int(match.group(1)) <= through:
            shutil.copyfile(path, target / path.name)
    if extra is not None:
        (target / "0030_context_budget.sql").write_text(extra, encoding="utf-8")
    return target


@pytest.fixture()
def read_0029(tmp_path: Path) -> ShippedSchema:
    """What 0001 to 0029 leave in place (unpatched)."""
    return db_fakes.read_shipped_schema(_migrations_copy(tmp_path / "m0029", None))


@pytest.fixture()
def read_0030(tmp_path: Path) -> ShippedSchema:
    """What 0001 to 0029 plus the contract's 0030 leave in place (unpatched)."""
    return db_fakes.read_shipped_schema(_migrations_copy(tmp_path / "m0030", MIGRATION_0030))


def _use(monkeypatch: pytest.MonkeyPatch, schema: ShippedSchema) -> ShippedSchema:
    monkeypatch.setattr(db_fakes, "shipped_schema", lambda: schema)
    return schema


@pytest.fixture()
def schema_0029(monkeypatch: pytest.MonkeyPatch, read_0029: ShippedSchema) -> ShippedSchema:
    """The fake runs 0029's schema."""
    return _use(monkeypatch, read_0029)


@pytest.fixture()
def schema_0030(monkeypatch: pytest.MonkeyPatch, read_0030: ShippedSchema) -> ShippedSchema:
    """The fake runs 0030's schema."""
    return _use(monkeypatch, read_0030)


@pytest.fixture(params=["0029", "0030"])
def either_schema(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    read_0029: ShippedSchema,
    read_0030: ShippedSchema,
) -> ShippedSchema:
    """The fake runs 0029's, then 0030's schema (forms that don't name ``active``)."""
    return _use(monkeypatch, read_0029 if request.param == "0029" else read_0030)


@dataclass(frozen=True)
class _World:
    db: FakeDb
    owner: uuid.UUID
    colleague: uuid.UUID
    chat: uuid.UUID
    other_chat: uuid.UUID
    colleague_chat: uuid.UUID
    foreign_chat: uuid.UUID
    m1: uuid.UUID
    m2: uuid.UUID
    m3: uuid.UUID


def _world(*, with_active: bool) -> _World:
    """The main chat (three messages, eight files) and three other chats' files.

    ``with_active``: SENT_INACTIVE is excluded (0030); otherwise it is seeded with
    the column's default (0029 has no column).
    """
    db = FakeDb()
    owner = db.add_account(org_id=ORG_ID)
    colleague = db.add_account(org_id=ORG_ID)
    foreigner = db.add_account(org_id=OTHER_ORG_ID)
    chat = db.add_chat(owner, title="main", created_at=_T0)
    other_chat = db.add_chat(owner, created_at=_T0)
    colleague_chat = db.add_chat(colleague, created_at=_T0)
    foreign_chat = db.add_chat(foreigner, created_at=_T0)
    m1 = db.add_chat_message(chat, "user", "first", created_at=_T1)
    m2 = db.add_chat_message(chat, "assistant", "answer", created_at=_T1)
    m3 = db.add_chat_message(chat, "user", "second", created_at=_T2)
    ready: dict[str, Any] = {"status": "ready"}
    db.add_attachment(
        chat, attachment_id=UNSENT_UPLOADED, filename="f.txt", kind="txt", created_at=_T3
    )
    db.add_attachment(
        chat,
        attachment_id=UNSENT_READY,
        filename="e.csv",
        kind="csv",
        page_count=0,
        token_estimate=30,
        derived_bytes=300,
        created_at=_T3,
        **ready,
    )
    db.add_attachment(
        chat,
        attachment_id=SENT_PROCESSING,
        filename="d.png",
        kind="png",
        status="processing",
        message_id=m3,
        created_at=_T2,
    )
    db.add_attachment(
        chat,
        attachment_id=SENT_INACTIVE,
        filename="b.txt",
        kind="txt",
        token_estimate=50,
        derived_bytes=500,
        message_id=m1,
        created_at=_T2,
        **ready,
        **({"active": False} if with_active else {}),
    )
    db.add_attachment(
        chat,
        attachment_id=SENT_READY,
        filename="a.pdf",
        kind="pdf",
        page_count=2,
        token_estimate=100,
        derived_bytes=1000,
        message_id=m1,
        created_at=_T1,
        **ready,
    )
    db.add_attachment(
        chat,
        attachment_id=FAILED,
        filename="h.pdf",
        kind="pdf",
        status="failed",
        failure_reason="context_overflow",
        token_estimate=999,
        created_at=_T1,
    )
    db.add_attachment(
        chat,
        attachment_id=LATER_READY,
        filename="c.md",
        kind="md",
        message_id=m3,
        created_at=_T0,
        **ready,
    )
    db.add_attachment(
        chat,
        attachment_id=TRASHED,
        filename="g.pdf",
        kind="pdf",
        token_estimate=7,
        derived_bytes=70,
        message_id=m1,
        created_at=_T0,
        deleted_at=_T3,
        **ready,
    )
    db.add_attachment(
        other_chat,
        attachment_id=OTHER_CHAT_FILE,
        token_estimate=1000,
        derived_bytes=9,
        created_at=_T1,
        **ready,
    )
    db.add_attachment(
        colleague_chat,
        attachment_id=COLLEAGUE_FILE,
        token_estimate=2000,
        created_at=_T1,
        **ready,
    )
    db.add_attachment(
        foreign_chat, attachment_id=FOREIGN_FILE, token_estimate=3000, created_at=_T1, **ready
    )
    return _World(db, owner, colleague, chat, other_chat, colleague_chat, foreign_chat, m1, m2, m3)


def _ids(rows: list[Any], key: str = "id") -> list[uuid.UUID]:
    return [plain(row[key]) for row in rows]


async def _outcome(call: Any) -> str:
    """The awaited call's result, or its exception's class name."""
    try:
        result = await call
    except asyncpg.PostgresError as exc:
        return type(exc).__name__
    return f"ok:{result!r}" if isinstance(result, str) else "ok"


# ---------------------------------------------------------------------------
# 1. The schema reader
# ---------------------------------------------------------------------------


class TestShippedSchemaReader:
    """``read_shipped_schema`` reads what a migrations directory leaves in place."""

    def test_fakedb_schema_of_0001_to_0029_is_the_0029_schema(
        self, read_0029: ShippedSchema
    ) -> None:
        """No ``active`` column, 0029's eight UPDATE columns, 1 to 200, 0027's catalog."""
        assert read_0029 == ShippedSchema(
            attachments_active=False,
            attachment_update_columns=UPDATE_COLUMNS_0029,
            max_context_messages_bounds=(1, 200),
            audit_actions=db_fakes.AUDIT_ACTIONS,
        )

    def test_fakedb_schema_with_the_contract_0030_is_the_0030_schema(
        self, read_0030: ShippedSchema
    ) -> None:
        """The column, its UPDATE grant, 0 to 200 and the two new actions."""
        assert read_0030 == ShippedSchema(
            attachments_active=True,
            attachment_update_columns=UPDATE_COLUMNS_0029 | {"active"},
            max_context_messages_bounds=(0, 200),
            audit_actions=db_fakes.AUDIT_ACTIONS | TOGGLE_ACTIONS,
        )

    def test_fakedb_schema_ignores_statements_in_comments(
        self, tmp_path: Path, read_0029: ShippedSchema
    ) -> None:
        """A 0030 that only describes the statements in comments changes nothing."""
        directory = _migrations_copy(tmp_path / "comments", MIGRATION_COMMENTS_ONLY)

        assert db_fakes.read_shipped_schema(directory) == read_0029

    def test_fakedb_schema_revoked_update_column_is_not_granted(
        self, tmp_path: Path, read_0030: ShippedSchema
    ) -> None:
        """A later ``REVOKE UPDATE (active) ON attachments FROM admino_app`` takes the
        column out of the grant (and only it)."""
        revoked = MIGRATION_0030 + "REVOKE UPDATE (active) ON attachments FROM admino_app;\n"
        directory = _migrations_copy(tmp_path / "revoked", revoked)

        assert db_fakes.read_shipped_schema(directory) == dataclasses.replace(
            read_0030, attachment_update_columns=UPDATE_COLUMNS_0029
        )

    def test_fakedb_shipped_migrations_give_the_0030_schema(
        self, tmp_path: Path, read_0030: ShippedSchema
    ) -> None:
        """The tree's own migrations through 0030 (what the fake uses unpatched, later
        migrations on top) leave 0030's schema, and the fake's import-time UPDATE grant
        is the shipped one, 0030's included (RED until 0030 ships). GH-194: read
        through 0030, as 0031 adds its own parts (tests/test_fakedb_trash.py)."""
        tree = db_fakes.read_shipped_schema(_migrations_copy(tmp_path / "tree", None, through=30))
        grant = db_fakes.ATTACHMENT_UPDATE_COLUMNS

        assert (tree, grant == db_fakes.shipped_schema().attachment_update_columns) == (
            read_0030,
            True,
        )
        assert read_0030.attachment_update_columns <= grant


# ---------------------------------------------------------------------------
# 2. attachments.active before migration 0030
# ---------------------------------------------------------------------------


class TestBefore0030:
    """0029's schema: there is no ``active`` column."""

    async def test_fakedb_before_0030_seeded_rows_have_no_active_column(
        self, schema_0029: ShippedSchema
    ) -> None:
        """``add_attachment()`` stores no ``active``; ``active=False`` is refused."""
        db = FakeDb()
        chat = db.add_chat(db.add_account(org_id=ORG_ID))
        attachment = db.add_attachment(chat)
        row = db.attachment_row(attachment)
        assert row is not None

        with pytest.raises(asyncpg.UndefinedColumnError):
            db.add_attachment(chat, active=False)
        assert ("active" in row, len(db.attachments_of(chat))) == (False, 1)

    async def test_fakedb_before_0030_every_form_naming_active_is_undefined(
        self, schema_0029: ShippedSchema
    ) -> None:
        """Even on an empty attachments table (refused when parsed, as PostgreSQL does)."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        chat = db.add_chat(owner)
        pool = db.pool
        any_id = uuid.uuid4()
        calls = {
            "T2''": pool.fetch(T2, chat, ORG_ID, owner, 10),
            "A5'": pool.fetchrow(A5, any_id, ORG_ID, chat, owner, "a.pdf", "pdf", 1),
            "A6'": pool.fetchrow(A6, any_id, ORG_ID, owner),
            "A8''": pool.fetch(A8, [any_id], chat, ORG_ID, owner),
            "A10a": pool.fetchrow(A10A, any_id, ORG_ID, owner),
            "A10b": pool.execute(A10B, any_id, ORG_ID, False),
            "A11": pool.fetch(A11, chat, ORG_ID, owner, None, None, 10),
            "A11'": pool.fetch(A11_AFTER, chat, ORG_ID, owner, None, None, _T0, any_id, 10),
            "A12": pool.fetch(A12, chat, ORG_ID, owner),
            "P6": pool.fetchval(P6, any_id, ORG_ID),
        }
        outcomes = {name: await _outcome(call) for name, call in calls.items()}

        assert outcomes == dict.fromkeys(calls, "UndefinedColumnError")
        assert db.attachments == {}


# ---------------------------------------------------------------------------
# 3. attachments.active after migration 0030
# ---------------------------------------------------------------------------


class TestActiveColumn:
    """0030's schema: ``active BOOLEAN NOT NULL DEFAULT true``, updatable by admino_app."""

    async def test_fakedb_active_defaults_to_true_and_seeds_false(
        self, schema_0030: ShippedSchema
    ) -> None:
        """``add_attachment()`` and an INSERT without the column store true;
        ``add_attachment(active=False)`` stores false."""
        db = FakeDb()
        owner = db.add_account(org_id=ORG_ID)
        chat = db.add_chat(owner)
        seeded = db.add_attachment(chat)
        excluded = db.add_attachment(chat, active=False)
        inserted = uuid.uuid4()
        tag = await db.pool.execute(
            "INSERT INTO attachments (id, org_id, chat_id, owner_user_id, filename, kind,"
            " size_bytes) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            inserted,
            ORG_ID,
            chat,
            owner,
            "x.txt",
            "txt",
            3,
        )

        values = {
            key: (db.attachment_row(attachment) or {}).get("active")
            for key, attachment in (("seeded", seeded), ("excluded", excluded), ("sql", inserted))
        }
        assert (tag, values) == ("INSERT 0 1", {"seeded": True, "excluded": False, "sql": True})

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(1, "DataError"), ("true", "DataError"), (None, "NotNullViolationError")],
        ids=["int", "str", "null"],
    )
    async def test_fakedb_active_refuses_non_bools_and_null(
        self, schema_0030: ShippedSchema, value: Any, expected: str
    ) -> None:
        """Through A10b and ``add_attachment``: nothing changes."""
        db = FakeDb()
        chat = db.add_chat(db.add_account(org_id=ORG_ID))
        attachment = db.add_attachment(chat)
        before = db.attachment_row(attachment)
        try:
            db.add_attachment(chat, active=value)
        except asyncpg.PostgresError as exc:
            seeded = type(exc).__name__
        else:
            seeded = "stored"

        updated = await _outcome(db.pool.execute(A10B, attachment, ORG_ID, value))

        assert (seeded, updated, db.attachments_of(chat)) == (expected, expected, [before])

    async def test_fakedb_active_is_last_in_the_failing_row_detail(
        self, schema_0030: ShippedSchema
    ) -> None:
        """ALTER TABLE ... ADD COLUMN appends it after derived_bytes."""
        db = FakeDb()
        chat = db.add_chat(db.add_account(org_id=ORG_ID))
        attachment = db.add_attachment(chat, token_estimate=5, derived_bytes=7, active=False)
        expected = [", -1, 7, f).", ", 5, 7, null)."]
        tails = []
        for sql, args, tail in (
            ("UPDATE attachments SET token_estimate = $1 WHERE id = $2", (-1, attachment), 0),
            (A10B, (attachment, ORG_ID, None), 1),
        ):
            with pytest.raises((asyncpg.CheckViolationError, asyncpg.NotNullViolationError)) as exc:
                await db.pool.execute(sql, *args)
            tails.append(str(exc.value)[-len(expected[tail]) :])

        assert tails == expected

    async def test_fakedb_active_update_needs_the_column_grant(
        self, monkeypatch: pytest.MonkeyPatch, read_0030: ShippedSchema
    ) -> None:
        """With 0030's grant A10b changes the row; without it, permission denied."""
        outcomes = {}
        for name, columns in (
            ("granted", read_0030.attachment_update_columns),
            ("no grant", UPDATE_COLUMNS_0029),
        ):
            _use(monkeypatch, dataclasses.replace(read_0030, attachment_update_columns=columns))
            db = FakeDb()
            attachment = db.add_attachment(db.add_chat(db.add_account(org_id=ORG_ID)))
            tag = await _outcome(db.pool.execute(A10B, attachment, ORG_ID, False))
            outcomes[name] = (tag, (db.attachment_row(attachment) or {}).get("active"))

        assert outcomes == {
            "granted": ("ok:'UPDATE 1'", False),
            "no grant": ("InsufficientPrivilegeError", True),
        }


# ---------------------------------------------------------------------------
# 4. platform_settings.max_context_messages and the audit action catalog
# ---------------------------------------------------------------------------


class TestReplacedChecks:
    """0030 replaces platform_settings_max_context_messages_check and the action catalog."""

    @pytest.mark.parametrize(
        ("schema", "stored"),
        [("0029", [1, 200]), ("0030", [0, 1, 200])],
        ids=["0029", "0030"],
    )
    async def test_fakedb_max_context_messages_bounds_follow_the_shipped_check(
        self,
        monkeypatch: pytest.MonkeyPatch,
        read_0029: ShippedSchema,
        read_0030: ShippedSchema,
        schema: str,
        stored: list[int],
    ) -> None:
        """Seeded and through the reader's UPDATE: -1 and 201 always refused, 0 only after 0030."""
        _use(monkeypatch, read_0029 if schema == "0029" else read_0030)
        accepted = []
        for value in (-1, 0, 1, 200, 201):
            try:
                FakeDb().add_platform_settings(max_context_messages=value)
            except asyncpg.CheckViolationError:
                continue
            accepted.append(value)
        db = FakeDb()
        db.add_platform_settings(max_context_messages=20)
        updated = await _outcome(db.pool.execute(PLATFORM_UPDATE, 0))
        row = db.platform_row()
        assert row is not None

        assert (accepted, updated, row["max_context_messages"]) == (
            stored,
            "ok:'UPDATE 1'" if 0 in stored else "CheckViolationError",
            0 if 0 in stored else 20,
        )

    @pytest.mark.parametrize(
        ("schema", "recorded"),
        [("0029", ["file.upload"]), ("0030", ["file.upload", "file.exclude", "file.include"])],
        ids=["0029", "0030"],
    )
    async def test_fakedb_audit_catalog_follows_the_shipped_check(
        self,
        monkeypatch: pytest.MonkeyPatch,
        read_0029: ShippedSchema,
        read_0030: ShippedSchema,
        schema: str,
        recorded: list[str],
    ) -> None:
        """file.exclude / file.include are refused by audit_events_action_check until 0030."""
        _use(monkeypatch, read_0029 if schema == "0029" else read_0030)
        db = FakeDb()
        actor = db.add_account(org_id=ORG_ID)
        refused = []
        for action in ("file.upload", "file.exclude", "file.include", "file.toggle"):
            target = json.dumps([str(uuid.uuid4())])
            try:
                await db.pool.execute(
                    AUDIT_INSERT, ORG_ID, actor, "member", action, "file", target, None, "{}"
                )
            except asyncpg.CheckViolationError as exc:
                refused.append((action, exc.constraint_name))

        assert [row["action"] for row in db.audit_rows()] == recorded
        assert {action for action, _ in refused} == {
            "file.upload",
            "file.exclude",
            "file.include",
            "file.toggle",
        } - set(recorded)
        assert {name for _, name in refused} == {"audit_events_action_check"}


# ---------------------------------------------------------------------------
# 5. The SQL forms of contract C5, C6 and C7 (0030's schema)
# ---------------------------------------------------------------------------


class TestTurnAndSendForms:
    """T2'' and A8'' (contract C5, C6)."""

    async def test_fakedb_t2_returns_sent_live_ready_active_files_as_text_arrays(
        self, schema_0030: ShippedSchema
    ) -> None:
        """By the carrying message, then upload order; NULLs stay None; the same array
        on every message row (three rows, newest first)."""
        world = _world(with_active=True)

        rows = await world.db.pool.fetch(T2, world.chat, ORG_ID, world.owner, 10)

        expected = [
            [str(SENT_READY), "a.pdf", "pdf", "2", "100", "1000"],
            [str(LATER_READY), "c.md", "md", None, None, None],
        ]
        assert [row["content"] for row in rows] == ["second", "answer", "first"]
        assert [row["attachment_rows"] for row in rows] == [expected] * 3

    async def test_fakedb_t2_of_a_chat_without_active_files_is_empty(
        self, schema_0030: ShippedSchema
    ) -> None:
        """The owner's other chat has only an unsent file: ``[]``; a colleague gets no row."""
        world = _world(with_active=True)

        own = await world.db.pool.fetch(T2, world.other_chat, ORG_ID, world.owner, 10)
        colleague = await world.db.pool.fetch(T2, world.chat, ORG_ID, world.colleague, 10)

        assert ([row["attachment_rows"] for row in own], colleague) == ([[]], [])

    async def test_fakedb_a8_returns_every_listed_live_file_with_estimate_bytes_and_flag(
        self, schema_0030: ShippedSchema
    ) -> None:
        """Inactive files included (the filter is the caller's), trashed and other chats'
        files left out, by created_at then id, the nine columns in order."""
        world = _world(with_active=True)
        listed = [UNSENT_READY, TRASHED, SENT_INACTIVE, OTHER_CHAT_FILE, UNKNOWN, SENT_READY]

        rows = await world.db.pool.fetch(A8, listed, world.chat, ORG_ID, world.owner)

        assert _ids(rows) == [SENT_READY, SENT_INACTIVE, UNSENT_READY]
        assert {
            **rows[1],
            "id": plain(rows[1]["id"]),
            "message_id": plain(rows[1]["message_id"]),
        } == {
            "id": SENT_INACTIVE,
            "message_id": world.m1,
            "status": "ready",
            "filename": "b.txt",
            "kind": "txt",
            "page_count": None,
            "token_estimate": 50,
            "derived_bytes": 500,
            "active": False,
        }
        assert list(rows[0]) == [
            "id",
            "message_id",
            "status",
            "filename",
            "kind",
            "page_count",
            "token_estimate",
            "derived_bytes",
            "active",
        ]


class TestAttachmentRecordForms:
    """A5', A6', A10a and A10b (contract C6)."""

    async def test_fakedb_a5_and_a6_return_the_r_list_with_active(
        self, schema_0030: ShippedSchema
    ) -> None:
        """A5' returns the new row (active true); A6' an excluded file's (false)."""
        world = _world(with_active=True)
        new_id = uuid.uuid4()

        inserted = await world.db.pool.fetchrow(
            A5, new_id, ORG_ID, world.chat, world.owner, "n.pdf", "pdf", 4
        )
        read = await world.db.pool.fetchrow(A6, SENT_INACTIVE, ORG_ID, world.owner)

        assert inserted is not None and read is not None
        assert (list(inserted), list(read)) == (list(R_COLUMNS), list(R_COLUMNS))
        assert (plain(inserted["id"]), inserted["active"], plain(read["id"]), read["active"]) == (
            new_id,
            True,
            SENT_INACTIVE,
            False,
        )

    async def test_fakedb_a10a_locks_the_owners_live_row_and_is_recorded(
        self, schema_0030: ShippedSchema
    ) -> None:
        """FOR UPDATE is recorded inside the transaction; a trashed file, a colleague's
        (as the owner) and another org's binding give no row."""
        world = _world(with_active=True)
        async with world.db.pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(A10A, SENT_INACTIVE, ORG_ID, world.owner)
            trashed = await conn.fetchrow(A10A, TRASHED, ORG_ID, world.owner)
            colleague = await conn.fetchrow(A10A, COLLEAGUE_FILE, ORG_ID, world.owner)
            other_org = await conn.fetchrow(A10A, SENT_INACTIVE, OTHER_ORG_ID, world.owner)
        locks = [call for call in world.db.calls if call.normalized.endswith("for update")]

        assert row is not None
        assert (list(row), plain(row["id"]), row["active"]) == (
            list(R_COLUMNS),
            SENT_INACTIVE,
            False,
        )
        assert (trashed, colleague, other_org) == (None, None, None)
        assert len(locks) == 4 and all(call.tx is not None for call in locks)

    async def test_fakedb_a10b_sets_the_flag_of_one_org_scoped_row(
        self, schema_0030: ShippedSchema
    ) -> None:
        """ "UPDATE 1" sets it; another org's binding is "UPDATE 0"; a rolled-back
        transaction puts the value back."""
        world = _world(with_active=True)
        pool = world.db.pool

        excluded = await pool.execute(A10B, SENT_READY, ORG_ID, False)
        foreign = await pool.execute(A10B, SENT_READY, OTHER_ORG_ID, True)
        with pytest.raises(RuntimeError):
            async with pool.acquire() as conn, conn.transaction():
                await conn.execute(A10B, SENT_READY, ORG_ID, True)
                raise RuntimeError
        row = world.db.attachment_row(SENT_READY)
        assert row is not None

        assert (excluded, foreign, row["active"]) == ("UPDATE 1", "UPDATE 0", False)


class TestListForms:
    """A11, A11' and A12 (contract C6)."""

    @pytest.mark.parametrize(
        ("status", "active", "expected"),
        [
            (None, None, list(LIVE_ORDER)),
            ("ready", None, [LATER_READY, SENT_READY, SENT_INACTIVE, UNSENT_READY]),
            (None, False, [SENT_INACTIVE]),
            ("ready", True, [LATER_READY, SENT_READY, UNSENT_READY]),
            ("failed", None, [FAILED]),
        ],
        ids=["all", "ready", "excluded", "ready-active", "failed"],
    )
    async def test_fakedb_a11_filters_by_status_and_active_in_upload_order(
        self,
        schema_0030: ShippedSchema,
        status: str | None,
        active: bool | None,
        expected: list[uuid.UUID],
    ) -> None:
        """NULL filters keep every live file of the owner's chat; created_at then id."""
        world = _world(with_active=True)

        rows = await world.db.pool.fetch(A11, world.chat, ORG_ID, world.owner, status, active, 50)

        assert _ids(rows) == expected
        assert all(list(row) == list(R_COLUMNS) for row in rows)

    async def test_fakedb_a11_limit_and_scope(self, schema_0030: ShippedSchema) -> None:
        """LIMIT cuts the page; a colleague's binding and another org's give nothing."""
        world = _world(with_active=True)
        pool = world.db.pool

        page = await pool.fetch(A11, world.chat, ORG_ID, world.owner, None, None, 3)
        colleague = await pool.fetch(A11, world.chat, ORG_ID, world.colleague, None, None, 50)
        other_org = await pool.fetch(A11, world.chat, OTHER_ORG_ID, world.owner, None, None, 50)

        assert (_ids(page), colleague, other_org) == (list(LIVE_ORDER[:3]), [], [])

    async def test_fakedb_a11_after_a_cursor_continues_on_a_created_at_tie(
        self, schema_0030: ShippedSchema
    ) -> None:
        """``(created_at, id) > ($6, $7)``: after FAILED (T1) comes SENT_READY (T1, a
        greater id); after SENT_READY, the T2 files; filters still apply."""
        world = _world(with_active=True)
        pool = world.db.pool
        args = (world.chat, ORG_ID, world.owner)

        after_failed = await pool.fetch(A11_AFTER, *args, None, None, _T1, FAILED, 2)
        after_ready = await pool.fetch(A11_AFTER, *args, "ready", None, _T1, SENT_READY, 50)

        assert (_ids(after_failed), _ids(after_ready)) == (
            [SENT_READY, SENT_INACTIVE],
            [SENT_INACTIVE, UNSENT_READY],
        )

    @pytest.mark.parametrize(
        ("status", "active"), [(1, None), (None, "true")], ids=["status-int", "active-str"]
    )
    async def test_fakedb_a11_filter_parameters_are_typed_by_their_column(
        self, schema_0030: ShippedSchema, status: Any, active: Any
    ) -> None:
        """``coalesce($4, status)`` is text and ``coalesce($5, active)`` boolean."""
        world = _world(with_active=True)

        with pytest.raises(asyncpg.DataError):
            await world.db.pool.fetch(A11, world.chat, ORG_ID, world.owner, status, active, 50)

    async def test_fakedb_a12_returns_the_live_ready_active_files(
        self, schema_0030: ShippedSchema
    ) -> None:
        """Sent or not, by created_at then id, with estimate and bytes (NULL as None)."""
        world = _world(with_active=True)

        rows = await world.db.pool.fetch(A12, world.chat, ORG_ID, world.owner)

        assert [{**row, "id": plain(row["id"])} for row in rows] == [
            {
                "id": LATER_READY,
                "filename": "c.md",
                "kind": "md",
                "page_count": None,
                "token_estimate": None,
                "derived_bytes": None,
            },
            {
                "id": SENT_READY,
                "filename": "a.pdf",
                "kind": "pdf",
                "page_count": 2,
                "token_estimate": 100,
                "derived_bytes": 1000,
            },
            {
                "id": UNSENT_READY,
                "filename": "e.csv",
                "kind": "csv",
                "page_count": 0,
                "token_estimate": 30,
                "derived_bytes": 300,
            },
        ]


class TestProcessingForms:
    """P6 and P3'' (contract C7)."""

    async def test_fakedb_p6_sums_the_other_live_ready_active_estimates_as_an_int(
        self, schema_0030: ShippedSchema
    ) -> None:
        """Self, inactive, failed, trashed and other chats' files don't count; NULL
        estimates count nothing; no other file (or another org's binding) gives 0."""
        world = _world(with_active=True)
        pool = world.db.pool

        sums = {
            "unsent": await pool.fetchval(P6, UNSENT_READY, ORG_ID),
            "sent": await pool.fetchval(P6, SENT_READY, ORG_ID),
            "processing": await pool.fetchval(P6, SENT_PROCESSING, ORG_ID),
            "alone": await pool.fetchval(P6, OTHER_CHAT_FILE, ORG_ID),
            "other org": await pool.fetchval(P6, UNSENT_READY, OTHER_ORG_ID),
        }

        assert sums == {"unsent": 100, "sent": 30, "processing": 130, "alone": 0, "other org": 0}
        assert {type(value) for value in sums.values()} == {int}

    async def test_fakedb_p3_fails_a_processing_file_with_reason_and_estimate(
        self, either_schema: ShippedSchema
    ) -> None:
        """Only while it is processing ("UPDATE 0" for a ready file); also before 0030."""
        world = _world(with_active=either_schema.attachments_active)
        pool = world.db.pool

        failed = await pool.execute(P3, SENT_PROCESSING, ORG_ID, "context_overflow", 4242)
        ready = await pool.execute(P3, SENT_READY, ORG_ID, "context_overflow", 4242)
        row = world.db.attachment_row(SENT_PROCESSING)
        assert row is not None

        assert (failed, ready) == ("UPDATE 1", "UPDATE 0")
        assert (row["status"], row["failure_reason"], row["token_estimate"]) == (
            "failed",
            "context_overflow",
            4242,
        )


class TestMessagePageForms:
    """S9' and S11' (contract C5): each message's live attachment ids."""

    async def test_fakedb_s9_gives_each_message_its_live_attachment_ids(
        self, either_schema: ShippedSchema
    ) -> None:
        """Newest message first; ids by created_at then id, excluded files included,
        trashed ones not; ``[]`` for a message without files; also before 0030."""
        world = _world(with_active=either_schema.attachments_active)

        rows = await world.db.pool.fetch(S9, world.chat, ORG_ID, 10)

        assert [
            (plain(row["id"]), [plain(item) for item in row["attachment_ids"]]) for row in rows
        ] == [
            (world.m3, [LATER_READY, SENT_PROCESSING]),
            (world.m2, []),
            (world.m1, [SENT_READY, SENT_INACTIVE]),
        ]

    async def test_fakedb_s11_pages_before_a_seq_with_the_same_ids(
        self, either_schema: ShippedSchema
    ) -> None:
        """``m.seq < $3`` and ``LIMIT $4``; another org's binding gives nothing."""
        world = _world(with_active=either_schema.attachments_active)
        m3 = next(row for row in world.db.messages_of(world.chat) if row["id"] == world.m3)

        rows = await world.db.pool.fetch(S11, world.chat, ORG_ID, m3["seq"], 1)
        foreign = await world.db.pool.fetch(S11, world.chat, OTHER_ORG_ID, m3["seq"], 10)

        assert [(plain(row["id"]), row["attachment_ids"]) for row in rows] == [(world.m2, [])]
        assert foreign == []
