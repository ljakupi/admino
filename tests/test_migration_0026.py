"""Tests for migration 0026_chats_owner_org.sql (GH-271): a chat's owner belongs to
the chat's org, and the user-deletion chat locks get an index.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
pipeline runs it on a throwaway postgres:16 as admino_app, EXPLAIN included). These
tests pin what the migration guarantees, not how it is worded: the SQL is read with
tests/test_migration_0018.py's lexer (comments blanked, '...' literals and
dollar-quoted bodies kept whole, nested DO / function bodies and EXECUTE literals
searched too), and the final schema across every shipped migration with
tests/test_schema_foreign_keys.py's parser.

What is pinned:
- ``0026_chats_owner_org.sql`` ships as the only version 26 and run_migrations
  applies it after 0025 (once).
- users gains ``users_id_org_key UNIQUE (id, org_id)`` (not deferrable: a foreign
  key can only reference an immediate key).
- 0026 drops ``chats_owner_user_id_fkey`` and adds ``chats_owner_org_fkey FOREIGN
  KEY (owner_user_id, org_id) REFERENCES users (id, org_id) ON DELETE CASCADE``,
  without NOT VALID (existing rows are checked: a mismatched chat makes the
  migration fail and change nothing). On the final schema chats has exactly two
  foreign keys, org_id -> organizations and the composite one, both cascading: one
  foreign key, so one cascade path, from chats to users.
- One index: ``chats_org_owner_id_idx`` on chats (org_id, owner_user_id, id), in
  that order, a plain btree, non-unique, non-partial (no WHERE: the deletion locks
  read trashed chats too), not CONCURRENTLY (migrations run in a transaction).
  No index is dropped or renamed (``chats_owner_activity_idx`` and
  ``chats_legacy_session_key`` stay).
- No GRANT / REVOKE, no data write, no function, trigger or role change, no
  other table or column change; the file opens with a header comment.
- tests/db_fakes.py mirrors 0026: an INSERT into chats (the real repository's
  ``create_chat`` and ``get_or_create_legacy_chat``) or ``add_chat`` whose owner is
  another org's member, a Super Admin (no org) or an unknown user raises
  ForeignKeyViolationError ``chats_owner_org_fkey`` on table chats, with no
  content in its text, and stores nothing; a same-org owner still works; deleting
  the owner still removes their chats (trashed included) with their messages; the
  fake's constraint name is the shipped one.

Security notes:
- Tenant isolation at the data layer: even a bug or injected SQL running as
  admino_app can't store a chat in one org owned by a user of another org.
- The constraint name and the refusal carry no row data (no title, no session id).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final, NamedTuple
from unittest.mock import AsyncMock

import asyncpg
import pytest

import admino.database as db_mod
from admino import chats, org_users
from admino.access import Principal
from admino.tenancy import TenantContext
from tests import db_fakes
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb
from tests.test_migration_0018 import (
    _executed,
    _fragments,
    _masked,
    _normalize,
    _split,
)
from tests.test_schema_foreign_keys import _shipped_schema

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME: Final = "0026_chats_owner_org.sql"
_PREVIOUS_MIGRATION: Final = "0025_chats_column_grants.sql"
_VERSION: Final = 26
_USERS_KEY: Final = "users_id_org_key"
_OLD_OWNER_FKEY: Final = "chats_owner_user_id_fkey"
_OWNER_FKEY: Final = "chats_owner_org_fkey"
_ORG_FKEY: Final = "chats_org_id_fkey"
_INDEX: Final = "chats_org_owner_id_idx"
_INDEX_COLUMNS: Final = ("org_id", "owner_user_id", "id")
_REFUSAL: Final = (
    f'insert or update on table "chats" violates foreign key constraint "{_OWNER_FKEY}"'
)
_TITLE: Final = "Merger plan"
_SESSION_ID: Final = "sess-gh271-owner"
_CHAT_ID: Final = uuid.UUID("6a1f0c2e-3b4d-4e5f-9a0b-1c2d3e4f5a71")
_UNKNOWN_USER: Final = uuid.UUID("7b2e1d3f-4c5e-4f60-8b1c-2d3e4f5a6b82")
_IP: Final = "203.0.113.71"
_CREATED: Final = datetime.now(UTC) - timedelta(days=3)
_OWNER_KINDS: Final = ("other-org-member", "super-admin", "unknown-user")

_ALTER_RE: Final = re.compile(
    r'alter table (?:if exists )?(?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"? (?P<actions>.+)'
)
_ADD_UNIQUE_RE: Final = re.compile(
    r'add constraint "?(?P<name>\w+)"? unique (?:nulls (?:not )?distinct )?'
    r"\((?P<columns>[^)]*)\)(?P<rest>.*)"
)
_ADD_FK_RE: Final = re.compile(
    r'add constraint "?(?P<name>\w+)"? foreign key ?\((?P<columns>[^)]*)\)'
    r' references (?:"?public"?\.)?"?(?P<target>\w+)"? ?\((?P<referenced>[^)]*)\)(?P<rest>.*)'
)
_DROP_CONSTRAINT_RE: Final = re.compile(
    r'drop constraint (?:if exists )?"?(?P<name>\w+)"?(?: (?:restrict|cascade))?'
)
_ON_DELETE_RE: Final = re.compile(
    r"\bon delete (cascade|restrict|no action|set null|set default)\b"
)
_INDEX_RE: Final = re.compile(
    r"create (?P<unique>unique )?index (?P<concurrently>concurrently )?(?:if not exists )?"
    r'"?(?P<name>\w+)"? on (?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"?(?: using (?P<method>\w+))?'
    r" ?\((?P<columns>[^)]*)\)(?P<rest>.*)"
)
_INDEX_COLUMN_RE: Final = re.compile(r'"?(\w+)"?(?: (?:asc|desc))?(?: nulls (?:first|last))?')
# A statement that drops, renames or otherwise changes an existing index.
_DROPPED_INDEX_RE: Final = re.compile(r"(?:drop|alter) index\b")
# Statement starts 0026 must not contain (top level, DO / function bodies, literals).
_FORBIDDEN: Final[dict[str, str]] = {
    "grant": r"grant\b",
    "revoke": r"revoke\b",
    "insert": r"insert into\b",
    "update": r"update (?:only )?\S+ set\b",
    "delete": r"delete from\b",
    "truncate": r"truncate\b",
    "copy": r"copy\b",
    "merge": r"merge into\b",
    "function": r"(?:create|alter|drop) (?:or replace )?(?:function|procedure)\b",
    "trigger": r"(?:create|alter|drop) (?:or replace )?(?:constraint )?trigger\b",
    "role": r"(?:create|alter|drop) (?:role|user|group)\b",
    "drop table": r"drop (?:table|view|schema|type)\b",
    "create table": r"create (?:table|view)\b",
}
# The only ALTER TABLE actions 0026 runs: the two keys and the old key's drop.
_ALLOWED_ACTIONS: Final = (_ADD_UNIQUE_RE, _ADD_FK_RE, _DROP_CONSTRAINT_RE)


# ---------------------------------------------------------------------------
# Helpers: the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    return _migration_path().read_text(encoding="utf-8")


def _statements() -> list[str]:
    """The statements 0026 runs (top level and DO blocks), normalized."""
    return _executed(_normalize(_raw_sql()))


def _names(text: str) -> tuple[str, ...]:
    return tuple(name.strip().strip('"') for name in _split(text, ","))


def _alter_actions() -> list[tuple[str, str]]:
    """(table, action) for every action of every ALTER TABLE 0026 runs."""
    found: list[tuple[str, str]] = []
    for statement in _statements():
        match = _ALTER_RE.fullmatch(_masked(statement))
        if match is None:
            continue
        for action in _split(statement[match.start("actions") :], ","):
            found.append((match.group("table"), action))
    return found


class _ForeignKey(NamedTuple):
    table: str
    name: str
    pairs: frozenset[tuple[str, str]]  # (column, referenced column)
    referenced: str
    on_delete: str
    not_valid: bool


def _added_foreign_keys() -> list[_ForeignKey]:
    found: list[_ForeignKey] = []
    for table, action in _alter_actions():
        match = _ADD_FK_RE.fullmatch(_masked(action))
        if match is None:
            continue
        columns = _names(action[match.start("columns") : match.end("columns")])
        referenced = _names(action[match.start("referenced") : match.end("referenced")])
        on_delete = _ON_DELETE_RE.search(match.group("rest"))
        found.append(
            _ForeignKey(
                table=table,
                name=match.group("name"),
                pairs=frozenset(zip(columns, referenced, strict=False)),
                referenced=match.group("target"),
                on_delete=on_delete.group(1) if on_delete else "no action",
                not_valid=re.search(r"\bnot valid\b", match.group("rest")) is not None,
            )
        )
    return found


class _Index(NamedTuple):
    name: str
    table: str
    unique: bool
    concurrently: bool
    btree: bool
    columns: tuple[str, ...]
    partial: bool


def _created_indexes() -> list[_Index]:
    found: list[_Index] = []
    for statement in _statements():
        masked = _masked(statement)
        match = _INDEX_RE.fullmatch(masked)
        if match is None:
            assert not re.match(r"create (?:unique )?index\b", masked), (
                f"the test can't read the index statement {statement!r}"
            )
            continue
        columns: list[str] = []
        for element in _split(match.group("columns"), ","):
            column = _INDEX_COLUMN_RE.fullmatch(element)
            columns.append(column.group(1) if column else f"<expression {element}>")
        found.append(
            _Index(
                name=match.group("name"),
                table=match.group("table"),
                unique=match.group("unique") is not None,
                concurrently=match.group("concurrently") is not None,
                btree=match.group("method") in (None, "btree"),
                columns=tuple(columns),
                partial=re.search(r"\bwhere\b", match.group("rest")) is not None,
            )
        )
    return found


def _header_lines() -> list[str]:
    """The non-empty ``--`` comment lines before the first statement."""
    lines: list[str] = []
    for line in _raw_sql().splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            lines.append(stripped[2:].strip())
        elif stripped:
            break
    return [line for line in lines if line]


# ---------------------------------------------------------------------------
# Helpers: the fake database
# ---------------------------------------------------------------------------


def _owner(db: FakeDb, kind: str) -> uuid.UUID:
    """An owner who is not a member of ORG_ID (the chat's org)."""
    if kind == "other-org-member":
        return db.add_account(org_id=OTHER_ORG_ID, role="org_admin")
    if kind == "super-admin":
        return db.add_account(kind="super_admin", role=None)
    assert kind == "unknown-user", kind
    return _UNKNOWN_USER


async def _store(db: FakeDb, entry: str, tenant: TenantContext) -> Any:
    """Store a chat of the tenant's user in the tenant's org through one entry point."""
    if entry == "create_chat":
        return await chats.create_chat(db.pool, tenant, title=_TITLE)
    assert entry == "legacy_chat", entry
    return await chats.get_or_create_legacy_chat(db.pool, tenant, _SESSION_ID, chat_id=_CHAT_ID)


def _refusal(exc: asyncpg.ForeignKeyViolationError) -> tuple[Any, ...]:
    """What a refused chat INSERT reports: constraint, table, message, content-free."""
    text = str(exc)
    return (
        getattr(exc, "constraint_name", None),
        getattr(exc, "table_name", None),
        text.splitlines()[0],
        _TITLE not in text and _SESSION_ID not in text,
    )


def _owned_chats(db: FakeDb, owner: uuid.UUID) -> list[uuid.UUID]:
    """A live and a trashed chat of the owner in their org, each with two messages."""
    made: list[uuid.UUID] = []
    for trashed in (False, True):
        chat_id = db.add_chat(
            owner, created_at=_CREATED, deleted_at=_CREATED + timedelta(days=1) if trashed else None
        )
        db.add_chat_message(chat_id, "user", "Hello")
        db.add_chat_message(chat_id, "assistant", "Hi there")
        made.append(chat_id)
    return made


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0026File:
    """The migration ships as version 26 and is applied by run_migrations after 0025."""

    def test_migration_0026_file_is_the_only_version_26(self) -> None:
        twenty_sixes = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert twenty_sixes == [_MIGRATION_NAME]

    async def test_migration_0026_run_migrations_applies_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0025 applied, run_migrations executes the file and records 26."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)
        assert (_VERSION, _MIGRATION_NAME) in recorded

    async def test_migration_0026_runs_after_0025(self, mock_pool: MagicMock) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0026_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0026_opens_with_a_header_comment(self) -> None:
        """Purpose, reason and consequences are explained before the first statement."""
        assert len(_header_lines()) >= 3


# ---------------------------------------------------------------------------
# 2. The owner's org: users key and the composite foreign key
# ---------------------------------------------------------------------------


class TestMigration0026OwnerOrgKey:
    """A chat's (owner_user_id, org_id) must be a (id, org_id) of users."""

    def test_migration_0026_users_gets_the_unique_id_org_key(self) -> None:
        """users_id_org_key UNIQUE (id, org_id), immediate (a foreign key can't reference
        a deferrable key); the only UNIQUE key 0026 adds."""
        found = [
            (
                table,
                match.group("name"),
                _names(match.group("columns")),
                match.group("rest").strip() in ("", "not deferrable"),
            )
            for table, action in _alter_actions()
            if (match := _ADD_UNIQUE_RE.fullmatch(_masked(action)))
        ]

        assert found == [("users", _USERS_KEY, ("id", "org_id"), True)]

    def test_migration_0026_adds_the_composite_owner_foreign_key(self) -> None:
        """chats (owner_user_id, org_id) -> users (id, org_id) ON DELETE CASCADE, named
        chats_owner_org_fkey, checked against existing rows (no NOT VALID)."""
        expected = _ForeignKey(
            table="chats",
            name=_OWNER_FKEY,
            pairs=frozenset({("owner_user_id", "id"), ("org_id", "org_id")}),
            referenced="users",
            on_delete="cascade",
            not_valid=False,
        )

        assert _added_foreign_keys() == [expected]

    def test_migration_0026_drops_the_single_column_owner_foreign_key(self) -> None:
        """0024's inline owner_user_id -> users key (default name) is dropped, and no
        other constraint."""
        dropped = [
            (table, match.group("name"))
            for table, action in _alter_actions()
            if (match := _DROP_CONSTRAINT_RE.fullmatch(_masked(action)))
        ]

        assert dropped == [("chats", _OLD_OWNER_FKEY)]

    def test_migration_0026_final_chats_foreign_keys_are_org_and_owner_org(self) -> None:
        """Across every shipped migration, chats has exactly two foreign keys: org_id ->
        organizations (id) and (owner_user_id, org_id) -> users (id, org_id), both
        ON DELETE CASCADE (a user delete and the org purge still remove the chats)."""
        found = {
            (fk.columns, fk.referenced, fk.referenced_columns or ("id",), fk.on_delete, fk.name)
            for fk in _shipped_schema().foreign_keys
            if fk.table == "chats"
        }

        assert found == {
            (("org_id",), "organizations", ("id",), "cascade", _ORG_FKEY),
            (("owner_user_id", "org_id"), "users", ("id", "org_id"), "cascade", _OWNER_FKEY),
        }

    def test_migration_0026_one_cascade_path_from_users_to_chats(self) -> None:
        """Exactly one foreign key from chats to users, and it cascades."""
        to_users = [
            (fk.name, fk.on_delete)
            for fk in _shipped_schema().foreign_keys
            if fk.table == "chats" and fk.referenced == "users"
        ]

        assert to_users == [(_OWNER_FKEY, "cascade")]


# ---------------------------------------------------------------------------
# 3. The deletion-lock index
# ---------------------------------------------------------------------------


class TestMigration0026Index:
    """The ordered chat locks of the user deletions (GH-265) get an index."""

    def test_migration_0026_creates_the_org_owner_id_index(self) -> None:
        """chats (org_id, owner_user_id, id) in that order: a plain btree, non-unique,
        without WHERE (the locks read trashed chats too, so the partial chat-list
        index can't serve them), not CONCURRENTLY (it can't run in the migration's
        transaction). The only index 0026 creates."""
        expected = _Index(
            name=_INDEX,
            table="chats",
            unique=False,
            concurrently=False,
            btree=True,
            columns=_INDEX_COLUMNS,
            partial=False,
        )

        assert _created_indexes() == [expected]

    def test_migration_0026_drops_or_renames_no_index(self) -> None:
        """chats_owner_activity_idx (the chat list) and chats_legacy_session_key (the
        legacy race) stay, and so does every other index."""
        touched = [
            fragment
            for fragment in _fragments(_normalize(_raw_sql()))
            if _DROPPED_INDEX_RE.match(_masked(fragment))
        ]

        assert _statements(), f"{_MIGRATION_NAME} runs nothing"
        assert touched == []


# ---------------------------------------------------------------------------
# 4. What 0026 must not do
# ---------------------------------------------------------------------------


class TestMigration0026Scope:
    """Only the two keys and the index: no privilege, data, function or trigger change."""

    def test_migration_0026_runs_no_grant_data_write_or_trigger(self) -> None:
        """No GRANT / REVOKE, INSERT / UPDATE / DELETE / TRUNCATE / COPY / MERGE,
        function, procedure, trigger, role or table change, also not nested in a DO
        block, a function body or an EXECUTE literal."""
        fragments = _fragments(_normalize(_raw_sql()))
        offenders = [
            (kind, fragment)
            for fragment in fragments
            for kind, pattern in _FORBIDDEN.items()
            if re.match(pattern, _masked(fragment))
        ]

        assert fragments, f"{_MIGRATION_NAME} runs nothing"
        assert offenders == []

    def test_migration_0026_alters_only_the_owner_keys(self) -> None:
        """Every ALTER TABLE action adds the users key or the chats foreign key, or drops
        the old one: no column change, no trigger disabled, no owner or RLS change."""
        actions = _alter_actions()
        other = [
            (table, action)
            for table, action in actions
            if not any(pattern.fullmatch(_masked(action)) for pattern in _ALLOWED_ACTIONS)
        ]

        assert {table for table, _ in actions} == {"users", "chats"}
        assert other == []


# ---------------------------------------------------------------------------
# 5. tests/db_fakes.py mirrors 0026
# ---------------------------------------------------------------------------


class TestMigration0026FakeDb:
    """The FakeDb refuses a chat whose owner isn't a member of the chat's org."""

    @pytest.mark.parametrize("owner_kind", _OWNER_KINDS)
    @pytest.mark.parametrize("entry", ["create_chat", "legacy_chat"])
    async def test_migration_0026_fake_refuses_a_chat_whose_owner_is_outside_its_org(
        self, entry: str, owner_kind: str
    ) -> None:
        """The repository's INSERT with a tenant whose user isn't an ORG_ID member is
        ForeignKeyViolationError chats_owner_org_fkey on chats; its text carries no
        title or session id; nothing is stored."""
        db = FakeDb()
        db.add_account(org_id=ORG_ID)
        owner = _owner(db, owner_kind)
        tenant = TenantContext(org_id=ORG_ID, user_id=owner, role="editor")
        before = db.snapshot()

        with pytest.raises(asyncpg.ForeignKeyViolationError) as caught:
            await _store(db, entry, tenant)

        assert _refusal(caught.value) == (_OWNER_FKEY, "chats", _REFUSAL, True)
        assert db.snapshot() == before

    @pytest.mark.parametrize(
        ("owner_kind", "org_id"),
        [
            pytest.param("other-org-member", ORG_ID, id="other-org-member"),
            pytest.param("super-admin", ORG_ID, id="super-admin"),
            pytest.param("unknown-user", ORG_ID, id="unknown-user-with-org"),
            pytest.param("unknown-user", None, id="unknown-user-without-org"),
        ],
    )
    def test_migration_0026_fake_add_chat_refuses_an_owner_outside_the_org(
        self, owner_kind: str, org_id: uuid.UUID | None
    ) -> None:
        """The seed helper checks the same key: another org's member or a Super Admin
        given ORG_ID, and an unknown owner with or without an org."""
        db = FakeDb()
        db.add_account(org_id=ORG_ID)
        owner = _owner(db, owner_kind)
        before = db.snapshot()

        with pytest.raises(asyncpg.ForeignKeyViolationError) as caught:
            db.add_chat(owner, org_id=org_id)

        assert (caught.value.constraint_name, caught.value.table_name) == (_OWNER_FKEY, "chats")
        assert db.snapshot() == before

    @pytest.mark.parametrize("entry", ["create_chat", "legacy_chat", "add_chat"])
    async def test_migration_0026_fake_same_org_owner_still_stores_the_chat(
        self, entry: str
    ) -> None:
        """Regression guard: an ORG_ID member's chat in ORG_ID is stored as before."""
        db = FakeDb()
        member = db.add_account(org_id=ORG_ID)
        tenant = TenantContext(org_id=ORG_ID, user_id=member, role="editor")

        if entry == "add_chat":
            chat_id = db.add_chat(member, org_id=ORG_ID)
        else:
            chat_id = (await _store(db, entry, tenant)).id
        row = db.chat_row(chat_id)

        assert row is not None
        assert (row["org_id"], row["owner_user_id"]) == (ORG_ID, member)

    async def test_migration_0026_fake_deleting_the_owner_still_removes_their_chats(
        self,
    ) -> None:
        """Regression guard: org_users.delete_org_user cascades through the composite
        key to the user's live and trashed chats and their messages; a colleague's
        chats stay."""
        db = FakeDb()
        admin = db.add_account(org_id=ORG_ID, role="org_admin")
        target = db.add_account(org_id=ORG_ID)
        colleague = db.add_account(org_id=ORG_ID, role="viewer")
        doomed = _owned_chats(db, target)
        kept = _owned_chats(db, colleague)
        actor = Principal(user_id=admin, kind="member", org_id=ORG_ID, role="org_admin")

        await org_users.delete_org_user(db.pool, actor=actor, user_id=target, ip=_IP)

        assert [db.chat_row(chat_id) for chat_id in doomed] == [None, None]
        assert [db.messages_of(chat_id) for chat_id in doomed] == [[], []]
        assert all(db.chat_row(chat_id) is not None for chat_id in kept)
        assert [len(db.messages_of(chat_id)) for chat_id in kept] == [2, 2]

    def test_migration_0026_fake_constraint_name_is_the_shipped_one(self) -> None:
        """The fake refuses with the name 0026 gives the composite owner key."""
        shipped = [fk.name for fk in _added_foreign_keys() if fk.table == "chats"]

        assert shipped == [db_fakes.CHAT_OWNER_FKEY]
