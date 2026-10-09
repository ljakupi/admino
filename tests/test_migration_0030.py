"""Tests for migration 0030_context_budget.sql (GH-190, contract C8 and C10, issue
Decisions 8 and 10): the attachments' ``active`` flag and its UPDATE grant, the
max_context_messages CHECK widened to 0 (no cap), and ``file.exclude`` /
``file.include`` in the audit action catalog.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
pipeline ran the contract's SQL on a throwaway postgres:16 as admino_app). The SQL is
read with tests/test_migration_0018.py's lexer (comments blanked, '...' literals and
dollar-quoted bodies kept whole, nested DO / function bodies and EXECUTE literals
searched too), the added column with tests/test_migration_0024.py's column parser, the
action list with tests/test_migration_0021.py's IN-list reader, and the GRANT / REVOKE
statements of every shipped migration are replayed into the privileges each role ends
up with (tests/test_migration_0027.py's replay).

What is pinned:
- ``0030_context_budget.sql`` ships as the only version 30, right after the versions 1
  to 29; run_migrations applies it after 0029 (once). It opens with a header comment
  (what, why, grants) that names the ``active`` column, ``max_context_messages`` and
  the two new audit actions, and says what is granted.
- ``ALTER TABLE attachments ADD COLUMN active BOOLEAN NOT NULL DEFAULT true``: nothing
  else on the column (no CHECK, key, reference or identity). Existing rows take the
  default: the file writes no data.
- ``GRANT UPDATE (active) ON attachments TO admino_app``: the file's only GRANT (nested
  ones included), without grant option, after the column exists; no REVOKE. Every
  (table, grantee) holds after 0030 what it held after 0029, except admino_app on
  attachments, which gains ``update(active)``. After every migration up to 0030
  admino_app holds on attachments SELECT, INSERT, DELETE and UPDATE on exactly
  message_id, status, failure_reason, page_count, token_estimate, derived_bytes,
  active, updated_at and deleted_at (no table-wide UPDATE, no grant option); PUBLIC
  nothing. (GH-194: migration 0031 adds ``update(trash_group_id)``; the cumulative
  set after every shipped migration is pinned in tests/test_migration_0031.py.)
- ``platform_settings_max_context_messages_check`` (0013's inline CHECK, PostgreSQL's
  name for it) is dropped (no IF EXISTS, no CASCADE) and re-added under the same name
  as ``CHECK (max_context_messages BETWEEN 0 AND 200)``, validated (nothing after the
  expression). 0 to 200 are exactly the bounds of ``LimitsConfig``, ``PlatformLimits``
  and ``PlatformLimitsPatch`` (the model sync for this column moved here from
  tests/test_migration_0013.py, which keeps 0013's own 1 to 200).
- ``audit_events_action_check`` is dropped (no IF EXISTS, no CASCADE) and re-added with
  0027's list plus ``'file.exclude', 'file.include'`` right after ``'file.restore'``,
  nothing else added or removed, each listed once; every one of them is a live
  ``AuditAction``, which has ``FILE_EXCLUDE = "file.exclude"`` and ``FILE_INCLUDE =
  "file.include"`` (GH-194: migration 0031 adds chat.purge and file.purge, so the
  exact sync moved on to tests/test_migration_0031.py; this file keeps a subset check).
- Statement order: the column's ALTER, the GRANT, the platform CHECK's DROP and ADD,
  the action CHECK's DROP and ADD. Nothing else: no DO block, function, trigger, role,
  INSERT / UPDATE / DELETE / TRUNCATE / COPY / MERGE, REVOKE, CREATE, DROP TABLE /
  INDEX or default privileges, also not nested in a body or an EXECUTE literal.
- tests/db_fakes.py mirrors 0030: ``db_fakes.shipped_schema()`` of the tree holds what
  the file says (the column, the cumulative UPDATE grant, 0 to 200, every action of
  0030's catalog; GH-194: the fake's catalog after every shipped migration is pinned
  in tests/test_migration_0031.py); the fake's attachments row has ``active`` (true)
  right after ``derived_bytes`` (GH-194: 0031's trash_group_id follows it);
  admino_app may UPDATE it; 0 and 200 are stored for max_context_messages, -1 and 201
  are CheckViolationError; ``file.exclude`` and ``file.include`` rows are recorded.

Security notes:
- admino_app gains exactly one updatable column, a flag: even a bug or injected SQL
  running as admino_app still can't move a file to another org, owner, chat, name or
  size.
- The catalog grows by two content-free actions: a toggle records the attachment's id
  as its target, never a file name or content.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock

import asyncpg

import admino.database as db_mod
from tests import db_fakes
from tests.db_fakes import ORG_ID, FakeDb
from tests.test_migration_0018 import (
    _executed,
    _fragments,
    _load_migrations,
    _masked,
    _normalize,
    _split,
)
from tests.test_migration_0021 import _added_actions
from tests.test_migration_0024 import _canonical_default, _Column, _parse_column
from tests.test_migration_0025 import _GRANT_RE, _acl_keys, _grantees, _privilege_entries
from tests.test_migration_0027 import _ALTER_RE, _apply, _targets, _unwrap

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME: Final = "0030_context_budget.sql"
_PREVIOUS_MIGRATION: Final = "0029_chat_message_attachments.sql"
_ACTIONS_MIGRATION: Final = "0027_attachments.sql"
_VERSION: Final = 30
_ROLE: Final = "admino_app"
_TABLE: Final = "attachments"
_COLUMN: Final = "active"
_PLATFORM_TABLE: Final = "platform_settings"
_PLATFORM_COLUMN: Final = "max_context_messages"
_PLATFORM_CHECK: Final = "platform_settings_max_context_messages_check"
_PLATFORM_BOUNDS: Final = (0, 200)
_AUDIT_TABLE: Final = "audit_events"
_ACTION_CHECK: Final = "audit_events_action_check"
_NEW_ACTIONS: Final = ("file.exclude", "file.include")
_AFTER_ACTION: Final = "file.restore"

# admino_app's UPDATE columns on attachments after every shipped migration.
_UPDATE_COLUMNS: Final = (
    "message_id",
    "status",
    "failure_reason",
    "page_count",
    "token_estimate",
    "derived_bytes",
    "active",
    "updated_at",
    "deleted_at",
)
_EXPECTED_PRIVILEGES: Final = frozenset(
    {"select", "insert", "delete", *(f"update({column})" for column in _UPDATE_COLUMNS)}
)
_BOOLEAN_TYPES: Final = frozenset({"boolean", "bool"})

_SCHEMA: Final = r'(?:"?public"?\.)?'
# ADD [COLUMN] name definition; ADD CONSTRAINT is no column.
_ADD_COLUMN_RE: Final = re.compile(
    r'add (?:column )?(?:if not exists )?(?!constraint\b)"?(?P<name>\w+)"? (?P<definition>.+)'
)
# A plain DROP (no IF EXISTS: a missing constraint fails loudly; no CASCADE).
_DROP_RE: Final = re.compile(r'drop constraint "?(?P<name>\w+)"?(?P<rest>(?: restrict)?)')
# ADD CONSTRAINT ... CHECK (...) with nothing after it (no NOT VALID, no NO INHERIT).
_ADD_CHECK_RE: Final = re.compile(r'add constraint "?(?P<name>\w+)"? check ?\((?P<expression>.*)\)')
# The statement kinds 0030 may run (masked, normalized).
_STATEMENT_KINDS: Final[dict[str, re.Pattern[str]]] = {
    "column": re.compile(rf'alter table (?:only )?{_SCHEMA}"?{_TABLE}"? add .+'),
    "grant": re.compile(rf'grant .+ on (?:table )?{_SCHEMA}"?{_TABLE}"? to .+'),
    "platform check": re.compile(
        rf'alter table (?:only )?{_SCHEMA}"?{_PLATFORM_TABLE}"? (?:drop|add) constraint .+'
    ),
    "action check": re.compile(
        rf'alter table (?:only )?{_SCHEMA}"?{_AUDIT_TABLE}"? (?:drop|add) constraint .+'
    ),
}
# Fragments 0030 must not contain (top level, DO / function bodies, literals).
_FORBIDDEN: Final[dict[str, str]] = {
    "do": r"do\b",
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
    "drop": r"drop (?:table|view|schema|type|index|column)\b",
    "default privileges": r"alter default privileges\b",
    "create": r"create (?:unique )?(?:table|index|view|type|schema)\b",
}

_SET_ACTIVE: Final = "UPDATE attachments SET active = $1 WHERE id = $2"
# The audit INSERT audit_events.record() runs (its statement's shape).
_AUDIT_INSERT: Final = """
    INSERT INTO audit_events
        (org_id, actor_user_id, actor_kind, action, target_type, target_ids, ip, metadata)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::inet, $8::jsonb)
"""
_ACTOR: Final = uuid.UUID("30a1c0de-0000-4000-8000-000000000001")
_TARGET_FILE: Final = uuid.UUID("30a1c0de-0000-4000-8000-000000000002")


# ---------------------------------------------------------------------------
# Helpers: the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    path = _migration_path()
    assert path.is_file(), f"{_MIGRATION_NAME} is not shipped"
    return path.read_text(encoding="utf-8")


def _statements() -> list[str]:
    """The statements 0030 runs (top level and DO blocks), normalized."""
    return _executed(_normalize(_raw_sql()))


def _canon(text: str) -> str:
    """Whitespace collapsed and dropped around parentheses, commas and comparisons."""
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*([(),])\s*", r"\1", text)
    return re.sub(r"\s*(>=|<=|<>|!=|=|<|>)\s*", r" \1 ", text).strip()


def _alter_actions() -> list[tuple[str, str]]:
    """(table, action) for every action of every ALTER TABLE 0030 runs, in order."""
    found: list[tuple[str, str]] = []
    for statement in _statements():
        match = _ALTER_RE.fullmatch(_masked(statement))
        if match is None:
            continue
        for action in _split(statement[match.start("actions") :], ","):
            found.append((match.group("table"), action))
    return found


def _action_kind(table: str, action: str) -> tuple[str, str]:
    """(table, what the action does): a column added, a constraint dropped or a CHECK added
    (by name, with anything after the DROP or the CHECK flagged), else the action itself."""
    masked = _masked(action)
    if (column := _ADD_COLUMN_RE.fullmatch(masked)) is not None:
        return table, f"add column {column.group('name')}"
    if (drop := _DROP_RE.fullmatch(masked)) is not None:
        return table, f"drop {drop.group('name')}"
    if (added := _ADD_CHECK_RE.fullmatch(masked)) is not None:
        return table, f"add check {added.group('name')}"
    return table, action


def _added_column() -> _Column:
    """The parsed definition of ``attachments.active`` as 0030 adds it (exactly once)."""
    found = []
    for table, action in _alter_actions():
        match = _ADD_COLUMN_RE.fullmatch(_masked(action))
        if match is not None and (table, match.group("name")) == (_TABLE, _COLUMN):
            definition = action[match.start("definition") :]
            found.append(_parse_column(_COLUMN, definition))
    assert len(found) == 1, f"{_MIGRATION_NAME} must add {_TABLE}.{_COLUMN} exactly once"
    return found[0]


def _added_check(table: str, name: str) -> str:
    """The expression 0030 adds the CHECK ``name`` on ``table`` with (exactly once)."""
    found = []
    for action_table, action in _alter_actions():
        match = _ADD_CHECK_RE.fullmatch(_masked(action))
        if match is not None and (action_table, match.group("name")) == (table, name):
            found.append(action[match.start("expression") : match.end("expression")])
    assert len(found) == 1, f"{_MIGRATION_NAME} must add {name} on {table} exactly once"
    return found[0]


def _and_parts(expression: str) -> list[str]:
    """The top-level AND-ed conditions, each unwrapped and canonical (BETWEEN read as two
    comparisons first)."""
    expression = re.sub(
        r"\b(\w+) between (-?\d+) and (-?\d+)\b",
        r"\1 >= \2 and \1 <= \3",
        _unwrap(expression),
    )
    masked = _masked(expression)
    parts: list[str] = []
    depth = 0
    start = 0
    for token in re.finditer(r"\(|\)|\band\b", masked):
        if token.group(0) == "(":
            depth += 1
        elif token.group(0) == ")":
            depth -= 1
        elif depth == 0:
            parts.append(expression[start : token.start()])
            start = token.end()
    parts.append(expression[start:])
    return [_canon(_unwrap(part)) for part in parts]


def _platform_bounds() -> tuple[int, int]:
    """The inclusive (low, high) of the max_context_messages CHECK 0030 adds; its whole
    expression must be the two bounds of that column."""
    low: int | None = None
    high: int | None = None
    for part in _and_parts(_added_check(_PLATFORM_TABLE, _PLATFORM_CHECK)):
        match = re.fullmatch(rf"{_PLATFORM_COLUMN} (>=|<=) (-?\d+)", part)
        assert match is not None, f"unexpected condition in {_PLATFORM_CHECK}: {part}"
        if match.group(1) == ">=":
            assert low is None, part
            low = int(match.group(2))
        else:
            assert high is None, part
            high = int(match.group(2))
    assert low is not None and high is not None, f"{_PLATFORM_CHECK} must bound both sides"
    return low, high


def _listed_actions() -> list[str]:
    """The literals of 0030's ``audit_events_action_check``, in written order."""
    _raw_sql()
    return _added_actions(_MIGRATION_NAME)


def _expected_actions() -> list[str]:
    """0027's list with the two new actions right after file.restore (contract C8/C10)."""
    base = _added_actions(_ACTIONS_MIGRATION)
    position = base.index(_AFTER_ACTION) + 1
    return [*base[:position], *_NEW_ACTIONS, *base[position:]]


def _acl(up_to: int | None = None) -> dict[tuple[str, str], frozenset[str]]:
    """(table, grantee) -> ACL entries after every shipped migration (up to a version).

    Fails the calling test when version 30 isn't shipped."""
    shipped = _load_migrations(db_mod._MIGRATIONS_DIR)
    assert _VERSION in [m.version for m in shipped], f"{_MIGRATION_NAME} is not shipped"
    acl: dict[tuple[str, str], set[str]] = {}
    for migration in shipped:
        if up_to is not None and migration.version > up_to:
            continue
        for statement in _executed(_normalize(migration.sql)):
            _apply(acl, statement)
    return {key: frozenset(value) for key, value in acl.items() if value}


def _final_update_columns() -> frozenset[str]:
    """The attachments columns admino_app may UPDATE after every shipped migration."""
    held = _acl().get((_TABLE, _ROLE), frozenset())
    return frozenset(
        match.group(1) for entry in held if (match := re.fullmatch(r"update\((\w+)\)", entry))
    )


def _file_grants() -> list[tuple[frozenset[str], tuple[str, ...], frozenset[str], bool]]:
    """(ACL entries, tables, grantees, grant option) of every GRANT in 0030, nested DO /
    function bodies and EXECUTE literals included."""
    grants = []
    for fragment in _fragments(_normalize(_raw_sql())):
        match = _GRANT_RE.fullmatch(_masked(fragment))
        if match is None:
            continue
        entries = frozenset(
            key
            for name, columns in _privilege_entries(match.group("privileges"))
            for key in _acl_keys(name, columns)
        )
        grants.append(
            (
                entries,
                _targets(match.group("target")),
                _grantees(match.group("grantees")),
                bool(match.group("option")),
            )
        )
    return grants


def _kind(statement: str) -> str:
    """The statement's kind (``_STATEMENT_KINDS``), else the statement itself."""
    masked = _masked(statement)
    for kind, pattern in _STATEMENT_KINDS.items():
        if pattern.fullmatch(masked):
            return kind
    return statement


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


def _model_accepts(model: Any, value: Any) -> bool:
    """Whether a limits model takes ``value`` for max_context_messages (the other limits
    given in range where the model needs them)."""
    from pydantic import ValidationError

    others = {
        "max_tool_calls_per_message": 10,
        "max_pending_confirmations": 3,
        "confirmation_timeout_s": 300,
        "max_message_length": 4000,
    }
    try:
        model.model_validate({**others, _PLATFORM_COLUMN: value})
    except ValidationError:
        return False
    return True


# ---------------------------------------------------------------------------
# Helpers: the FakeDb
# ---------------------------------------------------------------------------


def _attachment(db: FakeDb) -> uuid.UUID:
    member = db.add_account(org_id=ORG_ID)
    return db.add_attachment(db.add_chat(member), filename="a.pdf", kind="pdf")


async def _insert_audit(db: FakeDb, action: str) -> Any:
    """A member's ``action`` row on one file, without metadata."""
    return await db.pool.execute(
        _AUDIT_INSERT,
        ORG_ID,
        _ACTOR,
        "member",
        action,
        "file",
        json.dumps([str(_TARGET_FILE)]),
        None,
        json.dumps({}),
    )


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0030File:
    """The migration ships as version 30, right after 0029, and is applied once."""

    def test_migration_0030_file_is_the_only_version_30_after_versions_1_to_29(self) -> None:
        shipped = [
            (int(m.group(1)), path.name)
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name))
        ]

        assert [name for version, name in shipped if version == _VERSION] == [_MIGRATION_NAME]
        assert sorted(version for version, _ in shipped if version < _VERSION) == list(
            range(1, _VERSION)
        )

    async def test_migration_0030_run_migrations_applies_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0029 applied, run_migrations executes the file and records 30."""
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

    async def test_migration_0030_runs_after_0029(self, mock_pool: MagicMock) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0030_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0030_opens_with_a_header_comment_naming_what_it_changes(self) -> None:
        """What, why and grants, before any statement: the column, the widened limit, the
        two actions and what the runtime role is granted."""
        lines = _header_lines()
        header = " ".join(lines)

        assert len(lines) >= 3
        assert {
            "names the column": re.search(rf"\b{_COLUMN}\b", header) is not None,
            "names the limit": _PLATFORM_COLUMN in header,
            "names file.exclude": "file.exclude" in header,
            "names file.include": "file.include" in header,
            "says what is granted": re.search(r"\bgrant", header, re.IGNORECASE) is not None,
        } == dict.fromkeys(
            (
                "names the column",
                "names the limit",
                "names file.exclude",
                "names file.include",
                "says what is granted",
            ),
            True,
        )


# ---------------------------------------------------------------------------
# 2. The active column
# ---------------------------------------------------------------------------


class TestMigration0030Column:
    """ALTER TABLE attachments ADD COLUMN active BOOLEAN NOT NULL DEFAULT true."""

    def test_migration_0030_adds_only_the_active_column(self) -> None:
        """One ADD COLUMN on any table: attachments.active (the CHECKs' DROP and ADD
        CONSTRAINT actions are pinned by the CHECK and scope tests)."""
        actions = [(table, _ADD_COLUMN_RE.fullmatch(_masked(a))) for table, a in _alter_actions()]

        assert [(table, m.group("name")) for table, m in actions if m] == [(_TABLE, _COLUMN)]

    def test_migration_0030_active_is_a_boolean_not_null_defaulting_to_true(self) -> None:
        """BOOLEAN NOT NULL DEFAULT true (every existing and new file is active), nothing
        else: no CHECK, key, reference, identity or anything the contract doesn't name."""
        column = _added_column()

        assert {
            "boolean": column.type_name in _BOOLEAN_TYPES,
            "not null": column.not_null,
            "explicit null": column.explicit_null,
            "primary key": column.primary_key,
            "identity": column.identity,
            "default": _canonical_default(column),
            "checks": column.checks,
            "uniques": column.uniques,
            "references": column.references,
            "unexpected": column.unexpected,
        } == {
            "boolean": True,
            "not null": True,
            "explicit null": False,
            "primary key": False,
            "identity": None,
            "default": "true",
            "checks": [],
            "uniques": [],
            "references": [],
            "unexpected": [],
        }


# ---------------------------------------------------------------------------
# 3. Privileges
# ---------------------------------------------------------------------------


class TestMigration0030Privileges:
    """admino_app may write the flag; nothing else changes."""

    def test_migration_0030_grant_is_one_update_of_active_to_admino_app_only(self) -> None:
        """The file's only GRANT (nested ones included): UPDATE (active) on attachments,
        to admino_app alone, without grant option."""
        assert _file_grants() == [
            (frozenset({f"update({_COLUMN})"}), (_TABLE,), frozenset({_ROLE}), False)
        ]

    def test_migration_0030_adds_update_of_active_and_nothing_else(self) -> None:
        """Every (table, grantee) holds after 0030 what it held after 0029, except
        admino_app on attachments, which gains update(active) only."""
        before = _acl(_VERSION - 1)
        after = _acl(_VERSION)
        expected = dict(before)
        expected[(_TABLE, _ROLE)] = before[(_TABLE, _ROLE)] | {f"update({_COLUMN})"}

        assert after == expected

    def test_migration_0030_admino_app_privileges_on_attachments_after_every_migration(
        self,
    ) -> None:
        """After every migration up to 0030: SELECT, INSERT, DELETE and UPDATE on exactly
        the nine columns the application writes (active included; no table-wide UPDATE,
        so never id, org_id, chat_id, owner_user_id, filename, kind, size_bytes or
        created_at; no grant option); PUBLIC nothing. (GH-194: migration 0031 adds
        update(trash_group_id); the set after every shipped migration is pinned in
        tests/test_migration_0031.py.)"""
        acl = _acl(_VERSION)

        assert {
            _ROLE: acl.get((_TABLE, _ROLE), frozenset()),
            "public": acl.get((_TABLE, "public"), frozenset()),
        } == {_ROLE: _EXPECTED_PRIVILEGES, "public": frozenset()}


# ---------------------------------------------------------------------------
# 4. The max_context_messages CHECK (Decision 8)
# ---------------------------------------------------------------------------


class TestMigration0030ContextMessagesCheck:
    """platform_settings_max_context_messages_check: 0 (no cap) to 200."""

    def test_migration_0030_platform_check_is_dropped_then_re_added_under_its_name(
        self,
    ) -> None:
        """A plain DROP (no IF EXISTS, no CASCADE), then one ADD of the same name on
        platform_settings, with nothing after the expression (no NOT VALID)."""
        steps = [
            _action_kind(table, action)
            for table, action in _alter_actions()
            if table == _PLATFORM_TABLE
        ]

        assert steps == [
            (_PLATFORM_TABLE, f"drop {_PLATFORM_CHECK}"),
            (_PLATFORM_TABLE, f"add check {_PLATFORM_CHECK}"),
        ]

    def test_migration_0030_platform_check_allows_0_to_200(self) -> None:
        """The whole expression bounds max_context_messages from 0 to 200 (BETWEEN or two
        comparisons): 0 means no cap (the budget alone decides)."""
        assert _platform_bounds() == _PLATFORM_BOUNDS

    def test_migration_0030_platform_check_bounds_equal_the_models(self) -> None:
        """LimitsConfig (config.yaml), PlatformLimits (the stored row) and
        PlatformLimitsPatch (the PATCH body) take exactly the values the CHECK takes: one
        below, the bounds and one above."""
        from admino.config import LimitsConfig
        from admino.models import PlatformLimits, PlatformLimitsPatch

        low, high = _platform_bounds()
        probes = (low - 1, low, high, high + 1)
        sql = {value: low <= value <= high for value in probes}

        assert {
            model.__name__: {value: _model_accepts(model, value) for value in probes}
            for model in (LimitsConfig, PlatformLimits, PlatformLimitsPatch)
        } == {
            "LimitsConfig": sql,
            "PlatformLimits": sql,
            "PlatformLimitsPatch": sql,
        }


# ---------------------------------------------------------------------------
# 5. The audit action catalog (contract C8)
# ---------------------------------------------------------------------------


class TestMigration0030ActionCatalog:
    """audit_events_action_check is replaced with 0027's catalog plus the two toggles."""

    def test_migration_0030_action_check_is_dropped_then_re_added_under_its_name(
        self,
    ) -> None:
        """A plain DROP (no IF EXISTS, no CASCADE), then one ADD of the same name on
        audit_events, with nothing after the expression."""
        steps = [
            _action_kind(table, action)
            for table, action in _alter_actions()
            if table == _AUDIT_TABLE
        ]

        assert steps == [
            (_AUDIT_TABLE, f"drop {_ACTION_CHECK}"),
            (_AUDIT_TABLE, f"add check {_ACTION_CHECK}"),
        ]

    def test_migration_0030_action_list_is_0027s_with_the_two_toggles_after_file_restore(
        self,
    ) -> None:
        """0027's 50 actions in their order, with 'file.exclude', 'file.include' right
        after 'file.restore': nothing else added or removed, each listed once."""
        listed = _listed_actions()

        assert listed == _expected_actions()
        assert len(listed) == len(set(listed))

    def test_migration_0030_action_check_matches_audit_action(self) -> None:
        """Every action 0030 allows is still an AuditAction (none was dropped). GH-194: the
        exact catalog sync moved on to tests/test_migration_0031.py, whose list adds
        chat.purge and file.purge."""
        from admino.audit_events import AuditAction

        assert set(_listed_actions()) <= {action.value for action in AuditAction}

    def test_migration_0030_audit_action_has_the_two_toggle_members(self) -> None:
        """AuditAction.FILE_EXCLUDE / FILE_INCLUDE are 'file.exclude' / 'file.include'."""
        from admino import audit_events

        assert {
            name: getattr(getattr(audit_events.AuditAction, name, None), "value", None)
            for name in ("FILE_EXCLUDE", "FILE_INCLUDE")
        } == {"FILE_EXCLUDE": "file.exclude", "FILE_INCLUDE": "file.include"}


# ---------------------------------------------------------------------------
# 6. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0030Scope:
    """Only the column, its grant and the two CHECK replacements."""

    def test_migration_0030_statements_run_in_the_contract_order(self) -> None:
        """The column's ALTER, the GRANT (PostgreSQL refuses a column privilege on a column
        that doesn't exist yet), the platform CHECK's DROP and ADD, the action CHECK's
        DROP and ADD: nothing else at the top level or in a DO block."""
        kinds = [_kind(statement) for statement in _statements()]

        assert kinds == [
            "column",
            "grant",
            "platform check",
            "platform check",
            "action check",
            "action check",
        ]

    def test_migration_0030_alters_only_the_column_and_the_two_checks(self) -> None:
        """Every ALTER TABLE action, in order: the column, the platform CHECK's DROP and
        ADD, the action CHECK's DROP and ADD. No other column, constraint, trigger or
        owner change."""
        kinds = [_action_kind(table, action) for table, action in _alter_actions()]

        assert kinds == [
            (_TABLE, f"add column {_COLUMN}"),
            (_PLATFORM_TABLE, f"drop {_PLATFORM_CHECK}"),
            (_PLATFORM_TABLE, f"add check {_PLATFORM_CHECK}"),
            (_AUDIT_TABLE, f"drop {_ACTION_CHECK}"),
            (_AUDIT_TABLE, f"add check {_ACTION_CHECK}"),
        ]

    def test_migration_0030_runs_no_code_revoke_or_data_write(self) -> None:
        """No DO block, function, trigger, role, INSERT / UPDATE / DELETE / TRUNCATE / COPY
        / MERGE, REVOKE, CREATE, DROP TABLE / INDEX / COLUMN or default privileges, also
        not nested in a body or an EXECUTE literal (existing rows take the default)."""
        fragments = _fragments(_normalize(_raw_sql()))
        offenders = [
            (kind, fragment)
            for fragment in fragments
            for kind, pattern in _FORBIDDEN.items()
            if re.match(pattern, _masked(fragment))
        ]

        assert fragments, f"{_MIGRATION_NAME} runs nothing"
        assert offenders == []


# ---------------------------------------------------------------------------
# 7. tests/db_fakes.py mirrors 0030
# ---------------------------------------------------------------------------


class TestMigration0030FakeDb:
    """The FakeDb models what the shipped migrations leave in place, 0030 included."""

    def test_migration_0030_fake_shipped_schema_is_the_files(self) -> None:
        """db_fakes.shipped_schema() of the tree: the column, the cumulative UPDATE grant,
        the CHECK's bounds, as this file's parsers read them, and every action of 0030's
        catalog. (GH-194: a later migration adds actions and schema fields; the fake's
        catalog after every shipped migration is pinned in tests/test_migration_0031.py.)"""
        schema = db_fakes.shipped_schema()

        assert (
            schema.attachments_active,
            schema.attachment_update_columns,
            schema.max_context_messages_bounds,
        ) == (True, _final_update_columns(), _platform_bounds())
        assert frozenset(_listed_actions()) <= schema.audit_actions

    def test_migration_0030_fake_attachment_row_has_active_true_after_derived_bytes(
        self,
    ) -> None:
        """ADD COLUMN appends: in the fake's attachments row derived_bytes is followed by
        active, true by default (GH-194: 0031's trash_group_id comes after them)."""
        db = FakeDb()
        row = db.attachment_row(_attachment(db))
        assert row is not None
        columns = list(row)
        after = columns.index("derived_bytes")

        assert (columns[after : after + 2], row.get(_COLUMN)) == (["derived_bytes", _COLUMN], True)

    async def test_migration_0030_fake_admino_app_may_update_active(self) -> None:
        """The grant: an UPDATE of active stores the new value."""
        db = FakeDb()
        attachment = _attachment(db)

        await db.pool.execute(_SET_ACTIVE, False, attachment)

        row = db.attachment_row(attachment)
        assert row is not None
        assert row[_COLUMN] is False

    def test_migration_0030_fake_platform_limit_takes_0_to_200(self) -> None:
        """0 and 200 are stored; -1 and 201 are CheckViolationError."""
        outcomes: dict[int, Any] = {}
        for value in (-1, 0, 200, 201):
            db = FakeDb()
            try:
                row = db.add_platform_settings(**{_PLATFORM_COLUMN: value})
            except asyncpg.CheckViolationError:
                outcomes[value] = "refused"
            else:
                outcomes[value] = row[_PLATFORM_COLUMN]

        assert outcomes == {-1: "refused", 0: 0, 200: 200, 201: "refused"}

    async def test_migration_0030_fake_records_file_exclude_and_file_include(self) -> None:
        """The shipped catalog takes the two toggles."""
        db = FakeDb()
        db.add_org(ORG_ID)

        for action in _NEW_ACTIONS:
            await _insert_audit(db, action)

        assert [row["action"] for row in db.audit] == list(_NEW_ACTIONS)
