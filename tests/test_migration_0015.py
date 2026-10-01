"""Tests for migration 0015_task_done_notifications.sql — task-done pings (GH-35).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0014.py pattern): it must exist, be applied by
run_migrations as version 15, and make exactly the schema change GH-35 needs.
The SQL is read with ``--`` comments blanked; statements are split outside
parentheses and literals; keywords are compared case-insensitively with
whitespace collapsed. ALTER TABLE statements are split into their actions.

What these tests pin down:
- One statement: ``ALTER TABLE user_settings ADD COLUMN notifications_task_done
  BOOLEAN NOT NULL DEFAULT false``. Existing rows take the default (pings off),
  so no UPDATE or INSERT is needed.
- The SQL default equals the Pydantic default ``SettingsNotifications().task_done``
  (``False``: #28 asks the browser for permission when the toggle is switched
  on, so it can't start on), and the FakeDb (``tests/db_fakes.py``) mirrors the
  column: name, ``bool`` type, NOT NULL and the ``False`` default of a new row.
- Nothing else: only ``user_settings`` is altered and only by adding that one
  column; no DROP, no UPDATE / DELETE / TRUNCATE / MERGE, no INSERT / COPY, no
  table, index, function, trigger, view, type or DO block, no GRANT / REVOKE,
  no audit catalog change (the user settings scope is not audited),
  parameter-free.

Security notes:
- NOT NULL with a default: no row can hold an unknown (NULL) ping preference,
  so the gate #28 consumes is always a definite bool.
- Default OFF: no user is opted into notifications by the migration.
- The migration never touches the append-only audit log, other users' data or
  any other scope's settings.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import admino.database as db_mod
import admino.models as models_module
from admino import audit_events
from tests import db_fakes

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0015_task_done_notifications.sql"
_VERSION = 15
_TABLE = "user_settings"
_COLUMN = "notifications_task_done"
_API_FIELD = "task_done"
# user_settings as migration 0013 created it (pinned by tests/test_migration_0013.py).
_COLUMNS_0013 = frozenset({"user_id", "theme", "notifications_enabled", "updated_at"})
_SQL_BOOLS: dict[str, bool] = {"true": True, "false": False}
_BOOLEAN = r"(?:boolean|bool)\b"
_ALTER_RE = re.compile(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)\s+(.*)", re.DOTALL)


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _migration_sql() -> str:
    """The shipped migration, normalized outside literals only.

    ``--`` comments are blanked, whitespace is collapsed and keywords are
    lowercased; the contents of '...' and "..." are kept byte for byte.
    """
    raw = _migration_path().read_text(encoding="utf-8")
    out: list[str] = []
    quote = ""
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote:
            out.append(char)
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
            out.append(char)
        elif raw.startswith("--", index):
            end = raw.find("\n", index)
            index = len(raw) if end < 0 else end
            if out and out[-1] != " ":
                out.append(" ")
            continue
        elif char.isspace():
            if out and out[-1] != " ":
                out.append(" ")
        else:
            out.append(char.lower())
        index += 1
    return "".join(out).strip()


def _masked(text: str) -> str:
    """Blank out the contents of '...' and "..." literals (same length)."""
    out: list[str] = []
    quote = ""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
                out.append(char)
            else:
                out.append(" ")
        else:
            if char in "'\"":
                quote = char
            out.append(char)
    return "".join(out)


def _split(text: str, separator: str) -> list[str]:
    """Split text at a separator outside parentheses and literals."""
    masked = _masked(text)
    items: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(masked):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == separator and depth == 0:
            items.append(text[start:index].strip())
            start = index + 1
    items.append(text[start:].strip())
    return [item for item in items if item]


def _statements() -> list[str]:
    return _split(_migration_sql(), ";")


def _actions() -> list[tuple[str, str]]:
    """(table, action) for every ALTER TABLE action, in order."""
    actions: list[tuple[str, str]] = []
    for statement in _statements():
        match = _ALTER_RE.fullmatch(_masked(statement))
        if match is None:
            continue
        rest = statement[match.start(2) :]
        actions.extend((match.group(1), action) for action in _split(rest, ","))
    return actions


def _added_column(action: str) -> tuple[str, str] | None:
    """(column, definition) of an ``ADD [COLUMN] [IF NOT EXISTS]`` action, else None."""
    masked = _masked(action)
    add = re.match(r"add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?", masked)
    if add is None:
        return None
    if re.match(r"(?:constraint|check|unique|primary|foreign|exclude)\b", masked[add.end() :]):
        return None
    column = re.fullmatch(r'"?(\w+)"?\s+(.*)', action[add.end() :], re.DOTALL)
    if column is None:
        return None
    return column.group(1), column.group(2).strip()


def _added_columns() -> list[tuple[str, str]]:
    """(column, definition) for every ADD COLUMN on user_settings, in order."""
    return [
        added
        for table, action in _actions()
        if table == _TABLE
        for added in [_added_column(action)]
        if added is not None
    ]


def _definition() -> str:
    columns = dict(_added_columns())
    assert _COLUMN in columns, f"no ADD COLUMN {_COLUMN} in {_MIGRATION_NAME}"
    return columns[_COLUMN]


def _default(definition: str) -> str | None:
    """The DEFAULT token of a column definition (optionally parenthesized)."""
    match = re.search(r"\bdefault\s+\(*\s*(\w+)\s*\)*", _masked(definition))
    return None if match is None else match.group(1)


def _is_required(definition: str) -> bool:
    return re.search(r"\bnot\s+null\b", _masked(definition)) is not None


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0015File:
    """The migration ships as version 15 and is applied by run_migrations."""

    def test_migration_0015_file_is_shipped_as_version_15(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0015_is_the_only_version_15(self) -> None:
        fifteens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert fifteens == [_MIGRATION_NAME]

    async def test_migration_0015_run_migrations_applies_it_as_version_15(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0014 applied, run_migrations executes the file and records 15."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (_VERSION, _MIGRATION_NAME) in recorded
        assert all(version >= _VERSION for version, _ in recorded)

    async def test_migration_0015_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0015_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0015 recorded, the shipped SQL is not executed a second time."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0015_is_parameter_free(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked


# ---------------------------------------------------------------------------
# 2. One ALTER TABLE user_settings ADD COLUMN
# ---------------------------------------------------------------------------


class TestMigration0015Statements:
    """Exactly one statement, adding exactly one column to user_settings."""

    def test_migration_0015_is_one_alter_table_user_settings_statement(self) -> None:
        statements = _statements()

        assert len(statements) == 1, statements
        match = _ALTER_RE.fullmatch(_masked(statements[0]))
        assert match is not None, statements[0]
        assert match.group(1) == _TABLE, statements[0]

    def test_migration_0015_has_exactly_one_action_an_add_column(self) -> None:
        """No DROP / SET / ALTER COLUMN / RENAME / constraint action."""
        actions = _actions()

        assert len(actions) == 1, actions
        assert _added_column(actions[0][1]) is not None, actions

    def test_migration_0015_adds_only_notifications_task_done(self) -> None:
        added = [name for name, _ in _added_columns()]

        assert added == [_COLUMN]

    def test_migration_0015_column_is_new_to_user_settings(self) -> None:
        """Migration 0013 didn't create it, so the ADD COLUMN can't collide."""
        assert _COLUMN in dict(_added_columns())
        sql_0013 = (db_mod._MIGRATIONS_DIR / "0013_settings_scopes.sql").read_text(encoding="utf-8")
        assert _COLUMN not in sql_0013
        assert _COLUMN not in _COLUMNS_0013


# ---------------------------------------------------------------------------
# 3. The column
# ---------------------------------------------------------------------------


class TestMigration0015Column:
    """notifications_task_done BOOLEAN NOT NULL DEFAULT false."""

    def test_migration_0015_column_is_a_boolean(self) -> None:
        definition = _masked(_definition())

        assert re.match(_BOOLEAN, definition), definition

    def test_migration_0015_column_is_not_null(self) -> None:
        """No row can hold an unknown preference."""
        assert _is_required(_definition()), _definition()

    def test_migration_0015_column_default_is_false(self) -> None:
        """Pings start off: existing rows and new rows take false."""
        assert _default(_definition()) == "false", _definition()

    def test_migration_0015_column_definition_is_exactly_boolean_not_null_default_false(
        self,
    ) -> None:
        """No CHECK, REFERENCES, UNIQUE, GENERATED or COLLATE clause."""
        definition = _masked(_definition())

        assert re.fullmatch(
            r"(?:boolean|bool)\s+"
            r"(?:not\s+null\s+default\s+\(?\s*false\s*\)?"
            r"|default\s+\(?\s*false\s*\)?\s+not\s+null)",
            definition,
        ), definition


# ---------------------------------------------------------------------------
# 4. SQL, Pydantic and the FakeDb stay in sync
# ---------------------------------------------------------------------------


class TestMigration0015MatchesPython:
    """The SQL default equals the Pydantic default and the FakeDb mirrors the column."""

    def test_migration_0015_default_equals_the_pydantic_default(self) -> None:
        sql_default = _SQL_BOOLS.get(_default(_definition()) or "")
        pydantic_default = models_module.SettingsNotifications().task_done

        assert sql_default is False
        assert pydantic_default is False
        assert sql_default is pydantic_default

    def test_migration_0015_column_maps_to_the_api_field(self) -> None:
        """notifications_task_done <-> notifications.task_done (a plain bool)."""
        fields = models_module.SettingsNotifications.model_fields

        assert f"notifications_{_API_FIELD}" in dict(_added_columns())
        assert _API_FIELD in fields
        assert fields[_API_FIELD].annotation is bool

    def test_migration_0015_the_fake_database_has_the_column(self) -> None:
        """tests/db_fakes.py's user_settings is migration 0013 plus this migration."""
        added = {name for name, _ in _added_columns()}

        assert frozenset(db_fakes._USER_SETTINGS_COLUMNS) == _COLUMNS_0013 | added

    def test_migration_0015_the_fake_database_types_it_as_a_required_bool(self) -> None:
        definition = _masked(_definition())

        assert re.match(_BOOLEAN, definition), definition
        assert db_fakes._SETTINGS_TYPES[_TABLE][_COLUMN] == "bool"
        assert _is_required(definition), definition
        assert _COLUMN not in db_fakes._SETTINGS_NULLABLE[_TABLE]

    def test_migration_0015_the_fake_database_default_equals_the_sql_default(self) -> None:
        """A new FakeDb user_settings row takes the shipped default."""
        sql_default = _SQL_BOOLS.get(_default(_definition()) or "")
        row = db_fakes.FakeDb().settings_defaults(_TABLE, {}, datetime.now(UTC))

        assert sql_default is not None
        assert row[_COLUMN] is sql_default


# ---------------------------------------------------------------------------
# 5. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0015NothingElse:
    """No other table, data, code or privilege changes."""

    def test_migration_0015_alters_only_user_settings(self) -> None:
        targets = re.findall(
            r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", _masked(_migration_sql())
        )

        assert targets
        assert set(targets) == {_TABLE}

    def test_migration_0015_drops_nothing(self) -> None:
        assert re.search(r"\bdrop\b", _masked(_migration_sql())) is None

    def test_migration_0015_changes_no_existing_rows(self) -> None:
        """Existing rows take the column default; nothing is backfilled."""
        masked = _masked(_migration_sql())

        assert re.search(r"\bupdate\b", masked) is None
        assert re.search(r"\bdelete\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None
        assert re.search(r"\bmerge\b", masked) is None

    def test_migration_0015_inserts_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\b", masked) is None
        assert re.search(r"\bcopy\b", masked) is None

    def test_migration_0015_creates_nothing(self) -> None:
        """No table, index, function, procedure, trigger, view, type, rule or policy."""
        masked = _masked(_migration_sql())

        assert re.search(r"\bcreate\b", masked) is None
        assert re.search(r"\bdo\b", masked) is None
        assert "$$" not in masked

    def test_migration_0015_renames_nothing(self) -> None:
        assert re.search(r"\brename\b", _masked(_migration_sql())) is None

    def test_migration_0015_grants_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:grant|revoke)\b", masked) is None

    def test_migration_0015_leaves_the_audit_catalog_alone(self) -> None:
        """The user settings scope isn't audited (scoped_settings): no catalog change."""
        sql = _masked(_migration_sql())

        assert "audit_events" not in sql
        assert "action_check" not in sql
        assert not any(
            action.value.startswith(("user.settings", "settings."))
            for action in audit_events.AuditAction
        )
