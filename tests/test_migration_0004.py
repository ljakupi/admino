"""Tests for migration 0004_organizations_users.sql — orgs and users schema (GH-145).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the TestRemoveFilesToolMigration pattern in test_database.py): it must
exist, be applied by run_migrations as version 4, and declare the organizations
and users tables with the columns, defaults and CHECK constraints the issue
lists. The SQL is read with comments stripped, whitespace collapsed and
lowercased, then matched with formatting-tolerant regexes.

Security notes:
- CHECK constraints mirror the Pydantic bounds (Principal's kind/org/role
  validator), so a direct DB write can't create a super admin inside an org or
  a member without one.
- Email uniqueness is case-insensitive platform-wide (unique index on lower(email)).
- The migration is parameter-free and removes no existing data; the old
  single-tenant rows are dropped by the migrations that re-scope them (#159,
  #161, #162).
"""

from __future__ import annotations

import re
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import admino.database as db_mod

_MIGRATION_NAME = "0004_organizations_users.sql"

# Formatting-tolerant type patterns.
_UUID = r"uuid"
_TEXT = r"text"
_INTEGER = r"(?:integer|int4|int)"
_BIGINT = r"(?:bigint|int8)"
_BOOLEAN = r"(?:boolean|bool)"
_NUMERIC_12_2 = r"numeric\s*\(\s*12\s*,\s*2\s*\)"
_TIMESTAMPTZ = r"(?:timestamptz|timestamp with time zone)"

# Formatting-tolerant default patterns.
_GEN_UUID = r"gen_random_uuid\s*\(\s*\)"
_NOW = r"(?:now\s*\(\s*\)|current_timestamp)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _migration_sql() -> str:
    """Return the shipped 0004 migration, comments stripped, whitespace collapsed, lowercased."""
    raw = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")
    without_comments = re.sub(r"--[^\n]*", " ", raw)
    return re.sub(r"\s+", " ", without_comments).strip().lower()


def _table_body(table: str) -> str:
    """Return the text between the parentheses of CREATE TABLE <table> ( ... );."""
    match = re.search(
        rf"create table (?:if not exists )?{table}\s*\((.*?)\)\s*;",
        _migration_sql(),
    )
    if match is None:
        pytest.fail(f"no CREATE TABLE {table} in {_MIGRATION_NAME}")
    return match.group(1)


def _table_items(table: str) -> list[str]:
    """Split a table body into its top-level items (column definitions and constraints)."""
    items: list[str] = []
    depth = 0
    current: list[str] = []
    for char in _table_body(table):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            items.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    items.append("".join(current).strip())
    return [item for item in items if item]


def _column(table: str, column: str) -> str:
    """Return the full definition of one column (name, type and inline constraints)."""
    for item in _table_items(table):
        if item.split(" ", 1)[0].strip('"') == column:
            return item
    pytest.fail(f"column {table}.{column} is not defined in {_MIGRATION_NAME}")


def _in_check_values(table: str, column: str) -> set[str]:
    """Return the literal set of a CHECK (<column> IN ('a', 'b', ...)) on the table."""
    match = re.search(
        rf"check\s*\(\s*(?:{column}\s+is\s+null\s+or\s+)?{column}\s+in\s*\(([^)]*)\)\s*\)",
        _table_body(table),
    )
    if match is None:
        pytest.fail(f"no CHECK ({column} IN (...)) on {table}")
    return set(re.findall(r"'([^']*)'", match.group(1)))


def _length_bounds(table: str, column: str) -> tuple[int, int]:
    """Return (low, high) of a CHECK (char_length(<column>) BETWEEN low AND high)."""
    match = re.search(
        rf"check\s*\(\s*(?:{column}\s+is\s+null\s+or\s+)?(?:char_)?length\s*\(\s*{column}\s*\)"
        r"\s+between\s+(\d+)\s+and\s+(\d+)\s*\)",
        _table_body(table),
    )
    if match is None:
        pytest.fail(f"no CHECK (char_length({column}) BETWEEN ...) on {table}")
    return int(match.group(1)), int(match.group(2))


# ---------------------------------------------------------------------------
# Column specification: (table, column, type pattern, NOT NULL?, default pattern)
# NOT NULL: True = required, False = must be nullable, None = implied (primary key).
# ---------------------------------------------------------------------------

_COLUMNS: list[tuple[str, str, str, bool | None, str | None]] = [
    # organizations
    ("organizations", "id", _UUID, None, _GEN_UUID),
    ("organizations", "name", _TEXT, True, None),
    ("organizations", "status", _TEXT, True, r"'active'"),
    ("organizations", "seats", _INTEGER, True, None),
    ("organizations", "monthly_budget_chf", _NUMERIC_12_2, True, None),
    ("organizations", "storage_quota_bytes", _BIGINT, True, None),
    ("organizations", "data_residency", _BOOLEAN, True, r"true"),
    ("organizations", "default_response_language", _TEXT, True, r"'en'"),
    ("organizations", "deletion_requested_at", _TIMESTAMPTZ, False, None),
    ("organizations", "purge_after", _TIMESTAMPTZ, False, None),
    ("organizations", "created_at", _TIMESTAMPTZ, True, _NOW),
    ("organizations", "updated_at", _TIMESTAMPTZ, True, _NOW),
    # users
    ("users", "id", _UUID, None, _GEN_UUID),
    ("users", "email", _TEXT, True, None),
    ("users", "name", _TEXT, False, None),
    ("users", "password_hash", _TEXT, False, None),
    ("users", "kind", _TEXT, True, None),
    ("users", "org_id", _UUID, False, None),
    ("users", "role", _TEXT, False, None),
    ("users", "status", _TEXT, True, r"'invited'"),
    ("users", "ui_language", _TEXT, True, r"'en'"),
    ("users", "response_language", _TEXT, False, None),
    ("users", "created_at", _TIMESTAMPTZ, True, _NOW),
    ("users", "last_login_at", _TIMESTAMPTZ, False, None),
    ("users", "deleted_at", _TIMESTAMPTZ, False, None),
]

_TYPE_CASES = [
    pytest.param(table, column, type_pattern, id=f"{table}.{column}")
    for table, column, type_pattern, _, _ in _COLUMNS
]
_NULLABILITY_CASES = [
    pytest.param(table, column, not_null, id=f"{table}.{column}")
    for table, column, _, not_null, _ in _COLUMNS
    if not_null is not None
]
_DEFAULT_CASES = [
    pytest.param(table, column, default, id=f"{table}.{column}")
    for table, column, _, _, default in _COLUMNS
    if default is not None
]

_IN_CHECKS: list[Any] = [
    pytest.param(
        "organizations",
        "status",
        {"active", "deactivated", "pending_deletion"},
        id="organizations.status",
    ),
    pytest.param(
        "organizations",
        "default_response_language",
        {"de", "fr", "it", "en"},
        id="organizations.default_response_language",
    ),
    pytest.param("users", "kind", {"super_admin", "member"}, id="users.kind"),
    pytest.param("users", "role", {"org_admin", "editor", "viewer"}, id="users.role"),
    pytest.param("users", "status", {"invited", "active", "deactivated"}, id="users.status"),
    pytest.param("users", "ui_language", {"de", "fr", "en"}, id="users.ui_language"),
    pytest.param(
        "users",
        "response_language",
        {"de", "fr", "it", "en"},
        id="users.response_language",
    ),
]

_LENGTH_CHECKS: list[Any] = [
    pytest.param("organizations", "name", (1, 120), id="organizations.name"),
    pytest.param("users", "name", (1, 120), id="users.name"),
    pytest.param("users", "password_hash", (1, 512), id="users.password_hash"),
]


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0004File:
    """The migration ships as version 4, is applied by run_migrations, and keeps data."""

    def test_migration_0004_file_is_shipped_as_version_4(self) -> None:
        """0004_organizations_users.sql exists and matches the numbered-migration regex."""
        assert (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == 4

    async def test_migration_0004_run_migrations_applies_it_as_version_4(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0003 applied, run_migrations executes the file and records version 4."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": 1}, {"version": 2}, {"version": 3}])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (4, _MIGRATION_NAME) in recorded
        assert all(version >= 4 for version, _ in recorded)

    async def test_migration_0004_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        """run_migrations executes the 0004 file's SQL text verbatim."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": 1}, {"version": 2}, {"version": 3}])
        shipped = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0004_is_parameter_free(self) -> None:
        """No bind parameters or interpolation placeholders in the migration."""
        sql = _migration_sql()

        assert re.search(r"\$\d", sql) is None
        assert "%s" not in sql
        assert "%(" not in sql

    def test_migration_0004_removes_no_existing_data(self) -> None:
        """No DROP TABLE, DELETE FROM or TRUNCATE: the old settings/permissions/memory/
        oauth_tokens rows are dropped by #159/#161/#162, not by this migration."""
        sql = _migration_sql()

        assert re.search(r"\bdrop\s+table\b", sql) is None
        assert re.search(r"\bdelete\s+from\b", sql) is None
        assert re.search(r"\btruncate\b", sql) is None

    def test_migration_0004_creates_organizations_before_users(self) -> None:
        """users.org_id references organizations, so organizations is created first."""
        sql = _migration_sql()
        orgs = re.search(r"create table (?:if not exists )?organizations\b", sql)
        users = re.search(r"create table (?:if not exists )?users\b", sql)

        assert orgs is not None
        assert users is not None
        assert orgs.start() < users.start()


# ---------------------------------------------------------------------------
# 2. Column shapes (types, nullability, defaults)
# ---------------------------------------------------------------------------


class TestMigration0004Columns:
    """Every column the issue lists, with its type, nullability and default."""

    @pytest.mark.parametrize(("table", "column", "type_pattern"), _TYPE_CASES)
    def test_migration_0004_column_has_expected_type(
        self, table: str, column: str, type_pattern: str
    ) -> None:
        """The column exists with the specified SQL type."""
        definition = _column(table, column)

        assert re.match(rf"{column} {type_pattern}(?=\s|$)", definition), definition

    @pytest.mark.parametrize(("table", "column", "not_null"), _NULLABILITY_CASES)
    def test_migration_0004_column_has_expected_nullability(
        self, table: str, column: str, not_null: bool
    ) -> None:
        """Required columns are NOT NULL; invitee name/password_hash, org_id and role
        (NULL for super admins), response_language and lifecycle timestamps stay nullable."""
        definition = _column(table, column)
        # "(?<!is )" skips "IS NOT NULL" inside an inline CHECK expression.
        declared_not_null = re.search(r"(?<!is )\bnot null\b", definition) is not None

        assert declared_not_null is not_null, definition

    @pytest.mark.parametrize(("table", "column", "default"), _DEFAULT_CASES)
    def test_migration_0004_column_has_expected_default(
        self, table: str, column: str, default: str
    ) -> None:
        """The column's DEFAULT matches the issue (status, languages, residency, timestamps)."""
        definition = _column(table, column)

        assert re.search(rf"\bdefault\s+{default}", definition), definition

    @pytest.mark.parametrize("table", ["organizations", "users"])
    def test_migration_0004_id_is_primary_key(self, table: str) -> None:
        """id UUID PRIMARY KEY DEFAULT gen_random_uuid() on both tables."""
        assert "primary key" in _column(table, "id")

    def test_migration_0004_users_org_id_references_organizations(self) -> None:
        """users.org_id is a foreign key to organizations(id)."""
        inline = re.search(
            r"\breferences organizations\b(?:\s*\(\s*id\s*\))?", _column("users", "org_id")
        )
        table_level = re.search(
            r"foreign key\s*\(\s*org_id\s*\)\s*references organizations\b(?:\s*\(\s*id\s*\))?",
            _table_body("users"),
        )

        assert inline is not None or table_level is not None

    def test_migration_0004_org_with_users_cannot_be_deleted(self) -> None:
        """ON DELETE RESTRICT: deleting an org that still has users fails instead of
        cascading, so an org purge (#154) must remove its users on purpose."""
        assert re.search(r"\bon delete restrict\b", _column("users", "org_id"))


# ---------------------------------------------------------------------------
# 3. Value CHECK constraints (mirroring the Pydantic bounds)
# ---------------------------------------------------------------------------


class TestMigration0004ValueChecks:
    """Enumerations, lengths and numeric bounds are enforced by CHECK constraints."""

    @pytest.mark.parametrize(("table", "column", "values"), _IN_CHECKS)
    def test_migration_0004_enum_column_check_lists_exact_values(
        self, table: str, column: str, values: set[str]
    ) -> None:
        """CHECK (<column> IN (...)) allows exactly the values the issue lists."""
        assert _in_check_values(table, column) == values

    @pytest.mark.parametrize(("table", "column", "bounds"), _LENGTH_CHECKS)
    def test_migration_0004_text_column_length_check(
        self, table: str, column: str, bounds: tuple[int, int]
    ) -> None:
        """CHECK (char_length(<column>) BETWEEN low AND high) matches the issue's bounds."""
        assert _length_bounds(table, column) == bounds

    def test_migration_0004_users_email_at_most_254_chars(self) -> None:
        """users.email is limited to 254 characters (and can't be empty)."""
        low, high = _length_bounds("users", "email")

        assert high == 254
        assert low >= 1

    def test_migration_0004_users_email_has_no_whitespace(self) -> None:
        """users.email can't contain whitespace, so ' a@x.ch' can't dodge the lower(email)
        unique index as a second spelling of 'a@x.ch' (security audit, GH-145)."""
        assert re.search(r"check\s*\(\s*email\s*!~\s*'\[\[:space:\]\]'", _table_body("users"))

    def test_migration_0004_users_email_has_a_local_part_and_at_sign(self) -> None:
        """users.email has an '@' after at least one character."""
        assert re.search(r"position\s*\(\s*'@'\s+in\s+email\s*\)\s*>\s*1", _table_body("users"))

    def test_migration_0004_organizations_seats_between_1_and_100000(self) -> None:
        """Plan limit: CHECK (seats BETWEEN 1 AND 100000)."""
        assert re.search(
            r"check\s*\(\s*seats\s+between\s+1\s+and\s+100000\s*\)",
            _table_body("organizations"),
        )

    def test_migration_0004_organizations_budget_non_negative(self) -> None:
        """Plan limit: CHECK (monthly_budget_chf >= 0)."""
        assert re.search(
            r"check\s*\(\s*monthly_budget_chf\s*>=\s*0(?:\.0+)?\s*\)",
            _table_body("organizations"),
        )

    def test_migration_0004_organizations_storage_quota_non_negative(self) -> None:
        """Plan limit: CHECK (storage_quota_bytes >= 0)."""
        assert re.search(
            r"check\s*\(\s*storage_quota_bytes\s*>=\s*0\s*\)",
            _table_body("organizations"),
        )


# ---------------------------------------------------------------------------
# 4. Consistency CHECK constraints
# ---------------------------------------------------------------------------


class TestMigration0004ConsistencyChecks:
    """Row-level invariants: org lifecycle, super admin vs member, active accounts."""

    def test_migration_0004_pending_deletion_iff_purge_after_set(self) -> None:
        """CHECK ((status = 'pending_deletion') = (purge_after IS NOT NULL))."""
        assert re.search(
            r"check\s*\(\s*\(\s*status\s*=\s*'pending_deletion'\s*\)\s*=\s*"
            r"\(\s*purge_after\s+is\s+not\s+null\s*\)\s*\)",
            _table_body("organizations"),
        )

    def test_migration_0004_deletion_requested_iff_purge_after_set(self) -> None:
        """CHECK ((deletion_requested_at IS NULL) = (purge_after IS NULL))."""
        assert re.search(
            r"check\s*\(\s*\(\s*deletion_requested_at\s+is\s+null\s*\)\s*=\s*"
            r"\(\s*purge_after\s+is\s+null\s*\)\s*\)",
            _table_body("organizations"),
        )

    def test_migration_0004_super_admin_iff_no_org(self) -> None:
        """A super admin with an org is rejected, and so is a member without one:
        CHECK ((kind = 'super_admin') = (org_id IS NULL))."""
        assert re.search(
            r"check\s*\(\s*\(\s*kind\s*=\s*'super_admin'\s*\)\s*=\s*"
            r"\(\s*org_id\s+is\s+null\s*\)\s*\)",
            _table_body("users"),
        )

    def test_migration_0004_super_admin_iff_no_role(self) -> None:
        """A super admin with a role is rejected, and so is a member without one:
        CHECK ((kind = 'super_admin') = (role IS NULL))."""
        assert re.search(
            r"check\s*\(\s*\(\s*kind\s*=\s*'super_admin'\s*\)\s*=\s*"
            r"\(\s*role\s+is\s+null\s*\)\s*\)",
            _table_body("users"),
        )

    def test_migration_0004_active_users_have_name_and_password(self) -> None:
        """Invitees may lack name/password_hash, active users may not:
        CHECK (status <> 'active' OR (name IS NOT NULL AND password_hash IS NOT NULL))."""
        assert re.search(
            r"check\s*\(\s*status\s*(?:<>|!=)\s*'active'\s+or\s+\(\s*"
            r"(?:name\s+is\s+not\s+null\s+and\s+password_hash\s+is\s+not\s+null"
            r"|password_hash\s+is\s+not\s+null\s+and\s+name\s+is\s+not\s+null)"
            r"\s*\)\s*\)",
            _table_body("users"),
        )


# ---------------------------------------------------------------------------
# 5. Indexes
# ---------------------------------------------------------------------------


class TestMigration0004Indexes:
    """Case-insensitive email uniqueness and the org_id lookup index."""

    def test_migration_0004_email_unique_case_insensitively(self) -> None:
        """Platform-wide case-insensitive uniqueness: CREATE UNIQUE INDEX ... ON users
        (lower(email)), so Alice@Example.com and alice@example.com can't both exist."""
        assert re.search(
            r"create unique index (?:if not exists )?(?:\w+ )?on (?:only )?users\s*"
            r"(?:using btree\s*)?\(\s*lower\s*\(\s*email\s*\)\s*\)",
            _migration_sql(),
        )

    def test_migration_0004_users_org_id_indexed(self) -> None:
        """CREATE INDEX ... ON users (org_id) for per-org user listings."""
        assert re.search(
            r"create index (?:if not exists )?(?:\w+ )?on (?:only )?users\s*"
            r"(?:using btree\s*)?\(\s*org_id\s*\)",
            _migration_sql(),
        )


# ---------------------------------------------------------------------------
# 6. Identity columns are immutable (no UPDATE can mint a Super Admin)
# ---------------------------------------------------------------------------


def _immutability_function() -> tuple[str, str]:
    """Return (name, body) of the trigger function guarding users.kind / users.org_id."""
    sql = _migration_sql()
    for match in re.finditer(
        r"create (?:or replace )?function (\w+)\s*\(\s*\)\s*returns trigger\b(.*?)\$\$\s*;", sql
    ):
        if "old.kind" in match.group(2):
            return match.group(1), match.group(2)
    pytest.fail(f"no trigger function comparing old.kind in {_MIGRATION_NAME}")


class TestMigration0004IdentityImmutable:
    """users.kind and users.org_id can never change after the row is inserted.

    A BEFORE UPDATE trigger is the database's last line of defense: even a buggy
    or injected UPDATE can't turn a member into a Super Admin (kind), move a user
    into another org (org_id), or strip a member's org.
    """

    def test_migration_0004_kind_change_is_refused(self) -> None:
        """The trigger function raises when kind changes."""
        _, body = _immutability_function()

        assert re.search(r"new\.kind is distinct from old\.kind", body)
        assert "raise exception" in body

    def test_migration_0004_org_id_change_is_refused(self) -> None:
        """The trigger function raises when org_id changes (NULL to a value and back included)."""
        _, body = _immutability_function()

        assert re.search(r"new\.org_id is distinct from old\.org_id", body)

    def test_migration_0004_trigger_runs_before_every_update_of_users(self) -> None:
        """BEFORE UPDATE ON users FOR EACH ROW, with no column list to sidestep."""
        name, _ = _immutability_function()

        assert re.search(
            rf"create trigger \w+ before update on users for each row "
            rf"execute (?:function|procedure) {name}\s*\(\s*\)",
            _migration_sql(),
        )

    def test_migration_0004_trigger_error_carries_no_row_data(self) -> None:
        """No content in errors: the exception message doesn't interpolate NEW/OLD values."""
        _, body = _immutability_function()
        raise_stmt = re.search(r"raise exception ([^;]*);", body)

        assert raise_stmt is not None
        assert "new." not in raise_stmt.group(1)
        assert "old." not in raise_stmt.group(1)
