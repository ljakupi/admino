"""Tests for migration 0005_audit_events.sql — the append-only audit event store (GH-146).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0004.py pattern): it must exist, be applied by
run_migrations as version 5, and declare the audit_events table, its CHECK
constraints and indexes, the append-only trigger and the retention purge
function. The SQL is read with comments stripped, whitespace collapsed and
lowercased, then matched with formatting-tolerant regexes. Parsing is
quote-aware, so jsonpath literals with commas and parentheses don't confuse it,
and the regular expressions the CHECKs use are extracted and exercised with
sample values.

Security notes:
- Append-only: a BEFORE UPDATE OR DELETE row trigger refuses every UPDATE and
  every DELETE except those issued from purge_audit_events(integer) for rows
  older than the 6-month floor; a BEFORE TRUNCATE trigger refuses TRUNCATE.
  Trigger errors carry no row data.
- Content-free at the database level too: target_ids is a JSON array of
  UUID-shaped strings, metadata a flat JSON object with regex-restricted string
  values and a bounded size; the enumerations mirror the Python enums.
- org_id never cascades (ON DELETE RESTRICT/NO ACTION): an org purge removes its
  audit rows on purpose. actor_user_id has no foreign key, so the history
  outlives deleted accounts.
- The migration is parameter-free and removes no existing data; the purge
  function validates its bounds and uses no dynamic SQL.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, get_args
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from types import ModuleType

_MIGRATION_NAME = "0005_audit_events.sql"
_TABLE = "audit_events"

# Formatting-tolerant type patterns.
_UUID = r"uuid"
_TEXT = r"text"
_JSONB = r"jsonb"
_INET = r"inet"
_TIMESTAMPTZ = r"(?:timestamptz|timestamp with time zone)"

# Formatting-tolerant default patterns.
_GEN_UUID = r"gen_random_uuid\s*\(\s*\)"
_NOW = r"(?:now\s*\(\s*\)|current_timestamp)"
_EMPTY_ARRAY = r"'\[\]'(?:\s*::\s*jsonb)?"
_EMPTY_OBJECT = r"'\{\}'(?:\s*::\s*jsonb)?"

# "now" as a PL/pgSQL expression, and a month count as an interval.
_NOW_EXPR = (
    r"(?:now\s*\(\s*\)|current_timestamp|clock_timestamp\s*\(\s*\)"
    r"|statement_timestamp\s*\(\s*\)|transaction_timestamp\s*\(\s*\))"
)
_MONTHS_UNIT = r"(?:months?|mons?)"

_SAMPLE_UUIDS: tuple[str, ...] = (
    "3f2b8c1e-5d4a-4e7b-9a6c-0b1d2e3f4a5b",
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-4fff-bfff-ffffffffffff",
    str(UUID(int=1)),
)

_SPEC_ACTIONS: frozenset[str] = frozenset(
    {
        "login.success",
        "login.failure",
        "login.lockout",
        "password_reset.request",
        "password_reset.complete",
        "invitation.create",
        "invitation.revoke",
        "invitation.accept",
        "user.role_change",
        "user.activate",
        "user.deactivate",
        "user.delete",
        "project.share",
        "project.unshare",
        "project.member_role_change",
        "project.transfer",
        "project.delete",
        "project.restore",
        "chat.delete",
        "chat.restore",
        "file.delete",
        "file.restore",
        "project.admin_access",
        "export.create",
        "org.settings_change",
        "org.create",
        "org.limits_change",
        "org.deactivate",
        "org.reactivate",
        "org.deletion_schedule",
        "org.deletion_cancel",
        "org.purge",
        "org.residency_change",
        "platform.settings_change",
        "model.registry_change",
        "breakglass.start",
        "breakglass.end",
        "tool.call",
        "audit.purge",
    }
)


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _cased_sql() -> str:
    """Return the shipped 0005 migration, comments stripped, whitespace collapsed, case kept."""
    raw = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")
    without_comments = re.sub(r"--.*", " ", raw)
    return re.sub(r"\s+", " ", without_comments).strip()


def _migration_sql() -> str:
    """Return the shipped 0005 migration, comments stripped, whitespace collapsed, lowercased."""
    return _cased_sql().lower()


def _masked(text: str) -> str:
    """Blank out the contents of '...' and "..." literals (same length), so parentheses,
    commas and keywords inside literals don't count as SQL structure."""
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


def _balanced_end(masked: str, open_index: int) -> int:
    """Return the index of the parenthesis closing the one at open_index."""
    depth = 0
    for index in range(open_index, len(masked)):
        if masked[index] == "(":
            depth += 1
        elif masked[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    pytest.fail(f"unbalanced parentheses in {_MIGRATION_NAME}")


def _table_body(sql: str) -> str:
    """Return the text between the parentheses of CREATE TABLE audit_events ( ... )."""
    masked = _masked(sql)
    match = re.search(
        rf"create\s+table\s+(?:if\s+not\s+exists\s+)?{_TABLE}\s*\(", masked, re.IGNORECASE
    )
    if match is None:
        pytest.fail(f"no CREATE TABLE {_TABLE} in {_MIGRATION_NAME}")
    end = _balanced_end(masked, match.end() - 1)
    return sql[match.end() : end]


def _split_top_level(text: str) -> list[str]:
    """Split text at commas outside parentheses and literals."""
    masked = _masked(text)
    items: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(masked):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            items.append(text[start:index].strip())
            start = index + 1
    items.append(text[start:].strip())
    return [item for item in items if item]


def _table_items() -> list[str]:
    """Top-level items (column definitions and table constraints) of audit_events, lowercased."""
    return _split_top_level(_table_body(_migration_sql()))


_CONSTRAINT_WORDS = frozenset({"constraint", "check", "primary", "foreign", "unique", "exclude"})


def _column_names() -> set[str]:
    """Names of the columns audit_events defines."""
    names: set[str] = set()
    for item in _table_items():
        first = item.split(" ", 1)[0].strip('"')
        if first not in _CONSTRAINT_WORDS:
            names.add(first)
    return names


def _column(column: str) -> str:
    """Return the full definition of one column (name, type and inline constraints)."""
    for item in _table_items():
        if item.split(" ", 1)[0].strip('"') == column:
            return item
    pytest.fail(f"column {_TABLE}.{column} is not defined in {_MIGRATION_NAME}")


def _check_expressions(sql: str) -> list[str]:
    """Return the expression of every CHECK (...) in the audit_events table body of `sql`."""
    body = _table_body(sql)
    masked = _masked(body)
    expressions: list[str] = []
    for match in re.finditer(r"\bcheck\s*\(", masked, re.IGNORECASE):
        end = _balanced_end(masked, match.end() - 1)
        expressions.append(body[match.end() : end].strip())
    return expressions


def _checks() -> list[str]:
    """Every CHECK expression of audit_events, lowercased."""
    return _check_expressions(_migration_sql())


def _any_check_matches(*patterns: str) -> bool:
    """True when some CHECK expression of audit_events matches one of the patterns."""
    return any(re.search(pattern, check) for check in _checks() for pattern in patterns)


def _in_values(expression: str, column: str) -> set[str] | None:
    """Return the literals of '<column> IN (...)' when that is the whole expression."""
    match = re.fullmatch(
        rf"\s*(?:{column}\s+is\s+null\s+or\s+)?{column}\s+in\s*\(([^)]*)\)\s*", expression
    )
    if match is None:
        return None
    return set(re.findall(r"'([^']*)'", match.group(1)))


def _in_check_values(column: str) -> set[str]:
    """Return the literal set of a CHECK (<column> IN ('a', 'b', ...)) on audit_events."""
    for check in _checks():
        values = _in_values(check, column)
        if values is not None:
            return values
    pytest.fail(f"no CHECK ({column} IN (...)) on {_TABLE}")


def _named_check(name: str) -> str:
    """Return the expression of CONSTRAINT <name> CHECK (...) on audit_events."""
    body = _table_body(_migration_sql())
    masked = _masked(body)
    match = re.search(rf"\bconstraint\s+{name}\s+check\s*\(", masked)
    if match is None:
        pytest.fail(f"no CONSTRAINT {name} CHECK (...) on {_TABLE}")
    end = _balanced_end(masked, match.end() - 1)
    return body[match.end() : end].strip()


_METADATA_KEY_CAP_RE = re.compile(
    r"jsonb_array_length\s*\(\s*jsonb_path_query_array\s*\(\s*metadata\s*,\s*"
    r"'(?:strict\s+|lax\s+)?\$\s*\.\s*keyvalue\s*\(\s*\)'\s*\)\s*\)\s*(?:<=\s*(\d+)|<\s*(\d+))"
)


def _metadata_key_cap() -> int:
    """Return the most metadata keys a CHECK on audit_events lets through."""
    for check in _checks():
        match = _METADATA_KEY_CAP_RE.search(check)
        if match is not None:
            return int(match.group(1)) if match.group(1) else int(match.group(2)) - 1
    pytest.fail(f"no CHECK on {_TABLE} caps the number of metadata keys")


_LIKE_REGEX_RE = re.compile(
    r'like_regex\s+"((?:[^"\\]|\\.)*)"(?:\s+flag\s+"(\w*)")?', re.IGNORECASE
)
_TILDE_RE = re.compile(r"(~\*?)\s*'((?:[^']|'')*)'")


def _regex_patterns(expression: str) -> list[re.Pattern[str]]:
    """Compile the like_regex (jsonpath) and ~ (SQL) patterns an expression uses."""
    patterns: list[re.Pattern[str]] = []
    for match in _LIKE_REGEX_RE.finditer(expression):
        source = re.sub(r'\\([\\"/])', r"\1", match.group(1))
        flags = re.IGNORECASE if "i" in (match.group(2) or "") else 0
        patterns.append(re.compile(source, flags))
    for match in _TILDE_RE.finditer(expression):
        flags = re.IGNORECASE if match.group(1) == "~*" else 0
        patterns.append(re.compile(match.group(2).replace("''", "'"), flags))
    return patterns


def _patterns_for(column: str) -> list[re.Pattern[str]]:
    """The regex patterns of every CHECK on audit_events that mentions `column`."""
    patterns: list[re.Pattern[str]] = []
    for check in _check_expressions(_cased_sql()):
        if re.search(rf"\b{column}\b", check, re.IGNORECASE):
            patterns.extend(_regex_patterns(check))
    if not patterns:
        pytest.fail(f"no CHECK with a regex on {_TABLE}.{column}")
    return patterns


def _allowed_by(patterns: list[re.Pattern[str]], value: str) -> bool:
    """True when some pattern matches the value (like_regex and ~ are unanchored searches)."""
    return any(pattern.search(value) for pattern in patterns)


class _Function(NamedTuple):
    """One CREATE FUNCTION statement, lowercased."""

    name: str
    arguments: str
    returns: str
    options: str
    body: str


_FUNCTION_RE = re.compile(
    r"create\s+(?:or\s+replace\s+)?function\s+(?:public\.)?(\w+)\s*\(([^)]*)\)\s*"
    r"returns\s+(\w+)(.*?)\$(\w*)\$(.*?)\$\5\$([^;]*);"
)


def _functions() -> dict[str, _Function]:
    """Every function the migration creates, by name."""
    return {
        match.group(1): _Function(
            name=match.group(1),
            arguments=match.group(2).strip(),
            returns=match.group(3),
            options=f"{match.group(4)} {match.group(7)}",
            body=match.group(6),
        )
        for match in _FUNCTION_RE.finditer(_migration_sql())
    }


def _append_only_function() -> _Function:
    """The trigger function guarding audit_events (the one that reads pg_context)."""
    for function in _functions().values():
        if function.returns == "trigger" and "pg_context" in function.body:
            return function
    pytest.fail(f"no trigger function reading pg_context in {_MIGRATION_NAME}")


def _purge_function() -> _Function:
    """The retention purge function."""
    function = _functions().get("purge_audit_events")
    if function is None:
        pytest.fail(f"no function purge_audit_events in {_MIGRATION_NAME}")
    return function


def _statements(body: str, keyword: str) -> list[str]:
    """Return every '<keyword> ... ;' statement of a PL/pgSQL body (literal-aware)."""
    masked = _masked(body)
    statements: list[str] = []
    for match in re.finditer(rf"\b{keyword}\b", masked):
        end = masked.find(";", match.start())
        statements.append(body[match.start() : end + 1 if end >= 0 else len(body)])
    return statements


# A RAISE whose message is a plain literal with, at most, an ERRCODE: no format
# arguments, no concatenation, no DETAIL/HINT that could carry row data or input.
_LITERAL_RAISE_RE = re.compile(
    r"raise\s+exception\s+'(?:[^']|'')*'(?:\s+using\s+errcode\s*=\s*'\w+')?\s*;"
)


def _audit_events_module() -> ModuleType:
    """Import admino.audit_events lazily, so only the sync tests need it."""
    import admino.audit_events as audit_events_mod

    return audit_events_mod


# ---------------------------------------------------------------------------
# Column specification: (column, type pattern, NOT NULL?, default pattern)
# NOT NULL: True = required, False = must be nullable, None = implied (primary key).
# ---------------------------------------------------------------------------

_COLUMNS: list[tuple[str, str, bool | None, str | None]] = [
    ("id", _UUID, None, _GEN_UUID),
    ("occurred_at", _TIMESTAMPTZ, True, _NOW),
    ("org_id", _UUID, False, None),
    ("actor_user_id", _UUID, False, None),
    ("actor_kind", _TEXT, True, None),
    ("action", _TEXT, True, None),
    ("target_type", _TEXT, False, None),
    ("target_ids", _JSONB, True, _EMPTY_ARRAY),
    ("ip", _INET, False, None),
    ("metadata", _JSONB, True, _EMPTY_OBJECT),
]

_TYPE_CASES = [
    pytest.param(column, type_pattern, id=column) for column, type_pattern, _, _ in _COLUMNS
]
_NULLABILITY_CASES = [
    pytest.param(column, not_null, id=column)
    for column, _, not_null, _ in _COLUMNS
    if not_null is not None
]
_DEFAULT_CASES = [
    pytest.param(column, default, id=column)
    for column, _, _, default in _COLUMNS
    if default is not None
]


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0005File:
    """The migration ships as version 5, is applied by run_migrations, and keeps data."""

    def test_migration_0005_file_is_shipped_as_version_5(self) -> None:
        """0005_audit_events.sql exists and matches the numbered-migration regex."""
        assert (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == 5

    async def test_migration_0005_run_migrations_applies_it_as_version_5(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0004 applied, run_migrations executes the file and records version 5."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in (1, 2, 3, 4)])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (5, _MIGRATION_NAME) in recorded
        assert all(version >= 5 for version, _ in recorded)

    async def test_migration_0005_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        """run_migrations executes the 0005 file's SQL text verbatim."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in (1, 2, 3, 4)])
        shipped = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0005_is_parameter_free(self) -> None:
        """No bind parameters or interpolation placeholders in the migration."""
        sql = _migration_sql()

        assert re.search(r"\$\d", sql) is None
        assert "%s" not in sql
        assert "%(" not in sql

    def test_migration_0005_drops_nothing(self) -> None:
        """No DROP TABLE, DROP COLUMN or DROP SCHEMA."""
        assert re.search(r"\bdrop\s+(?:table|column|schema)\b", _masked(_migration_sql())) is None

    def test_migration_0005_truncates_nothing(self) -> None:
        """No TRUNCATE statement (the only TRUNCATE is the trigger event it refuses)."""
        masked = _masked(_migration_sql())

        assert re.search(r"(?:^|;|\bbegin|\bthen|\belse|\bloop)\s*truncate\b", masked) is None

    def test_migration_0005_deletes_only_from_audit_events(self) -> None:
        """The only DELETE is the retention purge's, on audit_events."""
        masked = _masked(_migration_sql())
        targets = re.findall(r"\bdelete\s+from\s+(?:only\s+)?(\w+)", masked)

        assert set(targets) <= {_TABLE}

    def test_migration_0005_updates_no_rows(self) -> None:
        """No UPDATE ... SET statement."""
        masked = _masked(_migration_sql())

        assert re.search(r"\bupdate\s+(?:only\s+)?\w+\s+set\b", masked) is None

    def test_migration_0005_leaves_organizations_and_users_alone(self) -> None:
        """No ALTER TABLE of the 0004 tables."""
        masked = _masked(_migration_sql())

        assert re.search(r"\balter\s+table\s+(?:only\s+)?(?:organizations|users)\b", masked) is None

    def test_migration_0005_creates_the_table_before_its_triggers(self) -> None:
        """The triggers can only attach to an existing audit_events table."""
        sql = _migration_sql()
        table = re.search(rf"create\s+table\s+(?:if\s+not\s+exists\s+)?{_TABLE}\b", sql)
        trigger = re.search(r"create\s+(?:or\s+replace\s+)?trigger\b", sql)

        assert table is not None
        assert trigger is not None
        assert table.start() < trigger.start()


# ---------------------------------------------------------------------------
# 2. Column shapes (types, nullability, defaults, keys)
# ---------------------------------------------------------------------------


class TestMigration0005Columns:
    """Every column the issue lists, with its type, nullability and default: nothing else."""

    def test_migration_0005_defines_exactly_the_event_columns(self) -> None:
        """No free-text column (title, details, description, email...) can exist."""
        assert _column_names() == {column for column, _, _, _ in _COLUMNS}

    @pytest.mark.parametrize(("column", "type_pattern"), _TYPE_CASES)
    def test_migration_0005_column_has_expected_type(self, column: str, type_pattern: str) -> None:
        """The column exists with the specified SQL type."""
        definition = _column(column)

        assert re.match(rf"{column} {type_pattern}(?=\s|$)", definition), definition

    @pytest.mark.parametrize(("column", "not_null"), _NULLABILITY_CASES)
    def test_migration_0005_column_has_expected_nullability(
        self, column: str, not_null: bool
    ) -> None:
        """occurred_at, actor_kind, action, target_ids and metadata are NOT NULL; org_id
        (platform events), actor_user_id (system/operator), target_type and ip are nullable."""
        definition = _masked(_column(column))
        # "(?<!is )" skips "IS NOT NULL" inside an inline CHECK expression.
        declared_not_null = re.search(r"(?<!is )\bnot null\b", definition) is not None

        assert declared_not_null is not_null, definition

    @pytest.mark.parametrize(("column", "default"), _DEFAULT_CASES)
    def test_migration_0005_column_has_expected_default(self, column: str, default: str) -> None:
        """id, occurred_at, target_ids and metadata have database defaults (the app never
        sets id or occurred_at, so it can't backdate an event)."""
        assert re.search(rf"\bdefault\s+{default}", _column(column)), _column(column)

    def test_migration_0005_id_is_primary_key(self) -> None:
        """id UUID PRIMARY KEY DEFAULT gen_random_uuid()."""
        assert "primary key" in _column("id")

    def test_migration_0005_org_id_references_organizations(self) -> None:
        """org_id is a foreign key to organizations(id)."""
        inline = re.search(r"\breferences\s+organizations\b", _column("org_id"))
        table_level = re.search(
            r"foreign\s+key\s*\(\s*org_id\s*\)\s*references\s+organizations\b",
            _table_body(_migration_sql()),
        )

        assert inline is not None or table_level is not None

    def test_migration_0005_org_id_never_cascades(self) -> None:
        """No ON DELETE CASCADE / SET NULL / SET DEFAULT: deleting an org with audit rows
        fails, so an org purge removes them on purpose (a cascade would fight the trigger)."""
        body = _table_body(_migration_sql())

        assert re.search(r"\bon\s+delete\s+(?:cascade|set\s+null|set\s+default)\b", body) is None

    def test_migration_0005_org_id_delete_is_restricted(self) -> None:
        """The org_id foreign key is ON DELETE RESTRICT or NO ACTION (explicit or default)."""
        body = _table_body(_migration_sql())
        clauses = re.findall(r"\bon\s+delete\s+(\w+(?:\s+\w+)?)", body)

        assert all(clause in {"restrict", "no action"} for clause in clauses), clauses

    def test_migration_0005_actor_user_id_has_no_foreign_key(self) -> None:
        """actor_user_id references nothing: the audit history outlives deleted accounts."""
        body = _table_body(_migration_sql())

        assert "references" not in _column("actor_user_id")
        assert re.search(r"foreign\s+key\s*\(\s*actor_user_id\s*\)", body) is None


# ---------------------------------------------------------------------------
# 3. Value CHECK constraints (mirroring the Pydantic bounds)
# ---------------------------------------------------------------------------


class TestMigration0005ValueChecks:
    """Enumerations, target shapes and metadata shapes are enforced by CHECK constraints."""

    def test_migration_0005_actor_kind_check_lists_exact_values(self) -> None:
        """CHECK (actor_kind IN ('member', 'super_admin', 'system', 'operator'))."""
        assert _in_check_values("actor_kind") == {"member", "super_admin", "system", "operator"}

    def test_migration_0005_action_check_is_named_for_later_migrations(self) -> None:
        """The action catalog CHECK is CONSTRAINT audit_events_action_check, so a later
        migration can replace it when the catalog grows."""
        assert _in_values(_named_check("audit_events_action_check"), "action") is not None

    def test_migration_0005_action_check_lists_the_catalog(self) -> None:
        """The action CHECK allows exactly the catalog of the issue."""
        assert _in_values(_named_check("audit_events_action_check"), "action") == _SPEC_ACTIONS

    def test_migration_0005_target_type_check_lists_exact_values(self) -> None:
        """CHECK (target_type IN (...)) allows exactly the seven target kinds."""
        assert _in_check_values("target_type") == {
            "organization",
            "user",
            "invitation",
            "project",
            "chat",
            "file",
            "model",
        }

    def test_migration_0005_target_ids_is_a_json_array(self) -> None:
        """CHECK (jsonb_typeof(target_ids) = 'array')."""
        assert _any_check_matches(r"jsonb_typeof\s*\(\s*target_ids\s*\)\s*=\s*'array'")

    def test_migration_0005_target_ids_at_most_one_hundred(self) -> None:
        """CHECK (jsonb_array_length(target_ids) <= 100)."""
        assert _any_check_matches(
            r"jsonb_array_length\s*\(\s*target_ids\s*\)\s*"
            r"(?:<=\s*100\b|<\s*101\b|between\s+0\s+and\s+100\b)"
        )

    def test_migration_0005_target_ids_elements_must_be_strings(self) -> None:
        """A non-string element (a number, or an object like {"title": ...}) is refused, not
        skipped: jsonpath's like_regex on a non-string is 'unknown', so the check has to
        test the element type (or 'is unknown') explicitly."""
        uuid_checks = [
            check
            for check in _checks()
            if "target_ids" in check and ("like_regex" in check or "~" in check)
        ]

        assert uuid_checks, "no regex CHECK on target_ids"
        assert any('"string"' in check or "is unknown" in check for check in uuid_checks)

    @pytest.mark.parametrize("value", _SAMPLE_UUIDS)
    def test_migration_0005_target_ids_pattern_accepts_canonical_uuid(self, value: str) -> None:
        """The target_ids element regex accepts canonical lowercase UUID strings."""
        assert _allowed_by(_patterns_for("target_ids"), value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("Project Alpha", id="title"),
            pytest.param("project alpha", id="lowercase-title"),
            pytest.param("report.pdf", id="file-name"),
            pytest.param("alice@example.com", id="email"),
            pytest.param("", id="empty"),
            pytest.param("not-a-uuid", id="not-a-uuid"),
            pytest.param("3f2b8c1e5d4a4e7b9a6c0b1d2e3f4a5b", id="hex-without-dashes"),
            pytest.param("x3f2b8c1e-5d4a-4e7b-9a6c-0b1d2e3f4a5b", id="prefixed"),
            pytest.param("3f2b8c1e-5d4a-4e7b-9a6c-0b1d2e3f4a5b and more", id="suffixed"),
            pytest.param("Alice 3f2b8c1e-5d4a-4e7b-9a6c-0b1d2e3f4a5b", id="name-and-uuid"),
        ],
    )
    def test_migration_0005_target_ids_pattern_rejects_non_uuid(self, value: str) -> None:
        """The element regex is anchored and UUID-shaped: text around a UUID is refused."""
        assert not _allowed_by(_patterns_for("target_ids"), value)

    def test_migration_0005_metadata_is_a_json_object(self) -> None:
        """CHECK (jsonb_typeof(metadata) = 'object')."""
        assert _any_check_matches(r"jsonb_typeof\s*\(\s*metadata\s*\)\s*=\s*'object'")

    def test_migration_0005_metadata_is_flat(self) -> None:
        """No object or array values: a jsonpath type test on metadata's values, either
        refusing "object" and "array" or allowing only the scalar types."""
        scalar_types = ('"string"', '"number"', '"boolean"', '"null"')

        assert any(
            "metadata" in check
            and ".type()" in check
            and (
                ('"object"' in check and '"array"' in check)
                or all(kind in check for kind in scalar_types)
            )
            for check in _checks()
        )

    def test_migration_0005_metadata_size_is_bounded(self) -> None:
        """CHECK (pg_column_size(metadata) <= 4096) or an equivalent length bound."""
        assert _any_check_matches(
            r"(?:pg_column_size\s*\(\s*metadata\s*\)"
            r"|(?:octet_length|char_length|length)\s*\(\s*metadata\s*::\s*text\s*\))"
            r"\s*(?:<=\s*4096\b|<\s*4097\b)"
        )

    def test_migration_0005_metadata_key_count_is_bounded(self) -> None:
        """At most 16 keys, as AuditEvent allows: jsonb_array_length(jsonb_path_query_array(
        metadata, 'strict $.keyvalue()')) <= 16 (a CHECK can't hold a subquery)."""
        assert _metadata_key_cap() == 16

    @pytest.mark.parametrize(
        "value",
        ["editor", "org_admin", "allow", "google_calendar", "download", *_SAMPLE_UUIDS],
    )
    def test_migration_0005_metadata_pattern_accepts_tokens_and_uuids(self, value: str) -> None:
        """The metadata string regex accepts vocabulary tokens and canonical UUID strings."""
        assert _allowed_by(_patterns_for("metadata"), value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("quarterly report", id="free-text"),
            pytest.param("hello world", id="greeting"),
            pytest.param("alice@example.com", id="email"),
            pytest.param("report.pdf", id="file-name"),
            pytest.param("", id="empty"),
        ],
    )
    def test_migration_0005_metadata_pattern_rejects_text(self, value: str) -> None:
        """The metadata string regex refuses spaces, '@', '.', and the empty string."""
        assert not _allowed_by(_patterns_for("metadata"), value)


# ---------------------------------------------------------------------------
# 4. Consistency CHECK constraints (mirroring the AuditEvent validators)
# ---------------------------------------------------------------------------

_SYSTEM_OR_OPERATOR = (
    r"actor_kind\s+in\s*\(\s*(?:'system'\s*,\s*'operator'|'operator'\s*,\s*'system')\s*\)"
)
_MEMBER_OR_SUPER_ADMIN = (
    r"actor_kind\s+in\s*\(\s*(?:'member'\s*,\s*'super_admin'|'super_admin'\s*,\s*'member')\s*\)"
)
_TARGET_IDS_EMPTY = (
    r"(?:target_ids\s*=\s*'\[\]'(?:\s*::\s*jsonb)?"
    r"|jsonb_array_length\s*\(\s*target_ids\s*\)\s*=\s*0)"
)


class TestMigration0005ConsistencyChecks:
    """Row-level invariants: actor vs user id, member vs org, target type vs target ids."""

    def test_migration_0005_system_or_operator_iff_no_actor_user_id(self) -> None:
        """CHECK ((actor_kind IN ('system', 'operator')) = (actor_user_id IS NULL)), or the
        equivalent with member/super_admin and IS NOT NULL."""
        assert _any_check_matches(
            rf"\(\s*{_SYSTEM_OR_OPERATOR}\s*\)\s*=\s*\(\s*actor_user_id\s+is\s+null\s*\)",
            rf"\(\s*actor_user_id\s+is\s+null\s*\)\s*=\s*\(\s*{_SYSTEM_OR_OPERATOR}\s*\)",
            rf"\(\s*{_MEMBER_OR_SUPER_ADMIN}\s*\)\s*=\s*\(\s*actor_user_id\s+is\s+not\s+null\s*\)",
            rf"\(\s*actor_user_id\s+is\s+not\s+null\s*\)\s*=\s*\(\s*{_MEMBER_OR_SUPER_ADMIN}\s*\)",
        )

    def test_migration_0005_member_requires_org(self) -> None:
        """CHECK (actor_kind <> 'member' OR org_id IS NOT NULL)."""
        assert _any_check_matches(
            r"actor_kind\s*(?:<>|!=)\s*'member'\s+or\s+org_id\s+is\s+not\s+null",
            r"org_id\s+is\s+not\s+null\s+or\s+actor_kind\s*(?:<>|!=)\s*'member'",
        )

    def test_migration_0005_target_type_iff_target_ids(self) -> None:
        """CHECK ((target_type IS NULL) = (target_ids = '[]'::jsonb)), or the same with
        jsonb_array_length(target_ids) = 0."""
        assert _any_check_matches(
            rf"\(\s*target_type\s+is\s+null\s*\)\s*=\s*\(\s*{_TARGET_IDS_EMPTY}\s*\)",
            rf"\(\s*{_TARGET_IDS_EMPTY}\s*\)\s*=\s*\(\s*target_type\s+is\s+null\s*\)",
        )


# ---------------------------------------------------------------------------
# 5. Indexes
# ---------------------------------------------------------------------------


class TestMigration0005Indexes:
    """Per-org log listing and the retention purge are indexed."""

    def test_migration_0005_org_id_occurred_at_indexed(self) -> None:
        """CREATE INDEX ... ON audit_events (org_id, occurred_at) for an org's audit log."""
        assert re.search(
            r"create index (?:if not exists )?(?:\w+ )?on (?:only )?audit_events\s*"
            r"(?:using btree\s*)?\(\s*org_id\s*,\s*occurred_at(?:\s+(?:asc|desc))?\s*\)",
            _migration_sql(),
        )

    def test_migration_0005_occurred_at_indexed(self) -> None:
        """CREATE INDEX ... ON audit_events (occurred_at) for the retention purge and the
        platform log."""
        assert re.search(
            r"create index (?:if not exists )?(?:\w+ )?on (?:only )?audit_events\s*"
            r"(?:using btree\s*)?\(\s*occurred_at(?:\s+(?:asc|desc))?\s*\)",
            _migration_sql(),
        )


# ---------------------------------------------------------------------------
# 6. Append-only trigger
# ---------------------------------------------------------------------------

_SIX_MONTH_FLOOR_RE = re.compile(
    rf"old\.occurred_at\s*<\s*{_NOW_EXPR}\s*-\s*"
    rf"(?:interval\s*'(\d+)\s*{_MONTHS_UNIT}'"
    rf"|'(\d+)\s*{_MONTHS_UNIT}'\s*::\s*interval"
    rf"|make_interval\s*\(\s*months\s*=>\s*(\d+)\s*\))"
)


def _floor_months() -> int:
    """Return the month floor the trigger compares old.occurred_at against."""
    match = _SIX_MONTH_FLOOR_RE.search(_append_only_function().body)
    if match is None:
        pytest.fail("the trigger doesn't compare old.occurred_at with now() - <months>")
    return int(next(group for group in match.groups() if group is not None))


class TestMigration0005AppendOnlyTrigger:
    """audit_events is append-only: no UPDATE, no TRUNCATE, and DELETE only from the purge.

    The trigger is the database's last line of defense: even a buggy or injected
    statement can't rewrite or erase the audit history. The only way rows leave
    is purge_audit_events(integer), and only once they are past the 6-month floor.
    """

    def test_migration_0005_trigger_function_is_plpgsql_returning_trigger(self) -> None:
        """A plpgsql function returning trigger that reads pg_context."""
        function = _append_only_function()

        assert function.returns == "trigger"
        assert "language plpgsql" in function.options

    def test_migration_0005_trigger_function_raises(self) -> None:
        """The function refuses with RAISE EXCEPTION."""
        assert re.search(r"\braise\s+exception\b", _masked(_append_only_function().body))

    def test_migration_0005_update_is_never_let_through(self) -> None:
        """No path returns NEW, so no UPDATE ever proceeds."""
        assert re.search(r"\breturn\s+new\b", _masked(_append_only_function().body)) is None

    def test_migration_0005_only_delete_can_be_let_through(self) -> None:
        """The function distinguishes DELETE by TG_OP; any other operation is refused."""
        body = _append_only_function().body

        assert re.search(r"\btg_op\s*(?:=|<>|!=)\s*'delete'", body)

    def test_migration_0005_delete_reads_the_call_stack(self) -> None:
        """GET DIAGNOSTICS <var> = PG_CONTEXT, and the variable is used afterwards."""
        body = _append_only_function().body
        match = re.search(r"get\s+diagnostics\s+(\w+)\s*(?::=|=)\s*pg_context", body)

        assert match is not None
        assert re.search(rf"\b{match.group(1)}\b", body[match.end() :])

    def test_migration_0005_delete_allowed_only_from_the_purge_function(self) -> None:
        """The call stack must show 'function purge_audit_events(integer)' (the PL/pgSQL
        context line), so a lookalike name like x_purge_audit_events doesn't qualify."""
        assert re.search(r"function purge_audit_events\(integer\)", _append_only_function().body)

    def test_migration_0005_delete_allowed_only_past_the_six_month_floor(self) -> None:
        """Even the purge can't delete a row younger than 6 months:
        old.occurred_at < now() - interval '6 months'."""
        assert _floor_months() == 6

    def test_migration_0005_trigger_errors_carry_no_row_data(self) -> None:
        """Every RAISE is a plain literal (with at most an ERRCODE): no OLD/NEW values, no
        format arguments, no DETAIL or HINT."""
        raises = _statements(_append_only_function().body, "raise")

        assert raises
        assert all(_LITERAL_RAISE_RE.fullmatch(statement) for statement in raises), raises

    def test_migration_0005_trigger_runs_before_every_update_and_delete(self) -> None:
        """BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW, with no column list."""
        name = _append_only_function().name

        assert re.search(
            r"create\s+(?:or\s+replace\s+)?trigger\s+\w+\s+before\s+"
            r"(?:update\s+or\s+delete|delete\s+or\s+update)\s+on\s+(?:only\s+)?audit_events\s+"
            rf"for\s+each\s+row\s+execute\s+(?:function|procedure)\s+{name}\s*\(\s*\)",
            _migration_sql(),
        )

    def test_migration_0005_truncate_is_refused(self) -> None:
        """A BEFORE TRUNCATE statement trigger calls a function that always raises."""
        match = re.search(
            r"create\s+(?:or\s+replace\s+)?trigger\s+\w+\s+before\s+truncate\s+on\s+"
            r"(?:only\s+)?audit_events\s+(?:for\s+each\s+statement\s+)?"
            r"execute\s+(?:function|procedure)\s+(\w+)\s*\(\s*\)",
            _migration_sql(),
        )
        assert match is not None
        function = _functions()[match.group(1)]
        body = _masked(function.body)

        assert re.search(r"\braise\s+exception\b", body)
        assert re.search(r"\breturn\s+new\b", body) is None
        if function.name != _append_only_function().name:
            assert re.search(r"\bif\b", body) is None, "the TRUNCATE refusal is unconditional"


# ---------------------------------------------------------------------------
# 7. Retention purge function
# ---------------------------------------------------------------------------

_RANGE_CHECK_RES: tuple[str, ...] = (
    r"retention_months\s+not\s+between\s+(\d+)\s+and\s+(\d+)",
    r"retention_months\s*<\s*(\d+)\s+or\s+retention_months\s*>\s*(\d+)",
    r"not\s*\(\s*retention_months\s+between\s+(\d+)\s+and\s+(\d+)\s*\)",
)


def _purge_bounds() -> tuple[int, int, int]:
    """Return (low, high, position) of the purge function's retention range check."""
    body = _purge_function().body
    for pattern in _RANGE_CHECK_RES:
        match = re.search(pattern, body)
        if match is not None:
            return int(match.group(1)), int(match.group(2)), match.start()
    pytest.fail("purge_audit_events doesn't check retention_months against a range")


class TestMigration0005PurgeFunction:
    """purge_audit_events(retention_months integer) deletes rows past the retention."""

    def test_migration_0005_purge_function_signature(self) -> None:
        """purge_audit_events(retention_months integer) RETURNS bigint LANGUAGE plpgsql."""
        function = _purge_function()

        assert re.fullmatch(
            r"(?:in\s+)?retention_months\s+(?:integer|int4|int)", function.arguments
        )
        assert function.returns in {"bigint", "int8"}
        assert "language plpgsql" in function.options

    def test_migration_0005_purge_refuses_retention_outside_bounds(self) -> None:
        """The function raises unless the retention is between 6 and 84 months."""
        low, high, _ = _purge_bounds()

        assert (low, high) == (6, 84)
        assert re.search(r"\braise\s+exception\b", _masked(_purge_function().body))

    def test_migration_0005_purge_checks_bounds_before_deleting(self) -> None:
        """The range check comes before the DELETE."""
        _, _, check_position = _purge_bounds()
        delete = re.search(r"\bdelete\s+from\b", _purge_function().body)

        assert delete is not None
        assert check_position < delete.start()

    def test_migration_0005_purge_deletes_rows_older_than_retention(self) -> None:
        """DELETE FROM audit_events WHERE occurred_at < now() - make_interval(months =>
        retention_months), or an equivalent month interval."""
        assert re.search(
            rf"\bdelete\s+from\s+(?:only\s+)?audit_events\s+where\s+occurred_at\s*<\s*"
            rf"{_NOW_EXPR}\s*-\s*"
            rf"(?:make_interval\s*\(\s*months\s*=>\s*retention_months\s*\)"
            rf"|retention_months\s*\*\s*interval\s*'1\s*{_MONTHS_UNIT}'"
            rf"|interval\s*'1\s*{_MONTHS_UNIT}'\s*\*\s*retention_months)",
            _purge_function().body,
        )

    def test_migration_0005_purge_returns_the_row_count(self) -> None:
        """GET DIAGNOSTICS <var> = ROW_COUNT; RETURN <var>."""
        body = _purge_function().body
        match = re.search(r"get\s+diagnostics\s+(\w+)\s*(?::=|=)\s*row_count", body)

        assert match is not None
        assert re.search(rf"\breturn\s+{match.group(1)}\s*;", body[match.end() :])

    def test_migration_0005_purge_uses_no_dynamic_sql(self) -> None:
        """No EXECUTE: the DELETE is static SQL with the months as a typed argument."""
        assert re.search(r"\bexecute\b", _masked(_purge_function().body)) is None

    def test_migration_0005_purge_errors_echo_no_input(self) -> None:
        """Every RAISE is a plain literal: the rejected retention isn't echoed."""
        raises = _statements(_purge_function().body, "raise")

        assert raises
        assert all(_LITERAL_RAISE_RE.fullmatch(statement) for statement in raises), raises


# ---------------------------------------------------------------------------
# 8. Python and SQL stay in sync
# ---------------------------------------------------------------------------


class TestMigration0005PythonSync:
    """The CHECKs and functions mirror admino.audit_events."""

    def test_migration_0005_action_check_is_still_in_audit_action(self) -> None:
        """Every action 0005 allows is still an AuditAction (none was dropped).

        A shipped migration never changes, so 0005's list stays the original 39
        (test_migration_0005_action_check_lists_the_catalog pins it). The catalog
        grows by replacing the audit_events_action_check constraint in a later
        migration (0009 for GH-152's session.revoke and session.force_logout), so
        the exact sync with the live AuditAction lives in that migration's tests
        (tests/test_migration_0009.py).
        """
        audit_events = _audit_events_module()
        sql_actions = _in_values(_named_check("audit_events_action_check"), "action")

        assert sql_actions is not None
        assert sql_actions <= {action.value for action in audit_events.AuditAction}

    def test_migration_0005_actor_kind_check_matches_actor_kind(self) -> None:
        """The SQL actor kinds equal the ActorKind Literal."""
        audit_events = _audit_events_module()

        assert _in_check_values("actor_kind") == set(get_args(audit_events.ActorKind))

    def test_migration_0005_target_type_check_matches_target_type(self) -> None:
        """The SQL target types equal TargetType's values."""
        audit_events = _audit_events_module()

        assert _in_check_values("target_type") == {t.value for t in audit_events.TargetType}

    def test_migration_0005_purge_bounds_match_retention_constants(self) -> None:
        """The purge function's bounds are MIN_RETENTION_MONTHS and MAX_RETENTION_MONTHS."""
        audit_events = _audit_events_module()
        low, high, _ = _purge_bounds()

        assert (low, high) == (audit_events.MIN_RETENTION_MONTHS, audit_events.MAX_RETENTION_MONTHS)

    def test_migration_0005_trigger_floor_matches_min_retention(self) -> None:
        """The trigger's floor is MIN_RETENTION_MONTHS."""
        audit_events = _audit_events_module()

        assert _floor_months() == audit_events.MIN_RETENTION_MONTHS

    def test_migration_0005_metadata_key_cap_matches_the_validator(self) -> None:
        """The database's metadata key cap is the validator's (audit_events._MAX_METADATA_KEYS)."""
        audit_events = _audit_events_module()

        assert _metadata_key_cap() == audit_events._MAX_METADATA_KEYS

    def test_migration_0005_metadata_pattern_accepts_every_vocabulary_token(self) -> None:
        """Every string the Python validator accepts passes the database's metadata regex."""
        audit_events = _audit_events_module()
        patterns = _patterns_for("metadata")
        refused = sorted(
            t for t in audit_events.METADATA_VOCABULARY if not _allowed_by(patterns, t)
        )

        assert refused == []

    def test_migration_0005_purge_function_is_what_purge_expired_calls(self) -> None:
        """purge_expired calls purge_audit_events, which the migration defines with an
        integer argument (the signature the trigger's call-stack check names)."""
        audit_events = _audit_events_module()
        source = re.sub(r"\s+", " ", _read_source(audit_events)).lower()

        assert "purge_audit_events(" in source
        assert _purge_function().name == "purge_audit_events"


def _read_source(module: ModuleType) -> str:
    """Return a module's source text."""
    path = module.__file__
    assert path is not None
    return Path(path).read_text(encoding="utf-8")
