"""Tests for migration 0012_login_throttle.sql — the login throttle counters (GH-157).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0010.py pattern): it must exist, be applied by
run_migrations as version 12, and make exactly the schema change GH-157 needs.
The SQL is read with comments stripped, whitespace collapsed and lowercased,
then matched with formatting-tolerant regexes; parsing is quote-aware, and a
constraint may be written inline on its column or as a table constraint.

What these tests pin down:
- ``CREATE TABLE login_throttle`` with exactly these columns and no defaults
  (the app sets every value): ``scope TEXT NOT NULL CHECK (scope IN
  ('account', 'ip'))``; ``subject BYTEA NOT NULL CHECK (octet_length(subject)
  = 32)``; ``failures INTEGER NOT NULL CHECK (failures >= 0)``;
  ``window_started_at TIMESTAMPTZ NOT NULL``; ``locked_until TIMESTAMPTZ``
  (nullable); ``expires_at TIMESTAMPTZ NOT NULL``. ``PRIMARY KEY (scope,
  subject)``, ``CHECK (expires_at > window_started_at)`` and ``CHECK
  (locked_until IS NULL OR expires_at >= locked_until)``.
- ``CREATE INDEX ... ON login_throttle (expires_at)`` for the purge.
- No column for an email, an IP address or any text beyond ``scope``.
- Nothing else changes: no other table, no ALTER (the audit catalog already
  holds ``login.lockout``), no DML, function, trigger, view or type.

Security notes:
- Only digests are stored (a 32-byte subject); no email and no IP text.
- ``expires_at >= locked_until`` means a purge by ``expires_at`` can never
  remove a live lock.
- The migration is parameter-free.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0012_login_throttle.sql"
_COLUMNS = frozenset(
    {"scope", "subject", "failures", "window_started_at", "locked_until", "expires_at"}
)
_TIMESTAMPTZ = r"(?:timestamptz|timestamp\s*(?:\(\s*\d\s*\)\s*)?with\s+time\s+zone)"
_CONSTRAINT_START = (
    r"(?:constraint\s+\w+\s+)?(?:check|unique|primary\s+key|foreign\s+key|exclude)\b"
)


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _migration_sql() -> str:
    """The shipped migration, comments stripped, whitespace collapsed, lowercased."""
    raw = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")
    without_comments = re.sub(r"--.*", " ", raw)
    return re.sub(r"\s+", " ", without_comments).strip().lower()


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


def _balanced_end(masked: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(masked)):
        if masked[index] == "(":
            depth += 1
        elif masked[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    pytest.fail(f"unbalanced parentheses in {_MIGRATION_NAME}")


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


def _create_table_body() -> str:
    for statement in _statements():
        masked = _masked(statement)
        match = re.match(r"create\s+table\s+(?:if\s+not\s+exists\s+)?login_throttle\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        assert masked[end + 1 :].strip() == "", statement
        return statement[match.end() : end]
    pytest.fail("no CREATE TABLE login_throttle (...)")


def _elements() -> list[str]:
    return _split(_create_table_body(), ",")


def _column_definitions() -> dict[str, str]:
    columns: dict[str, str] = {}
    for element in _elements():
        if re.match(_CONSTRAINT_START, element):
            continue
        match = re.fullmatch(r'"?(\w+)"?\s+(.*)', element)
        assert match is not None, element
        columns[match.group(1)] = match.group(2)
    return columns


def _column(name: str) -> str:
    columns = _column_definitions()
    assert name in columns, f"no column {name} in CREATE TABLE login_throttle"
    return columns[name]


def _table_constraints() -> list[str]:
    return [element for element in _elements() if re.match(_CONSTRAINT_START, element)]


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    while (
        expression.startswith("(") and _balanced_end(_masked(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _check_expressions() -> list[str]:
    """Every CHECK (...) expression of the table (inline or table-level), unwrapped."""
    expressions: list[str] = []
    for element in _elements():
        masked = _masked(element)
        for match in re.finditer(r"\bcheck\s*\(", masked):
            end = _balanced_end(masked, match.end() - 1)
            expressions.append(_unwrap(element[match.end() : end]))
    return expressions


def _check_atoms() -> list[str]:
    """Every AND-ed condition of every CHECK, parentheses around each dropped."""
    atoms: list[str] = []
    for expression in _check_expressions():
        masked = _masked(expression)
        start = 0
        depth = 0
        for match in re.finditer(r"\(|\)|\band\b", masked):
            token = match.group(0)
            if token == "(":
                depth += 1
            elif token == ")":
                depth -= 1
            elif depth == 0:
                atoms.append(_unwrap(expression[start : match.start()]))
                start = match.end()
        atoms.append(_unwrap(expression[start:]))
    return atoms


def _any_atom(*patterns: str) -> bool:
    return any(re.fullmatch(pattern, atom) for atom in _check_atoms() for pattern in patterns)


def _in_values(column: str) -> set[str] | None:
    """The literals of '<column> IN (...)' when a CHECK atom is exactly that."""
    for atom in _check_atoms():
        match = re.fullmatch(rf"{column}\s+in\s*\(([^)]*)\)", atom)
        if match is not None:
            return set(re.findall(r"'([^']*)'", match.group(1)))
    return None


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0012File:
    """The migration ships as version 12 and is applied by run_migrations."""

    def test_migration_0012_file_is_shipped_as_version_12(self) -> None:
        assert (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == 12

    def test_migration_0012_is_the_only_version_12(self) -> None:
        twelves = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == 12
        ]

        assert twelves == [_MIGRATION_NAME]

    async def test_migration_0012_run_migrations_applies_it_as_version_12(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0011 applied, run_migrations executes the file and records 12."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, 12)])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (12, _MIGRATION_NAME) in recorded
        assert all(version >= 12 for version, _ in recorded)

    async def test_migration_0012_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, 12)])
        shipped = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0012_is_parameter_free(self) -> None:
        sql = _migration_sql()

        assert re.search(r"\$\d", sql) is None
        assert "%s" not in sql
        assert "%(" not in sql


# ---------------------------------------------------------------------------
# 2. The login_throttle table
# ---------------------------------------------------------------------------


class TestMigration0012Table:
    """CREATE TABLE login_throttle: the columns, their types and keys."""

    def test_migration_0012_creates_the_table_once(self) -> None:
        creates = [s for s in _statements() if re.match(r"create\s+table\b", _masked(s))]

        assert len(creates) == 1
        _create_table_body()

    def test_migration_0012_has_exactly_the_listed_columns(self) -> None:
        """No column for an email, an IP address or any other content."""
        assert set(_column_definitions()) == _COLUMNS

    def test_migration_0012_no_column_has_a_default(self) -> None:
        """The app sets every value (its own clock and counts)."""
        for name, definition in _column_definitions().items():
            assert re.search(r"\bdefault\b", _masked(definition)) is None, name

    def test_migration_0012_scope_is_required_text(self) -> None:
        definition = _masked(_column("scope"))

        assert re.match(r"text\b", definition), definition
        assert re.search(r"\bnot\s+null\b", definition), definition

    def test_migration_0012_scope_is_account_or_ip(self) -> None:
        assert _in_values("scope") == {"account", "ip"}, _check_expressions()

    def test_migration_0012_only_scope_is_text(self) -> None:
        """No other text, varchar, inet or cidr column (no email, no IP text)."""
        for name, definition in _column_definitions().items():
            if name == "scope":
                continue
            assert (
                re.match(r"(?:text|varchar|character|char|inet|cidr|citext)\b", definition) is None
            ), name

    def test_migration_0012_subject_is_a_required_bytea(self) -> None:
        definition = _masked(_column("subject"))

        assert re.match(r"bytea\b", definition), definition
        assert re.search(r"\bnot\s+null\b", definition), definition

    def test_migration_0012_subject_is_exactly_32_bytes(self) -> None:
        assert _any_atom(
            r"octet_length\s*\(\s*subject\s*\)\s*=\s*32",
            r"32\s*=\s*octet_length\s*\(\s*subject\s*\)",
        ), _check_expressions()

    def test_migration_0012_failures_is_a_required_integer(self) -> None:
        definition = _masked(_column("failures"))

        assert re.match(r"(?:integer|int|int4)\b", definition), definition
        assert re.search(r"\bnot\s+null\b", definition), definition

    def test_migration_0012_failures_is_never_negative(self) -> None:
        assert _any_atom(r"failures\s*>=\s*0", r"0\s*<=\s*failures"), _check_expressions()

    @pytest.mark.parametrize("column", ["window_started_at", "expires_at"])
    def test_migration_0012_required_timestamps(self, column: str) -> None:
        definition = _masked(_column(column))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert re.search(r"\bnot\s+null\b", definition), definition

    def test_migration_0012_locked_until_is_a_nullable_timestamp(self) -> None:
        definition = _masked(_column("locked_until"))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert re.search(r"\bnot\s+null\b", definition) is None

    def test_migration_0012_primary_key_is_scope_and_subject(self) -> None:
        keys = [
            match.group(1)
            for constraint in _table_constraints()
            if (
                match := re.fullmatch(
                    r"(?:constraint\s+\w+\s+)?primary\s+key\s*\(\s*(\w+\s*,\s*\w+)\s*\)",
                    constraint,
                )
            )
        ]

        assert len(keys) == 1
        assert {column.strip() for column in keys[0].split(",")} == {"scope", "subject"}
        for name, definition in _column_definitions().items():
            assert re.search(r"\b(?:primary\s+key|unique)\b", _masked(definition)) is None, name

    def test_migration_0012_expires_after_the_window_start(self) -> None:
        assert _any_atom(
            r"expires_at\s*>\s*window_started_at",
            r"window_started_at\s*<\s*expires_at",
        ), _check_expressions()

    def test_migration_0012_expiry_never_ends_before_the_lock(self) -> None:
        """So a purge by expires_at can never remove a live lock."""
        later = r"(?:expires_at\s*>=\s*locked_until|locked_until\s*<=\s*expires_at)"
        null = r"locked_until\s+is\s+null"
        assert _any_atom(
            rf"{null}\s+or\s+\(?\s*{later}\s*\)?",
            rf"\(?\s*{later}\s*\)?\s+or\s+{null}",
        ), _check_expressions()

    def test_migration_0012_has_no_foreign_key(self) -> None:
        """The subject is a digest, not a reference: an unknown email counts too."""
        assert re.search(r"\breferences\b", _masked(_create_table_body())) is None


# ---------------------------------------------------------------------------
# 3. The purge index, and nothing else
# ---------------------------------------------------------------------------


class TestMigration0012NothingElse:
    """One table and its expires_at index; no other change."""

    def test_migration_0012_indexes_expires_at_for_the_purge(self) -> None:
        indexes = [
            statement
            for statement in _statements()
            if re.match(r"create\s+(?:unique\s+)?index\b", _masked(statement))
        ]

        assert len(indexes) == 1
        assert re.fullmatch(
            r"create\s+index\s+(?:if\s+not\s+exists\s+)?\w+\s+on\s+(?:only\s+)?login_throttle"
            r"\s*(?:using\s+btree\s*)?\(\s*expires_at\s*\)",
            indexes[0],
        ), indexes[0]

    def test_migration_0012_has_exactly_two_statements(self) -> None:
        assert len(_statements()) == 2

    def test_migration_0012_alters_and_drops_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\balter\s+table\b", masked) is None
        assert re.search(r"\bdrop\b", masked) is None

    def test_migration_0012_writes_no_data(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\bupdate\s+(?:only\s+)?\w+\s+set\b", masked) is None
        assert re.search(r"\binsert\s+into\b", masked) is None
        assert re.search(r"\bdelete\s+from\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None

    def test_migration_0012_defines_no_function_trigger_or_view(self) -> None:
        masked = _masked(_migration_sql())

        assert (
            re.search(
                r"\b(?:create|drop|alter)\s+(?:or\s+replace\s+)?(?:function|trigger|view|type)\b",
                masked,
            )
            is None
        )
        assert re.search(r"\bdo\s+\$", masked) is None

    def test_migration_0012_audit_catalog_already_holds_the_lockout(self) -> None:
        """login.lockout was in the catalog before: no audit_events change is needed."""
        from admino.audit_events import AuditAction

        assert AuditAction.LOGIN_LOCKOUT.value == "login.lockout"
        assert "audit_events" not in _migration_sql()
