"""Tests for migration 0006_email_outbox.sql — the transactional email outbox (GH-148).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0005.py pattern): it must exist, be applied by
run_migrations as version 6, and declare the email_outbox table with its
columns, CHECK constraints and indexes. The SQL is read with comments
stripped, whitespace collapsed and lowercased, then matched with
formatting-tolerant regexes; parsing is quote-aware.

What these tests pin down:
- Exactly the outbox columns: id, recipient_user_id (FK to users, ON DELETE
  CASCADE), recipient_address, template_key, language, params, status,
  attempts, next_attempt_at, created_at and finished_at. No subject, body,
  error text or other content column.
- CHECKs that mirror the Python bounds: the address format mirrors
  users_email_format_check, template_key is the EmailTemplate catalog,
  language is EmailLanguage, status is OutboxStatus, attempts is non-negative
  (any upper bound leaves room for MAX_ATTEMPTS), params is a JSON object.
- Row invariants: a row is pending exactly when finished_at is NULL, and only
  a pending row may keep params (sent/failed rows are scrubbed to '{}').
- Indexes for the sender's due scan (partial, pending only), the retention
  purge (finished_at) and the users FK cascade (recipient_user_id).
- The migration is parameter-free and changes no existing table or data.

Security notes:
- One-time links don't outlive delivery: the database refuses a sent or
  failed row that still holds params.
- A user purge cascades to their queued mail, so no address outlives the
  account.
- No free-text column exists where SMTP error text (which echoes addresses)
  could be stored.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, get_args
from unittest.mock import AsyncMock, MagicMock

import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from types import ModuleType

_MIGRATION_NAME = "0006_email_outbox.sql"
_TABLE = "email_outbox"

# Formatting-tolerant type patterns.
_UUID = r"uuid"
_TEXT = r"text"
_JSONB = r"jsonb"
_INTEGER = r"(?:integer|int4|int)"
_TIMESTAMPTZ = r"(?:timestamptz|timestamp with time zone)"

# Formatting-tolerant default patterns.
_GEN_UUID = r"gen_random_uuid\s*\(\s*\)"
_NOW = r"(?:now\s*\(\s*\)|current_timestamp)"
_EMPTY_OBJECT = r"'\{\}'(?:\s*::\s*jsonb)?"
_PENDING = r"'pending'(?:\s*::\s*text)?"
_ZERO = r"0"

_SPEC_TEMPLATE_KEYS: frozenset[str] = frozenset(
    {
        "invitation",
        "password_reset",
        "account_activated",
        "account_deactivated",
        "budget_alert",
        "model_deprecation",
        "org_deletion_scheduled",
    }
)


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _cased_sql() -> str:
    """Return the shipped 0006 migration, comments stripped, whitespace collapsed, case kept."""
    raw = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")
    without_comments = re.sub(r"--.*", " ", raw)
    return re.sub(r"\s+", " ", without_comments).strip()


def _migration_sql() -> str:
    """Return the shipped 0006 migration, comments stripped, whitespace collapsed, lowercased."""
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
    """Return the text between the parentheses of CREATE TABLE email_outbox ( ... )."""
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
    """Top-level items (column definitions and table constraints) of email_outbox, lowercased."""
    return _split_top_level(_table_body(_migration_sql()))


_CONSTRAINT_WORDS = frozenset({"constraint", "check", "primary", "foreign", "unique", "exclude"})


def _column_names() -> set[str]:
    """Names of the columns email_outbox defines."""
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


def _checks() -> list[str]:
    """Every CHECK (...) expression of the email_outbox table body, lowercased."""
    body = _table_body(_migration_sql())
    masked = _masked(body)
    expressions: list[str] = []
    for match in re.finditer(r"\bcheck\s*\(", masked):
        end = _balanced_end(masked, match.end() - 1)
        expressions.append(body[match.end() : end].strip())
    return expressions


def _any_check_matches(*patterns: str) -> bool:
    """True when some CHECK expression of email_outbox matches one of the patterns."""
    return any(re.search(pattern, check) for check in _checks() for pattern in patterns)


def _in_values(expression: str, column: str) -> set[str] | None:
    """Return the literals of '<column> IN (...)' when that is the whole expression."""
    match = re.fullmatch(rf"\s*\(?\s*{column}\s+in\s*\(([^)]*)\)\s*\)?\s*", expression)
    if match is None:
        return None
    return set(re.findall(r"'([^']*)'", match.group(1)))


def _in_check_values(column: str) -> set[str]:
    """Return the literal set of a CHECK (<column> IN ('a', 'b', ...)) on email_outbox."""
    for check in _checks():
        values = _in_values(check, column)
        if values is not None:
            return values
    pytest.fail(f"no CHECK ({column} IN (...)) on {_TABLE}")


def _statements() -> list[str]:
    """The migration's statements (split at semicolons outside literals), lowercased."""
    sql = _migration_sql()
    masked = _masked(sql)
    statements: list[str] = []
    start = 0
    for index, char in enumerate(masked):
        if char == ";":
            statements.append(sql[start:index].strip())
            start = index + 1
    statements.append(sql[start:].strip())
    return [statement for statement in statements if statement]


def _index_statements() -> list[str]:
    """Every CREATE INDEX ... ON email_outbox statement."""
    return [
        statement
        for statement in _statements()
        if re.match(
            rf"create\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?"
            rf"(?:\w+\s+)?on\s+(?:only\s+)?{_TABLE}\b",
            statement,
        )
    ]


def _index_columns(statement: str) -> str:
    """The column list of a CREATE INDEX statement."""
    match = re.search(rf"\bon\s+(?:only\s+)?{_TABLE}\s*(?:using\s+\w+\s*)?\(", statement)
    assert match is not None, statement
    end = _balanced_end(_masked(statement), match.end() - 1)
    return statement[match.end() : end]


def _index_predicate(statement: str) -> str:
    """The WHERE predicate of a partial index ('' when there is none)."""
    match = re.search(r"\bwhere\b(.*)$", statement)
    return match.group(1).strip() if match else ""


def _attempts_upper_bound() -> int | None:
    """The largest attempts value a CHECK allows, or None when there is no upper bound."""
    for check in _checks():
        between = re.search(r"\battempts\s+between\s+\d+\s+and\s+(\d+)", check)
        if between:
            return int(between.group(1))
        at_most = re.search(r"\battempts\s*<=\s*(\d+)", check)
        if at_most:
            return int(at_most.group(1))
        below = re.search(r"\battempts\s*<\s*(\d+)", check)
        if below:
            return int(below.group(1)) - 1
    return None


def _email_outbox_module() -> ModuleType:
    """Import admino.email_outbox lazily, so only the sync tests need it."""
    import admino.email_outbox as email_outbox_mod

    return email_outbox_mod


def _email_templates_module() -> ModuleType:
    """Import admino.email_templates lazily, so only the sync tests need it."""
    import admino.email_templates as email_templates_mod

    return email_templates_mod


# ---------------------------------------------------------------------------
# Column specification: (column, type pattern, NOT NULL?, default pattern)
# NOT NULL: True = required, False = must be nullable, None = implied (primary key).
# ---------------------------------------------------------------------------

_COLUMNS: list[tuple[str, str, bool | None, str | None]] = [
    ("id", _UUID, None, _GEN_UUID),
    ("recipient_user_id", _UUID, True, None),
    ("recipient_address", _TEXT, True, None),
    ("template_key", _TEXT, True, None),
    ("language", _TEXT, True, None),
    ("params", _JSONB, True, _EMPTY_OBJECT),
    ("status", _TEXT, True, _PENDING),
    ("attempts", _INTEGER, True, _ZERO),
    ("next_attempt_at", _TIMESTAMPTZ, True, _NOW),
    ("created_at", _TIMESTAMPTZ, True, _NOW),
    ("finished_at", _TIMESTAMPTZ, False, None),
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


class TestMigration0006File:
    """The migration ships as version 6, is applied by run_migrations, and keeps data."""

    def test_migration_0006_file_is_shipped_as_version_6(self) -> None:
        """0006_email_outbox.sql exists and matches the numbered-migration regex."""
        assert (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == 6

    def test_migration_0006_is_the_only_version_6(self) -> None:
        """No other migration file claims version 6."""
        sixes = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == 6
        ]

        assert sixes == [_MIGRATION_NAME]

    async def test_migration_0006_run_migrations_applies_it_as_version_6(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0005 applied, run_migrations executes the file and records version 6."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in (1, 2, 3, 4, 5)])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (6, _MIGRATION_NAME) in recorded
        assert all(version >= 6 for version, _ in recorded)

    async def test_migration_0006_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        """run_migrations executes the 0006 file's SQL text verbatim."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in (1, 2, 3, 4, 5)])
        shipped = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0006_is_parameter_free(self) -> None:
        """No bind parameters or interpolation placeholders in the migration."""
        sql = _migration_sql()

        assert re.search(r"\$\d", sql) is None
        assert "%s" not in sql
        assert "%(" not in sql

    def test_migration_0006_drops_nothing(self) -> None:
        """No DROP of any table, column, schema, index, type or function."""
        masked = _masked(_migration_sql())

        assert (
            re.search(r"\bdrop\s+(?:table|column|schema|index|type|function|trigger)\b", masked)
            is None
        )

    def test_migration_0006_alters_no_existing_table(self) -> None:
        """No ALTER TABLE of anything but email_outbox itself."""
        masked = _masked(_migration_sql())
        targets = re.findall(r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", masked)

        assert set(targets) <= {_TABLE}

    def test_migration_0006_changes_no_rows(self) -> None:
        """No INSERT, UPDATE, DELETE or TRUNCATE: the migration only creates."""
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\s+into\b", masked) is None
        assert re.search(r"\bupdate\s+(?:only\s+)?\w+\s+set\b", masked) is None
        assert re.search(r"\bdelete\s+from\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None


# ---------------------------------------------------------------------------
# 2. Column shapes (types, nullability, defaults, keys)
# ---------------------------------------------------------------------------


class TestMigration0006Columns:
    """Every column the issue lists, with its type, nullability and default: nothing else."""

    def test_migration_0006_defines_exactly_the_outbox_columns(self) -> None:
        """No subject, body, error text or any other content column can exist."""
        assert _column_names() == {column for column, _, _, _ in _COLUMNS}

    @pytest.mark.parametrize(("column", "type_pattern"), _TYPE_CASES)
    def test_migration_0006_column_has_expected_type(self, column: str, type_pattern: str) -> None:
        """The column exists with the specified SQL type."""
        definition = _column(column)

        assert re.match(rf"{column} {type_pattern}(?=\s|$)", definition), definition

    @pytest.mark.parametrize(("column", "not_null"), _NULLABILITY_CASES)
    def test_migration_0006_column_has_expected_nullability(
        self, column: str, not_null: bool
    ) -> None:
        """Every column but finished_at is NOT NULL; finished_at stays NULL while pending."""
        definition = _masked(_column(column))
        # "(?<!is )" skips "IS NOT NULL" inside an inline CHECK expression.
        declared_not_null = re.search(r"(?<!is )\bnot null\b", definition) is not None

        assert declared_not_null is not_null, definition

    @pytest.mark.parametrize(("column", "default"), _DEFAULT_CASES)
    def test_migration_0006_column_has_expected_default(self, column: str, default: str) -> None:
        """id, params ('{}'), status ('pending'), attempts (0), next_attempt_at and created_at
        (now()) have database defaults."""
        assert re.search(rf"\bdefault\s+{default}(?=[\s,)]|$)", _column(column)), _column(column)

    def test_migration_0006_id_is_primary_key(self) -> None:
        """id UUID PRIMARY KEY DEFAULT gen_random_uuid()."""
        assert "primary key" in _column("id")

    def test_migration_0006_recipient_references_users_with_cascade(self) -> None:
        """recipient_user_id REFERENCES users (id) ON DELETE CASCADE: purging a user removes
        their queued mail and the addresses in it."""
        inline = re.search(
            r"\breferences\s+users\s*(?:\(\s*id\s*\))?\s+on\s+delete\s+cascade\b",
            _column("recipient_user_id"),
        )
        table_level = re.search(
            r"foreign\s+key\s*\(\s*recipient_user_id\s*\)\s*references\s+users\s*"
            r"(?:\(\s*id\s*\))?\s+on\s+delete\s+cascade\b",
            _table_body(_migration_sql()),
        )

        assert inline is not None or table_level is not None


# ---------------------------------------------------------------------------
# 3. Value CHECK constraints (mirroring the Python bounds)
# ---------------------------------------------------------------------------


class TestMigration0006ValueChecks:
    """Enumerations, the address format, params shape and attempts are CHECKed."""

    def test_migration_0006_address_length_is_bounded(self) -> None:
        """CHECK (char_length(recipient_address) BETWEEN 3 AND 254), as users.email."""
        assert _any_check_matches(
            r"(?:char_length|length)\s*\(\s*recipient_address\s*\)\s+between\s+3\s+and\s+254\b"
        )

    def test_migration_0006_address_has_no_whitespace(self) -> None:
        """recipient_address !~ '[[:space:]]', as users_email_format_check."""
        assert _any_check_matches(r"recipient_address\s*!~\s*'\[\[:space:\]\]'")

    def test_migration_0006_address_has_a_local_part(self) -> None:
        """position('@' in recipient_address) > 1, as users_email_format_check."""
        assert _any_check_matches(r"position\s*\(\s*'@'\s+in\s+recipient_address\s*\)\s*>\s*1\b")

    def test_migration_0006_template_key_check_lists_the_seven_templates(self) -> None:
        """CHECK (template_key IN (...)) allows exactly the seven template keys."""
        assert _in_check_values("template_key") == _SPEC_TEMPLATE_KEYS

    def test_migration_0006_language_check_lists_de_fr_en(self) -> None:
        """CHECK (language IN ('de', 'fr', 'en')), as users.ui_language."""
        assert _in_check_values("language") == {"de", "fr", "en"}

    def test_migration_0006_status_check_lists_the_three_states(self) -> None:
        """CHECK (status IN ('pending', 'sent', 'failed'))."""
        assert _in_check_values("status") == {"pending", "sent", "failed"}

    def test_migration_0006_params_is_a_json_object(self) -> None:
        """CHECK (jsonb_typeof(params) = 'object')."""
        assert _any_check_matches(r"jsonb_typeof\s*\(\s*params\s*\)\s*=\s*'object'")

    def test_migration_0006_attempts_is_non_negative(self) -> None:
        """CHECK (attempts >= 0) (or BETWEEN 0 AND n)."""
        assert _any_check_matches(r"\battempts\s*>=\s*0\b", r"\battempts\s+between\s+0\s+and\s+\d+")

    def test_migration_0006_attempts_upper_bound_leaves_room(self) -> None:
        """If attempts has an upper bound, it's at least the 10 attempts the sender makes."""
        bound = _attempts_upper_bound()

        assert bound is None or bound >= 10


# ---------------------------------------------------------------------------
# 4. Row invariants
# ---------------------------------------------------------------------------

_PENDING_EQ = r"status\s*=\s*'pending'"
_PENDING_NE = r"status\s*(?:<>|!=)\s*'pending'"


class TestMigration0006RowInvariants:
    """Pending iff unfinished; only pending rows keep params."""

    def test_migration_0006_pending_iff_not_finished(self) -> None:
        """CHECK ((status = 'pending') = (finished_at IS NULL)), or an equivalent form."""
        assert _any_check_matches(
            rf"\(\s*{_PENDING_EQ}\s*\)\s*=\s*\(\s*finished_at\s+is\s+null\s*\)",
            rf"\(\s*finished_at\s+is\s+null\s*\)\s*=\s*\(\s*{_PENDING_EQ}\s*\)",
            rf"\(\s*{_PENDING_NE}\s*\)\s*=\s*\(\s*finished_at\s+is\s+not\s+null\s*\)",
            rf"\(\s*finished_at\s+is\s+not\s+null\s*\)\s*=\s*\(\s*{_PENDING_NE}\s*\)",
        )

    def test_migration_0006_finished_rows_hold_no_params(self) -> None:
        """CHECK (status = 'pending' OR params = '{}'::jsonb): the database itself refuses a
        sent or failed row that still holds a one-time link."""
        assert _any_check_matches(
            rf"{_PENDING_EQ}\s+or\s+params\s*=\s*{_EMPTY_OBJECT}",
            rf"params\s*=\s*{_EMPTY_OBJECT}\s+or\s+{_PENDING_EQ}",
        )


# ---------------------------------------------------------------------------
# 5. Indexes
# ---------------------------------------------------------------------------


class TestMigration0006Indexes:
    """The due scan, the purge and the FK cascade are indexed."""

    def test_migration_0006_due_scan_has_a_partial_index(self) -> None:
        """CREATE INDEX ... ON email_outbox (next_attempt_at) WHERE status = 'pending'."""
        assert any(
            re.match(r"\s*next_attempt_at\b", _index_columns(statement))
            and re.fullmatch(rf"\(?\s*{_PENDING_EQ}\s*\)?", _index_predicate(statement))
            for statement in _index_statements()
        ), _index_statements()

    def test_migration_0006_finished_at_is_indexed_for_the_purge(self) -> None:
        """An index whose columns include finished_at (the retention purge's range scan)."""
        assert any(
            re.search(r"\bfinished_at\b", _index_columns(statement))
            for statement in _index_statements()
        ), _index_statements()

    def test_migration_0006_recipient_user_id_is_indexed(self) -> None:
        """CREATE INDEX ... ON email_outbox (recipient_user_id ...), so the users FK cascade
        doesn't scan the table."""
        assert any(
            re.match(r"\s*recipient_user_id\b", _index_columns(statement))
            for statement in _index_statements()
        ), _index_statements()


# ---------------------------------------------------------------------------
# 6. Python and SQL stay in sync
# ---------------------------------------------------------------------------


class TestMigration0006PythonSync:
    """The CHECKs mirror admino.email_templates and admino.email_outbox."""

    def test_migration_0006_template_key_check_matches_email_template(self) -> None:
        """The SQL template keys equal EmailTemplate's values."""
        templates = _email_templates_module()

        assert _in_check_values("template_key") == {t.value for t in templates.EmailTemplate}

    def test_migration_0006_language_check_matches_email_language(self) -> None:
        """The SQL languages equal the EmailLanguage Literal."""
        templates = _email_templates_module()

        assert _in_check_values("language") == set(get_args(templates.EmailLanguage))

    def test_migration_0006_status_check_matches_outbox_status(self) -> None:
        """The SQL statuses equal OutboxStatus's values."""
        outbox = _email_outbox_module()

        assert _in_check_values("status") == {s.value for s in outbox.OutboxStatus}

    def test_migration_0006_attempts_bound_fits_max_attempts(self) -> None:
        """Any attempts upper bound admits MAX_ATTEMPTS."""
        outbox = _email_outbox_module()
        bound = _attempts_upper_bound()

        assert bound is None or bound >= outbox.MAX_ATTEMPTS
