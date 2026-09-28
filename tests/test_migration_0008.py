"""Tests for migration 0008_password_reset_tokens.sql — password reset tokens (GH-151).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0007.py pattern): it must exist, be applied by
run_migrations as version 8, and declare the password_reset_tokens table with
its columns, keys and CHECK constraints. The SQL is read with comments
stripped, whitespace collapsed and lowercased, then matched with
formatting-tolerant regexes; parsing is quote-aware.

What these tests pin down:
- Exactly four columns: user_id (the primary key, so one live token per user,
  FK to users, ON DELETE CASCADE), token_hash (the SHA-256 of the emailed
  token: 32 bytes, unique), created_at (DEFAULT now()) and expires_at. No raw
  token column and no content column.
- Row invariants: a token expires after it was created and at most 30 minutes
  later (mirroring admino.password_reset.RESET_TOKEN_LIFETIME).
- The migration only creates that table: no other table, no ALTER of an
  existing one, no DROP, no data change, no bind parameters.

Security notes:
- Only the token's hash is stored: a leaked table can't be replayed as links.
- One row per user: a newer request replaces (invalidates) the older token.
- A user purge cascades to their token.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0008_password_reset_tokens.sql"
_TABLE = "password_reset_tokens"

# Formatting-tolerant type patterns.
_UUID = r"uuid"
_BYTEA = r"bytea"
_TIMESTAMPTZ = r"(?:timestamptz|timestamp with time zone)"

# Formatting-tolerant default pattern.
_NOW = r"(?:now\s*\(\s*\)|current_timestamp)"

# A 30-minute interval, however it is spelled.
_THIRTY_MINUTES = (
    r"(?:interval\s*'\s*30\s*min(?:ute)?s?\s*'"
    r"|'\s*30\s*min(?:ute)?s?\s*'\s*::\s*interval"
    r"|interval\s*'\s*00:30(?::00)?\s*'"
    r"|interval\s*'\s*1800\s*sec(?:ond)?s?\s*'"
    r"|make_interval\s*\(\s*mins\s*=>\s*30\s*\))"
)


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _migration_sql() -> str:
    """Return the shipped 0008 migration, comments stripped, whitespace collapsed, lowercased."""
    raw = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")
    without_comments = re.sub(r"--.*", " ", raw)
    return re.sub(r"\s+", " ", without_comments).strip().lower()


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
    """Return the text between the parentheses of CREATE TABLE password_reset_tokens ( ... )."""
    masked = _masked(sql)
    match = re.search(rf"create\s+table\s+(?:if\s+not\s+exists\s+)?{_TABLE}\s*\(", masked)
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
    """Top-level items (column definitions and table constraints) of the table, lowercased."""
    return _split_top_level(_table_body(_migration_sql()))


_CONSTRAINT_WORDS = frozenset({"constraint", "check", "primary", "foreign", "unique", "exclude"})


def _column_names() -> set[str]:
    """Names of the columns the table defines."""
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
    """Every CHECK (...) expression of the table body, lowercased."""
    body = _table_body(_migration_sql())
    masked = _masked(body)
    expressions: list[str] = []
    for match in re.finditer(r"\bcheck\s*\(", masked):
        end = _balanced_end(masked, match.end() - 1)
        expressions.append(body[match.end() : end].strip())
    return expressions


def _any_check_matches(*patterns: str) -> bool:
    """True when some CHECK expression matches one of the patterns."""
    return any(re.search(pattern, check) for check in _checks() for pattern in patterns)


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
    """Every CREATE [UNIQUE] INDEX ... ON password_reset_tokens statement."""
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


# ---------------------------------------------------------------------------
# Column specification: (column, type pattern, NOT NULL?, default pattern)
# NOT NULL: True = required, None = implied (primary key).
# ---------------------------------------------------------------------------

_COLUMNS: list[tuple[str, str, bool | None, str | None]] = [
    ("user_id", _UUID, None, None),
    ("token_hash", _BYTEA, True, None),
    ("created_at", _TIMESTAMPTZ, True, _NOW),
    ("expires_at", _TIMESTAMPTZ, True, None),
]

_TYPE_CASES = [
    pytest.param(column, type_pattern, id=column) for column, type_pattern, _, _ in _COLUMNS
]
_NULLABILITY_CASES = [
    pytest.param(column, not_null, id=column)
    for column, _, not_null, _ in _COLUMNS
    if not_null is not None
]


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0008File:
    """The migration ships as version 8 and is applied by run_migrations."""

    def test_migration_0008_file_is_shipped_as_version_8(self) -> None:
        """0008_password_reset_tokens.sql exists and matches the numbered-migration regex."""
        assert (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == 8

    def test_migration_0008_is_the_only_version_8(self) -> None:
        """Exactly one migration file claims version 8, and it is this one."""
        eights = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == 8
        ]

        assert eights == [_MIGRATION_NAME]

    async def test_migration_0008_run_migrations_applies_it_as_version_8(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0007 applied, run_migrations executes the file and records version 8."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in (1, 2, 3, 4, 5, 6, 7)])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (8, _MIGRATION_NAME) in recorded
        assert all(version >= 8 for version, _ in recorded)

    async def test_migration_0008_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        """run_migrations executes the 0008 file's SQL text verbatim."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in (1, 2, 3, 4, 5, 6, 7)])
        shipped = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0008_is_parameter_free(self) -> None:
        """No bind parameters or interpolation placeholders in the migration."""
        sql = _migration_sql()

        assert re.search(r"\$\d", sql) is None
        assert "%s" not in sql
        assert "%(" not in sql

    def test_migration_0008_drops_nothing(self) -> None:
        """No DROP of any table, column, schema, index, type, function or trigger."""
        masked = _masked(_migration_sql())

        assert (
            re.search(r"\bdrop\s+(?:table|column|schema|index|type|function|trigger)\b", masked)
            is None
        )

    def test_migration_0008_creates_only_the_token_table(self) -> None:
        """One CREATE TABLE, for password_reset_tokens."""
        masked = _masked(_migration_sql())
        created = re.findall(r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(\w+)", masked)

        assert created == [_TABLE]

    def test_migration_0008_alters_no_existing_table(self) -> None:
        """No ALTER TABLE of anything but password_reset_tokens itself."""
        masked = _masked(_migration_sql())
        targets = re.findall(r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", masked)

        assert set(targets) <= {_TABLE}

    def test_migration_0008_changes_no_rows(self) -> None:
        """No INSERT, UPDATE, DELETE or TRUNCATE: the migration only creates."""
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\s+into\b", masked) is None
        assert re.search(r"\bupdate\s+(?:only\s+)?\w+\s+set\b", masked) is None
        assert re.search(r"\bdelete\s+from\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None


# ---------------------------------------------------------------------------
# 2. Column shapes (types, nullability, defaults, keys)
# ---------------------------------------------------------------------------


class TestMigration0008Columns:
    """Exactly the four columns, with their types, nullability, defaults and keys."""

    def test_migration_0008_defines_exactly_the_token_columns(self) -> None:
        """No raw token, email, link or any other content column can exist."""
        assert _column_names() == {column for column, _, _, _ in _COLUMNS}

    @pytest.mark.parametrize(("column", "type_pattern"), _TYPE_CASES)
    def test_migration_0008_column_has_expected_type(self, column: str, type_pattern: str) -> None:
        """The column exists with the specified SQL type."""
        definition = _column(column)

        assert re.match(rf"{column} {type_pattern}(?=\s|$)", definition), definition

    @pytest.mark.parametrize(("column", "not_null"), _NULLABILITY_CASES)
    def test_migration_0008_column_has_expected_nullability(
        self, column: str, not_null: bool
    ) -> None:
        """token_hash, created_at and expires_at are NOT NULL."""
        definition = _masked(_column(column))
        # "(?<!is )" skips "IS NOT NULL" inside an inline CHECK expression.
        declared_not_null = re.search(r"(?<!is )\bnot null\b", definition) is not None

        assert declared_not_null is not_null, definition

    def test_migration_0008_created_at_defaults_to_now(self) -> None:
        """created_at DEFAULT now() (the same transaction clock the upsert uses)."""
        assert re.search(rf"\bdefault\s+{_NOW}(?=[\s,)]|$)", _column("created_at")), _column(
            "created_at"
        )

    @pytest.mark.parametrize("column", ["user_id", "token_hash", "expires_at"])
    def test_migration_0008_app_set_columns_have_no_default(self, column: str) -> None:
        """The app always sets the owner, the hash and the expiry."""
        assert re.search(r"\bdefault\b", _masked(_column(column))) is None, _column(column)

    def test_migration_0008_user_id_is_the_primary_key(self) -> None:
        """PRIMARY KEY (user_id): one live token per user (a new request replaces it)."""
        inline = "primary key" in _column("user_id")
        table_level = any(
            re.fullmatch(r"(?:constraint \w+ )?primary key\s*\(\s*user_id\s*\)", item)
            for item in _table_items()
        )

        assert inline or table_level

    def test_migration_0008_token_hash_is_unique(self) -> None:
        """token_hash is UNIQUE (inline, as a table constraint, or a unique index)."""
        inline = re.search(r"\bunique\b", _masked(_column("token_hash")))
        table_level = any(
            re.fullmatch(r"(?:constraint \w+ )?unique\s*\(\s*token_hash\s*\)", item)
            for item in _table_items()
        )
        unique_index = any(
            statement.startswith("create unique index")
            and re.fullmatch(r"\s*token_hash\s*", _index_columns(statement))
            for statement in _index_statements()
        )

        assert inline is not None or table_level or unique_index

    def test_migration_0008_user_references_users_with_cascade(self) -> None:
        """user_id REFERENCES users (id) ON DELETE CASCADE: purging a user removes the token."""
        inline = re.search(
            r"\breferences\s+users\s*(?:\(\s*id\s*\))?\s+on\s+delete\s+cascade\b",
            _column("user_id"),
        )
        table_level = re.search(
            r"foreign\s+key\s*\(\s*user_id\s*\)\s*references\s+users\s*"
            r"(?:\(\s*id\s*\))?\s+on\s+delete\s+cascade\b",
            _table_body(_migration_sql()),
        )

        assert inline is not None or table_level is not None


# ---------------------------------------------------------------------------
# 3. CHECK constraints
# ---------------------------------------------------------------------------


class TestMigration0008Checks:
    """The hash size and the expiry window are CHECKed."""

    def test_migration_0008_token_hash_is_32_bytes(self) -> None:
        """CHECK (octet_length(token_hash) = 32): a SHA-256 digest, never a raw token."""
        assert _any_check_matches(r"octet_length\s*\(\s*token_hash\s*\)\s*=\s*32\b")

    def test_migration_0008_expires_after_creation(self) -> None:
        """CHECK (expires_at > created_at)."""
        assert _any_check_matches(
            r"\bexpires_at\s*>\s*created_at\b", r"\bcreated_at\s*<\s*expires_at\b"
        )

    def test_migration_0008_expires_within_30_minutes(self) -> None:
        """CHECK (expires_at <= created_at + interval '30 minutes')."""
        assert _any_check_matches(
            rf"\bexpires_at\s*<=\s*\(?\s*created_at\s*\+\s*{_THIRTY_MINUTES}",
            rf"\bcreated_at\s*\+\s*{_THIRTY_MINUTES}\s*\)?\s*>=\s*expires_at\b",
        )


# ---------------------------------------------------------------------------
# 4. Python and SQL stay in sync
# ---------------------------------------------------------------------------


class TestMigration0008PythonSync:
    """The CHECKs mirror admino.password_reset and admino.sessions."""

    def test_migration_0008_lifetime_matches_password_reset(self) -> None:
        """RESET_TOKEN_LIFETIME is the CHECK's 30 minutes."""
        from admino.password_reset import RESET_TOKEN_LIFETIME  # type: ignore[import-not-found]

        assert timedelta(minutes=30) == RESET_TOKEN_LIFETIME
        assert _any_check_matches(rf"created_at\s*\+\s*{_THIRTY_MINUTES}")

    def test_migration_0008_token_hash_size_matches_sha256(self) -> None:
        """The digest the service stores is exactly the 32 bytes the CHECK demands."""
        from admino.sessions import hash_session_token

        assert len(hash_session_token("t" * 43)) == 32
        assert _any_check_matches(r"octet_length\s*\(\s*token_hash\s*\)\s*=\s*32\b")
