"""Tests for migration 0017_per_user_connections.sql — per-user OAuth connections and
memory notes (GH-162).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0016.py pattern): it must exist, be applied by
run_migrations as version 17, and make exactly the schema change GH-162 needs.
The SQL is read with ``--`` comments blanked; statements are split outside
parentheses and literals; keywords are compared case-insensitively with
whitespace collapsed, while string literals are kept byte for byte (the memory
key regex and the provider list are compared exactly). A constraint may be
written inline on its column or as a table constraint.

What these tests pin down:
- ``DROP TABLE oauth_tokens`` then ``CREATE TABLE oauth_tokens`` re-keyed per
  user: ``user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE``,
  ``org_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE``,
  ``provider TEXT NOT NULL CHECK (provider IN ('google', 'microsoft'))``,
  ``encrypted_refresh_token TEXT NOT NULL CHECK (length(...) BETWEEN 1 AND
  4096)``, ``email TEXT CHECK (email IS NULL OR length(email) <= 254)``,
  ``scopes JSONB NOT NULL CHECK (jsonb_typeof(scopes) = 'array' AND
  jsonb_array_length(scopes) <= 50)``, ``healthy BOOLEAN NOT NULL DEFAULT
  true``, ``created_at`` / ``last_refreshed_at TIMESTAMPTZ NOT NULL DEFAULT
  now()``, ``PRIMARY KEY (user_id, provider)``.
- ``DROP TABLE memory`` then ``CREATE TABLE memory``: the same two foreign
  keys, ``key TEXT NOT NULL CHECK (key ~ '^[a-zA-Z0-9_. -]{1,200}$')`` (the
  literal compared exactly), ``value TEXT NOT NULL CHECK (char_length(value)
  <= 2000)``, ``created_at`` / ``updated_at TIMESTAMPTZ NOT NULL DEFAULT
  now()``, ``PRIMARY KEY (user_id, key)``.
- The CHECK bounds equal the Pydantic bounds: ``admino.oauth.OAuthToken``
  (encrypted_refresh_token 1..4096, email <= 254, scopes <= 50 items, the
  providers of ``OAuthProvider``) and ``admino.models.MemoryStoreArgs`` (key
  max_length 200 and its pattern, value max_length 2000). The key CHECK accepts
  and refuses exactly what ``MemoryStoreArgs`` does, so a key the tool accepts
  never makes the database refuse the write with an error.
- The header comment says the existing rows are dropped (#139 §4.2: the
  single-install connections and notes belong to nobody, users reconnect).
- Nothing else: no INSERT / UPDATE / DELETE / TRUNCATE, no other DROP, no
  ALTER of any table (no audit_events catalog change), no index, function,
  trigger, view, type or DO block, no GRANT / REVOKE, parameter-free.

Security notes:
- Both foreign keys cascade, so deleting a user or the org purge (GH-154)
  removes the user's tokens and notes with them (tests/test_schema_foreign_keys.py).
- user_id and org_id are NOT NULL with no default: every token and note row
  names its owner explicitly; nothing is shared by omission.
- The CHECKs mirror the Pydantic bounds, so the database refuses what the
  models refuse even if a write bypasses them.
- The old rows are dropped, never assigned to some user: a token one person
  granted can never become another person's connection.
"""

from __future__ import annotations

import re
import typing
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

import admino.database as db_mod
from admino import oauth as oauth_mod
from admino.models import MemoryStoreArgs

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

    from pydantic import BaseModel

_MIGRATION_NAME = "0017_per_user_connections.sql"
_VERSION = 17
_OAUTH = "oauth_tokens"
_MEMORY = "memory"
_TABLES = (_OAUTH, _MEMORY)
_COLUMNS: dict[str, tuple[str, ...]] = {
    _OAUTH: (
        "user_id",
        "org_id",
        "provider",
        "encrypted_refresh_token",
        "email",
        "scopes",
        "healthy",
        "created_at",
        "last_refreshed_at",
    ),
    _MEMORY: ("user_id", "org_id", "key", "value", "created_at", "updated_at"),
}
_PRIMARY_KEYS: dict[str, tuple[str, ...]] = {
    _OAUTH: ("user_id", "provider"),
    _MEMORY: ("user_id", "key"),
}
# column -> referenced table; both ON DELETE CASCADE.
_FOREIGN_KEYS: dict[str, str] = {"user_id": "users", "org_id": "organizations"}
_TIMESTAMP_COLUMNS: tuple[tuple[str, str], ...] = (
    (_OAUTH, "created_at"),
    (_OAUTH, "last_refreshed_at"),
    (_MEMORY, "created_at"),
    (_MEMORY, "updated_at"),
)
_REQUIRED_TEXT_COLUMNS: tuple[tuple[str, str], ...] = (
    (_OAUTH, "provider"),
    (_OAUTH, "encrypted_refresh_token"),
    (_MEMORY, "key"),
    (_MEMORY, "value"),
)
# No implicit owner, org, provider, token, scopes, key or value.
_NO_DEFAULT_COLUMNS: tuple[tuple[str, str], ...] = (
    (_OAUTH, "user_id"),
    (_OAUTH, "org_id"),
    (_OAUTH, "provider"),
    (_OAUTH, "encrypted_refresh_token"),
    (_OAUTH, "scopes"),
    (_MEMORY, "user_id"),
    (_MEMORY, "org_id"),
    (_MEMORY, "key"),
    (_MEMORY, "value"),
)
_PROVIDERS = frozenset({"google", "microsoft"})
_MEMORY_KEY_REGEX = "^[a-zA-Z0-9_. -]{1,200}$"
_TIMESTAMPTZ = r"(?:timestamptz|timestamp\s*(?:\(\s*\d\s*\)\s*)?with\s+time\s+zone)"
_NOW = r"(?:now\s*\(\s*\)|current_timestamp|transaction_timestamp\s*\(\s*\))"
_LENGTH_FN = r"(?:length|char_length|character_length)"
_CONSTRAINT_START = (
    r"(?:constraint\s+\w+\s+)?(?:check|unique|primary\s+key|foreign\s+key|exclude)\b"
)

# Characters built with chr() so they survive editing tools verbatim.
_NUL = chr(0x00)
_TAB = chr(0x09)
_NEWLINE = chr(0x0A)
_E_ACUTE = chr(0x00E9)
_CYRILLIC_IE = chr(0x0435)  # looks like a Latin "e"
_FULLWIDTH_A = chr(0xFF41)
_ZERO_WIDTH_SPACE = chr(0x200B)
_NBSP = chr(0x00A0)

# (sample, accepted): the memory key rule of MemoryStoreArgs
# (letters, digits, underscore, dot, hyphen, space; 1 to 200 characters).
_KEY_SAMPLES: tuple[tuple[str, bool], ...] = (
    ("a", True),
    ("Z", True),
    ("7", True),
    ("my_note", True),
    ("project.alpha", True),
    ("project-alpha", True),
    ("shopping list", True),
    ("Mixed.Case_key-1 2", True),
    (" ", True),
    ("-", True),
    ("..", True),
    ("a" * 200, True),
    ("a" * 201, False),
    ("", False),
    ("note" + _NEWLINE, False),
    (_NEWLINE + "note", False),
    ("note" + _NUL, False),
    ("note" + _TAB, False),
    ("note/1", False),
    ("../etc", False),
    ("note;drop", False),
    ("note'", False),
    ('note"', False),
    ("note%", False),
    ("note*", False),
    ("caf" + _E_ACUTE, False),
    ("not" + _CYRILLIC_IE, False),
    (_FULLWIDTH_A + "note", False),
    ("note" + _ZERO_WIDTH_SPACE, False),
    ("note" + _NBSP + "1", False),
)


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    return _migration_path().read_text(encoding="utf-8")


def _normalized() -> str:
    """The shipped migration, normalized outside literals only.

    ``--`` comments are blanked, whitespace is collapsed and keywords are
    lowercased; the contents of '...' and "..." are kept byte for byte.
    """
    raw = _raw_sql()
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
    return _split(_normalized(), ";")


def _create_table_body(table: str) -> str:
    for statement in _statements():
        masked = _masked(statement)
        match = re.match(rf"create\s+table\s+(?:if\s+not\s+exists\s+)?{table}\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        assert masked[end + 1 :].strip() == "", statement
        return statement[match.end() : end]
    pytest.fail(f"no CREATE TABLE {table} (...) in {_MIGRATION_NAME}")


def _elements(table: str) -> list[str]:
    return _split(_create_table_body(table), ",")


def _columns(table: str) -> dict[str, str]:
    columns: dict[str, str] = {}
    for element in _elements(table):
        if re.match(_CONSTRAINT_START, _masked(element)):
            continue
        match = re.fullmatch(r'"?(\w+)"?\s+(.*)', element)
        assert match is not None, element
        columns[match.group(1)] = match.group(2)
    return columns


def _column(table: str, name: str) -> str:
    columns = _columns(table)
    assert name in columns, f"no column {name} in CREATE TABLE {table}"
    return columns[name]


def _table_constraints(table: str) -> list[str]:
    return [
        element for element in _elements(table) if re.match(_CONSTRAINT_START, _masked(element))
    ]


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    while (
        expression.startswith("(") and _balanced_end(_masked(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _checks_in(text: str) -> list[str]:
    masked = _masked(text)
    expressions: list[str] = []
    for match in re.finditer(r"\bcheck\s*\(", masked):
        end = _balanced_end(masked, match.end() - 1)
        expressions.append(_unwrap(text[match.end() : end]))
    return expressions


def _check_expressions(table: str, column: str) -> list[str]:
    """The CHECKs on a column: inline on it, or table-level ones naming it."""
    expressions = _checks_in(_column(table, column))
    for constraint in _table_constraints(table):
        for expression in _checks_in(constraint):
            if re.search(rf"\b{column}\b", _masked(expression)):
                expressions.append(expression)
    return expressions


def _and_atoms(expression: str) -> list[str]:
    """The top-level AND-ed conditions of an expression, each unwrapped.

    The AND of ``x BETWEEN a AND b`` is part of its condition, not a split.
    """
    masked = _masked(expression)
    atoms: list[str] = []
    depth = 0
    start = 0
    in_between = False
    for match in re.finditer(r"\(|\)|\bbetween\b|\band\b", masked):
        token = match.group(0)
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        elif depth != 0:
            continue
        elif token == "between":
            in_between = True
        elif in_between:
            in_between = False
        else:
            atoms.append(_unwrap(expression[start : match.start()]))
            start = match.end()
    atoms.append(_unwrap(expression[start:]))
    return atoms


def _check_atoms(table: str, column: str) -> list[str]:
    atoms: list[str] = []
    for expression in _check_expressions(table, column):
        atoms.extend(_and_atoms(expression))
    return atoms


def _in_values(table: str, column: str) -> list[str] | None:
    """The literals of '<column> IN (...)' when a CHECK condition is exactly that."""
    for atom in _check_atoms(table, column):
        match = re.fullmatch(rf"{column}\s+in\s*\(([^)]*)\)", atom)
        if match is not None:
            return re.findall(r"'([^']*)'", match.group(1))
    return None


def _length_bounds(table: str, column: str) -> tuple[int | None, int | None]:
    """(min, max) characters the CHECKs on a text column allow (None: unbounded).

    Reads ``length(col) BETWEEN a AND b`` and ``length(col) >= / > / <= / < n``
    (also as char_length / character_length), each optionally behind
    ``<col> IS NULL OR``. Any other condition on the column fails the test.
    """
    low: int | None = None
    high: int | None = None
    function = rf"{_LENGTH_FN}\s*\(\s*{column}\s*\)"
    for atom in _check_atoms(table, column):
        condition = _unwrap(re.sub(rf"^{column}\s+is\s+null\s+or\s+", "", atom))
        if match := re.fullmatch(rf"{function}\s+between\s+(\d+)\s+and\s+(\d+)", condition):
            low, high = int(match.group(1)), int(match.group(2))
        elif match := re.fullmatch(rf"{function}\s*>=\s*(\d+)", condition):
            low = int(match.group(1))
        elif match := re.fullmatch(rf"{function}\s*>\s*(\d+)", condition):
            low = int(match.group(1)) + 1
        elif match := re.fullmatch(rf"{function}\s*<=\s*(\d+)", condition):
            high = int(match.group(1))
        elif match := re.fullmatch(rf"{function}\s*<\s*(\d+)", condition):
            high = int(match.group(1)) - 1
        else:
            pytest.fail(f"unexpected CHECK condition on {table}.{column}: {atom}")
    return low, high


def _key_regex() -> str:
    """The one CHECK of memory.key, which must be 'key ~ '<regex>''."""
    atoms = _check_atoms(_MEMORY, "key")
    assert len(atoms) == 1, f"memory.key needs exactly one CHECK condition: {atoms}"
    match = re.fullmatch(r"key\s*~\s*'((?:[^']|'')*)'", atoms[0])
    assert match is not None, f"memory.key CHECK is not a '~' regex: {atoms[0]}"
    return match.group(1).replace("''", "'")


def _sql_key_accepts(sample: str) -> bool:
    """Emulate PostgreSQL's CHECK (key ~ '^...$') on a sample value."""
    pattern = _key_regex()
    assert pattern.startswith("^"), pattern
    assert pattern.endswith("$"), pattern
    # PostgreSQL's '$' (not newline-sensitive) only matches at the very end, so
    # an anchored ~ is a full match of the inner pattern.
    return re.fullmatch(pattern[1:-1], sample) is not None


def _store_accepts(key: str) -> bool:
    try:
        MemoryStoreArgs(key=key, value="v")
    except ValidationError:
        return False
    return True


def _field_bound(model: type[BaseModel], name: str, bound: str) -> int | None:
    """A field's min_length / max_length from its metadata (None: not set)."""
    values = [
        getattr(item, bound)
        for item in model.model_fields[name].metadata
        if getattr(item, bound, None) is not None
    ]
    assert len(values) <= 1, f"{model.__name__}.{name} has several {bound}"
    return int(values[0]) if values else None


def _default(definition: str) -> str | None:
    """The DEFAULT expression of a column definition (literals kept verbatim)."""
    masked = _masked(definition)
    match = re.search(r"\bdefault\s+", masked)
    if match is None:
        return None
    rest = definition[match.end() :]
    rest_masked = masked[match.end() :]
    if rest.startswith("'"):
        closing = rest_masked.index("'", 1)
        return rest[: closing + 1]
    token = re.match(r"\w+(?:\s*\(\s*\))?", rest_masked)
    assert token is not None, definition
    return rest[: token.end()]


def _primary_key(table: str) -> tuple[str, ...]:
    """The primary key columns, in declared order."""
    inline = [
        name
        for name, definition in _columns(table).items()
        if re.search(r"\bprimary\s+key\b", _masked(definition))
    ]
    table_level = [
        match.group(1)
        for constraint in _table_constraints(table)
        if (
            match := re.fullmatch(
                r"(?:constraint\s+\w+\s+)?primary\s+key\s*\(([^)]*)\)", _masked(constraint)
            )
        )
    ]
    assert len(inline) + len(table_level) == 1, f"exactly one primary key on {table}"
    if inline:
        return (inline[0],)
    return tuple(column.strip().strip('"') for column in table_level[0].split(","))


def _foreign_key(table: str, column: str) -> tuple[str, str, str]:
    """(referenced table, referenced column, rest after the reference) for a column's FK."""
    pattern = r"references\s+(\w+)\s*(?:\(\s*(\w+)\s*\))?(.*)"
    inline = re.search(rf"\b{pattern}", _masked(_column(table, column)))
    if inline is not None:
        return inline.group(1), inline.group(2) or "id", inline.group(3)
    for constraint in _table_constraints(table):
        match = re.fullmatch(
            rf"(?:constraint\s+\w+\s+)?foreign\s+key\s*\(\s*{column}\s*\)\s*{pattern}",
            _masked(constraint),
        )
        if match is not None:
            return match.group(1), match.group(2) or "id", match.group(3)
    pytest.fail(f"{table}.{column} has no foreign key")


def _is_required(definition: str) -> bool:
    return re.search(r"\bnot\s+null\b", _masked(definition)) is not None


def _header_comment() -> str:
    """The ``--`` comment lines before the first statement, joined."""
    lines: list[str] = []
    for line in _raw_sql().splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            lines.append(stripped[2:].strip())
        elif stripped:
            break
    return " ".join(lines)


# ---------------------------------------------------------------------------
# Statement classification
# ---------------------------------------------------------------------------


def _kind(statement: str) -> str | None:
    masked = _masked(statement)
    for table in _TABLES:
        if re.fullmatch(rf"drop\s+table\s+(?:if\s+exists\s+)?{table}(?:\s+restrict)?", masked):
            return f"drop {table}"
        if re.fullmatch(rf"create\s+table\s+(?:if\s+not\s+exists\s+)?{table}\s*\(.*\)", masked):
            return f"create {table}"
    return None


def _kinds() -> list[str | None]:
    return [_kind(statement) for statement in _statements()]


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0017File:
    """The migration ships as version 17 and is applied by run_migrations."""

    def test_migration_0017_file_is_shipped_as_version_17(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0017_is_the_only_version_17(self) -> None:
        seventeens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert seventeens == [_MIGRATION_NAME]

    async def test_migration_0017_run_migrations_applies_it_as_version_17(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0016 applied, run_migrations executes the file and records 17."""
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

    async def test_migration_0017_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0017_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0017 recorded, the shipped SQL is not executed a second time."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0017_is_parameter_free(self) -> None:
        masked = _masked(_normalized())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked

    def test_migration_0017_header_comment_says_existing_rows_are_dropped(self) -> None:
        """The operator reading the file learns the old tokens and notes are not kept."""
        header = _header_comment().lower()

        assert re.search(r"\bdrop", header), header
        assert re.search(r"\brows?\b", header), header

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0017_header_comment_names_the_table(self, table: str) -> None:
        assert re.search(rf"\b{table}\b", _header_comment().lower())


# ---------------------------------------------------------------------------
# 2. Exactly the contract's statements
# ---------------------------------------------------------------------------


class TestMigration0017Statements:
    """Drop and recreate oauth_tokens and memory, nothing else."""

    def test_migration_0017_every_statement_is_part_of_the_contract(self) -> None:
        for statement in _statements():
            assert _kind(statement) is not None, statement

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0017_drops_and_creates_the_table_once(self, table: str) -> None:
        kinds = _kinds()

        assert kinds.count(f"drop {table}") == 1
        assert kinds.count(f"create {table}") == 1

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0017_drops_the_old_table_before_creating_the_new(self, table: str) -> None:
        """The single-install rows are not carried over (#139 §4.2)."""
        kinds = _kinds()

        assert kinds.index(f"drop {table}") < kinds.index(f"create {table}")

    def test_migration_0017_drops_do_not_cascade(self) -> None:
        """Nothing depends on these tables; CASCADE could silently drop more."""
        drops = [s for s in _statements() if re.match(r"drop\b", _masked(s))]

        assert len(drops) == len(_TABLES)
        for statement in drops:
            assert re.search(r"\bcascade\b", _masked(statement)) is None, statement


# ---------------------------------------------------------------------------
# 3. Columns and keys shared by both tables
# ---------------------------------------------------------------------------


class TestMigration0017Ownership:
    """Both tables are owned by a user in an org, and go with them."""

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0017_table_has_exactly_the_contract_columns(self, table: str) -> None:
        assert set(_columns(table)) == set(_COLUMNS[table])

    @pytest.mark.parametrize("table", _TABLES)
    @pytest.mark.parametrize("column", sorted(_FOREIGN_KEYS))
    def test_migration_0017_owner_column_is_a_required_uuid(self, table: str, column: str) -> None:
        definition = _masked(_column(table, column))

        assert re.match(r"uuid\b", definition), definition
        assert _is_required(definition), definition

    @pytest.mark.parametrize("table", _TABLES)
    @pytest.mark.parametrize("column", sorted(_FOREIGN_KEYS))
    def test_migration_0017_owner_column_references_its_table_on_delete_cascade(
        self, table: str, column: str
    ) -> None:
        """Deleting the user, or the org purge, removes the rows with them."""
        referenced, referenced_column, rest = _foreign_key(table, column)

        assert (referenced, referenced_column) == (_FOREIGN_KEYS[column], "id")
        assert re.search(r"\bon\s+delete\s+cascade\b", rest), rest

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0017_table_has_exactly_two_foreign_keys(self, table: str) -> None:
        body = _masked(_create_table_body(table))

        assert len(re.findall(r"\breferences\b", body)) == len(_FOREIGN_KEYS)

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0017_primary_key_leads_with_the_user(self, table: str) -> None:
        """oauth_tokens (user_id, provider), memory (user_id, key)."""
        assert _primary_key(table) == _PRIMARY_KEYS[table]

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0017_table_has_no_other_unique_or_exclusion_constraint(
        self, table: str
    ) -> None:
        body = _masked(_create_table_body(table))

        assert re.search(r"\b(?:unique|exclude)\b", body) is None

    @pytest.mark.parametrize(("table", "column"), _TIMESTAMP_COLUMNS)
    def test_migration_0017_timestamp_column_is_required_with_now_default(
        self, table: str, column: str
    ) -> None:
        definition = _masked(_column(table, column))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert _is_required(definition), definition
        assert re.fullmatch(_NOW, _default(definition) or ""), definition

    @pytest.mark.parametrize(("table", "column"), _REQUIRED_TEXT_COLUMNS)
    def test_migration_0017_text_column_is_required_text(self, table: str, column: str) -> None:
        definition = _masked(_column(table, column))

        assert re.match(r"text\b", definition), definition
        assert _is_required(definition), definition

    @pytest.mark.parametrize(("table", "column"), _NO_DEFAULT_COLUMNS)
    def test_migration_0017_column_has_no_default(self, table: str, column: str) -> None:
        """No implicit owner, org, provider, token or note: nothing shared by omission."""
        assert _default(_column(table, column)) is None


# ---------------------------------------------------------------------------
# 4. oauth_tokens: the CHECKs mirror OAuthToken
# ---------------------------------------------------------------------------


class TestMigration0017OAuthTokens:
    """One row per (user, provider), with the OAuthToken bounds."""

    def test_migration_0017_provider_check_is_google_and_microsoft(self) -> None:
        """CHECK (provider IN ('google', 'microsoft')): the OAuthProvider literal."""
        values = _in_values(_OAUTH, "provider")

        assert values is not None, _check_expressions(_OAUTH, "provider")
        assert sorted(values) == sorted(_PROVIDERS)
        assert set(typing.get_args(oauth_mod.OAuthProvider)) == set(values)

    def test_migration_0017_provider_check_is_the_only_condition(self) -> None:
        assert len(_check_atoms(_OAUTH, "provider")) == 1, _check_atoms(_OAUTH, "provider")

    def test_migration_0017_encrypted_refresh_token_bounds_mirror_oauth_token(self) -> None:
        """length(encrypted_refresh_token) BETWEEN 1 AND 4096."""
        bounds = _length_bounds(_OAUTH, "encrypted_refresh_token")

        assert bounds == (1, 4096)
        assert bounds == (
            _field_bound(oauth_mod.OAuthToken, "encrypted_refresh_token", "min_length"),
            _field_bound(oauth_mod.OAuthToken, "encrypted_refresh_token", "max_length"),
        )

    def test_migration_0017_email_is_optional_text(self) -> None:
        """The connected account's email is display-only and may be unknown (NULL)."""
        definition = _masked(_column(_OAUTH, "email"))

        assert re.match(r"text\b", definition), definition
        assert not _is_required(definition), definition

    def test_migration_0017_email_bound_mirrors_oauth_token(self) -> None:
        """email IS NULL OR length(email) <= 254."""
        low, high = _length_bounds(_OAUTH, "email")

        assert low in {None, 0}
        assert high == 254
        assert high == _field_bound(oauth_mod.OAuthToken, "email", "max_length")

    def test_migration_0017_scopes_is_required_jsonb(self) -> None:
        definition = _masked(_column(_OAUTH, "scopes"))

        assert re.match(r"jsonb\b", definition), definition
        assert _is_required(definition), definition

    def test_migration_0017_scopes_check_is_an_array_of_at_most_50(self) -> None:
        """jsonb_typeof(scopes) = 'array' AND jsonb_array_length(scopes) <= 50."""
        atoms = _check_atoms(_OAUTH, "scopes")
        typed = [
            a for a in atoms if re.fullmatch(r"jsonb_typeof\s*\(\s*scopes\s*\)\s*=\s*'array'", a)
        ]
        sized = [
            match
            for a in atoms
            if (match := re.fullmatch(r"jsonb_array_length\s*\(\s*scopes\s*\)\s*<=\s*(\d+)", a))
        ]

        assert len(atoms) == 2, atoms
        assert len(typed) == 1, atoms
        assert len(sized) == 1, atoms
        assert int(sized[0].group(1)) == 50

    def test_migration_0017_scopes_bound_mirrors_oauth_token(self) -> None:
        atoms = _check_atoms(_OAUTH, "scopes")
        limits = [
            int(match.group(1))
            for a in atoms
            if (match := re.fullmatch(r"jsonb_array_length\s*\(\s*scopes\s*\)\s*<=\s*(\d+)", a))
        ]

        assert limits == [_field_bound(oauth_mod.OAuthToken, "scopes", "max_length")]

    def test_migration_0017_healthy_is_required_boolean_default_true(self) -> None:
        """A new connection is healthy until a terminal refresh failure (GH-237)."""
        definition = _masked(_column(_OAUTH, "healthy"))

        assert re.match(r"bool(?:ean)?\b", definition), definition
        assert _is_required(definition), definition
        assert _default(definition) == "true", definition


# ---------------------------------------------------------------------------
# 5. memory: the CHECKs mirror MemoryStoreArgs
# ---------------------------------------------------------------------------


class TestMigration0017Memory:
    """One note per (user, key), with the MemoryStoreArgs bounds."""

    def test_migration_0017_key_check_is_exactly_the_contract_regex(self) -> None:
        """CHECK (key ~ '^[a-zA-Z0-9_. -]{1,200}$'), the literal byte for byte."""
        assert _key_regex() == _MEMORY_KEY_REGEX

    def test_migration_0017_key_length_mirrors_memory_store_args(self) -> None:
        """The regex quantifier {1,200}: at least one character (the model's '+') and
        at most MemoryStoreArgs.key's max_length."""
        quantifier = re.search(r"\{(\d+),(\d+)\}\$$", _key_regex())

        assert quantifier is not None, _key_regex()
        assert int(quantifier.group(1)) == 1
        assert int(quantifier.group(2)) == _field_bound(MemoryStoreArgs, "key", "max_length")
        assert _field_bound(MemoryStoreArgs, "key", "max_length") == 200

    @pytest.mark.parametrize(
        ("sample", "accepted"),
        _KEY_SAMPLES,
        ids=[repr(s)[:40] for s, _ in _KEY_SAMPLES],
    )
    def test_migration_0017_key_check_matches_memory_store_args(
        self, sample: str, accepted: bool
    ) -> None:
        """The DB CHECK and MemoryStoreArgs accept and refuse the same keys."""
        assert _sql_key_accepts(sample) is accepted
        assert _store_accepts(sample) is accepted

    def test_migration_0017_key_check_allows_the_model_character_set(self) -> None:
        """Every character up to U+02FF (and some lookalikes) is accepted alone, and
        between two letters, by both or by neither."""
        characters = [chr(code) for code in range(0x300)] + [
            _ZERO_WIDTH_SPACE,
            _FULLWIDTH_A,
            _CYRILLIC_IE,
            chr(0x2028),
            chr(0x3000),
        ]
        disagreements = [
            repr(sample)
            for character in characters
            for sample in (character, "a" + character + "b")
            if _sql_key_accepts(sample) is not _store_accepts(sample)
        ]

        assert disagreements == []

    def test_migration_0017_value_bound_mirrors_memory_store_args(self) -> None:
        """char_length(value) <= 2000; no lower bound, since the model allows ''."""
        low, high = _length_bounds(_MEMORY, "value")

        assert low in {None, 0}
        assert high == 2000
        assert high == _field_bound(MemoryStoreArgs, "value", "max_length")
        assert _field_bound(MemoryStoreArgs, "value", "min_length") is None


# ---------------------------------------------------------------------------
# 6. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0017NothingElse:
    """No other table, constraint, data, code or privilege changes."""

    def test_migration_0017_writes_no_data(self) -> None:
        """No rows are carried over or seeded."""
        masked = _masked(_normalized())

        assert re.search(r"\binsert\b", masked) is None
        assert re.search(r"\bupdate\s+(?:only\s+)?\w+\s+set\b", masked) is None
        assert re.search(r"\bdelete\s+from\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None
        assert re.search(r"\bmerge\s+into\b", masked) is None
        assert re.search(r"\bcopy\b", masked) is None

    def test_migration_0017_drops_nothing_else(self) -> None:
        """The two drops are the old oauth_tokens and memory tables."""
        assert len(re.findall(r"\bdrop\b", _masked(_normalized()))) == len(_TABLES)

    def test_migration_0017_alters_no_table(self) -> None:
        """No ALTER at all: users, organizations and audit_events stay as they are."""
        assert re.search(r"\balter\b", _masked(_normalized())) is None

    def test_migration_0017_leaves_the_audit_catalog_alone(self) -> None:
        """#146's catalog has no OAuth or memory actions: no audit_events change."""
        assert "audit_events" not in _masked(_normalized())

    def test_migration_0017_creates_only_the_two_tables(self) -> None:
        masked = _masked(_normalized())
        created = re.findall(
            r"\bcreate\s+(?:\w+\s+)*?table\s+(?:if\s+not\s+exists\s+)?(\w+)", masked
        )

        assert sorted(created) == sorted(_TABLES)

    def test_migration_0017_references_only_users_and_organizations(self) -> None:
        masked = _masked(_normalized())

        assert set(re.findall(r"\breferences\s+(\w+)", masked)) == set(_FOREIGN_KEYS.values())

    def test_migration_0017_defines_no_index_function_trigger_view_or_type(self) -> None:
        masked = _masked(_normalized())

        assert (
            re.search(
                r"\bcreate\s+(?:or\s+replace\s+)?(?:unique\s+)?"
                r"(?:index|function|procedure|trigger|view|type|rule|policy|sequence)\b",
                masked,
            )
            is None
        )
        assert re.search(r"\bdo\s+\$", masked) is None
        assert re.search(r"\bdo\s+'", masked) is None
        assert "$$" not in masked

    def test_migration_0017_grants_nothing(self) -> None:
        masked = _masked(_normalized())

        assert re.search(r"\b(?:grant|revoke)\b", masked) is None
