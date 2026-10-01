"""Tests for migration 0016_org_permissions.sql — tool permissions per org (GH-161).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0013.py pattern): it must exist, be applied by
run_migrations as version 16, and make exactly the schema change GH-161 needs.
The SQL is read with ``--`` comments blanked; statements are split outside
parentheses and literals; keywords are compared case-insensitively with
whitespace collapsed, while string literals are kept byte for byte (the
identifier regex, the permission states and the audit action list are compared
exactly). A constraint may be written inline on its column or as a table
constraint; the two audit_events actions may be one ALTER TABLE or two.

What these tests pin down:
- ``DROP TABLE permissions``: the old global (tool, action) table goes, nothing
  is carried over (startup seeds every org from ``DEFAULT_PERMISSIONS``).
- ``CREATE TABLE permissions`` with exactly ``org_id UUID NOT NULL REFERENCES
  organizations (id) ON DELETE CASCADE``; ``tool`` and ``action`` ``TEXT NOT
  NULL`` with ``CHECK (<column> ~ '^[a-z][a-z0-9_]{0,62}$')`` (the literal
  compared exactly); ``permission TEXT NOT NULL CHECK (permission IN ('allow',
  'confirm', 'deny'))``; ``updated_at TIMESTAMPTZ NOT NULL DEFAULT now()``;
  ``PRIMARY KEY (org_id, tool, action)`` (org_id leading, so the per-org reads
  use the key). No default other than updated_at's (no implicit org, no
  implicit permission state).
- The identifier CHECK accepts and refuses exactly what
  ``permissions._VALID_IDENTIFIER`` and the ``PermissionPatch`` /
  ``PermissionEntry`` pattern do (a trailing newline, upper case, 63 vs 64
  characters), so a value the API accepts never makes the database refuse the
  write with a 500. The permission values equal ``get_args(PermissionState)``.
- ``audit_events_action_check`` is dropped, then added again with a list that
  is exactly the live ``AuditAction`` catalog (47 actions): 0010's 43 plus
  ``org.permission_change``, ``org.permission_promote``,
  ``org.permission_promote_cancel`` and ``org.permission_demote``. The exact
  sync with the live catalog moved here from tests/test_migration_0010.py.
- Nothing else: no INSERT (no seed rows), no UPDATE / DELETE / TRUNCATE, no
  other DROP or ALTER, no index, function, trigger, view, type or DO block, no
  GRANT / REVOKE, parameter-free.

Security notes:
- The org foreign key cascades, so the org purge (GH-154) removes an org's
  permission rows with it (tests/test_schema_foreign_keys.py).
- The CHECKs mirror the Pydantic bounds and the permission engine's identifier
  rule, so the database refuses what the API refuses even if a write bypasses
  the models.
- No column has a default permission or org: a row always names its org and
  its state explicitly, so nothing is granted by omission.
- The audit log stays append-only: the migration only widens the catalog.
"""

from __future__ import annotations

import re
import typing
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

import admino.database as db_mod
from admino import permissions as permissions_mod
from admino.models import PermissionEntry, PermissionPatch
from admino.permissions import PermissionState

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

    from pydantic import BaseModel

_MIGRATION_NAME = "0016_org_permissions.sql"
_PREVIOUS_CATALOG_MIGRATION = "0010_invitations.sql"
_VERSION = 16
_TABLE = "permissions"
_COLUMNS = ("org_id", "tool", "action", "permission", "updated_at")
_IDENTIFIER_COLUMNS = ("tool", "action")
_IDENTIFIER_REGEX = "^[a-z][a-z0-9_]{0,62}$"
_STATES = frozenset({"allow", "confirm", "deny"})
_NEW_ACTIONS = frozenset(
    {
        "org.permission_change",
        "org.permission_promote",
        "org.permission_promote_cancel",
        "org.permission_demote",
    }
)
_CATALOG_SIZE = 47
_TIMESTAMPTZ = r"(?:timestamptz|timestamp\s*(?:\(\s*\d\s*\)\s*)?with\s+time\s+zone)"
_NOW = r"(?:now\s*\(\s*\)|current_timestamp|transaction_timestamp\s*\(\s*\))"
_CONSTRAINT_START = (
    r"(?:constraint\s+\w+\s+)?(?:check|unique|primary\s+key|foreign\s+key|exclude)\b"
)

# Characters built with chr() so they survive editing tools verbatim.
_NUL = chr(0x00)
_TAB = chr(0x09)
_NEWLINE = chr(0x0A)
_A_ACUTE = chr(0x00E1)
_CYRILLIC_IE = chr(0x0435)  # looks like a Latin "e"
_FULLWIDTH_A = chr(0xFF41)
_ZERO_WIDTH_SPACE = chr(0x200B)

# (sample, accepted): the identifier rule of the permission engine
# (fullmatch of [a-z][a-z0-9_]{0,62}; a trailing newline is refused).
_IDENTIFIER_SAMPLES: tuple[tuple[str, bool], ...] = (
    ("gmail", True),
    ("google_calendar", True),
    ("outlook_calendar", True),
    ("send", True),
    ("a", True),
    ("a1", True),
    ("a_", True),
    ("x" + "0" * 62, True),
    ("a" * 63, True),
    ("a" * 64, False),
    ("", False),
    ("Gmail", False),
    ("GMAIL", False),
    ("gmaiL", False),
    ("gmail" + _NEWLINE, False),
    (_NEWLINE + "gmail", False),
    ("gmail" + _NUL, False),
    ("gmail" + _TAB, False),
    ("gmail ", False),
    (" gmail", False),
    ("1gmail", False),
    ("_gmail", False),
    ("gmail-send", False),
    ("gmail.send", False),
    ("gmail send", False),
    ("gmail;drop", False),
    ("gmail'", False),
    ("gm" + _A_ACUTE + "il", False),
    ("s" + _CYRILLIC_IE + "nd", False),
    (_FULLWIDTH_A + "ction", False),
    ("send" + _ZERO_WIDTH_SPACE, False),
)


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _normalized(name: str) -> str:
    """A shipped migration, normalized outside literals only.

    ``--`` comments are blanked, whitespace is collapsed and keywords are
    lowercased; the contents of '...' and "..." are kept byte for byte.
    """
    raw = (db_mod._MIGRATIONS_DIR / name).read_text(encoding="utf-8")
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


def _migration_sql() -> str:
    return _normalized(_MIGRATION_NAME)


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


def _statements(name: str = _MIGRATION_NAME) -> list[str]:
    return _split(_normalized(name), ";")


def _create_table_body() -> str:
    for statement in _statements():
        masked = _masked(statement)
        match = re.match(rf"create\s+table\s+(?:if\s+not\s+exists\s+)?{_TABLE}\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        assert masked[end + 1 :].strip() == "", statement
        return statement[match.end() : end]
    pytest.fail(f"no CREATE TABLE {_TABLE} (...) in {_MIGRATION_NAME}")


def _elements() -> list[str]:
    return _split(_create_table_body(), ",")


def _columns() -> dict[str, str]:
    columns: dict[str, str] = {}
    for element in _elements():
        if re.match(_CONSTRAINT_START, _masked(element)):
            continue
        match = re.fullmatch(r'"?(\w+)"?\s+(.*)', element)
        assert match is not None, element
        columns[match.group(1)] = match.group(2)
    return columns


def _column(name: str) -> str:
    columns = _columns()
    assert name in columns, f"no column {name} in CREATE TABLE {_TABLE}"
    return columns[name]


def _table_constraints() -> list[str]:
    return [element for element in _elements() if re.match(_CONSTRAINT_START, _masked(element))]


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


def _check_expressions(column: str) -> list[str]:
    """The CHECKs on a column: inline on it, or table-level ones naming it."""
    expressions = _checks_in(_column(column))
    for constraint in _table_constraints():
        for expression in _checks_in(constraint):
            if re.search(rf"\b{column}\b", _masked(expression)):
                expressions.append(expression)
    return expressions


def _and_atoms(expression: str) -> list[str]:
    """The top-level AND-ed conditions of an expression, each unwrapped."""
    masked = _masked(expression)
    atoms: list[str] = []
    depth = 0
    start = 0
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


def _check_atoms(column: str) -> list[str]:
    atoms: list[str] = []
    for expression in _check_expressions(column):
        atoms.extend(_and_atoms(expression))
    return atoms


def _in_values(column: str) -> list[str] | None:
    """The literals of '<column> IN (...)' when a CHECK condition is exactly that."""
    for atom in _check_atoms(column):
        match = re.fullmatch(rf"{column}\s+in\s*\(([^)]*)\)", atom)
        if match is not None:
            return re.findall(r"'([^']*)'", match.group(1))
    return None


def _identifier_regex(column: str) -> str:
    """The one CHECK of an identifier column, which must be '<column> ~ '<regex>''."""
    atoms = _check_atoms(column)
    assert len(atoms) == 1, f"{_TABLE}.{column} needs exactly one CHECK condition: {atoms}"
    match = re.fullmatch(rf"{column}\s*~\s*'((?:[^']|'')*)'", atoms[0])
    assert match is not None, f"{_TABLE}.{column} CHECK is not a '~' regex: {atoms[0]}"
    return match.group(1).replace("''", "'")


def _sql_accepts(column: str, sample: str) -> bool:
    """Emulate PostgreSQL's CHECK (column ~ '^...$') on a sample value."""
    pattern = _identifier_regex(column)
    assert pattern.startswith("^"), pattern
    assert pattern.endswith("$"), pattern
    # PostgreSQL's '$' (not newline-sensitive) only matches at the very end, so
    # an anchored ~ is a full match of the inner pattern.
    return re.fullmatch(pattern[1:-1], sample) is not None


def _engine_accepts(sample: str) -> bool:
    return permissions_mod._VALID_IDENTIFIER.fullmatch(sample) is not None


def _patch_accepts(column: str, sample: str) -> bool:
    values = {"tool": "gmail", "action": "read", "permission": "deny", column: sample}
    try:
        PermissionPatch.model_validate(values)
    except ValidationError:
        return False
    return True


def _field_pattern(model: type[BaseModel], name: str) -> str:
    metadata = model.model_fields[name].metadata
    patterns = [item.pattern for item in metadata if getattr(item, "pattern", None)]
    assert len(patterns) == 1, f"{model.__name__}.{name} needs one pattern"
    return str(patterns[0])


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


def _primary_key() -> tuple[str, ...]:
    """The primary key columns, in declared order."""
    inline = [
        name
        for name, definition in _columns().items()
        if re.search(r"\bprimary\s+key\b", _masked(definition))
    ]
    table_level = [
        match.group(1)
        for constraint in _table_constraints()
        if (
            match := re.fullmatch(
                r"(?:constraint\s+\w+\s+)?primary\s+key\s*\(([^)]*)\)", _masked(constraint)
            )
        )
    ]
    assert len(inline) + len(table_level) == 1, "exactly one primary key"
    if inline:
        return (inline[0],)
    return tuple(column.strip().strip('"') for column in table_level[0].split(","))


def _foreign_key(column: str) -> tuple[str, str, str]:
    """(referenced table, referenced column, rest after the reference) for a column's FK."""
    pattern = r"references\s+(\w+)\s*(?:\(\s*(\w+)\s*\))?(.*)"
    inline = re.search(rf"\b{pattern}", _masked(_column(column)))
    if inline is not None:
        return inline.group(1), inline.group(2) or "id", inline.group(3)
    for constraint in _table_constraints():
        match = re.fullmatch(
            rf"(?:constraint\s+\w+\s+)?foreign\s+key\s*\(\s*{column}\s*\)\s*{pattern}",
            _masked(constraint),
        )
        if match is not None:
            return match.group(1), match.group(2) or "id", match.group(3)
    pytest.fail(f"{_TABLE}.{column} has no foreign key")


def _is_required(definition: str) -> bool:
    return re.search(r"\bnot\s+null\b", _masked(definition)) is not None


def _added_action_check(name: str = _MIGRATION_NAME) -> list[str]:
    """The action list of ADD CONSTRAINT audit_events_action_check CHECK (action IN (...))
    in a shipped migration, in written order (duplicates kept)."""
    for statement in _statements(name):
        masked = _masked(statement)
        match = re.search(r"\badd\s+constraint\s+audit_events_action_check\s+check\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        expression = _unwrap(statement[match.end() : end])
        listed = re.fullmatch(r"action\s+in\s*\(([^)]*)\)", expression)
        assert listed is not None, statement
        return re.findall(r"'([^']*)'", listed.group(1))
    pytest.fail(f"no ADD CONSTRAINT audit_events_action_check CHECK (action IN (...)) in {name}")


def _live_catalog() -> set[str]:
    from admino.audit_events import AuditAction

    return {action.value for action in AuditAction}


# ---------------------------------------------------------------------------
# Statement classification
# ---------------------------------------------------------------------------

_DROP_TABLE = rf"drop\s+table\s+(?:if\s+exists\s+)?{_TABLE}(?:\s+restrict)?"
_CREATE_TABLE = rf"create\s+table\s+(?:if\s+not\s+exists\s+)?{_TABLE}\s*\(.*\)"
_ALTER_AUDIT = r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?audit_events\s+(.*)"
_DROP_ACTION_CHECK = (
    r"drop\s+constraint\s+(?:if\s+exists\s+)?audit_events_action_check(?:\s+restrict)?"
)
_ADD_ACTION_CHECK = r"add\s+constraint\s+audit_events_action_check\s+check\s*\(.*\)"


def _audit_actions() -> list[tuple[int, str]]:
    """(statement index, kind) for every ALTER TABLE audit_events action, in order."""
    actions: list[tuple[int, str]] = []
    for index, statement in enumerate(_statements()):
        match = re.fullmatch(_ALTER_AUDIT, _masked(statement))
        if match is None:
            continue
        offset = match.start(1)
        for action in _split(statement[offset:], ","):
            masked = _masked(action)
            if re.fullmatch(_DROP_ACTION_CHECK, masked):
                actions.append((index, "drop check"))
            elif re.fullmatch(_ADD_ACTION_CHECK, masked):
                actions.append((index, "add check"))
            else:
                actions.append((index, f"unexpected: {action}"))
    return actions


def _kind(statement: str) -> str | None:
    masked = _masked(statement)
    if re.fullmatch(_DROP_TABLE, masked):
        return "drop table"
    if re.fullmatch(_CREATE_TABLE, masked):
        return "create table"
    if re.fullmatch(_ALTER_AUDIT, masked):
        return "alter audit_events"
    return None


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0016File:
    """The migration ships as version 16 and is applied by run_migrations."""

    def test_migration_0016_file_is_shipped_as_version_16(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0016_is_the_only_version_16(self) -> None:
        sixteens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert sixteens == [_MIGRATION_NAME]

    async def test_migration_0016_run_migrations_applies_it_as_version_16(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0015 applied, run_migrations executes the file and records 16."""
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

    async def test_migration_0016_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0016_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0016 recorded, the shipped SQL is not executed a second time."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0016_is_parameter_free(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked


# ---------------------------------------------------------------------------
# 2. Exactly the contract's statements
# ---------------------------------------------------------------------------


class TestMigration0016Statements:
    """Drop the global table, create the per-org one, replace the action check."""

    def test_migration_0016_every_statement_is_part_of_the_contract(self) -> None:
        for statement in _statements():
            assert _kind(statement) is not None, statement

    def test_migration_0016_drops_and_creates_the_permissions_table_once(self) -> None:
        kinds = [_kind(statement) for statement in _statements()]

        assert kinds.count("drop table") == 1
        assert kinds.count("create table") == 1

    def test_migration_0016_drops_the_old_table_before_creating_the_new(self) -> None:
        """The old global (tool, action) rows are not carried over."""
        kinds = [_kind(statement) for statement in _statements()]

        assert kinds.index("drop table") < kinds.index("create table")

    def test_migration_0016_drop_does_not_cascade(self) -> None:
        """Nothing depends on permissions; CASCADE could silently drop more."""
        drops = [s for s in _statements() if re.match(r"drop\b", _masked(s))]

        assert drops
        for statement in drops:
            assert re.search(r"\bcascade\b", _masked(statement)) is None, statement

    def test_migration_0016_audit_events_actions_are_only_the_action_check_swap(self) -> None:
        """audit_events gets exactly one DROP, then one ADD, of audit_events_action_check
        (in one ALTER TABLE or two)."""
        kinds = [kind for _, kind in _audit_actions()]

        assert kinds == ["drop check", "add check"]


# ---------------------------------------------------------------------------
# 3. The per-org permissions table
# ---------------------------------------------------------------------------


class TestMigration0016PermissionsTable:
    """One row per (org, tool, action): the org's permission state."""

    def test_migration_0016_permissions_has_exactly_the_contract_columns(self) -> None:
        assert set(_columns()) == set(_COLUMNS)

    def test_migration_0016_org_id_is_a_required_uuid(self) -> None:
        definition = _masked(_column("org_id"))

        assert re.match(r"uuid\b", definition), definition
        assert _is_required(definition), definition

    def test_migration_0016_org_id_references_organizations_on_delete_cascade(self) -> None:
        """The org purge removes the org's permission rows with it."""
        referenced, column, rest = _foreign_key("org_id")

        assert (referenced, column) == ("organizations", "id")
        assert re.search(r"\bon\s+delete\s+cascade\b", rest), rest

    def test_migration_0016_org_id_is_the_only_foreign_key(self) -> None:
        body = _masked(_create_table_body())

        assert len(re.findall(r"\breferences\b", body)) == 1

    @pytest.mark.parametrize("column", _IDENTIFIER_COLUMNS)
    def test_migration_0016_identifier_column_is_required_text(self, column: str) -> None:
        definition = _masked(_column(column))

        assert re.match(r"text\b", definition), definition
        assert _is_required(definition), definition

    @pytest.mark.parametrize("column", _IDENTIFIER_COLUMNS)
    def test_migration_0016_identifier_check_is_exactly_the_contract_regex(
        self, column: str
    ) -> None:
        """CHECK (<column> ~ '^[a-z][a-z0-9_]{0,62}$'), the literal byte for byte."""
        assert _identifier_regex(column) == _IDENTIFIER_REGEX

    @pytest.mark.parametrize("column", _IDENTIFIER_COLUMNS)
    def test_migration_0016_identifier_regex_equals_the_python_rules(self, column: str) -> None:
        """The SQL regex is the permission engine's and the API models' pattern."""
        assert permissions_mod._VALID_IDENTIFIER.pattern == _IDENTIFIER_REGEX
        assert _field_pattern(PermissionPatch, column) == _IDENTIFIER_REGEX
        assert _field_pattern(PermissionEntry, column) == _IDENTIFIER_REGEX
        assert _identifier_regex(column) == permissions_mod._VALID_IDENTIFIER.pattern

    @pytest.mark.parametrize("column", _IDENTIFIER_COLUMNS)
    @pytest.mark.parametrize(
        ("sample", "accepted"),
        _IDENTIFIER_SAMPLES,
        ids=[repr(s)[:40] for s, _ in _IDENTIFIER_SAMPLES],
    )
    def test_migration_0016_identifier_check_matches_the_python_validators(
        self, column: str, sample: str, accepted: bool
    ) -> None:
        """The DB CHECK, the engine's identifier rule and PermissionPatch agree."""
        assert _sql_accepts(column, sample) is accepted
        assert _engine_accepts(sample) is accepted
        assert _patch_accepts(column, sample) is accepted

    def test_migration_0016_permission_is_required_text(self) -> None:
        definition = _masked(_column("permission"))

        assert re.match(r"text\b", definition), definition
        assert _is_required(definition), definition

    def test_migration_0016_permission_check_equals_permission_state(self) -> None:
        """CHECK (permission IN ('allow', 'confirm', 'deny')): the engine's states."""
        values = _in_values("permission")

        assert set(typing.get_args(PermissionState)) == _STATES
        assert values is not None, _check_expressions("permission")
        assert sorted(values) == sorted(typing.get_args(PermissionState))

    def test_migration_0016_permission_check_is_the_only_condition(self) -> None:
        """No other condition widens or narrows the state list."""
        assert len(_check_atoms("permission")) == 1, _check_atoms("permission")

    def test_migration_0016_updated_at(self) -> None:
        definition = _masked(_column("updated_at"))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert _is_required(definition), definition
        assert re.fullmatch(_NOW, _default(definition) or ""), definition

    @pytest.mark.parametrize("column", ("org_id", "tool", "action", "permission"))
    def test_migration_0016_column_has_no_default(self, column: str) -> None:
        """No implicit org and no implicit permission state: nothing granted by omission."""
        assert _default(_column(column)) is None

    def test_migration_0016_primary_key_is_org_tool_action(self) -> None:
        """PRIMARY KEY (org_id, tool, action), org_id leading for the per-org reads."""
        assert _primary_key() == ("org_id", "tool", "action")

    def test_migration_0016_table_has_no_other_unique_or_exclusion_constraint(self) -> None:
        body = _masked(_create_table_body())

        assert re.search(r"\b(?:unique|exclude)\b", body) is None


# ---------------------------------------------------------------------------
# 4. The audit action catalog grows by the four permission actions
# ---------------------------------------------------------------------------


class TestMigration0016ActionCatalog:
    """audit_events_action_check is replaced with the 47-action catalog."""

    def test_migration_0016_action_check_adds_exactly_the_permission_actions(self) -> None:
        """The new list is 0010's 43 actions plus the four org.permission_* actions."""
        old = set(_added_action_check(_PREVIOUS_CATALOG_MIGRATION))
        new = set(_added_action_check())

        assert new - old == _NEW_ACTIONS
        assert old <= new
        assert len(new) == _CATALOG_SIZE

    def test_migration_0016_action_check_lists_each_action_once(self) -> None:
        listed = _added_action_check()

        assert len(listed) == len(set(listed)) == _CATALOG_SIZE

    @pytest.mark.parametrize("action", sorted(_NEW_ACTIONS))
    def test_migration_0016_action_check_contains_the_new_action(self, action: str) -> None:
        assert action in _added_action_check()

    def test_migration_0016_action_check_matches_audit_action(self) -> None:
        """The live catalog sync (moved here from test_migration_0010.py): the SQL action
        list equals AuditAction's values exactly."""
        assert set(_added_action_check()) == _live_catalog()

    def test_migration_0016_live_catalog_has_the_contract_size(self) -> None:
        assert len(_live_catalog()) == _CATALOG_SIZE


# ---------------------------------------------------------------------------
# 5. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0016NothingElse:
    """No other table, constraint, data, code or privilege changes."""

    def test_migration_0016_writes_no_data(self) -> None:
        """No seed rows (startup seeds every org) and no change to existing rows."""
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\b", masked) is None
        assert re.search(r"\bupdate\s+(?:only\s+)?\w+\s+set\b", masked) is None
        assert re.search(r"\bdelete\s+from\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None
        assert re.search(r"\bmerge\s+into\b", masked) is None
        assert re.search(r"\bcopy\b", masked) is None

    def test_migration_0016_drops_nothing_else(self) -> None:
        """The two drops are the old permissions table and the old action check."""
        assert len(re.findall(r"\bdrop\b", _masked(_migration_sql()))) == 2

    def test_migration_0016_alters_only_audit_events(self) -> None:
        masked = _masked(_migration_sql())
        targets = re.findall(r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", masked)

        assert targets
        assert set(targets) == {"audit_events"}
        assert len(re.findall(r"\balter\b", masked)) == len(targets)

    def test_migration_0016_defines_no_index_function_trigger_view_or_type(self) -> None:
        masked = _masked(_migration_sql())

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

    def test_migration_0016_creates_only_the_permissions_table(self) -> None:
        masked = _masked(_migration_sql())
        created = re.findall(
            r"\bcreate\s+(?:\w+\s+)*?table\s+(?:if\s+not\s+exists\s+)?(\w+)", masked
        )

        assert created == [_TABLE]

    def test_migration_0016_grants_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:grant|revoke)\b", masked) is None
