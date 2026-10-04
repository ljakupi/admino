"""Tests for migration 0023_org_settings_policies.sql — GH-169's org policies and instructions.

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0021.py / 0022 pattern): it must exist, be applied by
run_migrations as version 23 (after 0022), and make exactly the schema change
GH-169 needs. The SQL is read with ``--`` and ``/* */`` comments blanked;
statements are split outside parentheses and literals; keywords are compared
case-insensitively with whitespace collapsed. ALTER TABLE statements are split
into their sub-actions, so one combined ALTER and several separate ones read the
same, and a CHECK may be inline on its column or an ``ADD CONSTRAINT``; a range
may be written as ``BETWEEN`` or as two comparisons.

What these tests pin down (contract section 1):
- ``org_settings`` gains exactly four columns, each NOT NULL with a default and
  a named CHECK:
  - ``instructions TEXT NOT NULL DEFAULT ''`` with ``CONSTRAINT
    org_settings_instructions_check CHECK (char_length(instructions) <= 8000)``
    (characters, not bytes);
  - ``session_idle_timeout_minutes INTEGER NOT NULL DEFAULT 60`` with
    ``CONSTRAINT org_settings_session_idle_timeout_check`` (15 to 480);
  - ``session_max_lifetime_hours INTEGER NOT NULL DEFAULT 12`` with
    ``CONSTRAINT org_settings_session_lifetime_check`` (1 to 72);
  - ``trash_retention_days INTEGER NOT NULL DEFAULT 30`` with
    ``CONSTRAINT org_settings_trash_retention_check`` (0 to 90).
  The existing rows take the defaults, which satisfy every CHECK.
- The SQL bounds and defaults equal the Python ones: ``admino.sessions``'
  MIN/MAX/DEFAULT constants and ``SessionPolicy()``, the patch models
  (``OrgSecurityPatch``, ``OrgRetentionPatch``, ``OrgSettingsPatch.instructions``),
  ``OrgSettingsResponse.instructions``, the platform trash bounds' range
  (``PlatformRetention``) and the FakeDb (``db_fakes.ORG_POLICY_COLUMNS`` /
  ``db_fakes.ORG_INSTRUCTIONS_MAX``).
- A header comment explains the migration.
- Nothing else: only ``org_settings`` is altered and only by adding; no
  ``organizations`` change, no row written (no INSERT / UPDATE / DELETE /
  TRUNCATE / MERGE / COPY), no CREATE (table, index, function, trigger ...), no
  GRANT / REVOKE (0018's table-level grants on ``org_settings`` cover the new
  columns), no audit catalog change (``org.settings_change`` exists), no DO
  block or dynamic SQL, no SET, no CASCADE, parameter-free.

Security notes:
- The CHECKs mirror the Pydantic bounds, so the database refuses what the API
  refuses even if a write bypasses the models (an idle timeout of 0 or a
  lifetime of a year would keep sessions alive far past the policy; unbounded
  instructions would be fed to the LLM on every chat by #170).
- The migration grants nothing and never touches the append-only audit log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest
from pydantic import BaseModel, ValidationError

import admino.database as db_mod
import admino.models as models_module
from admino import audit_events, sessions
from tests import db_fakes

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0023_org_settings_policies.sql"
_PREVIOUS_MIGRATION = "0022_platform_model_policy.sql"
_VERSION = 23
_TABLE = "org_settings"

_INSTRUCTIONS = "instructions"
_INSTRUCTIONS_CONSTRAINT = "org_settings_instructions_check"
_INSTRUCTIONS_MAX = 8000

_IDLE = "session_idle_timeout_minutes"
_LIFETIME = "session_max_lifetime_hours"
_TRASH = "trash_retention_days"

# column -> (default, low, high, constraint name): the contract's INTEGER columns.
_INT_COLUMNS: dict[str, tuple[int, int, int, str]] = {
    _IDLE: (60, 15, 480, "org_settings_session_idle_timeout_check"),
    _LIFETIME: (12, 1, 72, "org_settings_session_lifetime_check"),
    _TRASH: (30, 0, 90, "org_settings_trash_retention_check"),
}
_NEW_COLUMNS = (_INSTRUCTIONS, *_INT_COLUMNS)
_CONSTRAINTS = frozenset({_INSTRUCTIONS_CONSTRAINT, *(v[3] for v in _INT_COLUMNS.values())})
_INTEGER_TYPES = frozenset({"integer", "int", "int4"})
# A character-count function: char_length / character_length / length count
# characters on TEXT; octet_length (bytes) is not one of them.
_CHAR_LENGTH = r"(?:char_length|character_length|length)"

# A valid OrgSettingsResponse besides the field under test (contract section 2).
_RESPONSE_BASE: dict[str, Any] = {
    "profile": {"display_name": "Treuhand Muster AG", "default_response_language": "en"},
    "instructions": "",
    "security": {_IDLE: 60, _LIFETIME: 12},
    "retention": {_TRASH: 30, "trash_min_days": 0, "trash_max_days": 90},
    "tools": {
        "gmail": True,
        "google_calendar": True,
        "google_drive": True,
        "outlook": True,
        "outlook_calendar": True,
        "onedrive": True,
        "memory": True,
    },
    "data_residency": False,
    "plan": {"seats": 10, "storage_quota": 5 * 1024**3},
}


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _normalized(name: str) -> str:
    """A shipped migration, normalized outside literals only.

    ``--`` and ``/* */`` comments are blanked, whitespace is collapsed and
    keywords are lowercased; the contents of '...' and "..." are kept byte for
    byte.
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
        elif raw.startswith("--", index) or raw.startswith("/*", index):
            if raw.startswith("--", index):
                end = raw.find("\n", index)
                index = len(raw) if end < 0 else end
            else:
                end = raw.find("*/", index + 2)
                index = len(raw) if end < 0 else end + 2
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


def _statements() -> list[str]:
    return _split(_migration_sql(), ";")


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    while (
        expression.startswith("(") and _balanced_end(_masked(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _atoms(expression: str) -> list[str]:
    """The top-level AND-ed conditions of a CHECK expression, each unwrapped.

    ``x BETWEEN a AND b`` is rewritten to ``x >= a AND x <= b`` first, so the
    AND of a BETWEEN is never split.
    """
    expression = re.sub(
        r"\b(\w+)\s+between\s+(-?\d[\d_]*)\s+and\s+(-?\d[\d_]*)",
        r"\1 >= \2 and \1 <= \3",
        _unwrap(expression),
    )
    masked = _masked(expression)
    atoms: list[str] = []
    depth = 0
    start = 0
    for token in re.finditer(r"\(|\)|\band\b", masked):
        if token.group(0) == "(":
            depth += 1
        elif token.group(0) == ")":
            depth -= 1
        elif depth == 0:
            atoms.append(_unwrap(expression[start : token.start()]))
            start = token.end()
    atoms.append(_unwrap(expression[start:]))
    return atoms


def _comparison(atom: str) -> tuple[str, str, int] | None:
    """(column, operator, value) of '<col> op <int>' or '<int> op <col>'; operator as col op v."""
    forward = re.fullmatch(r"(\w+)\s*(>=|>|<=|<)\s*(-?\d[\d_]*)", atom)
    if forward is not None:
        return forward.group(1), forward.group(2), int(forward.group(3))
    backward = re.fullmatch(r"(-?\d[\d_]*)\s*(>=|>|<=|<)\s*(\w+)", atom)
    if backward is not None:
        flipped = {">=": "<=", ">": "<", "<=": ">=", "<": ">"}
        return backward.group(3), flipped[backward.group(2)], int(backward.group(1))
    return None


# ---------------------------------------------------------------------------
# Statement classification
# ---------------------------------------------------------------------------

_ALTER_TABLE = r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)\s+(.*)"
_ADD_COLUMN = r"add\s+(?:column\s+)?(\w+)\s+(.*)"
_ADD_CONSTRAINT = r"add\s+constraint\s+(\w+)\s+check\s*\((.*)\)"


def _sub_actions() -> list[tuple[int, str, str]]:
    """(statement index, table, sub-action) for every ALTER TABLE sub-action, in order.

    A statement that is not an ALTER TABLE is reported with an empty table name
    and the whole statement.
    """
    actions: list[tuple[int, str, str]] = []
    for index, statement in enumerate(_statements()):
        match = re.fullmatch(_ALTER_TABLE, _masked(statement))
        if match is None:
            actions.append((index, "", f"statement: {statement}"))
            continue
        for action in _split(statement[match.start(2) :], ","):
            actions.append((index, match.group(1), action))
    return actions


def _kind(table: str, action: str) -> str:
    """Classify one sub-action against the contract; anything else is "unexpected: ..."."""
    masked = _masked(action)
    if table == _TABLE:
        constraint = re.fullmatch(_ADD_CONSTRAINT, masked)
        if constraint is not None and constraint.group(1) in _CONSTRAINTS:
            return f"add constraint {constraint.group(1)}"
        column = re.fullmatch(_ADD_COLUMN, masked)
        if (
            constraint is None
            and column is not None
            and column.group(1) != "constraint"
            and column.group(1) in _NEW_COLUMNS
        ):
            return f"add column {column.group(1)}"
    return f"unexpected: {action}"


def _kinds() -> list[tuple[int, str, str]]:
    return [(index, table, _kind(table, action)) for index, table, action in _sub_actions()]


@dataclass
class _ColumnDefinition:
    """One parsed ``ADD COLUMN <name> <type> <constraints...>``."""

    type_name: str
    not_null: bool = False
    explicit_null: bool = False
    defaults: list[str] = field(default_factory=list)
    checks: list[tuple[str | None, str]] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)


def _parse_column(definition: str) -> _ColumnDefinition:
    """Parse the part after the column name: a type, then NOT NULL / NULL / DEFAULT /
    [CONSTRAINT name] CHECK (...) in any order; anything else is unexpected."""
    masked = _masked(definition)
    type_match = re.match(r"(\w+(?:\s*\([^)]*\))?)\s*", masked)
    assert type_match is not None, f"no column type in {definition!r}"
    column = _ColumnDefinition(type_name=type_match.group(1))
    position = type_match.end()
    while position < len(masked):
        rest = masked[position:]
        if step := re.match(r"not\s+null\b\s*", rest):
            column.not_null = True
        elif step := re.match(r"null\b\s*", rest):
            column.explicit_null = True
        elif step := re.match(r"default\s+('[^']*'(?:\s*::\s*\w+)?|-?\w+)\s*", rest):
            column.defaults.append(definition[position + step.start(1) : position + step.end(1)])
        elif step := re.match(r"(?:constraint\s+(\w+)\s+)?check\s*\(", rest):
            open_index = position + step.end() - 1
            end = _balanced_end(masked, open_index)
            column.checks.append((step.group(1), definition[open_index + 1 : end]))
            position = end + 1
            while position < len(masked) and masked[position] == " ":
                position += 1
            continue
        else:
            column.unexpected.append(definition[position:])
            break
        position += step.end()
    return column


def _columns() -> dict[str, list[_ColumnDefinition]]:
    """Every column ADDed to org_settings, by name (a name added twice has two entries)."""
    columns: dict[str, list[_ColumnDefinition]] = {}
    for _, table, action in _sub_actions():
        masked = _masked(action)
        if table != _TABLE or re.match(r"add\s+constraint\b", masked):
            continue
        match = re.fullmatch(_ADD_COLUMN, masked)
        if match is None:
            continue
        columns.setdefault(match.group(1), []).append(_parse_column(action[match.start(2) :]))
    return columns


def _column(name: str) -> _ColumnDefinition:
    definitions = _columns().get(name, [])
    assert len(definitions) == 1, f"org_settings.{name} must be added exactly once: {definitions}"
    return definitions[0]


def _checks() -> list[tuple[str | None, str]]:
    """Every CHECK the migration puts on org_settings: (constraint name or None, expression).

    Inline column constraints and ``ADD CONSTRAINT ... CHECK`` sub-actions both count.
    """
    checks: list[tuple[str | None, str]] = []
    for definitions in _columns().values():
        for definition in definitions:
            checks.extend(definition.checks)
    for _, table, action in _sub_actions():
        match = re.fullmatch(_ADD_CONSTRAINT, _masked(action))
        if table == _TABLE and match is not None:
            checks.append((match.group(1), action[match.start(2) : match.end(2)]))
    return checks


def _check_expression(constraint: str) -> str:
    found = [expression for name, expression in _checks() if name == constraint]
    assert len(found) == 1, f"{constraint} must be defined exactly once: {found}"
    return found[0]


def _int_default(column: str) -> int:
    defaults = _column(column).defaults
    assert len(defaults) == 1, (column, defaults)
    assert re.fullmatch(r"-?\d+", defaults[0]), (column, defaults)
    return int(defaults[0])


def _bounds(column: str) -> tuple[int | None, int | None]:
    """The inclusive (low, high) range the column's named CHECK allows."""
    low: int | None = None
    high: int | None = None
    for atom in _atoms(_check_expression(_INT_COLUMNS[column][3])):
        parsed = _comparison(atom)
        if parsed is None or parsed[0] != column:
            continue
        _, operator, value = parsed
        if operator == ">=":
            low = value
        elif operator == ">":
            low = value + 1
        elif operator == "<=":
            high = value
        else:
            high = value - 1
    return low, high


def _shipped_bounds(column: str) -> tuple[int, int]:
    low, high = _bounds(column)
    assert low is not None, column
    assert high is not None, column
    return low, high


def _instructions_max() -> int:
    """The N of the instructions CHECK, ``char_length(instructions) <= N``."""
    expression = _unwrap(_check_expression(_INSTRUCTIONS_CONSTRAINT))
    inclusive = re.fullmatch(
        rf"{_CHAR_LENGTH}\s*\(\s*{_INSTRUCTIONS}\s*\)\s*<=\s*(\d+)", _masked(expression)
    )
    if inclusive is not None:
        return int(inclusive.group(1))
    exclusive = re.fullmatch(
        rf"{_CHAR_LENGTH}\s*\(\s*{_INSTRUCTIONS}\s*\)\s*<\s*(\d+)", _masked(expression)
    )
    assert exclusive is not None, expression
    return int(exclusive.group(1)) - 1


# ---------------------------------------------------------------------------
# Helpers: the Python side
# ---------------------------------------------------------------------------


def _model(name: str) -> type[BaseModel]:
    """A GH-169 model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-169)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _accepts(model: type[BaseModel], payload: dict[str, Any]) -> bool:
    try:
        model.model_validate(payload)
    except ValidationError:
        return False
    return True


def _assert_bounds(
    model: type[BaseModel], base: dict[str, Any], field_name: str, low: int, high: int
) -> None:
    """The model takes low and high for the field and refuses low - 1 and high + 1."""
    name = model.__name__
    assert _accepts(model, {**base, field_name: low}), (name, field_name, low)
    assert _accepts(model, {**base, field_name: high}), (name, field_name, high)
    assert not _accepts(model, {**base, field_name: low - 1}), (name, field_name, low - 1)
    assert not _accepts(model, {**base, field_name: high + 1}), (name, field_name, high + 1)


def _header_comment_lines() -> list[str]:
    """The ``--`` lines at the top of the raw file, before the first statement."""
    lines: list[str] = []
    for line in _migration_path().read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped and not lines:
            continue
        if not stripped.startswith("--"):
            break
        lines.append(stripped)
    return lines


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0023File:
    """The migration ships as version 23 and is applied by run_migrations after 0022."""

    def test_migration_0023_file_is_shipped_as_version_23(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0023_is_the_only_version_23(self) -> None:
        twenty_threes = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert twenty_threes == [_MIGRATION_NAME]

    async def test_migration_0023_run_migrations_applies_it_as_version_23(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0022 applied, run_migrations executes the file and records 23."""
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

    async def test_migration_0023_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0023_runs_after_0022(self, mock_pool: MagicMock) -> None:
        """With 0001 to 0021 applied, 0022 is executed before 0023."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert shipped in executed
        assert previous in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0023_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0023 applied, the file is not executed or recorded again."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert shipped not in executed

    def test_migration_0023_is_parameter_free(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked

    def test_migration_0023_starts_with_a_header_comment(self) -> None:
        """A ``--`` header (purpose, defaults, no row written) before the first statement,
        naming the table it changes."""
        header = _header_comment_lines()

        assert len(header) >= 3, header
        assert any(_TABLE in line for line in header), header


# ---------------------------------------------------------------------------
# 2. Only additions to org_settings
# ---------------------------------------------------------------------------


class TestMigration0023Statements:
    """ALTER TABLE org_settings ADD COLUMN x 4 (with their named CHECKs), nothing else."""

    def test_migration_0023_has_statements(self) -> None:
        assert _statements()

    def test_migration_0023_every_statement_is_part_of_the_contract(self) -> None:
        """Every statement is an ALTER TABLE of org_settings, and every sub-action adds
        one of the four columns or one of their four named CHECKs."""
        unexpected = [kind for _, _, kind in _kinds() if kind.startswith("unexpected")]

        assert unexpected == []

    def test_migration_0023_adds_exactly_the_four_columns_once_each(self) -> None:
        added = sorted(kind for _, _, kind in _kinds() if kind.startswith("add column"))

        assert added == sorted(f"add column {column}" for column in _NEW_COLUMNS)

    def test_migration_0023_alters_exactly_org_settings(self) -> None:
        tables = {table for _, table, _ in _kinds()}

        assert tables == {_TABLE}

    def test_migration_0023_org_settings_has_only_the_four_named_checks(self) -> None:
        """No unnamed CHECK and no other constraint on org_settings."""
        names = sorted(str(name) for name, _ in _checks())

        assert names == sorted(_CONSTRAINTS)


# ---------------------------------------------------------------------------
# 3. org_settings.instructions
# ---------------------------------------------------------------------------


class TestMigration0023Instructions:
    """org_settings.instructions: TEXT NOT NULL DEFAULT '', at most 8000 characters."""

    def test_migration_0023_instructions_is_text(self) -> None:
        assert _column(_INSTRUCTIONS).type_name == "text"

    def test_migration_0023_instructions_is_not_null(self) -> None:
        """'' means "no instructions"; there is no second empty state."""
        column = _column(_INSTRUCTIONS)

        assert column.not_null is True
        assert column.explicit_null is False

    def test_migration_0023_instructions_defaults_to_empty(self) -> None:
        """Existing orgs get no instructions (the default fills the column, no UPDATE)."""
        defaults = _column(_INSTRUCTIONS).defaults

        assert len(defaults) == 1
        assert re.fullmatch(r"''(?:\s*::\s*text)?", defaults[0]), defaults

    def test_migration_0023_instructions_column_has_nothing_else(self) -> None:
        assert _column(_INSTRUCTIONS).unexpected == []

    def test_migration_0023_instructions_check_is_named(self) -> None:
        names = [name for name, _ in _checks()]

        assert names.count(_INSTRUCTIONS_CONSTRAINT) == 1

    def test_migration_0023_instructions_check_counts_characters_up_to_8000(self) -> None:
        """Exactly char_length(instructions) <= 8000: characters, not bytes
        (octet_length would refuse 8000 characters of accented text or emoji)."""
        expression = _unwrap(_check_expression(_INSTRUCTIONS_CONSTRAINT))

        assert re.fullmatch(
            rf"{_CHAR_LENGTH}\s*\(\s*{_INSTRUCTIONS}\s*\)\s*<=\s*{_INSTRUCTIONS_MAX}",
            _masked(expression),
        ), expression


# ---------------------------------------------------------------------------
# 4. The three INTEGER policy columns
# ---------------------------------------------------------------------------


class TestMigration0023IntegerColumns:
    """INTEGER NOT NULL DEFAULT d CONSTRAINT <name> CHECK (<column> BETWEEN low AND high)."""

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0023_int_column_is_an_integer(self, column: str) -> None:
        assert _column(column).type_name in _INTEGER_TYPES

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0023_int_column_is_not_null(self, column: str) -> None:
        definition = _column(column)

        assert definition.not_null is True
        assert definition.explicit_null is False

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0023_int_column_default_is_the_contract_default(self, column: str) -> None:
        """The existing org_settings rows take this value."""
        assert _int_default(column) == _INT_COLUMNS[column][0]

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0023_int_column_has_nothing_else(self, column: str) -> None:
        assert _column(column).unexpected == []

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0023_int_column_check_is_named(self, column: str) -> None:
        names = [name for name, _ in _checks()]

        assert names.count(_INT_COLUMNS[column][3]) == 1

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0023_int_column_check_only_bounds_its_column(self, column: str) -> None:
        """Every condition of the named CHECK is '<column> op <int>' on that column."""
        atoms = _atoms(_check_expression(_INT_COLUMNS[column][3]))

        assert atoms
        for atom in atoms:
            parsed = _comparison(atom)
            assert parsed is not None, atom
            assert parsed[0] == column, atom

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0023_int_column_bounds_are_the_contract_bounds(self, column: str) -> None:
        _, low, high, _ = _INT_COLUMNS[column]

        assert _bounds(column) == (low, high)

    def test_migration_0023_defaults_satisfy_every_check(self) -> None:
        """Adding the columns to the existing org_settings rows can't fail a CHECK."""
        for column in _INT_COLUMNS:
            low, high = _shipped_bounds(column)
            assert low <= _int_default(column) <= high, column


# ---------------------------------------------------------------------------
# 5. SQL and Python stay in sync
# ---------------------------------------------------------------------------


class TestMigration0023MatchesPython:
    """The SQL defaults and bounds equal the sessions constants and the Pydantic models'."""

    def test_migration_0023_idle_timeout_matches_the_sessions_constants(self) -> None:
        assert _shipped_bounds(_IDLE) == (
            sessions.MIN_IDLE_TIMEOUT_MINUTES,
            sessions.MAX_IDLE_TIMEOUT_MINUTES,
        )
        assert _int_default(_IDLE) == sessions.DEFAULT_IDLE_TIMEOUT_MINUTES

    def test_migration_0023_lifetime_matches_the_sessions_constants(self) -> None:
        assert _shipped_bounds(_LIFETIME) == (
            sessions.MIN_LIFETIME_HOURS,
            sessions.MAX_LIFETIME_HOURS,
        )
        assert _int_default(_LIFETIME) == sessions.DEFAULT_LIFETIME_HOURS

    def test_migration_0023_session_defaults_equal_the_session_policy_defaults(self) -> None:
        """A missing org_settings row reads as SessionPolicy() (contract section 4): the
        column defaults must be the same 60 minutes / 12 hours."""
        policy = sessions.SessionPolicy()

        assert policy.idle_timeout_minutes == _int_default(_IDLE)
        assert policy.max_lifetime_hours == _int_default(_LIFETIME)

    def test_migration_0023_session_bounds_equal_the_session_policy_bounds(self) -> None:
        idle_low, idle_high = _shipped_bounds(_IDLE)
        life_low, life_high = _shipped_bounds(_LIFETIME)

        _assert_bounds(sessions.SessionPolicy, {}, "idle_timeout_minutes", idle_low, idle_high)
        _assert_bounds(sessions.SessionPolicy, {}, "max_lifetime_hours", life_low, life_high)

    @pytest.mark.parametrize("column", [_IDLE, _LIFETIME])
    def test_migration_0023_session_bounds_match_the_security_patch(self, column: str) -> None:
        low, high = _shipped_bounds(column)

        _assert_bounds(_model("OrgSecurityPatch"), {}, column, low, high)

    def test_migration_0023_trash_retention_bounds_match_the_retention_patch(self) -> None:
        low, high = _shipped_bounds(_TRASH)

        _assert_bounds(_model("OrgRetentionPatch"), {}, _TRASH, low, high)

    @pytest.mark.parametrize(
        ("bound", "base"),
        [
            ("trash_min_days", {"trash_max_days": 90}),
            ("trash_max_days", {"trash_min_days": 0}),
        ],
    )
    def test_migration_0023_trash_retention_range_is_the_platform_trash_range(
        self, bound: str, base: dict[str, int]
    ) -> None:
        """The org value is clamped into the platform bounds, which live in the same 0..90."""
        from admino.models import PlatformRetention

        low, high = _shipped_bounds(_TRASH)

        _assert_bounds(PlatformRetention, base, bound, low, high)

    def test_migration_0023_instructions_bound_matches_the_patch_model(self) -> None:
        patch = _model("OrgSettingsPatch")
        limit = _instructions_max()

        assert limit == _INSTRUCTIONS_MAX
        assert _accepts(patch, {_INSTRUCTIONS: "a" * limit})
        assert not _accepts(patch, {_INSTRUCTIONS: "a" * (limit + 1)})

    def test_migration_0023_instructions_bound_matches_the_response_model(self) -> None:
        response = _model("OrgSettingsResponse")
        limit = _instructions_max()

        assert _accepts(response, {**_RESPONSE_BASE, _INSTRUCTIONS: "a" * limit})
        assert not _accepts(response, {**_RESPONSE_BASE, _INSTRUCTIONS: "a" * (limit + 1)})

    def test_migration_0023_the_fake_database_mirrors_the_migration(self) -> None:
        """tests/db_fakes.py enforces exactly the shipped defaults and CHECKs."""
        shipped = {
            column: (_int_default(column), *_shipped_bounds(column))
            for column in sorted(_INT_COLUMNS)
        }

        assert shipped == dict(db_fakes.ORG_POLICY_COLUMNS)
        assert _instructions_max() == db_fakes.ORG_INSTRUCTIONS_MAX


# ---------------------------------------------------------------------------
# 6. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0023NothingElse:
    """No other table, column, constraint, data, code or privilege changes."""

    def test_migration_0023_writes_no_data(self) -> None:
        """No row is changed, added or deleted: the defaults fill the new columns."""
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\b", masked) is None
        assert re.search(r"\bupdate\b", masked) is None
        assert re.search(r"\bdelete\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None
        assert re.search(r"\bmerge\b", masked) is None
        assert re.search(r"\bcopy\b", masked) is None

    def test_migration_0023_drops_nothing(self) -> None:
        assert re.search(r"\bdrop\b", _masked(_migration_sql())) is None

    def test_migration_0023_alters_only_org_settings(self) -> None:
        masked = _masked(_migration_sql())
        targets = re.findall(r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", masked)

        assert targets
        assert set(targets) == {_TABLE}
        assert len(re.findall(r"\balter\b", masked)) == len(targets)

    def test_migration_0023_leaves_organizations_alone(self) -> None:
        """The display name and response language already live on organizations (0004,
        0020): nothing there changes."""
        assert re.search(r"\borganizations\b", _masked(_migration_sql())) is None

    def test_migration_0023_changes_no_existing_column(self) -> None:
        """Only ADD COLUMN: no ALTER/DROP/RENAME COLUMN, no type change."""
        masked = _masked(_migration_sql())

        assert all(word == "add" for word in re.findall(r"(\w+)\s+column\b", masked))
        assert re.search(r"\brename\b", masked) is None
        assert re.search(r"\btype\b", masked) is None
        assert re.search(r"\busing\b", masked) is None

    def test_migration_0023_creates_nothing(self) -> None:
        """No table (so no grant is owed to the runtime role), index, function, trigger,
        view, type, sequence, role or extension."""
        assert re.search(r"\bcreate\b", _masked(_migration_sql())) is None

    def test_migration_0023_adds_no_key_reference_or_index(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:unique|primary|references|foreign|exclude|index)\b", masked) is None

    def test_migration_0023_runs_no_code(self) -> None:
        """No DO block, dollar-quoted body, function, trigger or dynamic SQL."""
        masked = _masked(_migration_sql())

        assert "$" not in masked
        assert re.search(r"\bdo\b", masked) is None
        assert re.search(r"\bexecute\b", masked) is None
        assert re.search(r"\b(?:function|procedure|trigger)\b", masked) is None

    def test_migration_0023_grants_nothing(self) -> None:
        """0018's table-level grants on org_settings cover the new columns."""
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:grant|revoke|owner|role|policy|security)\b", masked) is None

    def test_migration_0023_sets_no_parameter_and_cascades_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:set|reset)\b", masked) is None
        assert re.search(r"\bcascade\b", masked) is None

    def test_migration_0023_leaves_the_audit_catalog_alone(self) -> None:
        """org.settings_change is already in the catalog (0005/0013)."""
        assert audit_events.AuditAction.ORG_SETTINGS_CHANGE.value == "org.settings_change"
        masked = _masked(_migration_sql())
        assert "audit_events" not in masked
        assert "action_check" not in masked
