"""Tests for migration 0022_platform_model_policy.sql — the V1 model policy columns (GH-242).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0014.py pattern): it must exist, be applied by
run_migrations as version 22, and make exactly the schema change GH-242 needs.
The SQL is read with ``--`` and ``/* */`` comments blanked; statements are split
outside parentheses and literals; keywords are compared case-insensitively with
whitespace collapsed. ALTER TABLE statements are split into their actions, so
one combined ALTER and several separate ones read the same. A range may be
written as ``BETWEEN`` or as two comparisons, and a CHECK may be inline on its
column or an added table constraint.

What these tests pin down:
- ``ALTER TABLE platform_settings ADD COLUMN`` for exactly three columns:
  - ``max_input_tokens INTEGER NOT NULL DEFAULT 200000`` with a CHECK of
    exactly ``BETWEEN 1000 AND 2000000`` (the platform model's input window);
  - ``image_input BOOLEAN NOT NULL DEFAULT true`` (whether the platform model
    takes images), with no CHECK;
  - ``llm_max_retries INTEGER NOT NULL DEFAULT 2`` with a CHECK of exactly
    ``BETWEEN 0 AND 5`` (the retries of a retryable LLM failure).
  The existing platform row takes the defaults (which satisfy every CHECK), so
  no UPDATE is needed.
- The SQL defaults and bounds equal the Python ones: ``LLMConfig``
  (``max_input_tokens`` / ``image_input``), ``scoped_settings.StoredPlatformLLM``
  and ``models.SettingsLLM`` (all three fields, the column ``llm_max_retries``
  being the field ``max_retries``), the bounds of ``models.SettingsPatchLLM``
  and of ``AgentConfig.llm_max_retries``; the FakeDb
  (``db_fakes.PLATFORM_LLM_LIMITS`` and its ``image_input`` default) mirrors
  the migration.
- Nothing else: only ``platform_settings`` is altered and only by adding; no
  DROP, no UPDATE / DELETE / TRUNCATE / MERGE, no INSERT / COPY, no table,
  index, function, trigger, view, type or DO block, no GRANT / REVOKE (0018's
  table-level grants cover the new columns), no audit catalog change
  (``platform.settings_change`` already exists), parameter-free.

Security notes:
- The CHECKs mirror the Pydantic bounds, so the database refuses what the API
  refuses even if a write bypasses the models (for example 50 retries, which
  would multiply a provider's load, or an input window of 0 tokens).
- The migration never touches the append-only audit log and grants nothing.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest
from pydantic import BaseModel, ValidationError

import admino.database as db_mod
from admino import audit_events
from tests import db_fakes

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0022_platform_model_policy.sql"
_PREVIOUS_MIGRATION = "0021_account_self_service.sql"
_VERSION = 22
_TABLE = "platform_settings"

# column -> (default, low, high): the contract's integer columns.
_INT_COLUMNS: dict[str, tuple[int, int, int]] = {
    "max_input_tokens": (200_000, 1000, 2_000_000),
    "llm_max_retries": (2, 0, 5),
}
_BOOL_COLUMN = "image_input"
_ALL_COLUMNS = (*_INT_COLUMNS, _BOOL_COLUMN)
# The Python field of each integer column (the column llm_max_retries is max_retries).
_FIELD_OF: dict[str, str] = {
    "max_input_tokens": "max_input_tokens",
    "llm_max_retries": "max_retries",
}
_INTEGER = r"(?:integer|int4|int)\b"
_BOOLEAN = r"(?:boolean|bool)\b"
_CONSTRAINT_START = (
    r"(?:constraint\s+\w+\s+)?(?:check|unique|primary\s+key|foreign\s+key|exclude)\b"
)
_ALTER_RE = re.compile(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)\s+(.*)", re.DOTALL)
# What StoredPlatformLLM / SettingsLLM need besides the field under test.
_STORED_LLM_BASE: dict[str, Any] = {
    "provider": "infomaniak",
    "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
    "vllm_model": None,
    "anthropic_model": None,
    "openai_model": None,
}
_SETTINGS_LLM_BASE: dict[str, Any] = {
    "provider": "infomaniak",
    "anthropic_model": "",
    "openai_model": "",
}


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _migration_sql() -> str:
    """The shipped migration, normalized outside literals only.

    ``--`` and ``/* */`` comments are blanked, whitespace is collapsed and
    keywords are lowercased; the contents of '...' and "..." are kept byte for
    byte.
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


def _classify(action: str) -> tuple[str, str, str]:
    """('column', name, definition), ('constraint', '', text) or ('other', '', action)."""
    masked = _masked(action)
    add = re.match(r"add\s+", masked)
    if add is None:
        return "other", "", action
    explicit_column = re.match(r"add\s+column\s+(?:if\s+not\s+exists\s+)?", masked)
    if explicit_column is None and re.match(_CONSTRAINT_START, masked[add.end() :]):
        return "constraint", "", action[add.end() :]
    start = add.end() if explicit_column is None else explicit_column.end()
    column = re.fullmatch(r'"?(\w+)"?\s+(.*)', action[start:], re.DOTALL)
    if column is None:
        return "other", "", action
    return "column", column.group(1), column.group(2)


def _added_columns() -> list[tuple[str, str]]:
    """(column, definition) for every ADD COLUMN on platform_settings, in order."""
    return [
        (name, definition)
        for table, action in _actions()
        if table == _TABLE
        for kind, name, definition in [_classify(action)]
        if kind == "column"
    ]


def _column(name: str) -> str:
    columns = dict(_added_columns())
    assert name in columns, f"no ADD COLUMN {name} in {_MIGRATION_NAME}"
    return columns[name]


def _table_constraints() -> list[str]:
    return [
        text
        for table, action in _actions()
        if table == _TABLE
        for kind, _, text in [_classify(action)]
        if kind == "constraint"
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


def _and_atoms(expression: str) -> list[str]:
    """The top-level AND-ed conditions of an expression, each unwrapped.

    ``x BETWEEN a AND b`` is rewritten to ``x >= a AND x <= b`` first.
    """
    expression = re.sub(
        r"\b(\w+)\s+between\s+(-?\d[\d_]*)\s+and\s+(-?\d[\d_]*)",
        r"\1 >= \2 and \1 <= \3",
        expression,
    )
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


def _all_check_atoms() -> list[tuple[str | None, str]]:
    """(owning column or None for a table constraint, atom) for every CHECK condition."""
    atoms: list[tuple[str | None, str]] = []
    for name, definition in _added_columns():
        for expression in _checks_in(definition):
            atoms.extend((name, atom) for atom in _and_atoms(expression))
    for constraint in _table_constraints():
        for expression in _checks_in(constraint):
            atoms.extend((None, atom) for atom in _and_atoms(expression))
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


def _bounds(column: str) -> tuple[int | None, int | None]:
    """The inclusive (low, high) range the CHECKs allow for a column."""
    low: int | None = None
    high: int | None = None
    for _, atom in _all_check_atoms():
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


def _int_default(definition: str) -> int | None:
    """The integer DEFAULT of a column definition (optionally parenthesized)."""
    match = re.search(r"\bdefault\s+\(?\s*(-?\d[\d_]*)\s*\)?", _masked(definition))
    return None if match is None else int(match.group(1))


def _bool_default(definition: str) -> bool | None:
    """The boolean DEFAULT (true / false, optionally parenthesized) of a column definition."""
    match = re.search(r"\bdefault\s+\(?\s*(true|false)\b", _masked(definition))
    return None if match is None else match.group(1) == "true"


def _is_required(definition: str) -> bool:
    return re.search(r"\bnot\s+null\b", _masked(definition)) is not None


def _accepts(model: type[BaseModel], base: dict[str, Any], field: str, value: object) -> bool:
    try:
        model.model_validate({**base, field: value})
    except ValidationError:
        return False
    return True


def _assert_bounds(
    model: type[BaseModel], base: dict[str, Any], field: str, low: int, high: int
) -> None:
    """The model takes low and high for the field and refuses low - 1 and high + 1."""
    assert _accepts(model, base, field, low), (model.__name__, field, low)
    assert _accepts(model, base, field, high), (model.__name__, field, high)
    assert not _accepts(model, base, field, low - 1), (model.__name__, field, low - 1)
    assert not _accepts(model, base, field, high + 1), (model.__name__, field, high + 1)


def _stored_llm_model() -> Any:
    """scoped_settings.StoredPlatformLLM (looked up per test)."""
    from admino import scoped_settings

    return scoped_settings.StoredPlatformLLM


def _shipped_int_bounds(column: str) -> tuple[int, int]:
    low, high = _bounds(column)
    assert low is not None, column
    assert high is not None, column
    return low, high


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0022File:
    """The migration ships as version 22 and is applied by run_migrations."""

    def test_migration_0022_file_is_shipped_as_version_22(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0022_is_the_only_version_22(self) -> None:
        twenty_twos = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert twenty_twos == [_MIGRATION_NAME]

    async def test_migration_0022_run_migrations_applies_it_as_version_22(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0021 applied, run_migrations executes the file and records 22."""
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

    async def test_migration_0022_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0022_runs_after_0021(self, mock_pool: MagicMock) -> None:
        """With 0001 to 0020 applied, 0021 is executed before 0022."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert shipped in executed
        assert previous in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0022_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0022 applied, the file is not executed or recorded again."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert shipped not in executed

    def test_migration_0022_is_parameter_free(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked


# ---------------------------------------------------------------------------
# 2. Only additions to platform_settings
# ---------------------------------------------------------------------------


class TestMigration0022Statements:
    """ALTER TABLE platform_settings ADD COLUMN x 3 (and, optionally, their CHECKs)."""

    def test_migration_0022_every_statement_alters_platform_settings(self) -> None:
        statements = _statements()

        assert statements
        for statement in statements:
            match = _ALTER_RE.fullmatch(_masked(statement))
            assert match is not None, statement
            assert match.group(1) == _TABLE, statement

    def test_migration_0022_every_action_is_an_add(self) -> None:
        """No DROP / SET / ALTER COLUMN / RENAME action: columns and CHECKs are only added."""
        actions = _actions()

        assert actions
        for _, action in actions:
            assert _classify(action)[0] in {"column", "constraint"}, action

    def test_migration_0022_adds_exactly_the_three_columns_once_each(self) -> None:
        added = [name for name, _ in _added_columns()]

        assert sorted(added) == sorted(_ALL_COLUMNS)

    def test_migration_0022_added_constraints_are_checks_only(self) -> None:
        """No UNIQUE, PRIMARY KEY, FOREIGN KEY or EXCLUDE constraint is added."""
        for constraint in _table_constraints():
            assert re.match(r"(?:constraint\s+\w+\s+)?check\b", _masked(constraint)), constraint

    def test_migration_0022_every_check_condition_bounds_an_integer_column(self) -> None:
        """An inline CHECK only bounds its own column; image_input has no CHECK."""
        atoms = _all_check_atoms()

        assert atoms
        for owner, atom in atoms:
            parsed = _comparison(atom)
            assert parsed is not None, atom
            assert parsed[0] in _INT_COLUMNS, atom
            if owner is not None:
                assert parsed[0] == owner, (owner, atom)


# ---------------------------------------------------------------------------
# 3. Each column
# ---------------------------------------------------------------------------


class TestMigration0022Columns:
    """The two INTEGER NOT NULL DEFAULT ... CHECK (BETWEEN ...) columns and the BOOLEAN one."""

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0022_int_column_is_a_required_integer(self, column: str) -> None:
        definition = _masked(_column(column))

        assert re.match(_INTEGER, definition), definition
        assert _is_required(definition), definition

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0022_int_column_default_is_the_contract_default(self, column: str) -> None:
        """The existing platform row takes this value."""
        assert _int_default(_column(column)) == _INT_COLUMNS[column][0]

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0022_int_column_bounds_are_the_contract_bounds(self, column: str) -> None:
        _, low, high = _INT_COLUMNS[column]

        assert _bounds(column) == (low, high)

    def test_migration_0022_image_input_is_a_required_boolean_defaulting_to_true(self) -> None:
        definition = _masked(_column(_BOOL_COLUMN))

        assert re.match(_BOOLEAN, definition), definition
        assert _is_required(definition), definition
        assert _bool_default(definition) is True

    def test_migration_0022_image_input_has_no_check(self) -> None:
        """A boolean NOT NULL needs no CHECK; none names it."""
        assert _checks_in(_column(_BOOL_COLUMN)) == []
        assert all(_BOOL_COLUMN not in atom for _, atom in _all_check_atoms())

    @pytest.mark.parametrize("column", sorted(_ALL_COLUMNS))
    def test_migration_0022_column_has_no_reference_or_unique(self, column: str) -> None:
        definition = _masked(_column(column))

        assert re.search(r"\b(?:references|unique|primary\s+key)\b", definition) is None

    def test_migration_0022_defaults_satisfy_every_check(self) -> None:
        """Adding the columns to the existing platform row can't fail a CHECK."""
        for column in _INT_COLUMNS:
            value = _int_default(_column(column))
            low, high = _shipped_int_bounds(column)
            assert value is not None, column
            assert low <= value <= high, column


# ---------------------------------------------------------------------------
# 4. SQL and Python stay in sync
# ---------------------------------------------------------------------------


class TestMigration0022MatchesPython:
    """The SQL defaults and bounds equal the config, stored, response and patch models'."""

    def test_migration_0022_max_input_tokens_matches_llm_config(self) -> None:
        from admino.config import LLMConfig

        low, high = _shipped_int_bounds("max_input_tokens")

        assert LLMConfig().max_input_tokens == _int_default(_column("max_input_tokens"))
        _assert_bounds(LLMConfig, {}, "max_input_tokens", low, high)

    def test_migration_0022_image_input_default_matches_llm_config(self) -> None:
        from admino.config import LLMConfig

        assert LLMConfig().image_input is _bool_default(_column(_BOOL_COLUMN))

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0022_int_column_matches_stored_platform_llm(self, column: str) -> None:
        model = _stored_llm_model()
        field = _FIELD_OF[column]
        low, high = _shipped_int_bounds(column)

        stored = model.model_validate(_STORED_LLM_BASE)

        assert getattr(stored, field) == _int_default(_column(column))
        _assert_bounds(model, _STORED_LLM_BASE, field, low, high)

    def test_migration_0022_image_input_default_matches_stored_platform_llm(self) -> None:
        stored = _stored_llm_model().model_validate(_STORED_LLM_BASE)

        assert stored.image_input is _bool_default(_column(_BOOL_COLUMN))

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0022_int_column_matches_settings_llm(self, column: str) -> None:
        from admino.models import SettingsLLM

        field = _FIELD_OF[column]
        low, high = _shipped_int_bounds(column)

        shown = SettingsLLM.model_validate(_SETTINGS_LLM_BASE)

        assert getattr(shown, field) == _int_default(_column(column))
        _assert_bounds(SettingsLLM, _SETTINGS_LLM_BASE, field, low, high)

    def test_migration_0022_image_input_default_matches_settings_llm(self) -> None:
        from admino.models import SettingsLLM

        shown = SettingsLLM.model_validate(_SETTINGS_LLM_BASE)

        assert shown.image_input is _bool_default(_column(_BOOL_COLUMN))

    @pytest.mark.parametrize("column", sorted(_INT_COLUMNS))
    def test_migration_0022_int_column_bounds_match_the_patch_model(self, column: str) -> None:
        from admino.models import SettingsPatchLLM

        field = _FIELD_OF[column]
        low, high = _shipped_int_bounds(column)

        assert field in SettingsPatchLLM.model_fields
        _assert_bounds(SettingsPatchLLM, {}, field, low, high)

    def test_migration_0022_llm_max_retries_bounds_match_the_agent_config(self) -> None:
        from admino.models import AgentConfig

        low, high = _shipped_int_bounds("llm_max_retries")

        assert "llm_max_retries" in AgentConfig.model_fields
        _assert_bounds(AgentConfig, {}, "llm_max_retries", low, high)

    def test_migration_0022_the_fake_database_mirrors_the_migration(self) -> None:
        """tests/db_fakes.py enforces exactly the shipped defaults and CHECKs."""
        shipped = {
            column: (_int_default(_column(column)), *_bounds(column))
            for column in sorted(_INT_COLUMNS)
        }

        assert shipped == dict(db_fakes.PLATFORM_LLM_LIMITS)
        row = db_fakes.FakeDb().add_platform_settings()
        assert row[_BOOL_COLUMN] is _bool_default(_column(_BOOL_COLUMN))


# ---------------------------------------------------------------------------
# 5. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0022NothingElse:
    """No other table, data, code or privilege changes."""

    def test_migration_0022_alters_only_platform_settings(self) -> None:
        targets = re.findall(
            r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", _masked(_migration_sql())
        )

        assert targets
        assert set(targets) == {_TABLE}

    def test_migration_0022_drops_nothing(self) -> None:
        assert re.search(r"\bdrop\b", _masked(_migration_sql())) is None

    def test_migration_0022_changes_no_existing_rows(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\bupdate\b", masked) is None
        assert re.search(r"\bdelete\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None
        assert re.search(r"\bmerge\b", masked) is None

    def test_migration_0022_inserts_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\b", masked) is None
        assert re.search(r"\bcopy\b", masked) is None

    def test_migration_0022_creates_nothing(self) -> None:
        """No table, index, function, procedure, trigger, view, type, rule or policy."""
        masked = _masked(_migration_sql())

        assert re.search(r"\bcreate\b", masked) is None
        assert re.search(r"\bdo\s+\$", masked) is None
        assert "$$" not in masked

    def test_migration_0022_renames_nothing(self) -> None:
        assert re.search(r"\brename\b", _masked(_migration_sql())) is None

    def test_migration_0022_grants_nothing(self) -> None:
        """0018's table-level grants already cover new platform_settings columns."""
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:grant|revoke)\b", masked) is None

    def test_migration_0022_sets_and_cascades_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\bset\b", masked) is None
        assert re.search(r"\bcascade\b", masked) is None

    def test_migration_0022_leaves_the_audit_catalog_alone(self) -> None:
        """platform.settings_change is already in the catalog (0013)."""
        assert audit_events.AuditAction.PLATFORM_SETTINGS_CHANGE.value == "platform.settings_change"
        sql = _masked(_migration_sql())
        assert "audit_events" not in sql
        assert "action_check" not in sql
