"""Tests for migration 0014_platform_defaults.sql — the platform defaults (GH-160).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0013.py pattern): it must exist, be applied by
run_migrations as version 14, and make exactly the schema change GH-160 needs.
The SQL is read with ``--`` comments blanked; statements are split outside
parentheses and literals; keywords are compared case-insensitively with
whitespace collapsed. ALTER TABLE statements are split into their actions, so
one combined ALTER and several separate ones read the same. A range may be
written as ``BETWEEN`` or as two comparisons, and a CHECK may be inline on its
column or an added table constraint.

What these tests pin down:
- ``ALTER TABLE platform_settings ADD COLUMN`` for each of the 14 platform
  defaults (files, retention, security), each ``INTEGER NOT NULL DEFAULT
  <default>`` with a CHECK of exactly the issue's inclusive bounds, plus one
  CHECK ``trash_min_days <= trash_max_days``. The existing platform row takes
  the defaults (which satisfy every CHECK), so no UPDATE is needed.
- The SQL defaults and bounds equal the Pydantic ones (``PlatformFiles``,
  ``PlatformRetention``, ``PlatformSecurity`` and their patch models), the
  ``admino.sessions`` MIN/MAX/DEFAULT session constants and the
  ``admino.audit_events`` retention constants; the FakeDb
  (``db_fakes.PLATFORM_DEFAULTS``) mirrors the migration.
- Nothing else: only ``platform_settings`` is altered and only by adding; no
  DROP, no UPDATE / DELETE / TRUNCATE / MERGE, no INSERT / COPY, no table,
  index, function, trigger, view, type or DO block, no GRANT / REVOKE, no
  audit catalog change (``platform.settings_change`` already exists),
  parameter-free.

Security notes:
- The CHECKs mirror the Pydantic bounds, so the database refuses what the API
  refuses even if a write bypasses the models (for example a lockout threshold
  of 0 or a session lifetime beyond 72 hours).
- The trash order CHECK makes an inverted retention window impossible at rest.
- The migration never touches the append-only audit log.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
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

_MIGRATION_NAME = "0014_platform_defaults.sql"
_VERSION = 14
_TABLE = "platform_settings"

# column -> (section, default, low, high): the issue's Decisions table.
_COLUMNS: dict[str, tuple[str, int, int, int]] = {
    "max_file_size_mb": ("files", 50, 1, 500),
    "max_files_per_message": ("files", 10, 1, 50),
    "max_pages_per_file": ("files", 100, 1, 1000),
    "render_dpi": ("files", 150, 72, 300),
    "trash_min_days": ("retention", 0, 0, 90),
    "trash_max_days": ("retention", 90, 0, 90),
    "audit_months": ("retention", 12, 6, 84),
    "org_deletion_grace_days": ("retention", 30, 7, 90),
    "rate_limit_per_minute": ("security", 20, 1, 600),
    "lockout_after_failures": ("security", 10, 3, 100),
    "lockout_window_minutes": ("security", 15, 1, 1440),
    "lockout_minutes": ("security", 15, 1, 1440),
    "session_idle_timeout_minutes": ("security", 60, 15, 480),
    "session_max_lifetime_hours": ("security", 12, 1, 72),
}
_RESPONSE_MODELS = {
    "files": "PlatformFiles",
    "retention": "PlatformRetention",
    "security": "PlatformSecurity",
}
_PATCH_MODELS = {
    "files": "PlatformFilesPatch",
    "retention": "PlatformRetentionPatch",
    "security": "PlatformSecurityPatch",
}
_INTEGER = r"(?:integer|int4|int)\b"
_CONSTRAINT_START = (
    r"(?:constraint\s+\w+\s+)?(?:check|unique|primary\s+key|foreign\s+key|exclude)\b"
)
_ORDER_ATOMS = (
    r"trash_min_days\s*<=\s*trash_max_days",
    r"trash_max_days\s*>=\s*trash_min_days",
)
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


def _is_order_atom(atom: str) -> bool:
    return any(re.fullmatch(pattern, atom) for pattern in _ORDER_ATOMS)


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
        if _is_order_atom(atom):
            continue
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


def _default(definition: str) -> int | None:
    """The integer DEFAULT of a column definition (optionally parenthesized)."""
    match = re.search(r"\bdefault\s+\(?\s*(-?\d[\d_]*)\s*\)?", _masked(definition))
    return None if match is None else int(match.group(1))


def _is_required(definition: str) -> bool:
    return re.search(r"\bnot\s+null\b", _masked(definition)) is not None


def _model(name: str) -> type[BaseModel]:
    """A GH-160 model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-160)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _accepts(model: type[BaseModel], column: str, value: int) -> bool:
    try:
        model.model_validate({column: value})
    except ValidationError:
        return False
    return True


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0014File:
    """The migration ships as version 14 and is applied by run_migrations."""

    def test_migration_0014_file_is_shipped_as_version_14(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0014_is_the_only_version_14(self) -> None:
        fourteens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert fourteens == [_MIGRATION_NAME]

    async def test_migration_0014_run_migrations_applies_it_as_version_14(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0013 applied, run_migrations executes the file and records 14."""
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

    async def test_migration_0014_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0014_is_parameter_free(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked


# ---------------------------------------------------------------------------
# 2. Only additions to platform_settings
# ---------------------------------------------------------------------------


class TestMigration0014Statements:
    """ALTER TABLE platform_settings ADD COLUMN x 14 plus the trash order CHECK."""

    def test_migration_0014_every_statement_alters_platform_settings(self) -> None:
        statements = _statements()

        assert statements
        for statement in statements:
            match = _ALTER_RE.fullmatch(_masked(statement))
            assert match is not None, statement
            assert match.group(1) == _TABLE, statement

    def test_migration_0014_every_action_is_an_add(self) -> None:
        """No DROP / SET / ALTER COLUMN / RENAME action: columns and CHECKs are only added."""
        actions = _actions()

        assert actions
        for _, action in actions:
            assert _classify(action)[0] in {"column", "constraint"}, action

    def test_migration_0014_adds_exactly_the_fourteen_columns_once_each(self) -> None:
        added = [name for name, _ in _added_columns()]

        assert sorted(added) == sorted(_COLUMNS)

    def test_migration_0014_added_constraints_are_checks_only(self) -> None:
        """No UNIQUE, PRIMARY KEY, FOREIGN KEY or EXCLUDE constraint is added."""
        for constraint in _table_constraints():
            assert re.match(r"(?:constraint\s+\w+\s+)?check\b", _masked(constraint)), constraint

    def test_migration_0014_has_the_trash_order_check_exactly_once(self) -> None:
        """CHECK (trash_min_days <= trash_max_days), inline or as a table constraint."""
        order_atoms = [atom for _, atom in _all_check_atoms() if _is_order_atom(atom)]

        assert len(order_atoms) == 1, _all_check_atoms()

    def test_migration_0014_every_check_condition_is_a_bound_or_the_trash_order(self) -> None:
        """An inline CHECK only bounds its own column; nothing else is constrained."""
        for owner, atom in _all_check_atoms():
            if _is_order_atom(atom):
                continue
            parsed = _comparison(atom)
            assert parsed is not None, atom
            assert parsed[0] in _COLUMNS, atom
            if owner is not None:
                assert parsed[0] == owner, (owner, atom)


# ---------------------------------------------------------------------------
# 3. Each column
# ---------------------------------------------------------------------------


class TestMigration0014Columns:
    """INTEGER NOT NULL DEFAULT <default> CHECK (<column> BETWEEN low AND high)."""

    @pytest.mark.parametrize("column", sorted(_COLUMNS))
    def test_migration_0014_column_is_a_required_integer(self, column: str) -> None:
        definition = _masked(_column(column))

        assert re.match(_INTEGER, definition), definition
        assert _is_required(definition), definition

    @pytest.mark.parametrize("column", sorted(_COLUMNS))
    def test_migration_0014_column_default_is_the_issue_default(self, column: str) -> None:
        """The existing platform row takes this value."""
        assert _default(_column(column)) == _COLUMNS[column][1]

    @pytest.mark.parametrize("column", sorted(_COLUMNS))
    def test_migration_0014_column_bounds_are_the_issue_bounds(self, column: str) -> None:
        _, _, low, high = _COLUMNS[column]

        assert _bounds(column) == (low, high)

    @pytest.mark.parametrize("column", sorted(_COLUMNS))
    def test_migration_0014_column_has_no_reference_or_unique(self, column: str) -> None:
        definition = _masked(_column(column))

        assert re.search(r"\b(?:references|unique|primary\s+key)\b", definition) is None

    def test_migration_0014_defaults_satisfy_every_check(self) -> None:
        """Adding the columns to the existing platform row can't fail a CHECK."""
        defaults = {column: _default(_column(column)) for column in _COLUMNS}

        for column, value in defaults.items():
            low, high = _bounds(column)
            assert value is not None, column
            assert low is not None, column
            assert high is not None, column
            assert low <= value <= high, column
        trash_min = defaults["trash_min_days"]
        trash_max = defaults["trash_max_days"]
        assert trash_min is not None
        assert trash_max is not None
        assert trash_min <= trash_max


# ---------------------------------------------------------------------------
# 4. SQL and Python stay in sync
# ---------------------------------------------------------------------------


class TestMigration0014MatchesPython:
    """The SQL defaults and bounds equal the Pydantic models' and the module constants."""

    @pytest.mark.parametrize("column", sorted(_COLUMNS))
    def test_migration_0014_default_equals_the_response_model_default(self, column: str) -> None:
        model = _model(_RESPONSE_MODELS[_COLUMNS[column][0]])

        assert getattr(model(), column) == _default(_column(column))

    @pytest.mark.parametrize("column", sorted(_COLUMNS))
    def test_migration_0014_bounds_equal_the_response_model_bounds(self, column: str) -> None:
        model = _model(_RESPONSE_MODELS[_COLUMNS[column][0]])
        low, high = _bounds(column)
        assert low is not None
        assert high is not None

        assert _accepts(model, column, low)
        assert _accepts(model, column, high)
        assert not _accepts(model, column, low - 1)
        assert not _accepts(model, column, high + 1)

    @pytest.mark.parametrize("column", sorted(_COLUMNS))
    def test_migration_0014_bounds_equal_the_patch_model_bounds(self, column: str) -> None:
        model = _model(_PATCH_MODELS[_COLUMNS[column][0]])
        low, high = _bounds(column)
        assert low is not None
        assert high is not None

        assert _accepts(model, column, low)
        assert _accepts(model, column, high)
        assert not _accepts(model, column, low - 1)
        assert not _accepts(model, column, high + 1)

    def test_migration_0014_session_columns_equal_the_sessions_constants(self) -> None:
        assert _default(_column("session_idle_timeout_minutes")) == (
            sessions.DEFAULT_IDLE_TIMEOUT_MINUTES
        )
        assert _bounds("session_idle_timeout_minutes") == (
            sessions.MIN_IDLE_TIMEOUT_MINUTES,
            sessions.MAX_IDLE_TIMEOUT_MINUTES,
        )
        assert _default(_column("session_max_lifetime_hours")) == sessions.DEFAULT_LIFETIME_HOURS
        assert _bounds("session_max_lifetime_hours") == (
            sessions.MIN_LIFETIME_HOURS,
            sessions.MAX_LIFETIME_HOURS,
        )

    def test_migration_0014_audit_months_equals_the_audit_retention_constants(self) -> None:
        assert _default(_column("audit_months")) == audit_events.DEFAULT_RETENTION_MONTHS
        assert _bounds("audit_months") == (
            audit_events.MIN_RETENTION_MONTHS,
            audit_events.MAX_RETENTION_MONTHS,
        )

    def test_migration_0014_the_fake_database_mirrors_the_migration(self) -> None:
        """tests/db_fakes.py enforces exactly the shipped defaults and CHECKs."""
        shipped = {
            column: (_default(_column(column)), *_bounds(column)) for column in sorted(_COLUMNS)
        }

        assert shipped == dict(db_fakes.PLATFORM_DEFAULTS)


# ---------------------------------------------------------------------------
# 5. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0014NothingElse:
    """No other table, data, code or privilege changes."""

    def test_migration_0014_alters_only_platform_settings(self) -> None:
        targets = re.findall(
            r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", _masked(_migration_sql())
        )

        assert targets
        assert set(targets) == {_TABLE}

    def test_migration_0014_drops_nothing(self) -> None:
        assert re.search(r"\bdrop\b", _masked(_migration_sql())) is None

    def test_migration_0014_changes_no_existing_rows(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\bupdate\b", masked) is None
        assert re.search(r"\bdelete\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None
        assert re.search(r"\bmerge\b", masked) is None

    def test_migration_0014_inserts_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\b", masked) is None
        assert re.search(r"\bcopy\b", masked) is None

    def test_migration_0014_creates_nothing(self) -> None:
        """No table, index, function, procedure, trigger, view, type, rule or policy."""
        masked = _masked(_migration_sql())

        assert re.search(r"\bcreate\b", masked) is None
        assert re.search(r"\bdo\s+\$", masked) is None
        assert "$$" not in masked

    def test_migration_0014_renames_nothing(self) -> None:
        assert re.search(r"\brename\b", _masked(_migration_sql())) is None

    def test_migration_0014_grants_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:grant|revoke)\b", masked) is None

    def test_migration_0014_leaves_the_audit_catalog_alone(self) -> None:
        """platform.settings_change is already in the catalog (0013)."""
        assert audit_events.AuditAction.PLATFORM_SETTINGS_CHANGE.value == "platform.settings_change"
        sql = _masked(_migration_sql())
        assert "audit_events" not in sql
        assert "action_check" not in sql
