"""Tests for migration 0021_account_self_service.sql — GH-166's account self-service schema.

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0020.py pattern): it must exist, be applied by
run_migrations as version 21, and make exactly the schema change GH-166 needs.
The SQL is read with ``--`` and ``/* */`` comments blanked; statements are split
outside parentheses and literals; keywords are compared case-insensitively with
whitespace collapsed, while string literals are kept byte for byte (the audit
action list and the timezone pattern are compared exactly).

What these tests pin down:
- ``users`` gains two columns, next to ``ui_language`` / ``response_language``:
  - ``timezone TEXT``, nullable with no default (existing users get NULL: the
    PWA presets it after the next login, consumers treat NULL as
    Europe/Zurich), with ``CONSTRAINT users_timezone_check CHECK
    (char_length(timezone) <= 64 AND timezone ~
    '^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$')``. The pattern itself is evaluated
    here against good and bad names, and every name of
    ``zoneinfo.available_timezones()`` (what the API model accepts) passes the
    CHECK, so a zone the API accepts never fails the write.
  - ``personal_instructions TEXT NOT NULL DEFAULT ''`` (existing users get no
    instructions) with ``CONSTRAINT users_personal_instructions_check CHECK
    (char_length(personal_instructions) <= 1500)``: characters, not bytes.
- ``audit_events_action_check`` is dropped, then added again with a list that is
  0020's 48 actions plus ``password.change`` (49 actions, each once): a user
  changing their own password is an audit event (the profile edits are not).
- The exact sync of the SQL action list with the live Python catalog moved on to
  tests/test_migration_0027.py (GH-187's ``file.upload``): here 0021's list is a
  subset of the live catalog and still lists its own 49 actions (it came here from
  tests/test_migration_0020.py, which keeps a subset check too).
- Nothing else: only ``users`` and ``audit_events`` are altered; no existing
  column is changed, no other constraint is dropped or added; no CREATE of any
  kind (no table, so no new grant is owed to the runtime role: 0018's
  table-level grants cover the new columns, see tests/test_migration_0018.py);
  no INSERT / UPDATE / DELETE / TRUNCATE (no row is written: the defaults fill
  the new columns), no function, trigger, DO block or dynamic SQL, no GRANT /
  REVOKE, no SET, no CASCADE, parameter-free.

Security notes:
- The timezone CHECK keeps a direct-DB write (or a bug past the API model) from
  storing a path-like or control-character value that a later consumer would
  hand to a zone loader: dots, spaces, empty segments and non-ASCII are refused.
- The instructions CHECK bounds what is later fed to the LLM per request.
- The audit log stays append-only: the migration only widens the action catalog
  and touches no row. No privilege changes: the runtime role (GH-220) gains
  nothing.
"""

from __future__ import annotations

import re
import zoneinfo
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0021_account_self_service.sql"
_VERSION = 21
_PREVIOUS_ACTION_MIGRATION = "0020_user_management.sql"

_ACTION_CONSTRAINT = "audit_events_action_check"
_TIMEZONE_CONSTRAINT = "users_timezone_check"
_INSTRUCTIONS_CONSTRAINT = "users_personal_instructions_check"

_NEW_ACTION = "password.change"
_PREVIOUS_CATALOG_SIZE = 48
_ACTION_CATALOG_SIZE = 49

_TIMEZONE_MAX = 64
_INSTRUCTIONS_MAX = 1500
# The contract's pattern, byte for byte (a PostgreSQL ARE, anchored at both ends).
_TIMEZONE_PATTERN = "^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$"

_NEW_COLUMNS = ("timezone", "personal_instructions")
_USERS_CONSTRAINTS = frozenset({_TIMEZONE_CONSTRAINT, _INSTRUCTIONS_CONSTRAINT})

# A character-count function: char_length / character_length / length count
# characters on TEXT; octet_length (bytes) is not one of them.
_CHAR_LENGTH = r"(?:char_length|character_length|length)"


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


def _statements(name: str = _MIGRATION_NAME) -> list[str]:
    return _split(_normalized(name), ";")


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    while (
        expression.startswith("(") and _balanced_end(_masked(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _conjuncts(expression: str) -> list[str]:
    """Split a CHECK expression at its top-level ANDs (outside parentheses and literals)."""
    expression = _unwrap(expression)
    masked = _masked(expression)
    parts: list[str] = []
    depth = 0
    start = 0
    for token in re.finditer(r"\(|\)|\band\b", masked):
        if token.group(0) == "(":
            depth += 1
        elif token.group(0) == ")":
            depth -= 1
        elif depth == 0:
            parts.append(_unwrap(expression[start : token.start()]))
            start = token.end()
    parts.append(_unwrap(expression[start:]))
    return parts


def _check_values(name: str, constraint: str, column: str) -> list[str]:
    """The literals of ``ADD CONSTRAINT <constraint> CHECK (<column> IN (...))`` in a
    shipped migration, in written order (duplicates kept)."""
    for statement in _statements(name):
        masked = _masked(statement)
        match = re.search(rf"\badd\s+constraint\s+{constraint}\s+check\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        expression = _unwrap(statement[match.end() : end])
        listed = re.fullmatch(rf"{column}\s+in\s*\(([^)]*)\)", expression)
        assert listed is not None, f"{constraint} must be exactly {column} IN (...): {expression}"
        return re.findall(r"'([^']*)'", listed.group(1))
    pytest.fail(f"no ADD CONSTRAINT {constraint} CHECK ({column} IN (...)) in {name}")


def _added_actions(name: str = _MIGRATION_NAME) -> list[str]:
    return _check_values(name, _ACTION_CONSTRAINT, "action")


def _live_actions() -> set[str]:
    from admino.audit_events import AuditAction

    return {action.value for action in AuditAction}


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
    if table == "audit_events":
        if re.fullmatch(
            rf"drop\s+constraint\s+(?:if\s+exists\s+)?{_ACTION_CONSTRAINT}(?:\s+restrict)?", masked
        ):
            return "drop check"
        if re.fullmatch(rf"add\s+constraint\s+{_ACTION_CONSTRAINT}\s+check\s*\(.*\)", masked):
            return "add check"
    if table == "users":
        constraint = re.fullmatch(_ADD_CONSTRAINT, masked)
        if constraint is not None and constraint.group(1) in _USERS_CONSTRAINTS:
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


def _kinds_of(table: str) -> list[str]:
    return [kind for _, name, kind in _kinds() if name == table]


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
        elif step := re.match(r"default\s+('[^']*'(?:\s*::\s*\w+)?|\w+)\s*", rest):
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


def _users_columns() -> dict[str, list[_ColumnDefinition]]:
    """Every column ADDed to users, by name (a name added twice has two entries)."""
    columns: dict[str, list[_ColumnDefinition]] = {}
    for _, table, action in _sub_actions():
        masked = _masked(action)
        if table != "users" or re.match(r"add\s+constraint\b", masked):
            continue
        match = re.fullmatch(_ADD_COLUMN, masked)
        if match is None:
            continue
        columns.setdefault(match.group(1), []).append(_parse_column(action[match.start(2) :]))
    return columns


def _column(name: str) -> _ColumnDefinition:
    definitions = _users_columns().get(name, [])
    assert len(definitions) == 1, f"users.{name} must be added exactly once: {definitions}"
    return definitions[0]


def _users_checks() -> list[tuple[str | None, str]]:
    """Every CHECK the migration puts on users: (constraint name or None, expression).

    Inline column constraints and ``ADD CONSTRAINT ... CHECK`` sub-actions both count.
    """
    checks: list[tuple[str | None, str]] = []
    for definitions in _users_columns().values():
        for definition in definitions:
            checks.extend(definition.checks)
    for _, table, action in _sub_actions():
        match = re.fullmatch(_ADD_CONSTRAINT, _masked(action))
        if table == "users" and match is not None:
            checks.append((match.group(1), action[match.start(2) : match.end(2)]))
    return checks


def _check_expression(constraint: str) -> str:
    found = [expression for name, expression in _users_checks() if name == constraint]
    assert len(found) == 1, f"{constraint} must be defined exactly once: {found}"
    return found[0]


def _timezone_pattern() -> str:
    """The regex literal of users_timezone_check, byte for byte."""
    for atom in _conjuncts(_check_expression(_TIMEZONE_CONSTRAINT)):
        match = re.fullmatch(r"timezone\s*~\s*'([^']*)'", atom)
        if match is not None:
            return match.group(1)
    pytest.fail(f"{_TIMEZONE_CONSTRAINT} has no case-sensitive timezone ~ '...' match")


def _timezone_check_accepts(value: str) -> bool:
    """Evaluate users_timezone_check's two conditions in Python for a non-NULL value.

    The pattern is anchored with ^...$; PostgreSQL's ``$`` matches only at the
    very end (Python's would also match before a final newline), so the anchors
    are dropped and the body is fullmatched.
    """
    pattern = _timezone_pattern()
    assert pattern.startswith("^"), pattern
    assert pattern.endswith("$"), pattern
    return len(value) <= _TIMEZONE_MAX and re.fullmatch(pattern[1:-1], value) is not None


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0021File:
    """The migration ships as version 21 and is applied by run_migrations."""

    def test_migration_0021_file_is_shipped_as_version_21(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0021_is_the_only_version_21(self) -> None:
        twenty_ones = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert twenty_ones == [_MIGRATION_NAME]

    async def test_migration_0021_run_migrations_applies_it_as_version_21(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0020 applied, run_migrations executes the file and records 21."""
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

    async def test_migration_0021_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0021_runs_after_0020(self, mock_pool: MagicMock) -> None:
        """With 0001 to 0019 applied, 0020 is executed before 0021."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_ACTION_MIGRATION).read_text(encoding="utf-8")
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert shipped in executed
        assert previous in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0021_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0021 recorded, the shipped SQL is not executed a second time."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0021_is_parameter_free(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked


# ---------------------------------------------------------------------------
# 2. Exactly the contract's statements
# ---------------------------------------------------------------------------


class TestMigration0021Statements:
    """Two new users columns and one constraint swap on audit_events."""

    def test_migration_0021_has_statements(self) -> None:
        assert _statements()

    def test_migration_0021_every_statement_is_part_of_the_contract(self) -> None:
        """Every statement is an ALTER TABLE of users or audit_events, and every
        sub-action adds one of the two columns (or one of their two CHECKs), or drops
        or adds audit_events_action_check."""
        unexpected = [kind for _, _, kind in _kinds() if kind.startswith("unexpected")]

        assert unexpected == []

    def test_migration_0021_adds_exactly_the_two_users_columns(self) -> None:
        added = sorted(kind for kind in _kinds_of("users") if kind.startswith("add column"))

        assert added == ["add column personal_instructions", "add column timezone"]

    def test_migration_0021_audit_events_is_drop_then_add_of_the_action_check(self) -> None:
        """audit_events gets exactly one DROP, then one ADD, of audit_events_action_check."""
        assert _kinds_of("audit_events") == ["drop check", "add check"]

    def test_migration_0021_alters_exactly_users_and_audit_events(self) -> None:
        tables = {name for _, name, _ in _kinds()}

        assert tables == {"users", "audit_events"}

    def test_migration_0021_drop_does_not_cascade(self) -> None:
        """CASCADE could silently drop more than the named constraint."""
        assert re.search(r"\bcascade\b", _masked(_migration_sql())) is None


# ---------------------------------------------------------------------------
# 3. users.timezone
# ---------------------------------------------------------------------------

_TIMEZONES_THE_CHECK_ACCEPTS: list[str] = [
    "Europe/Zurich",
    "America/Argentina/Buenos_Aires",
    "Etc/GMT+5",
    "Etc/GMT-14",
    "America/Port-au-Prince",
    "UTC",
    "A" * _TIMEZONE_MAX,
]

_TIMEZONES_THE_CHECK_REFUSES: list[object] = [
    pytest.param("Europe/Zurich ", id="trailing-space"),
    pytest.param(" Europe/Zurich", id="leading-space"),
    pytest.param("Europe/Zurich\n", id="trailing-newline"),
    pytest.param("Europe Zurich", id="inner-space"),
    pytest.param("../etc", id="dot-dot"),
    pytest.param("../etc/passwd", id="path-traversal"),
    pytest.param("Europe/../../etc", id="dot-dot-segment"),
    pytest.param("a//b", id="empty-segment"),
    pytest.param("/Europe/Zurich", id="leading-slash"),
    pytest.param("Europe/Zurich/", id="trailing-slash"),
    pytest.param("Europe\\Zurich", id="backslash"),
    pytest.param("", id="empty"),
    pytest.param("Europe/Z" + chr(0x00FC) + "rich", id="non-ascii"),
    pytest.param("Europe/Zurich;", id="semicolon"),
    pytest.param("Europe/Zu" + chr(0) + "rich", id="nul"),
    pytest.param("A" * (_TIMEZONE_MAX + 1), id="65-chars"),
]


class TestMigration0021Timezone:
    """users.timezone: nullable TEXT, at most 64 characters, a zone-name shape."""

    def test_migration_0021_timezone_is_text(self) -> None:
        assert _column("timezone").type_name == "text"

    def test_migration_0021_timezone_is_nullable(self) -> None:
        """NULL means "not preset yet" (consumers use Europe/Zurich)."""
        assert _column("timezone").not_null is False

    def test_migration_0021_timezone_has_no_default(self) -> None:
        """Existing users get NULL: no zone is guessed for them in SQL."""
        assert _column("timezone").defaults in ([], ["null"])

    def test_migration_0021_timezone_column_has_nothing_else(self) -> None:
        assert _column("timezone").unexpected == []

    def test_migration_0021_timezone_check_is_named(self) -> None:
        """The CHECK is CONSTRAINT users_timezone_check (inline or ADD CONSTRAINT)."""
        names = [name for name, _ in _users_checks()]

        assert names.count(_TIMEZONE_CONSTRAINT) == 1

    def test_migration_0021_timezone_check_is_length_and_pattern(self) -> None:
        """Exactly two conditions: char_length(timezone) <= 64 AND timezone ~ '...'."""
        atoms = _conjuncts(_check_expression(_TIMEZONE_CONSTRAINT))
        bounded = [
            a
            for a in atoms
            if re.fullmatch(rf"{_CHAR_LENGTH}\s*\(\s*timezone\s*\)\s*<=\s*{_TIMEZONE_MAX}", a)
        ]
        patterns = [a for a in atoms if re.fullmatch(r"timezone\s*~\s*'[^']*'", a)]

        assert len(atoms) == 2
        assert len(bounded) == 1
        assert len(patterns) == 1

    def test_migration_0021_timezone_pattern_is_the_contract_pattern(self) -> None:
        """The literal is kept byte for byte (case matters: A-Z and a-z are both listed)."""
        assert _timezone_pattern() == _TIMEZONE_PATTERN

    @pytest.mark.parametrize("value", _TIMEZONES_THE_CHECK_ACCEPTS)
    def test_migration_0021_timezone_check_accepts(self, value: str) -> None:
        assert _timezone_check_accepts(value) is True

    @pytest.mark.parametrize("value", _TIMEZONES_THE_CHECK_REFUSES)
    def test_migration_0021_timezone_check_refuses(self, value: str) -> None:
        assert _timezone_check_accepts(value) is False

    def test_migration_0021_timezone_check_accepts_every_available_zone(self) -> None:
        """Every name the API model accepts (zoneinfo.available_timezones()) passes the
        CHECK, so a valid PATCH never ends in a constraint violation."""
        zones = sorted(zoneinfo.available_timezones())
        refused = [zone for zone in zones if not _timezone_check_accepts(zone)]

        assert zones
        assert refused == []


# ---------------------------------------------------------------------------
# 4. users.personal_instructions
# ---------------------------------------------------------------------------


class TestMigration0021PersonalInstructions:
    """users.personal_instructions: TEXT NOT NULL DEFAULT '', at most 1500 characters."""

    def test_migration_0021_instructions_is_text(self) -> None:
        assert _column("personal_instructions").type_name == "text"

    def test_migration_0021_instructions_is_not_null(self) -> None:
        """'' means "no instructions"; there is no second empty state."""
        column = _column("personal_instructions")

        assert column.not_null is True
        assert column.explicit_null is False

    def test_migration_0021_instructions_defaults_to_empty(self) -> None:
        """Existing users get no instructions (the default fills the column, no UPDATE)."""
        defaults = _column("personal_instructions").defaults

        assert len(defaults) == 1
        assert re.fullmatch(r"''(?:\s*::\s*text)?", defaults[0]), defaults

    def test_migration_0021_instructions_column_has_nothing_else(self) -> None:
        assert _column("personal_instructions").unexpected == []

    def test_migration_0021_instructions_check_is_named(self) -> None:
        names = [name for name, _ in _users_checks()]

        assert names.count(_INSTRUCTIONS_CONSTRAINT) == 1

    def test_migration_0021_instructions_check_counts_characters_up_to_1500(self) -> None:
        """Exactly char_length(personal_instructions) <= 1500: characters, not bytes
        (octet_length would refuse 1500 characters of accented text or emoji)."""
        expression = _unwrap(_check_expression(_INSTRUCTIONS_CONSTRAINT))

        assert re.fullmatch(
            rf"{_CHAR_LENGTH}\s*\(\s*personal_instructions\s*\)\s*<=\s*{_INSTRUCTIONS_MAX}",
            expression,
        ), expression

    def test_migration_0021_users_has_only_the_two_named_checks(self) -> None:
        """No unnamed CHECK and no other constraint on users."""
        names = sorted(str(name) for name, _ in _users_checks())

        assert names == sorted(_USERS_CONSTRAINTS)


# ---------------------------------------------------------------------------
# 5. The audit action catalog grows by password.change
# ---------------------------------------------------------------------------


class TestMigration0021ActionCatalog:
    """audit_events_action_check is replaced with the 49-action catalog."""

    def test_migration_0021_action_check_adds_exactly_password_change(self) -> None:
        """The new list is 0020's 48 actions plus password.change."""
        old = set(_added_actions(_PREVIOUS_ACTION_MIGRATION))
        new = set(_added_actions())

        assert len(old) == _PREVIOUS_CATALOG_SIZE
        assert new - old == {_NEW_ACTION}
        assert old <= new
        assert len(new) == _ACTION_CATALOG_SIZE

    def test_migration_0021_action_check_lists_each_action_once(self) -> None:
        listed = _added_actions()

        assert len(listed) == len(set(listed)) == _ACTION_CATALOG_SIZE

    def test_migration_0021_action_check_contains_password_change(self) -> None:
        """The literal byte for byte (lowercase, dotted)."""
        assert _NEW_ACTION in _added_actions()

    def test_migration_0021_action_check_is_still_in_audit_action(self) -> None:
        """Every action 0021 allows is still an AuditAction (none was dropped).

        A shipped migration never changes, so 0021's list stays its 49 actions. The
        catalog grows by replacing the audit_events_action_check constraint in a later
        migration (0027 for GH-187's file.upload), so the exact sync with the live
        AuditAction lives in that migration's tests (tests/test_migration_0027.py).
        """
        assert set(_added_actions()) <= _live_actions()

    def test_migration_0021_action_check_still_lists_its_own_49_actions(self) -> None:
        """0021's list is its own 49 actions, whatever the live catalog has grown to."""
        listed = set(_added_actions())
        live = _live_actions()

        assert len(listed) == _ACTION_CATALOG_SIZE
        assert _NEW_ACTION in live
        assert len(live) >= _ACTION_CATALOG_SIZE


# ---------------------------------------------------------------------------
# 6. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0021NothingElse:
    """No other table, column, constraint, data, code or privilege changes."""

    def test_migration_0021_writes_no_data(self) -> None:
        """No row is changed, added or deleted: the defaults fill the new columns."""
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\b", masked) is None
        assert re.search(r"\bupdate\b", masked) is None
        assert re.search(r"\bdelete\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None
        assert re.search(r"\bmerge\b", masked) is None
        assert re.search(r"\bcopy\b", masked) is None

    def test_migration_0021_drops_only_the_action_check(self) -> None:
        """One drop: the old action check; no table, column, default or other constraint."""
        masked = _masked(_migration_sql())

        assert len(re.findall(r"\bdrop\b", masked)) == 1
        assert re.search(
            rf"\bdrop\s+constraint\s+(?:if\s+exists\s+)?{_ACTION_CONSTRAINT}\b", masked
        )

    def test_migration_0021_alters_only_users_and_audit_events(self) -> None:
        masked = _masked(_migration_sql())
        targets = re.findall(r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", masked)

        assert set(targets) == {"users", "audit_events"}
        assert len(re.findall(r"\balter\b", masked)) == len(targets)

    def test_migration_0021_changes_no_existing_column(self) -> None:
        """Only ADD COLUMN: no ALTER/DROP/RENAME COLUMN, no type change."""
        masked = _masked(_migration_sql())

        assert all(word == "add" for word in re.findall(r"(\w+)\s+column\b", masked))
        assert re.search(r"\brename\b", masked) is None
        assert re.search(r"\btype\b", masked) is None
        assert re.search(r"\busing\b", masked) is None

    def test_migration_0021_creates_nothing(self) -> None:
        """No table (so no grant is owed to the runtime role), index, function, trigger,
        view, type, sequence, role or extension."""
        assert re.search(r"\bcreate\b", _masked(_migration_sql())) is None

    def test_migration_0021_adds_no_key_reference_or_index(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:unique|primary|references|foreign|exclude|index)\b", masked) is None

    def test_migration_0021_runs_no_code(self) -> None:
        """No DO block, dollar-quoted body, function, trigger or dynamic SQL."""
        masked = _masked(_migration_sql())

        assert "$" not in masked
        assert re.search(r"\bdo\b", masked) is None
        assert re.search(r"\bexecute\b", masked) is None
        assert re.search(r"\b(?:function|procedure|trigger)\b", masked) is None

    def test_migration_0021_grants_nothing(self) -> None:
        """0018's table-level grants cover the new columns: no privilege change."""
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:grant|revoke|owner|role|policy|security)\b", masked) is None

    def test_migration_0021_sets_no_parameter(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:set|reset)\b", masked) is None
