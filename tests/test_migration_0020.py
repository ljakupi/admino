"""Tests for migration 0020_user_management.sql — the GH-164 catalog growth.

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0016.py pattern): it must exist, be applied by
run_migrations as version 20, and make exactly the schema change GH-164 needs.
The SQL is read with ``--`` and ``/* */`` comments blanked; statements are split
outside parentheses and literals; keywords are compared case-insensitively with
whitespace collapsed, while string literals are kept byte for byte (the audit
action list and the template key list are compared exactly). The DROP and the
ADD of one constraint may be one ALTER TABLE or two.

What these tests pin down:
- ``audit_events_action_check`` is dropped, then added again with a list that is
  0016's 47 actions plus ``user.profile_change`` (48 actions, each once): an Org
  Admin changing a user's name or email (or the refused attempt on a taken
  email) is an audit event.
- ``email_outbox_template_key_check`` is dropped, then added again with a list
  that is 0006's 7 template keys plus ``email_changed`` (8 keys, each once): the
  content-free notice that goes to a user's old address on an email change.
- The exact sync of the template key list with the live Python catalog lives
  here: it equals ``{t.value for t in EmailTemplate}`` (moved from
  tests/test_migration_0006.py, which keeps a subset check). The action list's
  exact sync with ``AuditAction`` moved on to tests/test_migration_0021.py
  (GH-166's ``password.change``): here 0020's list is a subset of the live
  catalog and still lists its own 48 actions.
- Nothing else: only ``audit_events`` and ``email_outbox`` are altered, and only
  those two constraints; no CREATE of any kind (no table, so no new grant is
  owed to the runtime role, see tests/test_migration_0018.py), no other DROP,
  no column change, no INSERT / UPDATE / DELETE / TRUNCATE (no audit event and
  no outbox row is changed), no function, trigger, DO block or dynamic SQL, no
  GRANT / REVOKE, no role change, parameter-free.

Security notes:
- The audit log stays append-only: the migration only widens the action catalog
  and touches no row.
- The template CHECK keeps a direct-DB write from queuing an unknown template;
  the new key is the only addition.
- No privilege changes: the runtime role (GH-220) gains nothing.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

import admino.database as db_mod

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0020_user_management.sql"
_VERSION = 20
_PREVIOUS_ACTION_MIGRATION = "0016_org_permissions.sql"
_PREVIOUS_TEMPLATE_MIGRATION = "0006_email_outbox.sql"

_ACTION_CONSTRAINT = "audit_events_action_check"
_TEMPLATE_CONSTRAINT = "email_outbox_template_key_check"

_NEW_ACTION = "user.profile_change"
_NEW_TEMPLATE = "email_changed"
_ACTION_CATALOG_SIZE = 48
_TEMPLATE_CATALOG_SIZE = 8

# The template catalog after GH-164, written out (not derived from the code).
_SPEC_TEMPLATE_KEYS: frozenset[str] = frozenset(
    {
        "invitation",
        "password_reset",
        "account_activated",
        "account_deactivated",
        "budget_alert",
        "model_deprecation",
        "org_deletion_scheduled",
        "email_changed",
    }
)

# The two tables this migration may alter, with the one constraint of each.
_ALTERED: dict[str, str] = {
    "audit_events": _ACTION_CONSTRAINT,
    "email_outbox": _TEMPLATE_CONSTRAINT,
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


def _statements(name: str = _MIGRATION_NAME) -> list[str]:
    return _split(_normalized(name), ";")


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    while (
        expression.startswith("(") and _balanced_end(_masked(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _check_values(name: str, constraint: str, column: str, *, added: bool) -> list[str]:
    """The literals of ``[ADD] CONSTRAINT <constraint> CHECK (<column> IN (...))`` in a
    shipped migration, in written order (duplicates kept).

    With ``added``, only an ``ADD CONSTRAINT`` counts (the replacement); without it,
    an inline table constraint of a CREATE TABLE counts too (the original).
    """
    prefix = r"\badd\s+constraint\s+" if added else r"\bconstraint\s+"
    for statement in _statements(name):
        masked = _masked(statement)
        match = re.search(rf"{prefix}{constraint}\s+check\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        expression = _unwrap(statement[match.end() : end])
        listed = re.fullmatch(rf"{column}\s+in\s*\(([^)]*)\)", expression)
        assert listed is not None, f"{constraint} must be exactly {column} IN (...): {expression}"
        return re.findall(r"'([^']*)'", listed.group(1))
    pytest.fail(f"no CONSTRAINT {constraint} CHECK ({column} IN (...)) in {name}")


def _added_actions(name: str = _MIGRATION_NAME) -> list[str]:
    return _check_values(name, _ACTION_CONSTRAINT, "action", added=True)


def _added_templates() -> list[str]:
    return _check_values(_MIGRATION_NAME, _TEMPLATE_CONSTRAINT, "template_key", added=True)


def _original_templates() -> list[str]:
    return _check_values(
        _PREVIOUS_TEMPLATE_MIGRATION, _TEMPLATE_CONSTRAINT, "template_key", added=False
    )


def _live_actions() -> set[str]:
    from admino.audit_events import AuditAction

    return {action.value for action in AuditAction}


def _live_templates() -> set[str]:
    from admino.email_templates import EmailTemplate

    return {template.value for template in EmailTemplate}


# ---------------------------------------------------------------------------
# Statement classification
# ---------------------------------------------------------------------------

_CONTRACT_KINDS = frozenset({"drop check", "add check"})
_ALTER_TABLE = r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)\s+(.*)"


def _alter_actions() -> list[tuple[int, str, str]]:
    """(statement index, table, kind) for every ALTER TABLE sub-action, in order.

    kind is "drop check" or "add check" for the table's own constraint, else
    "unexpected: ..."; a statement that is not an ALTER TABLE is "statement: ...".
    """
    actions: list[tuple[int, str, str]] = []
    for index, statement in enumerate(_statements()):
        match = re.fullmatch(_ALTER_TABLE, _masked(statement))
        if match is None:
            actions.append((index, "", f"statement: {statement}"))
            continue
        table = match.group(1)
        constraint = _ALTERED.get(table)
        for action in _split(statement[match.start(2) :], ","):
            masked = _masked(action)
            if constraint is not None and re.fullmatch(
                rf"drop\s+constraint\s+(?:if\s+exists\s+)?{constraint}(?:\s+restrict)?", masked
            ):
                actions.append((index, table, "drop check"))
            elif constraint is not None and re.fullmatch(
                rf"add\s+constraint\s+{constraint}\s+check\s*\(.*\)", masked
            ):
                actions.append((index, table, "add check"))
            else:
                actions.append((index, table, f"unexpected: {action}"))
    return actions


def _kinds_of(table: str) -> list[str]:
    return [kind for _, name, kind in _alter_actions() if name == table]


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0020File:
    """The migration ships as version 20 and is applied by run_migrations."""

    def test_migration_0020_file_is_shipped_as_version_20(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0020_is_the_only_version_20(self) -> None:
        twenties = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert twenties == [_MIGRATION_NAME]

    async def test_migration_0020_run_migrations_applies_it_as_version_20(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0019 applied, run_migrations executes the file and records 20."""
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

    async def test_migration_0020_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0020_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0020 recorded, the shipped SQL is not executed a second time."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _migration_path().read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0020_is_parameter_free(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\$\d", masked) is None
        assert "%s" not in masked
        assert "%(" not in masked


# ---------------------------------------------------------------------------
# 2. Exactly the contract's statements
# ---------------------------------------------------------------------------


class TestMigration0020Statements:
    """Two constraint swaps: the audit action check and the outbox template check."""

    def test_migration_0020_has_statements(self) -> None:
        assert _statements()

    def test_migration_0020_every_statement_is_part_of_the_contract(self) -> None:
        """Every statement is an ALTER TABLE of audit_events or email_outbox, and every
        sub-action drops or adds that table's catalog constraint."""
        unexpected = [kind for _, _, kind in _alter_actions() if kind not in _CONTRACT_KINDS]

        assert unexpected == []

    def test_migration_0020_audit_events_is_drop_then_add_of_the_action_check(self) -> None:
        """audit_events gets exactly one DROP, then one ADD, of audit_events_action_check."""
        assert _kinds_of("audit_events") == ["drop check", "add check"]

    def test_migration_0020_email_outbox_is_drop_then_add_of_the_template_check(self) -> None:
        """email_outbox gets exactly one DROP, then one ADD, of
        email_outbox_template_key_check."""
        assert _kinds_of("email_outbox") == ["drop check", "add check"]

    def test_migration_0020_alters_exactly_the_two_tables(self) -> None:
        tables = {name for _, name, _ in _alter_actions()}

        assert tables == set(_ALTERED)

    def test_migration_0020_drop_does_not_cascade(self) -> None:
        """CASCADE could silently drop more than the named constraint."""
        assert re.search(r"\bcascade\b", _masked(_migration_sql())) is None


# ---------------------------------------------------------------------------
# 3. The audit action catalog grows by user.profile_change
# ---------------------------------------------------------------------------


class TestMigration0020ActionCatalog:
    """audit_events_action_check is replaced with the 48-action catalog."""

    def test_migration_0020_action_check_adds_exactly_user_profile_change(self) -> None:
        """The new list is 0016's 47 actions plus user.profile_change."""
        old = set(_added_actions(_PREVIOUS_ACTION_MIGRATION))
        new = set(_added_actions())

        assert new - old == {_NEW_ACTION}
        assert old <= new
        assert len(new) == _ACTION_CATALOG_SIZE

    def test_migration_0020_action_check_lists_each_action_once(self) -> None:
        listed = _added_actions()

        assert len(listed) == len(set(listed)) == _ACTION_CATALOG_SIZE

    def test_migration_0020_action_check_contains_user_profile_change(self) -> None:
        """The literal byte for byte (lowercase, dotted)."""
        assert _NEW_ACTION in _added_actions()

    def test_migration_0020_action_check_is_still_in_audit_action(self) -> None:
        """Every action 0020 allows is still an AuditAction (none was dropped).

        A shipped migration never changes, so 0020's list stays its 48 actions. The
        catalog grows by replacing the audit_events_action_check constraint in a later
        migration (0021 for GH-166's password.change), so the exact sync with the
        live AuditAction lives in that migration's tests (tests/test_migration_0021.py).
        """
        assert set(_added_actions()) <= _live_actions()

    def test_migration_0020_action_check_still_lists_its_own_48_actions(self) -> None:
        """0020's list is its own 48 actions, whatever the live catalog has grown to."""
        listed = set(_added_actions())
        live = _live_actions()

        assert len(listed) == _ACTION_CATALOG_SIZE
        assert _NEW_ACTION in live
        assert len(live) >= _ACTION_CATALOG_SIZE


# ---------------------------------------------------------------------------
# 4. The email template catalog grows by email_changed
# ---------------------------------------------------------------------------


class TestMigration0020TemplateCatalog:
    """email_outbox_template_key_check is replaced with the 8-key catalog."""

    def test_migration_0020_template_check_adds_exactly_email_changed(self) -> None:
        """The new list is 0006's 7 keys plus email_changed."""
        old = set(_original_templates())
        new = set(_added_templates())

        assert new - old == {_NEW_TEMPLATE}
        assert old <= new
        assert len(new) == _TEMPLATE_CATALOG_SIZE

    def test_migration_0020_template_check_is_exactly_the_spec_keys(self) -> None:
        assert set(_added_templates()) == _SPEC_TEMPLATE_KEYS

    def test_migration_0020_template_check_lists_each_key_once(self) -> None:
        listed = _added_templates()

        assert len(listed) == len(set(listed)) == _TEMPLATE_CATALOG_SIZE

    def test_migration_0020_template_check_matches_email_template(self) -> None:
        """The live catalog sync (moved here from test_migration_0006.py): the SQL template
        keys equal EmailTemplate's values exactly."""
        assert set(_added_templates()) == _live_templates()

    def test_migration_0020_live_template_catalog_is_the_spec(self) -> None:
        assert _live_templates() == _SPEC_TEMPLATE_KEYS


# ---------------------------------------------------------------------------
# 5. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0020NothingElse:
    """No other table, column, constraint, data, code or privilege changes."""

    def test_migration_0020_writes_no_data(self) -> None:
        """No audit event and no outbox row is changed, added or deleted."""
        masked = _masked(_migration_sql())

        assert re.search(r"\binsert\b", masked) is None
        assert re.search(r"\bupdate\b", masked) is None
        assert re.search(r"\bdelete\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None
        assert re.search(r"\bmerge\b", masked) is None
        assert re.search(r"\bcopy\b", masked) is None

    def test_migration_0020_drops_only_the_two_constraints(self) -> None:
        """Two drops: the old action check and the old template check; no table."""
        masked = _masked(_migration_sql())

        assert len(re.findall(r"\bdrop\b", masked)) == 2
        assert re.search(r"\bdrop\s+table\b", masked) is None

    def test_migration_0020_alters_only_audit_events_and_email_outbox(self) -> None:
        masked = _masked(_migration_sql())
        targets = re.findall(r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", masked)

        assert set(targets) == set(_ALTERED)
        assert len(re.findall(r"\balter\b", masked)) == len(targets)

    def test_migration_0020_creates_nothing(self) -> None:
        """No table (so no grant is owed to the runtime role), index, function, trigger,
        view, type, sequence, role or extension."""
        assert re.search(r"\bcreate\b", _masked(_migration_sql())) is None

    def test_migration_0020_changes_no_column(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\bcolumn\b", masked) is None
        assert re.search(r"\brename\b", masked) is None
        assert re.search(r"\btype\b", masked) is None

    def test_migration_0020_runs_no_code(self) -> None:
        """No DO block, dollar-quoted body or dynamic SQL."""
        masked = _masked(_migration_sql())

        assert "$" not in masked
        assert re.search(r"\bdo\b", masked) is None
        assert re.search(r"\bexecute\b", masked) is None

    def test_migration_0020_grants_nothing(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:grant|revoke|owner|role|policy|security)\b", masked) is None

    def test_migration_0020_sets_no_parameter(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\b(?:set|reset)\b", masked) is None
