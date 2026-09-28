"""Tests for migration 0009_session_policies.sql — session policies (GH-152).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0007.py / 0008 pattern): it must exist, be applied by
run_migrations as version 9, and make exactly the schema changes GH-152 needs.
The SQL is read with comments stripped, whitespace collapsed and lowercased,
then matched with formatting-tolerant regexes; parsing is quote-aware, and
ALTER TABLE statements are split into their actions, so one combined ALTER and
several separate ones are read the same way.

What these tests pin down:
- Revoking a session deletes its row: the rows that were already revoked are
  deleted (``DELETE FROM sessions WHERE revoked_at IS NOT NULL``) before the
  ``revoked_at`` column is dropped (its ``sessions_revocation_check`` goes with
  it, explicitly or through the column drop).
- ``sessions.idle_timeout_minutes INTEGER NOT NULL`` is added with a CHECK of 15
  to 480; existing rows are backfilled with 60 through the column's DEFAULT,
  which is dropped afterwards so the app always sets it.
- A CHECK caps the lifetime: ``expires_at <= created_at + interval '72 hours'``.
- ``audit_events_action_check`` is replaced (dropped, then added) by a CHECK
  whose action list is 0005's 39 plus ``session.revoke`` and
  ``session.force_logout`` (41 actions, all still in ``AuditAction``; the exact
  sync with the live catalog moved to tests/test_migration_0010.py when GH-153
  added ``invitation.resend``).
- Nothing else changes: no table is created or dropped, only ``sessions`` and
  ``audit_events`` are altered, no UPDATE, no INSERT, and no DELETE other than
  the revoked sessions one (never on audit_events).
- Python and SQL stay in sync: the bounds and the default are the
  ``admino.sessions`` constants.

Security notes:
- The CHECKs mirror the Pydantic bounds, so the schema stays safe even against
  a direct-DB write that bypasses the app.
- The audit log stays append-only: the migration never deletes or updates an
  audit event, it only widens the action catalog.
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

_MIGRATION_NAME = "0009_session_policies.sql"
_NEW_ACTIONS = frozenset({"session.revoke", "session.force_logout"})

# Formatting-tolerant patterns.
_INTEGER = r"(?:integer|int4|int)"
_SEVENTY_TWO_HOURS = (
    r"(?:interval\s*'\s*72\s*hours?\s*'"
    r"|'\s*72\s*hours?\s*'\s*::\s*interval"
    r"|interval\s*'\s*3\s*days?\s*'"
    r"|interval\s*'\s*72:00(?::00)?\s*'"
    r"|make_interval\s*\(\s*hours\s*=>\s*72\s*\))"
)


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _read(name: str) -> str:
    """Return a shipped migration, comments stripped, whitespace collapsed, lowercased."""
    raw = (db_mod._MIGRATIONS_DIR / name).read_text(encoding="utf-8")
    without_comments = re.sub(r"--.*", " ", raw)
    return re.sub(r"\s+", " ", without_comments).strip().lower()


def _migration_sql() -> str:
    return _read(_MIGRATION_NAME)


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


def _statements(sql: str | None = None) -> list[str]:
    """The migration's statements (split at semicolons outside literals), lowercased."""
    return _split(_migration_sql() if sql is None else sql, ";")


_ALTER_RE = re.compile(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)\s+(.*)", re.DOTALL)


def _alter_actions(table: str) -> list[tuple[int, int, str]]:
    """(statement index, action index, action) for every ALTER TABLE <table> action, in
    order. One ALTER with several comma-separated actions and several ALTERs read the
    same."""
    actions: list[tuple[int, int, str]] = []
    for statement_index, statement in enumerate(_statements()):
        match = _ALTER_RE.fullmatch(statement)
        if match is None or match.group(1) != table:
            continue
        for action_index, action in enumerate(_split(match.group(2), ",")):
            actions.append((statement_index, action_index, action))
    return actions


def _position(table: str, pattern: str) -> tuple[int, int]:
    """The (statement, action) position of the first ALTER TABLE <table> action that
    fully matches the pattern."""
    for statement_index, action_index, action in _alter_actions(table):
        if re.fullmatch(pattern, action):
            return statement_index, action_index
    pytest.fail(f"no ALTER TABLE {table} action matches {pattern!r} in {_MIGRATION_NAME}")


def _checks_on(table: str) -> list[str]:
    """Every CHECK (...) expression the migration adds to a table (inline in ADD COLUMN or
    as ADD CONSTRAINT), lowercased."""
    expressions: list[str] = []
    for _, _, action in _alter_actions(table):
        if not re.match(r"add\s+", action):
            continue
        masked = _masked(action)
        for match in re.finditer(r"\bcheck\s*\(", masked):
            end = _balanced_end(masked, match.end() - 1)
            expressions.append(action[match.end() : end].strip())
    return expressions


def _any_check_matches(table: str, *patterns: str) -> bool:
    return any(re.search(pattern, check) for check in _checks_on(table) for pattern in patterns)


def _in_values(expression: str) -> set[str] | None:
    """The literals of 'action IN (...)' when that is the whole expression."""
    match = re.fullmatch(r"\s*\(?\s*action\s+in\s*\(([^)]*)\)\s*\)?\s*", expression)
    if match is None:
        return None
    return set(re.findall(r"'([^']*)'", match.group(1)))


def _added_action_check() -> set[str]:
    """The action list of ADD CONSTRAINT audit_events_action_check CHECK (action IN (...))."""
    for _, _, action in _alter_actions("audit_events"):
        masked = _masked(action)
        match = re.match(r"add\s+constraint\s+audit_events_action_check\s+check\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        values = _in_values(action[match.end() : end])
        assert values is not None, action
        return values
    pytest.fail("no ADD CONSTRAINT audit_events_action_check CHECK (action IN (...))")


def _migration_0005_actions() -> set[str]:
    """The action list migration 0005 shipped (its named CHECK inside CREATE TABLE)."""
    sql = _read("0005_audit_events.sql")
    masked = _masked(sql)
    match = re.search(r"\bconstraint\s+audit_events_action_check\s+check\s*\(", masked)
    assert match is not None
    end = _balanced_end(masked, match.end() - 1)
    values = _in_values(sql[match.end() : end])
    assert values is not None
    return values


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0009File:
    """The migration ships as version 9 and is applied by run_migrations."""

    def test_migration_0009_file_is_shipped_as_version_9(self) -> None:
        """0009_session_policies.sql exists and matches the numbered-migration regex."""
        assert (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == 9

    def test_migration_0009_is_the_only_version_9(self) -> None:
        """Exactly one migration file claims version 9, and it is this one."""
        nines = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == 9
        ]

        assert nines == [_MIGRATION_NAME]

    async def test_migration_0009_run_migrations_applies_it_as_version_9(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0008 applied, run_migrations executes the file and records version 9."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, 9)])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (9, _MIGRATION_NAME) in recorded
        assert all(version >= 9 for version, _ in recorded)

    async def test_migration_0009_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        """run_migrations executes the 0009 file's SQL text verbatim."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, 9)])
        shipped = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0009_is_parameter_free(self) -> None:
        """No bind parameters or interpolation placeholders in the migration."""
        sql = _migration_sql()

        assert re.search(r"\$\d", sql) is None
        assert "%s" not in sql
        assert "%(" not in sql


# ---------------------------------------------------------------------------
# 2. Revoking deletes the row: revoked_at goes, and so do the revoked rows
# ---------------------------------------------------------------------------

_DELETE_REVOKED = r"delete\s+from\s+sessions\s+where\s+revoked_at\s+is\s+not\s+null"
_DROP_REVOKED_AT = r"drop\s+column\s+(?:if\s+exists\s+)?revoked_at(?:\s+(?:restrict|cascade))?"
_DROP_REVOCATION_CHECK = r"drop\s+constraint\s+(?:if\s+exists\s+)?sessions_revocation_check\b.*"


class TestMigration0009Revocation:
    """Already-revoked rows are deleted, then revoked_at is dropped."""

    def test_migration_0009_deletes_the_revoked_sessions(self) -> None:
        """DELETE FROM sessions WHERE revoked_at IS NOT NULL, exactly once."""
        deletes = [s for s in _statements() if re.fullmatch(_DELETE_REVOKED, s)]

        assert len(deletes) == 1

    def test_migration_0009_drops_the_revoked_at_column(self) -> None:
        """ALTER TABLE sessions DROP COLUMN revoked_at."""
        _position("sessions", _DROP_REVOKED_AT)

    def test_migration_0009_deletes_before_dropping_the_column(self) -> None:
        """The DELETE needs the column, so it runs first."""
        delete_index = next(
            index for index, s in enumerate(_statements()) if re.fullmatch(_DELETE_REVOKED, s)
        )

        assert delete_index < _position("sessions", _DROP_REVOKED_AT)[0]

    def test_migration_0009_revocation_check_goes_with_the_column(self) -> None:
        """sessions_revocation_check (revoked_at >= created_at) disappears: dropped
        explicitly before the column (or with IF EXISTS), or with the column itself."""
        explicit = [
            (statement, action, text)
            for statement, action, text in _alter_actions("sessions")
            if re.fullmatch(_DROP_REVOCATION_CHECK, text)
        ]
        column = _position("sessions", _DROP_REVOKED_AT)

        for statement, action, text in explicit:
            assert (statement, action) < column or re.search(r"\bif\s+exists\b", text), text

    def test_migration_0009_names_revoked_at_only_to_remove_it(self) -> None:
        """revoked_at appears only in the DELETE of revoked rows and in its DROP COLUMN:
        nothing re-adds or reads it."""
        for statement in _statements():
            if not re.search(r"\brevoked_at\b", _masked(statement)):
                continue
            if re.fullmatch(_DELETE_REVOKED, statement):
                continue
            match = _ALTER_RE.fullmatch(statement)
            assert match is not None, statement
            assert match.group(1) == "sessions", statement
            for action in _split(match.group(2), ","):
                if re.search(r"\brevoked_at\b", _masked(action)):
                    assert re.fullmatch(_DROP_REVOKED_AT, action), action


# ---------------------------------------------------------------------------
# 3. idle_timeout_minutes: each row's own idle timeout
# ---------------------------------------------------------------------------

_ADD_IDLE = rf"add\s+column\s+(?:if\s+not\s+exists\s+)?idle_timeout_minutes\s+{_INTEGER}\b.*"
_DROP_IDLE_DEFAULT = r"alter\s+(?:column\s+)?idle_timeout_minutes\s+drop\s+default"


def _add_idle_action() -> str:
    """The ADD COLUMN idle_timeout_minutes action."""
    for _, _, action in _alter_actions("sessions"):
        if re.fullmatch(_ADD_IDLE, action):
            return action
    pytest.fail("no ALTER TABLE sessions ADD COLUMN idle_timeout_minutes INTEGER")


class TestMigration0009IdleTimeout:
    """INTEGER NOT NULL, CHECKed 15 to 480, backfilled with 60, then no default."""

    def test_migration_0009_adds_idle_timeout_as_integer(self) -> None:
        """ALTER TABLE sessions ADD COLUMN idle_timeout_minutes INTEGER ..."""
        assert re.match(
            rf"add\s+column\s+.*idle_timeout_minutes\s+{_INTEGER}\b", _add_idle_action()
        )

    def test_migration_0009_idle_timeout_is_not_null(self) -> None:
        """NOT NULL: every session has an idle timeout."""
        masked = _masked(_add_idle_action())

        assert re.search(r"(?<!is )\bnot null\b", masked) is not None, masked

    def test_migration_0009_existing_rows_are_backfilled_with_60(self) -> None:
        """DEFAULT 60 on the ADD COLUMN fills the rows that exist (the old default)."""
        assert re.search(r"\bdefault\s+\(?\s*60\s*\)?(?=[\s,)]|$)", _add_idle_action()), (
            _add_idle_action()
        )

    def test_migration_0009_drops_the_default_after_the_backfill(self) -> None:
        """ALTER COLUMN idle_timeout_minutes DROP DEFAULT, after the ADD COLUMN: the app
        always sets the row's timeout from its policy."""
        added = _position("sessions", _ADD_IDLE)
        dropped = _position("sessions", _DROP_IDLE_DEFAULT)

        assert added < dropped

    def test_migration_0009_sets_no_other_default(self) -> None:
        """No SET DEFAULT brings a default back."""
        masked = _masked(_migration_sql())

        assert re.search(r"\bidle_timeout_minutes\s+set\s+default\b", masked) is None

    def test_migration_0009_idle_timeout_is_checked_15_to_480(self) -> None:
        """CHECK (idle_timeout_minutes BETWEEN 15 AND 480), or the >= / <= pair."""
        assert _any_check_matches(
            "sessions",
            r"^\(?\s*idle_timeout_minutes\s+between\s+15\s+and\s+480\s*\)?$",
            r"^\(?\s*idle_timeout_minutes\s*>=\s*15\s+and\s+idle_timeout_minutes\s*<=\s*480"
            r"\s*\)?$",
            r"^\(?\s*idle_timeout_minutes\s*<=\s*480\s+and\s+idle_timeout_minutes\s*>=\s*15"
            r"\s*\)?$",
        ), _checks_on("sessions")


# ---------------------------------------------------------------------------
# 4. The lifetime cap
# ---------------------------------------------------------------------------


class TestMigration0009Lifetime:
    """A session expires at most 72 hours after it was created."""

    def test_migration_0009_caps_the_lifetime_at_72_hours(self) -> None:
        """CHECK (expires_at <= created_at + interval '72 hours')."""
        assert _any_check_matches(
            "sessions",
            rf"\bexpires_at\s*<=\s*\(?\s*created_at\s*\+\s*{_SEVENTY_TWO_HOURS}",
            rf"\bcreated_at\s*\+\s*{_SEVENTY_TWO_HOURS}\s*\)?\s*>=\s*expires_at\b",
        ), _checks_on("sessions")


# ---------------------------------------------------------------------------
# 5. The audit action catalog grows by two
# ---------------------------------------------------------------------------

_DROP_ACTION_CHECK = r"drop\s+constraint\s+(?:if\s+exists\s+)?audit_events_action_check"
_ADD_ACTION_CHECK = r"add\s+constraint\s+audit_events_action_check\s+check\s*\(.*\)"


class TestMigration0009ActionCatalog:
    """audit_events_action_check is replaced with the 41-action catalog."""

    def test_migration_0009_drops_the_old_action_check(self) -> None:
        """ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check."""
        _position("audit_events", _DROP_ACTION_CHECK)

    def test_migration_0009_adds_the_new_action_check_after_dropping_the_old(self) -> None:
        """The same name comes back: DROP first, then ADD CONSTRAINT ... CHECK."""
        dropped = _position("audit_events", _DROP_ACTION_CHECK)
        added = _position("audit_events", _ADD_ACTION_CHECK)

        assert dropped < added

    def test_migration_0009_action_check_adds_exactly_the_session_actions(self) -> None:
        """The new list is 0005's list plus session.revoke and session.force_logout."""
        old = _migration_0005_actions()
        new = _added_action_check()

        assert new - old == _NEW_ACTIONS
        assert old <= new
        assert len(new) == 41

    def test_migration_0009_action_check_is_still_in_audit_action(self) -> None:
        """Every action 0009 allows is still an AuditAction (none was dropped).

        A shipped migration never changes, so 0009's list stays its 41 actions
        (test_migration_0009_action_check_adds_exactly_the_session_actions pins it). The
        catalog grows by replacing the audit_events_action_check constraint in a later
        migration (0010 for GH-153's invitation.resend), so the exact sync with the live
        AuditAction lives in that migration's tests (tests/test_migration_0010.py).
        """
        from admino.audit_events import AuditAction

        assert _added_action_check() <= {action.value for action in AuditAction}


# ---------------------------------------------------------------------------
# 6. Nothing else changes
# ---------------------------------------------------------------------------


class TestMigration0009ChangesNothingElse:
    """Only sessions and audit_events are altered; no other data is touched."""

    def test_migration_0009_creates_and_drops_no_table(self) -> None:
        masked = _masked(_migration_sql())

        assert re.search(r"\bcreate\s+table\b", masked) is None
        assert re.search(r"\bdrop\s+table\b", masked) is None

    def test_migration_0009_alters_only_sessions_and_audit_events(self) -> None:
        masked = _masked(_migration_sql())
        targets = re.findall(r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", masked)

        assert set(targets) == {"sessions", "audit_events"}

    def test_migration_0009_updates_and_inserts_nothing(self) -> None:
        """No UPDATE, INSERT or TRUNCATE: the backfill is the column default."""
        masked = _masked(_migration_sql())

        assert re.search(r"\bupdate\s+(?:only\s+)?\w+\s+set\b", masked) is None
        assert re.search(r"\binsert\s+into\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None

    def test_migration_0009_deletes_only_revoked_sessions(self) -> None:
        """The one DELETE is the revoked sessions one; no audit event is ever deleted."""
        masked = _masked(_migration_sql())

        assert len(re.findall(r"\bdelete\s+from\b", masked)) == 1
        assert re.search(r"\bdelete\s+from\s+audit_events\b", masked) is None

    def test_migration_0009_drops_only_revoked_at_and_the_two_checks(self) -> None:
        """The only column dropped is revoked_at; the only constraints dropped are
        audit_events_action_check (replaced) and sessions_revocation_check."""
        masked = _masked(_migration_sql())
        columns = re.findall(r"\bdrop\s+column\s+(?:if\s+exists\s+)?(\w+)", masked)
        constraints = re.findall(r"\bdrop\s+constraint\s+(?:if\s+exists\s+)?(\w+)", masked)

        assert columns == ["revoked_at"]
        assert set(constraints) <= {"audit_events_action_check", "sessions_revocation_check"}
        assert "audit_events_action_check" in constraints

    def test_migration_0009_defines_no_function_trigger_or_view(self) -> None:
        """The append-only trigger and the purge function of 0005 stay untouched."""
        masked = _masked(_migration_sql())

        assert (
            re.search(
                r"\b(?:create|drop|alter)\s+(?:or\s+replace\s+)?(?:function|trigger|view|type)\b",
                masked,
            )
            is None
        )


# ---------------------------------------------------------------------------
# 7. Python and SQL stay in sync
# ---------------------------------------------------------------------------


class TestMigration0009PythonSync:
    """The CHECKs and the backfill mirror admino.sessions."""

    def test_migration_0009_idle_bounds_match_sessions(self) -> None:
        """MIN/MAX_IDLE_TIMEOUT_MINUTES are the CHECK's 15 and 480."""
        from admino import sessions

        low, high = sessions.MIN_IDLE_TIMEOUT_MINUTES, sessions.MAX_IDLE_TIMEOUT_MINUTES
        assert (low, high) == (15, 480)
        assert _any_check_matches(
            "sessions",
            rf"idle_timeout_minutes\s+between\s+{low}\s+and\s+{high}\b",
            rf"idle_timeout_minutes\s*>=\s*{low}\b.*idle_timeout_minutes\s*<=\s*{high}\b",
            rf"idle_timeout_minutes\s*<=\s*{high}\b.*idle_timeout_minutes\s*>=\s*{low}\b",
        )

    def test_migration_0009_backfill_is_the_default_idle_timeout(self) -> None:
        """DEFAULT_IDLE_TIMEOUT_MINUTES is the backfill value."""
        from admino import sessions

        assert sessions.DEFAULT_IDLE_TIMEOUT_MINUTES == 60
        assert re.search(
            rf"\bdefault\s+\(?\s*{sessions.DEFAULT_IDLE_TIMEOUT_MINUTES}\b", _add_idle_action()
        )

    def test_migration_0009_lifetime_cap_matches_sessions(self) -> None:
        """MAX_LIFETIME_HOURS is the CHECK's 72 hours."""
        from admino import sessions

        assert sessions.MAX_LIFETIME_HOURS == 72
        assert _any_check_matches("sessions", rf"created_at\s*\+\s*{_SEVENTY_TWO_HOURS}")
