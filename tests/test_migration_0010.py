"""Tests for migration 0010_invitations.sql — the invitations table (GH-153).

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0009.py pattern): it must exist, be applied by
run_migrations as version 10, and make exactly the schema changes GH-153
needs. The SQL is read with comments stripped, whitespace collapsed and
lowercased, then matched with formatting-tolerant regexes; parsing is
quote-aware, and a constraint may be written inline on its column or as a
table constraint (a UNIQUE also as a unique index on the one column).

What these tests pin down:
- ``CREATE TABLE invitations`` with exactly these columns: ``id UUID PRIMARY
  KEY DEFAULT gen_random_uuid()``; ``user_id UUID NOT NULL UNIQUE REFERENCES
  users (id) ON DELETE CASCADE`` (revoking deletes the invited users row, and
  the invitation goes with it); ``token_hash BYTEA NOT NULL UNIQUE`` with
  ``CHECK (octet_length(token_hash) = 32)``; ``created_at`` and ``sent_at``
  ``TIMESTAMPTZ NOT NULL DEFAULT now()``; ``expires_at TIMESTAMPTZ NOT NULL``
  (no default: the app sets it); ``accepted_at TIMESTAMPTZ`` (nullable, no
  default). No column for a raw token, an email, a name or a link.
- CHECKs: ``sent_at >= created_at``; ``expires_at > sent_at`` and
  ``expires_at <= sent_at + interval '72 hours'``.
- ``audit_events_action_check`` is replaced (dropped, then added) by a CHECK
  whose action list is 0009's 41 plus ``invitation.resend`` and
  ``invitation.refuse`` (43 actions, all still in ``AuditAction``; the exact
  sync with the live catalog moved to tests/test_migration_0016.py when GH-161
  added the ``org.permission_*`` actions).
- Nothing else changes: one table created, none dropped, only ``audit_events``
  altered (and only its action check), no UPDATE / INSERT / DELETE / TRUNCATE,
  no function, trigger, view or type; an index, if any, is on invitations.
- Python and SQL stay in sync: the 72-hour cap is
  ``admino.invitations.INVITATION_LIFETIME``, the action list is within
  ``AuditAction``.

Security notes:
- Only the SHA-256 digest of a token can be stored (32 bytes, no raw column).
- The CHECKs mirror the Python bounds, so the schema stays safe even against a
  direct-DB write that bypasses the app.
- The audit log stays append-only: the migration only widens the catalog.
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

_MIGRATION_NAME = "0010_invitations.sql"
_NEW_ACTIONS = frozenset({"invitation.resend", "invitation.refuse"})
_COLUMNS = frozenset(
    {"id", "user_id", "token_hash", "created_at", "sent_at", "expires_at", "accepted_at"}
)

# Formatting-tolerant patterns.
_TIMESTAMPTZ = r"(?:timestamptz|timestamp\s*(?:\(\s*\d\s*\)\s*)?with\s+time\s+zone)"
_NOW = r"(?:now\s*\(\s*\)|current_timestamp|transaction_timestamp\s*\(\s*\))"
_SEVENTY_TWO_HOURS = (
    r"(?:interval\s*'\s*72\s*hours?\s*'"
    r"|'\s*72\s*hours?\s*'\s*::\s*interval"
    r"|interval\s*'\s*3\s*days?\s*'"
    r"|interval\s*'\s*72:00(?::00)?\s*'"
    r"|make_interval\s*\(\s*hours\s*=>\s*72\s*\))"
)
_CONSTRAINT_START = (
    r"(?:constraint\s+\w+\s+)?(?:check|unique|primary\s+key|foreign\s+key|exclude)\b"
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


def _statements() -> list[str]:
    """The migration's statements (split at semicolons outside literals), lowercased."""
    return _split(_migration_sql(), ";")


def _create_table_body() -> str:
    """The text between the parentheses of CREATE TABLE invitations (...)."""
    for statement in _statements():
        masked = _masked(statement)
        match = re.match(r"create\s+table\s+(?:if\s+not\s+exists\s+)?invitations\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        assert masked[end + 1 :].strip() == "", statement
        return statement[match.end() : end]
    pytest.fail("no CREATE TABLE invitations (...)")


def _elements() -> list[str]:
    """The column definitions and table constraints of CREATE TABLE invitations."""
    return _split(_create_table_body(), ",")


def _column_definitions() -> dict[str, str]:
    """Column name -> the rest of its definition."""
    columns: dict[str, str] = {}
    for element in _elements():
        if re.match(_CONSTRAINT_START, element):
            continue
        match = re.fullmatch(r'"?(\w+)"?\s+(.*)', element)
        assert match is not None, element
        columns[match.group(1)] = match.group(2)
    return columns


def _column(name: str) -> str:
    columns = _column_definitions()
    assert name in columns, f"no column {name} in CREATE TABLE invitations"
    return columns[name]


def _table_constraints() -> list[str]:
    return [element for element in _elements() if re.match(_CONSTRAINT_START, element)]


def _check_expressions() -> list[str]:
    """Every CHECK (...) expression of the table (inline or table-level)."""
    expressions: list[str] = []
    for element in _elements():
        masked = _masked(element)
        for match in re.finditer(r"\bcheck\s*\(", masked):
            end = _balanced_end(masked, match.end() - 1)
            expressions.append(element[match.end() : end].strip())
    return expressions


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    while (
        expression.startswith("(") and _balanced_end(_masked(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _check_atoms() -> list[str]:
    """Every AND-ed condition of every CHECK, parentheses around each dropped."""
    atoms: list[str] = []
    for expression in _check_expressions():
        masked = _masked(_unwrap(expression))
        unwrapped = _unwrap(expression)
        start = 0
        depth = 0
        for match in re.finditer(r"\(|\)|\band\b", masked):
            token = match.group(0)
            if token == "(":
                depth += 1
            elif token == ")":
                depth -= 1
            elif depth == 0:
                atoms.append(_unwrap(unwrapped[start : match.start()]))
                start = match.end()
        atoms.append(_unwrap(unwrapped[start:]))
    return atoms


def _any_atom(*patterns: str) -> bool:
    return any(re.fullmatch(pattern, atom) for atom in _check_atoms() for pattern in patterns)


def _is_unique(column: str) -> bool:
    """UNIQUE inline, as a table constraint on the one column, or as a unique index."""
    if re.search(r"\bunique\b", _masked(_column(column))):
        return True
    for constraint in _table_constraints():
        if re.fullmatch(rf"(?:constraint\s+\w+\s+)?unique\s*\(\s*{column}\s*\)", constraint):
            return True
    return any(
        re.fullmatch(
            rf"create\s+unique\s+index\s+(?:if\s+not\s+exists\s+)?\w+\s+on\s+invitations"
            rf"\s*(?:using\s+btree\s*)?\(\s*{column}\s*\)",
            statement,
        )
        for statement in _statements()
    )


def _alter_actions(table: str) -> list[tuple[int, int, str]]:
    """(statement index, action index, action) for every ALTER TABLE <table> action."""
    actions: list[tuple[int, int, str]] = []
    for statement_index, statement in enumerate(_statements()):
        match = re.fullmatch(
            r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)\s+(.*)", statement, re.DOTALL
        )
        if match is None or match.group(1) != table:
            continue
        for action_index, action in enumerate(_split(match.group(2), ",")):
            actions.append((statement_index, action_index, action))
    return actions


def _position(table: str, pattern: str) -> tuple[int, int]:
    for statement_index, action_index, action in _alter_actions(table):
        if re.fullmatch(pattern, action):
            return statement_index, action_index
    pytest.fail(f"no ALTER TABLE {table} action matches {pattern!r} in {_MIGRATION_NAME}")


def _in_values(expression: str) -> set[str] | None:
    """The literals of 'action IN (...)' when that is the whole expression."""
    match = re.fullmatch(r"\s*\(?\s*action\s+in\s*\(([^)]*)\)\s*\)?\s*", expression)
    if match is None:
        return None
    return set(re.findall(r"'([^']*)'", match.group(1)))


def _added_action_check(name: str = _MIGRATION_NAME) -> set[str]:
    """The action list of ADD CONSTRAINT audit_events_action_check CHECK (action IN (...))
    in a shipped migration."""
    for statement in _split(_read(name), ";"):
        masked = _masked(statement)
        match = re.search(r"\badd\s+constraint\s+audit_events_action_check\s+check\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        values = _in_values(statement[match.end() : end])
        assert values is not None, statement
        return values
    pytest.fail(f"no ADD CONSTRAINT audit_events_action_check CHECK (action IN (...)) in {name}")


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0010File:
    """The migration ships as version 10 and is applied by run_migrations."""

    def test_migration_0010_file_is_shipped_as_version_10(self) -> None:
        assert (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == 10

    def test_migration_0010_is_the_only_version_10(self) -> None:
        tens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == 10
        ]

        assert tens == [_MIGRATION_NAME]

    async def test_migration_0010_run_migrations_applies_it_as_version_10(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0009 applied, run_migrations executes the file and records 10."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, 10)])

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert (10, _MIGRATION_NAME) in recorded
        assert all(version >= 10 for version, _ in recorded)

    async def test_migration_0010_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, 10)])
        shipped = (db_mod._MIGRATIONS_DIR / _MIGRATION_NAME).read_text(encoding="utf-8")

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0010_is_parameter_free(self) -> None:
        sql = _migration_sql()

        assert re.search(r"\$\d", sql) is None
        assert "%s" not in sql
        assert "%(" not in sql


# ---------------------------------------------------------------------------
# 2. The invitations table
# ---------------------------------------------------------------------------


class TestMigration0010InvitationsTable:
    """CREATE TABLE invitations: the columns, their types, defaults and keys."""

    def test_migration_0010_creates_the_invitations_table_once(self) -> None:
        creates = [s for s in _statements() if re.match(r"create\s+table\b", _masked(s))]

        assert len(creates) == 1
        _create_table_body()

    def test_migration_0010_has_exactly_the_listed_columns(self) -> None:
        """No column for a raw token, an email, a name or a link."""
        assert set(_column_definitions()) == _COLUMNS

    def test_migration_0010_id_is_a_generated_uuid_primary_key(self) -> None:
        definition = _masked(_column("id"))

        assert re.match(r"uuid\b", definition), definition
        assert re.search(r"\bdefault\s+gen_random_uuid\s*\(\s*\)", definition), definition
        primary_inline = re.search(r"\bprimary\s+key\b", definition) is not None
        primary_table = any(
            re.fullmatch(r"(?:constraint\s+\w+\s+)?primary\s+key\s*\(\s*id\s*\)", constraint)
            for constraint in _table_constraints()
        )
        assert primary_inline or primary_table

    def test_migration_0010_user_id_is_a_required_unique_uuid(self) -> None:
        """One invitation per invited user."""
        definition = _masked(_column("user_id"))

        assert re.match(r"uuid\b", definition), definition
        assert re.search(r"\bnot\s+null\b", definition), definition
        assert _is_unique("user_id")

    def test_migration_0010_user_id_cascades_from_users(self) -> None:
        """REFERENCES users (id) ON DELETE CASCADE: revoking (deleting the invited users
        row) removes the invitation."""
        inline = re.search(
            r"\breferences\s+users\s*\(\s*id\s*\)\s+on\s+delete\s+cascade\b",
            _masked(_column("user_id")),
        )
        table_level = any(
            re.fullmatch(
                r"(?:constraint\s+\w+\s+)?foreign\s+key\s*\(\s*user_id\s*\)\s+references\s+users"
                r"\s*\(\s*id\s*\)\s+on\s+delete\s+cascade",
                constraint,
            )
            for constraint in _table_constraints()
        )
        assert inline or table_level

    def test_migration_0010_token_hash_is_a_required_unique_bytea(self) -> None:
        definition = _masked(_column("token_hash"))

        assert re.match(r"bytea\b", definition), definition
        assert re.search(r"\bnot\s+null\b", definition), definition
        assert _is_unique("token_hash")

    def test_migration_0010_token_hash_is_exactly_32_bytes(self) -> None:
        """CHECK (octet_length(token_hash) = 32): a SHA-256 digest, never a raw token."""
        assert _any_atom(
            r"octet_length\s*\(\s*token_hash\s*\)\s*=\s*32",
            r"32\s*=\s*octet_length\s*\(\s*token_hash\s*\)",
        ), _check_expressions()

    @pytest.mark.parametrize("column", ["created_at", "sent_at"])
    def test_migration_0010_timestamps_default_to_now(self, column: str) -> None:
        definition = _masked(_column(column))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert re.search(r"\bnot\s+null\b", definition), definition
        assert re.search(rf"\bdefault\s+\(?\s*{_NOW}", definition), definition

    def test_migration_0010_expires_at_is_required_without_default(self) -> None:
        """The app computes it (now() + 72 hours on the database clock)."""
        definition = _masked(_column("expires_at"))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert re.search(r"\bnot\s+null\b", definition), definition
        assert re.search(r"\bdefault\b", definition) is None

    def test_migration_0010_accepted_at_is_nullable_without_default(self) -> None:
        """NULL while the invitation is pending."""
        definition = _masked(_column("accepted_at"))

        assert re.match(_TIMESTAMPTZ, definition), definition
        assert re.search(r"\bnot\s+null\b", definition) is None
        assert re.search(r"\bdefault\b", definition) is None


# ---------------------------------------------------------------------------
# 3. The CHECKs
# ---------------------------------------------------------------------------


class TestMigration0010Checks:
    """sent_at after created_at; expires_at after sent_at and at most 72 hours later."""

    def test_migration_0010_sent_at_is_not_before_created_at(self) -> None:
        assert _any_atom(
            r"sent_at\s*>=\s*created_at",
            r"created_at\s*<=\s*sent_at",
        ), _check_expressions()

    def test_migration_0010_expires_at_is_after_sent_at(self) -> None:
        assert _any_atom(
            r"expires_at\s*>\s*sent_at",
            r"sent_at\s*<\s*expires_at",
        ), _check_expressions()

    def test_migration_0010_lifetime_is_capped_at_72_hours(self) -> None:
        """expires_at <= sent_at + interval '72 hours' (a resend moves both)."""
        assert _any_atom(
            rf"expires_at\s*<=\s*\(?\s*sent_at\s*\+\s*{_SEVENTY_TWO_HOURS}\s*\)?",
            rf"\(?\s*sent_at\s*\+\s*{_SEVENTY_TWO_HOURS}\s*\)?\s*>=\s*expires_at",
        ), _check_expressions()


# ---------------------------------------------------------------------------
# 4. The audit action catalog grows by one
# ---------------------------------------------------------------------------

_DROP_ACTION_CHECK = r"drop\s+constraint\s+(?:if\s+exists\s+)?audit_events_action_check"
_ADD_ACTION_CHECK = r"add\s+constraint\s+audit_events_action_check\s+check\s*\(.*\)"


class TestMigration0010ActionCatalog:
    """audit_events_action_check is replaced with the 43-action catalog."""

    def test_migration_0010_drops_the_old_action_check(self) -> None:
        _position("audit_events", _DROP_ACTION_CHECK)

    def test_migration_0010_adds_the_new_action_check_after_dropping_the_old(self) -> None:
        dropped = _position("audit_events", _DROP_ACTION_CHECK)
        added = _position("audit_events", _ADD_ACTION_CHECK)

        assert dropped < added

    def test_migration_0010_action_check_adds_exactly_the_invitation_actions(self) -> None:
        """The new list is 0009's 41 actions plus invitation.resend and invitation.refuse."""
        old = _added_action_check("0009_session_policies.sql")
        new = _added_action_check()

        assert new - old == _NEW_ACTIONS
        assert old <= new
        assert len(new) == 43

    def test_migration_0010_action_check_is_still_in_audit_action(self) -> None:
        """Every action 0010 allows is still an AuditAction (none was dropped).

        A shipped migration never changes, so 0010's list stays its 43 actions
        (test_migration_0010_action_check_adds_exactly_the_invitation_actions pins it). The
        catalog grows by replacing the audit_events_action_check constraint in a later
        migration (0016 for GH-161's org.permission_* actions), so the exact sync with the
        live AuditAction lives in that migration's tests (tests/test_migration_0016.py).
        """
        from admino.audit_events import AuditAction

        assert _added_action_check() <= {action.value for action in AuditAction}


# ---------------------------------------------------------------------------
# 5. Nothing else changes
# ---------------------------------------------------------------------------


class TestMigration0010ChangesNothingElse:
    """One table created; only audit_events' action check altered; no data touched."""

    def test_migration_0010_drops_no_table(self) -> None:
        assert re.search(r"\bdrop\s+table\b", _masked(_migration_sql())) is None

    def test_migration_0010_alters_only_audit_events(self) -> None:
        masked = _masked(_migration_sql())
        targets = re.findall(r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(\w+)", masked)

        assert set(targets) == {"audit_events"}

    def test_migration_0010_changes_only_the_action_check_of_audit_events(self) -> None:
        """The audit_events actions are the DROP and the ADD of audit_events_action_check."""
        for _, _, action in _alter_actions("audit_events"):
            assert re.fullmatch(_DROP_ACTION_CHECK + r"(?:\s+(?:restrict|cascade))?", action) or (
                re.fullmatch(_ADD_ACTION_CHECK, action)
            ), action

    def test_migration_0010_writes_no_data(self) -> None:
        """No UPDATE, INSERT, DELETE or TRUNCATE."""
        masked = _masked(_migration_sql())

        assert re.search(r"\bupdate\s+(?:only\s+)?\w+\s+set\b", masked) is None
        assert re.search(r"\binsert\s+into\b", masked) is None
        assert re.search(r"\bdelete\s+from\b", masked) is None
        assert re.search(r"\btruncate\b", masked) is None

    def test_migration_0010_defines_no_function_trigger_or_view(self) -> None:
        masked = _masked(_migration_sql())

        assert (
            re.search(
                r"\b(?:create|drop|alter)\s+(?:or\s+replace\s+)?(?:function|trigger|view|type)\b",
                masked,
            )
            is None
        )

    def test_migration_0010_indexes_only_invitations(self) -> None:
        masked = _masked(_migration_sql())
        tables = re.findall(
            r"\bcreate\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?"
            r"\w+\s+on\s+(?:only\s+)?(\w+)",
            masked,
        )

        assert set(tables) <= {"invitations"}
        assert re.search(r"\bdrop\s+index\b", masked) is None


# ---------------------------------------------------------------------------
# 6. Python and SQL stay in sync
# ---------------------------------------------------------------------------


class TestMigration0010PythonSync:
    """The CHECKs mirror admino.invitations."""

    def test_migration_0010_lifetime_cap_matches_invitation_lifetime(self) -> None:
        from datetime import timedelta

        from admino import invitations

        assert timedelta(hours=72) == invitations.INVITATION_LIFETIME
        assert _any_atom(
            rf"expires_at\s*<=\s*\(?\s*sent_at\s*\+\s*{_SEVENTY_TWO_HOURS}\s*\)?",
            rf"\(?\s*sent_at\s*\+\s*{_SEVENTY_TWO_HOURS}\s*\)?\s*>=\s*expires_at",
        )
