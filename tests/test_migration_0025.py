"""Tests for migration 0025_chats_column_grants.sql (GH-266): admino_app updates only
the chat columns the application writes, and a chat's external-content mark sticks.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec. These
tests pin what the migration guarantees, not how it is worded: the SQL is read with
tests/test_migration_0018.py's lexer (comments blanked, '...' literals and
dollar-quoted bodies kept whole), the GRANT / REVOKE statements of every shipped
migration up to 0025 are replayed into the privileges admino_app ends up with, and the
trigger function's body is interpreted on every (OLD, NEW) external_content pair.

What is pinned:
- ``0025_chats_column_grants.sql`` ships as the only version 25 and run_migrations
  applies it after 0024 (once).
- Effective privileges after 0024 + 0025 (table-wide REVOKE, then the column GRANT:
  the other order would leave no column privilege): admino_app holds SELECT and INSERT
  on chats and UPDATE on exactly title, title_source, last_activity_at,
  external_content and deleted_at, so never on id, org_id, owner_user_id, created_at
  or legacy_session_id; no DELETE, no grant option. chat_messages keeps SELECT,
  INSERT. PUBLIC holds nothing on either table.
- 0025's only GRANT (nested bodies and literals included) is that column-level UPDATE
  on chats to admino_app, without grant option.
- One trigger: BEFORE UPDATE (no ``UPDATE OF`` column list, which other UPDATE forms
  would skip), FOR EACH ROW, no WHEN, on chats, executing the plpgsql function returning
  ``trigger`` this file creates (SECURITY INVOKER).
- The function refuses OLD true -> NEW false with check_violation (SQLSTATE 23514)
  and returns NEW for every other pair; its RAISE interpolates no row value (no
  NEW / OLD reference, no ``%`` placeholder).
- tests/db_fakes.py mirrors 0025: an UPDATE of chats naming a column outside the five
  is InsufficientPrivilegeError ("permission denied for table chats") before anything
  changes; a reset of external_content is CheckViolationError ("chats.external_content
  can't be reset") and the statement changes no row; false -> true, true -> true and
  other columns of a flagged chat pass; the fake's columns and message equal the
  shipped ones.

Security notes:
- Without the column grant, a bug or injected SQL running as admino_app could move a
  chat to another org or owner (``UPDATE chats SET org_id = ...``); the grant takes
  that away from the runtime role.
- The trigger holds GH-243's "never reset" rule in the database: content that came
  from an external source stays flagged even if application code regresses.
- The trigger's message carries no row data, so a log line quoting the error leaks
  no title or session id.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NamedTuple
from unittest.mock import AsyncMock

import asyncpg
import pytest

import admino.database as db_mod
from tests import db_fakes
from tests.db_fakes import FakeDb
from tests.test_migration_0018 import (
    _executed,
    _fragments,
    _load_migrations,
    _masked,
    _normalize,
    _scan,
    _split,
)

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0025_chats_column_grants.sql"
_PREVIOUS_MIGRATION = "0024_chats.sql"
_VERSION = 25
_ROLE = "admino_app"
_CHATS = "chats"
_MESSAGES = "chat_messages"
_CHAT_TABLES = (_CHATS, _MESSAGES)
_UPDATE_COLUMNS = ("title", "title_source", "last_activity_at", "external_content", "deleted_at")
_FIXED_COLUMNS = ("id", "org_id", "owner_user_id", "created_at", "legacy_session_id")
_RESET_MESSAGE = "chats.external_content can't be reset"
_DENIED_MESSAGE = "permission denied for table chats"

_ALL_TABLE_PRIVILEGES = ("select", "insert", "update", "delete", "truncate", "references")
_ALL_COLUMN_PRIVILEGES = ("select", "insert", "update", "references")
_NON_TABLE_TARGET = re.compile(
    r"(?:sequence|database|domain|foreign|function|procedure|routine|language|large object"
    r"|schema|tablespace|type|parameter|all (?:sequences|functions|procedures|routines))\b"
)
_GRANT_RE = re.compile(
    r"grant (?P<privileges>.+?) on (?P<target>.+?) to (?P<grantees>.+?)"
    r"(?P<option> with grant option)?(?: granted by \S+)?"
)
_REVOKE_RE = re.compile(
    r"revoke (?P<option>grant option for )?(?P<privileges>.+?) on (?P<target>.+?)"
    r" from (?P<grantees>.+?)(?: granted by \S+)?(?: (?:cascade|restrict))?"
)
_TRIGGER_RE = re.compile(
    r"create (?:or replace )?(?:constraint )?trigger (?P<name>\w+)"
    r" (?P<timing>before|after|instead of) (?P<events>.+?) on (?:only )?(?:public\.)?"
    r"(?P<table>\w+)(?P<rest>.*)"
)
_FUNCTION_RE = re.compile(
    r"create (?:or replace )?function (?:public\.)?(?P<name>\w+) ?\((?P<args>[^)]*)\)"
    r"(?P<options>.*)"
)
_SQLSTATES = {"23514": "check_violation"}


# ---------------------------------------------------------------------------
# Helpers: the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    return _migration_path().read_text(encoding="utf-8")


def _statements() -> list[str]:
    """The statements 0025 runs (top level and DO blocks), normalized."""
    return _executed(_normalize(_raw_sql()))


def _privilege_entries(text: str) -> list[tuple[str, tuple[str, ...]]]:
    """(privilege, columns) per item of a privilege list; () for a table-level one."""
    entries: list[tuple[str, tuple[str, ...]]] = []
    for item in _split(text, ","):
        match = re.fullmatch(r"([a-z]+(?: privileges)?) ?(?:\(([^)]*)\))?", item.strip())
        assert match is not None, f"the test can't read the privilege {item!r}"
        name = "all" if match.group(1).startswith("all") else match.group(1)
        raw_columns = (match.group(2) or "").split(",")
        entries.append((name, tuple(c.strip().strip('"') for c in raw_columns if c.strip())))
    return entries


def _acl_keys(name: str, columns: tuple[str, ...]) -> list[str]:
    """ACL entries of one item: 'select' (table level) or 'update(title)' (column level)."""
    if name == "all":
        names = _ALL_COLUMN_PRIVILEGES if columns else _ALL_TABLE_PRIVILEGES
    else:
        names = (name,)
    if not columns:
        return list(names)
    return [f"{privilege}({column})" for privilege in names for column in columns]


def _target_tables(target: str) -> tuple[str, ...]:
    """The chat tables a GRANT / REVOKE target names (other object kinds: none)."""
    if _NON_TABLE_TARGET.match(target):
        return ()
    if re.fullmatch(r"all tables in schema .+", target):
        return _CHAT_TABLES
    names = _split(re.sub(r"^table ", "", target), ",")
    return tuple(
        name for raw in names if (name := raw.strip().strip('"').split(".")[-1]) in _CHAT_TABLES
    )


def _grantees(text: str) -> frozenset[str]:
    return frozenset(re.sub(r"^group ", "", g.strip()).strip('"') for g in _split(text, ","))


def _apply(acl: dict[tuple[str, str], set[str]], statement: str) -> None:
    """Apply one GRANT or REVOKE to the chat tables' ACL, as PostgreSQL does.

    A table-level REVOKE also takes the privilege away from every column; a
    ``*`` suffix marks a grant option.
    """
    masked = _masked(statement)
    grant = _GRANT_RE.fullmatch(masked)
    revoke = None if grant is not None else _REVOKE_RE.fullmatch(masked)
    match = grant or revoke
    if match is None:
        return
    for table in _target_tables(match.group("target")):
        for grantee in _grantees(match.group("grantees")):
            held = acl.setdefault((table, grantee), set())
            for name, columns in _privilege_entries(match.group("privileges")):
                keys = _acl_keys(name, columns)
                if grant is not None:
                    held.update(keys)
                    if grant.group("option"):
                        held.update(f"{key}*" for key in keys)
                    continue
                only_option = revoke is not None and revoke.group("option") is not None
                for entry in list(held):
                    base = entry.removesuffix("*")
                    hit = base in keys or (
                        not columns and any(base.startswith(f"{key}(") for key in keys)
                    )
                    if hit and (entry.endswith("*") or not only_option):
                        held.discard(entry)


def _effective_acl() -> tuple[list[int], dict[tuple[str, str], frozenset[str]]]:
    """(replayed versions, (table, grantee) -> ACL entries) after every migration up to 25."""
    acl: dict[tuple[str, str], set[str]] = {}
    versions: list[int] = []
    for migration in _load_migrations(db_mod._MIGRATIONS_DIR):
        if migration.version > _VERSION:
            continue
        versions.append(migration.version)
        for statement in _executed(_normalize(migration.sql)):
            _apply(acl, statement)
    return versions, {key: frozenset(value) for key, value in acl.items()}


def _held(table: str, grantee: str) -> frozenset[str]:
    versions, acl = _effective_acl()
    assert _VERSION in versions, f"{_MIGRATION_NAME} is not shipped"
    return acl.get((table, grantee), frozenset())


class _Grant(NamedTuple):
    entries: frozenset[str]
    tables: tuple[str, ...]
    grantees: frozenset[str]
    option: bool


def _file_grants() -> list[_Grant]:
    """Every GRANT in 0025, nested DO / function bodies and EXECUTE literals included."""
    grants: list[_Grant] = []
    for fragment in _fragments(_normalize(_raw_sql())):
        match = _GRANT_RE.fullmatch(_masked(fragment))
        if match is None:
            continue
        entries = frozenset(
            key
            for name, columns in _privilege_entries(match.group("privileges"))
            for key in _acl_keys(name, columns)
        )
        target = match.group("target")
        tables = tuple(
            raw.strip().strip('"').split(".")[-1]
            for raw in _split(re.sub(r"^table ", "", target), ",")
        )
        grants.append(
            _Grant(entries, tables, _grantees(match.group("grantees")), bool(match.group("option")))
        )
    return grants


class _Trigger(NamedTuple):
    timing: str
    events: tuple[str, ...]
    table: str
    level: str
    when: bool
    function: str
    arguments: str


def _triggers() -> list[_Trigger]:
    triggers: list[_Trigger] = []
    for statement in _statements():
        match = _TRIGGER_RE.fullmatch(_masked(statement))
        if match is None:
            continue
        rest = match.group("rest")
        level = re.search(r"\bfor (?:each )?(row|statement)\b", rest)
        execute = re.search(
            r"\bexecute (?:function|procedure) (?:public\.)?(\w+) ?\(([^)]*)\)\s*$", rest
        )
        assert execute is not None, f"the trigger executes no function: {statement}"
        triggers.append(
            _Trigger(
                timing=match.group("timing"),
                events=tuple(e.strip() for e in re.split(r" or ", match.group("events"))),
                table=match.group("table"),
                level=level.group(1) if level else "statement",
                when=re.search(r"\bwhen\b", rest) is not None,
                function=execute.group(1),
                arguments=execute.group(2).strip(),
            )
        )
    return triggers


class _Function(NamedTuple):
    name: str
    arguments: str
    options: str
    body: str


def _functions() -> list[_Function]:
    functions: list[_Function] = []
    for statement in _statements():
        masked = _masked(statement)
        match = _FUNCTION_RE.fullmatch(masked)
        if match is None:
            continue
        bodies = _scan(statement)[2]
        assert len(bodies) == 1, f"one dollar-quoted body expected: {statement}"
        functions.append(
            _Function(
                name=match.group("name"),
                arguments=match.group("args").strip(),
                options=match.group("options"),
                body=bodies[0].strip(),
            )
        )
    return functions


def _trigger_function() -> _Function:
    """The function the chats trigger executes, created in 0025."""
    (trigger,) = _triggers()
    found = [function for function in _functions() if function.name == trigger.function]
    assert len(found) == 1, f"0025 must create {trigger.function} exactly once: {found}"
    return found[0]


# ---------------------------------------------------------------------------
# Helpers: a PL/pgSQL subset interpreter for the trigger body
# ---------------------------------------------------------------------------


class _If(NamedTuple):
    branches: tuple[tuple[str | None, tuple[Any, ...]], ...]  # (condition | None: ELSE, body)


def _instructions(code: str) -> list[tuple[str, str]]:
    """(kind, text) per IF / ELSIF / ELSE / END IF marker and plain statement."""
    tokens: list[tuple[str, str]] = []
    for piece in _split(code, ";"):
        rest = piece.strip()
        while rest:
            masked = _masked(rest)
            if opener := re.match(r"(if|elsif|elseif) ", masked):
                then = re.search(r" then\b", masked)
                assert then is not None, f"IF without THEN: {rest}"
                kind = "if" if opener.group(1) == "if" else "elsif"
                tokens.append((kind, rest[opener.end() : then.start()]))
                rest = rest[then.end() :].strip()
            elif other := re.match(r"else\b", masked):
                tokens.append(("else", ""))
                rest = rest[other.end() :].strip()
            elif masked == "end if":
                tokens.append(("endif", ""))
                rest = ""
            else:
                tokens.append(("stmt", rest))
                rest = ""
    return tokens


def _nodes(
    tokens: list[tuple[str, str]], index: int, stop: frozenset[str]
) -> tuple[list[Any], int]:
    nodes: list[Any] = []
    while index < len(tokens) and tokens[index][0] not in stop:
        kind, text = tokens[index]
        index += 1
        if kind == "stmt":
            nodes.append(text)
            continue
        assert kind == "if", f"unexpected {kind.upper()} in the trigger body"
        branches: list[tuple[str | None, tuple[Any, ...]]] = []
        condition: str | None = text
        while True:
            body, index = _nodes(tokens, index, frozenset({"elsif", "else", "endif"}))
            branches.append((condition, tuple(body)))
            assert index < len(tokens), "IF without END IF in the trigger body"
            kind, text = tokens[index]
            index += 1
            if kind == "endif":
                break
            condition = text if kind == "elsif" else None
        nodes.append(_If(tuple(branches)))
    return nodes, index


def _body_tree(body: str) -> list[Any]:
    match = re.fullmatch(r"begin (?P<code>.*?);? ?end;?", body.strip())
    assert match is not None, f"the test reads a BEGIN ... END body only: {body}"
    nodes, _ = _nodes(_instructions(match.group("code")), 0, frozenset())
    return nodes


def _and3(left: bool | None, right: bool | None) -> bool | None:
    if left is False or right is False:
        return False
    return None if left is None or right is None else True


def _or3(left: bool | None, right: bool | None) -> bool | None:
    if left is True or right is True:
        return True
    return None if left is None or right is None else False


class _Condition:
    """A boolean expression over OLD / NEW.external_content in SQL's 3-valued logic."""

    def __init__(self, text: str, row: dict[str, bool | None]) -> None:
        self.tokens = re.findall(r"<>|!=|=|\(|\)|[a-z_][\w.]*|\S", _masked(text))
        self.index = 0
        self.row = row

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self, expected: str | None = None) -> str:
        token = self._peek()
        assert token is not None, f"the condition ends early: {self.tokens}"
        assert expected is None or token == expected, f"{expected} expected: {self.tokens}"
        self.index += 1
        return token

    def evaluate(self) -> bool | None:
        value = self._or()
        assert self._peek() is None, f"the test can't read the condition: {self.tokens}"
        return value

    def _or(self) -> bool | None:
        value = self._and()
        while self._peek() == "or":
            self._take()
            value = _or3(value, self._and())
        return value

    def _and(self) -> bool | None:
        value = self._not()
        while self._peek() == "and":
            self._take()
            value = _and3(value, self._not())
        return value

    def _not(self) -> bool | None:
        if self._peek() == "not":
            self._take()
            value = self._not()
            return None if value is None else not value
        return self._comparison()

    def _comparison(self) -> bool | None:
        left = self._primary()
        if self._peek() in ("=", "<>", "!="):
            operator = self._take()
            right = self._primary()
            if left is None or right is None:
                return None
            return (left == right) is (operator == "=")
        if self._peek() != "is":
            return left
        self._take()
        negate = self._peek() == "not"
        if negate:
            self._take()
        word = self._take()
        if word in ("true", "false"):
            result = left is (word == "true")
        elif word == "null":
            result = left is None
        else:
            assert word == "distinct", f"the test can't read IS {word}"
            self._take("from")
            result = left != self._primary()
        return not result if negate else result

    def _primary(self) -> bool | None:
        token = self._take()
        if token == "(":
            value = self._or()
            self._take(")")
            return value
        if token in ("true", "false"):
            return token == "true"
        if token == "null":
            return None
        assert token in self.row, f"the test can't evaluate {token!r} in the trigger"
        return self.row[token]


def _literal_after(statement: str, pattern: str) -> str | None:
    """The '...' literal right after the first match of pattern (on the masked text)."""
    found = re.search(rf"{pattern} ?'", _masked(statement))
    if found is None:
        return None
    literal = re.match(r"'((?:[^']|'')*)'", statement[found.end() - 1 :])
    assert literal is not None, statement
    return literal.group(1).replace("''", "'")


def _errcode(statement: str) -> str:
    """The SQLSTATE condition a RAISE EXCEPTION raises (raise_exception by default)."""
    code = _literal_after(statement, r"\berrcode ?=") or _literal_after(
        statement, r"^raise (?:exception )?sqlstate"
    )
    named = re.match(r"raise (?:exception )?([a-z_]+)\b", _masked(statement))
    if code is None and named is not None and named.group(1) != "using":
        code = named.group(1)
    code = code or "raise_exception"
    return _SQLSTATES.get(code, code)


def _raise_message(statement: str) -> str | None:
    """A RAISE's message: USING MESSAGE = '...', else its format literal."""
    return _literal_after(statement, r"\bmessage ?=") or _literal_after(
        statement, r"^raise (?:exception )?"
    )


def _run(nodes: list[Any] | tuple[Any, ...], row: dict[str, bool | None]) -> str | None:
    """Run body nodes: 'raise:<condition>', 'return:<new|old|null>' or None (fell through)."""
    for node in nodes:
        if isinstance(node, _If):
            for condition, body in node.branches:
                if condition is None or _Condition(condition, row).evaluate() is True:
                    outcome = _run(body, row)
                    if outcome is not None:
                        return outcome
                    break
            continue
        masked = _masked(node)
        if returned := re.fullmatch(r"return (new|old|null)", masked):
            return f"return:{returned.group(1)}"
        if masked == "null":
            continue
        if masked.startswith("raise"):
            level = re.match(r"raise (debug|log|info|notice|warning)\b", masked)
            if level is None:
                return f"raise:{_errcode(node)}"
            continue
        pytest.fail(f"the test can't run the trigger statement {node!r}")
    return None


def _raise_statements(nodes: list[Any] | tuple[Any, ...]) -> list[str]:
    found: list[str] = []
    for node in nodes:
        if isinstance(node, _If):
            for _, body in node.branches:
                found.extend(_raise_statements(body))
        elif _masked(node).startswith("raise"):
            found.append(node)
    return found


def _outcomes() -> dict[tuple[bool, bool], str | None]:
    tree = _body_tree(_trigger_function().body)
    return {
        (old, new): _run(tree, {"old.external_content": old, "new.external_content": new})
        for old in (True, False)
        for new in (True, False)
    }


# ---------------------------------------------------------------------------
# Helpers: the fake database
# ---------------------------------------------------------------------------

_NEW_VALUES: dict[str, Any] = {
    "id": uuid.UUID("0b6f3c1e-2a4d-4e5f-8a9b-1c2d3e4f5a6b"),
    "org_id": db_fakes.OTHER_ORG_ID,
    "owner_user_id": None,  # another account's id, set in the test
    "created_at": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
    "legacy_session_id": "sess-other",
    "title": "Renamed",
    "title_source": "user",
    "last_activity_at": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
    "external_content": True,
    "deleted_at": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
}
# One literal statement per column (no SQL built from strings).
_SET_ONE: dict[str, str] = {
    "id": "UPDATE chats SET id = $1 WHERE id = $2",
    "org_id": "UPDATE chats SET org_id = $1 WHERE id = $2",
    "owner_user_id": "UPDATE chats SET owner_user_id = $1 WHERE id = $2",
    "created_at": "UPDATE chats SET created_at = $1 WHERE id = $2",
    "legacy_session_id": "UPDATE chats SET legacy_session_id = $1 WHERE id = $2",
    "title": "UPDATE chats SET title = $1 WHERE id = $2",
    "title_source": "UPDATE chats SET title_source = $1 WHERE id = $2",
    "last_activity_at": "UPDATE chats SET last_activity_at = $1 WHERE id = $2",
    "external_content": "UPDATE chats SET external_content = $1 WHERE id = $2",
    "deleted_at": "UPDATE chats SET deleted_at = $1 WHERE id = $2",
}


async def _outcome(db: FakeDb, chat: uuid.UUID, sql: str, *args: Any) -> str:
    """'ok', 'permission denied' or 'reset refused' (each refusal changing nothing)."""
    before = db.chat_row(chat)
    try:
        await db.pool.execute(sql, *args)
    except asyncpg.exceptions.InsufficientPrivilegeError as exc:
        unchanged = db.chat_row(chat) == before
        return "permission denied" if str(exc) == _DENIED_MESSAGE and unchanged else repr(exc)
    except asyncpg.exceptions.CheckViolationError as exc:
        unchanged = db.chat_row(chat) == before
        return "reset refused" if str(exc) == _RESET_MESSAGE and unchanged else repr(exc)
    except asyncpg.exceptions.PostgresError as exc:
        return repr(exc)
    return "ok"


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0025File:
    """The migration ships as version 25 and is applied by run_migrations after 0024."""

    def test_migration_0025_file_is_the_only_version_25(self) -> None:
        twenty_fives = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert twenty_fives == [_MIGRATION_NAME]

    async def test_migration_0025_run_migrations_applies_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0024 applied, run_migrations executes the file and records 25."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        recorded = [
            (c.args[1], c.args[2])
            for c in conn.execute.call_args_list
            if len(c.args) > 2 and "INSERT INTO _migrations" in c.args[0]
        ]
        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)
        assert (_VERSION, _MIGRATION_NAME) in recorded

    async def test_migration_0025_runs_after_0024(self, mock_pool: MagicMock) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0025_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)


# ---------------------------------------------------------------------------
# 2. Privileges
# ---------------------------------------------------------------------------


class TestMigration0025Privileges:
    """What admino_app (and PUBLIC) may do on the chat tables after 0024 + 0025."""

    def test_migration_0025_admino_app_updates_only_the_five_chat_columns(self) -> None:
        """SELECT, INSERT on chats; UPDATE on exactly the five columns; no table-wide
        UPDATE, no DELETE, no grant option. A REVOKE after the GRANT would leave none."""
        expected = {"select", "insert", *(f"update({column})" for column in _UPDATE_COLUMNS)}

        assert _held(_CHATS, _ROLE) == expected

    def test_migration_0025_admino_app_cannot_update_the_identity_columns(self) -> None:
        """The criterion's five fixed columns: no column and no table-wide UPDATE."""
        held = _held(_CHATS, _ROLE)
        updatable = {
            column: "update" in held or f"update({column})" in held for column in _FIXED_COLUMNS
        }

        assert updatable == dict.fromkeys(_FIXED_COLUMNS, False)

    def test_migration_0025_chat_messages_privileges_are_unchanged(self) -> None:
        """Still append-only for the app: SELECT, INSERT."""
        assert _held(_MESSAGES, _ROLE) == {"select", "insert"}

    @pytest.mark.parametrize("table", _CHAT_TABLES)
    def test_migration_0025_public_holds_nothing_on_the_chat_table(self, table: str) -> None:
        assert _held(table, "public") == frozenset()

    def test_migration_0025_grants_only_the_column_update_to_admino_app(self) -> None:
        """0025's one GRANT, DO / function bodies and EXECUTE literals included."""
        expected = _Grant(
            frozenset(f"update({column})" for column in _UPDATE_COLUMNS),
            (_CHATS,),
            frozenset({_ROLE}),
            option=False,
        )

        assert _file_grants() == [expected]


# ---------------------------------------------------------------------------
# 3. The sticky external_content trigger
# ---------------------------------------------------------------------------


class TestMigration0025Trigger:
    """A BEFORE UPDATE row trigger on chats refuses resetting external_content."""

    def test_migration_0025_trigger_fires_before_every_update_of_each_chat(self) -> None:
        """No UPDATE OF column list and no WHEN: no UPDATE form skips it."""
        triggers = _triggers()

        assert [(t.timing, t.events, t.table, t.level, t.when) for t in triggers] == [
            ("before", ("update",), _CHATS, "row", False)
        ]

    def test_migration_0025_trigger_executes_its_plpgsql_trigger_function(self) -> None:
        """The function is created here: no arguments, RETURNS trigger, plpgsql, and
        not SECURITY DEFINER (it needs no rights beyond the updating role's)."""
        (trigger,) = _triggers()
        function = _trigger_function()
        options = function.options

        assert trigger.arguments == ""
        assert function.arguments == ""
        assert re.search(r"\breturns trigger\b", options)
        assert re.search(r"\blanguage '?plpgsql'?", options)
        assert re.search(r"\bsecurity definer\b", options) is None

    def test_migration_0025_function_refuses_only_true_to_false(self) -> None:
        """(OLD, NEW) external_content: true -> false raises check_violation (SQLSTATE
        23514, asyncpg CheckViolationError); every other pair returns NEW unchanged."""
        assert _outcomes() == {
            (True, False): "raise:check_violation",
            (True, True): "return:new",
            (False, True): "return:new",
            (False, False): "return:new",
        }

    def test_migration_0025_refusal_message_carries_no_row_data(self) -> None:
        """No NEW / OLD value in the RAISE (message, detail, hint) and no % placeholder."""
        raises = _raise_statements(_body_tree(_trigger_function().body))

        assert raises, "the trigger function raises nothing"
        for statement in raises:
            assert re.search(r"\b(?:new|old)\b", _masked(statement)) is None, statement
            assert not any("%" in literal for literal in _scan(statement)[1]), statement


# ---------------------------------------------------------------------------
# 4. tests/db_fakes.py mirrors 0025
# ---------------------------------------------------------------------------


class TestMigration0025FakeDb:
    """The FakeDb refuses what admino_app may not do after 0025."""

    async def test_migration_0025_fake_allows_updating_exactly_the_five_columns(self) -> None:
        """Each forbidden column is 'permission denied for table chats' and changes nothing."""
        db = FakeDb()
        owner = db.add_account()
        other = db.add_account(email="other@example.test")
        outcomes: dict[str, str] = {}
        for column, sql in _SET_ONE.items():
            chat = db.add_chat(owner, title="Plan")
            value = other if column == "owner_user_id" else _NEW_VALUES[column]
            outcome = await _outcome(db, chat, sql, value, chat)
            row = db.chat_row(chat) or db.chat_row(_NEW_VALUES["id"])
            if outcome == "ok" and (row is None or row[column] != value):
                outcome = f"not written: {row}"
            outcomes[column] = outcome

        assert outcomes == {
            **dict.fromkeys(_FIXED_COLUMNS, "permission denied"),
            **dict.fromkeys(_UPDATE_COLUMNS, "ok"),
        }

    async def test_migration_0025_fake_refuses_a_forbidden_column_next_to_allowed_ones(
        self,
    ) -> None:
        """Checked before the statement runs: the allowed title isn't written either."""
        db = FakeDb()
        owner = db.add_account()
        chat = db.add_chat(owner, title="Plan")

        outcome = await _outcome(
            db,
            chat,
            "UPDATE chats SET title = $1, org_id = $2 WHERE id = $3",
            "Renamed",
            db_fakes.ORG_ID,
            chat,
        )

        assert outcome == "permission denied"

    async def test_migration_0025_fake_trigger_refuses_only_the_reset(self) -> None:
        """true -> false refused (the row unchanged); false -> true, true -> true,
        false -> false and other columns of a flagged chat pass."""
        db = FakeDb()
        owner = db.add_account()
        cases = {
            "true -> false": (True, "UPDATE chats SET external_content = false WHERE id = $1"),
            "true -> false (bound)": (True, _SET_ONE["external_content"]),
            "true -> true": (True, "UPDATE chats SET external_content = true WHERE id = $1"),
            "false -> true": (False, "UPDATE chats SET external_content = true WHERE id = $1"),
            "false -> false": (False, "UPDATE chats SET external_content = false WHERE id = $1"),
            "flagged, title": (True, "UPDATE chats SET title = 'x' WHERE id = $1"),
            "flagged, trash": (True, "UPDATE chats SET deleted_at = now() WHERE id = $1"),
            "flagged, activity": (
                True,
                "UPDATE chats SET last_activity_at = now(), external_content = true WHERE id = $1",
            ),
        }
        outcomes: dict[str, str] = {}
        for name, (flagged, sql) in cases.items():
            chat = db.add_chat(owner, external_content=flagged)
            args = (False, chat) if "$2" in sql else (chat,)
            outcomes[name] = await _outcome(db, chat, sql, *args)

        assert outcomes == {
            **dict.fromkeys(cases, "ok"),
            "true -> false": "reset refused",
            "true -> false (bound)": "reset refused",
        }

    async def test_migration_0025_fake_reset_error_is_check_violation_without_row_data(
        self,
    ) -> None:
        """SQLSTATE 23514, the trigger's message only: no title or session id in it."""
        db = FakeDb()
        owner = db.add_account()
        chat = db.add_chat(
            owner, title="Merger plan", legacy_session_id="sess-secret", external_content=True
        )

        with pytest.raises(asyncpg.exceptions.CheckViolationError) as caught:
            await db.pool.execute("UPDATE chats SET external_content = false WHERE id = $1", chat)

        assert caught.value.sqlstate == "23514"
        assert str(caught.value) == _RESET_MESSAGE

    async def test_migration_0025_fake_reset_in_a_multi_row_update_changes_no_row(
        self,
    ) -> None:
        """One flagged row refuses the whole statement: the other chat keeps its title."""
        db = FakeDb()
        owner = db.add_account()
        plain = db.add_chat(owner, title="Plain")
        flagged = db.add_chat(owner, title="Flagged", external_content=True)
        before = (db.chat_row(plain), db.chat_row(flagged))

        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await db.pool.execute(
                "UPDATE chats SET title = $1, external_content = false WHERE owner_user_id = $2",
                "Renamed",
                owner,
            )

        assert (db.chat_row(plain), db.chat_row(flagged)) == before

    async def test_migration_0025_fake_mirrors_the_shipped_grant_and_message(self) -> None:
        """The fake's updatable columns and refusal message are the shipped ones."""
        (grant,) = _file_grants()
        shipped_columns = frozenset(
            entry.removeprefix("update(").removesuffix(")") for entry in grant.entries
        )
        (statement,) = _raise_statements(_body_tree(_trigger_function().body))
        shipped_message = _raise_message(statement)

        assert (shipped_columns, shipped_message) == (
            db_fakes.CHAT_UPDATE_COLUMNS,
            db_fakes.CHAT_EXTERNAL_CONTENT_RESET,
        )
