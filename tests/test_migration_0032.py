"""Tests for migration 0032_trash.sql (GH-194, contract section 1, issue Decisions 2, 9
and 10): the trash groups on chats and attachments, their backfill and CHECKs, the trash
indexes, DELETE on chats and UPDATE of the groups for the runtime role, and
``chat.purge`` / ``file.purge`` in the audit action catalog.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
pipeline ran the contract's SQL on a throwaway postgres:16 as admino_app: the backfill,
both CHECKs, the cascade of a chat DELETE and the refused writes). The SQL is read with
tests/test_migration_0018.py's lexer (comments blanked, '...' literals and
dollar-quoted bodies kept whole, nested DO / function bodies and EXECUTE literals
searched too), the added columns with tests/test_migration_0024.py's column parser,
the indexes with tests/test_migration_0027.py's reader, the action list with
tests/test_migration_0021.py's IN-list reader, and the GRANT / REVOKE statements of
every shipped migration are replayed into the privileges each role ends up with
(tests/test_migration_0027.py's replay). The two backfill UPDATEs are read into their
target, assignments (a CASE and an EXISTS sub-select included) and WHERE conditions,
with every column reference resolved to its table (alias or not).

What is pinned:
- ``0032_trash.sql`` ships as the only version 32, right after the versions 1 to 31;
  run_migrations applies and records it after 0031 (GH-245's 0031_chat_retry.sql),
  and not again once applied. It
  opens with a header comment naming trash_group_id, the two new actions and what is
  granted.
- ``trash_group_id`` is added to chats and to attachments, each a UUID, nullable,
  without a default, CHECK, key or reference (existing rows read NULL until the
  backfill; the application sets it).
- The backfill: ``UPDATE chats SET trash_group_id = id WHERE deleted_at IS NOT
  NULL`` (every trashed chat is its own group); ``UPDATE attachments SET
  trash_group_id = CASE WHEN EXISTS (a chat with the file's chat_id and org_id whose
  deleted_at IS NOT NULL) THEN chat_id ELSE id END WHERE deleted_at IS NOT NULL`` (a
  file trashed with its chat joins the chat's group, any other trashed file is its
  own); live rows are untouched. They are the only data writes.
- ``chats_trash_group_check`` and ``attachments_trash_group_check``, each exactly
  ``CHECK ((deleted_at IS NULL) = (trash_group_id IS NULL))`` (validated: nothing
  after the expression), added after the backfill of their table.
- ``chats_trash_idx`` / ``attachments_trash_idx``: plain btree, non-unique, not
  CONCURRENTLY, on (org_id, owner_user_id, deleted_at, id) WHERE deleted_at IS NOT
  NULL.
- Grants: ``DELETE`` on chats and ``UPDATE (trash_group_id)`` on chats and on
  attachments, to admino_app only, without grant option, after the columns exist;
  no REVOKE. Every (table, grantee) holds after 0032 what it held after 0031, except
  admino_app on chats (``delete``, ``update(trash_group_id)``) and on attachments
  (``update(trash_group_id)``). After every shipped migration admino_app holds on
  chats SELECT, INSERT, DELETE and UPDATE on exactly title, title_source,
  last_activity_at, external_content, deleted_at and trash_group_id; on attachments
  SELECT, INSERT, DELETE and UPDATE on exactly message_id, status, failure_reason,
  page_count, token_estimate, derived_bytes, active, updated_at, deleted_at and
  trash_group_id; on chat_messages SELECT and INSERT only (append-only: a chat's
  DELETE cascades to its messages as the table owner); PUBLIC nothing. (The
  cumulative pin moved here from tests/test_migration_0030.py.) The runtime-role
  grant guards of tests/test_migration_0018.py still hold, and they read 0032's
  grants. (tests/test_migration_0031.py pins that 0031 changes no table privilege.)
- ``audit_events_action_check`` is dropped (no IF EXISTS, no CASCADE) and re-added
  with 0030's list (0031 changes no catalog) plus ``'chat.purge'`` right after
  ``'chat.restore'`` and
  ``'file.purge'`` right after ``'file.restore'``, nothing else added or removed,
  each listed once; the list equals ``AuditAction`` (the exact sync moved here from
  tests/test_migration_0030.py), which has ``CHAT_PURGE = "chat.purge"`` and
  ``FILE_PURGE = "file.purge"``. The FakeDb's catalog (``db_fakes.shipped_schema()``)
  is that list.
- Nothing else: every statement (top level and DO blocks) is one of the above; no DO
  block, function, trigger, role, INSERT / DELETE / TRUNCATE / COPY / MERGE, REVOKE,
  CREATE TABLE, DROP TABLE / INDEX / COLUMN, SECURITY DEFINER, owner change or default
  privileges, also not nested in a body or an EXECUTE literal.

Security notes:
- DELETE on chats is the one new table-level privilege: delete forever and the
  retention purge need it. The cascade to chat_messages and attachments runs as their
  owner, so the app still can't delete a message on its own; no other table gains
  DELETE, no table gains a table-wide UPDATE, and no grant reaches PUBLIC.
- The new columns hold ids only; the catalog grows by two content-free actions.
- A CHECK added before the backfill would refuse every existing trashed row (the
  migration would fail); one with NOT VALID would let a row hold a deletion time
  without a group.
"""

from __future__ import annotations

import itertools
import re
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock

import admino.database as db_mod
from tests import db_fakes
from tests.test_migration_0018 import (
    _GUARDS,
    _executed,
    _fragments,
    _load_migrations,
    _masked,
    _migration_grants,
    _normalize,
    _shipped,
    _split,
)
from tests.test_migration_0021 import _added_actions
from tests.test_migration_0024 import _canonical_default, _Column, _parse_column
from tests.test_migration_0025 import _GRANT_RE, _acl_keys, _grantees, _privilege_entries
from tests.test_migration_0027 import (
    _ALTER_RE,
    _INDEX_RE,
    _apply,
    _conditions,
    _Index,
    _names,
    _targets,
    _unwrap,
)

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME: Final = "0032_trash.sql"
_PREVIOUS_MIGRATION: Final = "0031_chat_retry.sql"
# The action catalog in force before 0032: 0030's (0031_chat_retry.sql adds none).
_CATALOG_MIGRATION: Final = "0030_context_budget.sql"
_VERSION: Final = 32
_ROLE: Final = "admino_app"
_CHATS: Final = "chats"
_ATTACHMENTS: Final = "attachments"
_MESSAGES: Final = "chat_messages"
_AUDIT_TABLE: Final = "audit_events"
_COLUMN: Final = "trash_group_id"
_TABLES: Final = (_CHATS, _ATTACHMENTS)
_TRASH_CHECKS: Final[dict[str, str]] = {
    _CHATS: "chats_trash_group_check",
    _ATTACHMENTS: "attachments_trash_group_check",
}
_TRASH_INDEXES: Final[dict[str, str]] = {
    "chats_trash_idx": _CHATS,
    "attachments_trash_idx": _ATTACHMENTS,
}
_INDEX_COLUMNS: Final = ("org_id", "owner_user_id", "deleted_at", "id")
_ACTION_CHECK: Final = "audit_events_action_check"
# Each new action and the action it follows in the written list.
_NEW_ACTIONS: Final[dict[str, str]] = {"chat.purge": "chat.restore", "file.purge": "file.restore"}

# admino_app's privileges after every shipped migration.
_CHAT_UPDATE_COLUMNS: Final = (
    "title",
    "title_source",
    "last_activity_at",
    "external_content",
    "deleted_at",
    "trash_group_id",
)
_ATTACHMENT_UPDATE_COLUMNS: Final = (
    "message_id",
    "status",
    "failure_reason",
    "page_count",
    "token_estimate",
    "derived_bytes",
    "active",
    "updated_at",
    "deleted_at",
    "trash_group_id",
)
_EXPECTED_PRIVILEGES: Final[dict[str, frozenset[str]]] = {
    _CHATS: frozenset(
        {"select", "insert", "delete", *(f"update({c})" for c in _CHAT_UPDATE_COLUMNS)}
    ),
    _ATTACHMENTS: frozenset(
        {"select", "insert", "delete", *(f"update({c})" for c in _ATTACHMENT_UPDATE_COLUMNS)}
    ),
    _MESSAGES: frozenset({"select", "insert"}),
}
# What 0032 adds to admino_app's privileges, per table.
_ADDED_PRIVILEGES: Final[dict[str, frozenset[str]]] = {
    _CHATS: frozenset({"delete", f"update({_COLUMN})"}),
    _ATTACHMENTS: frozenset({f"update({_COLUMN})"}),
}

_UUID_TYPES: Final = frozenset({"uuid"})
# ADD [COLUMN] name definition; ADD CONSTRAINT is no column.
_ADD_COLUMN_RE: Final = re.compile(
    r'add (?:column )?(?:if not exists )?(?!constraint\b)"?(?P<name>\w+)"? (?P<definition>.+)'
)
# A plain DROP (no IF EXISTS: a missing constraint fails loudly; no CASCADE).
_DROP_RE: Final = re.compile(r'drop constraint "?(?P<name>\w+)"?(?P<rest>(?: restrict)?)')
# ADD CONSTRAINT ... CHECK (...) with nothing after it (no NOT VALID, no NO INHERIT).
_ADD_CHECK_RE: Final = re.compile(r'add constraint "?(?P<name>\w+)"? check ?\((?P<expression>.*)\)')
# UPDATE <table> [[AS] alias] SET ... (the alias is never the keyword SET).
_UPDATE_HEAD_RE: Final = re.compile(
    r'update (?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"?'
    r'(?: (?:as )?"?(?P<alias>(?!set\b)\w+)"?)? set (?P<rest>.+)'
)
# SELECT ... FROM <table> [[AS] alias] WHERE ... (an EXISTS sub-select).
_SUBSELECT_RE: Final = re.compile(
    r'select (?P<columns>.+?) from (?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"?'
    r'(?: (?:as )?"?(?P<alias>(?!where\b)\w+)"?)? where (?P<where>.+)'
)
# A column reference: [qualifier.]name, not a function call.
_REFERENCE_RE: Final = re.compile(
    r'(?<![\w."])(?:"?(?P<qualifier>\w+)"?\.)?"?(?P<name>\w+)"?(?![\w(])'
)
_COLUMNS_READ: Final = frozenset(
    {"id", "org_id", "chat_id", "owner_user_id", "message_id", "deleted_at", "trash_group_id"}
)
# Fragments 0032 must not start with (top level, DO / function bodies, literals).
_FORBIDDEN: Final[dict[str, str]] = {
    "do": r"do\b",
    "revoke": r"revoke\b",
    "insert": r"insert into\b",
    "delete": r"delete from\b",
    "truncate": r"truncate\b",
    "copy": r"copy\b",
    "merge": r"merge into\b",
    "function": r"(?:create|alter|drop) (?:or replace )?(?:function|procedure)\b",
    "trigger": r"(?:create|alter|drop) (?:or replace )?(?:constraint )?trigger\b",
    "role": r"(?:create|alter|drop) (?:role|user|group)\b",
    "drop": r"drop (?:table|view|schema|type|index|column)\b",
    "default privileges": r"alter default privileges\b",
    "create": r"create (?:table|view|type|schema)\b",
}
# Fragments 0032 must not contain anywhere.
_FORBIDDEN_ANYWHERE: Final[dict[str, str]] = {
    "security definer": r"\bsecurity definer\b",
    "drop column": r"\bdrop column\b",
    "owner change": r"\bowner to\b",
    "trigger switch": r"\b(?:disable|enable) (?:always |replica )?trigger\b",
    "grant option": r"\bwith grant option\b",
}
_UPDATE_FRAGMENT: Final = r"update (?:only )?\S+ "
_INDEX_FRAGMENT: Final = r"create (?:unique )?index\b"

# The steps the contract runs (ALTER TABLE actions one by one), as a multiset.
_CONTRACT_STEPS: Final = (
    f"column {_CHATS}.{_COLUMN}",
    f"column {_ATTACHMENTS}.{_COLUMN}",
    f"backfill {_CHATS}",
    f"backfill {_ATTACHMENTS}",
    f"check {_CHATS}.{_TRASH_CHECKS[_CHATS]}",
    f"check {_ATTACHMENTS}.{_TRASH_CHECKS[_ATTACHMENTS]}",
    "index chats_trash_idx",
    "index attachments_trash_idx",
    f"grant delete on {_CHATS} to {_ROLE}",
    f"grant update({_COLUMN}) on {_CHATS} to {_ROLE}",
    f"grant update({_COLUMN}) on {_ATTACHMENTS} to {_ROLE}",
    f"drop {_AUDIT_TABLE}.{_ACTION_CHECK}",
    f"check {_AUDIT_TABLE}.{_ACTION_CHECK}",
)

# A backfill as read: (table, {column: value}, WHERE conditions, anything unexpected).
_Backfill = tuple[str, dict[str, Any], frozenset[str], tuple[str, ...]]

_CHATS_BACKFILL: Final[_Backfill] = (
    _CHATS,
    {_COLUMN: f"{_CHATS}.id"},
    frozenset({f"{_CHATS}.deleted_at is not null"}),
    (),
)
_ATTACHMENTS_BACKFILL: Final[_Backfill] = (
    _ATTACHMENTS,
    {
        _COLUMN: (
            "case",
            (
                (
                    (
                        "exists",
                        _CHATS,
                        frozenset(
                            {
                                f"{_ATTACHMENTS}.chat_id = {_CHATS}.id",
                                f"{_ATTACHMENTS}.org_id = {_CHATS}.org_id",
                                f"{_CHATS}.deleted_at is not null",
                            }
                        ),
                    ),
                    f"{_ATTACHMENTS}.chat_id",
                ),
            ),
            f"{_ATTACHMENTS}.id",
        )
    },
    frozenset({f"{_ATTACHMENTS}.deleted_at is not null"}),
    (),
)


# ---------------------------------------------------------------------------
# Helpers: the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    path = _migration_path()
    assert path.is_file(), f"{_MIGRATION_NAME} is not shipped"
    return path.read_text(encoding="utf-8")


def _statements() -> list[str]:
    """The statements 0032 runs (top level and DO blocks), normalized."""
    return _executed(_normalize(_raw_sql()))


def _canon(text: str) -> str:
    """Whitespace collapsed and dropped around parentheses and commas; one space around
    a comparison."""
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*([(),])\s*", r"\1", text)
    return re.sub(r"\s*(>=|<=|<>|!=|=|<|>)\s*", r" \1 ", text).strip()


def _closing(masked: str, open_index: int) -> int:
    """The index of the parenthesis closing the one at ``open_index`` (-1: none)."""
    depth = 0
    for index in range(open_index, len(masked)):
        if masked[index] == "(":
            depth += 1
        elif masked[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _top_level(masked: str, words: str) -> list[re.Match[str]]:
    """The matches of the keyword pattern ``words`` outside parentheses."""
    found: list[re.Match[str]] = []
    depth = 0
    for token in re.finditer(rf"\(|\)|\b(?:{words})\b", masked):
        if token.group(0) == "(":
            depth += 1
        elif token.group(0) == ")":
            depth -= 1
        elif depth == 0:
            found.append(token)
    return found


def _and_parts(expression: str) -> list[str]:
    """The top-level AND-ed conditions, each unwrapped."""
    expression = _unwrap(expression)
    parts: list[str] = []
    start = 0
    for token in _top_level(_masked(expression), "and"):
        parts.append(_unwrap(expression[start : token.start()]))
        start = token.end()
    parts.append(_unwrap(expression[start:]))
    return parts


def _resolved(text: str, scope: dict[str, str], default: str) -> str:
    """``text`` with every column reference written as ``<table>.<column>``.

    A qualifier is looked up in ``scope`` (table names and aliases); a bare column
    the statements read belongs to ``default`` (the innermost FROM / UPDATE table).
    An unknown qualifier stays visible as ``?<qualifier>``.
    """

    def replace(match: re.Match[str]) -> str:
        qualifier, name = match.group("qualifier"), match.group("name")
        if qualifier is not None:
            return f"{scope.get(qualifier, '?' + qualifier)}.{name}"
        if name in _COLUMNS_READ:
            return f"{default}.{name}"
        return match.group(0)

    masked = _masked(text)
    out: list[str] = []
    position = 0
    for match in _REFERENCE_RE.finditer(masked):
        out.append(text[position : match.start()])
        out.append(replace(match))
        position = match.end()
    out.append(text[position:])
    return _canon("".join(out))


def _condition(text: str, scope: dict[str, str], default: str) -> Any:
    """One condition, its references resolved; ``a = b`` with its sides sorted; an
    EXISTS sub-select read as ("exists", table, its WHERE conditions)."""
    text = _unwrap(text)
    masked = _masked(text)
    exists = re.fullmatch(r"exists ?\((?P<body>.*)\)", masked)
    if exists is not None and _closing(masked, exists.start("body") - 1) == len(masked) - 1:
        return _subselect(text[exists.start("body") : exists.end("body")], scope)
    resolved = _resolved(text, scope, default)
    sides = re.fullmatch(r"(?P<left>[\w.?]+) = (?P<right>[\w.?]+)", resolved)
    if sides is not None:
        return " = ".join(sorted((sides.group("left"), sides.group("right"))))
    return resolved


def _subselect(text: str, scope: dict[str, str]) -> Any:
    """("exists", table, conditions) of ``SELECT ... FROM t [alias] WHERE ...``."""
    text = _unwrap(text)
    match = _SUBSELECT_RE.fullmatch(_masked(text))
    if match is None:
        return ("unreadable sub-select", _canon(text))
    table = match.group("table")
    inner = {**scope, table: table}
    if match.group("alias"):
        inner[match.group("alias")] = table
    where = text[match.start("where") : match.end("where")]
    return ("exists", table, frozenset(_condition(p, inner, table) for p in _and_parts(where)))


def _value(text: str, scope: dict[str, str], default: str) -> Any:
    """An assigned value: a CASE as ("case", ((condition, value), ...), else), else the
    resolved expression."""
    text = _unwrap(text)
    masked = _masked(text)
    if not (masked.startswith("case ") and masked.endswith(" end")):
        return _resolved(text, scope, default)
    keywords = _top_level(masked, "case|when|then|else|end")
    words = [token.group(0) for token in keywords]
    branch_count = (len(words) - 3) // 2
    if branch_count < 1 or words != ["case", *["when", "then"] * branch_count, "else", "end"]:
        return ("unreadable case", _canon(text))
    pieces = [
        text[token.end() : following.start()].strip()
        for token, following in itertools.pairwise(keywords)
    ]
    if pieces[0]:  # CASE <operand> WHEN ...: not the contract's searched CASE
        return ("unreadable case", _canon(text))
    branches = tuple(
        (
            _condition(pieces[1 + 2 * branch], scope, default),
            _value(pieces[2 + 2 * branch], scope, default),
        )
        for branch in range(branch_count)
    )
    return ("case", branches, _value(pieces[-1], scope, default))


def _backfill(statement: str) -> _Backfill:
    """(table, {column: value}, WHERE conditions, unexpected clauses) of an UPDATE."""
    masked = _masked(statement)
    head = _UPDATE_HEAD_RE.fullmatch(masked)
    assert head is not None, f"the test can't read the UPDATE {statement!r}"
    table = head.group("table")
    scope = {table: table}
    if head.group("alias"):
        scope[head.group("alias")] = table
    rest = statement[head.start("rest") :]
    clauses = _top_level(_masked(rest), "where|from|returning")
    unexpected = tuple(token.group(0) for token in clauses if token.group(0) != "where")
    wheres = [token for token in clauses if token.group(0) == "where"]
    set_end = clauses[0].start() if clauses else len(rest)
    where = ""
    if len(wheres) == 1:
        later = [token.start() for token in clauses if token.start() > wheres[0].start()]
        where = rest[wheres[0].end() : later[0] if later else len(rest)]
    assignments: dict[str, Any] = {}
    for item in _split(rest[:set_end], ","):
        match = re.fullmatch(r'"?(\w+)"? ?= ?(.+)', item.strip())
        assert match is not None, f"the test can't read the assignment {item!r}"
        assignments[match.group(1)] = _value(match.group(2), scope, table)
    conditions = (
        frozenset(_condition(p, scope, table) for p in _and_parts(where)) if where else frozenset()
    )
    return table, assignments, conditions, unexpected


def _backfills() -> list[_Backfill]:
    """Every UPDATE 0032 runs (top level and DO blocks), read."""
    return [_backfill(s) for s in _statements() if re.match(r"update\b", _masked(s))]


def _alter_actions() -> list[tuple[str, str]]:
    """(table, action) for every action of every ALTER TABLE 0032 runs, in order."""
    found: list[tuple[str, str]] = []
    for statement in _statements():
        match = _ALTER_RE.fullmatch(_masked(statement))
        if match is None:
            continue
        for action in _split(statement[match.start("actions") :], ","):
            found.append((match.group("table"), action))
    return found


def _action_step(table: str, action: str) -> str:
    """One ALTER TABLE action as a step: a column added, a constraint dropped (plainly)
    or a CHECK added (validated), else the action itself."""
    masked = _masked(action)
    if (column := _ADD_COLUMN_RE.fullmatch(masked)) is not None:
        return f"column {table}.{column.group('name')}"
    if (drop := _DROP_RE.fullmatch(masked)) is not None:
        return f"drop {table}.{drop.group('name')}"
    if (added := _ADD_CHECK_RE.fullmatch(masked)) is not None:
        return f"check {table}.{added.group('name')}"
    return f"other: alter table {table} {action}"


def _grant_steps(statement: str) -> list[str] | None:
    """One step per (privilege, table, grantee) of a GRANT; None if it isn't one."""
    match = _GRANT_RE.fullmatch(_masked(statement))
    if match is None:
        return None
    suffix = " with grant option" if match.group("option") else ""
    return [
        f"grant {key} on {table} to {grantee}{suffix}"
        for name, columns in _privilege_entries(match.group("privileges"))
        for key in _acl_keys(name, columns)
        for table in _targets(match.group("target"))
        for grantee in sorted(_grantees(match.group("grantees")))
    ]


def _steps() -> list[str]:
    """What 0032 does, in order: ALTER TABLE actions one by one, the backfills, the
    indexes, one step per granted privilege; anything else as ``other: ...``."""
    steps: list[str] = []
    for statement in _statements():
        masked = _masked(statement)
        if (alter := _ALTER_RE.fullmatch(masked)) is not None:
            for action in _split(statement[alter.start("actions") :], ","):
                steps.append(_action_step(alter.group("table"), action))
        elif (update := _UPDATE_HEAD_RE.fullmatch(masked)) is not None:
            steps.append(f"backfill {update.group('table')}")
        elif (index := _INDEX_RE.fullmatch(masked)) is not None:
            steps.append(f"index {index.group('name')}")
        elif (grants := _grant_steps(statement)) is not None:
            steps.extend(grants)
        else:
            steps.append(f"other: {statement}")
    return steps


def _added_column(table: str) -> _Column:
    """The parsed definition of ``<table>.trash_group_id`` as 0032 adds it (exactly once)."""
    found = []
    for action_table, action in _alter_actions():
        match = _ADD_COLUMN_RE.fullmatch(_masked(action))
        if match is not None and (action_table, match.group("name")) == (table, _COLUMN):
            definition = action[match.start("definition") :]
            found.append(_parse_column(_COLUMN, definition))
    assert len(found) == 1, f"{_MIGRATION_NAME} must add {table}.{_COLUMN} exactly once"
    return found[0]


def _added_check(table: str, name: str) -> str:
    """The expression 0032 adds the CHECK ``name`` on ``table`` with (exactly once)."""
    found = []
    for action_table, action in _alter_actions():
        match = _ADD_CHECK_RE.fullmatch(_masked(action))
        if match is not None and (action_table, match.group("name")) == (table, name):
            found.append(action[match.start("expression") : match.end("expression")])
    assert len(found) == 1, f"{_MIGRATION_NAME} must add {name} on {table} exactly once"
    return found[0]


def _equality(expression: str) -> Any:
    """The two sides of a top-level ``a = b`` (unwrapped, canonical, as a set: the order
    of the sides doesn't matter), else the canonical expression."""
    expression = _unwrap(expression)
    masked = _masked(expression)
    operators = []
    depth = 0
    for index, char in enumerate(masked):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char == "=" and masked[index - 1 : index] not in ("<", ">", "!"):
            operators.append(index)
    if len(operators) != 1:
        return _canon(expression)
    left, right = expression[: operators[0]], expression[operators[0] + 1 :]
    return frozenset({_canon(_unwrap(left)), _canon(_unwrap(right))})


def _indexes() -> dict[str, _Index]:
    """Every CREATE INDEX 0032 runs, by name."""
    found: dict[str, _Index] = {}
    for statement in _statements():
        masked = _masked(statement)
        match = _INDEX_RE.fullmatch(masked)
        if match is None:
            assert not re.match(r"create (?:unique )?index\b", masked), (
                f"the test can't read the index statement {statement!r}"
            )
            continue
        columns = tuple(
            re.sub(r" asc$", "", column.strip().strip('"'))
            for column in _split(match.group("columns"), ",")
        )
        assert match.group("name") not in found, f"index {match.group('name')} created twice"
        found[match.group("name")] = _Index(
            table=match.group("table"),
            unique=match.group("unique") is not None,
            concurrently=match.group("concurrently") is not None,
            btree=match.group("method") in (None, "btree"),
            columns=columns,
            include=_names(match.group("include")) if match.group("include") else (),
            where=(
                _conditions(statement[match.start("where") : match.end("where")])
                if match.group("where")
                else frozenset()
            ),
        )
    return found


def _listed_actions() -> list[str]:
    """The literals of 0032's ``audit_events_action_check``, in written order."""
    _raw_sql()
    return _added_actions(_MIGRATION_NAME)


def _expected_actions() -> list[str]:
    """0030's list with each purge right after its restore (contract section 1)."""
    expected = list(_added_actions(_CATALOG_MIGRATION))
    for action, after in _NEW_ACTIONS.items():
        expected.insert(expected.index(after) + 1, action)
    return expected


def _acl(up_to: int | None = None) -> dict[tuple[str, str], frozenset[str]]:
    """(table, grantee) -> ACL entries after every shipped migration (up to a version).

    Fails the calling test when version 32 isn't shipped."""
    shipped = _load_migrations(db_mod._MIGRATIONS_DIR)
    assert _VERSION in [m.version for m in shipped], f"{_MIGRATION_NAME} is not shipped"
    acl: dict[tuple[str, str], set[str]] = {}
    for migration in shipped:
        if up_to is not None and migration.version > up_to:
            continue
        for statement in _executed(_normalize(migration.sql)):
            _apply(acl, statement)
    return {key: frozenset(value) for key, value in acl.items() if value}


def _file_grants() -> list[tuple[frozenset[str], tuple[str, ...], frozenset[str], bool]]:
    """(ACL entries, tables, grantees, grant option) of every GRANT in 0032, nested DO /
    function bodies and EXECUTE literals included."""
    grants = []
    for fragment in _fragments(_normalize(_raw_sql())):
        match = _GRANT_RE.fullmatch(_masked(fragment))
        if match is None:
            continue
        entries = frozenset(
            key
            for name, columns in _privilege_entries(match.group("privileges"))
            for key in _acl_keys(name, columns)
        )
        grants.append(
            (
                entries,
                _targets(match.group("target")),
                _grantees(match.group("grantees")),
                bool(match.group("option")),
            )
        )
    return grants


def _header_lines() -> list[str]:
    """The non-empty ``--`` comment lines before the first statement."""
    lines: list[str] = []
    for line in _raw_sql().splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            lines.append(stripped[2:].strip())
        elif stripped:
            break
    return [line for line in lines if line]


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0032File:
    """The migration ships as version 32, right after 0031, and is applied once."""

    def test_migration_0032_file_is_the_only_version_32_after_versions_1_to_31(self) -> None:
        shipped = [
            (int(m.group(1)), path.name)
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name))
        ]

        assert [name for version, name in shipped if version == _VERSION] == [_MIGRATION_NAME]
        assert sorted(version for version, _ in shipped if version < _VERSION) == list(
            range(1, _VERSION)
        )

    async def test_migration_0032_run_migrations_applies_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0031 applied, run_migrations executes the file and records 32."""
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

    async def test_migration_0032_runs_after_0031(self, mock_pool: MagicMock) -> None:
        """With 0001 to 0030 applied, 0031 (GH-245's chat retry) runs before 0032."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0032_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0032 applied, the file isn't executed."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0032_opens_with_a_header_comment_naming_what_it_changes(self) -> None:
        """What, why and grants, before any statement: the group column, the two new
        actions and the DELETE granted to the runtime role."""
        lines = _header_lines()
        header = " ".join(lines)

        assert len(lines) >= 3
        assert {
            "names the column": re.search(rf"\b{_COLUMN}\b", header) is not None,
            "names chat.purge": "chat.purge" in header,
            "names file.purge": "file.purge" in header,
            "says what is granted": re.search(r"\bgrant", header, re.IGNORECASE) is not None,
            "names the delete": re.search(r"\bdelete\b", header, re.IGNORECASE) is not None,
        } == dict.fromkeys(
            (
                "names the column",
                "names chat.purge",
                "names file.purge",
                "says what is granted",
                "names the delete",
            ),
            True,
        )


# ---------------------------------------------------------------------------
# 2. The trash_group_id columns (Decision 2)
# ---------------------------------------------------------------------------


class TestMigration0032Columns:
    """ALTER TABLE chats / attachments ADD COLUMN trash_group_id UUID."""

    def test_migration_0032_adds_only_the_two_trash_group_columns(self) -> None:
        """One ADD COLUMN per table, trash_group_id on chats and on attachments, and no
        other column anywhere."""
        added = sorted(
            (table, match.group("name"))
            for table, action in _alter_actions()
            if (match := _ADD_COLUMN_RE.fullmatch(_masked(action))) is not None
        )

        assert added == sorted((table, _COLUMN) for table in _TABLES)

    def test_migration_0032_trash_group_ids_are_nullable_uuids_without_default(self) -> None:
        """UUID, nullable (a live row has no group), no default (the application sets it
        with deleted_at), nothing else on the column: no CHECK (the table CHECK pairs it
        with deleted_at), key, reference or identity."""
        columns = {table: _added_column(table) for table in _TABLES}

        assert {
            table: {
                "uuid": column.type_name in _UUID_TYPES,
                "not null": column.not_null,
                "primary key": column.primary_key,
                "identity": column.identity,
                "default": _canonical_default(column),
                "checks": column.checks,
                "uniques": column.uniques,
                "references": column.references,
                "unexpected": column.unexpected,
            }
            for table, column in columns.items()
        } == {
            table: {
                "uuid": True,
                "not null": False,
                "primary key": False,
                "identity": None,
                "default": None,
                "checks": [],
                "uniques": [],
                "references": [],
                "unexpected": [],
            }
            for table in _TABLES
        }


# ---------------------------------------------------------------------------
# 3. The backfill of the existing trash (Decision 2)
# ---------------------------------------------------------------------------


class TestMigration0032Backfill:
    """Existing trashed rows get their group; live rows keep NULL."""

    def test_migration_0032_backfills_every_trashed_chat_as_its_own_group(self) -> None:
        """UPDATE chats SET trash_group_id = id WHERE deleted_at IS NOT NULL: nothing
        else is set, no other filter, no FROM or RETURNING."""
        by_table = {backfill[0]: backfill for backfill in _backfills()}

        assert by_table.get(_CHATS) == _CHATS_BACKFILL

    def test_migration_0032_backfills_trashed_files_into_their_trashed_chat_or_their_own(
        self,
    ) -> None:
        """UPDATE attachments SET trash_group_id = CASE WHEN EXISTS (a chat with the
        file's chat_id and org_id that is trashed) THEN chat_id ELSE id END WHERE
        deleted_at IS NOT NULL: a file trashed with its chat joins the chat's group,
        any other trashed file (deleted on its own) is its own group, a live file keeps
        NULL. Nothing else is set; no FROM or RETURNING."""
        by_table = {backfill[0]: backfill for backfill in _backfills()}

        assert by_table.get(_ATTACHMENTS) == _ATTACHMENTS_BACKFILL

    def test_migration_0032_the_two_backfills_are_its_only_data_writes(self) -> None:
        """Exactly one UPDATE per table, and no other UPDATE fragment anywhere (nested
        bodies and literals included)."""
        fragments = _fragments(_normalize(_raw_sql()))
        updates = [f for f in fragments if re.match(_UPDATE_FRAGMENT, _masked(f))]

        assert sorted(backfill[0] for backfill in _backfills()) == sorted(_TABLES)
        assert len(updates) == len(_TABLES)


# ---------------------------------------------------------------------------
# 4. The CHECKs pairing the group with deleted_at (Decision 2)
# ---------------------------------------------------------------------------


class TestMigration0032Checks:
    """A row has both deleted_at and trash_group_id, or neither."""

    def test_migration_0032_checks_pair_deleted_at_with_trash_group_id(self) -> None:
        """chats_trash_group_check and attachments_trash_group_check are each exactly
        (deleted_at IS NULL) = (trash_group_id IS NULL), validated (nothing after the
        expression: no NOT VALID)."""
        expressions = {
            name: _equality(_added_check(table, name)) for table, name in _TRASH_CHECKS.items()
        }

        assert expressions == dict.fromkeys(
            _TRASH_CHECKS.values(), frozenset({"deleted_at is null", f"{_COLUMN} is null"})
        )

    def test_migration_0032_steps_run_in_an_order_postgresql_accepts(self) -> None:
        """Each column exists before its backfill and its UPDATE grant; each CHECK comes
        after its table's backfill (before it, every trashed row would fail it); the
        action CHECK is dropped before it is added again."""
        steps = _steps()

        def position(step: str) -> int:
            assert step in steps, f"{_MIGRATION_NAME} has no step {step!r}: {steps}"
            return steps.index(step)

        orders = {
            f"{table}: column, backfill, check, grant": (
                position(f"column {table}.{_COLUMN}")
                < position(f"backfill {table}")
                < position(f"check {table}.{_TRASH_CHECKS[table]}")
                and position(f"column {table}.{_COLUMN}")
                < position(f"grant update({_COLUMN}) on {table} to {_ROLE}")
            )
            for table in _TABLES
        }
        orders["action check: drop, add"] = position(
            f"drop {_AUDIT_TABLE}.{_ACTION_CHECK}"
        ) < position(f"check {_AUDIT_TABLE}.{_ACTION_CHECK}")

        assert orders == dict.fromkeys(orders, True)


# ---------------------------------------------------------------------------
# 5. The trash indexes
# ---------------------------------------------------------------------------


class TestMigration0032Indexes:
    """The owner's trash and the purge read an org's trashed rows by deletion time."""

    def test_migration_0032_creates_exactly_the_two_partial_trash_indexes(self) -> None:
        """Plain btree, non-unique, not CONCURRENTLY (migrations run in a transaction), on
        (org_id, owner_user_id, deleted_at, id) WHERE deleted_at IS NOT NULL: they hold
        only the trash."""
        expected = {
            name: _Index(
                table=table,
                unique=False,
                concurrently=False,
                btree=True,
                columns=_INDEX_COLUMNS,
                include=(),
                where=frozenset({"deleted_at is not null"}),
            )
            for name, table in _TRASH_INDEXES.items()
        }

        assert _indexes() == expected


# ---------------------------------------------------------------------------
# 6. Privileges (Decision 10)
# ---------------------------------------------------------------------------


class TestMigration0032Privileges:
    """admino_app may delete chats and write the groups; nothing else changes."""

    def test_migration_0032_grants_delete_on_chats_and_update_of_the_groups_only(
        self,
    ) -> None:
        """Every GRANT of the file (nested ones included), together: DELETE on chats,
        UPDATE (trash_group_id) on chats and on attachments; to admino_app alone (never
        PUBLIC), without grant option."""
        grants = _file_grants()

        assert {
            (table, entry)
            for entries, tables, _, _ in grants
            for table in tables
            for entry in entries
        } == {(table, entry) for table, held in _ADDED_PRIVILEGES.items() for entry in held}
        assert {grantee for _, _, grantees, _ in grants for grantee in grantees} == {_ROLE}
        assert [option for *_, option in grants if option] == []

    def test_migration_0032_adds_exactly_the_contract_privileges(self) -> None:
        """Every (table, grantee) holds after 0032 what it held after 0031, except
        admino_app on chats (delete, update(trash_group_id)) and on attachments
        (update(trash_group_id)): no other table gains DELETE, nothing is revoked."""
        before = _acl(_VERSION - 1)
        expected = dict(before)
        for table, added in _ADDED_PRIVILEGES.items():
            expected[(table, _ROLE)] = before.get((table, _ROLE), frozenset()) | added

        assert _acl(_VERSION) == expected

    def test_migration_0032_runtime_role_privileges_after_every_migration(self) -> None:
        """After every shipped migration: chats SELECT, INSERT, DELETE and UPDATE on six
        columns (never id, org_id, owner_user_id, created_at or legacy_session_id);
        attachments SELECT, INSERT, DELETE and UPDATE on ten columns (never id, org_id,
        chat_id, owner_user_id, filename, kind, size_bytes or created_at); chat_messages
        SELECT, INSERT only (append-only: a chat's DELETE cascades as the owner); no
        table-wide UPDATE, no grant option; PUBLIC nothing on any of them."""
        acl = _acl()

        assert {
            (table, grantee): acl.get((table, grantee), frozenset())
            for table in _EXPECTED_PRIVILEGES
            for grantee in (_ROLE, "public")
        } == {
            **{(table, _ROLE): held for table, held in _EXPECTED_PRIVILEGES.items()},
            **{(table, "public"): frozenset() for table in _EXPECTED_PRIVILEGES},
        }

    def test_migration_0032_passes_the_runtime_role_grant_guards(self) -> None:
        """tests/test_migration_0018.py's guards hold over every shipped migration with
        0032 in place, and their parser reads 0032's table grants (DELETE and UPDATE on
        chats, UPDATE on attachments, to admino_app) and no role membership."""
        shipped = _shipped()
        ours = [migration for migration in shipped if migration.version == _VERSION]
        assert [migration.name for migration in ours] == [_MIGRATION_NAME]
        grants, memberships = _migration_grants(ours[0])

        assert {
            (table, privilege, grantee)
            for grant in grants
            if grant.kind == "table"
            for table in grant.objects
            for privilege in grant.privileges
            for grantee in grant.grantees
        } == {
            (_CHATS, "delete", _ROLE),
            (_CHATS, "update", _ROLE),
            (_ATTACHMENTS, "update", _ROLE),
        }
        assert memberships == []
        assert {guard_id: guard(shipped) for guard_id, guard in _GUARDS} == {
            guard_id: [] for guard_id, _ in _GUARDS
        }


# ---------------------------------------------------------------------------
# 7. The audit action catalog (Decision 9)
# ---------------------------------------------------------------------------


class TestMigration0032ActionCatalog:
    """audit_events_action_check is replaced with 0030's catalog plus the two purges."""

    def test_migration_0032_action_check_is_dropped_then_re_added_under_its_name(
        self,
    ) -> None:
        """A plain DROP (no IF EXISTS, no CASCADE), then one ADD of the same name on
        audit_events, with nothing after the expression."""
        steps = [
            _action_step(table, action)
            for table, action in _alter_actions()
            if table == _AUDIT_TABLE
        ]

        assert steps == [
            f"drop {_AUDIT_TABLE}.{_ACTION_CHECK}",
            f"check {_AUDIT_TABLE}.{_ACTION_CHECK}",
        ]

    def test_migration_0032_action_list_is_0030s_with_each_purge_after_its_restore(
        self,
    ) -> None:
        """0030's 52 actions in their order, with 'chat.purge' right after
        'chat.restore' and 'file.purge' right after 'file.restore': nothing else added
        or removed, each listed once."""
        listed = _listed_actions()

        assert listed == _expected_actions()
        assert len(listed) == len(set(listed)) == 54

    def test_migration_0032_action_check_matches_audit_action(self) -> None:
        """The live catalog sync (moved here from test_migration_0030.py): the SQL action
        list equals AuditAction's values exactly."""
        from admino.audit_events import AuditAction

        assert set(_listed_actions()) == {action.value for action in AuditAction}

    def test_migration_0032_audit_action_has_the_two_purge_members(self) -> None:
        """AuditAction.CHAT_PURGE / FILE_PURGE are 'chat.purge' / 'file.purge'."""
        from admino import audit_events

        assert {
            name: getattr(getattr(audit_events.AuditAction, name, None), "value", None)
            for name in ("CHAT_PURGE", "FILE_PURGE")
        } == {"CHAT_PURGE": "chat.purge", "FILE_PURGE": "file.purge"}

    def test_migration_0032_fake_catalog_is_the_shipped_one(self) -> None:
        """tests/db_fakes.py reads its action catalog from the shipped migrations: after
        0032 it is 0032's list (moved here from test_migration_0030.py's mirror)."""
        assert db_fakes.shipped_schema().audit_actions == frozenset(_listed_actions())


# ---------------------------------------------------------------------------
# 8. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0032Scope:
    """Only the columns, the backfill, the CHECKs, the indexes, the grants and the
    catalog."""

    def test_migration_0032_runs_exactly_the_contract_steps(self) -> None:
        """Every statement at the top level or in a DO block, ALTER TABLE actions and
        granted privileges one by one: two columns, two backfills, three CHECKs, one
        DROP, two indexes, three grants; nothing else, nothing twice."""
        assert sorted(_steps()) == sorted(_CONTRACT_STEPS)

    def test_migration_0032_runs_no_code_revoke_or_other_write(self) -> None:
        """No DO block, function, trigger, role, INSERT / DELETE / TRUNCATE / COPY /
        MERGE, REVOKE, CREATE TABLE, DROP TABLE / INDEX / COLUMN, SECURITY DEFINER,
        owner change, trigger switch, grant option or default privileges, also not
        nested in a body or an EXECUTE literal; the two indexes are the only CREATE
        INDEX fragments."""
        fragments = _fragments(_normalize(_raw_sql()))
        offenders = [
            (kind, fragment)
            for fragment in fragments
            for kind, pattern in _FORBIDDEN.items()
            if re.match(pattern, _masked(fragment))
        ] + [
            (kind, fragment)
            for fragment in fragments
            for kind, pattern in _FORBIDDEN_ANYWHERE.items()
            if re.search(pattern, _masked(fragment))
        ]
        indexes = [f for f in fragments if re.match(_INDEX_FRAGMENT, _masked(f))]

        assert fragments, f"{_MIGRATION_NAME} runs nothing"
        assert offenders == []
        assert len(indexes) == len(_TRASH_INDEXES)
