"""Tests for migration 0029_chat_message_attachments.sql (GH-189, contract C13 and its
Amendment A1, issue Decisions 10 and 11): the attachment ids an assistant message was
answered with, and the audit metadata CHECK that lets a tool.call row carry them.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
pipeline runs it on a throwaway postgres:16 as admino_app). The SQL is read with
tests/test_migration_0018.py's lexer (comments blanked, '...' literals and
dollar-quoted bodies kept whole, nested DO / function bodies and EXECUTE literals
searched too), the added column with tests/test_migration_0024.py's column parser (an
array type ``UUID[]`` read first), and the GRANT / REVOKE statements of every shipped
migration are replayed into the privileges each role ends up with
(tests/test_migration_0027.py's replay). The CHECK is compared as its top-level OR-ed
alternatives, each a set of top-level AND-ed conditions, canonical (whitespace around
parentheses, commas and comparison operators ignored, literals byte for byte).

What is pinned:
- ``0029_chat_message_attachments.sql`` ships as the only version 29, right after the
  versions 1 to 28; run_migrations applies it after 0028 (once). It opens with a
  header comment that names the column and ``audit_events_metadata_check``.
- One ``ALTER TABLE chat_messages`` with one action, ``ADD COLUMN
  included_attachment_ids UUID[]``, nullable (NULL: no attachments in the slot), no
  default, nothing else on the column but exactly one CHECK, named
  ``chat_messages_included_attachment_ids_check``: ``included_attachment_ids IS NULL OR
  (role = 'assistant' AND array_ndims(...) = 1 AND cardinality(...) >= 1 AND
  array_position(..., NULL) IS NULL)``: a one-dimensional array of at least one
  non-NULL id, on an assistant row only.
- Amendment A1 (security audit F1): after the column, ``ALTER TABLE audit_events DROP
  CONSTRAINT audit_events_metadata_check`` (no IF EXISTS, no CASCADE), then ``ADD
  CONSTRAINT audit_events_metadata_check CHECK (...)`` (validated: nothing after the
  expression). Its meaning, compared as nested CASE / top-level AND structure with
  whitespace (also inside the jsonpath literals, outside their strings) ignored, is
  the contract's: an object of at most 8192 bytes (``octet_length(metadata::text)``,
  up from 0005's 4096), with 0005's other rules kept as they were (at most 16 keys,
  the key regex) and the value rule of 0005 kept for every key but
  ``attachment_ids`` (no object or array, strings are ``^[a-z0-9_-]{1,64}$`` tokens);
  ``attachment_ids``, when present, is an array of 1 to 100 strings matching the
  canonical lowercase UUID regex. No other audit_events change: the action catalog
  (``audit_events_action_check``) isn't named.
- No privilege change: the file holds no GRANT or REVOKE (nested ones included), every
  (table, grantee) holds after 0029 what it held after 0028, and admino_app keeps
  exactly SELECT, INSERT on chat_messages (append-only), PUBLIC nothing.
- Nothing else: no DO block, function, trigger, role, INSERT / UPDATE / DELETE /
  TRUNCATE / COPY / MERGE, CREATE, DROP or default privileges, also not nested; every
  statement is the column's ALTER or the metadata CHECK's.
- tests/db_fakes.py mirrors 0029 (contract C14): the contract's assistant INSERT (S8',
  ``$9::uuid[]``) stores the ids in the given order, NULL stays NULL, today's INSERT
  (S8) stores NULL; ``'{}'``, ``ARRAY[NULL]``, an id list with a NULL, a user or tool
  row with ids and a 2-D array are CheckViolationError on the shipped CHECK's name with
  nothing stored; ``add_chat_message(..., included_attachment_ids=)`` is checked the
  same way; the fake's chat_messages columns are 0024's followed by the new one.
- The fake's INSERT INTO audit_events applies the shipped metadata CHECK: the
  contract's verified accepted rows (today's six keys; plus 1 id and its count; plus
  100 ids and a count of 150; exactly 8192 bytes) are stored, and its verified refused
  rows (101 ids, ``[]``, a non-UUID or upper-case id, a number, a nested array or an
  object in the ids, a plain string under attachment_ids, an array or object under
  another key, free text, a bad key, 17 keys, 8193 bytes, a non-object) are
  CheckViolationError on the shipped constraint's name with nothing stored.

Changed in Amendment A1 (existing tests): ``_ADD_COLUMN_RE`` no longer reads ``ADD
CONSTRAINT`` as a column named "constraint"; "adds only the column" counts ADD COLUMN
actions on every table (the CHECK's actions are pinned in their own tests); "exactly
one ALTER TABLE on chat_messages" became "the column's ALTER plus the metadata CHECK's
statements, nothing else".

Security notes:
- The column holds attachment ids only: no name, kind, size or content of a file.
- admino_app gains no privilege: chat_messages stays append-only for the app.
- The audit metadata stays content-free in the database too: only ``attachment_ids``
  may be an array, and only of UUIDs; free text, emails and file names stay refused.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock

import asyncpg
import pytest

import admino.database as db_mod
from tests.db_fakes import ORG_ID, FakeDb
from tests.test_migration_0018 import (
    _executed,
    _fragments,
    _load_migrations,
    _masked,
    _normalize,
    _split,
)
from tests.test_migration_0024 import _canonical_default, _Column, _parse_column
from tests.test_migration_0024 import _table as _table_0024
from tests.test_migration_0027 import _ALTER_RE, _apply, _balanced_end, _canon, _unwrap

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME: Final = "0029_chat_message_attachments.sql"
_PREVIOUS_MIGRATION: Final = "0028_attachment_token_estimate.sql"
_VERSION: Final = 29
_ROLE: Final = "admino_app"
_TABLE: Final = "chat_messages"
_COLUMN: Final = "included_attachment_ids"
_CHECK_NAME: Final = "chat_messages_included_attachment_ids_check"

_SCHEMA: Final = r'(?:"?public"?\.)?'
# ADD [COLUMN] name definition; ADD CONSTRAINT (the metadata CHECK) is no column.
_ADD_COLUMN_RE: Final = re.compile(
    r'add (?:column )?(?:if not exists )?(?!constraint\b)"?(?P<name>\w+)"? (?P<definition>.+)'
)
# A one-dimensional array type: "uuid[]" or "uuid array" (the SQL-standard spelling).
_ARRAY_TYPE_RE: Final = re.compile(r"(?P<base>\w+)\s*(?:\[\s*\]|\s+array\b)\s*")

# Amendment A1: audit_events_metadata_check (migration 0005), replaced by 0029.
_AUDIT_TABLE: Final = "audit_events"
_AUDIT_MIGRATION: Final = "0005_audit_events.sql"
_METADATA_CHECK: Final = "audit_events_metadata_check"
_ACTION_CHECK: Final = "audit_events_action_check"
_METADATA_BYTES: Final = 8192
# A plain DROP (no IF EXISTS: a missing 0005 constraint fails loudly; no CASCADE).
_DROP_METADATA_CHECK_RE: Final = re.compile(rf'drop constraint "?{_METADATA_CHECK}"?(?: restrict)?')
# ADD CONSTRAINT ... CHECK (...) with nothing after it (no NOT VALID, no NO INHERIT).
_ADD_METADATA_CHECK_RE: Final = re.compile(
    rf'add constraint "?{_METADATA_CHECK}"? check ?\((?P<expression>.*)\)'
)
# The statement kinds 0029 may run (masked, normalized).
_ALLOWED_STATEMENTS: Final[dict[str, re.Pattern[str]]] = {
    "column": re.compile(rf'alter table (?:only )?{_SCHEMA}"?{_TABLE}"? add .+'),
    "metadata check": re.compile(
        rf'alter table (?:only )?{_SCHEMA}"?{_AUDIT_TABLE}"? (?:drop|add) constraint .+'
    ),
}
# One CASE with one WHEN (masked text; a nested CASE sits in the THEN branch).
_CASE_RE: Final = re.compile(r"case when (?P<when>.+?) then (?P<then>.+) else (?P<else>.+?) end")

# The contract's CHECK (Amendment A1, verified on postgres:16-alpine), by conjunct.
_IS_OBJECT: Final = "jsonb_typeof(metadata) = 'object'"
_SIZE_CAP: Final = f"octet_length(metadata::text) <= {_METADATA_BYTES}"
_OLD_SIZE_CAP: Final = "octet_length(metadata::text) <= 4096"
_KEY_COUNT: Final = (
    "jsonb_array_length(jsonb_path_query_array(metadata, 'strict $.keyvalue()')) <= 16"
)
_KEY_NAMES: Final = (
    "NOT jsonb_path_exists(metadata,"
    " 'strict $.keyvalue() ? (!(@.key like_regex \"^[a-z][a-z0-9_]{0,39}$\"))')"
)
# Every key but attachment_ids: no object or array, a string is a token.
_SCALAR_VALUES: Final = (
    "NOT jsonb_path_exists(metadata,"
    ' \'strict $.keyvalue() ? (@.key != "attachment_ids") ? (@.value.type() == "object"'
    ' || @.value.type() == "array" || (@.value.type() == "string"'
    ' && !(@.value like_regex "^[a-z0-9_-]{1,64}$")))\')'
)
# 0005's value rule: the same, for every key.
_OLD_SCALAR_VALUES: Final = (
    "NOT jsonb_path_exists(metadata,"
    ' \'strict $.* ? (@.type() == "object" || @.type() == "array"'
    ' || (@.type() == "string" && !(@ like_regex "^[a-z0-9_-]{1,64}$")))\')'
)
_ATTACHMENT_IDS_RULE: Final = (
    "CASE WHEN metadata ? 'attachment_ids' THEN"
    " CASE WHEN jsonb_typeof(metadata -> 'attachment_ids') = 'array' THEN"
    " jsonb_array_length(metadata -> 'attachment_ids') BETWEEN 1 AND 100"
    " AND NOT jsonb_path_exists(metadata -> 'attachment_ids',"
    ' \'strict $[*] ? (@.type() != "string" || !(@ like_regex'
    ' "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))\')'
    " ELSE false END"
    " ELSE true END"
)
_CONTRACT_METADATA_CHECK: Final = (
    f"CASE WHEN {_IS_OBJECT} THEN "
    + " AND ".join((_SIZE_CAP, _KEY_COUNT, _KEY_NAMES, _SCALAR_VALUES, _ATTACHMENT_IDS_RULE))
    + " ELSE false END"
)
# Fragments 0029 must not contain (top level, DO / function bodies, literals).
_FORBIDDEN: Final[dict[str, str]] = {
    "do": r"do\b",
    "grant": r"grant\b",
    "revoke": r"revoke\b",
    "insert": r"insert into\b",
    "update": r"update (?:only )?\S+ set\b",
    "delete": r"delete from\b",
    "truncate": r"truncate\b",
    "copy": r"copy\b",
    "merge": r"merge into\b",
    "function": r"(?:create|alter|drop) (?:or replace )?(?:function|procedure)\b",
    "trigger": r"(?:create|alter|drop) (?:or replace )?(?:constraint )?trigger\b",
    "role": r"(?:create|alter|drop) (?:role|user|group)\b",
    "drop": r"drop (?:table|view|schema|type|index)\b",
    "default privileges": r"alter default privileges\b",
    "create": r"create (?:unique )?(?:table|index|view|type|schema)\b",
}

# The CHECK's meaning (canonical): NULL, or the four conditions together.
_NULL_ALTERNATIVE: Final = frozenset({f"{_COLUMN} is null"})
_NON_EMPTY: Final = f"cardinality({_COLUMN}) >= 1"
_NON_EMPTY_EQUIVALENTS: Final = frozenset(
    {
        _NON_EMPTY,
        f"cardinality({_COLUMN}) > 0",
        f"array_length({_COLUMN},1) >= 1",
        f"array_length({_COLUMN},1) > 0",
    }
)
_IDS_ALTERNATIVE: Final = frozenset(
    {
        "role = 'assistant'",
        f"array_ndims({_COLUMN}) = 1",
        _NON_EMPTY,
        f"array_position({_COLUMN},null) is null",
    }
)

# Contract C4's S8' (an assistant message with the slot's ids) and today's S8.
_INSERT_WITH_IDS: Final = """
    INSERT INTO chat_messages
        (chat_id, org_id, role, content, tool_use_blocks, tool_call_id, tool_calls, status,
         included_attachment_ids)
    VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8, $9::uuid[])
    RETURNING id
"""
_INSERT_TODAY: Final = """
    INSERT INTO chat_messages
        (chat_id, org_id, role, content, tool_use_blocks, tool_call_id, tool_calls, status)
    VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8)
    RETURNING id
"""
_FIRST: Final = uuid.UUID("f9000000-0000-4000-8000-000000000002")
_SECOND: Final = uuid.UUID("10000000-0000-4000-8000-000000000001")

# The audit INSERT audit_events.record() runs (its statement's shape).
_AUDIT_INSERT: Final = """
    INSERT INTO audit_events
        (org_id, actor_user_id, actor_kind, action, target_type, target_ids, ip, metadata)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::inet, $8::jsonb)
"""
_ACTOR: Final = uuid.UUID("29a1c0de-0000-4000-8000-000000000001")
_TARGET_CHAT: Final = uuid.UUID("29a1c0de-0000-4000-8000-000000000002")
# 101 canonical ids in descending order.
_AUDIT_IDS: Final[tuple[str, ...]] = tuple(
    str(uuid.UUID(f"{0xF0000000 - n:08x}-{n:04x}-4029-8000-{0x029000000000 + n:012x}"))
    for n in range(101)
)
# The six keys of today's tool.call row (record_tool_call).
_SIX_KEYS: Final[dict[str, Any]] = {
    "tool": "memory",
    "action": "read",
    "decision": "allow",
    "success": True,
    "duration_ms": 42,
    "escalated": False,
}


def _tool_call_metadata(**extra: Any) -> str:
    """Today's six keys plus ``extra``, as the JSON text record() binds."""
    return json.dumps({**_SIX_KEYS, **extra})


def _sized_metadata(total: int) -> str:
    """``{"a": 1...1, "b": 1...1}`` of exactly ``total`` bytes, which is also its jsonb
    text form; two integers stay below Python's 4300-digit int conversion limit."""
    digits = total - len('{"a": , "b": }')
    first = digits // 2
    return '{"a": ' + "1" * first + ', "b": ' + "1" * (digits - first) + "}"


# Contract Amendment A1's verified cases (postgres:16-alpine), plus the size boundary.
_ACCEPTED_METADATA: Final = [
    pytest.param(json.dumps(_SIX_KEYS), id="todays-six-keys"),
    pytest.param(
        _tool_call_metadata(attachment_ids=list(_AUDIT_IDS[:1]), attachment_count=1),
        id="one-id-and-its-count",
    ),
    pytest.param(
        _tool_call_metadata(attachment_ids=list(_AUDIT_IDS[:100]), attachment_count=150),
        id="hundred-ids-and-a-count-of-150",
    ),
    pytest.param(_sized_metadata(_METADATA_BYTES), id="exactly-8192-bytes"),
]
_REFUSED_METADATA: Final = [
    pytest.param(
        _tool_call_metadata(attachment_ids=list(_AUDIT_IDS), attachment_count=101), id="101-ids"
    ),
    pytest.param(_tool_call_metadata(attachment_ids=[]), id="empty-ids"),
    pytest.param(_tool_call_metadata(attachment_ids=["report-2026"]), id="non-uuid-string"),
    pytest.param(_tool_call_metadata(attachment_ids=[_AUDIT_IDS[0].upper()]), id="upper-case-id"),
    pytest.param(_tool_call_metadata(attachment_ids=[7]), id="number-in-ids"),
    pytest.param(_tool_call_metadata(attachment_ids=7), id="number-as-ids"),
    pytest.param(_tool_call_metadata(attachment_ids=[[_AUDIT_IDS[0]]]), id="nested-array"),
    pytest.param(_tool_call_metadata(attachment_ids={"id": _AUDIT_IDS[0]}), id="object-as-ids"),
    pytest.param(_tool_call_metadata(attachment_ids=_AUDIT_IDS[0]), id="plain-string-as-ids"),
    pytest.param(_tool_call_metadata(ids=[_AUDIT_IDS[0]]), id="array-under-another-key"),
    pytest.param(_tool_call_metadata(target={"id": _AUDIT_IDS[0]}), id="object-under-another-key"),
    pytest.param(_tool_call_metadata(note="Quarterly report.pdf"), id="free-text"),
    pytest.param(_tool_call_metadata(**{"Bad-Key": 1}), id="bad-key"),
    pytest.param(json.dumps({f"k{n}": n for n in range(17)}), id="17-keys"),
    pytest.param(_sized_metadata(_METADATA_BYTES + 1), id="8193-bytes"),
    pytest.param(json.dumps(list(_AUDIT_IDS[:1])), id="not-an-object"),
]


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
    """The statements 0029 runs (top level and DO blocks), normalized."""
    return _executed(_normalize(_raw_sql()))


def _expr(text: str) -> str:
    """Canonical: 0027's canonical form, comparison operators with one space each side."""
    return _canon(re.sub(r"\s*(>=|<=|<>|!=|=|<|>)\s*", r" \1 ", text))


def _top_level(expression: str, word: str) -> list[str]:
    """The parts of an expression between its top-level ``word``s (and / or), unwrapped."""
    expression = _unwrap(expression)
    masked = _masked(expression)
    parts: list[str] = []
    depth = 0
    start = 0
    for token in re.finditer(rf"\(|\)|\b{word}\b", masked):
        if token.group(0) == "(":
            depth += 1
        elif token.group(0) == ")":
            depth -= 1
        elif depth == 0:
            parts.append(expression[start : token.start()])
            start = token.end()
    parts.append(expression[start:])
    return [_unwrap(part) for part in parts]


def _meaning(expression: str) -> frozenset[frozenset[str]]:
    """The OR-ed alternatives of a CHECK, each the set of its AND-ed conditions."""
    alternatives = set()
    for alternative in _top_level(expression, "or"):
        conditions = {_expr(condition) for condition in _top_level(alternative, "and")}
        equivalents = {_expr(text) for text in _NON_EMPTY_EQUIVALENTS}
        if conditions & equivalents:
            conditions = (conditions - equivalents) | {_expr(_NON_EMPTY)}
        alternatives.add(frozenset(conditions))
    return frozenset(alternatives)


def _alter_actions() -> list[tuple[str, str]]:
    """(table, action) for every action of every ALTER TABLE 0029 runs, in order."""
    found: list[tuple[str, str]] = []
    for statement in _statements():
        match = _ALTER_RE.fullmatch(_masked(statement))
        if match is None:
            continue
        for action in _split(statement[match.start("actions") :], ","):
            found.append((match.group("table"), action))
    return found


def _parse_definition(name: str, definition: str) -> _Column:
    """0024's column parser, with an array type (``uuid[]``) read first."""
    array = _ARRAY_TYPE_RE.match(_masked(definition))
    if array is None:
        return _parse_column(name, definition)
    column = _parse_column(name, "placeholder " + definition[array.end() :])
    column.type_name = f"{array.group('base')}[]"
    return column


def _added_columns() -> list[tuple[str, str, _Column]]:
    """(table, column, parsed definition) of every ADD COLUMN action, in order."""
    added = []
    for table, action in _alter_actions():
        match = _ADD_COLUMN_RE.fullmatch(_masked(action))
        if match is None:
            continue
        definition = action[match.start("definition") :]
        added.append(
            (table, match.group("name"), _parse_definition(match.group("name"), definition))
        )
    return added


def _added_column() -> _Column:
    """The parsed definition of ``chat_messages.included_attachment_ids`` (exactly once)."""
    found = [
        parsed for table, name, parsed in _added_columns() if (table, name) == (_TABLE, _COLUMN)
    ]
    assert len(found) == 1, f"{_MIGRATION_NAME} must add {_TABLE}.{_COLUMN} exactly once"
    return found[0]


def _shipped_column() -> str:
    """The one column 0029 adds to chat_messages: what the fake must store."""
    added = [name for table, name, _ in _added_columns() if table == _TABLE]
    assert added == [_COLUMN], added
    return added[0]


def _check_name() -> str:
    checks = _added_column().checks
    assert len(checks) == 1, checks
    name = checks[0][0]
    assert name is not None, "the CHECK must be named"
    return name


def _acl(up_to: int) -> dict[tuple[str, str], frozenset[str]]:
    """(table, grantee) -> ACL entries after every shipped migration up to a version.

    Fails the calling test when 0029 isn't shipped (nothing to compare)."""
    versions: list[int] = []
    acl: dict[tuple[str, str], set[str]] = {}
    for migration in _load_migrations(db_mod._MIGRATIONS_DIR):
        if migration.version > up_to:
            continue
        versions.append(migration.version)
        for statement in _executed(_normalize(migration.sql)):
            _apply(acl, statement)
    assert _VERSION in [m.version for m in _load_migrations(db_mod._MIGRATIONS_DIR)], (
        f"{_MIGRATION_NAME} is not shipped"
    )
    assert up_to in versions
    return {key: frozenset(value) for key, value in acl.items() if value}


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
# Helpers: the audit metadata CHECK (Amendment A1)
# ---------------------------------------------------------------------------


def _jsonpath_canon(path: str) -> str:
    """A jsonpath literal without the whitespace outside its "..." strings."""
    out: list[str] = []
    in_string = False
    escaped = False
    for char in path:
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            out.append(char)
        elif not char.isspace():
            out.append(char)
    return "".join(out)


def _condition_canon(text: str) -> str:
    """0029's canonical form, with every '...' literal read as jsonpath."""
    return _expr(re.sub(r"'((?:[^']|'')*)'", lambda m: f"'{_jsonpath_canon(m.group(1))}'", text))


def _conjuncts(expression: str) -> list[str]:
    """The top-level AND-ed parts of an expression, unwrapped: the AND of a BETWEEN and
    the ANDs inside parentheses or a CASE ... END are no separators."""
    expression = _unwrap(expression)
    masked = _masked(expression)
    parts: list[str] = []
    depth = 0
    start = 0
    in_between = False
    for token in re.finditer(r"\(|\)|\bcase\b|\bend\b|\bbetween\b|\band\b", masked):
        word = token.group(0)
        if word in {"(", "case"}:
            depth += 1
        elif word in {")", "end"}:
            depth -= 1
        elif depth:
            continue
        elif word == "between":
            in_between = True
        elif in_between:
            in_between = False
        else:
            parts.append(expression[start : token.start()])
            start = token.end()
    parts.append(expression[start:])
    return [_unwrap(part) for part in parts]


def _check_meaning(expression: str) -> Any:
    """A CHECK expression's meaning: an AND as the frozenset of its parts' meanings, a
    one-WHEN CASE as ("case", when, then, else), anything else canonical."""
    expression = _unwrap(_normalize(expression))
    parts = _conjuncts(expression)
    if len(parts) > 1:
        return frozenset(_check_meaning(part) for part in parts)
    case = _CASE_RE.fullmatch(_masked(expression))
    if case is not None:
        return (
            "case",
            *(
                _check_meaning(expression[case.start(group) : case.end(group)])
                for group in ("when", "then", "else")
            ),
        )
    return _condition_canon(expression)


def _then_conditions(meaning: Any) -> frozenset[Any]:
    """The AND-ed conditions of a CASE meaning's THEN branch."""
    assert isinstance(meaning, tuple), "the CHECK is one CASE WHEN ... THEN ... ELSE ... END"
    then = meaning[2]
    return then if isinstance(then, frozenset) else frozenset({then})


def _metadata_check_steps() -> list[tuple[str, str, str]]:
    """(table, "drop" | "add", the added expression or "") for every ALTER TABLE action
    of 0029 on audit_events_metadata_check, in order."""
    steps: list[tuple[str, str, str]] = []
    for table, action in _alter_actions():
        masked = _masked(action)
        if _DROP_METADATA_CHECK_RE.fullmatch(masked):
            steps.append((table, "drop", ""))
        elif (added := _ADD_METADATA_CHECK_RE.fullmatch(masked)) is not None:
            steps.append(
                (table, "add", action[added.start("expression") : added.end("expression")])
            )
    return steps


def _new_metadata_check() -> str:
    """The expression 0029 re-adds audit_events_metadata_check with (exactly once)."""
    added = [
        expression
        for table, kind, expression in _metadata_check_steps()
        if (table, kind) == (_AUDIT_TABLE, "add")
    ]
    assert len(added) == 1, f"{_MIGRATION_NAME} must re-add {_METADATA_CHECK} once"
    return added[0]


def _old_metadata_check() -> str:
    """0005's audit_events_metadata_check expression (inside CREATE TABLE audit_events)."""
    sql = _normalize((db_mod._MIGRATIONS_DIR / _AUDIT_MIGRATION).read_text(encoding="utf-8"))
    masked = _masked(sql)
    found = re.search(rf'constraint "?{_METADATA_CHECK}"? check ?\(', masked)
    assert found is not None, f"{_AUDIT_MIGRATION} defines no {_METADATA_CHECK}"
    return sql[found.end() : _balanced_end(masked, found.end() - 1)]


def _metadata_check_name() -> str:
    """The name the fake's refusals must carry: the constraint 0029 re-adds (fails the
    calling test while 0029 doesn't re-add it)."""
    _new_metadata_check()
    return _METADATA_CHECK


def _action_kind(table: str, action: str) -> tuple[str, str]:
    """(table, what the action does) for the column and the metadata CHECK, else the action."""
    masked = _masked(action)
    if (column := _ADD_COLUMN_RE.fullmatch(masked)) is not None:
        return table, f"add column {column.group('name')}"
    if _DROP_METADATA_CHECK_RE.fullmatch(masked):
        return table, f"drop {_METADATA_CHECK}"
    if _ADD_METADATA_CHECK_RE.fullmatch(masked):
        return table, f"add {_METADATA_CHECK}"
    return table, action


# ---------------------------------------------------------------------------
# Helpers: the FakeDb
# ---------------------------------------------------------------------------


def _chat(db: FakeDb) -> uuid.UUID:
    return db.add_chat(db.add_account(org_id=ORG_ID))


async def _insert(db: FakeDb, chat: uuid.UUID, role: str, ids: Any) -> Any:
    """S8' for one message of ``role`` carrying ``ids`` as $9."""
    tool_call_id = "tc-1" if role == "tool" else None
    return await db.pool.fetchval(
        _INSERT_WITH_IDS, chat, ORG_ID, role, "Answer", None, tool_call_id, None, "complete", ids
    )


def _audit_db() -> FakeDb:
    db = FakeDb()
    db.add_org(ORG_ID)
    return db


async def _insert_audit(db: FakeDb, metadata: str) -> Any:
    """A member's tool.call row on a chat, with ``metadata`` bound as the JSON text."""
    return await db.pool.execute(
        _AUDIT_INSERT,
        ORG_ID,
        _ACTOR,
        "member",
        "tool.call",
        "chat",
        json.dumps([str(_TARGET_CHAT)]),
        None,
        metadata,
    )


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0029File:
    """The migration ships as version 29, right after 0028, and is applied once."""

    def test_migration_0029_file_is_the_only_version_29_after_versions_1_to_28(self) -> None:
        shipped = [
            (int(m.group(1)), path.name)
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name))
        ]

        assert [name for version, name in shipped if version == _VERSION] == [_MIGRATION_NAME]
        assert sorted(version for version, _ in shipped if version < _VERSION) == list(
            range(1, _VERSION)
        )

    async def test_migration_0029_run_migrations_applies_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0028 applied, run_migrations executes the file and records 29."""
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

    async def test_migration_0029_runs_after_0028(self, mock_pool: MagicMock) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0029_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0029_opens_with_a_header_comment_naming_the_column(self) -> None:
        """Why the column exists and what it holds, before any statement."""
        lines = _header_lines()

        assert len(lines) >= 3
        assert _COLUMN in " ".join(lines)

    def test_migration_0029_header_comment_names_the_metadata_check_replacement(self) -> None:
        """Amendment A1: the header explains why audit_events_metadata_check is replaced."""
        assert _METADATA_CHECK in " ".join(_header_lines())


# ---------------------------------------------------------------------------
# 2. The included_attachment_ids column
# ---------------------------------------------------------------------------


class TestMigration0029Column:
    """ALTER TABLE chat_messages ADD COLUMN included_attachment_ids UUID[] with its CHECK."""

    def test_migration_0029_adds_only_the_included_attachment_ids_column(self) -> None:
        """One ADD COLUMN on any table: no other column (the metadata CHECK's DROP and ADD
        CONSTRAINT are pinned by TestMigration0029MetadataCheck and the scope tests)."""
        actions = [(table, _ADD_COLUMN_RE.fullmatch(_masked(a))) for table, a in _alter_actions()]

        assert [(table, m.group("name")) for table, m in actions if m] == [(_TABLE, _COLUMN)]

    def test_migration_0029_column_is_a_nullable_uuid_array_without_default(self) -> None:
        """UUID[] (ids only), NULL when the slot held no attachment, no default, no
        identity, no key, nothing the contract doesn't name."""
        column = _added_column()

        assert {
            "type": column.type_name,
            "not null": column.not_null,
            "explicit null": column.explicit_null,
            "primary key": column.primary_key,
            "identity": column.identity,
            "default": _canonical_default(column),
            "uniques": column.uniques,
            "references": column.references,
            "unexpected": column.unexpected,
        } == {
            "type": "uuid[]",
            "not null": False,
            "explicit null": False,
            "primary key": False,
            "identity": None,
            "default": None,
            "uniques": [],
            "references": [],
            "unexpected": [],
        }

    def test_migration_0029_has_exactly_one_check_with_the_contract_name(self) -> None:
        assert [name for name, _ in _added_column().checks] == [_CHECK_NAME]

    def test_migration_0029_check_means_null_or_a_one_dimensional_id_list_on_an_assistant_row(
        self,
    ) -> None:
        """NULL, or: role 'assistant', one dimension, at least one element, no NULL in it."""
        checks = _added_column().checks
        assert len(checks) == 1, checks

        assert _meaning(checks[0][1]) == frozenset(
            frozenset(_expr(text) for text in alternative)
            for alternative in (_NULL_ALTERNATIVE, _IDS_ALTERNATIVE)
        )


# ---------------------------------------------------------------------------
# 3. The audit metadata CHECK (Amendment A1, security audit F1)
# ---------------------------------------------------------------------------


class TestMigration0029MetadataCheck:
    """audit_events_metadata_check is replaced so a tool.call row can carry its ids."""

    def test_migration_0029_metadata_check_is_dropped_then_re_added_under_its_name(
        self,
    ) -> None:
        """A plain DROP (no IF EXISTS, no CASCADE), then one ADD of the same name on
        audit_events, with nothing after the expression (no NOT VALID)."""
        steps = [(table, kind) for table, kind, _ in _metadata_check_steps()]

        assert steps == [(_AUDIT_TABLE, "drop"), (_AUDIT_TABLE, "add")]

    def test_migration_0029_metadata_check_caps_the_metadata_at_8192_bytes(self) -> None:
        """octet_length(metadata::text) <= 8192, and no other size condition."""
        then = _then_conditions(_check_meaning(_new_metadata_check()))
        sizes = [c for c in then if isinstance(c, str) and c.startswith("octet_length(")]

        assert sizes == [_check_meaning(_SIZE_CAP)]

    def test_migration_0029_metadata_check_allows_1_to_100_uuids_under_attachment_ids_only(
        self,
    ) -> None:
        """attachment_ids, when present, is an array of 1 to 100 canonical lowercase UUID
        strings, and it is the only key the scalar rule exempts."""
        then = _then_conditions(_check_meaning(_new_metadata_check()))

        assert {
            "attachment_ids rule": _check_meaning(_ATTACHMENT_IDS_RULE) in then,
            "scalar rule exempts attachment_ids only": _check_meaning(_SCALAR_VALUES) in then,
        } == {"attachment_ids rule": True, "scalar rule exempts attachment_ids only": True}

    def test_migration_0029_metadata_check_keeps_every_other_rule_of_0005(self) -> None:
        """0005's object test, ELSE false, 16 keys and key regex stay as they were; only
        the size cap and the value rule (now for every key but attachment_ids) change,
        and the attachment_ids rule is added."""
        old = _check_meaning(_old_metadata_check())
        new = _check_meaning(_new_metadata_check())
        old_then = _then_conditions(old)
        replaced = {_check_meaning(_OLD_SIZE_CAP), _check_meaning(_OLD_SCALAR_VALUES)}
        kept = {_check_meaning(_KEY_COUNT), _check_meaning(_KEY_NAMES)}
        added = {
            _check_meaning(_SIZE_CAP),
            _check_meaning(_SCALAR_VALUES),
            _check_meaning(_ATTACHMENT_IDS_RULE),
        }

        assert old_then == replaced | kept
        assert _then_conditions(new) == kept | added
        assert (new[0], new[1], new[3]) == (old[0], old[1], old[3])

    def test_migration_0029_metadata_check_means_the_contract_check(self) -> None:
        """Nothing more and nothing less than Amendment A1's verified CHECK."""
        assert _check_meaning(_new_metadata_check()) == _check_meaning(_CONTRACT_METADATA_CHECK)


# ---------------------------------------------------------------------------
# 4. Privileges
# ---------------------------------------------------------------------------


class TestMigration0029Privileges:
    """No grant changes: chat_messages stays SELECT, INSERT for the app."""

    def test_migration_0029_changes_no_privilege_of_any_table_or_role(self) -> None:
        assert _acl(_VERSION) == _acl(_VERSION - 1)

    def test_migration_0029_chat_messages_stays_select_insert_for_admino_app(self) -> None:
        acl = _acl(_VERSION)

        assert {
            _ROLE: acl.get((_TABLE, _ROLE), frozenset()),
            "public": acl.get((_TABLE, "public"), frozenset()),
        } == {_ROLE: frozenset({"select", "insert"}), "public": frozenset()}


# ---------------------------------------------------------------------------
# 5. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0029Scope:
    """Only the column with its CHECK, and the audit metadata CHECK's replacement."""

    def test_migration_0029_runs_the_column_alter_and_the_metadata_check_statements_only(
        self,
    ) -> None:
        """One ALTER TABLE chat_messages; every other statement drops or adds a
        constraint on audit_events (which ones: the next test)."""
        kinds = [
            next((kind for kind, p in _ALLOWED_STATEMENTS.items() if p.fullmatch(_masked(s))), s)
            for s in _statements()
        ]

        assert (sorted(set(kinds)), kinds.count("column")) == (["column", "metadata check"], 1)

    def test_migration_0029_alters_only_the_column_and_the_metadata_check(self) -> None:
        """Every ALTER TABLE action, in order: the column, then the metadata CHECK's DROP
        and ADD. No other audit_events change (no column, other constraint, trigger or
        owner), and the action catalog (audit_events_action_check) isn't named."""
        kinds = [_action_kind(table, action) for table, action in _alter_actions()]

        assert kinds == [
            (_TABLE, f"add column {_COLUMN}"),
            (_AUDIT_TABLE, f"drop {_METADATA_CHECK}"),
            (_AUDIT_TABLE, f"add {_METADATA_CHECK}"),
        ]
        assert _ACTION_CHECK not in _normalize(_raw_sql())

    def test_migration_0029_runs_no_grant_code_or_data_write(self) -> None:
        """No GRANT / REVOKE, DO block, function, trigger, role, INSERT / UPDATE / DELETE /
        TRUNCATE / COPY / MERGE, CREATE, DROP or default privileges, also not nested in a
        body or an EXECUTE literal."""
        fragments = _fragments(_normalize(_raw_sql()))
        offenders = [
            (kind, fragment)
            for fragment in fragments
            for kind, pattern in _FORBIDDEN.items()
            if re.match(pattern, _masked(fragment))
        ]

        assert fragments, f"{_MIGRATION_NAME} runs nothing"
        assert offenders == []


# ---------------------------------------------------------------------------
# 6. tests/db_fakes.py mirrors 0029
# ---------------------------------------------------------------------------


class TestMigration0029FakeDb:
    """The FakeDb holds what 0029 ships (contract C14)."""

    async def test_migration_0029_fake_stores_the_ids_of_an_assistant_message_in_order(
        self,
    ) -> None:
        column = _shipped_column()
        db = FakeDb()
        chat = _chat(db)

        await _insert(db, chat, "assistant", [_FIRST, _SECOND])

        stored = db.messages_of(chat)[-1][column]
        assert stored == [_FIRST, _SECOND]
        assert [type(item) for item in stored] == [uuid.UUID, uuid.UUID]

    async def test_migration_0029_fake_null_and_todays_insert_store_null(self) -> None:
        """S8' with NULL, and S8 (no column named): the column is NULL."""
        column = _shipped_column()
        db = FakeDb()
        chat = _chat(db)

        await _insert(db, chat, "assistant", None)
        await db.pool.fetchval(
            _INSERT_TODAY, chat, ORG_ID, "user", "Hi", None, None, None, "complete"
        )

        assert [row[column] for row in db.messages_of(chat)] == [None, None]

    @pytest.mark.parametrize(
        ("role", "ids"),
        [
            pytest.param("assistant", [], id="empty-array"),
            pytest.param("assistant", [None], id="array-of-null"),
            pytest.param("assistant", [_FIRST, None], id="id-and-null"),
            pytest.param("assistant", [[_FIRST], [_SECOND]], id="two-dimensional"),
            pytest.param("user", [_FIRST], id="user-row"),
            pytest.param("tool", [_FIRST], id="tool-row"),
        ],
    )
    async def test_migration_0029_fake_check_refuses_what_the_shipped_check_refuses(
        self, role: str, ids: Any
    ) -> None:
        """CheckViolationError on the shipped CHECK's name; nothing is stored."""
        name = _check_name()
        db = FakeDb()
        chat = _chat(db)
        before = db.messages_of(chat)

        with pytest.raises(asyncpg.CheckViolationError) as caught:
            await _insert(db, chat, role, ids)

        assert caught.value.constraint_name == name
        assert db.messages_of(chat) == before

    async def test_migration_0029_fake_seed_helper_applies_the_same_check(self) -> None:
        """add_chat_message(..., included_attachment_ids=) stores ids on an assistant row
        and refuses them on a user row with the shipped CHECK's name."""
        name = _check_name()
        db = FakeDb()
        chat = _chat(db)

        db.add_chat_message(chat, "assistant", "Answer", included_attachment_ids=[_SECOND])  # type: ignore[call-arg]
        with pytest.raises(asyncpg.CheckViolationError) as caught:
            db.add_chat_message(chat, "user", "Hi", included_attachment_ids=[_SECOND])  # type: ignore[call-arg]

        assert [row[_COLUMN] for row in db.messages_of(chat)] == [[_SECOND]]
        assert caught.value.constraint_name == name

    def test_migration_0029_fake_columns_are_0024s_then_the_added_one(self) -> None:
        """ADD COLUMN appends: the fake's chat_messages row has 0024's columns in order,
        then included_attachment_ids (NULL by default)."""
        added = [name for table, name, _ in _added_columns() if table == _TABLE]
        db = FakeDb()
        chat = _chat(db)
        db.add_chat_message(chat, "user", "Hi")
        row = db.messages_of(chat)[0]

        assert added == [_COLUMN]
        assert list(row) == [*(name for name, _ in _table_0024(_TABLE).columns), *added]
        assert row[_COLUMN] is None

    @pytest.mark.parametrize("metadata", _ACCEPTED_METADATA)
    async def test_migration_0029_fake_audit_insert_stores_what_the_shipped_metadata_check_accepts(
        self, metadata: str
    ) -> None:
        """Amendment A1: the contract's verified accepted rows, and exactly 8192 bytes."""
        _metadata_check_name()
        db = _audit_db()

        await _insert_audit(db, metadata)

        assert [row["metadata"] for row in db.audit] == [json.loads(metadata)]

    @pytest.mark.parametrize("metadata", _REFUSED_METADATA)
    async def test_migration_0029_fake_audit_insert_refuses_what_the_shipped_metadata_check_refuses(
        self, metadata: str
    ) -> None:
        """CheckViolationError on the shipped constraint's name; nothing is stored."""
        name = _metadata_check_name()
        db = _audit_db()

        with pytest.raises(asyncpg.CheckViolationError) as caught:
            await _insert_audit(db, metadata)

        assert caught.value.constraint_name == name
        assert db.audit == []
