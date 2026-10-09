"""Tests for migration 0024_chats.sql — GH-176's persisted, tenant-scoped chats.

There is no real PostgreSQL in the suite, so the shipped SQL file itself is the
spec (the test_migration_0017.py / 0023 pattern): it must exist, be applied by
run_migrations as version 24 (after 0023), and create the tables, keys, CHECKs,
indexes and grants GH-176 needs. Since GH-266 these tests pin that structure
only, not the file's wording (no header, "nothing else" or statement-order text
scans: a reviewer note on PR #261). The SQL is read with ``--`` and ``/* */`` comments blanked;
statements are split outside parentheses and literals; keywords are compared
case-insensitively with whitespace collapsed, while string literals are kept
byte for byte (the two regexes and the IN lists are compared exactly). A CHECK
may be inline on its column or a table constraint; a default may carry a
``::text`` cast.

What these tests pin down (contract section 1):
- ``CREATE TABLE chats``: ``id UUID PRIMARY KEY DEFAULT gen_random_uuid()``,
  ``org_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE``,
  ``owner_user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE``,
  ``title TEXT NOT NULL DEFAULT ''`` (``chats_title_check``:
  ``char_length(title) <= 200``), ``title_source TEXT NOT NULL DEFAULT 'auto'``
  (``chats_title_source_check``: auto / user), ``legacy_session_id TEXT``
  (``chats_legacy_session_id_check``: NULL or ``~ '^[a-zA-Z0-9_-]{1,64}$'``),
  ``external_content BOOLEAN NOT NULL DEFAULT false``, ``created_at`` /
  ``last_activity_at TIMESTAMPTZ NOT NULL DEFAULT now()``, ``deleted_at
  TIMESTAMPTZ`` (NULL: live), and ``CONSTRAINT chats_id_org_key UNIQUE (id,
  org_id)`` (the target of the messages' composite foreign key).
- ``CREATE TABLE chat_messages``: ``id UUID PRIMARY KEY DEFAULT
  gen_random_uuid()``, ``seq BIGINT GENERATED ALWAYS AS IDENTITY CONSTRAINT
  chat_messages_seq_key UNIQUE``, ``chat_id UUID NOT NULL``, ``org_id UUID NOT
  NULL REFERENCES organizations (id) ON DELETE CASCADE``, ``role TEXT NOT
  NULL`` (user / assistant / tool: never ``system``), ``content TEXT NOT
  NULL`` (``char_length(content) <= 65536``), ``tool_use_blocks JSONB`` (NULL
  or a JSON array), ``tool_call_id TEXT`` (NULL or ``~
  '^[a-zA-Z0-9_-]{1,128}$'``), ``tool_calls JSONB`` (NULL or an array of at
  most 50), ``status TEXT NOT NULL DEFAULT 'complete'`` (the five message
  statuses), ``created_at TIMESTAMPTZ NOT NULL DEFAULT now()`` and ``CONSTRAINT
  chat_messages_chat_fkey FOREIGN KEY (chat_id, org_id) REFERENCES chats (id,
  org_id) ON DELETE CASCADE``. Every CHECK is named as in the contract.
- The three indexes: ``chats_owner_activity_idx`` on (org_id, owner_user_id,
  last_activity_at DESC, id DESC) WHERE deleted_at IS NULL; the UNIQUE
  ``chats_legacy_session_key`` on (owner_user_id, legacy_session_id) WHERE
  legacy_session_id IS NOT NULL AND deleted_at IS NULL; ``chat_messages_chat_seq_idx``
  on (chat_id, seq DESC). No other index.
- Grants: exactly ``SELECT, INSERT, UPDATE ON chats`` and ``SELECT, INSERT ON
  chat_messages`` to admino_app (no DELETE: trash is ``deleted_at``;
  chat_messages is append-only), no grant option, no other grantee. Migration
  0025 (GH-266, tests/test_migration_0025.py) narrows the UPDATE on chats to
  the five columns the application writes; migration 0031 (GH-194,
  tests/test_migration_0031.py) grants DELETE on chats for the trash purge.
- The SQL bounds equal the Python ones (contract section 6): the title bound
  is ``ChatSummary.title``'s, the content bound ``ChatMessageView.content``'s
  and ``LLMMessage.content``'s, the tool_calls bound ``ChatMessageView.tool_calls``'s,
  the status set ``models.MessageStatus``, the role and title_source sets the
  models' literals, the legacy regex accepts and refuses what
  ``ChatRequest.session_id`` does and the tool_call_id regex what
  ``LLMMessage.tool_call_id`` does; tests/db_fakes.py mirrors the shipped
  bounds.

Security notes:
- Owner and org are NOT NULL without a default: every row names whose it is.
- The composite foreign key (chat_id, org_id) -> chats (id, org_id) makes a
  message whose org differs from its chat's impossible, so an org-scoped read of
  chat_messages can never surface another org's chat.
- Every foreign key cascades: deleting a user or the org purge removes the
  chats and their messages (tests/test_schema_foreign_keys.py).
- 0024 gives the runtime role no DELETE on chats and no UPDATE / DELETE on
  messages: the stored conversation can only grow, and trash is a timestamp
  (GH-194: 0031's DELETE on chats removes a chat's messages only by the cascade,
  which runs as the table owner).
- No ``system`` role: system prompts and org/personal instructions are never
  persisted.
"""

from __future__ import annotations

import re
import typing
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest
from pydantic import BaseModel, ValidationError

import admino.database as db_mod
import admino.models as models_module
from tests import db_fakes

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME = "0024_chats.sql"
_PREVIOUS_MIGRATION = "0023_org_settings_policies.sql"
_VERSION = 24
_CHATS = "chats"
_MESSAGES = "chat_messages"
_TABLES = (_CHATS, _MESSAGES)
_ROLE = "admino_app"


@dataclass(frozen=True)
class _Spec:
    """One contract column: canonical type, NOT NULL (explicit or implied), default."""

    type_name: str
    required: bool
    default: str | None


# table -> column -> spec, in the contract's column order.
_COLUMNS: dict[str, dict[str, _Spec]] = {
    _CHATS: {
        "id": _Spec("uuid", True, "gen_random_uuid()"),
        "org_id": _Spec("uuid", True, None),
        "owner_user_id": _Spec("uuid", True, None),
        "title": _Spec("text", True, "''"),
        "title_source": _Spec("text", True, "'auto'"),
        "legacy_session_id": _Spec("text", False, None),
        "external_content": _Spec("boolean", True, "false"),
        "created_at": _Spec("timestamptz", True, "now()"),
        "last_activity_at": _Spec("timestamptz", True, "now()"),
        "deleted_at": _Spec("timestamptz", False, None),
    },
    _MESSAGES: {
        "id": _Spec("uuid", True, "gen_random_uuid()"),
        "seq": _Spec("bigint", True, None),
        "chat_id": _Spec("uuid", True, None),
        "org_id": _Spec("uuid", True, None),
        "role": _Spec("text", True, None),
        "content": _Spec("text", True, None),
        "tool_use_blocks": _Spec("jsonb", False, None),
        "tool_call_id": _Spec("text", False, None),
        "tool_calls": _Spec("jsonb", False, None),
        "status": _Spec("text", True, "'complete'"),
        "created_at": _Spec("timestamptz", True, "now()"),
    },
}
_ALL_COLUMNS: tuple[tuple[str, str], ...] = tuple(
    (table, column) for table, columns in _COLUMNS.items() for column in columns
)

# table -> constraint name -> the one column it checks.
_CHECKS: dict[str, dict[str, str]] = {
    _CHATS: {
        "chats_title_check": "title",
        "chats_title_source_check": "title_source",
        "chats_legacy_session_id_check": "legacy_session_id",
    },
    _MESSAGES: {
        "chat_messages_role_check": "role",
        "chat_messages_content_check": "content",
        "chat_messages_tool_use_blocks_check": "tool_use_blocks",
        "chat_messages_tool_call_id_check": "tool_call_id",
        "chat_messages_tool_calls_check": "tool_calls",
        "chat_messages_status_check": "status",
    },
}
_ALL_CHECKS: tuple[tuple[str, str, str], ...] = tuple(
    (table, name, column) for table, checks in _CHECKS.items() for name, column in checks.items()
)

_TITLE_MAX = 200
_CONTENT_MAX = 65536
_TOOL_CALLS_MAX = 50
_TITLE_SOURCES = frozenset({"auto", "user"})
_ROLES = frozenset({"user", "assistant", "tool"})
_STATUSES = frozenset({"complete", "stopped", "error", "awaiting_confirmation", "limit_reached"})
_LEGACY_REGEX = "^[a-zA-Z0-9_-]{1,64}$"
_TOOL_CALL_ID_REGEX = "^[a-zA-Z0-9_-]{1,128}$"

# (columns, referenced table, referenced columns, on delete) per table.
_FOREIGN_KEYS: dict[str, frozenset[tuple[tuple[str, ...], str, tuple[str, ...], str]]] = {
    _CHATS: frozenset(
        {
            (("org_id",), "organizations", ("id",), "cascade"),
            (("owner_user_id",), "users", ("id",), "cascade"),
        }
    ),
    _MESSAGES: frozenset(
        {
            (("org_id",), "organizations", ("id",), "cascade"),
            (("chat_id", "org_id"), _CHATS, ("id", "org_id"), "cascade"),
        }
    ),
}
_COMPOSITE_FK_NAME = "chat_messages_chat_fkey"

# name -> (unique, table, columns, WHERE atoms)
_INDEXES: dict[str, tuple[bool, str, tuple[str, ...], frozenset[str]]] = {
    "chats_owner_activity_idx": (
        False,
        _CHATS,
        ("org_id", "owner_user_id", "last_activity_at desc", "id desc"),
        frozenset({"deleted_at is null"}),
    ),
    "chats_legacy_session_key": (
        True,
        _CHATS,
        ("owner_user_id", "legacy_session_id"),
        frozenset({"legacy_session_id is not null", "deleted_at is null"}),
    ),
    "chat_messages_chat_seq_idx": (False, _MESSAGES, ("chat_id", "seq desc"), frozenset()),
}

_GRANTS: dict[str, frozenset[str]] = {
    _CHATS: frozenset({"select", "insert", "update"}),
    _MESSAGES: frozenset({"select", "insert"}),
}

_TYPE_CANON: dict[str, str] = {
    "uuid": "uuid",
    "text": "text",
    "bool": "boolean",
    "boolean": "boolean",
    "timestamptz": "timestamptz",
    "timestamp with time zone": "timestamptz",
    "bigint": "bigint",
    "int8": "bigint",
    "jsonb": "jsonb",
}
_DEFAULT_CANON: dict[str, str] = {
    "current_timestamp": "now()",
    "transaction_timestamp()": "now()",
}
_CHAR_LENGTH = r"(?:char_length|character_length)"
_ON_ACTION = r"(?:cascade|restrict|no\s+action|set\s+null|set\s+default)"

# Characters built with chr() so they survive editing tools verbatim.
_NEWLINE = chr(0x0A)
_TAB = chr(0x09)
_NUL = chr(0x00)
_E_ACUTE = chr(0x00E9)
_NBSP = chr(0x00A0)

# Session ids for the legacy regex: (sample, accepted by ChatRequest.session_id).
_SESSION_SAMPLES: tuple[tuple[str, bool], ...] = (
    ("a", True),
    ("sess-1", True),
    ("Mixed_Case-09", True),
    ("-", True),
    ("_", True),
    ("a" * 64, True),
    ("a" * 65, False),
    ("", False),
    ("has space", False),
    ("sess" + _NEWLINE, False),
    (_NEWLINE + "sess", False),
    ("sess" + _TAB, False),
    ("sess" + _NUL, False),
    ("sess.1", False),
    ("sess/1", False),
    ("sess'1", False),
    ("caf" + _E_ACUTE, False),
    ("sess" + _NBSP, False),
)
# Tool call ids for the tool_call_id regex: (sample, accepted by LLMMessage.tool_call_id).
_TOOL_CALL_ID_SAMPLES: tuple[tuple[str, bool], ...] = (
    ("t", True),
    ("toolu_01ABC-xyz", True),
    ("call_" + "a" * 123, True),
    ("a" * 129, False),
    ("", False),
    ("call 1", False),
    ("call" + _NEWLINE, False),
    ("call.1", False),
    ("call:1", False),
    ("call" + _NUL, False),
)

_UUID = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
_TIMESTAMP = "2026-10-05T09:30:00+00:00"


# ---------------------------------------------------------------------------
# Helpers: reading and quote-aware parsing of the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    return _migration_path().read_text(encoding="utf-8")


def _normalized() -> str:
    """The shipped migration, normalized outside literals only.

    ``--`` and ``/* */`` comments are blanked, whitespace is collapsed and
    keywords are lowercased; the contents of '...' and "..." are kept byte for
    byte.
    """
    raw = _raw_sql()
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
    return _split(_normalized(), ";")


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    while (
        expression.startswith("(") and _balanced_end(_masked(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _names(text: str) -> tuple[str, ...]:
    return tuple(name.strip().strip('"') for name in text.split(",") if name.strip())


def _and_atoms(expression: str) -> list[str]:
    """The top-level AND-ed conditions of an expression, each unwrapped and collapsed."""
    expression = _unwrap(expression)
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
            atoms.append(_collapse(_unwrap(expression[start : token.start()])))
            start = token.end()
    atoms.append(_collapse(_unwrap(expression[start:])))
    return atoms


@dataclass(frozen=True)
class _Reference:
    """One foreign key: inline on a column or a table constraint."""

    name: str | None
    columns: tuple[str, ...]
    table: str
    referenced_columns: tuple[str, ...]
    on_delete: str

    def shape(self) -> tuple[tuple[str, ...], str, tuple[str, ...], str]:
        return self.columns, self.table, self.referenced_columns, self.on_delete


@dataclass
class _Column:
    """One parsed column definition of a CREATE TABLE."""

    type_name: str
    not_null: bool = False
    explicit_null: bool = False
    primary_key: bool = False
    identity: str | None = None
    defaults: list[str] = field(default_factory=list)
    checks: list[tuple[str | None, str]] = field(default_factory=list)
    uniques: list[str | None] = field(default_factory=list)
    references: list[_Reference] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)


@dataclass
class _Table:
    """A parsed CREATE TABLE: columns (by name, a repeated name kept twice) and constraints."""

    columns: list[tuple[str, _Column]] = field(default_factory=list)
    checks: list[tuple[str | None, str]] = field(default_factory=list)
    uniques: list[tuple[str | None, tuple[str, ...]]] = field(default_factory=list)
    primary_keys: list[tuple[str, ...]] = field(default_factory=list)
    foreign_keys: list[_Reference] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)


def _on_delete(clause: str) -> str:
    match = re.search(rf"\bon\s+delete\s+({_ON_ACTION})", clause)
    return _collapse(match.group(1)) if match else "no action"


def _parse_reference(
    masked: str, name: str | None, columns: tuple[str, ...]
) -> tuple[_Reference, int] | None:
    """A ``REFERENCES t [(cols)] [ON DELETE x] [ON UPDATE y]`` at the start of masked."""
    match = re.match(
        rf"references\s+(?:public\.)?(\w+)\s*(?:\(([^)]*)\)\s*)?"
        rf"((?:on\s+(?:delete|update)\s+{_ON_ACTION}\s*)*)",
        masked,
    )
    if match is None:
        return None
    referenced = _names(match.group(2)) if match.group(2) else ("id",)
    reference = _Reference(name, columns, match.group(1), referenced, _on_delete(match.group(3)))
    return reference, match.end()


def _parse_column(name: str, definition: str) -> _Column:
    """Parse the part after the column name: a type, then NOT NULL / NULL / PRIMARY KEY /
    GENERATED ... AS IDENTITY / DEFAULT / [CONSTRAINT n] CHECK / UNIQUE / REFERENCES in
    any order; anything else is unexpected."""
    masked = _masked(definition)
    type_match = re.match(
        r"(timestamp\s+with\s+time\s+zone|\w+(?:\s*\(\s*\d+\s*\))?)\s*",
        masked,
    )
    assert type_match is not None, f"no column type in {definition!r}"
    column = _Column(type_name=_collapse(type_match.group(1)))
    position = type_match.end()
    while position < len(masked):
        rest = masked[position:]
        constraint = re.match(r"constraint\s+(\w+)\s+", rest)
        constraint_name = constraint.group(1) if constraint else None
        body_start = position + (constraint.end() if constraint else 0)
        body = masked[body_start:]
        if constraint is None and (step := re.match(r"not\s+null\b\s*", rest)):
            column.not_null = True
            position += step.end()
        elif constraint is None and (step := re.match(r"null\b\s*", rest)):
            column.explicit_null = True
            position += step.end()
        elif constraint is None and (step := re.match(r"primary\s+key\b\s*", rest)):
            column.primary_key = True
            position += step.end()
        elif constraint is None and (
            step := re.match(r"generated\s+(always|by\s+default)\s+as\s+identity\b\s*", rest)
        ):
            column.identity = _collapse(step.group(1))
            position += step.end()
        elif constraint is None and (
            step := re.match(
                r"default\s+('[^']*'(?:\s*::\s*\w+)?|\w+\s*\(\s*\)|-?\w+)\s*",
                rest,
            )
        ):
            column.defaults.append(definition[position + step.start(1) : position + step.end(1)])
            position += step.end()
        elif step := re.match(r"check\s*\(", body):
            open_index = body_start + step.end() - 1
            end = _balanced_end(masked, open_index)
            column.checks.append((constraint_name, definition[open_index + 1 : end]))
            position = end + 1
            while position < len(masked) and masked[position] == " ":
                position += 1
        elif step := re.match(r"unique\b\s*", body):
            column.uniques.append(constraint_name)
            position = body_start + step.end()
        elif (parsed := _parse_reference(body, constraint_name, (name,))) is not None:
            column.references.append(parsed[0])
            position = body_start + parsed[1]
        else:
            column.unexpected.append(definition[position:])
            break
    return column


def _parse_table_constraint(table: _Table, element: str) -> None:
    masked = _masked(element)
    constraint = re.match(r"constraint\s+(\w+)\s+", masked)
    name = constraint.group(1) if constraint else None
    start = constraint.end() if constraint else 0
    body = masked[start:]
    if match := re.fullmatch(r"check\s*\((.*)\)", body):
        table.checks.append((name, element[start + match.start(1) : start + match.end(1)]))
    elif match := re.fullmatch(r"unique\s*\(([^)]*)\)", body):
        table.uniques.append((name, _names(match.group(1))))
    elif match := re.fullmatch(r"primary\s+key\s*\(([^)]*)\)", body):
        table.primary_keys.append(_names(match.group(1)))
    elif match := re.match(r"foreign\s+key\s*\(([^)]*)\)\s*", body):
        parsed = _parse_reference(body[match.end() :], name, _names(match.group(1)))
        if parsed is None or body[match.end() + parsed[1] :].strip():
            table.unexpected.append(element)
        else:
            table.foreign_keys.append(parsed[0])
    else:
        table.unexpected.append(element)


_CONSTRAINT_START = (
    r"(?:constraint\s+\w+\s+)?(?:check|unique|primary\s+key|foreign\s+key|exclude)\b"
)


def _create_table_body(table: str) -> str:
    for statement in _statements():
        masked = _masked(statement)
        match = re.match(rf"create\s+table\s+{table}\s*\(", masked)
        if match is None:
            continue
        end = _balanced_end(masked, match.end() - 1)
        assert masked[end + 1 :].strip() == "", statement
        return statement[match.end() : end]
    pytest.fail(f"no CREATE TABLE {table} (...) in {_MIGRATION_NAME}")


def _table(name: str) -> _Table:
    table = _Table()
    for element in _split(_create_table_body(name), ","):
        if re.match(_CONSTRAINT_START, _masked(element)):
            _parse_table_constraint(table, element)
            continue
        match = re.fullmatch(r'"?(\w+)"?\s+(.*)', element)
        assert match is not None, element
        column_name = match.group(1)
        table.columns.append((column_name, _parse_column(column_name, match.group(2))))
    return table


def _column(table: str, name: str) -> _Column:
    found = [column for column_name, column in _table(table).columns if column_name == name]
    assert len(found) == 1, f"{table}.{name} must be defined exactly once: {found}"
    return found[0]


def _all_checks(table: str) -> list[tuple[str | None, str]]:
    """Every CHECK of a table: inline on a column or a table constraint."""
    parsed = _table(table)
    checks = list(parsed.checks)
    for _, column in parsed.columns:
        checks.extend(column.checks)
    return checks


def _check(table: str, name: str) -> str:
    found = [expression for check_name, expression in _all_checks(table) if check_name == name]
    assert len(found) == 1, f"{name} must be defined exactly once on {table}: {found}"
    return _collapse(_unwrap(found[0]))


def _all_foreign_keys(table: str) -> list[_Reference]:
    parsed = _table(table)
    references = list(parsed.foreign_keys)
    for _, column in parsed.columns:
        references.extend(column.references)
    return references


def _all_uniques(table: str) -> list[tuple[str | None, tuple[str, ...]]]:
    parsed = _table(table)
    uniques = list(parsed.uniques)
    for name, column in parsed.columns:
        uniques.extend((constraint, (name,)) for constraint in column.uniques)
    return uniques


def _primary_key(table: str) -> list[tuple[str, ...]]:
    parsed = _table(table)
    keys = list(parsed.primary_keys)
    keys.extend((name,) for name, column in parsed.columns if column.primary_key)
    return keys


def _canonical_default(column: _Column) -> str | None:
    assert len(column.defaults) <= 1, column.defaults
    if not column.defaults:
        return None
    text = re.sub(r"\s+", "", column.defaults[0])
    text = re.sub(r"::\w+$", "", text)
    return _DEFAULT_CANON.get(text, text)


def _null_or(column: str, expression: str) -> str:
    """The condition behind ``<column> IS NULL OR``, which must lead the expression."""
    match = re.fullmatch(rf"{column}\s+is\s+null\s+or\s+(.*)", _collapse(_unwrap(expression)))
    assert match is not None, f"{column} CHECK must start with '{column} IS NULL OR': {expression}"
    return _collapse(_unwrap(match.group(1)))


def _in_values(column: str, expression: str) -> list[str]:
    """The literals of ``<column> IN (...)``, which must be the whole expression."""
    match = re.fullmatch(rf"{column}\s+in\s*\(([^)]*)\)", _collapse(_unwrap(expression)))
    assert match is not None, f"{column} CHECK must be '{column} IN (...)': {expression}"
    return re.findall(r"'([^']*)'", match.group(1))


def _char_length_max(column: str, expression: str) -> int:
    """The N of ``char_length(<column>) <= N``, which must be the whole expression."""
    match = re.fullmatch(
        rf"{_CHAR_LENGTH}\s*\(\s*{column}\s*\)\s*<=\s*(\d+)", _collapse(_unwrap(expression))
    )
    assert match is not None, f"{column} CHECK must be 'char_length({column}) <= N': {expression}"
    return int(match.group(1))


def _regex_literal(column: str, condition: str) -> str:
    """The literal of ``<column> ~ '<regex>'`` (case-sensitive ``~`` only)."""
    match = re.fullmatch(rf"{column}\s*~\s*'((?:[^']|'')*)'", condition)
    assert match is not None, f"{column} CHECK must be '{column} ~ <regex>': {condition}"
    return match.group(1).replace("''", "'")


def _legacy_regex() -> str:
    return _regex_literal(
        "legacy_session_id",
        _null_or("legacy_session_id", _check(_CHATS, "chats_legacy_session_id_check")),
    )


def _tool_call_id_regex() -> str:
    return _regex_literal(
        "tool_call_id",
        _null_or("tool_call_id", _check(_MESSAGES, "chat_messages_tool_call_id_check")),
    )


def _tool_calls_max() -> int:
    """The N of ``jsonb_array_length(tool_calls) <= N`` in the tool_calls CHECK."""
    atoms = _and_atoms(_null_or("tool_calls", _check(_MESSAGES, "chat_messages_tool_calls_check")))
    limits = [
        int(match.group(1))
        for atom in atoms
        if (match := re.fullmatch(r"jsonb_array_length\s*\(\s*tool_calls\s*\)\s*<=\s*(\d+)", atom))
    ]
    assert len(limits) == 1, atoms
    return limits[0]


def _sql_regex_accepts(pattern: str, sample: str) -> bool:
    """Emulate PostgreSQL's CHECK (col ~ '^...$'): '$' matches only at the very end."""
    assert pattern.startswith("^"), pattern
    assert pattern.endswith("$"), pattern
    return re.fullmatch(pattern[1:-1], sample) is not None


@dataclass(frozen=True)
class _Index:
    unique: bool
    name: str
    table: str
    method: str | None
    columns: tuple[str, ...]
    where: frozenset[str]
    unexpected: str


def _parse_index(statement: str) -> _Index | None:
    masked = _masked(statement)
    match = re.match(
        r"create\s+(unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?(\w+)\s+"
        r"on\s+(?:only\s+)?(\w+)\s*(?:using\s+(\w+)\s*)?\(",
        masked,
    )
    if match is None:
        return None
    end = _balanced_end(masked, match.end() - 1)
    columns = tuple(
        re.sub(r"\s+asc$", "", _collapse(item))
        for item in _split(statement[match.end() : end], ",")
    )
    rest = statement[end + 1 :].strip()
    where_match = re.fullmatch(r"where\s+(.*)", _masked(rest))
    where = frozenset(_and_atoms(rest[where_match.start(1) :])) if where_match else frozenset()
    return _Index(
        unique=match.group(1) is not None,
        name=match.group(2),
        table=match.group(3),
        method=match.group(4),
        columns=columns,
        where=where,
        unexpected="" if where_match or not rest else rest,
    )


def _indexes() -> list[_Index]:
    return [index for s in _statements() if (index := _parse_index(s)) is not None]


def _index(name: str) -> _Index:
    found = [index for index in _indexes() if index.name == name]
    assert len(found) == 1, f"index {name} must be created exactly once: {found}"
    return found[0]


@dataclass(frozen=True)
class _Grant:
    privileges: frozenset[str]
    objects: tuple[str, ...]
    grantees: frozenset[str]
    grant_option: bool


def _parse_grant(statement: str) -> _Grant | None:
    match = re.fullmatch(
        r"grant\s+(.+?)\s+on\s+(?:table\s+)?(.+?)\s+to\s+(.+?)(\s+with\s+grant\s+option)?",
        _masked(statement),
    )
    if match is None:
        return None
    return _Grant(
        privileges=frozenset(_collapse(p) for p in _split(match.group(1), ",")),
        objects=tuple(name.split(".")[-1] for name in _names(match.group(2))),
        grantees=frozenset(_names(match.group(3))),
        grant_option=match.group(4) is not None,
    )


def _grants() -> list[_Grant]:
    return [grant for s in _statements() if (grant := _parse_grant(s)) is not None]


def _granted(table: str) -> frozenset[str]:
    """Every privilege the migration grants the app on a table (all GRANTs together)."""
    privileges: set[str] = set()
    for grant in _grants():
        if table in grant.objects and grant.grantees & {_ROLE, "public"}:
            privileges |= grant.privileges
    return frozenset(privileges)


# ---------------------------------------------------------------------------
# Helpers: the Python side
# ---------------------------------------------------------------------------


def _model(name: str) -> type[BaseModel]:
    """A model from admino.models; fails the calling test when missing (GH-176)."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-176)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _accepts(model: type[BaseModel], payload: dict[str, Any]) -> bool:
    try:
        model.model_validate(payload)
    except ValidationError:
        return False
    return True


def _summary_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _UUID,
        "title": "Quarterly report",
        "title_source": "user",
        "created_at": _TIMESTAMP,
        "last_activity_at": _TIMESTAMP,
    }
    payload.update(overrides)
    return payload


def _record_payload() -> dict[str, Any]:
    return {
        "tool": "gmail",
        "action": "read",
        "args": {"message_id": "m1"},
        "permission": "allow",
        "success": True,
    }


def _message_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _UUID,
        "role": "assistant",
        "content": "Done.",
        "status": "complete",
        "created_at": _TIMESTAMP,
    }
    payload.update(overrides)
    return payload


def _literal_values(model: type[BaseModel], field_name: str) -> frozenset[str]:
    return frozenset(typing.get_args(model.model_fields[field_name].annotation))


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0024File:
    """The migration ships as version 24 and is applied by run_migrations after 0023."""

    def test_migration_0024_file_is_shipped_as_version_24(self) -> None:
        assert _migration_path().is_file()
        match = db_mod._MIGRATION_FILE_RE.match(_MIGRATION_NAME)
        assert match is not None
        assert int(match.group(1)) == _VERSION

    def test_migration_0024_is_the_only_version_24(self) -> None:
        twenty_fours = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert twenty_fours == [_MIGRATION_NAME]

    async def test_migration_0024_run_migrations_applies_it_as_version_24(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0023 applied, run_migrations executes the file and records 24."""
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

    async def test_migration_0024_run_migrations_executes_the_shipped_sql(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    async def test_migration_0024_runs_after_0023(self, mock_pool: MagicMock) -> None:
        """With 0001 to 0022 applied, 0023 is executed before 0024."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert shipped in executed
        assert previous in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0024_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0024 recorded, the shipped SQL is not executed a second time."""
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)


# ---------------------------------------------------------------------------
# 2. Columns
# ---------------------------------------------------------------------------


class TestMigration0024Columns:
    """Every column with its type, NOT NULL and default; nothing else on it."""

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0024_table_has_exactly_the_contract_columns(self, table: str) -> None:
        """The contract's columns, in its order (the FakeDb's DETAIL follows that order)."""
        assert [name for name, _ in _table(table).columns] == list(_COLUMNS[table])

    @pytest.mark.parametrize(("table", "column"), _ALL_COLUMNS)
    def test_migration_0024_column_type(self, table: str, column: str) -> None:
        raw = _column(table, column).type_name

        assert _TYPE_CANON.get(raw) == _COLUMNS[table][column].type_name, raw

    @pytest.mark.parametrize(("table", "column"), _ALL_COLUMNS)
    def test_migration_0024_column_nullability(self, table: str, column: str) -> None:
        """NOT NULL (written, or implied by PRIMARY KEY / IDENTITY) exactly where the
        contract says; the nullable columns have no NOT NULL."""
        parsed = _column(table, column)
        required = parsed.not_null or parsed.primary_key or parsed.identity is not None

        assert required is _COLUMNS[table][column].required
        assert parsed.explicit_null is False

    @pytest.mark.parametrize(("table", "column"), _ALL_COLUMNS)
    def test_migration_0024_column_default(self, table: str, column: str) -> None:
        """No implicit owner, org, chat, role or content: those have no default."""
        assert _canonical_default(_column(table, column)) == _COLUMNS[table][column].default

    @pytest.mark.parametrize(("table", "column"), _ALL_COLUMNS)
    def test_migration_0024_column_has_nothing_unexpected(self, table: str, column: str) -> None:
        assert _column(table, column).unexpected == []

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0024_table_has_no_unexpected_constraint(self, table: str) -> None:
        assert _table(table).unexpected == []

    def test_migration_0024_seq_is_a_generated_always_identity(self) -> None:
        """seq orders a chat's messages: the server assigns it and no INSERT can set it."""
        parsed = _column(_MESSAGES, "seq")

        assert parsed.identity == "always"
        assert parsed.defaults == []

    @pytest.mark.parametrize(("table", "column"), [(t, c) for t, c in _ALL_COLUMNS if c != "seq"])
    def test_migration_0024_only_seq_is_an_identity(self, table: str, column: str) -> None:
        assert _column(table, column).identity is None


# ---------------------------------------------------------------------------
# 3. Keys and foreign keys
# ---------------------------------------------------------------------------


class TestMigration0024Keys:
    """Primary keys on id, the two UNIQUE constraints, and four cascading foreign keys."""

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0024_primary_key_is_id(self, table: str) -> None:
        assert _primary_key(table) == [("id",)]

    def test_migration_0024_chats_unique_id_org(self) -> None:
        """chats_id_org_key UNIQUE (id, org_id): the composite foreign key's target."""
        assert _all_uniques(_CHATS) == [("chats_id_org_key", ("id", "org_id"))]

    def test_migration_0024_chat_messages_seq_is_unique(self) -> None:
        assert _all_uniques(_MESSAGES) == [("chat_messages_seq_key", ("seq",))]

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0024_foreign_keys_are_exactly_the_contract(self, table: str) -> None:
        shapes = [reference.shape() for reference in _all_foreign_keys(table)]

        assert len(shapes) == len(_FOREIGN_KEYS[table]), shapes
        assert set(shapes) == _FOREIGN_KEYS[table]

    def test_migration_0024_message_chat_and_org_reference_the_chat_together(self) -> None:
        """(chat_id, org_id) -> chats (id, org_id) ON DELETE CASCADE, named
        chat_messages_chat_fkey: a message can't sit in another org than its chat."""
        composite = [
            reference for reference in _all_foreign_keys(_MESSAGES) if reference.table == _CHATS
        ]

        assert len(composite) == 1, composite
        assert composite[0].name == _COMPOSITE_FK_NAME
        assert composite[0].columns == ("chat_id", "org_id")
        assert composite[0].referenced_columns == ("id", "org_id")
        assert composite[0].on_delete == "cascade"

    def test_migration_0024_chat_id_has_no_reference_of_its_own(self) -> None:
        """chat_id only references chats through the composite key (never chats (id) alone,
        which would let a message name another org's chat)."""
        assert _column(_MESSAGES, "chat_id").references == []

    def test_migration_0024_references_only_organizations_users_and_chats(self) -> None:
        masked = _masked(_normalized())

        assert set(re.findall(r"\breferences\s+(\w+)", masked)) == {
            "organizations",
            "users",
            _CHATS,
        }


# ---------------------------------------------------------------------------
# 4. CHECK constraints
# ---------------------------------------------------------------------------


class TestMigration0024Checks:
    """Every CHECK is named and holds exactly the contract's rule."""

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0024_table_has_exactly_the_named_checks(self, table: str) -> None:
        """No unnamed CHECK and no other one."""
        names = sorted(str(name) for name, _ in _all_checks(table))

        assert names == sorted(_CHECKS[table])

    @pytest.mark.parametrize(("table", "name", "column"), _ALL_CHECKS)
    def test_migration_0024_check_names_only_its_column(
        self, table: str, name: str, column: str
    ) -> None:
        identifiers = set(re.findall(r"\b[a-z_]\w*\b", _masked(_check(table, name))))

        assert identifiers & set(_COLUMNS[table]) == {column}

    def test_migration_0024_title_check_counts_characters_up_to_200(self) -> None:
        """char_length(title) <= 200: characters, not bytes ('' is allowed for #179)."""
        assert _char_length_max("title", _check(_CHATS, "chats_title_check")) == _TITLE_MAX

    def test_migration_0024_title_source_check_is_auto_or_user(self) -> None:
        values = _in_values("title_source", _check(_CHATS, "chats_title_source_check"))

        assert sorted(values) == sorted(_TITLE_SOURCES)

    def test_migration_0024_legacy_session_id_check_is_null_or_the_session_regex(self) -> None:
        """legacy_session_id IS NULL OR legacy_session_id ~ '^[a-zA-Z0-9_-]{1,64}$'."""
        assert _legacy_regex() == _LEGACY_REGEX

    def test_migration_0024_role_check_is_user_assistant_tool(self) -> None:
        """No 'system': system prompts and instructions are never stored."""
        values = _in_values("role", _check(_MESSAGES, "chat_messages_role_check"))

        assert sorted(values) == sorted(_ROLES)
        assert "system" not in values

    def test_migration_0024_content_check_counts_characters_up_to_65536(self) -> None:
        check = _check(_MESSAGES, "chat_messages_content_check")

        assert _char_length_max("content", check) == _CONTENT_MAX

    def test_migration_0024_tool_use_blocks_check_is_null_or_a_json_array(self) -> None:
        condition = _null_or(
            "tool_use_blocks", _check(_MESSAGES, "chat_messages_tool_use_blocks_check")
        )

        assert re.fullmatch(r"jsonb_typeof\s*\(\s*tool_use_blocks\s*\)\s*=\s*'array'", condition)

    def test_migration_0024_tool_call_id_check_is_null_or_the_id_regex(self) -> None:
        """tool_call_id IS NULL OR tool_call_id ~ '^[a-zA-Z0-9_-]{1,128}$'."""
        assert _tool_call_id_regex() == _TOOL_CALL_ID_REGEX

    def test_migration_0024_tool_calls_check_is_null_or_an_array_of_at_most_50(self) -> None:
        """tool_calls IS NULL OR (jsonb_typeof(tool_calls) = 'array' AND
        jsonb_array_length(tool_calls) <= 50)."""
        atoms = _and_atoms(
            _null_or("tool_calls", _check(_MESSAGES, "chat_messages_tool_calls_check"))
        )
        typed = [
            a
            for a in atoms
            if re.fullmatch(r"jsonb_typeof\s*\(\s*tool_calls\s*\)\s*=\s*'array'", a)
        ]

        assert len(atoms) == 2, atoms
        assert len(typed) == 1, atoms
        assert _tool_calls_max() == _TOOL_CALLS_MAX

    def test_migration_0024_status_check_is_the_five_message_statuses(self) -> None:
        values = _in_values("status", _check(_MESSAGES, "chat_messages_status_check"))

        assert sorted(values) == sorted(_STATUSES)

    def test_migration_0024_defaults_satisfy_their_checks(self) -> None:
        """A row written with the defaults passes every CHECK ('' title, 'auto', 'complete')."""
        assert _canonical_default(_column(_CHATS, "title")) == "''"
        assert "auto" in _in_values("title_source", _check(_CHATS, "chats_title_source_check"))
        assert "complete" in _in_values("status", _check(_MESSAGES, "chat_messages_status_check"))

    @pytest.mark.parametrize(
        ("sample", "accepted"), _SESSION_SAMPLES, ids=[repr(s)[:30] for s, _ in _SESSION_SAMPLES]
    )
    def test_migration_0024_legacy_regex_on_samples(self, sample: str, accepted: bool) -> None:
        assert _sql_regex_accepts(_legacy_regex(), sample) is accepted

    @pytest.mark.parametrize(
        ("sample", "accepted"),
        _TOOL_CALL_ID_SAMPLES,
        ids=[repr(s)[:30] for s, _ in _TOOL_CALL_ID_SAMPLES],
    )
    def test_migration_0024_tool_call_id_regex_on_samples(
        self, sample: str, accepted: bool
    ) -> None:
        assert _sql_regex_accepts(_tool_call_id_regex(), sample) is accepted


# ---------------------------------------------------------------------------
# 5. Indexes
# ---------------------------------------------------------------------------


class TestMigration0024Indexes:
    """The chat list index, the legacy session key and the message order index."""

    def test_migration_0024_creates_exactly_the_three_indexes(self) -> None:
        assert sorted(index.name for index in _indexes()) == sorted(_INDEXES)

    @pytest.mark.parametrize("name", sorted(_INDEXES))
    def test_migration_0024_index_matches_the_contract(self, name: str) -> None:
        """Uniqueness, table, columns with their order, and the partial predicate."""
        index = _index(name)
        unique, table, columns, where = _INDEXES[name]

        assert index.unique is unique
        assert index.table == table
        assert index.method in {None, "btree"}
        assert index.columns == columns
        assert index.where == where
        assert index.unexpected == ""

    def test_migration_0024_chat_list_index_skips_trashed_chats(self) -> None:
        """The list of live chats, newest activity first, keyset (last_activity_at, id)."""
        index = _index("chats_owner_activity_idx")

        assert index.columns[:2] == ("org_id", "owner_user_id")
        assert index.where == frozenset({"deleted_at is null"})

    def test_migration_0024_legacy_session_key_is_unique_per_owner_among_live_chats(
        self,
    ) -> None:
        """One live chat per (user, legacy session id); a trashed one frees the id."""
        index = _index("chats_legacy_session_key")

        assert index.unique is True
        assert index.columns == ("owner_user_id", "legacy_session_id")
        assert "deleted_at is null" in index.where
        assert "legacy_session_id is not null" in index.where


# ---------------------------------------------------------------------------
# 6. Grants
# ---------------------------------------------------------------------------


class TestMigration0024Grants:
    """The runtime role gets SELECT, INSERT, UPDATE on chats and SELECT, INSERT on messages."""

    @pytest.mark.parametrize("table", _TABLES)
    def test_migration_0024_grants_exactly_the_contract_privileges(self, table: str) -> None:
        assert _granted(table) == _GRANTS[table]

    def test_migration_0024_chat_messages_are_append_only_for_the_app(self) -> None:
        """No UPDATE or DELETE on chat_messages: the stored conversation can only grow."""
        granted = _granted(_MESSAGES)

        assert granted, "chat_messages gets no grant"
        assert "update" not in granted
        assert "delete" not in granted

    def test_migration_0024_chats_are_never_deleted_by_the_app(self) -> None:
        """Trash is deleted_at: 0024 grants no DELETE on chats. (GH-194: migration 0031
        grants it for delete forever and the retention purge; tests/test_migration_0031.py
        pins the privileges after every shipped migration.)"""
        granted = _granted(_CHATS)

        assert "update" in granted
        assert "delete" not in granted

    def test_migration_0024_grants_only_to_admino_app(self) -> None:
        grants = _grants()

        assert grants
        assert all(grant.grantees == {_ROLE} for grant in grants), grants

    def test_migration_0024_grants_no_grant_option(self) -> None:
        assert not any(grant.grant_option for grant in _grants())

    def test_migration_0024_grants_only_on_the_two_tables(self) -> None:
        objects = {table for grant in _grants() for table in grant.objects}

        assert objects == set(_TABLES)


# ---------------------------------------------------------------------------
# 7. SQL and Python stay in sync
# ---------------------------------------------------------------------------


class TestMigration0024MatchesPython:
    """The CHECK bounds equal the Pydantic bounds of contract section 6 and the FakeDb's."""

    def test_migration_0024_title_bound_matches_chat_summary(self) -> None:
        summary = _model("ChatSummary")
        limit = _char_length_max("title", _check(_CHATS, "chats_title_check"))

        assert _accepts(summary, _summary_payload(title="a" * limit))
        assert not _accepts(summary, _summary_payload(title="a" * (limit + 1)))

    @pytest.mark.parametrize("name", ["ChatCreateRequest", "ChatUpdateRequest"])
    def test_migration_0024_title_bound_matches_the_request_models(self, name: str) -> None:
        """A title the API takes always fits the column."""
        model = _model(name)
        limit = _char_length_max("title", _check(_CHATS, "chats_title_check"))

        assert _accepts(model, {"title": "a" * limit})
        assert not _accepts(model, {"title": "a" * (limit + 1)})

    def test_migration_0024_title_source_matches_chat_summary(self) -> None:
        values = _in_values("title_source", _check(_CHATS, "chats_title_source_check"))

        assert _literal_values(_model("ChatSummary"), "title_source") == frozenset(values)

    def test_migration_0024_content_bound_matches_chat_message_view(self) -> None:
        view = _model("ChatMessageView")
        limit = _char_length_max("content", _check(_MESSAGES, "chat_messages_content_check"))

        assert _accepts(view, _message_payload(content="a" * limit))
        assert not _accepts(view, _message_payload(content="a" * (limit + 1)))

    def test_migration_0024_content_bound_matches_llm_message(self) -> None:
        """Every history message the agent returns fits the column."""
        llm_message = models_module.LLMMessage
        limit = _char_length_max("content", _check(_MESSAGES, "chat_messages_content_check"))

        assert _accepts(llm_message, {"role": "assistant", "content": "a" * limit})
        assert not _accepts(llm_message, {"role": "assistant", "content": "a" * (limit + 1)})

    def test_migration_0024_tool_calls_bound_matches_chat_message_view(self) -> None:
        view = _model("ChatMessageView")
        limit = _tool_calls_max()

        assert _accepts(view, _message_payload(tool_calls=[_record_payload()] * limit))
        assert not _accepts(view, _message_payload(tool_calls=[_record_payload()] * (limit + 1)))

    def test_migration_0024_tool_calls_bound_holds_a_run_s_tool_calls(self) -> None:
        """AgentResult.tool_calls (what append_messages stores) is bounded the same way."""
        limit = _tool_calls_max()
        records = [_record_payload()] * limit

        assert _accepts(models_module.AgentResult, {"status": "final", "tool_calls": records})
        assert not _accepts(
            models_module.AgentResult,
            {"status": "final", "tool_calls": [*records, _record_payload()]},
        )

    def test_migration_0024_status_set_is_models_message_status(self) -> None:
        status = getattr(models_module, "MessageStatus", None)
        values = _in_values("status", _check(_MESSAGES, "chat_messages_status_check"))

        assert status is not None, "admino.models.MessageStatus does not exist (GH-176)"
        assert frozenset(typing.get_args(status)) == frozenset(values)

    def test_migration_0024_status_set_matches_chat_message_view(self) -> None:
        values = _in_values("status", _check(_MESSAGES, "chat_messages_status_check"))

        assert _literal_values(_model("ChatMessageView"), "status") == frozenset(values)

    def test_migration_0024_role_set_matches_chat_message_view(self) -> None:
        values = _in_values("role", _check(_MESSAGES, "chat_messages_role_check"))

        assert _literal_values(_model("ChatMessageView"), "role") == frozenset(values)

    @pytest.mark.parametrize(
        ("sample", "accepted"), _SESSION_SAMPLES, ids=[repr(s)[:30] for s, _ in _SESSION_SAMPLES]
    )
    def test_migration_0024_legacy_regex_matches_chat_request_session_id(
        self, sample: str, accepted: bool
    ) -> None:
        """Every session id the legacy route takes fits the column, and nothing else does."""
        chat_request = _accepts(models_module.ChatRequest, {"message": "hi", "session_id": sample})

        assert _sql_regex_accepts(_legacy_regex(), sample) is chat_request
        assert chat_request is accepted

    @pytest.mark.parametrize(
        ("sample", "accepted"),
        _TOOL_CALL_ID_SAMPLES,
        ids=[repr(s)[:30] for s, _ in _TOOL_CALL_ID_SAMPLES],
    )
    def test_migration_0024_tool_call_id_regex_matches_llm_message(
        self, sample: str, accepted: bool
    ) -> None:
        """Every tool_call_id a history message can carry fits the column."""
        llm_message = _accepts(
            models_module.LLMMessage, {"role": "tool", "content": "r", "tool_call_id": sample}
        )

        assert _sql_regex_accepts(_tool_call_id_regex(), sample) is llm_message
        assert llm_message is accepted

    def test_migration_0024_the_fake_database_mirrors_the_migration(self) -> None:
        """tests/db_fakes.py enforces exactly the shipped CHECKs."""
        shipped = (
            _char_length_max("title", _check(_CHATS, "chats_title_check")),
            _char_length_max("content", _check(_MESSAGES, "chat_messages_content_check")),
            _tool_calls_max(),
            frozenset(_in_values("title_source", _check(_CHATS, "chats_title_source_check"))),
            frozenset(_in_values("role", _check(_MESSAGES, "chat_messages_role_check"))),
            frozenset(_in_values("status", _check(_MESSAGES, "chat_messages_status_check"))),
            _legacy_regex()[1:-1],
            _tool_call_id_regex()[1:-1],
        )

        assert shipped == (
            db_fakes.CHAT_TITLE_MAX,
            db_fakes.CHAT_CONTENT_MAX,
            db_fakes.CHAT_TOOL_CALLS_MAX,
            db_fakes.CHAT_TITLE_SOURCES,
            db_fakes.CHAT_ROLES,
            db_fakes.CHAT_MESSAGE_STATUSES,
            db_fakes.LEGACY_SESSION_ID_RE.pattern,
            db_fakes.TOOL_CALL_ID_RE.pattern,
        )

    def test_migration_0024_the_fake_database_has_the_shipped_columns(self) -> None:
        """0024's columns, in order. A column a later migration appends (GH-189: 0029's
        chat_messages.included_attachment_ids; GH-194: 0031's chats.trash_group_id) is
        pinned, after these, by its own migration's test (tests/test_migration_0029.py,
        tests/test_migration_0031.py and tests/test_fakedb_trash.py)."""
        later = {_MESSAGES: ("included_attachment_ids",), _CHATS: ("trash_group_id",)}
        shipped = {table: [name for name, _ in _table(table).columns] for table in _TABLES}

        assert shipped == {
            table: [c for c in db_fakes._CHAT_TYPES[table] if c not in later.get(table, ())]
            for table in _TABLES
        }
