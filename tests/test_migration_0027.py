"""Tests for migration 0027_attachments.sql (GH-187): the chat attachments table, its
privileges, and ``file.upload`` in the audit action catalog.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
pipeline ran it on a throwaway postgres:16 as admino_app). These tests pin what the
migration guarantees, not how it is worded: the SQL is read with
tests/test_migration_0018.py's lexer (comments blanked, '...' literals and
dollar-quoted bodies kept whole, nested DO / function bodies and EXECUTE literals
searched too), the CREATE TABLE with tests/test_migration_0024.py's column and
constraint parser, the final foreign keys with tests/test_schema_foreign_keys.py's
parser, and the GRANT / REVOKE statements of every shipped migration are replayed into
the privileges each role ends up with (tests/test_migration_0025.py's privilege lists).
CHECK expressions are compared as their top-level AND-ed conditions, with whitespace
around parentheses and commas ignored and literals kept byte for byte.

What is pinned (contract section 1):
- ``0027_attachments.sql`` ships as the only version 27; run_migrations applies it
  after 0026 (once). It opens with a header comment.
- chats gains ``chats_id_org_owner_key UNIQUE (id, org_id, owner_user_id)`` (immediate),
  before ``CREATE TABLE attachments`` (the composite foreign key needs it).
- ``attachments``, columns in this order: ``id UUID PRIMARY KEY`` without a default
  (the application generates it: it names the file), ``org_id``, ``chat_id``,
  ``owner_user_id`` (UUID NOT NULL), ``message_id UUID`` (NULL: not sent),
  ``filename``, ``kind`` (TEXT NOT NULL), ``size_bytes BIGINT NOT NULL``, ``status
  TEXT NOT NULL DEFAULT 'uploaded'``, ``failure_reason TEXT``, ``page_count
  INTEGER``, ``created_at`` / ``updated_at TIMESTAMPTZ NOT NULL DEFAULT now()``,
  ``deleted_at TIMESTAMPTZ``; nothing else on a column or the table.
- Six named CHECKs: filename 1 to 255 characters with no control character, ``/``
  or ``\\`` (``!~ '[[:cntrl:]/\\\\]'``); kind one of the nine kinds; size_bytes 1 to
  524288000; status one of uploaded / processing / ready / failed; failure_reason
  set exactly when the status is failed, and then a reason code
  (``~ '^[a-z][a-z0-9_]{0,63}$'``); page_count NULL or >= 0. The SQL sets and bounds
  equal ``admino.models``' (AttachmentKind, AttachmentStatus, AttachmentSummary).
- Foreign keys, all ON DELETE CASCADE: org_id -> organizations (id), message_id ->
  chat_messages (id), and ``attachments_chat_fkey`` (chat_id, org_id, owner_user_id)
  -> chats (id, org_id, owner_user_id): an attachment of another org's chat or of a
  chat its owner doesn't own can't exist, and deleting a user (their chats) or
  purging an org removes the rows. No foreign key from attachments to users.
- Five plain btree indexes on attachments: (org_id) INCLUDE (size_bytes); (chat_id,
  org_id, owner_user_id); (message_id) WHERE message_id IS NOT NULL; (created_at)
  WHERE message_id IS NULL; (created_at) WHERE status IN ('uploaded', 'processing').
- Privileges after every migration up to 0027: admino_app holds SELECT, INSERT and
  DELETE on attachments and UPDATE on exactly message_id, status, failure_reason,
  page_count, updated_at and deleted_at (never id, org_id, chat_id, owner_user_id,
  filename, kind, size_bytes or created_at; no table-wide UPDATE, no grant option);
  PUBLIC holds nothing; no other table's privileges change. 0027's GRANTs (nested
  bodies and literals included) all target attachments for admino_app. (GH-188:
  migration 0028 adds token_estimate to the UPDATE grant; the cumulative set after
  every shipped migration is pinned in tests/test_migration_0028.py.)
- ``audit_events_action_check`` is dropped (no CASCADE), then added again with
  migration 0021's list plus ``file.upload`` (50 actions, each once), every one of them
  a live ``AuditAction`` (GH-190: migration 0030 adds file.exclude and file.include,
  so the exact sync moved on to tests/test_migration_0030.py; this file keeps a subset
  check).
- Nothing else: every statement is one of the above; no DO block, function,
  trigger, role, data write, REVOKE, TRUNCATE or DROP TABLE (nested ones included).
- tests/db_fakes.py mirrors 0027: its action catalog, its update grant on 0027's
  columns (the fake's cumulative grant, token_estimate included, is pinned against
  every shipped migration in tests/test_migration_0028.py), composite key name,
  kinds, statuses and bounds equal the shipped ones; an UPDATE naming a
  column outside the grant is "permission denied for table attachments" and changes
  nothing; an INSERT for another org's, a colleague's or an unknown chat is
  ForeignKeyViolationError on the composite key and stores nothing.

Security notes:
- Tenant isolation in the database: even a bug or injected SQL running as admino_app
  can't store an attachment in one org for a chat of another, or move a file to
  another org, owner, chat, name or size (no UPDATE on those columns).
- The filename CHECK keeps path separators and control characters out of the one
  column that holds user-chosen text about a file.
"""

from __future__ import annotations

import re
import typing
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock

import asyncpg
import pytest

import admino.database as db_mod
from tests import db_fakes
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb
from tests.test_migration_0018 import (
    _executed,
    _fragments,
    _load_migrations,
    _masked,
    _normalize,
    _split,
)
from tests.test_migration_0021 import _added_actions
from tests.test_migration_0024 import (
    _CONSTRAINT_START,
    _canonical_default,
    _Column,
    _parse_column,
    _parse_table_constraint,
    _Reference,
    _Table,
)
from tests.test_migration_0025 import (
    _GRANT_RE,
    _NON_TABLE_TARGET,
    _REVOKE_RE,
    _acl_keys,
    _grantees,
    _privilege_entries,
)
from tests.test_schema_foreign_keys import _shipped_schema

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME: Final = "0027_attachments.sql"
_PREVIOUS_MIGRATION: Final = "0026_chats_owner_org.sql"
_ACTIONS_MIGRATION: Final = "0021_account_self_service.sql"
_VERSION: Final = 27
_ROLE: Final = "admino_app"
_TABLE: Final = "attachments"
_CHATS_KEY: Final = "chats_id_org_owner_key"
_CHAT_FKEY: Final = "attachments_chat_fkey"
_ACTION_CONSTRAINT: Final = "audit_events_action_check"
_NEW_ACTION: Final = "file.upload"
_ACTION_CATALOG_SIZE: Final = 50
_DENIED: Final = "permission denied for table attachments"

_UPDATE_COLUMNS: Final = (
    "message_id",
    "status",
    "failure_reason",
    "page_count",
    "updated_at",
    "deleted_at",
)
_KINDS: Final = ("pdf", "docx", "xlsx", "csv", "txt", "md", "png", "jpeg", "webp")
_STATUSES: Final = ("uploaded", "processing", "ready", "failed")
_FILENAME_MAX: Final = 255
_SIZE_MAX: Final = 524_288_000
_REASON_REGEX: Final = "^[a-z][a-z0-9_]{0,63}$"
# The filename CHECK's regex literal as written in the SQL file: two backslashes
# (standard_conforming_strings: one escaped backslash inside the bracket).
_FILENAME_REGEX: Final = "[[:cntrl:]/" + chr(0x5C) * 2 + "]"


@dataclass(frozen=True)
class _Spec:
    """One contract column: canonical type, NOT NULL (explicit or implied), default."""

    type_name: str
    required: bool
    default: str | None


_COLUMNS: Final[dict[str, _Spec]] = {
    "id": _Spec("uuid", True, None),
    "org_id": _Spec("uuid", True, None),
    "chat_id": _Spec("uuid", True, None),
    "owner_user_id": _Spec("uuid", True, None),
    "message_id": _Spec("uuid", False, None),
    "filename": _Spec("text", True, None),
    "kind": _Spec("text", True, None),
    "size_bytes": _Spec("bigint", True, None),
    "status": _Spec("text", True, "'uploaded'"),
    "failure_reason": _Spec("text", False, None),
    "page_count": _Spec("integer", False, None),
    "created_at": _Spec("timestamptz", True, "now()"),
    "updated_at": _Spec("timestamptz", True, "now()"),
    "deleted_at": _Spec("timestamptz", False, None),
}
_FIXED_COLUMNS: Final = tuple(c for c in _COLUMNS if c not in _UPDATE_COLUMNS)

_TYPE_CANON: Final[dict[str, str]] = {
    "uuid": "uuid",
    "text": "text",
    "bigint": "bigint",
    "int8": "bigint",
    "integer": "integer",
    "int": "integer",
    "int4": "integer",
    "timestamptz": "timestamptz",
    "timestamp with time zone": "timestamptz",
}


def _canon(text: str) -> str:
    """Whitespace collapsed and dropped around parentheses and commas."""
    return re.sub(r"\s*([(),])\s*", r"\1", re.sub(r"\s+", " ", text)).strip()


# CHECK name -> its top-level AND-ed conditions (canonical).
_CHECKS: Final[dict[str, frozenset[str]]] = {
    "attachments_filename_check": frozenset(
        {
            _canon(f"char_length(filename) between 1 and {_FILENAME_MAX}"),
            _canon(f"filename !~ '{_FILENAME_REGEX}'"),
        }
    ),
    "attachments_kind_check": frozenset(
        {_canon("kind in (" + ", ".join(f"'{k}'" for k in _KINDS) + ")")}
    ),
    "attachments_size_bytes_check": frozenset({_canon(f"size_bytes between 1 and {_SIZE_MAX}")}),
    "attachments_status_check": frozenset(
        {_canon("status in (" + ", ".join(f"'{s}'" for s in _STATUSES) + ")")}
    ),
    "attachments_failure_reason_check": frozenset(
        {
            _canon("(status = 'failed') = (failure_reason is not null)"),
            _canon(f"failure_reason is null or failure_reason ~ '{_REASON_REGEX}'"),
        }
    ),
    "attachments_page_count_check": frozenset({_canon("page_count is null or page_count >= 0")}),
}

# (columns, referenced table, referenced columns, on delete), name (None: default).
_FOREIGN_KEYS: Final = frozenset(
    {
        ((("org_id",), "organizations", ("id",), "cascade"), None),
        ((("message_id",), "chat_messages", ("id",), "cascade"), None),
        (
            (
                ("chat_id", "org_id", "owner_user_id"),
                "chats",
                ("id", "org_id", "owner_user_id"),
                "cascade",
            ),
            _CHAT_FKEY,
        ),
    }
)

# name -> (columns, INCLUDE columns, WHERE conditions)
_INDEXES: Final[dict[str, tuple[tuple[str, ...], tuple[str, ...], frozenset[str]]]] = {
    "attachments_org_size_idx": (("org_id",), ("size_bytes",), frozenset()),
    "attachments_chat_idx": (("chat_id", "org_id", "owner_user_id"), (), frozenset()),
    "attachments_message_idx": (
        ("message_id",),
        (),
        frozenset({_canon("message_id is not null")}),
    ),
    "attachments_unsent_idx": (("created_at",), (), frozenset({_canon("message_id is null")})),
    "attachments_pending_idx": (
        ("created_at",),
        (),
        frozenset({_canon("status in ('uploaded', 'processing')")}),
    ),
}

_ALTER_RE: Final = re.compile(
    r'alter table (?:if exists )?(?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"? (?P<actions>.+)'
)
_ADD_UNIQUE_RE: Final = re.compile(
    r'add constraint "?(?P<name>\w+)"? unique (?:nulls (?:not )?distinct )?'
    r"\((?P<columns>[^)]*)\)(?P<rest>.*)"
)
_DROP_CHECK_RE: Final = re.compile(
    rf'drop constraint (?:if exists )?"?{_ACTION_CONSTRAINT}"?(?P<rest>.*)'
)
_ADD_CHECK_RE: Final = re.compile(rf'add constraint "?{_ACTION_CONSTRAINT}"? check ?\(.*\)')
_INDEX_RE: Final = re.compile(
    r"create (?P<unique>unique )?index (?P<concurrently>concurrently )?(?:if not exists )?"
    r'"?(?P<name>\w+)"? on (?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"?'
    r"(?: using (?P<method>\w+))? ?\((?P<columns>[^)]*)\)"
    r"(?: include ?\((?P<include>[^)]*)\))?(?: where (?P<where>.+))?"
)
_CREATE_TABLE_RE: Final = re.compile(
    rf'create table (?:if not exists )?(?:"?public"?\.)?"?{_TABLE}"? ?\('
)
# The statement kinds 0027 may run (masked, normalized).
_SCHEMA: Final = r'(?:"?public"?\.)?'
_ALLOWED_STATEMENTS: Final[dict[str, re.Pattern[str]]] = {
    "chats key": re.compile(rf'alter table (?:only )?{_SCHEMA}"?chats"? add constraint .+'),
    "create table": re.compile(rf'create table {_SCHEMA}"?{_TABLE}"? ?\(.*\)'),
    "index": re.compile(rf'create index "?\w+"? on (?:only )?{_SCHEMA}"?{_TABLE}"?.*'),
    "grant": re.compile(rf'grant .+ on (?:table )?{_SCHEMA}"?{_TABLE}"? to .+'),
    "action check": re.compile(
        rf'alter table (?:only )?{_SCHEMA}"?audit_events"? (?:drop|add) constraint .+'
    ),
}
# Fragments 0027 must not contain (top level, DO / function bodies, literals).
_FORBIDDEN: Final[dict[str, str]] = {
    "do": r"do\b",
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
}


# ---------------------------------------------------------------------------
# Helpers: the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    return _migration_path().read_text(encoding="utf-8")


def _statements() -> list[str]:
    """The statements 0027 runs (top level and DO blocks), normalized."""
    return _executed(_normalize(_raw_sql()))


def _names(text: str) -> tuple[str, ...]:
    return tuple(name.strip().strip('"') for name in _split(text, ","))


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


def _unwrap(expression: str) -> str:
    expression = expression.strip()
    while (
        expression.startswith("(") and _balanced_end(_masked(expression), 0) == len(expression) - 1
    ):
        expression = expression[1:-1].strip()
    return expression


def _conditions(expression: str) -> frozenset[str]:
    """The top-level AND-ed conditions, each unwrapped and canonical (the AND of a
    BETWEEN is not a separator)."""
    expression = _unwrap(expression)
    masked = _masked(expression)
    parts: list[str] = []
    depth = 0
    start = 0
    in_between = False
    for token in re.finditer(r"\(|\)|\bbetween\b|\band\b", masked):
        word = token.group(0)
        if word == "(":
            depth += 1
        elif word == ")":
            depth -= 1
        elif depth == 0 and word == "between":
            in_between = True
        elif depth == 0 and in_between:
            in_between = False
        elif depth == 0:
            parts.append(expression[start : token.start()])
            start = token.end()
    parts.append(expression[start:])
    return frozenset(_canon(_unwrap(part)) for part in parts)


def _alter_actions() -> list[tuple[str, str]]:
    """(table, action) for every action of every ALTER TABLE 0027 runs, in order."""
    found: list[tuple[str, str]] = []
    for statement in _statements():
        match = _ALTER_RE.fullmatch(_masked(statement))
        if match is None:
            continue
        for action in _split(statement[match.start("actions") :], ","):
            found.append((match.group("table"), action))
    return found


def _action_kind(action: str) -> str:
    """unique (the chats key), drop / check (the action CHECK), else the action itself."""
    masked = _masked(action)
    if _ADD_UNIQUE_RE.fullmatch(masked):
        return "unique"
    if _DROP_CHECK_RE.fullmatch(masked):
        return "drop"
    if _ADD_CHECK_RE.fullmatch(masked):
        return "check"
    return action


def _create_table_statement() -> str:
    found = [s for s in _statements() if _CREATE_TABLE_RE.match(_masked(s))]
    assert len(found) == 1, f"{_MIGRATION_NAME} must create {_TABLE} exactly once: {found}"
    return found[0]


def _table() -> _Table:
    """The parsed CREATE TABLE attachments: columns (in order) and table constraints."""
    statement = _create_table_statement()
    masked = _masked(statement)
    open_index = _CREATE_TABLE_RE.match(masked).end() - 1  # type: ignore[union-attr]
    end = _balanced_end(masked, open_index)
    assert masked[end + 1 :].strip() == "", statement
    table = _Table()
    for element in _split(statement[open_index + 1 : end], ","):
        if re.match(_CONSTRAINT_START, _masked(element)):
            _parse_table_constraint(table, element)
            continue
        match = re.fullmatch(r'"?(\w+)"?\s+(.*)', element)
        assert match is not None, element
        table.columns.append((match.group(1), _parse_column(match.group(1), match.group(2))))
    return table


def _column(name: str) -> _Column:
    found = [column for column_name, column in _table().columns if column_name == name]
    assert len(found) == 1, f"{_TABLE}.{name} must be defined exactly once: {found}"
    return found[0]


def _all_checks() -> list[tuple[str | None, str]]:
    table = _table()
    checks = list(table.checks)
    for _, column in table.columns:
        checks.extend(column.checks)
    return checks


def _check(name: str) -> str:
    found = [expression for check_name, expression in _all_checks() if check_name == name]
    assert len(found) == 1, f"{name} must be defined exactly once on {_TABLE}: {found}"
    return found[0]


def _in_list(column: str, name: str) -> list[str]:
    """The literals of ``<column> IN (...)``, the whole of the named CHECK."""
    expression = _unwrap(_check(name))
    match = re.fullmatch(rf"{column} in ?\(([^)]*)\)", _masked(expression))
    assert match is not None, f"{name} must be '{column} IN (...)': {expression}"
    return re.findall(r"'([^']*)'", expression[match.start(1) : match.end(1)])


def _between(column: str, name: str, operand: str) -> tuple[int, int]:
    """The bounds of ``<operand> BETWEEN a AND b`` among the named CHECK's conditions."""
    bounds = [
        (int(match.group(1)), int(match.group(2)))
        for condition in _conditions(_check(name))
        if (
            match := re.fullmatch(
                rf"{re.escape(_canon(operand))} ?between (\d+) and (\d+)", condition
            )
        )
    ]
    assert len(bounds) == 1, f"{name} must bound {column} once: {_check(name)}"
    return bounds[0]


def _reason_regex() -> str:
    found = [
        match.group(1)
        for condition in _conditions(_check("attachments_failure_reason_check"))
        if (match := re.fullmatch(r"failure_reason is null or failure_reason ~ '(.*)'", condition))
    ]
    assert len(found) == 1, _check("attachments_failure_reason_check")
    return found[0]


def _foreign_keys() -> list[_Reference]:
    table = _table()
    references = list(table.foreign_keys)
    for _, column in table.columns:
        references.extend(column.references)
    return references


@dataclass(frozen=True)
class _Index:
    table: str
    unique: bool
    concurrently: bool
    btree: bool
    columns: tuple[str, ...]
    include: tuple[str, ...]
    where: frozenset[str]


def _indexes() -> dict[str, _Index]:
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
        include = _names(match.group("include")) if match.group("include") else ()
        where = (
            _conditions(statement[match.start("where") : match.end("where")])
            if match.group("where")
            else frozenset()
        )
        assert match.group("name") not in found, f"index {match.group('name')} created twice"
        found[match.group("name")] = _Index(
            table=match.group("table"),
            unique=match.group("unique") is not None,
            concurrently=match.group("concurrently") is not None,
            btree=match.group("method") in (None, "btree"),
            columns=columns,
            include=include,
            where=where,
        )
    return found


def _targets(target: str) -> tuple[str, ...]:
    """The tables a GRANT / REVOKE target names (a bulk target as one pseudo-table)."""
    if _NON_TABLE_TARGET.match(target):
        return ()
    if re.fullmatch(r"all tables in schema .+", target):
        return ("<all tables>",)
    return tuple(
        raw.strip().strip('"').split(".")[-1] for raw in _split(re.sub(r"^table ", "", target), ",")
    )


def _apply(acl: dict[tuple[str, str], set[str]], statement: str) -> None:
    """Apply one GRANT or REVOKE as PostgreSQL does (a table-level REVOKE also takes
    the privilege away from every column; ``*`` marks a grant option)."""
    masked = _masked(statement)
    grant = _GRANT_RE.fullmatch(masked)
    revoke = None if grant is not None else _REVOKE_RE.fullmatch(masked)
    match = grant or revoke
    if match is None:
        return
    for table in _targets(match.group("target")):
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


def _acl(up_to: int) -> dict[tuple[str, str], frozenset[str]]:
    """(table, grantee) -> ACL entries after every shipped migration up to a version.

    Fails the calling test when version 27 isn't shipped (nothing to replay)."""
    versions: list[int] = []
    acl: dict[tuple[str, str], set[str]] = {}
    for migration in _load_migrations(db_mod._MIGRATIONS_DIR):
        if migration.version > up_to:
            continue
        versions.append(migration.version)
        for statement in _executed(_normalize(migration.sql)):
            _apply(acl, statement)
    assert _VERSION in versions or up_to < _VERSION, f"{_MIGRATION_NAME} is not shipped"
    return {key: frozenset(value) for key, value in acl.items() if value}


def _file_grants() -> list[tuple[frozenset[str], tuple[str, ...], frozenset[str], bool]]:
    """(ACL entries, tables, grantees, grant option) of every GRANT in 0027, nested
    DO / function bodies and EXECUTE literals included."""
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


def _shipped_update_columns() -> frozenset[str]:
    held = _acl(_VERSION).get((_TABLE, _ROLE), frozenset())
    return frozenset(
        match.group(1) for entry in held if (match := re.fullmatch(r"update\((\w+)\)", entry))
    )


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


def _model_bound(model: Any, field: str, attribute: str) -> Any:
    """A constraint (ge, le, max_length, pattern, ...) of a Pydantic model field."""
    for item in model.model_fields[field].metadata:
        value = getattr(item, attribute, None)
        if value is not None:
            return value
    pytest.fail(f"{model.__name__}.{field} has no {attribute}")


# ---------------------------------------------------------------------------
# 1. The migration file and how it is applied
# ---------------------------------------------------------------------------


class TestMigration0027File:
    """The migration ships as version 27 and is applied by run_migrations after 0026."""

    def test_migration_0027_file_is_the_only_version_27(self) -> None:
        twenty_sevens = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert twenty_sevens == [_MIGRATION_NAME]

    async def test_migration_0027_run_migrations_applies_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0026 applied, run_migrations executes the file and records 27."""
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

    async def test_migration_0027_runs_after_0026(self, mock_pool: MagicMock) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0027_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0027_opens_with_a_header_comment(self) -> None:
        """Purpose, layout and consequences are explained before the first statement."""
        assert len(_header_lines()) >= 3


# ---------------------------------------------------------------------------
# 2. The chats key the composite foreign key references
# ---------------------------------------------------------------------------


class TestMigration0027ChatsKey:
    """chats gains UNIQUE (id, org_id, owner_user_id) before attachments references it."""

    def test_migration_0027_chats_gets_the_id_org_owner_unique_key(self) -> None:
        """chats_id_org_owner_key UNIQUE (id, org_id, owner_user_id), immediate (a foreign
        key can't reference a deferrable key); the only UNIQUE key 0027 adds."""
        found = [
            (
                table,
                match.group("name"),
                _names(match.group("columns")),
                match.group("rest").strip() in ("", "not deferrable"),
            )
            for table, action in _alter_actions()
            if (match := _ADD_UNIQUE_RE.fullmatch(_masked(action)))
        ]

        assert found == [("chats", _CHATS_KEY, ("id", "org_id", "owner_user_id"), True)]

    def test_migration_0027_chats_key_comes_before_the_attachments_table(self) -> None:
        """PostgreSQL refuses a foreign key whose referenced columns have no unique key
        yet, so the ALTER on chats runs first."""
        statements = [_masked(s) for s in _statements()]
        key = [i for i, s in enumerate(statements) if re.match(r"alter table \"?chats\"?", s)]
        table = [i for i, s in enumerate(statements) if _CREATE_TABLE_RE.match(s)]

        assert len(key) == 1
        assert len(table) == 1
        assert key[0] < table[0]


# ---------------------------------------------------------------------------
# 3. The attachments table: columns, keys and CHECKs
# ---------------------------------------------------------------------------


class TestMigration0027Table:
    """CREATE TABLE attachments: the contract's columns, CHECKs and foreign keys."""

    def test_migration_0027_columns_types_not_null_and_defaults(self) -> None:
        """The fourteen columns in the contract's order, each with its type, NOT NULL
        (explicit or by the primary key) and default."""
        found = {
            name: _Spec(
                _TYPE_CANON.get(column.type_name, column.type_name),
                column.not_null or column.primary_key,
                _canonical_default(column),
            )
            for name, column in _table().columns
        }

        assert [name for name, _ in _table().columns] == list(_COLUMNS)
        assert found == _COLUMNS

    def test_migration_0027_id_is_the_primary_key_without_default(self) -> None:
        """The application generates the id before the file is written (it names the
        file): no gen_random_uuid() default, no identity."""
        table = _table()
        keys = list(table.primary_keys) + [
            (name,) for name, column in table.columns if column.primary_key
        ]
        column = _column("id")

        assert keys == [("id",)]
        assert (column.defaults, column.identity) == ([], None)

    def test_migration_0027_nothing_unexpected_on_a_column_or_the_table(self) -> None:
        """No clause the contract doesn't name: no UNIQUE, no extra constraint."""
        table = _table()
        column_extras = {
            name: (column.unexpected, column.uniques, column.explicit_null)
            for name, column in table.columns
            if column.unexpected or column.uniques or column.explicit_null
        }

        assert column_extras == {}
        assert (table.unexpected, table.uniques) == ([], [])

    def test_migration_0027_checks_are_the_six_named_ones(self) -> None:
        """Every CHECK has a name, and the names are exactly the contract's."""
        names = [name for name, _ in _all_checks()]

        assert sorted(names, key=str) == sorted(_CHECKS)

    @pytest.mark.parametrize("name", sorted(_CHECKS))
    def test_migration_0027_check_means_the_contract(self, name: str) -> None:
        """The CHECK's AND-ed conditions, literals byte for byte."""
        assert _conditions(_check(name)) == _CHECKS[name]

    def test_migration_0027_sql_sets_and_bounds_equal_the_models(self) -> None:
        """The kind and status lists are the models' Literals (same order), and the
        filename, size and reason bounds are AttachmentSummary's: a value the API
        returns always fits the column, and the reverse."""
        import admino.models as models

        summary = models.AttachmentSummary  # type: ignore[attr-defined]
        sql = {
            "kinds": tuple(_in_list("kind", "attachments_kind_check")),
            "statuses": tuple(_in_list("status", "attachments_status_check")),
            "filename": _between("filename", "attachments_filename_check", "char_length(filename)"),
            "size": _between("size_bytes", "attachments_size_bytes_check", "size_bytes"),
            "reason": _reason_regex(),
        }
        python = {
            "kinds": typing.get_args(models.AttachmentKind),  # type: ignore[attr-defined]
            "statuses": typing.get_args(models.AttachmentStatus),  # type: ignore[attr-defined]
            "filename": (
                _model_bound(summary, "filename", "min_length"),
                _model_bound(summary, "filename", "max_length"),
            ),
            "size": (
                _model_bound(summary, "size_bytes", "ge"),
                _model_bound(summary, "size_bytes", "le"),
            ),
            "reason": _model_bound(summary, "failure_reason", "pattern"),
        }

        assert sql == python

    def test_migration_0027_foreign_keys_all_cascade(self) -> None:
        """org_id -> organizations, message_id -> chat_messages and the named composite
        (chat_id, org_id, owner_user_id) -> chats (id, org_id, owner_user_id), each
        ON DELETE CASCADE, column pairs in order; nothing references users directly."""
        found = [(reference.shape(), reference.name) for reference in _foreign_keys()]

        assert sorted(found, key=str) == sorted(_FOREIGN_KEYS, key=str)

    def test_migration_0027_final_schema_foreign_keys_of_attachments(self) -> None:
        """Across every shipped migration (tests/test_schema_foreign_keys.py's parser),
        attachments has exactly these three keys: one cascade path from users (through
        chats), one from organizations, one from chat_messages."""
        found = {
            (fk.columns, fk.referenced, fk.referenced_columns or ("id",), fk.on_delete, fk.name)
            for fk in _shipped_schema().foreign_keys
            if fk.table == _TABLE
        }

        assert found == {
            (("org_id",), "organizations", ("id",), "cascade", "attachments_org_id_fkey"),
            (("message_id",), "chat_messages", ("id",), "cascade", "attachments_message_id_fkey"),
            (
                ("chat_id", "org_id", "owner_user_id"),
                "chats",
                ("id", "org_id", "owner_user_id"),
                "cascade",
                _CHAT_FKEY,
            ),
        }


# ---------------------------------------------------------------------------
# 4. Indexes
# ---------------------------------------------------------------------------


class TestMigration0027Indexes:
    """The five indexes behind the quota sum, the chat lookups, the GC and recovery."""

    def test_migration_0027_creates_exactly_the_five_indexes(self) -> None:
        """Plain btree, non-unique, not CONCURRENTLY (migrations run in a transaction),
        on attachments, with the contract's columns, INCLUDE and WHERE."""
        expected = {
            name: _Index(
                table=_TABLE,
                unique=False,
                concurrently=False,
                btree=True,
                columns=columns,
                include=include,
                where=where,
            )
            for name, (columns, include, where) in _INDEXES.items()
        }

        assert _indexes() == expected


# ---------------------------------------------------------------------------
# 5. Privileges
# ---------------------------------------------------------------------------


class TestMigration0027Privileges:
    """What admino_app (and PUBLIC) may do on attachments after every migration."""

    def test_migration_0027_admino_app_privileges_on_attachments(self) -> None:
        """SELECT, INSERT, DELETE (the orphan GC) and UPDATE on exactly the six columns
        the application writes: no table-wide UPDATE, so never id, org_id, chat_id,
        owner_user_id, filename, kind, size_bytes or created_at; no grant option."""
        expected = {"select", "insert", "delete", *(f"update({c})" for c in _UPDATE_COLUMNS)}

        assert _acl(_VERSION).get((_TABLE, _ROLE), frozenset()) == expected

    def test_migration_0027_identity_columns_are_not_updatable(self) -> None:
        held = _acl(_VERSION).get((_TABLE, _ROLE), frozenset())
        updatable = {
            column: "update" in held or f"update({column})" in held for column in _FIXED_COLUMNS
        }

        assert held, f"{_ROLE} holds nothing on {_TABLE}"
        assert updatable == dict.fromkeys(_FIXED_COLUMNS, False)

    def test_migration_0027_public_holds_nothing_on_attachments(self) -> None:
        acl = _acl(_VERSION)

        assert (_TABLE, _ROLE) in acl
        assert acl.get((_TABLE, "public"), frozenset()) == frozenset()

    def test_migration_0027_changes_no_privilege_on_another_table(self) -> None:
        """Every other (table, grantee) holds after 0027 exactly what it held after 0026."""
        before = _acl(_VERSION - 1)
        after = {key: value for key, value in _acl(_VERSION).items() if key[0] != _TABLE}

        assert (_TABLE, _ROLE) in _acl(_VERSION)
        assert after == before

    def test_migration_0027_grants_only_on_attachments_to_admino_app(self) -> None:
        """Every GRANT in the file (nested ones included) is on attachments, to
        admino_app alone, without grant option."""
        grants = _file_grants()

        assert grants, f"{_MIGRATION_NAME} grants nothing"
        assert {(tables, grantees, option) for _, tables, grantees, option in grants} == {
            ((_TABLE,), frozenset({_ROLE}), False)
        }


# ---------------------------------------------------------------------------
# 6. The audit action catalog grows by file.upload
# ---------------------------------------------------------------------------


class TestMigration0027ActionCatalog:
    """audit_events_action_check is replaced with the 50-action catalog."""

    def test_migration_0027_action_check_adds_exactly_file_upload(self) -> None:
        """The new list is 0021's 49 actions plus file.upload, each listed once."""
        old = set(_added_actions(_ACTIONS_MIGRATION))
        listed = _added_actions(_MIGRATION_NAME)

        assert set(listed) - old == {_NEW_ACTION}
        assert old <= set(listed)
        assert len(listed) == len(set(listed)) == _ACTION_CATALOG_SIZE

    def test_migration_0027_action_check_matches_audit_action(self) -> None:
        """Every action 0027 allows is still an AuditAction (none was dropped). GH-190: the
        exact catalog sync moved on to tests/test_migration_0030.py, whose list adds
        file.exclude and file.include."""
        from admino.audit_events import AuditAction

        assert set(_added_actions(_MIGRATION_NAME)) <= {action.value for action in AuditAction}

    def test_migration_0027_action_check_is_dropped_then_added(self) -> None:
        """One DROP (without CASCADE), then one ADD, of the constraint on audit_events."""
        steps = []
        for table, action in _alter_actions():
            masked = _masked(action)
            if (drop := _DROP_CHECK_RE.fullmatch(masked)) is not None:
                steps.append((table, "drop", drop.group("rest").strip()))
            elif _ADD_CHECK_RE.fullmatch(masked):
                steps.append((table, "add", ""))

        assert steps == [("audit_events", "drop", ""), ("audit_events", "add", "")]


# ---------------------------------------------------------------------------
# 7. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0027Scope:
    """Only the chats key, the table, its indexes and grants, and the catalog."""

    def test_migration_0027_every_statement_is_part_of_the_contract(self) -> None:
        statements = _statements()
        other = [
            statement
            for statement in statements
            if not any(p.fullmatch(_masked(statement)) for p in _ALLOWED_STATEMENTS.values())
        ]

        assert statements, f"{_MIGRATION_NAME} runs nothing"
        assert other == []

    def test_migration_0027_alters_only_the_chats_key_and_the_action_check(self) -> None:
        """Every ALTER TABLE action adds the chats key or drops / adds the action CHECK:
        no column change, no other constraint, no trigger disabled, no owner change."""
        kinds = sorted((table, _action_kind(action)) for table, action in _alter_actions())

        assert kinds == [
            ("audit_events", "check"),
            ("audit_events", "drop"),
            ("chats", "unique"),
        ]

    def test_migration_0027_runs_no_code_data_write_or_role_change(self) -> None:
        """No DO block, function, trigger, role, INSERT / UPDATE / DELETE / TRUNCATE /
        COPY / MERGE, REVOKE, default privileges or DROP TABLE / INDEX, also not nested
        in a body or an EXECUTE literal."""
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
# 8. tests/db_fakes.py mirrors 0027
# ---------------------------------------------------------------------------


_UPDATE_VALUES: Final[dict[str, Any]] = {
    "id": uuid.UUID("27a1c0de-0000-4000-8000-000000000001"),
    "org_id": OTHER_ORG_ID,
    "chat_id": uuid.UUID("27a1c0de-0000-4000-8000-000000000002"),
    "owner_user_id": uuid.UUID("27a1c0de-0000-4000-8000-000000000003"),
    "message_id": None,
    "filename": "renamed.txt",
    "kind": "txt",
    "size_bytes": 2,
    "status": "processing",
    "failure_reason": None,
    "page_count": 2,
    "created_at": datetime(2026, 1, 1, tzinfo=UTC),
    "updated_at": datetime(2026, 1, 2, tzinfo=UTC),
    "deleted_at": datetime(2026, 1, 3, tzinfo=UTC),
}
# When the file whose deleted_at is rewritten went to the trash (GH-194).
_TRASHED_AT: Final = datetime(2026, 1, 2, 12, tzinfo=UTC)
_SET_HEAD: Final = "UPDATE attachments SET "
_SET_TAIL: Final = " = $1 WHERE id = $2"
_INSERT_SQL: Final = (
    "INSERT INTO attachments (id, org_id, chat_id, owner_user_id, filename, kind, size_bytes) "
    "VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
)


class TestMigration0027FakeDb:
    """The FakeDb holds what 0027 ships."""

    def test_migration_0027_fake_constants_are_the_shipped_ones(self) -> None:
        """Catalog, update grant, composite key name, kinds, statuses and bounds.

        The update grant is compared on 0027's own columns: what 0027 grants of them.
        Columns later migrations add (0028's token_estimate) are pinned, with the
        cumulative grant, by their own migration's test."""
        composite = [r.name for r in _foreign_keys() if r.table == "chats"]
        fake = {
            "actions": frozenset(db_fakes.AUDIT_ACTIONS),
            "update columns": frozenset(db_fakes.ATTACHMENT_UPDATE_COLUMNS) & frozenset(_COLUMNS),
            "chat fkey": [db_fakes.ATTACHMENT_CHAT_FKEY],
            "kinds": frozenset(db_fakes.ATTACHMENT_KINDS),
            "statuses": frozenset(db_fakes.ATTACHMENT_STATUSES),
            "filename max": db_fakes.ATTACHMENT_FILENAME_MAX,
            "size max": db_fakes.ATTACHMENT_SIZE_MAX,
        }
        shipped = {
            "actions": frozenset(_added_actions(_MIGRATION_NAME)),
            "update columns": _shipped_update_columns(),
            "chat fkey": composite,
            "kinds": frozenset(_in_list("kind", "attachments_kind_check")),
            "statuses": frozenset(_in_list("status", "attachments_status_check")),
            "filename max": _between(
                "filename", "attachments_filename_check", "char_length(filename)"
            )[1],
            "size max": _between("size_bytes", "attachments_size_bytes_check", "size_bytes")[1],
        }

        assert fake == shipped

    async def test_migration_0027_fake_updates_only_the_granted_columns(self) -> None:
        """An UPDATE naming a column outside the shipped grant is 'permission denied for
        table attachments' and changes nothing; a granted column is updated. (GH-194: a
        new deleted_at goes on a file already in the trash, and so in its trash group:
        migration 0032's CHECK refuses a deleted_at without a group.)"""
        granted = _shipped_update_columns()
        outcomes: dict[str, str] = {}
        for column in _COLUMNS:
            db = FakeDb()
            member = db.add_account(org_id=ORG_ID)
            attachment = db.add_attachment(
                db.add_chat(member),
                filename="a.txt",
                kind="txt",
                deleted_at=_TRASHED_AT if column == "deleted_at" else None,
            )
            before = db.attachment_row(attachment)
            try:
                await db.pool.execute(
                    _SET_HEAD + column + _SET_TAIL,
                    _UPDATE_VALUES[column],
                    attachment,
                )
            except asyncpg.InsufficientPrivilegeError as exc:
                unchanged = db.attachment_row(attachment) == before
                outcomes[column] = "denied" if str(exc) == _DENIED and unchanged else str(exc)
            except Exception as exc:
                outcomes[column] = f"error:{type(exc).__name__}"
            else:
                outcomes[column] = "allowed"

        assert granted, f"{_MIGRATION_NAME} grants no column UPDATE"
        assert outcomes == {c: "allowed" if c in granted else "denied" for c in _COLUMNS}

    @pytest.mark.parametrize("chat_kind", ["other-org-chat", "colleague-chat", "unknown-chat"])
    async def test_migration_0027_fake_refuses_an_attachment_of_another_chat_owner(
        self, chat_kind: str
    ) -> None:
        """The contract's INSERT for ORG_ID's member naming another org's chat, a
        colleague's chat or an unknown chat is ForeignKeyViolationError on the shipped
        composite key; nothing is stored."""
        db = FakeDb()
        member = db.add_account(org_id=ORG_ID)
        if chat_kind == "other-org-chat":
            chat = db.add_chat(db.add_account(org_id=OTHER_ORG_ID))
        elif chat_kind == "colleague-chat":
            chat = db.add_chat(db.add_account(org_id=ORG_ID))
        else:
            chat = uuid.UUID("27a1c0de-0000-4000-8000-0000000000ff")
        before = db.snapshot()
        composite = [r.name for r in _foreign_keys() if r.table == "chats"]

        with pytest.raises(asyncpg.ForeignKeyViolationError) as caught:
            await db.pool.fetchrow(
                _INSERT_SQL, uuid.uuid4(), ORG_ID, chat, member, "a.txt", "txt", 1
            )

        assert [caught.value.constraint_name] == composite
        assert db.snapshot() == before
