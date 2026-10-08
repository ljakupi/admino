"""Tests for migration 0029_chat_message_attachments.sql (GH-189, contract C13, issue
Decision 11): the attachment ids an assistant message was answered with.

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
  header comment that names the column.
- Exactly one statement: ``ALTER TABLE chat_messages`` with one action, ``ADD COLUMN
  included_attachment_ids UUID[]``, nullable (NULL: no attachments in the slot), no
  default, nothing else on the column but exactly one CHECK, named
  ``chat_messages_included_attachment_ids_check``: ``included_attachment_ids IS NULL OR
  (role = 'assistant' AND array_ndims(...) = 1 AND cardinality(...) >= 1 AND
  array_position(..., NULL) IS NULL)``: a one-dimensional array of at least one
  non-NULL id, on an assistant row only.
- No privilege change: the file holds no GRANT or REVOKE (nested ones included), every
  (table, grantee) holds after 0029 what it held after 0028, and admino_app keeps
  exactly SELECT, INSERT on chat_messages (append-only), PUBLIC nothing.
- Nothing else: no DO block, function, trigger, role, INSERT / UPDATE / DELETE /
  TRUNCATE / COPY / MERGE, CREATE, DROP or default privileges, also not nested.
- tests/db_fakes.py mirrors 0029 (contract C14): the contract's assistant INSERT (S8',
  ``$9::uuid[]``) stores the ids in the given order, NULL stays NULL, today's INSERT
  (S8) stores NULL; ``'{}'``, ``ARRAY[NULL]``, an id list with a NULL, a user or tool
  row with ids and a 2-D array are CheckViolationError on the shipped CHECK's name with
  nothing stored; ``add_chat_message(..., included_attachment_ids=)`` is checked the
  same way; the fake's chat_messages columns are 0024's followed by the new one.

Security notes:
- The column holds attachment ids only: no name, kind, size or content of a file.
- admino_app gains no privilege: chat_messages stays append-only for the app.
"""

from __future__ import annotations

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
from tests.test_migration_0027 import _ALTER_RE, _apply, _canon, _unwrap

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
_ADD_COLUMN_RE: Final = re.compile(
    r'add (?:column )?(?:if not exists )?"?(?P<name>\w+)"? (?P<definition>.+)'
)
# A one-dimensional array type: "uuid[]" or "uuid array" (the SQL-standard spelling).
_ARRAY_TYPE_RE: Final = re.compile(r"(?P<base>\w+)\s*(?:\[\s*\]|\s+array\b)\s*")
_ALLOWED_STATEMENT: Final = re.compile(rf'alter table (?:only )?{_SCHEMA}"?{_TABLE}"? add .+')
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


# ---------------------------------------------------------------------------
# 2. The included_attachment_ids column
# ---------------------------------------------------------------------------


class TestMigration0029Column:
    """ALTER TABLE chat_messages ADD COLUMN included_attachment_ids UUID[] with its CHECK."""

    def test_migration_0029_adds_only_the_included_attachment_ids_column(self) -> None:
        """One ALTER TABLE action: no other column, constraint, owner or trigger change."""
        actions = [(table, _ADD_COLUMN_RE.fullmatch(_masked(a))) for table, a in _alter_actions()]

        assert [(table, m.group("name") if m else None) for table, m in actions] == [
            (_TABLE, _COLUMN)
        ]

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
# 3. Privileges
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
# 4. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0029Scope:
    """Only the column and its CHECK."""

    def test_migration_0029_runs_exactly_one_alter_table_on_chat_messages(self) -> None:
        statements = _statements()

        assert [bool(_ALLOWED_STATEMENT.fullmatch(_masked(s))) for s in statements] == [True]

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
# 5. tests/db_fakes.py mirrors 0029
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
