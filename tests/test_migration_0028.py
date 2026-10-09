"""Tests for migration 0028_attachment_token_estimate.sql (GH-188): the per-file token
estimate and derived-bytes columns on attachments, their UPDATE grant, and the requeue of
files that were ``ready`` before conversion existed.

There is no real PostgreSQL in the suite, so the shipped SQL file is the spec (the
pipeline runs it on a throwaway postgres:16 as admino_app). The SQL is read with
tests/test_migration_0018.py's lexer (comments blanked, '...' literals and
dollar-quoted bodies kept whole, nested DO / function bodies and EXECUTE literals
searched too), the added column with tests/test_migration_0024.py's column parser, and
the GRANT / REVOKE statements of every shipped migration are replayed into the
privileges each role ends up with (tests/test_migration_0027.py's replay). CHECK and
WHERE expressions are compared as their top-level AND-ed conditions, canonical
(whitespace around parentheses, commas and comparison operators ignored, literals
byte for byte).

What is pinned (contract sections 8 and 12.4):
- ``0028_attachment_token_estimate.sql`` ships as the only version 28; run_migrations
  applies it after 0027 (once). It opens with a header comment.
- Two ALTER TABLE statements on attachments, each with one action, in this order:
  - ADD COLUMN ``token_estimate INTEGER``, nullable (``null`` until the file is
    ready), no default, with exactly one CHECK, named
    ``attachments_token_estimate_check``: NULL or >= 0. The bound and the nullability
    equal ``AttachmentSummary.token_estimate``'s (``int | None``, ge=0).
  - (GH-188 audit fix M-3, contract 12.4) ADD COLUMN ``derived_bytes BIGINT``,
    nullable (``null`` until the file is ready), no default, with exactly one CHECK,
    named ``attachments_derived_bytes_check``: NULL or >= 0.
  Nothing else on either column (no NOT NULL, UNIQUE, REFERENCES, identity, default).
- One ``GRANT UPDATE (token_estimate, derived_bytes) ON attachments TO admino_app``,
  after both columns exist; the file's only GRANT (nested ones included), without
  grant option. Statement order: the two ALTERs, the GRANT, the requeue UPDATE.
- After every migration up to 0028 admino_app holds on attachments SELECT, INSERT,
  DELETE and UPDATE on exactly message_id, status, failure_reason, page_count,
  token_estimate, derived_bytes, updated_at and deleted_at (no table-wide UPDATE, no
  grant option); PUBLIC holds nothing; 0028 adds ``update(token_estimate)`` and
  ``update(derived_bytes)`` and changes no other privilege of any table or role.
  (GH-190: migration 0030 adds ``update(active)``; the cumulative set after every
  shipped migration is pinned in tests/test_migration_0030.py.)
- The one data write: ``UPDATE attachments SET status = 'uploaded', updated_at =
  now() WHERE status = 'ready'`` (files ready before this release have no derived
  files; the startup recovery converts them). No other statement: no DO block,
  function, trigger, role, INSERT / DELETE / TRUNCATE / COPY / MERGE, other UPDATE,
  REVOKE, DROP or default privileges, also not nested in a body or an EXECUTE literal.
- tests/db_fakes.py mirrors 0028: its UPDATE grant on attachments is the cumulative
  shipped one; an UPDATE of token_estimate (derived_bytes) stores None, 0 and a large
  value (for derived_bytes one past the INTEGER range: a BIGINT), and a negative one
  is CheckViolationError on the shipped CHECK's name with the row unchanged; the
  fake's attachments columns are 0027's followed by the columns 0028 adds, in the
  file's order (ALTER TABLE ... ADD COLUMN appends them; GH-190: 0030's ``active``
  follows them, pinned in tests/test_migration_0030.py).

Security notes:
- admino_app gains exactly two updatable columns, both counters the processing step
  writes: even a bug or injected SQL running as admino_app still can't move a file to
  another org, owner, chat, name or size.
- derived_bytes is what the storage quota counts beside size_bytes (contract 12.4): a
  conversion's derived files can no longer fill the shared volume outside the quota.
- The requeue writes no content: a status and a timestamp, nothing about the file.
"""

from __future__ import annotations

import re
import typing
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock

import asyncpg

import admino.database as db_mod
from tests import db_fakes
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
from tests.test_migration_0025 import (
    _GRANT_RE,
    _acl_keys,
    _grantees,
    _privilege_entries,
)
from tests.test_migration_0027 import (
    _ALTER_RE,
    _apply,
    _canon,
    _model_bound,
    _table,
    _targets,
    _unwrap,
)

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

_MIGRATION_NAME: Final = "0028_attachment_token_estimate.sql"
_PREVIOUS_MIGRATION: Final = "0027_attachments.sql"
_VERSION: Final = 28
_ROLE: Final = "admino_app"
_TABLE: Final = "attachments"
_COLUMN: Final = "token_estimate"
_CHECK_NAME: Final = "attachments_token_estimate_check"
# GH-188 audit fix M-3 (contract 12.4): the derived files' bytes of each file.
_DERIVED: Final = "derived_bytes"
_DERIVED_CHECK_NAME: Final = "attachments_derived_bytes_check"
# The columns 0028 adds, in the file's order.
_ADDED: Final = (_COLUMN, _DERIVED)

# admino_app's privileges on attachments after every shipped migration.
_UPDATE_COLUMNS: Final = (
    "message_id",
    "status",
    "failure_reason",
    "page_count",
    "token_estimate",
    "derived_bytes",
    "updated_at",
    "deleted_at",
)
_EXPECTED_PRIVILEGES: Final = frozenset(
    {"select", "insert", "delete", *(f"update({column})" for column in _UPDATE_COLUMNS)}
)

_TYPE_CANON: Final[dict[str, str]] = {
    "integer": "integer",
    "int": "integer",
    "int4": "integer",
    "bigint": "bigint",
    "int8": "bigint",
}
_SCHEMA: Final = r'(?:"?public"?\.)?'
_ADD_COLUMN_RE: Final = re.compile(
    r'add (?:column )?(?:if not exists )?"?(?P<name>\w+)"? (?P<definition>.+)'
)
# Plain literals (no interpolation): the schema prefix is _SCHEMA's.
_UPDATE_RE: Final = re.compile(
    r'update (?:only )?(?:"?public"?\.)?"?(?P<table>\w+)"? set (?P<set>.+?) where (?P<where>.+)'
)
# The statement kinds 0028 may run (masked, normalized).
_ALLOWED_STATEMENTS: Final[dict[str, re.Pattern[str]]] = {
    "alter": re.compile(rf'alter table (?:only )?{_SCHEMA}"?{_TABLE}"? add .+'),
    "grant": re.compile(rf'grant .+ on (?:table )?{_SCHEMA}"?{_TABLE}"? to .+'),
    "update": re.compile(r'update (?:only )?(?:"?public"?\.)?"?attachments"? set .+'),
}
# Fragments 0028 must not contain (top level, DO / function bodies, literals).
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
    "drop": r"drop (?:table|view|schema|type|index)\b",
    "default privileges": r"alter default privileges\b",
    "create": r"create (?:unique )?(?:table|index|view|type|schema)\b",
}
_UPDATE_FRAGMENT: Final = r"update (?:only )?\S+ set\b"

# The contract's requeue, canonical: SET assignments and WHERE conditions.
_REQUEUE: Final = (
    _TABLE,
    frozenset({"status = 'uploaded'", "updated_at = now()"}),
    frozenset({"status = 'ready'"}),
)
_DENIED: Final = "permission denied for table attachments"
_SET_TOKEN_ESTIMATE: Final = "UPDATE attachments SET token_estimate = $1 WHERE id = $2"
_SET_DERIVED_BYTES: Final = "UPDATE attachments SET derived_bytes = $1 WHERE id = $2"
# One past INTEGER's maximum: only a BIGINT column stores it.
_PAST_INT4: Final = 2_147_483_648


# ---------------------------------------------------------------------------
# Helpers: the shipped SQL
# ---------------------------------------------------------------------------


def _migration_path() -> Path:
    return db_mod._MIGRATIONS_DIR / _MIGRATION_NAME


def _raw_sql() -> str:
    return _migration_path().read_text(encoding="utf-8")


def _statements() -> list[str]:
    """The statements 0028 runs (top level and DO blocks), normalized."""
    return _executed(_normalize(_raw_sql()))


def _expr(text: str) -> str:
    """Canonical: 0027's canonical form, comparison operators with one space each side."""
    return _canon(re.sub(r"\s*(>=|<=|<>|!=|=|<|>)\s*", r" \1 ", text))


def _conditions(expression: str) -> frozenset[str]:
    """The top-level AND-ed conditions of an expression, each unwrapped and canonical."""
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
            parts.append(expression[start : token.start()])
            start = token.end()
    parts.append(expression[start:])
    return frozenset(_expr(_unwrap(part)) for part in parts)


def _alter_actions() -> list[tuple[str, str]]:
    """(table, action) for every action of every ALTER TABLE 0028 runs, in order."""
    found: list[tuple[str, str]] = []
    for statement in _statements():
        match = _ALTER_RE.fullmatch(_masked(statement))
        if match is None:
            continue
        for action in _split(statement[match.start("actions") :], ","):
            found.append((match.group("table"), action))
    return found


def _added_columns() -> list[tuple[str, str, _Column]]:
    """(table, column, parsed definition) of every ADD COLUMN action, in order."""
    added = []
    for table, action in _alter_actions():
        match = _ADD_COLUMN_RE.fullmatch(_masked(action))
        if match is None:
            continue
        definition = action[match.start("definition") :]
        added.append((table, match.group("name"), _parse_column(match.group("name"), definition)))
    return added


def _added_column(column: str) -> _Column:
    """The parsed definition of ``attachments.<column>`` as 0028 adds it (exactly once)."""
    found = [
        parsed for table, name, parsed in _added_columns() if (table, name) == (_TABLE, column)
    ]
    assert len(found) == 1, f"{_MIGRATION_NAME} must add {_TABLE}.{column} exactly once"
    return found[0]


def _token_estimate_column() -> _Column:
    return _added_column(_COLUMN)


def _derived_bytes_column() -> _Column:
    return _added_column(_DERIVED)


def _check_lower_bound(column: str = _COLUMN) -> int:
    """The N of ``<column> IS NULL OR <column> >= N`` (the whole CHECK)."""
    checks = _added_column(column).checks
    assert len(checks) == 1, checks
    conditions = _conditions(checks[0][1])
    bounds = [
        int(match.group(1))
        for condition in conditions
        if (
            match := re.fullmatch(
                rf"{column} is null or {column} >= (\d+)",
                condition,
            )
        )
    ]
    assert len(bounds) == 1 == len(conditions), conditions
    return bounds[0]


def _column_shape(column: _Column) -> dict[str, Any]:
    """Everything a column definition says besides its CHECKs, canonical."""
    return {
        "type": _TYPE_CANON.get(column.type_name, column.type_name),
        "not null": column.not_null,
        "explicit null": column.explicit_null,
        "primary key": column.primary_key,
        "identity": column.identity,
        "default": _canonical_default(column),
        "uniques": column.uniques,
        "references": column.references,
        "unexpected": column.unexpected,
    }


def _nullable_without_default(type_name: str) -> dict[str, Any]:
    """The shape of a nullable column of a type with nothing else on it."""
    return {
        "type": type_name,
        "not null": False,
        "explicit null": False,
        "primary key": False,
        "identity": None,
        "default": None,
        "uniques": [],
        "references": [],
        "unexpected": [],
    }


def _acl(up_to: int | None = None) -> dict[tuple[str, str], frozenset[str]]:
    """(table, grantee) -> ACL entries after every shipped migration (up to a version).

    Fails the calling test when version 28 isn't shipped (nothing to replay)."""
    versions: list[int] = []
    acl: dict[tuple[str, str], set[str]] = {}
    for migration in _load_migrations(db_mod._MIGRATIONS_DIR):
        if up_to is not None and migration.version > up_to:
            continue
        versions.append(migration.version)
        for statement in _executed(_normalize(migration.sql)):
            _apply(acl, statement)
    assert _VERSION in versions or (up_to is not None and up_to < _VERSION), (
        f"{_MIGRATION_NAME} is not shipped"
    )
    return {key: frozenset(value) for key, value in acl.items() if value}


def _final_update_columns() -> frozenset[str]:
    """The attachments columns admino_app may UPDATE after every shipped migration."""
    held = _acl().get((_TABLE, _ROLE), frozenset())
    return frozenset(
        match.group(1) for entry in held if (match := re.fullmatch(r"update\((\w+)\)", entry))
    )


def _file_grants() -> list[tuple[frozenset[str], tuple[str, ...], frozenset[str], bool]]:
    """(ACL entries, tables, grantees, grant option) of every GRANT in 0028, nested
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


def _kind(statement: str) -> str:
    """alter / grant / update (the allowed kinds), else the statement itself."""
    masked = _masked(statement)
    for kind, pattern in _ALLOWED_STATEMENTS.items():
        if pattern.fullmatch(masked):
            return kind
    return statement


def _data_writes() -> list[tuple[str, frozenset[str], frozenset[str]]]:
    """(table, SET assignments, WHERE conditions) of every UPDATE 0028 runs."""
    writes = []
    for statement in _statements():
        masked = _masked(statement)
        match = _UPDATE_RE.fullmatch(masked)
        if match is None:
            assert not re.match(r"update\b", masked), (
                f"the test can't read the UPDATE {statement!r}"
            )
            continue
        assignments = frozenset(
            _expr(item) for item in _split(statement[match.start("set") : match.end("set")], ",")
        )
        where = _conditions(statement[match.start("where") : match.end("where")])
        writes.append((match.group("table"), assignments, where))
    return writes


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


class TestMigration0028File:
    """The migration ships as version 28 and is applied by run_migrations after 0027."""

    def test_migration_0028_file_is_the_only_version_28(self) -> None:
        twenty_eights = [
            path.name
            for path in db_mod._MIGRATIONS_DIR.iterdir()
            if (m := db_mod._MIGRATION_FILE_RE.match(path.name)) and int(m.group(1)) == _VERSION
        ]

        assert twenty_eights == [_MIGRATION_NAME]

    async def test_migration_0028_run_migrations_applies_and_records_it(
        self, mock_pool: MagicMock
    ) -> None:
        """With 0001 to 0027 applied, run_migrations executes the file and records 28."""
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

    async def test_migration_0028_runs_after_0027(self, mock_pool: MagicMock) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION - 1)])
        previous = (db_mod._MIGRATIONS_DIR / _PREVIOUS_MIGRATION).read_text(encoding="utf-8")
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        executed = [c.args[0] for c in conn.execute.call_args_list if c.args]
        assert previous in executed
        assert shipped in executed
        assert executed.index(previous) < executed.index(shipped)

    async def test_migration_0028_already_applied_is_not_run_again(
        self, mock_pool: MagicMock
    ) -> None:
        conn = mock_pool._mock_conn
        conn.fetch = AsyncMock(return_value=[{"version": v} for v in range(1, _VERSION + 1)])
        shipped = _raw_sql()

        await db_mod.run_migrations(mock_pool)

        assert not any(c.args and c.args[0] == shipped for c in conn.execute.call_args_list)

    def test_migration_0028_opens_with_a_header_comment(self) -> None:
        """Why the column exists and why ready files are requeued, before any statement."""
        assert len(_header_lines()) >= 3


# ---------------------------------------------------------------------------
# 2. The token_estimate column
# ---------------------------------------------------------------------------


class TestMigration0028Column:
    """ALTER TABLE attachments ADD COLUMN token_estimate INTEGER and (contract 12.4)
    derived_bytes BIGINT, each with its named CHECK."""

    def test_migration_0028_adds_only_the_token_estimate_and_derived_bytes_columns(
        self,
    ) -> None:
        """The file's ALTER TABLE actions add attachments.token_estimate, then
        attachments.derived_bytes: no other column, constraint, owner or trigger change."""
        actions = [(table, _ADD_COLUMN_RE.fullmatch(_masked(a))) for table, a in _alter_actions()]

        assert [(table, m.group("name") if m else None) for table, m in actions] == [
            (_TABLE, _COLUMN),
            (_TABLE, _DERIVED),
        ]

    def test_migration_0028_column_is_a_nullable_integer_without_default(self) -> None:
        """INTEGER (like page_count), NULL until the file is ready, no default, no
        identity, no key, nothing the contract doesn't name."""
        assert _column_shape(_token_estimate_column()) == _nullable_without_default("integer")

    def test_migration_0028_derived_bytes_is_a_nullable_bigint_without_default(self) -> None:
        """Contract 12.4: BIGINT (a byte count, like size_bytes), NULL until the file is
        ready (the quota counts NULL as 0), no default, no identity, no key."""
        assert _column_shape(_derived_bytes_column()) == _nullable_without_default("bigint")

    def test_migration_0028_derived_bytes_check_is_named_and_means_null_or_not_negative(
        self,
    ) -> None:
        """Exactly one CHECK, attachments_derived_bytes_check: NULL or >= 0."""
        checks = _derived_bytes_column().checks

        assert [name for name, _ in checks] == [_DERIVED_CHECK_NAME]
        assert _conditions(checks[0][1]) == frozenset({f"{_DERIVED} is null or {_DERIVED} >= 0"})

    def test_migration_0028_check_is_named_and_means_null_or_not_negative(self) -> None:
        """Exactly one CHECK, attachments_token_estimate_check: NULL or >= 0."""
        checks = _token_estimate_column().checks

        assert [name for name, _ in checks] == [_CHECK_NAME]
        assert _conditions(checks[0][1]) == frozenset({f"{_COLUMN} is null or {_COLUMN} >= 0"})

    def test_migration_0028_check_bound_equals_the_model(self) -> None:
        """AttachmentSummary.token_estimate is ``int | None`` with ge=0: a value the API
        returns always fits the column, and the reverse."""
        import admino.models as models

        summary = models.AttachmentSummary
        field = summary.model_fields.get(_COLUMN)
        assert field is not None, f"AttachmentSummary.{_COLUMN} does not exist (GH-188)"
        sql = {"ge": _check_lower_bound(), "nullable": not _token_estimate_column().not_null}
        python = {
            "ge": _model_bound(summary, _COLUMN, "ge"),
            "nullable": type(None) in typing.get_args(field.annotation),
        }

        assert sql == python


# ---------------------------------------------------------------------------
# 3. Privileges
# ---------------------------------------------------------------------------


class TestMigration0028Privileges:
    """admino_app may write the estimate; nothing else changes."""

    def test_migration_0028_admino_app_privileges_on_attachments_after_every_migration(
        self,
    ) -> None:
        """After every migration up to 0028: SELECT, INSERT, DELETE and UPDATE on exactly
        the eight columns the application writes (derived_bytes included, contract 12.4;
        no table-wide UPDATE, so never id, org_id, chat_id, owner_user_id, filename,
        kind, size_bytes or created_at; no grant option); PUBLIC nothing. (GH-190:
        migration 0030 adds update(active); the set after every shipped migration is
        pinned in tests/test_migration_0030.py.)"""
        acl = _acl(_VERSION)

        assert {
            _ROLE: acl.get((_TABLE, _ROLE), frozenset()),
            "public": acl.get((_TABLE, "public"), frozenset()),
        } == {_ROLE: _EXPECTED_PRIVILEGES, "public": frozenset()}

    def test_migration_0028_adds_update_of_its_two_columns_and_nothing_else(self) -> None:
        """Every (table, grantee) holds after 0028 what it held after 0027, except
        admino_app on attachments, which gains update(token_estimate) and
        update(derived_bytes) only."""
        before = _acl(_VERSION - 1)
        after = _acl(_VERSION)
        expected = dict(before)
        expected[(_TABLE, _ROLE)] = before[(_TABLE, _ROLE)] | {
            f"update({column})" for column in _ADDED
        }

        assert after == expected

    def test_migration_0028_grant_is_one_update_of_both_columns_to_admino_app_only(
        self,
    ) -> None:
        """The file's only GRANT (nested ones included): UPDATE (token_estimate,
        derived_bytes) on attachments, to admino_app alone, without grant option."""
        assert _file_grants() == [
            (
                frozenset({f"update({column})" for column in _ADDED}),
                (_TABLE,),
                frozenset({_ROLE}),
                False,
            )
        ]

    def test_migration_0028_statements_run_in_the_contract_order(self) -> None:
        """The two ALTERs, then the GRANT (PostgreSQL refuses a column privilege on a
        column that doesn't exist yet), then the requeue UPDATE."""
        kinds = [_kind(statement) for statement in _statements()]

        assert kinds == ["alter", "alter", "grant", "update"]


# ---------------------------------------------------------------------------
# 4. The requeue of files that were ready
# ---------------------------------------------------------------------------


class TestMigration0028Requeue:
    """Files ready before this release have no derived files: back to uploaded."""

    def test_migration_0028_requeues_ready_files_as_uploaded(self) -> None:
        """The only data write: UPDATE attachments SET status = 'uploaded', updated_at =
        now() WHERE status = 'ready' (no other filter, no RETURNING)."""
        assert _data_writes() == [_REQUEUE]


# ---------------------------------------------------------------------------
# 5. Nothing else
# ---------------------------------------------------------------------------


class TestMigration0028Scope:
    """Only the column, its grant and the requeue."""

    def test_migration_0028_every_statement_is_part_of_the_contract(self) -> None:
        """Two ALTER TABLEs, one GRANT and one UPDATE, nothing else at the top level or
        in a DO block."""
        kinds = sorted(_kind(statement) for statement in _statements())

        assert kinds == ["alter", "alter", "grant", "update"]

    def test_migration_0028_runs_no_code_or_other_write(self) -> None:
        """No DO block, function, trigger, role, INSERT / DELETE / TRUNCATE / COPY /
        MERGE, REVOKE, CREATE, DROP or default privileges, also not nested in a body or
        an EXECUTE literal; the requeue is the only UPDATE fragment anywhere."""
        fragments = _fragments(_normalize(_raw_sql()))
        offenders = [
            (kind, fragment)
            for fragment in fragments
            for kind, pattern in _FORBIDDEN.items()
            if re.match(pattern, _masked(fragment))
        ]
        updates = [f for f in fragments if re.match(_UPDATE_FRAGMENT, _masked(f))]

        assert fragments, f"{_MIGRATION_NAME} runs nothing"
        assert offenders == []
        assert len(updates) == 1


# ---------------------------------------------------------------------------
# 6. tests/db_fakes.py mirrors 0028
# ---------------------------------------------------------------------------


class TestMigration0028FakeDb:
    """The FakeDb holds what 0028 ships."""

    def test_migration_0028_fake_update_grant_is_the_shipped_one(self) -> None:
        """The fake's attachments UPDATE grant is the cumulative one after every shipped
        migration (0027's six columns plus token_estimate and derived_bytes)."""
        shipped = _final_update_columns()

        assert {column: column in shipped for column in _ADDED} == dict.fromkeys(_ADDED, True)
        assert frozenset(db_fakes.ATTACHMENT_UPDATE_COLUMNS) == shipped

    async def test_migration_0028_fake_token_estimate_check_is_the_shipped_one(self) -> None:
        """None, 0 and a large estimate are stored; -1 is CheckViolationError on the
        shipped CHECK's name and changes nothing."""
        name = _token_estimate_column().checks[0][0]
        outcomes: dict[Any, Any] = {}
        for value in (None, 0, 4195, -1):
            db = FakeDb()
            member = db.add_account(org_id=ORG_ID)
            attachment = db.add_attachment(db.add_chat(member), filename="a.pdf", kind="pdf")
            before = db.attachment_row(attachment)
            assert before is not None
            try:
                await db.pool.execute(_SET_TOKEN_ESTIMATE, value, attachment)
            except asyncpg.CheckViolationError as exc:
                unchanged = db.attachment_row(attachment) == before
                outcomes[value] = (exc.constraint_name, unchanged)
            except asyncpg.InsufficientPrivilegeError as exc:
                outcomes[value] = "denied" if str(exc) == _DENIED else str(exc)
            else:
                row = db.attachment_row(attachment)
                assert row is not None
                outcomes[value] = ("stored", row[_COLUMN])

        assert outcomes == {
            None: ("stored", None),
            0: ("stored", 0),
            4195: ("stored", 4195),
            -1: (name, True),
        }

    async def test_migration_0028_fake_derived_bytes_check_is_the_shipped_one(self) -> None:
        """None, 0 and a value past INTEGER's range (a BIGINT, like the shipped column)
        are stored; -1 is CheckViolationError on the shipped CHECK's name and changes
        nothing."""
        name = _derived_bytes_column().checks[0][0]
        outcomes: dict[Any, Any] = {}
        for value in (None, 0, _PAST_INT4, -1):
            db = FakeDb()
            member = db.add_account(org_id=ORG_ID)
            attachment = db.add_attachment(db.add_chat(member), filename="a.pdf", kind="pdf")
            before = db.attachment_row(attachment)
            assert before is not None
            try:
                await db.pool.execute(_SET_DERIVED_BYTES, value, attachment)
            except asyncpg.CheckViolationError as exc:
                unchanged = db.attachment_row(attachment) == before
                outcomes[value] = (exc.constraint_name, unchanged)
            except asyncpg.InsufficientPrivilegeError as exc:
                outcomes[value] = "denied" if str(exc) == _DENIED else str(exc)
            else:
                row = db.attachment_row(attachment)
                assert row is not None
                outcomes[value] = ("stored", row[_DERIVED])

        assert outcomes == {
            None: ("stored", None),
            0: ("stored", 0),
            _PAST_INT4: ("stored", _PAST_INT4),
            -1: (name, True),
        }

    def test_migration_0028_fake_columns_are_0027s_then_the_added_ones(self) -> None:
        """ADD COLUMN appends: the fake's attachments row has 0027's columns in order,
        then token_estimate and derived_bytes in the file's order (NULL by default).
        GH-190: a later migration's columns (0030's active) follow them; which ones is
        pinned by that migration's test."""
        added = [name for table, name, _ in _added_columns() if table == _TABLE]
        db = FakeDb()
        member = db.add_account(org_id=ORG_ID)
        attachment = db.add_attachment(db.add_chat(member))
        row = db.attachment_row(attachment)
        assert row is not None
        expected = [*(name for name, _ in _table().columns), *added]

        assert added == list(_ADDED)
        assert list(row)[: len(expected)] == expected
        assert (row[_COLUMN], row[_DERIVED]) == (None, None)
