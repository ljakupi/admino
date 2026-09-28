"""Tests for admino.accounts — the last-admin guard (GH-145) and the Super Admin bootstrap (GH-150).

An organization always has at least one active Org Admin. The single guard that
enforces this, ensure_not_last_active_admin(), runs before a user is demoted,
deactivated or deleted (#164, #167 reuse it). It must run inside the caller's
transaction: it locks the target's row and the org's active Org Admin rows
(SELECT ... FOR UPDATE) so two concurrent demotions can't both pass. It also
verifies that the target belongs to the org, so a mismatched (org_id, user_id)
pair can't slip past it (UserNotInOrgError).

GH-150 adds the repository side of the create-superadmin CLI: email_exists()
(a case-insensitive duplicate check) and create_super_admin(), which inserts an
active Super Admin and records one user.activate audit event on the same
connection, inside the caller's transaction, so a failed audit write creates
no account. A unique violation (a concurrent create) becomes
DuplicateEmailError, which never carries the email.

GH-154 retires #147's default-org bridge: admino.accounts has neither
DEFAULT_ORG_ID nor ensure_default_org, and no file under src/admino mentions
them (migration 0011 schedules the org for the regular purge instead).

All asyncpg calls are mocked. No real PostgreSQL connections are made. The new
GH-150 names are looked up on the module at call time, so the GH-145 tests in
this file keep collecting and passing before they exist.

Security notes:
- Parameterized SQL only: org_id, the email, the name and the hash travel as
  bind parameters, never in the text.
- No content in errors: LastAdminError, DuplicateEmailError and the
  transaction error carry no IDs, emails, names or hashes.
"""

from __future__ import annotations

import ast
import json
import re
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import asyncpg
import pytest

import admino.accounts as accounts_mod
from admino.accounts import LastAdminError, UserNotInOrgError, ensure_not_last_active_admin
from admino.audit_events import AuditAction, AuditRecordError, TargetType

if TYPE_CHECKING:
    from collections.abc import Iterator


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


async def _target_is_plain_member(_sql: str, _org_id: UUID, user_id: UUID) -> list[dict[str, Any]]:
    """Default fetch result: the target is in the org but isn't an active Org Admin."""
    return [_row(user_id, active_admin=False)]


@pytest.fixture()
def conn() -> MagicMock:
    """A mocked asyncpg connection inside a transaction; the target is a plain org member."""
    connection = MagicMock(spec=asyncpg.Connection)
    connection.is_in_transaction = MagicMock(return_value=True)
    connection.fetch = AsyncMock(side_effect=_target_is_plain_member)
    connection.fetchrow = AsyncMock(return_value=None)
    connection.fetchval = AsyncMock(return_value=None)
    connection.execute = AsyncMock(return_value="")
    return connection


def _row(user_id: UUID, *, active_admin: bool) -> dict[str, Any]:
    """One row of the guard's query: the target's row or an active Org Admin's row."""
    return {"id": user_id, "is_active_admin": active_admin}


def _rows(target: UUID, *, target_is_admin: bool, other_admins: int) -> list[dict[str, Any]]:
    """The target's row plus `other_admins` other active Org Admin rows."""
    others = [_row(uuid4(), active_admin=True) for _ in range(other_admins)]
    return [_row(target, active_admin=target_is_admin), *others]


def _normalized(sql: str) -> str:
    """Collapse whitespace and lowercase, so SQL checks ignore formatting."""
    return re.sub(r"\s+", " ", sql).strip().lower()


def _guard_sql(conn: MagicMock) -> str:
    """Return the normalized SQL text of the guard's single fetch."""
    assert conn.fetch.await_args is not None, "the guard issued no fetch"
    return _normalized(conn.fetch.await_args.args[0])


def _assert_no_ids(message: str, *ids: UUID) -> None:
    """Assert none of the ids appears (canonical or hex form) in a message."""
    for value in ids:
        assert str(value) not in message
        assert value.hex not in message


# ---------------------------------------------------------------------------
# 1. Transaction requirement
# ---------------------------------------------------------------------------


class TestLastAdminGuardTransaction:
    """The guard's row lock only means something inside the caller's transaction."""

    async def test_accounts_guard_outside_transaction_raises_runtime_error(
        self, conn: MagicMock
    ) -> None:
        """Called on a connection that is not in a transaction → RuntimeError."""
        conn.is_in_transaction.return_value = False

        with pytest.raises(RuntimeError):
            await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=uuid4())

    async def test_accounts_guard_outside_transaction_issues_no_query(
        self, conn: MagicMock
    ) -> None:
        """Outside a transaction the guard refuses before touching the database."""
        conn.is_in_transaction.return_value = False

        with pytest.raises(RuntimeError):
            await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=uuid4())

        conn.fetch.assert_not_awaited()
        conn.fetchrow.assert_not_awaited()
        conn.fetchval.assert_not_awaited()
        conn.execute.assert_not_awaited()

    async def test_accounts_guard_outside_transaction_error_has_no_ids(
        self, conn: MagicMock
    ) -> None:
        """The transaction error message carries neither the org_id nor the user_id."""
        conn.is_in_transaction.return_value = False
        org_id = uuid4()
        user_id = uuid4()

        with pytest.raises(RuntimeError) as exc_info:
            await ensure_not_last_active_admin(conn, org_id=org_id, user_id=user_id)

        _assert_no_ids(str(exc_info.value), org_id, user_id)


# ---------------------------------------------------------------------------
# 2. The query
# ---------------------------------------------------------------------------

_REQUIRED_SQL_PATTERNS: list[Any] = [
    pytest.param(r"\bfrom\s+users\b", id="reads-users"),
    pytest.param(r"\borg_id\s*=\s*\$1\b", id="filters-org-id-bind-param"),
    pytest.param(r"\bid\s*=\s*\$2\b", id="includes-target-row-bind-param"),
    pytest.param(r"\brole\s*=\s*'org_admin'", id="filters-org-admin-role"),
    pytest.param(r"\bstatus\s*=\s*'active'", id="filters-active-status"),
    pytest.param(r"\bdeleted_at\s+is\s+null\b", id="excludes-deleted-users"),
    pytest.param(r"\border\s+by\s+id\b", id="locks-in-id-order"),
    pytest.param(r"\bfor\s+update\b", id="locks-rows-for-update"),
]


class TestLastAdminGuardQuery:
    """One parameterized fetch of the target's row and the org's active Org Admins, locked.

    ORDER BY id makes every transaction take the row locks in the same order, so
    concurrent guards serialize instead of deadlocking.
    """

    async def test_accounts_guard_issues_exactly_one_fetch(self, conn: MagicMock) -> None:
        """The guard reads the admins with a single conn.fetch and writes nothing."""
        await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=uuid4())

        assert conn.fetch.await_count == 1
        conn.fetchrow.assert_not_awaited()
        conn.fetchval.assert_not_awaited()
        conn.execute.assert_not_awaited()

    async def test_accounts_guard_binds_org_id_and_user_id(self, conn: MagicMock) -> None:
        """conn.fetch(sql, org_id, user_id): the ids are the $1 and $2 bind parameters."""
        org_id = uuid4()
        user_id = uuid4()

        await ensure_not_last_active_admin(conn, org_id=org_id, user_id=user_id)

        assert conn.fetch.await_args is not None
        assert tuple(conn.fetch.await_args.args[1:]) == (org_id, user_id)

    @pytest.mark.parametrize("pattern", _REQUIRED_SQL_PATTERNS)
    async def test_accounts_guard_sql_selects_active_org_admins_locked(
        self, conn: MagicMock, pattern: str
    ) -> None:
        """The SQL selects the target and the org's active Org Admins, in id order, FOR UPDATE."""
        await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=uuid4())

        assert re.search(pattern, _guard_sql(conn)), f"{pattern!r} not in {_guard_sql(conn)!r}"

    async def test_accounts_guard_sql_has_no_interpolated_ids(self, conn: MagicMock) -> None:
        """Parameterized SQL only: neither id is interpolated into the query text."""
        org_id = uuid4()
        user_id = uuid4()

        await ensure_not_last_active_admin(conn, org_id=org_id, user_id=user_id)

        _assert_no_ids(_guard_sql(conn), org_id, user_id)

    async def test_accounts_guard_takes_ids_as_keyword_only(self, conn: MagicMock) -> None:
        """org_id and user_id are keyword-only, so callers can't swap them by position."""
        with pytest.raises(TypeError):
            await ensure_not_last_active_admin(conn, uuid4(), uuid4())  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 3. The decision
# ---------------------------------------------------------------------------


class TestLastAdminGuardDecision:
    """LastAdminError only when the target is the org's sole active Org Admin."""

    async def test_accounts_guard_sole_active_admin_raises(self, conn: MagicMock) -> None:
        """The target is the only active Org Admin → LastAdminError."""
        user_id = uuid4()
        conn.fetch.side_effect = None
        conn.fetch.return_value = _rows(user_id, target_is_admin=True, other_admins=0)

        with pytest.raises(LastAdminError):
            await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=user_id)

    async def test_accounts_guard_target_with_another_admin_passes(self, conn: MagicMock) -> None:
        """Another active Org Admin remains → no error."""
        user_id = uuid4()
        conn.fetch.side_effect = None
        conn.fetch.return_value = _rows(user_id, target_is_admin=True, other_admins=1)

        result = await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=user_id)

        assert result is None

    async def test_accounts_guard_target_not_an_admin_passes(self, conn: MagicMock) -> None:
        """The target isn't an active Org Admin (editor, viewer, inactive) → no error."""
        user_id = uuid4()
        conn.fetch.side_effect = None
        conn.fetch.return_value = _rows(user_id, target_is_admin=False, other_admins=1)

        result = await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=user_id)

        assert result is None

    async def test_accounts_guard_several_other_admins_passes(self, conn: MagicMock) -> None:
        """Several other active Org Admins and the target isn't one → no error."""
        user_id = uuid4()
        conn.fetch.side_effect = None
        conn.fetch.return_value = _rows(user_id, target_is_admin=False, other_admins=2)

        result = await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=user_id)

        assert result is None

    async def test_accounts_guard_no_active_admins_passes(self, conn: MagicMock) -> None:
        """The org has no active Org Admin and the target isn't one → it can't be the last one."""
        user_id = uuid4()
        conn.fetch.side_effect = None
        conn.fetch.return_value = _rows(user_id, target_is_admin=False, other_admins=0)

        result = await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=user_id)

        assert result is None

    async def test_accounts_guard_error_message_has_no_ids(self, conn: MagicMock) -> None:
        """No content in errors: LastAdminError carries neither the org_id nor the user_id."""
        org_id = uuid4()
        user_id = uuid4()
        conn.fetch.side_effect = None
        conn.fetch.return_value = _rows(user_id, target_is_admin=True, other_admins=0)

        with pytest.raises(LastAdminError) as exc_info:
            await ensure_not_last_active_admin(conn, org_id=org_id, user_id=user_id)

        _assert_no_ids(str(exc_info.value), org_id, user_id)


class TestLastAdminGuardOrgMembership:
    """A target outside org_id is refused, never waved through (security audit, GH-145).

    The query only returns the target's row when it belongs to org_id, so a missing
    target row means another org's user (or no such user).
    """

    async def test_accounts_guard_target_outside_org_raises(self, conn: MagicMock) -> None:
        """The org's sole admin comes back but not the target → UserNotInOrgError."""
        conn.fetch.side_effect = None
        conn.fetch.return_value = [_row(uuid4(), active_admin=True)]

        with pytest.raises(UserNotInOrgError):
            await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=uuid4())

    async def test_accounts_guard_no_rows_raises(self, conn: MagicMock) -> None:
        """No rows at all: the target isn't in the org → UserNotInOrgError."""
        conn.fetch.side_effect = None
        conn.fetch.return_value = []

        with pytest.raises(UserNotInOrgError):
            await ensure_not_last_active_admin(conn, org_id=uuid4(), user_id=uuid4())

    async def test_accounts_guard_not_in_org_is_not_a_last_admin_error(
        self, conn: MagicMock
    ) -> None:
        """The two refusals stay distinct, so callers can answer 404 for another org's user."""
        assert not issubclass(UserNotInOrgError, LastAdminError)
        assert not issubclass(LastAdminError, UserNotInOrgError)

    async def test_accounts_guard_not_in_org_message_has_no_ids(self, conn: MagicMock) -> None:
        """No content in errors: UserNotInOrgError carries neither id."""
        org_id = uuid4()
        user_id = uuid4()
        conn.fetch.side_effect = None
        conn.fetch.return_value = []

        with pytest.raises(UserNotInOrgError) as exc_info:
            await ensure_not_last_active_admin(conn, org_id=org_id, user_id=user_id)

        _assert_no_ids(str(exc_info.value), org_id, user_id)


# ---------------------------------------------------------------------------
# 4. Isolation
# ---------------------------------------------------------------------------

_FORBIDDEN_IMPORT_PREFIXES: tuple[str, ...] = (
    "admino.server",
    "admino.agent",
    "admino.llm",
    "admino.permissions",
    "admino.tools",
    "admino.oauth",
    "admino.main",
)


class TestAccountsIsolation:
    """The account repository stays out of the agent, LLM, server and permission layers."""

    def test_accounts_imports_no_agent_llm_server_or_permission_modules(self) -> None:
        """accounts.py imports nothing from server, agent, llm*, permissions, tools or oauth."""
        tree = ast.parse(Path(accounts_mod.__file__).read_text(encoding="utf-8"))
        imported = [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        ] + [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        ]

        assert [m for m in imported if m.startswith(_FORBIDDEN_IMPORT_PREFIXES)] == []


# ---------------------------------------------------------------------------
# 5. Documentation
# ---------------------------------------------------------------------------


class TestAccountsModuleDocs:
    """The module documents the last-admin rule it enforces."""

    def test_accounts_docstring_describes_last_admin_guard(self) -> None:
        """admino.accounts' docstring mentions the last (Org) Admin guard."""
        doc = (accounts_mod.__doc__ or "").lower()

        assert "last" in doc
        assert "admin" in doc


# ---------------------------------------------------------------------------
# GH-154: #147's default organization is gone
# ---------------------------------------------------------------------------

_SRC_DIR = Path(accounts_mod.__file__).resolve().parent
_DEFAULT_ORG_NAMES: tuple[str, ...] = ("DEFAULT_ORG_ID", "ensure_default_org")


class TestDefaultOrgRemoved:
    """GH-154 deletes the default-org bridge: migration 0011 schedules the org for the
    regular purge, and the code that created it no longer exists."""

    def test_accounts_has_no_default_org_id(self) -> None:
        assert not hasattr(accounts_mod, "DEFAULT_ORG_ID")

    def test_accounts_has_no_ensure_default_org(self) -> None:
        assert not hasattr(accounts_mod, "ensure_default_org")

    def test_accounts_no_src_file_mentions_the_default_org(self) -> None:
        """No file under src/admino (code, docstrings, SQL, resources) names either one."""
        offenders = [
            f"{path.relative_to(_SRC_DIR)}: {name}"
            for path in sorted(_SRC_DIR.rglob("*"))
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
            for name in _DEFAULT_ORG_NAMES
            if name.encode() in path.read_bytes()
        ]

        assert offenders == []


# ---------------------------------------------------------------------------
# GH-150: the Super Admin bootstrap — email_exists() and create_super_admin()
# ---------------------------------------------------------------------------

_SA_EMAIL = "Ops.Admin@Example.ch"
_SA_NAME = "Ada Lovelace-Operator"
_SA_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA"
    "$ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0MDE"
)
# Would break out of a quoted literal if it were ever spliced into the SQL.
_HOSTILE_EMAIL = "x');DROP-TABLE-users;--@example.ch"
_NEW_USER_ID = UUID("5f0c3a1e-8d2b-4c7a-9e61-0b4d2f8a7c35")
_DUPLICATE_MESSAGE = "A user with this email already exists."


@pytest.fixture()
def sa_conn() -> MagicMock:
    """A mocked asyncpg connection inside a transaction; the users insert returns the new id."""
    connection = MagicMock(spec=asyncpg.Connection)
    connection.is_in_transaction = MagicMock(return_value=True)
    connection.fetch = AsyncMock(return_value=[])
    connection.fetchrow = AsyncMock(return_value=None)
    connection.fetchval = AsyncMock(return_value=_NEW_USER_ID)
    connection.execute = AsyncMock(return_value="INSERT 0 1")
    return connection


@pytest.fixture()
def record_mock() -> Iterator[AsyncMock]:
    """Patch admino.audit_events.record (accounts calls it through the module attribute)."""
    with patch("admino.audit_events.record", new_callable=AsyncMock) as mock:
        yield mock


async def _create(conn: MagicMock, **overrides: Any) -> Any:
    """Call accounts.create_super_admin (looked up lazily) with the test account's values."""
    kwargs: dict[str, Any] = {"email": _SA_EMAIL, "name": _SA_NAME, "password_hash": _SA_HASH}
    kwargs.update(overrides)
    return await accounts_mod.create_super_admin(conn, **kwargs)  # type: ignore[attr-defined]


def _insert_columns(sql: str) -> dict[str, str]:
    """Map each column of the users INSERT to its VALUES token (casts stripped).

    Expects ``INSERT INTO users (c1, c2, ...) VALUES (v1, v2, ...) RETURNING id``.
    """
    match = re.search(
        r"insert\s+into\s+users\s*\(([^)]*)\)\s*values\s*\(([^)]*)\)\s*returning\s+id\b",
        _normalized(sql),
    )
    assert match is not None, f"not a single-row users INSERT ... RETURNING id: {sql!r}"
    columns = [column.strip() for column in match.group(1).split(",")]
    values = [re.sub(r"\s*::\s*\w+$", "", value.strip()) for value in match.group(2).split(",")]
    assert len(columns) == len(values), sql
    return dict(zip(columns, values, strict=True))


def _audit_row(conn: MagicMock) -> dict[str, Any]:
    """Map the columns of the one INSERT INTO audit_events on conn to their bind arguments."""
    inserts = [
        call
        for call in conn.execute.await_args_list
        if re.search(r"insert\s+into\s+audit_events", _normalized(call.args[0]))
    ]
    assert len(inserts) == 1, conn.execute.await_args_list
    sql, *args = inserts[0].args
    match = re.search(r"\(([^)]*)\)\s*values\s*\((.*)\)", _normalized(sql))
    assert match is not None, sql
    columns = [column.strip() for column in match.group(1).split(",")]
    values = [value.strip() for value in match.group(2).split(",")]
    row: dict[str, Any] = {}
    for column, value in zip(columns, values, strict=True):
        placeholder = re.fullmatch(r"\$(\d+)(?:\s*::\s*\w+)?", value)
        assert placeholder is not None, value
        row[column] = args[int(placeholder.group(1)) - 1]
    return row


class TestDuplicateEmailError:
    """The refusal for an email that is already taken carries no email."""

    def test_accounts_duplicate_email_error_has_fixed_message(self) -> None:
        """DuplicateEmailError() → 'A user with this email already exists.'."""
        error = accounts_mod.DuplicateEmailError()  # type: ignore[attr-defined]

        assert str(error) == _DUPLICATE_MESSAGE

    def test_accounts_duplicate_email_error_is_a_distinct_exception(self) -> None:
        """It's an Exception of its own, not one of the last-admin guard's refusals."""
        error_cls = accounts_mod.DuplicateEmailError  # type: ignore[attr-defined]

        assert issubclass(error_cls, Exception)
        assert not issubclass(error_cls, LastAdminError | UserNotInOrgError)


_EMAIL_EXISTS_SQL_PATTERNS: list[Any] = [
    pytest.param(r"\bfrom\s+users\b", id="reads-users"),
    pytest.param(
        r"\blower\(\s*email\s*\)\s*=\s*lower\(\s*\$1\s*\)", id="case-insensitive-bind-param"
    ),
]


class TestEmailExists:
    """email_exists(): one parameterized, case-insensitive lookup of the users table.

    It mirrors the users_email_lower_key unique index (lower(email)), so
    'Ops.Admin@Example.ch' is found when 'ops.admin@example.ch' exists.
    """

    async def test_accounts_email_exists_issues_exactly_one_fetchval(
        self, sa_conn: MagicMock
    ) -> None:
        """One conn.fetchval and nothing else: no writes, no other reads."""
        await accounts_mod.email_exists(sa_conn, _SA_EMAIL)  # type: ignore[attr-defined]

        assert sa_conn.fetchval.await_count == 1
        sa_conn.fetch.assert_not_awaited()
        sa_conn.fetchrow.assert_not_awaited()
        sa_conn.execute.assert_not_awaited()

    async def test_accounts_email_exists_binds_email_as_only_parameter(
        self, sa_conn: MagicMock
    ) -> None:
        """fetchval(sql, email): the email is the single bind parameter, passed as given."""
        await accounts_mod.email_exists(sa_conn, _SA_EMAIL)  # type: ignore[attr-defined]

        assert sa_conn.fetchval.await_args is not None
        assert tuple(sa_conn.fetchval.await_args.args[1:]) == (_SA_EMAIL,)

    @pytest.mark.parametrize("pattern", _EMAIL_EXISTS_SQL_PATTERNS)
    async def test_accounts_email_exists_sql_matches_case_insensitively(
        self, sa_conn: MagicMock, pattern: str
    ) -> None:
        """The SQL compares lower(email) = lower($1) on the users table."""
        await accounts_mod.email_exists(sa_conn, _SA_EMAIL)  # type: ignore[attr-defined]

        assert sa_conn.fetchval.await_args is not None
        sql = _normalized(sa_conn.fetchval.await_args.args[0])
        assert re.search(pattern, sql), f"{pattern!r} not in {sql!r}"

    async def test_accounts_email_exists_sql_has_no_interpolated_email(
        self, sa_conn: MagicMock
    ) -> None:
        """Parameterized SQL only: a hostile email never reaches the query text."""
        await accounts_mod.email_exists(sa_conn, _HOSTILE_EMAIL)  # type: ignore[attr-defined]

        assert sa_conn.fetchval.await_args is not None
        sql = sa_conn.fetchval.await_args.args[0]
        assert _HOSTILE_EMAIL.lower() not in sql.lower()
        assert "drop-table" not in sql.lower()

    @pytest.mark.parametrize(
        ("fetched", "expected"),
        [
            pytest.param(True, True, id="exists-true"),
            pytest.param(1, True, id="select-1-row"),
            pytest.param(False, False, id="exists-false"),
            pytest.param(None, False, id="no-row"),
            pytest.param(0, False, id="count-zero"),
        ],
    )
    async def test_accounts_email_exists_returns_a_bool(
        self, sa_conn: MagicMock, fetched: object, expected: bool
    ) -> None:
        """The fetched value becomes a real bool (True/False), whatever the query returns."""
        sa_conn.fetchval.return_value = fetched

        result = await accounts_mod.email_exists(sa_conn, _SA_EMAIL)  # type: ignore[attr-defined]

        assert result is expected

    async def test_accounts_email_exists_accepts_the_pool(self, mock_pool: MagicMock) -> None:
        """The CLI checks before its transaction, so the pool works as the executor too."""
        mock_pool.fetchval.return_value = True

        result = await accounts_mod.email_exists(mock_pool, _SA_EMAIL)  # type: ignore[attr-defined]

        assert result is True
        assert mock_pool.fetchval.await_args is not None
        assert tuple(mock_pool.fetchval.await_args.args[1:]) == (_SA_EMAIL,)


class TestCreateSuperAdminTransaction:
    """create_super_admin() must run inside the caller's transaction (insert + audit together)."""

    async def test_accounts_create_super_admin_outside_transaction_raises(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """A connection that is not in a transaction → RuntimeError."""
        sa_conn.is_in_transaction.return_value = False

        with pytest.raises(RuntimeError):
            await _create(sa_conn)

    async def test_accounts_create_super_admin_outside_transaction_issues_no_query(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """Outside a transaction nothing is inserted and nothing is audited."""
        sa_conn.is_in_transaction.return_value = False

        with pytest.raises(RuntimeError):
            await _create(sa_conn)

        sa_conn.fetchval.assert_not_awaited()
        sa_conn.fetch.assert_not_awaited()
        sa_conn.fetchrow.assert_not_awaited()
        sa_conn.execute.assert_not_awaited()
        record_mock.assert_not_awaited()

    async def test_accounts_create_super_admin_outside_transaction_error_has_no_content(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """The transaction error carries neither the email, the name nor the hash."""
        sa_conn.is_in_transaction.return_value = False

        with pytest.raises(RuntimeError) as exc_info:
            await _create(sa_conn)

        message = str(exc_info.value)
        assert _SA_EMAIL not in message
        assert _SA_NAME not in message
        assert _SA_HASH not in message


class TestCreateSuperAdminInsert:
    """One parameterized INSERT of an active Super Admin (no org, no role), RETURNING id."""

    async def test_accounts_create_super_admin_inserts_with_one_fetchval(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """The users row is written by a single conn.fetchval; nothing else touches conn."""
        await _create(sa_conn)

        assert sa_conn.fetchval.await_count == 1
        sa_conn.fetch.assert_not_awaited()
        sa_conn.fetchrow.assert_not_awaited()
        sa_conn.execute.assert_not_awaited()

    async def test_accounts_create_super_admin_binds_email_name_hash_in_order(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """fetchval(sql, email, name, password_hash): the three values are $1, $2, $3."""
        await _create(sa_conn)

        assert sa_conn.fetchval.await_args is not None
        assert tuple(sa_conn.fetchval.await_args.args[1:]) == (_SA_EMAIL, _SA_NAME, _SA_HASH)

    @pytest.mark.parametrize(
        ("column", "value"),
        [
            pytest.param("email", "$1", id="email-is-bind-1"),
            pytest.param("name", "$2", id="name-is-bind-2"),
            pytest.param("password_hash", "$3", id="hash-is-bind-3"),
            pytest.param("kind", "'super_admin'", id="kind-super-admin"),
            pytest.param("status", "'active'", id="status-active"),
        ],
    )
    async def test_accounts_create_super_admin_sql_sets_super_admin_columns(
        self, sa_conn: MagicMock, record_mock: AsyncMock, column: str, value: str
    ) -> None:
        """INSERT INTO users (...) VALUES (...) RETURNING id, with the fixed kind and status."""
        await _create(sa_conn)

        assert sa_conn.fetchval.await_args is not None
        columns = _insert_columns(sa_conn.fetchval.await_args.args[0])
        assert columns.get(column) == value, columns

    @pytest.mark.parametrize("column", ["org_id", "role"])
    async def test_accounts_create_super_admin_sql_leaves_org_and_role_null(
        self, sa_conn: MagicMock, record_mock: AsyncMock, column: str
    ) -> None:
        """A Super Admin has no org and no role: the column is omitted or set to NULL."""
        await _create(sa_conn)

        assert sa_conn.fetchval.await_args is not None
        columns = _insert_columns(sa_conn.fetchval.await_args.args[0])
        assert columns.get(column, "null") == "null", columns

    async def test_accounts_create_super_admin_sql_has_no_interpolated_content(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """Parameterized SQL only: neither the email, the name nor the hash is in the text."""
        await _create(sa_conn, email=_HOSTILE_EMAIL)

        assert sa_conn.fetchval.await_args is not None
        sql = sa_conn.fetchval.await_args.args[0].lower()
        assert _HOSTILE_EMAIL.lower() not in sql
        assert "drop-table" not in sql
        assert _SA_NAME.lower() not in sql
        assert _SA_HASH.lower() not in sql

    async def test_accounts_create_super_admin_returns_the_new_id(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """The id RETURNING hands back is the function's result."""
        result = await _create(sa_conn)

        assert result == _NEW_USER_ID

    async def test_accounts_create_super_admin_takes_values_as_keyword_only(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """email, name and password_hash are keyword-only, so they can't be swapped by position."""
        with pytest.raises(TypeError):
            await accounts_mod.create_super_admin(  # type: ignore[attr-defined]
                sa_conn, _SA_EMAIL, _SA_NAME, _SA_HASH
            )

        sa_conn.fetchval.assert_not_awaited()


class TestCreateSuperAdminAudit:
    """One user.activate event by the operator, on the same connection, after the insert."""

    async def test_accounts_create_super_admin_records_one_audit_event(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """audit_events.record is awaited exactly once."""
        await _create(sa_conn)

        assert record_mock.await_count == 1

    async def test_accounts_create_super_admin_audits_on_the_same_connection(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """The event is written through the insert's connection, i.e. in its transaction."""
        await _create(sa_conn)

        assert record_mock.await_args is not None
        assert record_mock.await_args.args == (sa_conn,)

    @pytest.mark.parametrize(
        ("field", "expected"),
        [
            pytest.param("action", AuditAction.USER_ACTIVATE, id="user-activate"),
            pytest.param("actor_kind", "operator", id="operator"),
            pytest.param("actor_user_id", None, id="no-actor-user"),
            pytest.param("org_id", None, id="no-org"),
            pytest.param("target_type", TargetType.USER, id="targets-a-user"),
        ],
    )
    async def test_accounts_create_super_admin_audit_event_fields(
        self, sa_conn: MagicMock, record_mock: AsyncMock, field: str, expected: object
    ) -> None:
        """user.activate, actor_kind operator (no user id), no org, target type user."""
        await _create(sa_conn)

        assert record_mock.await_args is not None
        kwargs = record_mock.await_args.kwargs
        assert field in kwargs, kwargs
        assert kwargs[field] == expected

    async def test_accounts_create_super_admin_audit_targets_the_new_user(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """target_ids is exactly [the id the insert returned]."""
        await _create(sa_conn)

        assert record_mock.await_args is not None
        assert list(record_mock.await_args.kwargs["target_ids"]) == [_NEW_USER_ID]

    async def test_accounts_create_super_admin_audits_after_the_insert(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """The users row is inserted before the event is recorded."""
        inserts_at_record_time: list[int] = []

        async def _spy(*_args: Any, **_kwargs: Any) -> None:
            inserts_at_record_time.append(sa_conn.fetchval.await_count)

        record_mock.side_effect = _spy

        await _create(sa_conn)

        assert inserts_at_record_time == [1]

    async def test_accounts_create_super_admin_audit_event_has_no_content(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """Content-free: no argument of the event carries the email, the name or the hash."""
        await _create(sa_conn)

        assert record_mock.await_args is not None
        passed = repr(record_mock.await_args.args[1:]) + repr(record_mock.await_args.kwargs)
        assert _SA_EMAIL not in passed
        assert _SA_EMAIL.lower() not in passed.lower()
        assert _SA_NAME not in passed
        assert _SA_HASH not in passed

    async def test_accounts_create_super_admin_writes_a_valid_audit_row(
        self, sa_conn: MagicMock
    ) -> None:
        """With the real record(): one audit_events INSERT on conn, accepted by its validation."""
        await _create(sa_conn)

        row = _audit_row(sa_conn)
        assert row["action"] == "user.activate"
        assert row["actor_kind"] == "operator"
        assert row["actor_user_id"] is None
        assert row["org_id"] is None
        assert row["target_type"] == "user"
        assert json.loads(row["target_ids"]) == [str(_NEW_USER_ID)]

    async def test_accounts_create_super_admin_audit_failure_propagates(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """AuditRecordError from record() propagates unchanged, so the transaction rolls back."""
        record_mock.side_effect = AuditRecordError()

        with pytest.raises(AuditRecordError):
            await _create(sa_conn)

    async def test_accounts_create_super_admin_failed_audit_write_raises(
        self, sa_conn: MagicMock
    ) -> None:
        """With the real record(): a failing audit INSERT surfaces as AuditRecordError."""
        sa_conn.execute.side_effect = asyncpg.PostgresError("audit insert failed")

        with pytest.raises(AuditRecordError):
            await _create(sa_conn)


class TestCreateSuperAdminDuplicate:
    """A unique violation on insert (a concurrent create) gets the same refusal as the check."""

    @staticmethod
    def _unique_violation() -> asyncpg.UniqueViolationError:
        """The driver's error, whose detail repeats the email (as PostgreSQL's does)."""
        return asyncpg.UniqueViolationError(
            "duplicate key value violates unique constraint users_email_lower_key "
            f"DETAIL: Key (lower(email))=({_SA_EMAIL.lower()}) already exists."
        )

    async def test_accounts_create_super_admin_unique_violation_raises_duplicate(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """asyncpg.UniqueViolationError from the insert → DuplicateEmailError."""
        sa_conn.fetchval.side_effect = self._unique_violation()

        with pytest.raises(accounts_mod.DuplicateEmailError):  # type: ignore[attr-defined]
            await _create(sa_conn)

    async def test_accounts_create_super_admin_duplicate_message_has_no_email(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """The refusal is the fixed message; the driver's detail (with the email) is dropped."""
        sa_conn.fetchval.side_effect = self._unique_violation()

        with pytest.raises(accounts_mod.DuplicateEmailError) as exc_info:  # type: ignore[attr-defined]
            await _create(sa_conn)

        assert str(exc_info.value) == _DUPLICATE_MESSAGE
        assert _SA_EMAIL.lower() not in str(exc_info.value).lower()

    async def test_accounts_create_super_admin_duplicate_suppresses_driver_error(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """Raised ``from None``: no cause, context suppressed, no email in the traceback."""
        sa_conn.fetchval.side_effect = self._unique_violation()

        with pytest.raises(accounts_mod.DuplicateEmailError) as exc_info:  # type: ignore[attr-defined]
            await _create(sa_conn)

        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__ is True
        formatted = "".join(traceback.format_exception(exc_info.value))
        assert _SA_EMAIL.lower() not in formatted.lower()

    async def test_accounts_create_super_admin_duplicate_records_no_audit_event(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """Nothing was created, so nothing is audited."""
        sa_conn.fetchval.side_effect = self._unique_violation()

        with pytest.raises(accounts_mod.DuplicateEmailError):  # type: ignore[attr-defined]
            await _create(sa_conn)

        record_mock.assert_not_awaited()

    async def test_accounts_create_super_admin_other_db_errors_propagate_unchanged(
        self, sa_conn: MagicMock, record_mock: AsyncMock
    ) -> None:
        """Only a unique violation is a duplicate: a CHECK violation propagates as itself."""
        sa_conn.fetchval.side_effect = asyncpg.CheckViolationError("check failed")

        with pytest.raises(asyncpg.CheckViolationError) as exc_info:
            await _create(sa_conn)

        assert not isinstance(
            exc_info.value,
            accounts_mod.DuplicateEmailError,  # type: ignore[attr-defined]
        )
        record_mock.assert_not_awaited()
