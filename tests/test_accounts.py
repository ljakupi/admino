"""Tests for admino.accounts — the last-admin guard (GH-145).

An organization always has at least one active Org Admin. The single guard that
enforces this, ensure_not_last_active_admin(), runs before a user is demoted,
deactivated or deleted (#164, #167 reuse it). It must run inside the caller's
transaction: it locks the target's row and the org's active Org Admin rows
(SELECT ... FOR UPDATE) so two concurrent demotions can't both pass. It also
verifies that the target belongs to the org, so a mismatched (org_id, user_id)
pair can't slip past it (UserNotInOrgError).

All asyncpg calls are mocked. No real PostgreSQL connections are made.

Security notes:
- Parameterized SQL only: org_id travels as a bind parameter, never in the text.
- No content in errors: LastAdminError and the transaction error carry no IDs.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import asyncpg
import pytest

import admino.accounts as accounts_mod
from admino.accounts import LastAdminError, UserNotInOrgError, ensure_not_last_active_admin

if TYPE_CHECKING:
    from uuid import UUID


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
