"""Tests for admino.org_users: listing and changing the users of an org (GH-164).

``list_org_users(pool, *, actor)`` returns the caller's org's users and
``update_org_user(pool, *, actor, user_id, patch, ip)`` changes one user's role,
name or email (``admino.models.OrgUserPatch``). Both return
``admino.models.OrgUserSummary`` values. (Deactivate, reactivate, delete and the
admin-triggered password reset are covered in another file.)

What these tests pin down:
- Authorization comes first, through ``access.can``: listing needs
  ``ORG_USERS_VIEW``; a change needs ``ORG_USERS_MANAGE``, plus
  ``ORG_USERS_ROLE_CHANGE`` when the patch carries a role. An Editor, a Viewer or a
  Super Admin gets ``PermissionError`` before any statement runs.
- The list holds the actor's org's ``active`` and ``deactivated`` users only (no
  invited account, no deleted row, no Super Admin, no other org's user), with
  name, email, role, status, created_at and last_login_at, ordered by created_at,
  then id. It is one query with the org id as a bind parameter.
- A role change is audited as ``user.role_change`` (``{"old_role", "new_role"}``);
  demoting to Viewer deletes nothing (sessions, OAuth connections, memory stay).
- The last-admin guard (``accounts.ensure_not_last_active_admin``, inside the
  transaction, before the change) refuses to demote the org's last active Org
  Admin with ``accounts.LastAdminError``: nothing changes, nothing is audited.
- A name or email change is audited as ``user.profile_change``
  (``{"name_changed", "email_changed"}``); a role and a profile change in one patch
  give both events, role first. Values equal to the stored ones are no change:
  no audit row, nothing queued.
- An email change queues one ``email_changed`` email (params: the org name only)
  to the OLD address and deletes the user's live reset token, in the same
  transaction. A taken email (any user on the platform, any capitalization) is
  ``accounts.DuplicateEmailError``: the whole transaction rolls back, then one
  ``user.profile_change`` row with ``{"email_taken": True}`` is recorded.
- Tenant isolation: another org's user, an unknown id, an invited account, a
  deleted account or a Super Admin is ``accounts.UserNotInOrgError``.
- Fail closed: an audit failure raises ``audit_events.AuditRecordError`` and
  nothing is changed or queued.
- No name or email in any audit row or log line; the module imports no server,
  agent, LLM, tools or OAuth module and builds no SQL from values.

All database calls go to the in-memory fake of tests/db_fakes.py. No real
PostgreSQL connections are made.

Security notes:
- Tenant isolation at the data layer: every statement is scoped by the actor's
  org; a user of another org is "not found", never "forbidden".
- Content-free audit and logs (tracker #139 section 5): IDs, role tokens and bools only.
"""

from __future__ import annotations

import ast
import copy
import inspect
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from admino import access, accounts, org_users
from admino.access import Capability, Principal
from admino.audit_events import AuditRecordError
from admino.models import OrgUserPatch, OrgUserSummary
from tests.db_fakes import (
    ORG_ID,
    ORG_ID_PARAM_RE,
    ORG_NAME,
    OTHER_ORG_ID,
    OTHER_ORG_NAME,
    Call,
    FakeDb,
)

if TYPE_CHECKING:
    from collections.abc import Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "203.0.113.7"
_CREATED = datetime(2026, 3, 4, 9, 30, tzinfo=UTC)
_LAST_LOGIN = datetime(2026, 9, 30, 17, 5, 12, tzinfo=UTC)
_OLD_EMAIL = "old.address.marker@example.test"
_NEW_EMAIL = "new.address.marker@example.test"
_OLD_NAME = "Oldname Markerperson"
_NEW_NAME = "Newname Markerperson"
_TAKEN_EMAIL = "taken.address.marker@example.test"
_SRC = Path(inspect.getfile(org_users))
_SQL_KEYWORD_RE = re.compile(
    r"\b(?:select\b.*\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|where)\b",
    re.IGNORECASE | re.DOTALL,
)
_DB_METHODS = frozenset({"execute", "executemany", "fetch", "fetchrow", "fetchval"})


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


def _principal(db: FakeDb, user_id: uuid.UUID) -> Principal:
    """The Principal a resolved session of this stored account would carry."""
    account = db.users[user_id]
    if account["kind"] == "super_admin":
        return Principal(user_id=user_id, kind="super_admin")
    return Principal(user_id=user_id, kind="member", org_id=account["org_id"], role=account["role"])


def _admin(db: FakeDb, org_id: uuid.UUID = ORG_ID, **fields: Any) -> tuple[uuid.UUID, Principal]:
    """A stored active Org Admin of the org and their Principal."""
    admin_id = db.add_account(role="org_admin", org_id=org_id, **fields)
    return admin_id, _principal(db, admin_id)


def _actor(db: FakeDb, who: str) -> Principal:
    """A stored Editor, Viewer or Super Admin of ORG_ID and their Principal."""
    if who == "super_admin":
        return _principal(db, db.add_account(kind="super_admin", role=None))
    return _principal(db, db.add_account(role=who))


async def _update(
    db: FakeDb, actor: Any, user_id: uuid.UUID, *, ip: str | None = _IP, **fields: Any
) -> Any:
    return await org_users.update_org_user(
        db.pool, actor=actor, user_id=user_id, patch=OrgUserPatch(**fields), ip=ip
    )


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of every table these functions could touch."""
    return copy.deepcopy(
        {
            "users": db.users,
            "orgs": db.orgs,
            "invitations": db.invitations,
            "tokens": db.tokens,
            "sessions": db.sessions,
            "outbox": db.outbox,
            "audit": db.audit,
            "oauth_tokens": db.oauth_tokens,
            "memory": db.memory,
            "user_settings": db.user_settings,
        }
    )


def _audit_view(row: dict[str, Any]) -> dict[str, Any]:
    """The comparable columns of a stored audit row (ids as strings)."""

    def text(value: Any) -> str | None:
        return None if value is None else str(value)

    return {
        "action": row["action"],
        "actor_kind": row["actor_kind"],
        "actor_user_id": text(row["actor_user_id"]),
        "org_id": text(row["org_id"]),
        "target_type": row["target_type"],
        "target_ids": row["target_ids"],
        "ip": row["ip"],
        "metadata": row["metadata"],
    }


def _expected_audit(
    action: str,
    actor_id: uuid.UUID,
    target: uuid.UUID,
    metadata: dict[str, Any],
    *,
    org_id: uuid.UUID = ORG_ID,
    ip: str | None = _IP,
) -> dict[str, Any]:
    return {
        "action": action,
        "actor_kind": "member",
        "actor_user_id": str(actor_id),
        "org_id": str(org_id),
        "target_type": "user",
        "target_ids": [str(target)],
        "ip": ip,
        "metadata": metadata,
    }


def _summary_of(db: FakeDb, user_id: uuid.UUID) -> dict[str, Any]:
    """What OrgUserSummary.model_dump() must give for a stored account."""
    account = db.users[user_id]
    return {
        "id": user_id,
        "name": account["name"],
        "email": account["email"],
        "role": account["role"],
        "status": account["status"],
        "created_at": account["created_at"],
        "last_login_at": account["last_login_at"],
    }


def _is_write(call: Call) -> bool:
    """A statement that changes data, or the last-admin guard's locking read."""
    return bool(re.match(r"(?:insert|update|delete) ", call.normalized)) or (
        "is_active_admin" in call.normalized
    )


def _guard_calls(db: FakeDb) -> list[Call]:
    return [call for call in db.calls if "is_active_admin" in call.normalized]


def _spy_can(
    monkeypatch: pytest.MonkeyPatch, decide: Callable[[Principal, Capability], bool] | None = None
) -> list[Capability]:
    """Replace access.can (and org_users.can, if imported by name); record each capability."""
    real = access.can
    seen: list[Capability] = []

    def spy(principal: Any, capability: Any) -> bool:
        seen.append(capability)
        if decide is not None:
            return decide(principal, capability)
        return real(principal, capability)

    monkeypatch.setattr(access, "can", spy)
    if hasattr(org_users, "can"):
        monkeypatch.setattr(org_users, "can", spy)
    return seen


def _deny(denied: Capability) -> Callable[[Principal, Capability], bool]:
    """A decision that refuses one capability and asks the real matrix for the rest."""
    real = access.can

    def decide(principal: Principal, capability: Capability) -> bool:
        return capability is not denied and real(principal, capability)

    return decide


# ---------------------------------------------------------------------------
# 1. Module surface
# ---------------------------------------------------------------------------


class TestModuleSurface:
    """Signatures, constants and the module's hygiene."""

    def test_org_users_list_signature_is_keyword_only(self) -> None:
        """list_org_users(pool, *, actor), a coroutine function."""
        params = list(inspect.signature(org_users.list_org_users).parameters.values())

        assert [p.name for p in params] == ["pool", "actor"]
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params[1:])
        assert inspect.iscoroutinefunction(org_users.list_org_users)

    def test_org_users_update_signature_is_keyword_only(self) -> None:
        """update_org_user(pool, *, actor, user_id, patch, ip), a coroutine function."""
        params = list(inspect.signature(org_users.update_org_user).parameters.values())

        assert [p.name for p in params] == ["pool", "actor", "user_id", "patch", "ip"]
        assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in params[1:])
        assert inspect.iscoroutinefunction(org_users.update_org_user)

    def test_org_users_fixed_messages(self) -> None:
        assert org_users.USER_NOT_FOUND_MESSAGE == "User not found"
        assert org_users.INVALID_USER_STATUS_MESSAGE == (
            "This change isn't possible in the user's current status."
        )

    def test_org_users_invalid_status_error_carries_the_fixed_message(self) -> None:
        error = org_users.InvalidUserStatusError()

        assert isinstance(error, Exception)
        assert str(error) == org_users.INVALID_USER_STATUS_MESSAGE

    def test_org_users_module_docstring_has_security_notes(self) -> None:
        assert org_users.__doc__ is not None
        assert "security" in org_users.__doc__.lower()

    def test_org_users_imports_no_forbidden_module(self) -> None:
        """Never the server, agent, LLM, tools, OAuth or permission engine modules, and
        no FastAPI/Starlette (a service layer)."""
        modules = _imported_modules()
        forbidden = [
            module
            for module in modules
            if module in {"admino.server", "admino.agent", "admino.oauth", "admino.permissions"}
            or module.startswith(("admino.llm", "admino.tools", "fastapi", "starlette"))
        ]

        assert forbidden == []

    def test_org_users_imports_only_the_allowed_admino_modules(self) -> None:
        """The contract's list: accounts, audit_events, email_outbox, invitations,
        password_reset, sessions, access, models, email_templates."""
        allowed = {
            "accounts",
            "audit_events",
            "email_outbox",
            "invitations",
            "password_reset",
            "sessions",
            "access",
            "models",
            "email_templates",
        }
        admino_modules = {
            module.split(".")[1]
            for module in _imported_modules()
            if module.startswith("admino.") and module.count(".") >= 1
        }

        assert admino_modules <= allowed, admino_modules

    def test_org_users_builds_no_sql_by_string_formatting(self) -> None:
        """No f-string, %-format, concatenation or .format() produces SQL text."""
        assert _formatted_sql_sites() == []

    def test_org_users_passes_only_constant_sql_to_the_driver(self) -> None:
        """The SQL argument of every execute/fetch* call is a name or a literal, never an
        f-string, a concatenation or a call result."""
        tree = ast.parse(_SRC.read_text(encoding="utf-8"))
        dynamic = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _DB_METHODS
            and node.args
            and not isinstance(node.args[0], ast.Name | ast.Attribute | ast.Constant)
        ]

        assert dynamic == []

    def test_org_users_makes_no_dynamic_code_calls(self) -> None:
        tree = ast.parse(_SRC.read_text(encoding="utf-8"))
        calls = [
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "compile", "__import__"}
        ]

        assert calls == []


def _imported_modules() -> list[str]:
    """Every module org_users.py imports (``from admino import x`` gives admino.x)."""
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module == "admino":
                modules += [f"admino.{alias.name}" for alias in node.names]
            else:
                modules.append(node.module)
    return modules


def _formatted_sql_sites() -> list[str]:
    """f-strings, %-formatting, concatenations and .format() calls whose text looks like SQL."""
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    sites: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            text = "".join(
                part.value
                for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            if _SQL_KEYWORD_RE.search(text):
                sites.append(f"line {node.lineno}: f-string")
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod | ast.Add):
            parts = [node.left, node.right]
            if any(
                isinstance(part, ast.Constant)
                and isinstance(part.value, str)
                and _SQL_KEYWORD_RE.search(part.value)
                for part in parts
            ):
                sites.append(f"line {node.lineno}: %-format or concatenation")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
            and _SQL_KEYWORD_RE.search(node.func.value.value)
        ):
            sites.append(f"line {node.lineno}: str.format")
    return sites


# ---------------------------------------------------------------------------
# 2. Authorization: access.can before any statement
# ---------------------------------------------------------------------------

_REFUSED = ["editor", "viewer", "super_admin"]


class TestAuthorization:
    """Org Admin only; a refusal reads and writes nothing."""

    @pytest.mark.parametrize("who", _REFUSED)
    async def test_org_users_list_refused_without_org_users_view(
        self, db: FakeDb, who: str
    ) -> None:
        actor = _actor(db, who)
        db.calls.clear()

        with pytest.raises(PermissionError):
            await org_users.list_org_users(db.pool, actor=actor)

        assert db.calls == []

    @pytest.mark.parametrize("who", _REFUSED)
    @pytest.mark.parametrize(
        "fields",
        [
            pytest.param({"role": "viewer"}, id="role"),
            pytest.param({"name": _NEW_NAME}, id="name"),
            pytest.param({"email": _NEW_EMAIL}, id="email"),
        ],
    )
    async def test_org_users_update_refused_without_org_users_manage(
        self, db: FakeDb, who: str, fields: dict[str, Any]
    ) -> None:
        """PermissionError before any query; the target is untouched."""
        actor = _actor(db, who)
        target = db.add_account(role="editor", email=_OLD_EMAIL, name=_OLD_NAME)
        db.add_reset_token(target)
        before = _state(db)
        db.calls.clear()

        with pytest.raises(PermissionError):
            await _update(db, actor, target, **fields)

        assert db.calls == []
        assert _state(db) == before

    async def test_org_users_list_checks_org_users_view(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An Org Admin denied ORG_USERS_VIEW (all else granted) is refused."""
        _, admin = _admin(db)
        seen = _spy_can(monkeypatch, _deny(Capability.ORG_USERS_VIEW))
        db.calls.clear()

        with pytest.raises(PermissionError):
            await org_users.list_org_users(db.pool, actor=admin)

        assert Capability.ORG_USERS_VIEW in seen
        assert db.calls == []

    async def test_org_users_update_without_role_checks_manage_only(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A name change asks for ORG_USERS_MANAGE, never ORG_USERS_ROLE_CHANGE."""
        _, admin = _admin(db)
        target = db.add_account(role="editor")
        seen = _spy_can(monkeypatch)

        await _update(db, admin, target, name=_NEW_NAME)

        assert Capability.ORG_USERS_MANAGE in seen
        assert Capability.ORG_USERS_ROLE_CHANGE not in seen

    async def test_org_users_update_with_role_checks_manage_and_role_change(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, admin = _admin(db)
        target = db.add_account(role="editor")
        seen = _spy_can(monkeypatch)

        await _update(db, admin, target, role="viewer")

        assert Capability.ORG_USERS_MANAGE in seen
        assert Capability.ORG_USERS_ROLE_CHANGE in seen

    async def test_org_users_update_role_refused_without_role_change(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MANAGE alone isn't enough to change a role: PermissionError, no query."""
        _, admin = _admin(db)
        target = db.add_account(role="editor", name=_OLD_NAME)
        _spy_can(monkeypatch, _deny(Capability.ORG_USERS_ROLE_CHANGE))
        before = _state(db)
        db.calls.clear()

        with pytest.raises(PermissionError):
            await _update(db, admin, target, role="viewer", name=_NEW_NAME)

        assert db.calls == []
        assert _state(db) == before

    async def test_org_users_update_name_allowed_without_role_change(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without a role in the patch, ROLE_CHANGE isn't needed."""
        _, admin = _admin(db)
        target = db.add_account(role="editor", name=_OLD_NAME)
        _spy_can(monkeypatch, _deny(Capability.ORG_USERS_ROLE_CHANGE))

        await _update(db, admin, target, name=_NEW_NAME)

        assert db.users[target]["name"] == _NEW_NAME

    @pytest.mark.parametrize(
        "fields",
        [
            pytest.param({"role": "viewer"}, id="role"),
            pytest.param({"name": _NEW_NAME}, id="name"),
        ],
    )
    async def test_org_users_update_refused_without_manage_even_with_role_change(
        self, db: FakeDb, monkeypatch: pytest.MonkeyPatch, fields: dict[str, Any]
    ) -> None:
        """ROLE_CHANGE alone isn't enough: MANAGE is always required."""
        _, admin = _admin(db)
        target = db.add_account(role="editor", name=_OLD_NAME)
        _spy_can(monkeypatch, _deny(Capability.ORG_USERS_MANAGE))
        db.calls.clear()

        with pytest.raises(PermissionError):
            await _update(db, admin, target, **fields)

        assert db.calls == []


# ---------------------------------------------------------------------------
# 3. list_org_users
# ---------------------------------------------------------------------------


class TestListOrgUsers:
    """The caller's org's active and deactivated users, nothing else."""

    async def test_org_users_list_holds_only_active_and_deactivated_users_of_the_org(
        self, db: FakeDb
    ) -> None:
        admin_id, admin = _admin(db)
        editor = db.add_account(role="editor")
        deactivated = db.add_account(role="viewer", status="deactivated")
        db.add_account(role="viewer", status="invited", name=None, password_hash=None)
        db.add_account(role="editor", deleted_at=datetime.now(UTC) - timedelta(days=2))
        db.add_account(kind="super_admin", role=None)
        db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
        db.add_account(role="editor", org_id=OTHER_ORG_ID)

        users = await org_users.list_org_users(db.pool, actor=admin)

        assert {summary.id for summary in users} == {admin_id, editor, deactivated}

    async def test_org_users_list_of_the_other_org_holds_only_its_users(self, db: FakeDb) -> None:
        """The scope is the actor's org, not a fixed one."""
        db.add_account(role="org_admin")
        db.add_account(role="editor")
        other_admin_id, other_admin = _admin(db, OTHER_ORG_ID)
        other_viewer = db.add_account(role="viewer", org_id=OTHER_ORG_ID)

        users = await org_users.list_org_users(db.pool, actor=other_admin)

        assert {summary.id for summary in users} == {other_admin_id, other_viewer}

    async def test_org_users_list_returns_every_summary_field(self, db: FakeDb) -> None:
        _, admin = _admin(db, created_at=_CREATED - timedelta(days=30))
        target = db.add_account(
            role="viewer",
            status="deactivated",
            email="Mixed.Case@Example.test",
            name="Ada Beispiel",
            created_at=_CREATED,
            last_login_at=_LAST_LOGIN,
        )

        users = await org_users.list_org_users(db.pool, actor=admin)

        summary = next(summary for summary in users if summary.id == target)
        assert isinstance(summary, OrgUserSummary)
        assert type(summary.id) is uuid.UUID
        assert summary.model_dump() == {
            "id": target,
            "name": "Ada Beispiel",
            "email": "Mixed.Case@Example.test",
            "role": "viewer",
            "status": "deactivated",
            "created_at": _CREATED,
            "last_login_at": _LAST_LOGIN,
        }

    async def test_org_users_list_keeps_a_missing_last_login(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db, last_login_at=None)

        users = await org_users.list_org_users(db.pool, actor=admin)

        assert [(summary.id, summary.last_login_at) for summary in users] == [(admin_id, None)]

    async def test_org_users_list_orders_by_created_at_then_id(self, db: FakeDb) -> None:
        """Oldest first; equal created_at by id. Stored in another order on purpose."""
        newest_id, admin = _admin(db, created_at=_CREATED + timedelta(days=5))
        tied = [db.add_account(created_at=_CREATED) for _ in range(3)]
        oldest = db.add_account(created_at=_CREATED - timedelta(days=5))
        # Store the tied rows in descending id order, so insertion order isn't id order.
        for user_id in sorted(tied, reverse=True):
            db.users[user_id] = db.users.pop(user_id)

        users = await org_users.list_org_users(db.pool, actor=admin)

        assert [summary.id for summary in users] == [oldest, *sorted(tied), newest_id]

    async def test_org_users_list_is_a_list_of_summaries(self, db: FakeDb) -> None:
        _, admin = _admin(db)
        db.add_account()

        users = await org_users.list_org_users(db.pool, actor=admin)

        assert isinstance(users, list)
        assert all(isinstance(summary, OrgUserSummary) for summary in users)

    async def test_org_users_list_is_one_query_bound_to_the_actor_org(self, db: FakeDb) -> None:
        """One statement; org_id is a bind parameter, never in the SQL text."""
        admin_id, admin = _admin(db)
        db.calls.clear()

        await org_users.list_org_users(db.pool, actor=admin)

        assert len(db.calls) == 1
        call = db.calls[0]
        match = re.search(ORG_ID_PARAM_RE, call.normalized)
        assert match is not None, call.normalized
        assert str(call.args[int(match.group(1)) - 1]) == str(ORG_ID)
        assert str(ORG_ID) not in call.sql
        assert str(admin_id) not in call.sql

    async def test_org_users_list_never_reads_password_hashes(self, db: FakeDb) -> None:
        _, admin = _admin(db)
        db.calls.clear()

        await org_users.list_org_users(db.pool, actor=admin)

        assert all("password_hash" not in call.normalized for call in db.calls)
        assert all("select *" not in call.normalized for call in db.calls)

    async def test_org_users_list_changes_nothing_and_audits_nothing(self, db: FakeDb) -> None:
        _, admin = _admin(db)
        db.add_account()
        before = _state(db)

        await org_users.list_org_users(db.pool, actor=admin)

        assert _state(db) == before


# ---------------------------------------------------------------------------
# 4. update_org_user: role changes
# ---------------------------------------------------------------------------


_ROLE_CHANGES = [
    pytest.param("editor", "viewer", id="editor-to-viewer"),
    pytest.param("viewer", "editor", id="viewer-to-editor"),
    pytest.param("editor", "org_admin", id="editor-to-org_admin"),
    pytest.param("viewer", "org_admin", id="viewer-to-org_admin"),
    pytest.param("org_admin", "editor", id="second-admin-to-editor"),
]


class TestRoleChange:
    """A role change is stored, returned and audited; it deletes nothing."""

    @pytest.mark.parametrize(("old", "new"), _ROLE_CHANGES)
    async def test_org_users_update_role_is_stored_and_returned(
        self, db: FakeDb, old: str, new: str
    ) -> None:
        _, admin = _admin(db)
        target = db.add_account(
            role=old, email=_OLD_EMAIL, created_at=_CREATED, last_login_at=_LAST_LOGIN
        )

        summary = await _update(db, admin, target, role=new)

        assert db.users[target]["role"] == new
        assert isinstance(summary, OrgUserSummary)
        assert summary.model_dump() == {
            "id": target,
            "name": "Some Person",
            "email": _OLD_EMAIL,
            "role": new,
            "status": "active",
            "created_at": _CREATED,
            "last_login_at": _LAST_LOGIN,
        }

    @pytest.mark.parametrize(("old", "new"), _ROLE_CHANGES)
    async def test_org_users_update_role_records_one_role_change_event(
        self, db: FakeDb, old: str, new: str
    ) -> None:
        admin_id, admin = _admin(db)
        target = db.add_account(role=old)

        await _update(db, admin, target, role=new)

        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit(
                "user.role_change", admin_id, target, {"old_role": old, "new_role": new}
            )
        ]

    async def test_org_users_update_role_audits_a_missing_ip_as_null(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db)
        target = db.add_account(role="editor")

        await _update(db, admin, target, ip=None, role="viewer")

        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit(
                "user.role_change",
                admin_id,
                target,
                {"old_role": "editor", "new_role": "viewer"},
                ip=None,
            )
        ]

    async def test_org_users_update_role_in_another_org_is_audited_there(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db, OTHER_ORG_ID)
        target = db.add_account(role="viewer", org_id=OTHER_ORG_ID)

        await _update(db, admin, target, role="editor")

        assert db.users[target]["role"] == "editor"
        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit(
                "user.role_change",
                admin_id,
                target,
                {"old_role": "viewer", "new_role": "editor"},
                org_id=OTHER_ORG_ID,
            )
        ]

    async def test_org_users_update_role_to_viewer_deletes_nothing(self, db: FakeDb) -> None:
        """#162: the role is read on every request; sessions, connections, memory, settings
        and a pending reset token are kept."""
        _, admin = _admin(db)
        target = db.add_account(role="editor")
        db.open_session(target)
        db.open_session(target, last_seen_ago=timedelta(minutes=5))
        db.add_oauth_token(target, "google", encrypted_refresh_token="enc-google")
        db.add_oauth_token(target, "microsoft", encrypted_refresh_token="enc-microsoft")
        db.add_memory(target, "favourite", "tea")
        db.add_user_settings(target)
        db.add_reset_token(target)
        before = _state(db)

        await _update(db, admin, target, role="viewer")

        after = _state(db)
        for table in ("sessions", "oauth_tokens", "memory", "user_settings", "tokens", "outbox"):
            assert after[table] == before[table], table
        assert db.matching(r"^delete from") == []

    async def test_org_users_update_role_queues_no_email(self, db: FakeDb) -> None:
        _, admin = _admin(db)
        target = db.add_account(role="editor")

        await _update(db, admin, target, role="viewer")

        assert db.outbox == []

    async def test_org_users_update_role_change_runs_in_one_committed_transaction(
        self, db: FakeDb
    ) -> None:
        """The guard, the UPDATE and the audit INSERT share one connection and transaction."""
        _, admin = _admin(db)
        target = db.add_account(role="editor")
        db.calls.clear()

        await _update(db, admin, target, role="viewer")

        writes = [call for call in db.calls if _is_write(call)]
        assert db.matching(r"^update users\b")
        assert db.matching(r"^insert into audit_events\b")
        assert len({(call.via, call.tx) for call in writes}) == 1
        assert writes[0].tx is not None
        assert db.transactions == [(writes[0].tx, "commit")]

    async def test_org_users_update_sql_never_holds_ids_names_or_emails(self, db: FakeDb) -> None:
        """Values are bind parameters: no id, name or email in any statement's text."""
        admin_id, admin = _admin(db)
        target = db.add_account(role="editor", email=_OLD_EMAIL, name=_OLD_NAME)
        db.add_reset_token(target)
        db.calls.clear()

        await _update(db, admin, target, role="viewer", name=_NEW_NAME, email=_NEW_EMAIL)

        assert db.calls
        for call in db.calls:
            for value in (
                str(target),
                str(admin_id),
                str(ORG_ID),
                _OLD_EMAIL,
                _NEW_EMAIL,
                _OLD_NAME,
                _NEW_NAME,
            ):
                assert value.lower() not in call.normalized, (value, call.normalized)


# ---------------------------------------------------------------------------
# 5. The last-admin guard
# ---------------------------------------------------------------------------


class TestLastAdminGuard:
    """An org always keeps at least one active Org Admin."""

    @pytest.mark.parametrize("new_role", ["editor", "viewer"])
    async def test_org_users_demoting_the_last_active_admin_is_refused(
        self, db: FakeDb, new_role: str
    ) -> None:
        """LastAdminError; nothing changes, nothing is audited or queued."""
        admin_id, admin = _admin(db)
        db.add_account(role="editor")
        before = _state(db)

        with pytest.raises(accounts.LastAdminError):
            await _update(db, admin, admin_id, role=new_role)

        assert _state(db) == before
        assert db.audit == []

    async def test_org_users_last_admin_refusal_keeps_a_name_in_the_same_patch(
        self, db: FakeDb
    ) -> None:
        admin_id, admin = _admin(db, name=_OLD_NAME)
        before = _state(db)

        with pytest.raises(accounts.LastAdminError):
            await _update(db, admin, admin_id, role="viewer", name=_NEW_NAME)

        assert _state(db) == before

    async def test_org_users_last_admin_guard_runs_before_the_change_in_the_transaction(
        self, db: FakeDb
    ) -> None:
        """The guard query runs inside the transaction, bound to (org, target), and the
        refusal comes before any UPDATE; the transaction rolls back."""
        admin_id, admin = _admin(db)
        db.calls.clear()

        with pytest.raises(accounts.LastAdminError):
            await _update(db, admin, admin_id, role="editor")

        guards = _guard_calls(db)
        assert len(guards) == 1
        assert guards[0].tx is not None
        assert [str(arg) for arg in guards[0].args] == [str(ORG_ID), str(admin_id)]
        assert db.matching(r"^update users\b") == []
        assert db.transactions == [(guards[0].tx, "rollback:LastAdminError")]

    async def test_org_users_demoting_an_admin_with_a_second_active_admin_works(
        self, db: FakeDb
    ) -> None:
        admin_id, admin = _admin(db)
        second = db.add_account(role="org_admin")

        await _update(db, admin, second, role="editor")

        assert db.users[second]["role"] == "editor"
        assert db.users[admin_id]["role"] == "org_admin"

    async def test_org_users_self_demotion_of_a_non_last_admin_works(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db)
        db.add_account(role="org_admin")

        summary = await _update(db, admin, admin_id, role="viewer")

        assert db.users[admin_id]["role"] == "viewer"
        assert summary.role == "viewer"
        assert [row["action"] for row in db.audit] == ["user.role_change"]

    async def test_org_users_a_deactivated_second_admin_does_not_count(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db)
        db.add_account(role="org_admin", status="deactivated")
        before = _state(db)

        with pytest.raises(accounts.LastAdminError):
            await _update(db, admin, admin_id, role="editor")

        assert _state(db) == before

    async def test_org_users_a_deleted_second_admin_does_not_count(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db)
        db.add_account(role="org_admin", deleted_at=datetime.now(UTC) - timedelta(days=1))

        with pytest.raises(accounts.LastAdminError):
            await _update(db, admin, admin_id, role="editor")

        assert db.users[admin_id]["role"] == "org_admin"

    async def test_org_users_an_admin_of_another_org_does_not_count(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db)
        db.add_account(role="org_admin", org_id=OTHER_ORG_ID)

        with pytest.raises(accounts.LastAdminError):
            await _update(db, admin, admin_id, role="viewer")

        assert db.users[admin_id]["role"] == "org_admin"

    async def test_org_users_demoting_a_deactivated_admin_works(self, db: FakeDb) -> None:
        """A deactivated admin isn't an active one: demoting them needs no guard refusal."""
        admin_id, admin = _admin(db)
        dormant = db.add_account(role="org_admin", status="deactivated")

        summary = await _update(db, admin, dormant, role="editor")

        assert db.users[dormant]["role"] == "editor"
        assert db.users[dormant]["status"] == "deactivated"
        assert summary.status == "deactivated"
        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit(
                "user.role_change",
                admin_id,
                dormant,
                {"old_role": "org_admin", "new_role": "editor"},
            )
        ]

    async def test_org_users_setting_org_admin_on_the_last_admin_is_a_no_op(
        self, db: FakeDb
    ) -> None:
        """Not a demotion: no refusal, no change, no audit row."""
        admin_id, admin = _admin(db, created_at=_CREATED, last_login_at=_LAST_LOGIN)
        before = _state(db)

        summary = await _update(db, admin, admin_id, role="org_admin")

        assert summary.model_dump() == _summary_of(db, admin_id)
        assert _state(db) == before

    async def test_org_users_name_change_of_the_last_admin_needs_no_guard(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db, name=_OLD_NAME)

        summary = await _update(db, admin, admin_id, name=_NEW_NAME)

        assert db.users[admin_id]["name"] == _NEW_NAME
        assert summary.role == "org_admin"


# ---------------------------------------------------------------------------
# 6. update_org_user: name and email changes
# ---------------------------------------------------------------------------


class TestProfileChange:
    """Name and email changes, their audit row, the notice to the old address and the
    reset-token cancellation."""

    async def test_org_users_name_change_is_stored_returned_and_audited(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db)
        target = db.add_account(
            role="editor",
            name=_OLD_NAME,
            email=_OLD_EMAIL,
            created_at=_CREATED,
            last_login_at=_LAST_LOGIN,
        )

        summary = await _update(db, admin, target, name=_NEW_NAME)

        assert db.users[target]["name"] == _NEW_NAME
        assert summary.model_dump() == {
            "id": target,
            "name": _NEW_NAME,
            "email": _OLD_EMAIL,
            "role": "editor",
            "status": "active",
            "created_at": _CREATED,
            "last_login_at": _LAST_LOGIN,
        }
        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit(
                "user.profile_change",
                admin_id,
                target,
                {"name_changed": True, "email_changed": False},
            )
        ]

    async def test_org_users_name_change_queues_nothing_and_keeps_the_reset_token(
        self, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = db.add_account(name=_OLD_NAME)
        db.add_reset_token(target)
        token_row = copy.deepcopy(db.tokens[target])

        await _update(db, admin, target, name=_NEW_NAME)

        assert db.outbox == []
        assert db.tokens.get(target) == token_row

    async def test_org_users_email_change_is_stored_returned_and_audited(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db)
        target = db.add_account(role="viewer", email=_OLD_EMAIL, name=_OLD_NAME)

        summary = await _update(db, admin, target, email=_NEW_EMAIL)

        assert db.users[target]["email"] == _NEW_EMAIL
        assert summary.email == _NEW_EMAIL
        assert summary.name == _OLD_NAME
        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit(
                "user.profile_change",
                admin_id,
                target,
                {"name_changed": False, "email_changed": True},
            )
        ]

    async def test_org_users_email_change_notifies_the_old_address_with_the_org_name_only(
        self, db: FakeDb
    ) -> None:
        """Exactly one email_changed email, to the OLD address (queued before the UPDATE),
        whose params are the org name only."""
        _, admin = _admin(db)
        target = db.add_account(email=_OLD_EMAIL)

        await _update(db, admin, target, email=_NEW_EMAIL)

        assert len(db.outbox) == 1
        row = db.outbox[0]
        assert {
            "user_id": row["user_id"],
            "recipient_address": row["recipient_address"],
            "template_key": row["template_key"],
            "params": row["params"],
            "status": row["status"],
        } == {
            "user_id": target,
            "recipient_address": _OLD_EMAIL,
            "template_key": "email_changed",
            "params": {"org_name": ORG_NAME},
            "status": "pending",
        }

    async def test_org_users_email_change_notice_names_the_actor_org(self, db: FakeDb) -> None:
        _, admin = _admin(db, OTHER_ORG_ID)
        target = db.add_account(email=_OLD_EMAIL, org_id=OTHER_ORG_ID)

        await _update(db, admin, target, email=_NEW_EMAIL)

        assert [row["params"] for row in db.outbox] == [{"org_name": OTHER_ORG_NAME}]

    async def test_org_users_email_change_deletes_only_the_user_reset_token(
        self, db: FakeDb
    ) -> None:
        """A reset link already sent to the old address stops working; another user's
        token is kept."""
        _, admin = _admin(db)
        target = db.add_account(email=_OLD_EMAIL)
        bystander = db.add_account()
        db.add_reset_token(target)
        db.add_reset_token(bystander)
        kept = copy.deepcopy(db.tokens[bystander])

        await _update(db, admin, target, email=_NEW_EMAIL)

        assert target not in db.tokens
        assert db.tokens.get(bystander) == kept

    async def test_org_users_email_change_writes_in_one_committed_transaction(
        self, db: FakeDb
    ) -> None:
        """The notice, the token delete, the UPDATE and the audit row share one connection
        and transaction."""
        _, admin = _admin(db)
        target = db.add_account(email=_OLD_EMAIL)
        db.add_reset_token(target)
        db.calls.clear()

        await _update(db, admin, target, email=_NEW_EMAIL)

        writes = [call for call in db.calls if _is_write(call)]
        assert db.matching(r"^insert into email_outbox\b")
        assert db.matching(r"^delete from password_reset_tokens\b")
        assert db.matching(r"^update users\b")
        assert db.matching(r"^insert into audit_events\b")
        assert len({(call.via, call.tx) for call in writes}) == 1
        assert writes[0].tx is not None
        assert db.transactions == [(writes[0].tx, "commit")]

    async def test_org_users_name_and_email_change_is_one_profile_event(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db)
        target = db.add_account(email=_OLD_EMAIL, name=_OLD_NAME)

        await _update(db, admin, target, name=_NEW_NAME, email=_NEW_EMAIL)

        assert (db.users[target]["name"], db.users[target]["email"]) == (_NEW_NAME, _NEW_EMAIL)
        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit(
                "user.profile_change",
                admin_id,
                target,
                {"name_changed": True, "email_changed": True},
            )
        ]

    async def test_org_users_role_and_name_change_records_role_then_profile_event(
        self, db: FakeDb
    ) -> None:
        admin_id, admin = _admin(db)
        target = db.add_account(role="editor", name=_OLD_NAME)

        await _update(db, admin, target, role="viewer", name=_NEW_NAME)

        assert (db.users[target]["role"], db.users[target]["name"]) == ("viewer", _NEW_NAME)
        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit(
                "user.role_change", admin_id, target, {"old_role": "editor", "new_role": "viewer"}
            ),
            _expected_audit(
                "user.profile_change",
                admin_id,
                target,
                {"name_changed": True, "email_changed": False},
            ),
        ]

    async def test_org_users_role_and_email_change_records_both_and_queues_the_notice(
        self, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = db.add_account(role="viewer", email=_OLD_EMAIL)

        await _update(db, admin, target, role="editor", email=_NEW_EMAIL)

        assert [row["action"] for row in db.audit] == ["user.role_change", "user.profile_change"]
        assert db.audit[1]["metadata"] == {"name_changed": False, "email_changed": True}
        assert [row["recipient_address"] for row in db.outbox] == [_OLD_EMAIL]

    @pytest.mark.parametrize(
        "fields",
        [
            pytest.param({"role": "editor"}, id="role"),
            pytest.param({"name": _OLD_NAME}, id="name"),
            pytest.param({"email": _OLD_EMAIL}, id="email"),
            pytest.param({"role": "editor", "name": _OLD_NAME, "email": _OLD_EMAIL}, id="all"),
        ],
    )
    async def test_org_users_unchanged_values_are_no_change(
        self, db: FakeDb, fields: dict[str, Any]
    ) -> None:
        """Values equal to the stored ones: the summary comes back, nothing is written,
        audited or queued, and the reset token is kept."""
        _, admin = _admin(db)
        target = db.add_account(
            role="editor",
            name=_OLD_NAME,
            email=_OLD_EMAIL,
            created_at=_CREATED,
            last_login_at=_LAST_LOGIN,
        )
        db.add_reset_token(target)
        before = _state(db)

        summary = await _update(db, admin, target, **fields)

        assert summary.model_dump() == _summary_of(db, target)
        assert _state(db) == before

    async def test_org_users_unchanged_name_with_changed_email_flags_only_the_email(
        self, db: FakeDb
    ) -> None:
        admin_id, admin = _admin(db)
        target = db.add_account(name=_OLD_NAME, email=_OLD_EMAIL)

        await _update(db, admin, target, name=_OLD_NAME, email=_NEW_EMAIL)

        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit(
                "user.profile_change",
                admin_id,
                target,
                {"name_changed": False, "email_changed": True},
            )
        ]

    async def test_org_users_unchanged_role_with_changed_name_records_only_profile(
        self, db: FakeDb
    ) -> None:
        _, admin = _admin(db)
        target = db.add_account(role="viewer", name=_OLD_NAME)

        await _update(db, admin, target, role="viewer", name=_NEW_NAME)

        assert [row["action"] for row in db.audit] == ["user.profile_change"]
        assert db.audit[0]["metadata"] == {"name_changed": True, "email_changed": False}

    async def test_org_users_capitalization_change_of_own_email_works(self, db: FakeDb) -> None:
        """The same row holds the address: no DuplicateEmailError; it is an email change
        (exact compare), so it is audited and notified."""
        _, admin = _admin(db)
        target = db.add_account(email="Anna.Muster@Example.test")

        summary = await _update(db, admin, target, email="anna.muster@example.test")

        assert db.users[target]["email"] == "anna.muster@example.test"
        assert summary.email == "anna.muster@example.test"
        assert [row["metadata"] for row in db.audit] == [
            {"name_changed": False, "email_changed": True}
        ]
        assert [row["recipient_address"] for row in db.outbox] == ["Anna.Muster@Example.test"]

    async def test_org_users_admin_can_change_their_own_email(self, db: FakeDb) -> None:
        admin_id, admin = _admin(db, email=_OLD_EMAIL)

        await _update(db, admin, admin_id, email=_NEW_EMAIL)

        assert db.users[admin_id]["email"] == _NEW_EMAIL
        assert [row["recipient_address"] for row in db.outbox] == [_OLD_EMAIL]

    async def test_org_users_deactivated_user_can_be_renamed(self, db: FakeDb) -> None:
        _, admin = _admin(db)
        target = db.add_account(status="deactivated", name=_OLD_NAME)

        summary = await _update(db, admin, target, name=_NEW_NAME)

        assert db.users[target]["name"] == _NEW_NAME
        assert db.users[target]["status"] == "deactivated"
        assert summary.status == "deactivated"


# ---------------------------------------------------------------------------
# 7. Email uniqueness
# ---------------------------------------------------------------------------


def _add_occupant(db: FakeDb, holder: str, email: str) -> uuid.UUID:
    """An account that already uses the email."""
    if holder == "same_org":
        return db.add_account(email=email)
    if holder == "other_org":
        return db.add_account(email=email, org_id=OTHER_ORG_ID)
    if holder == "super_admin":
        return db.add_account(kind="super_admin", role=None, email=email)
    if holder == "invited":
        return db.add_account(status="invited", email=email, name=None, password_hash=None)
    assert holder == "deactivated"
    return db.add_account(status="deactivated", email=email)


_HOLDERS = ["same_org", "other_org", "super_admin", "invited", "deactivated"]
_CASINGS = [
    pytest.param(_TAKEN_EMAIL, id="same-case"),
    pytest.param("Taken.Address.MARKER@Example.TEST", id="other-case"),
]


class TestEmailUniqueness:
    """An email is unique on the whole platform, ignoring capitalization."""

    @pytest.mark.parametrize("holder", _HOLDERS)
    @pytest.mark.parametrize("requested", _CASINGS)
    async def test_org_users_taken_email_is_refused_and_rolls_everything_back(
        self, db: FakeDb, holder: str, requested: str
    ) -> None:
        """DuplicateEmailError; role and name in the same patch are not changed, nothing
        is queued, the reset token is kept, no role_change is audited."""
        _, admin = _admin(db)
        target = db.add_account(role="editor", name=_OLD_NAME, email=_OLD_EMAIL)
        _add_occupant(db, holder, _TAKEN_EMAIL)
        db.add_reset_token(target)
        before = _state(db)

        with pytest.raises(accounts.DuplicateEmailError):
            await _update(db, admin, target, role="viewer", name=_NEW_NAME, email=requested)

        after = _state(db)
        assert after["users"] == before["users"]
        assert after["outbox"] == []
        assert after["tokens"] == before["tokens"]
        assert all(row["action"] != "user.role_change" for row in db.audit)

    @pytest.mark.parametrize("holder", _HOLDERS)
    async def test_org_users_taken_email_records_one_email_taken_event(
        self, db: FakeDb, holder: str
    ) -> None:
        admin_id, admin = _admin(db)
        target = db.add_account(role="editor", email=_OLD_EMAIL)
        _add_occupant(db, holder, _TAKEN_EMAIL)

        with pytest.raises(accounts.DuplicateEmailError):
            await _update(db, admin, target, role="viewer", email=_TAKEN_EMAIL.upper())

        assert [_audit_view(row) for row in db.audit] == [
            _expected_audit("user.profile_change", admin_id, target, {"email_taken": True})
        ]

    async def test_org_users_taken_email_event_is_recorded_after_the_rollback(
        self, db: FakeDb
    ) -> None:
        """One transaction rolls back; the email_taken row is written after it, outside
        the rolled-back transaction."""
        _, admin = _admin(db)
        target = db.add_account(email=_OLD_EMAIL)
        _add_occupant(db, "other_org", _TAKEN_EMAIL)
        db.calls.clear()

        with pytest.raises(accounts.DuplicateEmailError):
            await _update(db, admin, target, email=_TAKEN_EMAIL)

        rolled_back = [tx for tx, outcome in db.transactions if outcome.startswith("rollback:")]
        assert len(rolled_back) == 1
        audit_inserts = [
            index
            for index, call in enumerate(db.calls)
            if call.normalized.startswith("insert into audit_events")
        ]
        in_tx = [index for index, call in enumerate(db.calls) if call.tx == rolled_back[0]]
        assert len(audit_inserts) >= 1
        assert in_tx
        assert audit_inserts[-1] > max(in_tx)
        assert db.calls[audit_inserts[-1]].tx != rolled_back[0]

    async def test_org_users_taken_email_error_carries_no_email(self, db: FakeDb) -> None:
        """The fixed message, raised from None: the driver's text (which repeats the key)
        is not chained."""
        _, admin = _admin(db)
        target = db.add_account(email=_OLD_EMAIL)
        _add_occupant(db, "same_org", _TAKEN_EMAIL)

        with pytest.raises(accounts.DuplicateEmailError) as caught:
            await _update(db, admin, target, email=_TAKEN_EMAIL)

        text = f"{caught.value!s} {caught.value!r} {caught.value.args!r}".lower()
        assert "taken.address.marker" not in text
        assert "old.address.marker" not in text
        assert "example.test" not in text
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__ is True

    async def test_org_users_free_email_with_other_rows_is_accepted(self, db: FakeDb) -> None:
        """A similar but different address is no conflict."""
        _, admin = _admin(db)
        target = db.add_account(email=_OLD_EMAIL)
        _add_occupant(db, "other_org", _TAKEN_EMAIL)

        await _update(db, admin, target, email="taken.address.marker2@example.test")

        assert db.users[target]["email"] == "taken.address.marker2@example.test"


# ---------------------------------------------------------------------------
# 8. Tenant isolation: not found, never forbidden
# ---------------------------------------------------------------------------


def _add_unreachable(db: FakeDb, kind: str) -> uuid.UUID:
    """A target the actor (an Org Admin of ORG_ID) must not reach."""
    if kind == "other_org":
        return db.add_account(role="editor", org_id=OTHER_ORG_ID, email=_OLD_EMAIL, name=_OLD_NAME)
    if kind == "other_org_admin":
        return db.add_account(role="org_admin", org_id=OTHER_ORG_ID, email=_OLD_EMAIL)
    if kind == "unknown":
        return uuid.UUID("0badc0de-0000-4000-8000-00000000beef")
    if kind == "invited":
        return db.add_account(status="invited", email=_OLD_EMAIL, name=None, password_hash=None)
    if kind == "deleted":
        return db.add_account(
            email=_OLD_EMAIL, name=_OLD_NAME, deleted_at=datetime.now(UTC) - timedelta(days=3)
        )
    assert kind == "super_admin"
    return db.add_account(kind="super_admin", role=None, email=_OLD_EMAIL)


_UNREACHABLE = ["other_org", "other_org_admin", "unknown", "invited", "deleted", "super_admin"]
_PATCHES = [
    pytest.param({"role": "viewer"}, id="role"),
    pytest.param({"role": "org_admin"}, id="promote"),
    pytest.param({"name": _NEW_NAME}, id="name"),
    pytest.param({"email": _NEW_EMAIL}, id="email"),
]


class TestTenantIsolation:
    """Another org's user, an unknown id, an invited, deleted or Super Admin account:
    UserNotInOrgError and nothing changes."""

    @pytest.mark.parametrize("kind", _UNREACHABLE)
    @pytest.mark.parametrize("fields", _PATCHES)
    async def test_org_users_update_of_an_unreachable_user_is_not_found(
        self, db: FakeDb, kind: str, fields: dict[str, Any]
    ) -> None:
        _, admin = _admin(db)
        db.add_account(role="org_admin")  # a second admin: no guard refusal on the actor's org
        target = _add_unreachable(db, kind)
        if target in db.users:
            db.add_reset_token(target)
        before = _state(db)

        with pytest.raises(accounts.UserNotInOrgError):
            await _update(db, admin, target, **fields)

        assert _state(db) == before
        assert db.audit == []
        assert db.outbox == []

    async def test_org_users_other_org_user_is_answered_like_an_unknown_id(
        self, db: FakeDb
    ) -> None:
        """Same exception type and message for both: no existence oracle."""
        _, admin = _admin(db)
        other = db.add_account(org_id=OTHER_ORG_ID)
        unknown = uuid.uuid4()

        with pytest.raises(accounts.UserNotInOrgError) as other_caught:
            await _update(db, admin, other, name=_NEW_NAME)
        with pytest.raises(accounts.UserNotInOrgError) as unknown_caught:
            await _update(db, admin, unknown, name=_NEW_NAME)

        assert str(other_caught.value) == str(unknown_caught.value)
        assert str(other) not in str(other_caught.value)

    async def test_org_users_update_never_writes_another_org_row(self, db: FakeDb) -> None:
        """Even with a taken email in the patch, another org's user is not found (no
        email_taken oracle) and no statement binds a write to it."""
        _, admin = _admin(db)
        other = db.add_account(org_id=OTHER_ORG_ID, email=_OLD_EMAIL)
        _add_occupant(db, "same_org", _TAKEN_EMAIL)
        db.calls.clear()

        with pytest.raises(accounts.UserNotInOrgError):
            await _update(db, admin, other, email=_TAKEN_EMAIL)

        assert db.audit == []
        writes = [
            call for call in db.calls if re.match(r"(?:insert|update|delete) ", call.normalized)
        ]
        assert writes == []


# ---------------------------------------------------------------------------
# 9. Fail closed: an audit failure undoes the change
# ---------------------------------------------------------------------------


class TestFailClosed:
    """The change never happens unaudited."""

    @pytest.mark.parametrize(
        "fields",
        [
            pytest.param({"role": "viewer"}, id="role"),
            pytest.param({"name": _NEW_NAME}, id="name"),
            pytest.param({"email": _NEW_EMAIL}, id="email"),
            pytest.param({"role": "viewer", "name": _NEW_NAME, "email": _NEW_EMAIL}, id="all"),
        ],
    )
    async def test_org_users_audit_failure_changes_nothing(
        self, db: FakeDb, fields: dict[str, Any]
    ) -> None:
        """AuditRecordError; the user, the outbox and the reset token are as before."""
        _, admin = _admin(db)
        target = db.add_account(role="editor", name=_OLD_NAME, email=_OLD_EMAIL)
        db.add_reset_token(target)
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _update(db, admin, target, **fields)

        assert _state(db) == before
        assert db.transactions[-1][1] == "rollback:AuditRecordError"

    async def test_org_users_profile_audit_failure_also_undoes_the_role_change(
        self, db: FakeDb
    ) -> None:
        """Both events are in the change's transaction: the second failing undoes all."""
        _, admin = _admin(db)
        target = db.add_account(role="editor", name=_OLD_NAME)
        before = _state(db)
        db.fail_audit_when = lambda row: row["action"] == "user.profile_change"

        with pytest.raises(AuditRecordError):
            await _update(db, admin, target, role="viewer", name=_NEW_NAME)

        assert _state(db) == before
        assert db.audit == []


# ---------------------------------------------------------------------------
# 10. No content in audit rows or logs
# ---------------------------------------------------------------------------


class TestNoContent:
    """IDs, role tokens and bools only: never a name or an email."""

    async def _run_everything(self, db: FakeDb) -> None:
        _, admin = _admin(db)
        db.add_account(role="org_admin")
        target = db.add_account(role="editor", name=_OLD_NAME, email=_OLD_EMAIL)
        _add_occupant(db, "other_org", _TAKEN_EMAIL)
        db.add_reset_token(target)
        await org_users.list_org_users(db.pool, actor=admin)
        await _update(db, admin, target, role="viewer", name=_NEW_NAME, email=_NEW_EMAIL)
        with pytest.raises(accounts.DuplicateEmailError):
            await _update(db, admin, target, email=_TAKEN_EMAIL)
        with pytest.raises(accounts.UserNotInOrgError):
            await _update(db, admin, uuid.uuid4(), name=_OLD_NAME)

    async def test_org_users_audit_rows_hold_no_name_or_email(self, db: FakeDb) -> None:
        await self._run_everything(db)

        text = str(db.audit).lower()
        assert len(db.audit) == 3
        for value in (_OLD_EMAIL, _NEW_EMAIL, _TAKEN_EMAIL, _OLD_NAME, _NEW_NAME):
            assert value.lower() not in text
        assert "marker" not in text
        assert "example.test" not in text

    async def test_org_users_logs_no_name_or_email(
        self, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)

        await self._run_everything(db)

        text = caplog.text.lower()
        assert "marker" not in text
        assert "example.test" not in text
