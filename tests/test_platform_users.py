"""Tests for admino.platform_users: Super Admin user administration and org metadata (GH-167).

``list_users(pool, *, actor, org_id)`` and ``org_metadata(pool, *, actor,
org_id)`` let the Super Admin read an org's accounts and its counts;
``deactivate_user(pool, *, actor, org_id, user_id, ip)``,
``reactivate_user(pool, *, actor, org_id, user_id, public_url, ip)`` and
``trigger_password_reset(pool, *, actor, org_id, user_id, public_url, ip)`` act
on one account of that org. (The re-invite of an org's first Org Admin,
``reinvite_org_admin``, is covered in tests/test_platform_users_reinvite.py.)
These tests run the real service against the in-memory database of
tests/db_fakes.py.

What these tests pin down (the GH-167 contract):
- Authorization first: the reads need ``platform.org_metadata.view``, the
  actions ``platform.users.manage``. Every member role (an Org Admin of the
  very org included), the ``access.Operator`` and a malformed principal get
  ``PermissionError("Forbidden")`` before any query (``db.calls`` stays
  empty). A Super Admin passes; the function's own capability alone is
  enough, and without it the Super Admin is refused too.
- Org scope: an unknown org is ``organizations.OrgNotFoundError`` (checked
  before the target, so a real user id of another org can't turn it into a
  "user not found"). A target is a non-deleted users row of that org: another
  org's user, an unknown id, a deleted account and a Super Admin's id are
  ``accounts.UserNotInOrgError``. An invited account IS a user of the org here:
  the actions refuse it with ``org_users.InvalidUserStatusError``.
- ``list_users``: the org's active, deactivated and invited accounts (never a
  deleted one, another org's or a Super Admin), oldest first (created_at, then
  id), exactly the ``PlatformUserSummary`` fields; an empty org is ``[]``; any
  org status. Read-only: nothing written, audited or logged.
- ``org_metadata``: ``seats.used`` = active + invited non-deleted users of the
  org (expired invitations included: #153's ``invitations._SEATS_TAKEN_SQL``),
  ``seats.limit`` = the org's seats (``used`` may exceed it); ``chat_count``
  (GH-176) = the org's chats that aren't trashed, of every member (never
  another org's; a count, no statement reads a title); ``storage_used_bytes``
  and ``file_count`` are 0; the JSON keys are exactly ``seats`` (``used``,
  ``limit``), ``storage_used_bytes``, ``chat_count`` and ``file_count``. Any org
  status; read-only. (GH-187 counts the org's attachments; GH-188, contract 12.4:
  ``storage_used_bytes`` is their originals plus their derived files, a NULL
  ``derived_bytes`` counting 0, never another org's, and no statement reads a file
  name or token estimate.)
- ``deactivate_user``: the last-admin guard applies to the Super Admin too
  (``accounts.LastAdminError``); then status ``deactivated``, every session of
  the user deleted through ``sessions.revoke_user_sessions`` (nobody else's),
  one ``account_deactivated`` email (``{"org_name"}`` of the affected org), one
  ``user.deactivate`` event with ``{"sessions_revoked": n}``. Any org status.
  Connections, memory and settings are kept.
- ``reactivate_user``: refused while the org's deletion is pending
  (``organizations.InvalidOrgStatusError``), then only a deactivated user, then
  the seat check (active + invited >= seats is ``invitations.SeatLimitError``);
  status ``active``, one ``account_activated`` email (``org_name``,
  ``login_link = {public_url}/login``), one ``user.activate`` event.
- ``trigger_password_reset``: an active org and an active user only; GH-151's
  link (a fresh token stored as its SHA-256 hash, replacing the previous one;
  ``{public_url}/reset-password#token=<43 chars>`` only in the queued email);
  one ``password_reset.request`` event with ``{"email_sent": True}``; returns
  None.
- Every event: ``actor_kind = "super_admin"``, ``actor_user_id`` = the Super
  Admin, ``org_id`` = the affected org, target the user, the client IP. One
  committed transaction per action; a failed audit write raises
  ``audit_events.AuditRecordError`` and nothing changes (status, sessions,
  token, outbox).
- No content: no audit row and no log line carries an email, a name, a token
  or a link; nothing is logged at all; errors carry no ids.

No real PostgreSQL, no network: every statement goes to ``FakeDb``.

Security notes:
- Operator blindness and least privilege: member roles and the terminal
  operator never reach the data; a forged or lookalike principal fails closed.
- Tenant isolation at the data layer: every statement binds the org id; a user
  of another org answers exactly like an unknown id.
- No credential path: the reset token never reaches the caller; no audit row
  or log line holds it.
- Fail closed: no change, email or token survives a failed audit write.
"""

from __future__ import annotations

import ast
import inspect
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import access, accounts, invitations, models, org_users, organizations
from admino import sessions as sessions_mod
from admino.access import Principal
from admino.audit_events import AuditRecordError
from tests.db_fakes import (
    LINK_PREFIX,
    ORG_ID,
    ORG_ID_PARAM_RE,
    ORG_NAME,
    OTHER_ORG_ID,
    OTHER_ORG_NAME,
    PUBLIC_URL,
    TOKEN_RE,
    Call,
    FakeDb,
    plain,
    sha256,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP: Final = "203.0.113.67"
_LOGIN_LINK: Final = PUBLIC_URL + "/login"
_VIEW: Final = "platform.org_metadata.view"
_MANAGE: Final = "platform.users.manage"

_READS: Final = ("list_users", "org_metadata")
_ACTIONS: Final = ("deactivate", "reactivate", "password_reset")
_FUNCTIONS: Final = (*_READS, *_ACTIONS)
_CAPABILITY_OF: Final = {
    "list_users": _VIEW,
    "org_metadata": _VIEW,
    "deactivate": _MANAGE,
    "reactivate": _MANAGE,
    "password_reset": _MANAGE,
}
# The status a target must have for the action to apply.
_VALID_STATUS: Final = {
    "deactivate": "active",
    "reactivate": "deactivated",
    "password_reset": "active",
}
_AUDIT_ACTION: Final = {
    "deactivate": "user.deactivate",
    "reactivate": "user.activate",
    "password_reset": "password_reset.request",
}
# The target statuses each action refuses with InvalidUserStatusError.
_WRONG_STATUSES: Final = [
    ("deactivate", "deactivated"),
    ("deactivate", "invited"),
    ("reactivate", "active"),
    ("reactivate", "invited"),
    ("password_reset", "deactivated"),
    ("password_reset", "invited"),
]
_OUTSIDE_CASES: Final = ("other-org", "unknown", "deleted", "super-admin")
_INACTIVE_OTHER_ADMINS: Final = ("none", "deactivated", "invited", "deleted", "other-org")
_MEMBER_ROLES: Final = ("org_admin", "editor")
_ORG_STATUSES: Final = ("active", "deactivated", "pending_deletion")

_SEATS: Final = 10
# Far past the 72 h invitation lifetime: the invitation has expired, the account is
# still an invited users row holding its seat.
_EXPIRED_AGO: Final = timedelta(days=10)
_CREATED: Final = datetime(2026, 3, 4, 9, 30, tzinfo=UTC)
_LAST_LOGIN: Final = datetime(2026, 9, 30, 17, 5, 12, tzinfo=UTC)

_GUARD_RE: Final = r"\bas is_active_admin from users\b"
_WRITE_RE: Final = r"^(?:insert|update|delete)\b"
_INVALID_USER_STATUS: Final = "This change isn't possible in the user's current status."
_DB_METHODS: Final = frozenset({"execute", "executemany", "fetch", "fetchrow", "fetchval"})
_SQL_KEYWORD_RE: Final = re.compile(
    r"\b(?:select\b.*\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|where)\b",
    re.IGNORECASE | re.DOTALL,
)

_MARKER_EMAIL: Final = "target.marker@example.test"
_MARKER_NAME: Final = "Zelda Markerperson"
_SA_EMAIL: Final = "root.marker@example.test"
_SA_NAME: Final = "Rita Rootmarker"
_ADMIN_EMAIL: Final = "admin.marker@example.test"
_ADMIN_NAME: Final = "Ada Adminmarker"
_CHAT_TITLE: Final = "Marker chat title Okapi"
# GH-188: a file name and a token estimate org metadata must never carry.
_FILE_NAME_MARKER: Final = "Marker file name Quokka.pdf"
_TOKEN_ESTIMATE_MARKER: Final = 918_273


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def pu() -> ModuleType:
    """admino.platform_users, imported per test so each test fails on its own until the
    module exists."""
    from admino import platform_users

    return platform_users


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database."""
    return FakeDb()


def _model(name: str) -> Any:
    """A GH-167 model of admino.models, looked up at call time (it is new)."""
    model = getattr(models, name, None)
    assert model is not None, f"admino.models must define {name}"
    return model


def _principal(db: FakeDb, user_id: uuid.UUID) -> Principal:
    """The Principal a resolved session of this stored account would carry."""
    account = db.users[user_id]
    if account["kind"] == "super_admin":
        return Principal(user_id=user_id, kind="super_admin")
    return Principal(user_id=user_id, kind="member", org_id=account["org_id"], role=account["role"])


def _super_admin(db: FakeDb) -> tuple[uuid.UUID, Principal]:
    """A stored Super Admin (no org, no role) and the Principal of their session."""
    sa_id = db.add_account(kind="super_admin", role=None, email=_SA_EMAIL, name=_SA_NAME)
    return sa_id, _principal(db, sa_id)


def _forge(principal: Principal, **fields: object) -> Principal:
    """Overwrite fields of a validated Principal without validation (a bypass's result)."""
    for name, value in fields.items():
        object.__setattr__(principal, name, value)
    return principal


class _PrincipalLookalike:
    """Duck-typed object with a Super Admin's attributes, not a Principal."""

    def __init__(self, user_id: uuid.UUID) -> None:
        self.user_id = user_id
        self.kind = "super_admin"
        self.org_id = None
        self.role = None


class _PrincipalSubclass(Principal):
    """A Principal subclass: can() trusts only Principal itself."""


def _forbidden_actor(db: FakeDb, who: str) -> Any:
    """A member of ORG_ID, the terminal operator, or a malformed Super Admin principal."""
    if who in _MEMBER_ROLES:
        return _principal(db, db.add_account(role=who))
    if who == "operator":
        return access.Operator()
    if who == "org-admin-forged-to-super-admin":
        return _forge(_principal(db, db.add_account(role="org_admin")), kind="super_admin")
    sa_id, sa = _super_admin(db)
    if who == "super-admin-given-an-org":
        return _forge(sa, org_id=ORG_ID)
    if who == "super-admin-given-a-role":
        return _forge(sa, role="org_admin")
    if who == "lookalike":
        return _PrincipalLookalike(sa_id)
    assert who == "subclass"
    return _PrincipalSubclass(user_id=sa_id, kind="super_admin")


_FORBIDDEN: Final = (
    *_MEMBER_ROLES,
    "operator",
    "org-admin-forged-to-super-admin",
    "super-admin-given-an-org",
    "super-admin-given-a-role",
    "lookalike",
    "subclass",
)


def _setup(db: FakeDb, name: str) -> uuid.UUID | None:
    """ORG_ID with an active Org Admin and, for an action, a target (with a session and a
    reset token) in the status the action applies to."""
    db.add_account(role="org_admin")
    if name in _READS:
        return None
    target = db.add_account(role="editor", status=_VALID_STATUS[name])
    db.open_session(target)
    db.add_reset_token(target)
    return target


async def _call(
    pu: ModuleType,
    db: FakeDb,
    name: str,
    actor: Any,
    *,
    org_id: uuid.UUID = ORG_ID,
    user_id: uuid.UUID | None = None,
    ip: str | None = _IP,
) -> Any:
    """Call one service function with the default IP and public URL."""
    if name == "list_users":
        return await pu.list_users(db.pool, actor=actor, org_id=org_id)
    if name == "org_metadata":
        return await pu.org_metadata(db.pool, actor=actor, org_id=org_id)
    if name == "deactivate":
        return await pu.deactivate_user(db.pool, actor=actor, org_id=org_id, user_id=user_id, ip=ip)
    if name == "reactivate":
        return await pu.reactivate_user(
            db.pool, actor=actor, org_id=org_id, user_id=user_id, public_url=PUBLIC_URL, ip=ip
        )
    assert name == "password_reset"
    return await pu.trigger_password_reset(
        db.pool, actor=actor, org_id=org_id, user_id=user_id, public_url=PUBLIC_URL, ip=ip
    )


def _invited(
    db: FakeDb,
    org_id: uuid.UUID = ORG_ID,
    *,
    role: str = "editor",
    sent_ago: timedelta = timedelta(0),
    **fields: Any,
) -> uuid.UUID:
    """An invited account (no name or password yet) with its invitation, sent ``sent_ago``."""
    user_id = db.add_account(
        role=role, org_id=org_id, status="invited", name=None, password_hash=None, **fields
    )
    db.add_invitation(user_id, sent_ago=sent_ago)
    return user_id


def _deleted(db: FakeDb, status: str = "active", **fields: Any) -> uuid.UUID:
    """A soft-deleted account (deleted_at set) of ORG_ID."""
    invited: dict[str, Any] = {"name": None, "password_hash": None}
    return db.add_account(
        status=status,
        deleted_at=datetime.now(UTC) - timedelta(days=1),
        **(invited if status == "invited" else {}),
        **fields,
    )


def _outside_target(db: FakeDb, case: str, action: str) -> uuid.UUID:
    """A user id the Super Admin must not reach through ORG_ID's path."""
    status = _VALID_STATUS[action]
    if case == "other-org":
        # The other org's only Org Admin: a guard without the org scope would leak
        # LastAdminError instead of "not found".
        return db.add_account(org_id=OTHER_ORG_ID, role="org_admin", status=status)
    if case == "deleted":
        return _deleted(db, status)
    if case == "super-admin":
        return db.add_account(kind="super_admin", role=None)
    assert case == "unknown"
    return uuid.uuid4()


def _inactive_other_admin(db: FakeDb, case: str) -> None:
    """Another Org Admin who does NOT count as an active Org Admin of ORG_ID."""
    if case == "deactivated":
        db.add_account(role="org_admin", status="deactivated")
    elif case == "invited":
        _invited(db, role="org_admin")
    elif case == "deleted":
        _deleted(db, role="org_admin")
    elif case == "other-org":
        db.add_account(role="org_admin", org_id=OTHER_ORG_ID)


def _mixed_org(db: FakeDb) -> dict[str, uuid.UUID]:
    """ORG_ID (10 seats) with accounts of every kind, OTHER_ORG_ID (3 seats) with its own.

    Listed for ORG_ID: admin, editor, colleague (a second Editor), deactivated,
    invited, expired (6). Seats used
    in ORG_ID: all of them but the deactivated one (5). Never listed or counted: the
    deleted active, invited and deactivated accounts, the Super Admin and every
    OTHER_ORG_ID account. OTHER_ORG_ID uses 2 seats (its admin and its invited account).
    """
    db.add_org(ORG_ID, seats=_SEATS)
    ids = {
        "admin": db.add_account(role="org_admin"),
        "editor": db.add_account(role="editor"),
        "colleague": db.add_account(role="editor"),
        "deactivated": db.add_account(role="editor", status="deactivated"),
        "invited": _invited(db),
        "expired": _invited(db, sent_ago=_EXPIRED_AGO),
    }
    _deleted(db, "active", role="editor")
    _deleted(db, "invited", role="editor")
    _deleted(db, "deactivated", role="editor")
    db.add_account(kind="super_admin", role=None)
    db.add_org(OTHER_ORG_ID, seats=3)
    db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
    db.add_account(role="editor", org_id=OTHER_ORG_ID, status="deactivated")
    _invited(db, OTHER_ORG_ID)
    return ids


def _summary_of(db: FakeDb, user_id: uuid.UUID, **overrides: Any) -> dict[str, Any]:
    """What PlatformUserSummary.model_dump() must give for a stored account."""
    account = db.users[user_id]
    summary = {
        "id": user_id,
        "name": account["name"],
        "email": account["email"],
        "role": account["role"],
        "status": account["status"],
        "created_at": account["created_at"],
        "last_login_at": account["last_login_at"],
    }
    summary.update(overrides)
    return summary


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


def _expected_event(
    action: str,
    sa_id: uuid.UUID,
    target: uuid.UUID,
    metadata: dict[str, Any],
    *,
    org_id: uuid.UUID = ORG_ID,
    ip: str | None = _IP,
) -> dict[str, Any]:
    """A Super Admin's event on one user, in the affected org's log."""
    return {
        "action": action,
        "actor_kind": "super_admin",
        "actor_user_id": str(sa_id),
        "org_id": str(org_id),
        "target_type": "user",
        "target_ids": [str(target)],
        "ip": ip,
        "metadata": metadata,
    }


def _audit_one(db: FakeDb, action: str) -> dict[str, Any]:
    """The single audit row of the action (and no other audit row at all)."""
    rows = db.audit_rows(action)
    assert len(rows) == 1, db.audit
    assert db.audit_rows() == rows, db.audit
    return rows[0]


def _index(db: FakeDb, pattern: str) -> int:
    """The position of the first call whose normalized SQL matches."""
    for index, call in enumerate(db.calls):
        if re.search(pattern, call.normalized):
            return index
    msg = f"no call matches {pattern!r}"
    raise AssertionError(msg)


def _one(calls: list[Call]) -> Call:
    assert len(calls) == 1, calls
    return calls[0]


def _assert_single_committed_transaction(db: FakeDb) -> None:
    """Every statement ran on one acquired connection, inside one committed transaction."""
    assert db.calls
    first = db.calls[0]
    assert first.via != "pool"
    assert first.tx is not None
    assert {(call.via, call.tx) for call in db.calls} == {(first.via, first.tx)}
    assert db.transactions == [(first.tx, "commit")]


def _plain_arg(value: Any) -> Any:
    """A bind argument with an asyncpg UUID made a plain uuid.UUID (anything else as is)."""
    if isinstance(value, uuid.UUID) or type(value).__name__ == "UUID":
        return uuid.UUID(str(value))
    return value


def _spy_can(
    pu: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    decide: Callable[[Any, Any], bool],
) -> list[str]:
    """Replace access.can (and platform_users.can, if imported by name); record each
    capability asked for, as its string value."""
    seen: list[str] = []

    def spy(principal: Any, capability: Any) -> bool:
        seen.append(str(capability))
        return decide(principal, capability)

    monkeypatch.setattr(access, "can", spy)
    if hasattr(pu, "can"):
        monkeypatch.setattr(pu, "can", spy)
    return seen


def _spy_revoke_user_sessions(
    pu: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
) -> list[tuple[Any, bool, int]]:
    """Wrap sessions.revoke_user_sessions (and a direct import in platform_users, if any)."""
    real = sessions_mod.revoke_user_sessions
    seen: list[tuple[Any, bool, int]] = []

    async def spy(executor: Any, user_id: Any) -> int:
        in_transaction = executor is not db.pool and executor.is_in_transaction()
        count: int = await real(executor, user_id)
        seen.append((user_id, in_transaction, count))
        return count

    monkeypatch.setattr(sessions_mod, "revoke_user_sessions", spy)
    if hasattr(pu, "revoke_user_sessions"):
        monkeypatch.setattr(pu, "revoke_user_sessions", spy)
    return seen


def _imported_modules(pu: ModuleType) -> list[str]:
    """Every module platform_users.py imports (``from admino import x`` gives admino.x)."""
    tree = ast.parse(Path(inspect.getfile(pu)).read_text(encoding="utf-8"))
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


# ---------------------------------------------------------------------------
# 1. Module surface
# ---------------------------------------------------------------------------


class TestSurface:
    """Signatures and the module's hygiene."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("list_users", ["pool", "actor", "org_id"]),
            ("org_metadata", ["pool", "actor", "org_id"]),
            ("deactivate_user", ["pool", "actor", "org_id", "user_id", "ip"]),
            ("reactivate_user", ["pool", "actor", "org_id", "user_id", "public_url", "ip"]),
            (
                "trigger_password_reset",
                ["pool", "actor", "org_id", "user_id", "public_url", "ip"],
            ),
        ],
    )
    def test_platform_users_signature_is_keyword_only_after_pool(
        self, pu: ModuleType, name: str, expected: list[str]
    ) -> None:
        function = getattr(pu, name)
        params = list(inspect.signature(function).parameters.values())

        assert inspect.iscoroutinefunction(function)
        assert [param.name for param in params] == expected
        assert all(param.kind is inspect.Parameter.KEYWORD_ONLY for param in params[1:])

    def test_platform_users_module_docstring_has_security_notes(self, pu: ModuleType) -> None:
        assert pu.__doc__ is not None
        assert "security" in pu.__doc__.lower()

    def test_platform_users_imports_no_server_agent_llm_tools_or_oauth(
        self, pu: ModuleType
    ) -> None:
        forbidden = [
            module
            for module in _imported_modules(pu)
            if module in {"admino.server", "admino.agent", "admino.oauth"}
            or module.startswith(("admino.llm", "admino.tools"))
        ]

        assert forbidden == []

    def test_platform_users_passes_only_constant_sql_to_the_driver(self, pu: ModuleType) -> None:
        """The SQL argument of every execute/fetch* call is a name or a literal, never an
        f-string, a concatenation or a call result."""
        tree = ast.parse(Path(inspect.getfile(pu)).read_text(encoding="utf-8"))
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

    def test_platform_users_builds_no_sql_by_string_formatting(self, pu: ModuleType) -> None:
        tree = ast.parse(Path(inspect.getfile(pu)).read_text(encoding="utf-8"))
        sites: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                text = "".join(
                    part.value
                    for part in node.values
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
                if _SQL_KEYWORD_RE.search(text):
                    sites.append(node.lineno)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod | ast.Add):
                if any(
                    isinstance(part, ast.Constant)
                    and isinstance(part.value, str)
                    and _SQL_KEYWORD_RE.search(part.value)
                    for part in (node.left, node.right)
                ):
                    sites.append(node.lineno)

        assert sites == []


# ---------------------------------------------------------------------------
# 2. Authorization before any query
# ---------------------------------------------------------------------------


class TestAuthorization:
    """Super Admin only, through the function's capability; a refusal issues no query."""

    @pytest.mark.parametrize("name", _FUNCTIONS)
    @pytest.mark.parametrize("who", _FORBIDDEN)
    async def test_platform_users_without_the_capability_is_forbidden_before_any_query(
        self, pu: ModuleType, db: FakeDb, name: str, who: str
    ) -> None:
        """Member roles (an Org Admin of the very org included), the Operator and malformed
        principals: PermissionError("Forbidden"), no statement, nothing changed."""
        target = _setup(db, name)
        actor = _forbidden_actor(db, who)
        before = db.snapshot()

        with pytest.raises(PermissionError) as excinfo:
            await _call(pu, db, name, actor, user_id=target)

        assert str(excinfo.value) == "Forbidden"
        assert db.calls == []
        assert db.snapshot() == before

    @pytest.mark.parametrize("name", _FUNCTIONS)
    async def test_platform_users_super_admin_passes_the_gate(
        self, pu: ModuleType, db: FakeDb, name: str
    ) -> None:
        target = _setup(db, name)
        _, sa = _super_admin(db)

        await _call(pu, db, name, sa, user_id=target)

        assert db.calls

    @pytest.mark.parametrize("name", _FUNCTIONS)
    async def test_platform_users_super_admin_without_the_capability_is_refused(
        self, pu: ModuleType, db: FakeDb, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The function's capability refused (every other one as the matrix says): the
        Super Admin is refused before any query."""
        target = _setup(db, name)
        _, sa = _super_admin(db)
        wanted = _CAPABILITY_OF[name]
        real = access.can
        seen = _spy_can(pu, monkeypatch, lambda p, cap: str(cap) != wanted and real(p, cap))

        with pytest.raises(PermissionError):
            await _call(pu, db, name, sa, user_id=target)

        assert wanted in seen
        assert db.calls == []

    @pytest.mark.parametrize("name", _FUNCTIONS)
    async def test_platform_users_its_capability_alone_is_enough(
        self, pu: ModuleType, db: FakeDb, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only the function's own capability granted: the call goes through."""
        target = _setup(db, name)
        _, sa = _super_admin(db)
        wanted = _CAPABILITY_OF[name]
        seen = _spy_can(pu, monkeypatch, lambda _p, cap: str(cap) == wanted)

        await _call(pu, db, name, sa, user_id=target)

        assert wanted in seen
        assert db.calls


# ---------------------------------------------------------------------------
# 3. Org scope: unknown org, targets outside the org
# ---------------------------------------------------------------------------


class TestOrgScope:
    """An unknown org is OrgNotFoundError; a user outside the org is UserNotInOrgError."""

    @pytest.mark.parametrize("name", _FUNCTIONS)
    async def test_platform_users_unknown_org_is_org_not_found(
        self, pu: ModuleType, db: FakeDb, name: str
    ) -> None:
        """Checked first: even a real user id (of ORG_ID) under an unknown org's path is
        "organization not found"; nothing changes, the error carries no id."""
        target = _setup(db, name) or db.add_account()
        unknown = uuid.uuid4()
        _, sa = _super_admin(db)
        before = db.snapshot()

        with pytest.raises(organizations.OrgNotFoundError) as excinfo:
            await _call(pu, db, name, sa, org_id=unknown, user_id=target)

        assert str(excinfo.value) == organizations.ORG_NOT_FOUND_MESSAGE
        assert str(unknown) not in str(excinfo.value)
        assert db.matching(_WRITE_RE) == []
        assert db.snapshot() == before

    @pytest.mark.parametrize("action", _ACTIONS)
    @pytest.mark.parametrize("case", _OUTSIDE_CASES)
    async def test_platform_users_target_outside_the_org_is_user_not_in_org(
        self, pu: ModuleType, db: FakeDb, action: str, case: str
    ) -> None:
        """Another org's user, an unknown id, a deleted account or a Super Admin's id under
        ORG_ID's path: UserNotInOrgError (no id in it), nothing changes."""
        _setup(db, "list_users")
        _, sa = _super_admin(db)
        target = _outside_target(db, case, action)
        if target in db.users:
            db.open_session(target)
            db.add_reset_token(target)
        before = db.snapshot()

        with pytest.raises(accounts.UserNotInOrgError) as excinfo:
            await _call(pu, db, action, sa, user_id=target)

        assert db.snapshot() == before
        assert str(target) not in str(excinfo.value)

    @pytest.mark.parametrize(("action", "status"), _WRONG_STATUSES)
    async def test_platform_users_action_in_the_wrong_user_status_is_invalid_status(
        self, pu: ModuleType, db: FakeDb, action: str, status: str
    ) -> None:
        """An invited account is a user of the org, but no action applies to it; nor does
        deactivating a deactivated user, reactivating an active one or resetting a
        deactivated one. The fixed message, nothing changed."""
        _setup(db, "list_users")
        _, sa = _super_admin(db)
        if status == "invited":
            target = _invited(db)
        else:
            target = db.add_account(status=status)
            db.open_session(target)
            db.add_reset_token(target)
        before = db.snapshot()

        with pytest.raises(org_users.InvalidUserStatusError) as excinfo:
            await _call(pu, db, action, sa, user_id=target)

        assert str(excinfo.value) == _INVALID_USER_STATUS
        assert db.snapshot() == before

    @pytest.mark.parametrize("name", _FUNCTIONS)
    async def test_platform_users_ids_travel_as_bind_parameters(
        self, pu: ModuleType, db: FakeDb, name: str
    ) -> None:
        """No org, user or actor id ever appears in the SQL text."""
        target = _setup(db, name)
        sa_id, sa = _super_admin(db)

        await _call(pu, db, name, sa, user_id=target)

        assert db.calls
        for call in db.calls:
            assert str(ORG_ID) not in call.sql
            assert str(sa_id) not in call.sql
            assert target is None or str(target) not in call.sql


# ---------------------------------------------------------------------------
# 4. list_users
# ---------------------------------------------------------------------------


class TestListUsers:
    """Every non-deleted account of the org: active, deactivated and invited."""

    async def test_platform_users_list_holds_active_deactivated_and_invited_accounts(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        ids = _mixed_org(db)
        _, sa = _super_admin(db)

        users = await pu.list_users(db.pool, actor=sa, org_id=ORG_ID)

        assert sorted(summary.id for summary in users) == sorted(ids.values())

    async def test_platform_users_list_of_the_other_org_holds_only_its_accounts(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The scope is the org_id argument: OTHER_ORG_ID's three accounts, none of ORG_ID's."""
        _mixed_org(db)
        _, sa = _super_admin(db)
        expected = {user_id for user_id, row in db.users.items() if row["org_id"] == OTHER_ORG_ID}

        users = await pu.list_users(db.pool, actor=sa, org_id=OTHER_ORG_ID)

        assert len(expected) == 3
        assert {summary.id for summary in users} == expected

    async def test_platform_users_list_never_holds_a_deleted_account(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """An org whose only accounts are deleted (any status) lists nothing."""
        db.add_org(ORG_ID)
        for status in ("active", "deactivated", "invited"):
            _deleted(db, status)
        _, sa = _super_admin(db)

        assert await pu.list_users(db.pool, actor=sa, org_id=ORG_ID) == []

    async def test_platform_users_list_returns_every_summary_field(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Exactly id, name, email, role, status, created_at, last_login_at; an invited
        account has no name and no last login."""
        db.add_account(role="org_admin", created_at=_CREATED - timedelta(days=30))
        deactivated = db.add_account(
            role="editor",
            status="deactivated",
            email="Mixed.Case@Example.test",
            name="Ada Beispiel",
            created_at=_CREATED,
            last_login_at=_LAST_LOGIN,
        )
        invited = _invited(
            db, role="org_admin", email="pending.admin@example.test", created_at=_CREATED
        )
        _, sa = _super_admin(db)

        users = await pu.list_users(db.pool, actor=sa, org_id=ORG_ID)

        by_id = {summary.id: summary for summary in users}
        assert all(isinstance(summary, _model("PlatformUserSummary")) for summary in users)
        assert all(type(summary.id) is uuid.UUID for summary in users)
        assert by_id[deactivated].model_dump() == {
            "id": deactivated,
            "name": "Ada Beispiel",
            "email": "Mixed.Case@Example.test",
            "role": "editor",
            "status": "deactivated",
            "created_at": _CREATED,
            "last_login_at": _LAST_LOGIN,
        }
        assert by_id[invited].model_dump() == {
            "id": invited,
            "name": None,
            "email": "pending.admin@example.test",
            "role": "org_admin",
            "status": "invited",
            "created_at": _CREATED,
            "last_login_at": None,
        }

    async def test_platform_users_list_orders_by_created_at_then_id(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Oldest first; equal created_at by id. Stored in another order on purpose."""
        newest = db.add_account(role="org_admin", created_at=_CREATED + timedelta(days=5))
        tied = [
            db.add_account(created_at=_CREATED),
            _invited(db, created_at=_CREATED),
            db.add_account(status="deactivated", created_at=_CREATED),
        ]
        oldest = _invited(db, created_at=_CREATED - timedelta(days=5))
        # Store the tied rows in descending id order, so insertion order isn't id order.
        for user_id in sorted(tied, reverse=True):
            db.users[user_id] = db.users.pop(user_id)
        _, sa = _super_admin(db)

        users = await pu.list_users(db.pool, actor=sa, org_id=ORG_ID)

        assert [summary.id for summary in users] == [oldest, *sorted(tied), newest]

    async def test_platform_users_list_of_an_org_without_users_is_empty(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID)
        db.add_account(org_id=OTHER_ORG_ID)
        _, sa = _super_admin(db)

        users = await pu.list_users(db.pool, actor=sa, org_id=ORG_ID)

        assert users == []

    @pytest.mark.parametrize("status", _ORG_STATUSES)
    async def test_platform_users_list_works_whatever_the_org_status(
        self, pu: ModuleType, db: FakeDb, status: str
    ) -> None:
        admin = db.add_account(role="org_admin")
        db.add_org(ORG_ID, status=status)
        _, sa = _super_admin(db)

        users = await pu.list_users(db.pool, actor=sa, org_id=ORG_ID)

        assert [summary.id for summary in users] == [admin]

    async def test_platform_users_list_users_statement_is_bound_to_the_org(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The users query is scoped by ``org_id = $n`` bound to the org; it reads no
        password hash and no ``*``."""
        _mixed_org(db)
        _, sa = _super_admin(db)

        await pu.list_users(db.pool, actor=sa, org_id=ORG_ID)

        scoped = [
            call
            for call in db.calls
            if "from users" in call.normalized and re.search(ORG_ID_PARAM_RE, call.normalized)
        ]
        assert scoped, [call.normalized for call in db.calls]
        for call in scoped:
            match = re.search(ORG_ID_PARAM_RE, call.normalized)
            assert match is not None
            assert _plain_arg(call.args[int(match.group(1)) - 1]) == ORG_ID
        assert all("password_hash" not in call.normalized for call in db.calls)
        assert all("select *" not in call.normalized for call in db.calls)

    async def test_platform_users_list_writes_and_audits_nothing(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        _mixed_org(db)
        _, sa = _super_admin(db)
        before = db.snapshot()

        await pu.list_users(db.pool, actor=sa, org_id=ORG_ID)

        assert db.matching(_WRITE_RE) == []
        assert db.snapshot() == before
        assert db.audit == []


# ---------------------------------------------------------------------------
# 5. org_metadata
# ---------------------------------------------------------------------------


async def _metadata(pu: ModuleType, db: FakeDb, org_id: uuid.UUID = ORG_ID) -> Any:
    """The org's metadata, read by a fresh Super Admin; its type checked."""
    _, sa = _super_admin(db)
    result = await pu.org_metadata(db.pool, actor=sa, org_id=org_id)
    assert isinstance(result, _model("OrgMetadata")), type(result)
    assert isinstance(result.seats, models.OrgSeats), type(result.seats)
    return result


def _seats(result: Any) -> tuple[int, int]:
    """(used, limit) of an OrgMetadata."""
    return result.seats.used, result.seats.limit


class TestOrgMetadata:
    """Counts and sizes only: seats used and limit, storage, chats and files."""

    async def test_platform_users_metadata_json_has_exactly_the_contract_keys(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """{"seats": {"used", "limit"}, "storage_used_bytes", "chat_count", "file_count"}:
        no name, title or any other field; storage and files are 0 until #187, and with no
        chats stored chat_count is 0 too."""
        _mixed_org(db)

        result = await _metadata(pu, db)

        assert result.model_dump(mode="json") == {
            "seats": {"used": 5, "limit": _SEATS},
            "storage_used_bytes": 0,
            "chat_count": 0,
            "file_count": 0,
        }

    async def test_platform_users_metadata_counts_are_ints(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        _mixed_org(db)

        result = await _metadata(pu, db)

        values = (
            result.seats.used,
            result.seats.limit,
            result.storage_used_bytes,
            result.chat_count,
            result.file_count,
        )
        assert [type(value) for value in values] == [int] * 5

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    async def test_platform_users_metadata_counts_an_active_member_of_any_role(
        self, pu: ModuleType, db: FakeDb, role: str
    ) -> None:
        db.add_org(ORG_ID, seats=_SEATS)
        db.add_account(role="org_admin")
        db.add_account(role=role)

        assert _seats(await _metadata(pu, db)) == (2, _SEATS)

    @pytest.mark.parametrize("sent_ago", [timedelta(0), _EXPIRED_AGO], ids=["pending", "expired"])
    async def test_platform_users_metadata_counts_an_invited_account(
        self, pu: ModuleType, db: FakeDb, sent_ago: timedelta
    ) -> None:
        """A pending and an expired invitation both hold their seat."""
        db.add_org(ORG_ID, seats=_SEATS)
        db.add_account(role="org_admin")
        _invited(db, sent_ago=sent_ago)

        assert _seats(await _metadata(pu, db)) == (2, _SEATS)

    async def test_platform_users_metadata_skips_a_deactivated_user(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID, seats=_SEATS)
        db.add_account(role="org_admin")
        db.add_account(status="deactivated")

        assert _seats(await _metadata(pu, db)) == (1, _SEATS)

    @pytest.mark.parametrize("status", ["active", "invited"])
    async def test_platform_users_metadata_skips_a_deleted_user(
        self, pu: ModuleType, db: FakeDb, status: str
    ) -> None:
        db.add_org(ORG_ID, seats=_SEATS)
        db.add_account(role="org_admin")
        _deleted(db, status)

        assert _seats(await _metadata(pu, db)) == (1, _SEATS)

    async def test_platform_users_metadata_never_counts_another_orgs_user_or_a_super_admin(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_org(ORG_ID, seats=_SEATS)
        db.add_account(role="org_admin")
        db.add_account(org_id=OTHER_ORG_ID)
        _invited(db, OTHER_ORG_ID)
        db.add_account(kind="super_admin", role=None)

        assert _seats(await _metadata(pu, db)) == (1, _SEATS)

    async def test_platform_users_metadata_of_a_mixed_org(self, pu: ModuleType, db: FakeDb) -> None:
        _mixed_org(db)

        assert _seats(await _metadata(pu, db)) == (5, _SEATS)

    async def test_platform_users_metadata_of_the_other_org_is_its_own(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        _mixed_org(db)

        assert _seats(await _metadata(pu, db, OTHER_ORG_ID)) == (2, 3)

    async def test_platform_users_metadata_used_follows_the_invitation_seat_rule(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """``used`` is what invitations._SEATS_TAKEN_SQL counts (#153's rule)."""
        _mixed_org(db)
        taken = await db.pool.fetchval(invitations._SEATS_TAKEN_SQL, ORG_ID)

        assert (await _metadata(pu, db)).seats.used == taken

    async def test_platform_users_metadata_used_may_exceed_the_limit(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Seats lowered below the org's users: 3 of 1, no error."""
        db.add_account(role="org_admin")
        db.add_account()
        _invited(db)
        db.add_org(ORG_ID, seats=1)

        assert _seats(await _metadata(pu, db)) == (3, 1)

    @pytest.mark.parametrize("limit", [1, 7, 250, 100000])
    async def test_platform_users_metadata_limit_is_the_orgs_seats(
        self, pu: ModuleType, db: FakeDb, limit: int
    ) -> None:
        db.add_org(ORG_ID, seats=limit)
        db.add_org(OTHER_ORG_ID, seats=42)

        assert _seats(await _metadata(pu, db)) == (0, limit)

    @pytest.mark.parametrize("status", _ORG_STATUSES)
    async def test_platform_users_metadata_works_whatever_the_org_status(
        self, pu: ModuleType, db: FakeDb, status: str
    ) -> None:
        db.add_account(role="org_admin")
        db.add_org(ORG_ID, seats=_SEATS, status=status)

        assert _seats(await _metadata(pu, db)) == (1, _SEATS)

    async def test_platform_users_metadata_chat_count_is_the_orgs_live_chats(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """GH-176: every member's chat that isn't trashed counts (the second Editor's and
        the deactivated member's included); a trashed chat and another org's chats don't. The
        Super Admin gets a count only: the exact contract keys, no title in the result and
        no statement that reads a title."""
        ids = _mixed_org(db)
        other_admin = next(
            user_id
            for user_id, row in db.users.items()
            if row["org_id"] == OTHER_ORG_ID and row["role"] == "org_admin"
        )
        for owner in ("admin", "admin", "editor", "colleague", "deactivated"):
            db.add_chat(ids[owner], title=_CHAT_TITLE)
        db.add_chat(ids["editor"], title=_CHAT_TITLE, deleted_at=_CREATED)
        for _ in range(2):
            db.add_chat(other_admin, title=_CHAT_TITLE)
        db.calls.clear()

        result = await _metadata(pu, db)

        assert result.model_dump(mode="json") == {
            "seats": {"used": 5, "limit": _SEATS},
            "storage_used_bytes": 0,
            "chat_count": 5,
            "file_count": 0,
        }
        assert _CHAT_TITLE not in json.dumps(result.model_dump(mode="json"))
        assert [call.normalized for call in db.calls if "title" in call.normalized] == []

    async def test_platform_users_metadata_chat_count_of_the_other_org_is_its_own(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """OTHER_ORG_ID counts its two chats, none of ORG_ID's."""
        ids = _mixed_org(db)
        other_admin = next(
            user_id
            for user_id, row in db.users.items()
            if row["org_id"] == OTHER_ORG_ID and row["role"] == "org_admin"
        )
        for owner in (ids["admin"], ids["editor"], other_admin, other_admin):
            db.add_chat(owner, title=_CHAT_TITLE)

        result = await _metadata(pu, db, OTHER_ORG_ID)

        assert (result.chat_count, type(result.chat_count)) == (2, int)

    async def test_platform_users_metadata_storage_counts_the_orgs_derived_bytes(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """GH-188 (contract 12.4, A7'): storage_used_bytes is the originals plus the
        derived files of every file of the org (NULL derived bytes count 0, trashed
        files too); another org's derived bytes count only for that org. Counts only: no
        file name or token estimate in the result, and no statement reads either."""
        ids = _mixed_org(db)
        other_admin = next(
            user_id
            for user_id, row in db.users.items()
            if row["org_id"] == OTHER_ORG_ID and row["role"] == "org_admin"
        )
        chat = db.add_chat(ids["editor"], title=_CHAT_TITLE)
        db.add_attachment(chat, filename=_FILE_NAME_MARKER, size_bytes=10)
        db.add_attachment(
            chat,
            filename=_FILE_NAME_MARKER,
            size_bytes=20,
            status="ready",
            page_count=3,
            token_estimate=_TOKEN_ESTIMATE_MARKER,
            derived_bytes=300,
        )
        db.add_attachment(chat, size_bytes=5, derived_bytes=7, deleted_at=_CREATED)
        db.add_attachment(db.add_chat(other_admin), size_bytes=1000, derived_bytes=5000)
        db.calls.clear()

        own = (await _metadata(pu, db)).model_dump(mode="json")
        other = (await _metadata(pu, db, OTHER_ORG_ID)).model_dump(mode="json")

        assert (own, other) == (
            {
                "seats": {"used": 5, "limit": _SEATS},
                "storage_used_bytes": 342,
                "chat_count": 1,
                "file_count": 3,
            },
            {
                "seats": {"used": 2, "limit": 3},
                "storage_used_bytes": 6000,
                "chat_count": 1,
                "file_count": 1,
            },
        )
        text = json.dumps([own, other])
        assert _FILE_NAME_MARKER not in text
        assert str(_TOKEN_ESTIMATE_MARKER) not in text
        assert [
            call.normalized
            for call in db.calls
            if "filename" in call.normalized or "token_estimate" in call.normalized
        ] == []

    async def test_platform_users_metadata_reads_are_bound_to_the_org(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Every statement binds the org id; none reads another org or a password hash."""
        _mixed_org(db)
        db.calls.clear()

        await _metadata(pu, db)

        assert db.calls, "org_metadata must read the database"
        assert all(ORG_ID in [_plain_arg(arg) for arg in call.args] for call in db.calls)
        assert all(OTHER_ORG_ID not in [_plain_arg(arg) for arg in call.args] for call in db.calls)
        assert all("password_hash" not in call.normalized for call in db.calls)

    async def test_platform_users_metadata_writes_and_audits_nothing(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        _mixed_org(db)
        _, sa = _super_admin(db)
        before = db.snapshot()

        await pu.org_metadata(db.pool, actor=sa, org_id=ORG_ID)

        assert db.matching(_WRITE_RE) == []
        assert db.snapshot() == before
        assert db.audit == []


# ---------------------------------------------------------------------------
# 6. deactivate_user
# ---------------------------------------------------------------------------


class TestDeactivateUser:
    """Status, sessions, email, audit, the last-admin guard; any org status."""

    async def test_platform_users_deactivate_sets_status_and_returns_the_summary(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account(
            role="editor",
            email="summary.target@example.test",
            name="Summary Person",
            created_at=_CREATED,
            last_login_at=_LAST_LOGIN,
        )
        _, sa = _super_admin(db)

        result = await _call(pu, db, "deactivate", sa, user_id=target)

        assert db.users[target]["status"] == "deactivated"
        assert isinstance(result, _model("PlatformUserSummary"))
        assert type(result.id) is uuid.UUID
        assert result.model_dump() == _summary_of(db, target, status="deactivated")

    async def test_platform_users_deactivate_revokes_every_session_of_the_user_only(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Live, idle and expired session rows of the target go; the admin's, a colleague's,
        another org's user's and the Super Admin's own stay."""
        admin = db.add_account(role="org_admin")
        target = db.add_account()
        bystander = db.add_account()
        outsider = db.add_account(org_id=OTHER_ORG_ID)
        sa_id, sa = _super_admin(db)
        theirs = [
            db.open_session(target),
            db.open_session(target, last_seen_ago=timedelta(minutes=90)),
            db.open_session(target, expires_in=timedelta(seconds=-5)),
        ]
        kept = [db.open_session(user_id) for user_id in (admin, bystander, outsider, sa_id)]

        await _call(pu, db, "deactivate", sa, user_id=target)

        assert db.sessions_of(target) == []
        assert all(db.session_revoked(token) for token in theirs)
        assert not any(db.session_revoked(token) for token in kept)

    async def test_platform_users_deactivate_revokes_through_revoke_user_sessions(
        self, pu: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The shared revocation service deletes the sessions, once, inside the transaction."""
        db.add_account(role="org_admin")
        target = db.add_account()
        db.open_session(target)
        db.open_session(target)
        _, sa = _super_admin(db)
        seen = _spy_revoke_user_sessions(pu, db, monkeypatch)

        await _call(pu, db, "deactivate", sa, user_id=target)

        assert len(seen) == 1
        user_id, in_transaction, count = seen[0]
        assert plain(user_id) == target
        assert in_transaction
        assert count == 2

    async def test_platform_users_deactivate_queues_one_account_deactivated_email(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account(email="deactivated.user@example.test")
        _, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, user_id=target)

        assert len(db.outbox) == 1
        row = db.outbox[0]
        assert row["user_id"] == target
        assert row["recipient_address"] == "deactivated.user@example.test"
        assert row["template_key"] == "account_deactivated"
        assert row["status"] == "pending"
        assert row["params"] == {"org_name": ORG_NAME}

    async def test_platform_users_deactivate_is_audited_in_the_orgs_log(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """One user.deactivate row: the Super Admin as actor, ORG_ID, target the user, the
        IP, {"sessions_revoked": n}."""
        db.add_account(role="org_admin")
        target = db.add_account()
        for _ in range(3):
            db.open_session(target)
        sa_id, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, user_id=target)

        row = _audit_one(db, "user.deactivate")
        assert _audit_view(row) == _expected_event(
            "user.deactivate", sa_id, target, {"sessions_revoked": 3}
        )
        assert type(row["metadata"]["sessions_revoked"]) is int

    async def test_platform_users_deactivate_without_sessions_records_zero_and_no_ip(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account()
        sa_id, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, user_id=target, ip=None)

        assert _audit_view(_audit_one(db, "user.deactivate")) == _expected_event(
            "user.deactivate", sa_id, target, {"sessions_revoked": 0}, ip=None
        )

    async def test_platform_users_deactivate_in_another_org_names_that_org(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Acting on OTHER_ORG_ID: the email carries its name and the event its id."""
        db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
        target = db.add_account(org_id=OTHER_ORG_ID)
        db.add_account(role="org_admin")
        sa_id, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, org_id=OTHER_ORG_ID, user_id=target)

        assert db.users[target]["status"] == "deactivated"
        assert [row["params"] for row in db.outbox] == [{"org_name": OTHER_ORG_NAME}]
        assert _audit_view(_audit_one(db, "user.deactivate")) == _expected_event(
            "user.deactivate", sa_id, target, {"sessions_revoked": 0}, org_id=OTHER_ORG_ID
        )

    async def test_platform_users_deactivate_keeps_connections_memory_and_settings(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account()
        db.add_oauth_token(target, "google", encrypted_refresh_token="enc-google")
        db.add_oauth_token(target, "microsoft", encrypted_refresh_token="enc-microsoft")
        db.add_memory(target, "favourite_colour", "blue")
        db.add_user_settings(target, theme="dark")
        _, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, user_id=target)

        assert db.oauth_token(target, "google") is not None
        assert db.oauth_token(target, "microsoft") is not None
        assert db.memories_of(target) == {"favourite_colour": "blue"}
        assert db.user_settings[target]["theme"] == "dark"

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    async def test_platform_users_deactivate_any_role(
        self, pu: ModuleType, db: FakeDb, role: str
    ) -> None:
        """Any member of the org (an Org Admin who isn't the last one included)."""
        db.add_account(role="org_admin")
        target = db.add_account(role=role)
        _, sa = _super_admin(db)

        result = await _call(pu, db, "deactivate", sa, user_id=target)

        assert result.status == "deactivated"
        assert db.users[target]["status"] == "deactivated"

    @pytest.mark.parametrize("status", _ORG_STATUSES)
    async def test_platform_users_deactivate_works_whatever_the_org_status(
        self, pu: ModuleType, db: FakeDb, status: str
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account()
        token = db.open_session(target)
        db.add_org(ORG_ID, status=status)
        _, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, user_id=target)

        assert db.users[target]["status"] == "deactivated"
        assert db.session_revoked(token)
        assert _audit_one(db, "user.deactivate")["target_ids"] == [str(target)]

    @pytest.mark.parametrize("other_admin", _INACTIVE_OTHER_ADMINS)
    async def test_platform_users_deactivate_last_active_admin_is_refused(
        self, pu: ModuleType, db: FakeDb, other_admin: str
    ) -> None:
        """The guard applies to the Super Admin too: the org's only active Org Admin
        (other admins deactivated, invited, deleted or of another org don't count) can't
        be deactivated. LastAdminError, nothing changes."""
        admin = db.add_account(role="org_admin")
        _inactive_other_admin(db, other_admin)
        db.open_session(admin)
        _, sa = _super_admin(db)
        before = db.snapshot()

        with pytest.raises(accounts.LastAdminError):
            await _call(pu, db, "deactivate", sa, user_id=admin)

        assert db.snapshot() == before

    async def test_platform_users_deactivate_admin_with_a_second_active_admin_passes(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        admin = db.add_account(role="org_admin")
        db.add_account(role="org_admin")
        token = db.open_session(admin)
        _, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, user_id=admin)

        assert db.users[admin]["status"] == "deactivated"
        assert db.session_revoked(token)

    async def test_platform_users_deactivate_runs_the_last_admin_guard_before_the_change(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """accounts.ensure_not_last_active_admin's query, bound to (org, target), runs in
        the transaction before the status UPDATE and the session deletion."""
        db.add_account(role="org_admin")
        target = db.add_account()
        db.open_session(target)
        _, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, user_id=target)

        guard_index = _index(db, _GUARD_RE)
        guard = db.calls[guard_index]
        update = _one(db.matching(r"^update users\b"))
        assert [plain(arg) for arg in guard.args] == [ORG_ID, target]
        assert (guard.via, guard.tx) == (update.via, update.tx)
        assert guard_index < db.calls.index(update)
        assert guard_index < _index(db, r"^delete from sessions\b")

    async def test_platform_users_deactivate_runs_in_one_committed_transaction(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account()
        db.open_session(target)
        _, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, user_id=target)

        _assert_single_committed_transaction(db)

    async def test_platform_users_deactivate_audit_failure_changes_nothing(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: AuditRecordError; status, sessions and outbox as before."""
        db.add_account(role="org_admin")
        target = db.add_account()
        tokens = [db.open_session(target), db.open_session(target)]
        _, sa = _super_admin(db)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _call(pu, db, "deactivate", sa, user_id=target)

        assert db.snapshot() == before
        assert db.users[target]["status"] == "active"
        assert not any(db.session_revoked(token) for token in tokens)
        assert db.outbox == []
        assert [outcome for _, outcome in db.transactions] == ["rollback:AuditRecordError"]


# ---------------------------------------------------------------------------
# 7. reactivate_user
# ---------------------------------------------------------------------------


class TestReactivateUser:
    """Status, seats, email, audit; refused while the org's deletion is pending."""

    async def test_platform_users_reactivate_sets_status_and_returns_the_summary(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account(
            role="editor",
            status="deactivated",
            email="back.again@example.test",
            created_at=_CREATED,
            last_login_at=_LAST_LOGIN,
        )
        _, sa = _super_admin(db)

        result = await _call(pu, db, "reactivate", sa, user_id=target)

        assert db.users[target]["status"] == "active"
        assert isinstance(result, _model("PlatformUserSummary"))
        assert result.model_dump() == _summary_of(db, target, status="active")

    async def test_platform_users_reactivate_queues_one_account_activated_email(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """org_name and login_link = {public_url}/login, to the user."""
        db.add_account(role="org_admin")
        target = db.add_account(status="deactivated", email="reactivated.user@example.test")
        _, sa = _super_admin(db)

        await _call(pu, db, "reactivate", sa, user_id=target)

        assert len(db.outbox) == 1
        row = db.outbox[0]
        assert row["user_id"] == target
        assert row["recipient_address"] == "reactivated.user@example.test"
        assert row["template_key"] == "account_activated"
        assert row["status"] == "pending"
        assert row["params"] == {"org_name": ORG_NAME, "login_link": _LOGIN_LINK}

    async def test_platform_users_reactivate_is_audited_in_the_orgs_log(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account(status="deactivated")
        sa_id, sa = _super_admin(db)

        await _call(pu, db, "reactivate", sa, user_id=target)

        assert _audit_view(_audit_one(db, "user.activate")) == _expected_event(
            "user.activate", sa_id, target, {}
        )

    async def test_platform_users_reactivate_in_another_org_names_that_org(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
        target = db.add_account(org_id=OTHER_ORG_ID, status="deactivated")
        db.add_account(role="org_admin")
        sa_id, sa = _super_admin(db)

        await _call(pu, db, "reactivate", sa, org_id=OTHER_ORG_ID, user_id=target)

        assert db.users[target]["status"] == "active"
        assert [row["params"] for row in db.outbox] == [
            {"org_name": OTHER_ORG_NAME, "login_link": _LOGIN_LINK}
        ]
        assert _audit_one(db, "user.activate")["org_id"] == OTHER_ORG_ID

    @pytest.mark.parametrize("status", ["active", "deactivated"])
    async def test_platform_users_reactivate_works_in_an_active_or_deactivated_org(
        self, pu: ModuleType, db: FakeDb, status: str
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account(status="deactivated")
        db.add_org(ORG_ID, status=status)
        _, sa = _super_admin(db)

        await _call(pu, db, "reactivate", sa, user_id=target)

        assert db.users[target]["status"] == "active"

    async def test_platform_users_reactivate_while_deletion_is_pending_is_invalid_org_status(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account(status="deactivated")
        db.add_org(ORG_ID, status="pending_deletion")
        _, sa = _super_admin(db)
        before = db.snapshot()

        with pytest.raises(organizations.InvalidOrgStatusError) as excinfo:
            await _call(pu, db, "reactivate", sa, user_id=target)

        assert str(excinfo.value) == organizations.INVALID_STATUS_MESSAGE
        assert db.snapshot() == before

    @pytest.mark.parametrize("target_kind", ["active-user", "unknown-user", "no-free-seat"])
    async def test_platform_users_reactivate_checks_the_org_status_before_the_target(
        self, pu: ModuleType, db: FakeDb, target_kind: str
    ) -> None:
        """Pending deletion wins over a wrong user status, an unknown user and a full org."""
        db.add_account(role="org_admin")
        if target_kind == "active-user":
            target = db.add_account()
        elif target_kind == "unknown-user":
            target = uuid.uuid4()
        else:
            target = db.add_account(status="deactivated")
            db.add_org(ORG_ID, seats=1)
        db.add_org(ORG_ID, status="pending_deletion")
        _, sa = _super_admin(db)

        with pytest.raises(organizations.InvalidOrgStatusError):
            await _call(pu, db, "reactivate", sa, user_id=target)

    async def test_platform_users_reactivate_checks_the_user_status_before_the_seats(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """An active user in a full org: InvalidUserStatusError, not SeatLimitError."""
        db.add_account(role="org_admin")
        target = db.add_account()
        db.add_org(ORG_ID, seats=2)
        _, sa = _super_admin(db)

        with pytest.raises(org_users.InvalidUserStatusError):
            await _call(pu, db, "reactivate", sa, user_id=target)

    @pytest.mark.parametrize("occupant", ["active", "pending-invite", "expired-invite"])
    async def test_platform_users_reactivate_without_a_free_seat_is_seat_limit(
        self, pu: ModuleType, db: FakeDb, occupant: str
    ) -> None:
        """Seats == active + invited users (an expired invitation keeps its seat):
        SeatLimitError, the user stays deactivated, nothing queued or audited."""
        db.add_account(role="org_admin")
        if occupant == "active":
            db.add_account()
        else:
            _invited(db, sent_ago=_EXPIRED_AGO if occupant == "expired-invite" else timedelta(0))
        target = db.add_account(status="deactivated")
        db.add_org(ORG_ID, seats=2)
        _, sa = _super_admin(db)
        before = db.snapshot()

        with pytest.raises(invitations.SeatLimitError) as excinfo:
            await _call(pu, db, "reactivate", sa, user_id=target)

        assert str(excinfo.value) == invitations.SEAT_LIMIT_MESSAGE
        assert db.snapshot() == before

    async def test_platform_users_reactivate_in_an_over_full_org_is_seat_limit(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        db.add_account()
        target = db.add_account(status="deactivated")
        db.add_org(ORG_ID, seats=1)
        _, sa = _super_admin(db)

        with pytest.raises(invitations.SeatLimitError):
            await _call(pu, db, "reactivate", sa, user_id=target)

        assert db.users[target]["status"] == "deactivated"

    async def test_platform_users_reactivate_takes_the_last_free_seat(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Seats 2: the admin, deactivated, deleted and other-org users leave one free."""
        db.add_account(role="org_admin")
        for _ in range(3):
            db.add_account(status="deactivated")
        _deleted(db, "active")
        _deleted(db, "invited")
        for _ in range(3):
            db.add_account(org_id=OTHER_ORG_ID)
        target = db.add_account(status="deactivated")
        db.add_org(ORG_ID, seats=2)
        _, sa = _super_admin(db)

        await _call(pu, db, "reactivate", sa, user_id=target)

        assert db.users[target]["status"] == "active"

    async def test_platform_users_reactivate_runs_in_one_committed_transaction(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account(status="deactivated")
        _, sa = _super_admin(db)

        await _call(pu, db, "reactivate", sa, user_id=target)

        _assert_single_committed_transaction(db)

    async def test_platform_users_reactivate_audit_failure_changes_nothing(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account(status="deactivated")
        _, sa = _super_admin(db)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _call(pu, db, "reactivate", sa, user_id=target)

        assert db.snapshot() == before
        assert db.users[target]["status"] == "deactivated"
        assert db.outbox == []
        assert [outcome for _, outcome in db.transactions] == ["rollback:AuditRecordError"]


# ---------------------------------------------------------------------------
# 8. trigger_password_reset
# ---------------------------------------------------------------------------


class TestTriggerPasswordReset:
    """GH-151's link for an active user of an active org, the Super Admin as actor."""

    async def test_platform_users_reset_queues_one_password_reset_email(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """{public_url}/reset-password#token=<43 URL-safe characters>, to the user."""
        db.add_account(role="org_admin")
        target = db.add_account(email="forgetful.user@example.test")
        _, sa = _super_admin(db)

        await _call(pu, db, "password_reset", sa, user_id=target)

        assert len(db.outbox) == 1
        row = db.outbox[0]
        assert row["user_id"] == target
        assert row["recipient_address"] == "forgetful.user@example.test"
        assert row["template_key"] == "password_reset"
        assert row["status"] == "pending"
        link = row["params"]["reset_link"]
        assert link.startswith(LINK_PREFIX)
        assert TOKEN_RE.fullmatch(link[len(LINK_PREFIX) :]) is not None

    async def test_platform_users_reset_stores_only_the_token_hash(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """The stored token is the SHA-256 of the emailed one; the raw token appears in no
        statement but the outbox INSERT."""
        db.add_account(role="org_admin")
        target = db.add_account()
        _, sa = _super_admin(db)

        await _call(pu, db, "password_reset", sa, user_id=target)

        token = db.issued_token()
        assert db.tokens[target]["token_hash"] == sha256(token)
        for call in db.calls:
            if call.normalized.startswith("insert into email_outbox"):
                continue
            assert token not in call.sql
            assert not any(token in str(arg) for arg in call.args), call.normalized

    async def test_platform_users_reset_replaces_the_previous_token(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """One live token per user: a stored one and the first reset's are both replaced
        by the newest."""
        db.add_account(role="org_admin")
        target = db.add_account()
        old = db.add_reset_token(target)
        _, sa = _super_admin(db)

        await _call(pu, db, "password_reset", sa, user_id=target)
        await _call(pu, db, "password_reset", sa, user_id=target)

        first, newest = db.issued_token(0), db.issued_token(1)
        assert len(db.reset_links()) == 2
        assert db.tokens[target]["token_hash"] == sha256(newest)
        assert db.tokens[target]["token_hash"] not in {sha256(old), sha256(first)}

    async def test_platform_users_reset_is_audited_with_the_super_admin_as_actor(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account()
        sa_id, sa = _super_admin(db)

        await _call(pu, db, "password_reset", sa, user_id=target)

        assert _audit_view(_audit_one(db, "password_reset.request")) == _expected_event(
            "password_reset.request", sa_id, target, {"email_sent": True}
        )

    async def test_platform_users_reset_in_another_org_is_audited_there(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin", org_id=OTHER_ORG_ID)
        target = db.add_account(org_id=OTHER_ORG_ID)
        db.add_account(role="org_admin")
        sa_id, sa = _super_admin(db)

        await _call(pu, db, "password_reset", sa, org_id=OTHER_ORG_ID, user_id=target)

        assert db.tokens[target]["token_hash"] == sha256(db.issued_token())
        assert _audit_view(_audit_one(db, "password_reset.request")) == _expected_event(
            "password_reset.request", sa_id, target, {"email_sent": True}, org_id=OTHER_ORG_ID
        )

    async def test_platform_users_reset_returns_none(self, pu: ModuleType, db: FakeDb) -> None:
        """The Super Admin never sees the token or the link."""
        db.add_account(role="org_admin")
        target = db.add_account()
        _, sa = _super_admin(db)

        assert await _call(pu, db, "password_reset", sa, user_id=target) is None

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    async def test_platform_users_reset_any_role(
        self, pu: ModuleType, db: FakeDb, role: str
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account(role=role)
        _, sa = _super_admin(db)

        await _call(pu, db, "password_reset", sa, user_id=target)

        assert db.tokens[target]["token_hash"] == sha256(db.issued_token())

    @pytest.mark.parametrize("status", ["deactivated", "pending_deletion"])
    async def test_platform_users_reset_in_an_org_that_is_not_active_is_invalid_org_status(
        self, pu: ModuleType, db: FakeDb, status: str
    ) -> None:
        """A link wouldn't work there: InvalidOrgStatusError, the old token kept, no email."""
        db.add_account(role="org_admin")
        target = db.add_account()
        old = db.add_reset_token(target)
        db.add_org(ORG_ID, status=status)
        _, sa = _super_admin(db)
        before = db.snapshot()

        with pytest.raises(organizations.InvalidOrgStatusError) as excinfo:
            await _call(pu, db, "password_reset", sa, user_id=target)

        assert str(excinfo.value) == organizations.INVALID_STATUS_MESSAGE
        assert db.snapshot() == before
        assert db.tokens[target]["token_hash"] == sha256(old)

    @pytest.mark.parametrize("target_kind", ["deactivated-user", "unknown-user"])
    async def test_platform_users_reset_checks_the_org_status_before_the_target(
        self, pu: ModuleType, db: FakeDb, target_kind: str
    ) -> None:
        db.add_account(role="org_admin")
        if target_kind == "deactivated-user":
            target = db.add_account(status="deactivated")
        else:
            target = uuid.uuid4()
        db.add_org(ORG_ID, status="deactivated")
        _, sa = _super_admin(db)

        with pytest.raises(organizations.InvalidOrgStatusError):
            await _call(pu, db, "password_reset", sa, user_id=target)

    async def test_platform_users_reset_runs_in_one_committed_transaction(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin")
        target = db.add_account()
        _, sa = _super_admin(db)

        await _call(pu, db, "password_reset", sa, user_id=target)

        _assert_single_committed_transaction(db)

    async def test_platform_users_reset_audit_failure_stores_and_queues_nothing(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        """Fail closed: AuditRecordError; the old token still matches, no email queued."""
        db.add_account(role="org_admin")
        target = db.add_account()
        old = db.add_reset_token(target)
        _, sa = _super_admin(db)
        before = db.snapshot()
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _call(pu, db, "password_reset", sa, user_id=target)

        assert db.snapshot() == before
        assert db.tokens[target]["token_hash"] == sha256(old)
        assert db.outbox == []
        assert [outcome for _, outcome in db.transactions] == ["rollback:AuditRecordError"]


# ---------------------------------------------------------------------------
# 9. No content in audit rows or logs
# ---------------------------------------------------------------------------


_SECRETS: Final = (
    _MARKER_EMAIL,
    "Markerperson",
    _SA_EMAIL,
    "Rootmarker",
    _ADMIN_EMAIL,
    "Adminmarker",
    ORG_NAME,
    PUBLIC_URL,
    "reset-password",
)


class TestNoContent:
    """IDs, counts and bools only: never a name, an email, a token or a link."""

    async def test_platform_users_audit_rows_carry_no_content(
        self, pu: ModuleType, db: FakeDb
    ) -> None:
        db.add_account(role="org_admin", email=_ADMIN_EMAIL, name=_ADMIN_NAME)
        target = db.add_account(email=_MARKER_EMAIL, name=_MARKER_NAME)
        db.open_session(target)
        _, sa = _super_admin(db)

        await _call(pu, db, "deactivate", sa, user_id=target)
        await _call(pu, db, "reactivate", sa, user_id=target)
        await _call(pu, db, "password_reset", sa, user_id=target)
        token = db.issued_token()

        assert [row["action"] for row in db.audit] == [
            "user.deactivate",
            "user.activate",
            "password_reset.request",
        ]
        text = json.dumps(db.audit, default=str)
        for secret in (*_SECRETS, token):
            assert secret not in text

    async def test_platform_users_log_nothing_on_success_or_refusal(
        self, pu: ModuleType, db: FakeDb, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Reads, actions and every kind of refusal: no admino log record at all, and no
        name, email, token or link in any log line."""
        caplog.set_level(logging.DEBUG)
        admin = db.add_account(role="org_admin", email=_ADMIN_EMAIL, name=_ADMIN_NAME)
        target = db.add_account(email=_MARKER_EMAIL, name=_MARKER_NAME)
        outsider = db.add_account(org_id=OTHER_ORG_ID, email="outsider.marker@example.test")
        db.add_org(ORG_ID, seats=2)
        db.open_session(target)
        _, sa = _super_admin(db)
        editor = _principal(db, target)

        await _call(pu, db, "list_users", sa)
        await _call(pu, db, "org_metadata", sa)
        with pytest.raises(PermissionError):
            await _call(pu, db, "list_users", editor)
        with pytest.raises(organizations.OrgNotFoundError):
            await _call(pu, db, "org_metadata", sa, org_id=uuid.uuid4())
        with pytest.raises(accounts.UserNotInOrgError):
            await _call(pu, db, "deactivate", sa, user_id=outsider)
        with pytest.raises(accounts.LastAdminError):
            await _call(pu, db, "deactivate", sa, user_id=admin)
        await _call(pu, db, "deactivate", sa, user_id=target)
        with pytest.raises(org_users.InvalidUserStatusError):
            await _call(pu, db, "password_reset", sa, user_id=target)
        filler = db.add_account()
        with pytest.raises(invitations.SeatLimitError):
            await _call(pu, db, "reactivate", sa, user_id=target)
        db.users[filler]["status"] = "deactivated"
        await _call(pu, db, "reactivate", sa, user_id=target)
        await _call(pu, db, "password_reset", sa, user_id=target)
        token = db.issued_token()
        db.add_org(ORG_ID, status="deactivated")
        with pytest.raises(organizations.InvalidOrgStatusError):
            await _call(pu, db, "password_reset", sa, user_id=target)

        assert [record.name for record in caplog.records if record.name.startswith("admino")] == []
        for secret in (*_SECRETS, "outsider.marker", token):
            assert secret not in caplog.text
