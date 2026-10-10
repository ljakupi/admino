"""Tests for admino.org_permissions — the per-org tool permission matrix and its
critical (tier-2) promotions (GH-161), gated by the org's data residency (GH-162).

The ``permissions`` table is recreated org-scoped (migration 0016: primary key
``(org_id, tool, action)``, ON DELETE CASCADE from organizations). Each org's
Org Admin manages the org's own matrix and critical permissions; every chat run
loads its org's policy (``ToolPolicy``) instead of a process-global one.

What these tests pin down (the GH-161 implementation contract):
- Surface: the six error classes and their bases, ``PROMOTION_COOLDOWN`` (5
  minutes), the coroutines and their keyword-only parameters, the sync
  ``clear_pending`` and ``current_time`` (the clock seam every ``now=None``
  default reads), and the module's admino imports (access, tenancy,
  audit_events, permissions, models, scoped_settings and auth only).
- ``seed_org_permissions``: exactly ``build_default_permissions_config()``'s 34
  rows for that org (hardcoded pairs stored 'deny'), ON CONFLICT DO NOTHING (an
  existing row is never overwritten), another org never touched, values bound
  as parameters, runs on the caller's connection.
- ``seed_missing_orgs``: only orgs without rows get the defaults (any status);
  returns how many; a second call seeds 0 and changes nothing.
- ``load_tool_policy``: only the tenant org's rows (``validate_permissions_config``
  of them), ``promoted`` = the tier-2 pairs stored 'confirm' (and nothing else),
  ``enabled_tools`` from that org's org_settings row (missing row: all on; org
  A's disabled service never disables org B's: the issue's cleanup criterion);
  an org without rows gets an empty config; a malformed stored state never
  escalates; nothing is written.
- ``get_org_permissions`` / ``update_org_permission`` (ORG_PERMISSIONS_MANAGE):
  sorted entries of the actor's org; an unknown pair or a hardcoded pair (either
  tier, any value) is refused before any statement; the stored value is the
  normalized one; a change is one transaction (row locked FOR UPDATE, upsert,
  ``org.permission_change`` audit row); a no-op writes nothing; an audit failure
  rolls back; another org is never touched.
- Critical promotions: ``critical_permissions`` (the 4 promotable pairs, sorted,
  per-org pending_at, no resolving), ``request_promotion`` (non-promotable
  refused before any re-auth; a failed re-auth leaves nothing; the
  ``org.permission_promote`` row first, then the pending entry; a repeat keeps
  the cooldown), ``resolve_due_promotions`` (only this org's due entries, at or
  after 5 minutes, no audit), ``cancel_promotion`` and ``demote`` (audited, the
  demotion in one transaction with its audit row). Org A never changes org B's
  rows or pending state.
- ``permissions_summary`` (ORG_PERMISSIONS_VIEW: every member role, never the
  Super Admin): one entry per stored pair of the actor's org, sorted;
  "disabled" for a switched-off service; hardcoded pairs "deny"; a promoted
  tier-2 pair "confirm".
- GH-162, data residency: for an org with ``data_residency = true`` (read through
  ``scoped_settings.org_residency(executor, tenant)``, fail closed when the org row
  is missing), ``load_tool_policy`` maps gmail, google_calendar, google_drive,
  outlook, outlook_calendar and onedrive to False in ``enabled_tools`` whatever the
  stored switches say (an Org Admin's enabled gmail included); memory keeps its
  stored switch; ``permissions`` and ``promoted`` are unchanged; nothing is written;
  another org is never affected. ``permissions_summary`` reads those six tools'
  actions "disabled" (a promoted pair included). The fixture orgs have residency
  off, so every other test sees the stored switches as they are.

All database calls go to tests/db_fakes.FakeDb (which models migration 0016's
permissions table). ``admino.org_permissions`` is imported per test through the
``svc`` fixture (which also empties the in-memory pending promotions), so each
test fails on its own until the module exists. The re-authentication is
replaced by an AsyncMock where its own behaviour isn't the subject
(tests/test_reauth.py pins it), and run for real with a fast password stand-in
in ``TestPromotionWithRealReauth``.

Security notes:
- Least privilege: only an Org Admin manages the matrix; every member (Org
  Admins and Editors) reads the summary; the Super Admin reaches neither
  (operator blindness).
- Tenant isolation: the org always comes from the principal; another org's id
  is never bound and its rows and pending promotions never change.
- Fail closed: hardcoded denials can't be changed through the matrix, a stored
  value can't escalate a hardcoded pair, every change shares one transaction
  with its audit row, and a promotion needs a fresh password plus a 5-minute
  cooldown.
- Content-free audit rows: tool/action/state tokens only; the password never
  reaches a statement, a row or a log line.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import copy
import inspect
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pydantic
import pytest

from admino import passwords
from admino.access import Principal
from admino.audit_events import AuditRecordError
from admino.permissions import (
    DEFAULT_PERMISSIONS,
    HARDCODED_DENIALS,
    PROMOTABLE_DENIALS,
    build_default_permissions_config,
    check_permission,
)
from admino.tenancy import TenantContext
from tests.db_fakes import (
    ORG_ID,
    OTHER_ORG_ID,
    TOOL_NAMES,
    Call,
    FakeDb,
    account_subject,
    fake_hash,
    plain,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IP = "203.0.113.7"
_OTHER_IP = "198.51.100.44"
_PASSWORD = "Promote-Marker-Secret-71"
_WRONG = "Promote-Marker-Secret-72"
_EMAIL = "Promote.Admin.Marker@Example.test"
# A fixed instant long in the past: the real clock is always far past its cooldown.
_T0 = datetime(2025, 3, 4, 10, 0, tzinfo=UTC)
_COOLDOWN = timedelta(minutes=5)
_OLD = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
_ALL_ON: dict[str, bool] = dict.fromkeys(TOOL_NAMES, True)
_PROMOTABLE: list[tuple[str, str]] = sorted(PROMOTABLE_DENIALS)
_DEFAULT_PAIRS: list[tuple[str, str]] = sorted(
    (tool, action) for tool, actions in DEFAULT_PERMISSIONS.items() for action in actions
)
# Hardcoded pairs that the matrix lists (documents.delete isn't a matrix row).
_HARDCODED_IN_MATRIX: list[tuple[str, str]] = sorted(HARDCODED_DENIALS & set(_DEFAULT_PAIRS))
_NOT_PROMOTABLE = [
    pytest.param("gmail", "read", id="gmail.read"),
    pytest.param("gmail", "delete", id="gmail.delete-tier1"),
    pytest.param("memory", "delete", id="memory.delete-tier1"),
    pytest.param("google_calendar", "create", id="google_calendar.create"),
    pytest.param("weather", "read", id="unknown-tool"),
]
_MANAGE_FUNCTIONS = [
    "get_org_permissions",
    "update_org_permission",
    "critical_permissions",
    "request_promotion",
    "demote",
    "cancel_promotion",
]
# The capability values (access.Capability.ORG_PERMISSIONS_VIEW is new in GH-161).
_MANAGE = "org.permissions.manage"
_VIEW = "org.permissions.view"
_REFUSED = [
    *(
        pytest.param(name, role, id=f"{name}-{role}")
        for name in _MANAGE_FUNCTIONS
        for role in ("editor", "super_admin")
    ),
    pytest.param("permissions_summary", "super_admin", id="permissions_summary-super_admin"),
]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def svc() -> Iterator[ModuleType]:
    """admino.org_permissions, imported per test (each test fails on its own until it
    exists), with its in-memory pending promotions emptied before and after."""
    from admino import org_permissions

    org_permissions.clear_pending()
    yield org_permissions
    org_permissions.clear_pending()


@pytest.fixture()
def db() -> FakeDb:
    """A fresh in-memory database with two active orgs and no permission rows.

    Both orgs have data residency off (GH-162: an org defaults to residency on, which
    switches the Google/Microsoft tools off), so the tests below see every stored switch
    as it is; the residency tests turn it on per org.
    """
    fake = FakeDb()
    fake.add_org(ORG_ID, data_residency=False)
    fake.add_org(OTHER_ORG_ID, data_residency=False)
    return fake


@pytest.fixture()
def reauth(monkeypatch: pytest.MonkeyPatch, svc: ModuleType) -> AsyncMock:
    """Replace admino.auth.reauthenticate (wherever the service looks it up) with an
    AsyncMock that accepts the password; a test sets ``return_value = False`` to refuse."""
    from admino import auth

    mock = AsyncMock(return_value=True)
    monkeypatch.setattr(auth, "reauthenticate", mock, raising=False)
    if hasattr(svc, "reauthenticate"):
        monkeypatch.setattr(svc, "reauthenticate", mock)
    return mock


def _principal(db: FakeDb, user_id: uuid.UUID) -> Principal:
    """The Principal a resolved session of this stored account would carry."""
    account = db.users[user_id]
    if account["kind"] == "super_admin":
        return Principal(user_id=user_id, kind="super_admin")
    return Principal(user_id=user_id, kind="member", org_id=account["org_id"], role=account["role"])


def _actor(db: FakeDb, role: str, org_id: uuid.UUID = ORG_ID, **fields: Any) -> Principal:
    """A stored account with this role (or a Super Admin) and its Principal."""
    if role == "super_admin":
        return _principal(db, db.add_account(kind="super_admin", role=None, **fields))
    return _principal(db, db.add_account(role=role, org_id=org_id, **fields))


def _tenant(principal: Principal) -> TenantContext:
    return TenantContext.from_principal(principal)


def _patch(tool: str, action: str, permission: str) -> Any:
    from admino.models import PermissionPatch

    return PermissionPatch(tool=tool, action=action, permission=permission)


def _default_matrix() -> dict[str, dict[str, str]]:
    """build_default_permissions_config() as tool -> {action: state}."""
    config = build_default_permissions_config()
    return {tool: dict(perms.actions) for tool, perms in config.tools.items()}


def _flat(matrix: dict[str, dict[str, str]]) -> list[tuple[str, str, str]]:
    """A tool -> {action: state} matrix as sorted (tool, action, state) triples."""
    return sorted(
        (tool, action, state)
        for tool, actions in matrix.items()
        for action, state in actions.items()
    )


def _with(**changes: str) -> dict[str, dict[str, str]]:
    """The default matrix with ``tool__action=state`` changes applied."""
    matrix = copy.deepcopy(_default_matrix())
    for key, state in changes.items():
        tool, action = key.split("__")
        matrix.setdefault(tool, {})[action] = state
    return matrix


def _entries(response: Any) -> list[tuple[str, str, str]]:
    """The (tool, action, permission) triples of a PermissionsResponse, in order."""
    return [(entry.tool, entry.action, entry.permission) for entry in response.permissions]


def _rows_of(db: FakeDb, org_id: uuid.UUID) -> dict[tuple[str, str], dict[str, Any]]:
    """Deep copies of an org's stored permissions rows (updated_at included)."""
    return {
        (tool, action): copy.deepcopy(row)
        for (row_org, tool, action), row in db.permissions.items()
        if plain(row_org) == org_id
    }


def _count(db: FakeDb, org_id: uuid.UUID) -> int:
    return sum(len(actions) for actions in db.org_permissions(org_id).values())


async def _critical(
    svc: ModuleType, db: FakeDb, actor: Principal
) -> dict[tuple[str, str], tuple[str, datetime | None]]:
    """critical_permissions as (tool, action) -> (state, pending_at)."""
    response = await svc.critical_permissions(db.pool, actor=actor)
    return {
        (entry.tool, entry.action): (entry.state, entry.pending_at)
        for entry in response.permissions
    }


async def _promote(
    svc: ModuleType,
    db: FakeDb,
    actor: Principal,
    tool: str = "gmail",
    action: str = "send",
    *,
    now: datetime | None = _T0,
    password: str = _PASSWORD,
    ip: str | None = _IP,
) -> Any:
    kwargs: dict[str, Any] = {} if now is None else {"now": now}
    return await svc.request_promotion(
        db.pool, actor=actor, tool=tool, action=action, password=password, ip=ip, **kwargs
    )


async def _resolve(svc: ModuleType, db: FakeDb, actor: Principal, now: datetime) -> Any:
    return await svc.resolve_due_promotions(db.pool, _tenant(actor), now=now)


async def _invoke(svc: ModuleType, db: FakeDb, name: str, actor: Principal) -> Any:
    """Call one of the authorized functions with a valid argument set."""
    pool = db.pool
    if name == "get_org_permissions":
        return await svc.get_org_permissions(pool, actor=actor)
    if name == "update_org_permission":
        return await svc.update_org_permission(
            pool, actor=actor, patch=_patch("gmail", "read", "confirm"), ip=_IP
        )
    if name == "critical_permissions":
        return await svc.critical_permissions(pool, actor=actor)
    if name == "request_promotion":
        return await _promote(svc, db, actor)
    if name == "demote":
        return await svc.demote(pool, actor=actor, tool="gmail", action="send", ip=_IP)
    if name == "cancel_promotion":
        return await svc.cancel_promotion(pool, actor=actor, tool="gmail", action="send", ip=_IP)
    assert name == "permissions_summary"
    return await svc.permissions_summary(pool, actor=actor)


def _one(items: list[Any]) -> Any:
    assert len(items) == 1, items
    return items[0]


def _uuid(value: Any) -> uuid.UUID | None:
    return None if value is None else plain(value)


def _bound(db: FakeDb, value: uuid.UUID) -> bool:
    """True when any recorded statement bound this id (as a UUID or its string)."""
    for call in db.calls:
        for arg in call.args:
            if isinstance(arg, uuid.UUID) and plain(arg) == value:
                return True
            if isinstance(arg, str) and arg == str(value):
                return True
    return False


def _writes(db: FakeDb) -> list[Call]:
    """Every INSERT, UPDATE or DELETE on permissions."""
    return db.matching(r"^(?:insert into|update|delete from) permissions\b")


def _audit_inserts(db: FakeDb) -> list[Call]:
    return db.matching(r"^insert into audit_events\b")


def _assert_change_in_one_transaction(db: FakeDb) -> None:
    """The permissions row lock (FOR UPDATE), the write and the audit insert ran in one
    committed transaction, the lock first."""
    locks = [
        call
        for call in db.matching(r"\bpermissions\b")
        if call.normalized.startswith("select") and "for update" in call.normalized
    ]
    writes = _writes(db)
    audit = _audit_inserts(db)
    assert locks, "the permissions row was never locked FOR UPDATE"
    assert writes, "no write on permissions"
    assert audit, "no audit insert"
    transactions = {call.tx for call in [*locks, *writes, *audit]}
    assert len(transactions) == 1 and None not in transactions, transactions
    (tx,) = transactions
    assert (tx, "commit") in db.transactions
    first_lock = db.calls.index(locks[0])
    assert first_lock < db.calls.index(writes[0])
    assert first_lock < db.calls.index(audit[0])


def _assert_org_event(
    row: dict[str, Any],
    *,
    action: str,
    actor: Principal,
    org_id: uuid.UUID,
    metadata: dict[str, Any],
    ip: str | None = _IP,
) -> None:
    """One org.permission_* event: the Org Admin actor, the org's log, the org as target."""
    assert row["action"] == action
    assert (row["actor_kind"], _uuid(row["actor_user_id"])) == ("member", actor.user_id)
    assert _uuid(row["org_id"]) == org_id
    assert (row["target_type"], row["target_ids"]) == ("organization", [str(org_id)])
    assert row["ip"] == ip
    assert row["metadata"] == metadata


def _state(db: FakeDb) -> dict[str, Any]:
    """A deep copy of the tables these functions may touch, for "nothing changed" checks."""
    return copy.deepcopy(
        {
            "permissions": db.permissions,
            "audit": db.audit,
            "org_settings": db.org_settings,
            "orgs": db.orgs,
            "users": db.users,
            "throttle": db.throttle,
            "sessions": db.sessions,
        }
    )


class _CanSpy:
    """Wraps admino.access.can wherever the service looks it up; records the capabilities
    asked for and refuses the chosen ones."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        svc: ModuleType,
        deny: frozenset[str] = frozenset(),
    ) -> None:
        from admino import access

        real = access.can
        self.capabilities: list[str] = []

        def spy(principal: Any, capability: Any) -> bool:
            self.capabilities.append(str(capability))
            if str(capability) in deny:
                return False
            return real(principal, capability)

        monkeypatch.setattr(access, "can", spy)
        if hasattr(svc, "can"):
            monkeypatch.setattr(svc, "can", spy)


def _imported_admino_modules(module: ModuleType) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {
                alias.name.split(".")[1] for alias in node.names if alias.name.startswith("admino.")
            }
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module == "admino":
                imported |= {alias.name for alias in node.names}
            elif node.module.startswith("admino."):
                imported.add(node.module.split(".")[1])
    return imported


# ---------------------------------------------------------------------------
# 1. The module's surface
# ---------------------------------------------------------------------------


class TestModuleSurface:
    """Errors, the cooldown, coroutines, keyword-only arguments, the clock seam, imports."""

    @pytest.mark.parametrize(
        ("name", "base"),
        [
            ("UnknownPermissionError", ValueError),
            ("HardcodedDenialError", ValueError),
            ("NotPromotableError", LookupError),
            ("NoPendingPromotionError", LookupError),
            ("NotPromotedError", LookupError),
            ("ReauthFailedError", Exception),
        ],
    )
    def test_org_permissions_error_classes_have_their_bases(
        self, svc: ModuleType, name: str, base: type[Exception]
    ) -> None:
        error = getattr(svc, name)
        assert isinstance(error, type)
        assert issubclass(error, base)

    def test_org_permissions_promotion_cooldown_is_five_minutes(self, svc: ModuleType) -> None:
        cooldown = svc.PROMOTION_COOLDOWN
        assert cooldown == timedelta(minutes=5)

    @pytest.mark.parametrize(
        "name",
        [
            "seed_org_permissions",
            "seed_missing_orgs",
            "load_tool_policy",
            "get_org_permissions",
            "update_org_permission",
            "resolve_due_promotions",
            "critical_permissions",
            "request_promotion",
            "demote",
            "cancel_promotion",
            "permissions_summary",
        ],
    )
    def test_org_permissions_function_is_a_coroutine(self, svc: ModuleType, name: str) -> None:
        assert inspect.iscoroutinefunction(getattr(svc, name))

    @pytest.mark.parametrize("name", ["clear_pending", "current_time"])
    def test_org_permissions_helper_is_sync(self, svc: ModuleType, name: str) -> None:
        assert callable(getattr(svc, name))
        assert not inspect.iscoroutinefunction(getattr(svc, name))

    @pytest.mark.parametrize(
        ("name", "keywords"),
        [
            ("get_org_permissions", {"actor"}),
            ("update_org_permission", {"actor", "patch", "ip"}),
            ("critical_permissions", {"actor"}),
            ("request_promotion", {"actor", "tool", "action", "password", "ip", "now"}),
            ("demote", {"actor", "tool", "action", "ip"}),
            ("cancel_promotion", {"actor", "tool", "action", "ip"}),
            ("resolve_due_promotions", {"now"}),
            ("permissions_summary", {"actor"}),
        ],
    )
    def test_org_permissions_arguments_are_keyword_only(
        self, svc: ModuleType, name: str, keywords: set[str]
    ) -> None:
        parameters = inspect.signature(getattr(svc, name)).parameters
        found = {key for key, p in parameters.items() if p.kind is inspect.Parameter.KEYWORD_ONLY}
        assert found == keywords

    @pytest.mark.parametrize("name", ["request_promotion", "resolve_due_promotions"])
    def test_org_permissions_now_defaults_to_none(self, svc: ModuleType, name: str) -> None:
        assert inspect.signature(getattr(svc, name)).parameters["now"].default is None

    def test_org_permissions_current_time_is_aware_utc_now(self, svc: ModuleType) -> None:
        before = datetime.now(UTC)
        value = svc.current_time()
        after = datetime.now(UTC)

        assert isinstance(value, datetime)
        assert value.utcoffset() == timedelta(0)
        assert before <= value <= after

    def test_org_permissions_imports_only_the_allowed_admino_modules(self, svc: ModuleType) -> None:
        """Never the server, agent, LLM, tools, OAuth or database modules."""
        allowed = {
            "access",
            "tenancy",
            "audit_events",
            "permissions",
            "models",
            "scoped_settings",
            "auth",
        }
        imported = _imported_admino_modules(svc)
        assert imported <= allowed, imported

    def test_org_permissions_module_docstring_has_security_notes(self, svc: ModuleType) -> None:
        assert svc.__doc__ is not None
        assert "security" in svc.__doc__.lower()


# ---------------------------------------------------------------------------
# 2. Authorization: access.can before any statement
# ---------------------------------------------------------------------------


class TestAuthorization:
    """The matrix and the critical permissions: Org Admin only. The summary: every member
    role, never the Super Admin. A refusal reads and writes nothing."""

    @pytest.mark.parametrize(("name", "role"), _REFUSED)
    async def test_org_permissions_refused_role_gets_permission_error_before_any_query(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, name: str, role: str
    ) -> None:
        db.add_permissions(ORG_ID)
        actor = _actor(db, role)
        before = _state(db)

        with pytest.raises(PermissionError):
            await _invoke(svc, db, name, actor)

        assert db.calls == []
        assert _state(db) == before
        reauth.assert_not_awaited()

    @pytest.mark.parametrize("role", ["editor", "super_admin"])
    async def test_org_permissions_refused_promotion_leaves_nothing_pending(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, role: str
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        actor = _actor(db, role)

        with pytest.raises(PermissionError):
            await _promote(svc, db, actor)

        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", None)

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    async def test_org_permissions_summary_is_open_to_every_member_role(
        self, svc: ModuleType, db: FakeDb, role: str
    ) -> None:
        from admino.models import PermissionsSummaryResponse

        db.add_permissions(ORG_ID)
        actor = _actor(db, role)

        result = await svc.permissions_summary(db.pool, actor=actor)

        assert isinstance(result, PermissionsSummaryResponse)
        assert db.calls

    @pytest.mark.parametrize("name", [*_MANAGE_FUNCTIONS, "permissions_summary"])
    async def test_org_permissions_asks_can_for_its_capability(
        self,
        svc: ModuleType,
        db: FakeDb,
        reauth: AsyncMock,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
    ) -> None:
        db.add_permissions(ORG_ID)
        actor = _actor(db, "org_admin")
        spy = _CanSpy(monkeypatch, svc)

        with contextlib.suppress(LookupError):
            await _invoke(svc, db, name, actor)

        expected = _VIEW if name == "permissions_summary" else _MANAGE
        assert expected in spy.capabilities

    @pytest.mark.parametrize("name", [*_MANAGE_FUNCTIONS, "permissions_summary"])
    async def test_org_permissions_capability_refused_by_can_is_a_permission_error(
        self,
        svc: ModuleType,
        db: FakeDb,
        reauth: AsyncMock,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
    ) -> None:
        """When can() refuses the function's capability, even the Org Admin is refused
        before any statement."""
        db.add_permissions(ORG_ID)
        actor = _actor(db, "org_admin")
        refused = _VIEW if name == "permissions_summary" else _MANAGE
        _CanSpy(monkeypatch, svc, deny=frozenset({refused}))

        with pytest.raises(PermissionError):
            await _invoke(svc, db, name, actor)

        assert db.calls == []
        reauth.assert_not_awaited()


# ---------------------------------------------------------------------------
# 3. Seeding
# ---------------------------------------------------------------------------


class TestSeedOrgPermissions:
    """A new org gets exactly the default matrix; nothing existing is overwritten."""

    async def test_org_permissions_seed_inserts_the_default_matrix(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        await svc.seed_org_permissions(db.pool, ORG_ID)

        assert db.org_permissions(ORG_ID) == _default_matrix()
        assert _count(db, ORG_ID) == 34

    async def test_org_permissions_seed_stores_every_hardcoded_pair_as_deny(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        await svc.seed_org_permissions(db.pool, ORG_ID)

        matrix = db.org_permissions(ORG_ID)
        assert {matrix[tool][action] for tool, action in _HARDCODED_IN_MATRIX} == {"deny"}

    async def test_org_permissions_seed_never_overwrites_an_existing_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """ON CONFLICT DO NOTHING: the stored rows keep their value and updated_at; the
        missing ones are added."""
        db.add_permissions(
            ORG_ID, {"gmail": {"read": "deny"}, "memory": {"store": "confirm"}}, updated_at=_OLD
        )

        await svc.seed_org_permissions(db.pool, ORG_ID)

        assert db.org_permissions(ORG_ID) == _with(gmail__read="deny", memory__store="confirm")
        rows = _rows_of(db, ORG_ID)
        assert rows[("gmail", "read")]["updated_at"] == _OLD
        assert rows[("memory", "store")]["updated_at"] == _OLD

    async def test_org_permissions_seed_twice_changes_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        await svc.seed_org_permissions(db.pool, ORG_ID)
        before = _rows_of(db, ORG_ID)

        await svc.seed_org_permissions(db.pool, ORG_ID)

        assert _rows_of(db, ORG_ID) == before

    async def test_org_permissions_seed_never_touches_another_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(OTHER_ORG_ID, {"gmail": {"read": "deny"}}, updated_at=_OLD)
        other = _rows_of(db, OTHER_ORG_ID)

        await svc.seed_org_permissions(db.pool, ORG_ID)

        assert _rows_of(db, OTHER_ORG_ID) == other
        assert not _bound(db, OTHER_ORG_ID)

    async def test_org_permissions_seed_uses_insert_on_conflict_do_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Every statement is an INSERT INTO permissions ... ON CONFLICT ... DO NOTHING with
        the org id bound and no tool, action or state written into the SQL text."""
        await svc.seed_org_permissions(db.pool, ORG_ID)

        assert db.calls
        for call in db.calls:
            assert call.normalized.startswith("insert into permissions"), call.sql
            assert "on conflict" in call.normalized and "do nothing" in call.normalized
            assert _bound_in(call, ORG_ID)
            for word in ("gmail", "google_calendar", "memory", "'allow'", "'deny'", "'confirm'"):
                assert word not in call.normalized, call.sql

    async def test_org_permissions_seed_runs_on_the_given_connection(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """create_org seeds inside its own transaction: every statement on that connection."""
        async with db.pool.acquire() as conn, conn.transaction():
            await svc.seed_org_permissions(conn, ORG_ID)

        assert db.calls
        assert {call.via for call in db.calls} != {"pool"}
        assert len({call.tx for call in db.calls}) == 1
        assert None not in {call.tx for call in db.calls}
        assert _count(db, ORG_ID) == 34

    async def test_org_permissions_seed_writes_no_audit_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        await svc.seed_org_permissions(db.pool, ORG_ID)

        assert db.audit == []


def _bound_in(call: Call, value: uuid.UUID) -> bool:
    return any(isinstance(arg, uuid.UUID) and plain(arg) == value for arg in call.args)


class TestSeedMissingOrgs:
    """Startup: every org without rows gets the defaults; the others stay as they are."""

    async def test_org_permissions_seed_missing_seeds_only_orgs_without_rows(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        third = db.add_org()
        db.add_permissions(ORG_ID, {"gmail": {"read": "deny"}}, updated_at=_OLD)
        existing = _rows_of(db, ORG_ID)

        seeded = await svc.seed_missing_orgs(db.pool)

        assert seeded == 2
        assert _rows_of(db, ORG_ID) == existing
        assert db.org_permissions(OTHER_ORG_ID) == _default_matrix()
        assert db.org_permissions(third) == _default_matrix()

    async def test_org_permissions_seed_missing_is_idempotent(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        await svc.seed_missing_orgs(db.pool)
        before = copy.deepcopy(db.permissions)

        assert await svc.seed_missing_orgs(db.pool) == 0
        assert db.permissions == before

    async def test_org_permissions_seed_missing_seeds_orgs_of_every_status(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        deactivated = db.add_org(status="deactivated")
        pending = db.add_org(status="pending_deletion")

        seeded = await svc.seed_missing_orgs(db.pool)

        assert seeded == 4
        assert db.org_permissions(deactivated) == _default_matrix()
        assert db.org_permissions(pending) == _default_matrix()

    async def test_org_permissions_seed_missing_without_orgs_seeds_nothing(
        self, svc: ModuleType
    ) -> None:
        empty = FakeDb()

        assert await svc.seed_missing_orgs(empty.pool) == 0
        assert empty.permissions == {}

    async def test_org_permissions_seed_missing_writes_no_audit_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        await svc.seed_missing_orgs(db.pool)

        assert db.audit == []


# ---------------------------------------------------------------------------
# 4. load_tool_policy: a run's per-org policy
# ---------------------------------------------------------------------------


class TestLoadToolPolicy:
    """Only the tenant org's rows and switches; nothing can escalate a hardcoded pair."""

    async def test_org_permissions_policy_is_a_frozen_tool_policy(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import ToolPolicy

        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert isinstance(policy, ToolPolicy)
        with pytest.raises(pydantic.ValidationError):
            policy.promoted = frozenset({("gmail", "send")})

    async def test_org_permissions_policy_of_the_default_rows_is_the_default_config(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert policy.permissions == build_default_permissions_config()
        assert policy.promoted == frozenset()
        assert policy.enabled_tools == _ALL_ON

    async def test_org_permissions_policy_reads_only_the_tenant_orgs_rows(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Org A's 'confirm' on google_calendar.read never appears in org B's policy."""
        db.add_permissions(ORG_ID, _with(google_calendar__read="confirm"))
        db.add_permissions(OTHER_ORG_ID)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)

        policy_a = await svc.load_tool_policy(db.pool, _tenant(admin_a))
        db.calls.clear()
        policy_b = await svc.load_tool_policy(db.pool, _tenant(admin_b))

        assert policy_a.permissions.tools["google_calendar"].actions["read"] == "confirm"
        assert policy_b.permissions.tools["google_calendar"].actions["read"] == "allow"
        assert check_permission("google_calendar", "read", policy_b.permissions).allowed == "allow"
        assert _bound(db, OTHER_ORG_ID)
        assert not _bound(db, ORG_ID)

    async def test_org_permissions_policy_promoted_is_the_tier2_pairs_stored_confirm(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID, _with(gmail__send="confirm", outlook_calendar__update="confirm"))
        db.add_permissions(OTHER_ORG_ID)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)

        policy_a = await svc.load_tool_policy(db.pool, _tenant(admin_a))
        policy_b = await svc.load_tool_policy(db.pool, _tenant(admin_b))

        assert policy_a.promoted == frozenset({("gmail", "send"), ("outlook_calendar", "update")})
        assert policy_b.promoted == frozenset()
        result = check_permission("gmail", "send", policy_a.permissions, promoted=policy_a.promoted)
        assert result.allowed == "confirm"

    async def test_org_permissions_policy_promoted_holds_tier2_pairs_only(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """A tier-1 pair or an ordinary pair stored 'confirm' is never "promoted"; a tier-2
        pair stored 'allow' isn't either (only 'confirm' promotes)."""
        db.add_permissions(
            ORG_ID,
            _with(
                gmail__delete="confirm",
                google_calendar__create="confirm",
                memory__store="confirm",
                outlook__send="allow",
            ),
        )
        admin = _actor(db, "org_admin")

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert policy.promoted == frozenset()

    async def test_org_permissions_policy_malformed_states_cant_escalate(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Hardcoded pairs stored 'allow' read as 'deny' (validate_permissions_config), and a
        write-mutating 'allow' reads as 'confirm'."""
        db.add_permissions(
            ORG_ID,
            _with(
                gmail__delete="allow",
                gmail__send="allow",
                google_calendar__update="allow",
                google_calendar__create="allow",
            ),
        )
        admin = _actor(db, "org_admin")

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        tools = policy.permissions.tools
        assert tools["gmail"].actions["delete"] == "deny"
        assert tools["gmail"].actions["send"] == "deny"
        assert tools["google_calendar"].actions["update"] == "deny"
        assert tools["google_calendar"].actions["create"] == "confirm"
        for tool, action in [("gmail", "delete"), ("gmail", "send"), ("google_calendar", "update")]:
            result = check_permission(tool, action, policy.permissions, promoted=policy.promoted)
            assert result.allowed == "deny", (tool, action)

    async def test_org_permissions_policy_enabled_tools_follow_the_orgs_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_org_settings(ORG_ID, gmail=False, onedrive=False)
        admin = _actor(db, "org_admin")

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert policy.enabled_tools == {**_ALL_ON, "gmail": False, "onedrive": False}

    async def test_org_permissions_policy_other_orgs_disabled_service_doesnt_disable_mine(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The issue's cleanup criterion: org A's disabled gmail doesn't disable org B's
        (the all-orgs gate is gone). B has no row: every service on."""
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID)
        db.add_org_settings(ORG_ID, gmail=False)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)

        policy_b = await svc.load_tool_policy(db.pool, _tenant(admin_b))

        assert policy_b.enabled_tools == _ALL_ON

    async def test_org_permissions_policy_each_org_gets_its_own_switches(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_org_settings(ORG_ID, gmail=False)
        db.add_org_settings(OTHER_ORG_ID, memory=False)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)

        policy_a = await svc.load_tool_policy(db.pool, _tenant(admin_a))
        policy_b = await svc.load_tool_policy(db.pool, _tenant(admin_b))

        assert policy_a.enabled_tools == {**_ALL_ON, "gmail": False}
        assert policy_b.enabled_tools == {**_ALL_ON, "memory": False}

    async def test_org_permissions_policy_of_an_org_without_rows_is_empty(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """No rows: an empty PermissionsConfig, so everything is default-deny."""
        db.add_permissions(OTHER_ORG_ID)
        admin = _actor(db, "org_admin", ORG_ID)

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert policy.permissions.tools == {}
        assert policy.promoted == frozenset()
        assert check_permission("gmail", "read", policy.permissions).allowed == "deny"

    async def test_org_permissions_policy_needs_no_capability(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The server loads it for any member's chat run: it never asks access.can."""
        db.add_permissions(ORG_ID)
        editor = _actor(db, "editor")
        spy = _CanSpy(monkeypatch, svc)

        policy = await svc.load_tool_policy(db.pool, _tenant(editor))

        assert policy.permissions == build_default_permissions_config()
        assert spy.capabilities == []

    async def test_org_permissions_policy_load_writes_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID, _with(gmail__send="confirm"))
        admin = _actor(db, "org_admin")
        before = _state(db)

        await svc.load_tool_policy(db.pool, _tenant(admin))

        assert _writes(db) == []
        assert _audit_inserts(db) == []
        assert _state(db) == before

    async def test_org_permissions_policy_ignores_pending_promotions(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        """A pending (cooling-down) promotion isn't promoted yet."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert policy.promoted == frozenset()


# ---------------------------------------------------------------------------
# 4b. load_tool_policy under data residency (GH-162)
# ---------------------------------------------------------------------------

# The tools an org's data residency policy switches off: both providers' services.
_RESIDENCY_TOOLS: tuple[str, ...] = (
    "gmail",
    "google_calendar",
    "google_drive",
    "outlook",
    "outlook_calendar",
    "onedrive",
)
# A residency org's switches when every stored switch is on: only memory stays on.
_RESIDENCY_ON: dict[str, bool] = {**_ALL_ON, **dict.fromkeys(_RESIDENCY_TOOLS, False)}
_RESIDENCY_PAIRS = [
    pytest.param(True, False, id="a-on-b-off"),
    pytest.param(False, True, id="a-off-b-on"),
]


def _residency(db: FakeDb, org_id: uuid.UUID, *, on: bool) -> None:
    """Set an org's data_residency flag (the organizations row)."""
    db.add_org(org_id, data_residency=on)


def _enabled(residency: bool) -> dict[str, bool]:
    """The enabled_tools of an org without an org_settings row."""
    return _RESIDENCY_ON if residency else _ALL_ON


class TestResidencyGating:
    """A residency org's policy has every Google/Microsoft tool off whatever its stored
    switches say; memory keeps its stored switch; the matrix and the promotions are
    unchanged; nothing is written; another org is never affected."""

    @pytest.mark.parametrize("role", ["org_admin", "editor"])
    async def test_org_permissions_policy_residency_org_has_the_six_connector_tools_off(
        self, svc: ModuleType, db: FakeDb, role: str
    ) -> None:
        db.add_permissions(ORG_ID)
        _residency(db, ORG_ID, on=True)
        member = _actor(db, role)

        policy = await svc.load_tool_policy(db.pool, _tenant(member))

        assert policy.enabled_tools == _RESIDENCY_ON
        assert all(type(value) is bool for value in policy.enabled_tools.values())

    @pytest.mark.parametrize("memory", [True, False])
    async def test_org_permissions_policy_residency_keeps_memorys_stored_switch(
        self, svc: ModuleType, db: FakeDb, memory: bool
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_org_settings(ORG_ID, memory=memory)
        _residency(db, ORG_ID, on=True)
        admin = _actor(db, "org_admin")

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert policy.enabled_tools == {**_RESIDENCY_ON, "memory": memory}

    async def test_org_permissions_policy_residency_overrides_a_service_the_org_admin_enabled(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The Org Admin switches gmail on through the org settings (stored on): the run
        still has gmail, and every other Google/Microsoft tool, off."""
        from admino import scoped_settings
        from admino.models import OrgSettingsPatch

        db.add_permissions(ORG_ID)
        db.add_org_settings(ORG_ID, gmail=False)
        _residency(db, ORG_ID, on=True)
        admin = _actor(db, "org_admin")
        await scoped_settings.update_org_settings(
            db.pool,
            actor=admin,
            patch=OrgSettingsPatch.model_validate({"tools": {"gmail": True}}),
            ip=_IP,
        )
        assert db.org_tools(ORG_ID) == _ALL_ON

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert policy.enabled_tools["gmail"] is False
        assert policy.enabled_tools == _RESIDENCY_ON

    async def test_org_permissions_policy_residency_leaves_the_stored_switches_untouched(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The gating happens in the policy only: the org_settings row, the
        organizations row and every other table stay as they were."""
        db.add_permissions(ORG_ID)
        db.add_org_settings(ORG_ID, onedrive=False, memory=False, updated_at=_OLD)
        _residency(db, ORG_ID, on=True)
        admin = _actor(db, "org_admin")
        before = _state(db)

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert policy.enabled_tools == {**_RESIDENCY_ON, "memory": False}
        assert _state(db) == before
        assert db.org_tools(ORG_ID) == {**_ALL_ON, "onedrive": False, "memory": False}
        assert db.matching(r"^(?:insert into|update|delete from)\b") == []

    async def test_org_permissions_policy_residency_keeps_the_matrix_and_promotions(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Residency changes enabled_tools only: a residency org's permissions and
        promoted pairs read exactly as a non-residency org's with the same rows."""
        rows = _with(gmail__send="confirm", google_drive__read="confirm")
        db.add_permissions(ORG_ID, rows)
        db.add_permissions(OTHER_ORG_ID, rows)
        _residency(db, ORG_ID, on=True)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)

        policy_a = await svc.load_tool_policy(db.pool, _tenant(admin_a))
        policy_b = await svc.load_tool_policy(db.pool, _tenant(admin_b))

        assert policy_a.enabled_tools == _RESIDENCY_ON
        assert policy_b.enabled_tools == _ALL_ON
        assert policy_a.permissions == policy_b.permissions
        assert policy_a.promoted == policy_b.promoted == frozenset({("gmail", "send")})
        assert policy_a.permissions.tools["google_drive"].actions["read"] == "confirm"

    @pytest.mark.parametrize(("residency_a", "residency_b"), _RESIDENCY_PAIRS)
    async def test_org_permissions_policy_residency_is_per_org(
        self, svc: ModuleType, db: FakeDb, residency_a: bool, residency_b: bool
    ) -> None:
        """Org A's residency never gates org B's tools (and the other way round); B's
        policy never binds A's id."""
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID)
        _residency(db, ORG_ID, on=residency_a)
        _residency(db, OTHER_ORG_ID, on=residency_b)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)

        policy_a = await svc.load_tool_policy(db.pool, _tenant(admin_a))
        db.calls.clear()
        policy_b = await svc.load_tool_policy(db.pool, _tenant(admin_b))

        assert policy_a.enabled_tools == _enabled(residency_a)
        assert policy_b.enabled_tools == _enabled(residency_b)
        assert not _bound(db, ORG_ID)

    async def test_org_permissions_policy_org_without_an_organizations_row_fails_closed(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """No organizations row to read the policy from: treated as residency on."""
        ghost = Principal(user_id=uuid.uuid4(), kind="member", org_id=uuid.uuid4(), role="editor")

        policy = await svc.load_tool_policy(db.pool, _tenant(ghost))

        assert policy.enabled_tools == _RESIDENCY_ON

    @pytest.mark.parametrize("residency", [True, False])
    async def test_org_permissions_policy_asks_scoped_settings_org_residency(
        self, svc: ModuleType, db: FakeDb, monkeypatch: pytest.MonkeyPatch, residency: bool
    ) -> None:
        """The decision is ``scoped_settings.org_residency(executor, tenant)`` (the one
        fail-closed residency read), asked once with the run's tenant; the stored flag is
        set the other way so a second read of its own would show."""
        from admino import scoped_settings

        db.add_permissions(ORG_ID)
        _residency(db, ORG_ID, on=not residency)
        admin = _actor(db, "org_admin")
        tenant = _tenant(admin)
        spy = AsyncMock(return_value=residency)
        monkeypatch.setattr(scoped_settings, "org_residency", spy, raising=False)
        if hasattr(svc, "org_residency"):
            monkeypatch.setattr(svc, "org_residency", spy)

        policy = await svc.load_tool_policy(db.pool, tenant)

        assert policy.enabled_tools == _enabled(residency)
        spy.assert_awaited_once()
        call = spy.await_args
        assert call is not None
        asked = call.kwargs.get("tenant", call.args[1] if len(call.args) > 1 else None)
        assert asked == tenant

    async def test_org_permissions_policy_reads_residency_on_the_given_connection(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """The residency read runs on the caller's executor, like the rest of the load."""
        db.add_permissions(ORG_ID)
        _residency(db, ORG_ID, on=True)
        admin = _actor(db, "org_admin")

        async with db.pool.acquire() as conn:
            policy = await svc.load_tool_policy(conn, _tenant(admin))

        assert policy.enabled_tools == _RESIDENCY_ON
        assert db.matching(r"\bfrom organizations\b")
        assert all(call.via != "pool" for call in db.calls)


# ---------------------------------------------------------------------------
# 5. get_org_permissions
# ---------------------------------------------------------------------------


class TestGetOrgPermissions:
    """The Org Admin reads the stored matrix of their own org."""

    async def test_org_permissions_get_returns_the_sorted_matrix(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import PermissionsResponse

        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        result = await svc.get_org_permissions(db.pool, actor=admin)

        assert isinstance(result, PermissionsResponse)
        assert _entries(result) == _flat(_default_matrix())

    async def test_org_permissions_get_shows_the_raw_stored_states(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """A promoted pair shows its stored 'confirm'."""
        db.add_permissions(ORG_ID, _with(gmail__send="confirm", gmail__read="deny"))
        admin = _actor(db, "org_admin")

        result = await svc.get_org_permissions(db.pool, actor=admin)

        assert _entries(result) == _flat(_with(gmail__send="confirm", gmail__read="deny"))

    async def test_org_permissions_get_reads_only_the_actors_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID, _with(gmail__read="deny", memory__store="confirm"))
        admin = _actor(db, "org_admin", ORG_ID)

        result = await svc.get_org_permissions(db.pool, actor=admin)

        assert _entries(result) == _flat(_default_matrix())
        assert not _bound(db, OTHER_ORG_ID)

    async def test_org_permissions_get_of_an_org_without_rows_is_empty(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(OTHER_ORG_ID)
        admin = _actor(db, "org_admin", ORG_ID)

        result = await svc.get_org_permissions(db.pool, actor=admin)

        assert result.permissions == []


# ---------------------------------------------------------------------------
# 6. update_org_permission
# ---------------------------------------------------------------------------


class TestUpdateOrgPermission:
    """One pair of the actor's org, validated, normalized and audited in one transaction."""

    async def test_org_permissions_update_changes_the_stored_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch("gmail", "read", "confirm"), ip=_IP
        )

        assert db.org_permissions(ORG_ID) == _with(gmail__read="confirm")

    async def test_org_permissions_update_returns_the_full_matrix_after_the_change(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import PermissionsResponse

        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        result = await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch("memory", "store", "deny"), ip=_IP
        )

        assert isinstance(result, PermissionsResponse)
        assert _entries(result) == _flat(_with(memory__store="deny"))

    async def test_org_permissions_update_stores_a_write_mutating_allow_as_confirm(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """validate_permissions_config's normalization: google_calendar.create 'allow' is
        stored (and audited) as 'confirm'."""
        db.add_permissions(ORG_ID, _with(google_calendar__create="deny"))
        admin = _actor(db, "org_admin")

        result = await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch("google_calendar", "create", "allow"), ip=_IP
        )

        assert db.org_permissions(ORG_ID)["google_calendar"]["create"] == "confirm"
        assert ("google_calendar", "create", "confirm") in _entries(result)
        assert _one(db.audit)["metadata"] == {
            "tool": "google_calendar",
            "action": "create",
            "old": "deny",
            "new": "confirm",
        }

    async def test_org_permissions_update_records_the_exact_audit_event(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch("gmail", "read", "confirm"), ip=_IP
        )

        _assert_org_event(
            _one(db.audit),
            action="org.permission_change",
            actor=admin,
            org_id=ORG_ID,
            metadata={"tool": "gmail", "action": "read", "old": "allow", "new": "confirm"},
        )

    async def test_org_permissions_update_of_a_missing_row_reads_old_as_deny(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        matrix = _default_matrix()
        del matrix["memory"]["recall"]
        db.add_permissions(ORG_ID, matrix)
        admin = _actor(db, "org_admin")

        await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch("memory", "recall", "allow"), ip=_IP
        )

        assert db.org_permissions(ORG_ID)["memory"]["recall"] == "allow"
        assert _one(db.audit)["metadata"] == {
            "tool": "memory",
            "action": "recall",
            "old": "deny",
            "new": "allow",
        }

    async def test_org_permissions_update_locks_writes_and_audits_in_one_transaction(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch("onedrive", "read", "deny"), ip=_IP
        )

        _assert_change_in_one_transaction(db)

    async def test_org_permissions_update_binds_every_value(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Parameterized SQL: no tool, action or state text in any statement."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch("google_drive", "search", "confirm"), ip=_IP
        )

        for call in db.matching(r"\bpermissions\b"):
            assert "google_drive" not in call.normalized, call.sql
            assert "'search'" not in call.normalized, call.sql
            assert "'confirm'" not in call.normalized, call.sql

    @pytest.mark.parametrize(
        ("tool", "action", "permission"),
        [
            pytest.param("gmail", "read", "allow", id="same-value"),
            pytest.param("google_calendar", "create", "allow", id="normalizes-to-stored-confirm"),
        ],
    )
    async def test_org_permissions_update_noop_writes_nothing(
        self, svc: ModuleType, db: FakeDb, tool: str, action: str, permission: str
    ) -> None:
        """Unchanged (after normalization): no write, no audit row; the matrix comes back."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        before = _state(db)

        result = await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch(tool, action, permission), ip=_IP
        )

        assert _writes(db) == []
        assert _audit_inserts(db) == []
        assert _state(db) == before
        assert _entries(result) == _flat(_default_matrix())

    @pytest.mark.parametrize(
        ("tool", "action"),
        [
            pytest.param("weather", "read", id="unknown-tool"),
            pytest.param("gmail", "archive", id="unknown-action"),
            pytest.param("memory", "write", id="confirm-only-but-not-a-matrix-row"),
        ],
    )
    async def test_org_permissions_update_unknown_pair_is_refused_before_any_statement(
        self, svc: ModuleType, db: FakeDb, tool: str, action: str
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        before = _state(db)

        with pytest.raises(svc.UnknownPermissionError):
            await svc.update_org_permission(
                db.pool, actor=admin, patch=_patch(tool, action, "confirm"), ip=_IP
            )

        assert db.calls == []
        assert _state(db) == before

    @pytest.mark.parametrize("permission", ["allow", "confirm", "deny"])
    @pytest.mark.parametrize(("tool", "action"), _HARDCODED_IN_MATRIX)
    async def test_org_permissions_update_hardcoded_pair_is_refused_before_any_statement(
        self, svc: ModuleType, db: FakeDb, tool: str, action: str, permission: str
    ) -> None:
        """Either tier, any value (even 'deny'): HardcodedDenialError, nothing read or
        written (the critical permissions are the only way to promote a tier-2 pair)."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        before = _state(db)

        with pytest.raises(svc.HardcodedDenialError):
            await svc.update_org_permission(
                db.pool, actor=admin, patch=_patch(tool, action, permission), ip=_IP
            )

        assert db.calls == []
        assert _state(db) == before

    async def test_org_permissions_update_hardcoded_pair_outside_the_matrix_is_refused(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """documents.delete is hardcoded but no matrix row: refused as a ValueError either
        way, before any statement."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        with pytest.raises((svc.UnknownPermissionError, svc.HardcodedDenialError)):
            await svc.update_org_permission(
                db.pool, actor=admin, patch=_patch("documents", "delete", "confirm"), ip=_IP
            )

        assert db.calls == []

    async def test_org_permissions_update_audit_failure_rolls_the_change_back(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await svc.update_org_permission(
                db.pool, actor=admin, patch=_patch("gmail", "read", "deny"), ip=_IP
            )

        assert _state(db) == before
        assert db.org_permissions(ORG_ID)["gmail"]["read"] == "allow"
        assert any(outcome.startswith("rollback") for _, outcome in db.transactions)

    async def test_org_permissions_update_never_touches_another_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID, updated_at=_OLD)
        other = _rows_of(db, OTHER_ORG_ID)
        admin = _actor(db, "org_admin", ORG_ID)

        await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch("gmail", "read", "deny"), ip=_IP
        )

        assert _rows_of(db, OTHER_ORG_ID) == other
        assert not _bound(db, OTHER_ORG_ID)
        assert _uuid(_one(db.audit)["org_id"]) == ORG_ID

    async def test_org_permissions_update_without_ip_records_no_ip(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        await svc.update_org_permission(
            db.pool, actor=admin, patch=_patch("gmail", "list", "confirm"), ip=None
        )

        assert _one(db.audit)["ip"] is None


# ---------------------------------------------------------------------------
# 7. critical_permissions
# ---------------------------------------------------------------------------


class TestCriticalPermissions:
    """The four promotable pairs of the actor's org, their stored state and pending_at."""

    async def test_org_permissions_critical_lists_the_four_promotable_pairs_sorted(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import CriticalPermissionsResponse

        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        result = await svc.critical_permissions(db.pool, actor=admin)

        assert isinstance(result, CriticalPermissionsResponse)
        assert [(e.tool, e.action) for e in result.permissions] == _PROMOTABLE
        assert {(e.state, e.pending_at) for e in result.permissions} == {("deny", None)}

    async def test_org_permissions_critical_state_follows_the_stored_row(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """'confirm' only when stored 'confirm'; a stored 'allow' or a missing row is 'deny'."""
        matrix = _with(gmail__send="confirm", outlook__send="allow")
        del matrix["outlook_calendar"]["update"]
        db.add_permissions(ORG_ID, matrix)
        admin = _actor(db, "org_admin")

        result = await _critical(svc, db, admin)

        assert result == {
            ("gmail", "send"): ("confirm", None),
            ("google_calendar", "update"): ("deny", None),
            ("outlook", "send"): ("deny", None),
            ("outlook_calendar", "update"): ("deny", None),
        }

    async def test_org_permissions_critical_pending_at_is_per_org(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)
        await _promote(svc, db, admin_a)

        mine = await _critical(svc, db, admin_a)
        theirs = await _critical(svc, db, admin_b)

        assert mine[("gmail", "send")] == ("deny", _T0)
        assert theirs[("gmail", "send")] == ("deny", None)

    async def test_org_permissions_critical_doesnt_resolve_due_promotions(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        """The server resolves first; critical_permissions itself only reads (the real
        clock is long past _T0's cooldown)."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)

        result = await _critical(svc, db, admin)

        assert result[("gmail", "send")] == ("deny", _T0)
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "deny"

    async def test_org_permissions_critical_reads_only_the_actors_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID, _with(gmail__send="confirm"))
        admin = _actor(db, "org_admin", ORG_ID)

        result = await _critical(svc, db, admin)

        assert result[("gmail", "send")] == ("deny", None)
        assert not _bound(db, OTHER_ORG_ID)


# ---------------------------------------------------------------------------
# 8. request_promotion
# ---------------------------------------------------------------------------


class TestRequestPromotion:
    """A fresh password, an audit row, then a 5-minute cooldown (nothing promoted yet)."""

    @pytest.mark.parametrize(("tool", "action"), _NOT_PROMOTABLE)
    async def test_org_permissions_promote_non_promotable_pair_is_refused_without_reauth(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, tool: str, action: str
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        before = _state(db)

        with pytest.raises(svc.NotPromotableError):
            await _promote(svc, db, admin, tool, action)

        reauth.assert_not_awaited()
        assert _state(db) == before

    async def test_org_permissions_promote_reauthenticates_the_actor(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        await _promote(svc, db, admin)

        reauth.assert_awaited_once()
        call = reauth.await_args
        assert call is not None
        assert call.kwargs == {"principal": admin, "password": _PASSWORD, "ip": _IP}
        assert call.args == (db.pool,)

    async def test_org_permissions_promote_failed_reauth_leaves_nothing(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        reauth.return_value = False
        before = _state(db)

        with pytest.raises(svc.ReauthFailedError):
            await _promote(svc, db, admin, password=_WRONG)

        assert _state(db) == before
        assert db.audit == []
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", None)

    async def test_org_permissions_promote_starts_the_cooldown(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        from admino.models import CriticalPermissionState

        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        result = await _promote(svc, db, admin)

        assert isinstance(result, CriticalPermissionState)
        assert (result.tool, result.action, result.state, result.pending_at) == (
            "gmail",
            "send",
            "deny",
            _T0,
        )
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "deny"
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", _T0)

    async def test_org_permissions_promote_records_the_exact_audit_event(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        await _promote(svc, db, admin, "outlook_calendar", "update")

        _assert_org_event(
            _one(db.audit),
            action="org.permission_promote",
            actor=admin,
            org_id=ORG_ID,
            metadata={
                "tool": "outlook_calendar",
                "action": "update",
                "old": "deny",
                "new": "confirm",
            },
        )

    async def test_org_permissions_promote_repeat_keeps_the_running_cooldown(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        """While pending: the existing pending_at comes back, no new cooldown, no 2nd row."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)

        again = await _promote(svc, db, admin, now=_T0 + timedelta(minutes=3))

        assert (again.state, again.pending_at) == ("deny", _T0)
        assert len(db.audit_rows("org.permission_promote")) == 1
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", _T0)

    async def test_org_permissions_promote_already_promoted_is_confirm_without_audit(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID, _with(gmail__send="confirm"))
        admin = _actor(db, "org_admin")

        result = await _promote(svc, db, admin)

        assert (result.state, result.pending_at) == ("confirm", None)
        assert db.audit == []
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("confirm", None)

    async def test_org_permissions_promote_audit_failure_leaves_nothing_pending(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await _promote(svc, db, admin)

        db.fail_audit = False
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", None)
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "deny"

    async def test_org_permissions_promote_without_now_reads_current_time(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The clock seam: the HTTP routes never pass now."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        monkeypatch.setattr(svc, "current_time", lambda: _T0 + timedelta(seconds=7))

        result = await _promote(svc, db, admin, now=None)

        assert result.pending_at == _T0 + timedelta(seconds=7)

    async def test_org_permissions_promote_never_records_the_password(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        await _promote(svc, db, admin)

        for call in db.calls:
            assert _PASSWORD not in call.sql
            assert all(_PASSWORD not in str(arg) for arg in call.args)
        assert _PASSWORD not in repr(db.audit)


# ---------------------------------------------------------------------------
# 9. resolve_due_promotions
# ---------------------------------------------------------------------------


class TestResolveDuePromotions:
    """Only this org's entries, once their cooldown has passed; no audit row."""

    async def test_org_permissions_resolve_before_the_cooldown_does_nothing(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)

        done = await _resolve(svc, db, admin, _T0 + _COOLDOWN - timedelta(seconds=1))

        assert done == []
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "deny"
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", _T0)

    @pytest.mark.parametrize(
        "elapsed",
        [
            pytest.param(_COOLDOWN, id="exactly-5-minutes"),
            pytest.param(_COOLDOWN + timedelta(hours=2), id="later"),
        ],
    )
    async def test_org_permissions_resolve_after_the_cooldown_promotes(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, elapsed: timedelta
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)

        done = await _resolve(svc, db, admin, _T0 + elapsed)

        assert done == [("gmail", "send")]
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "confirm"
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("confirm", None)

    async def test_org_permissions_resolved_pair_is_promoted_in_the_policy(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)
        await _resolve(svc, db, admin, _T0 + _COOLDOWN)

        policy = await svc.load_tool_policy(db.pool, _tenant(admin))

        assert policy.promoted == frozenset({("gmail", "send")})

    async def test_org_permissions_resolve_returns_the_completed_pairs_sorted(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin, "outlook", "send")
        await _promote(svc, db, admin, "gmail", "send", now=_T0 + timedelta(seconds=30))
        await _promote(svc, db, admin, "google_calendar", "update", now=_T0 + timedelta(minutes=4))

        done = await _resolve(svc, db, admin, _T0 + _COOLDOWN + timedelta(seconds=30))

        assert done == [("gmail", "send"), ("outlook", "send")]
        critical = await _critical(svc, db, admin)
        pending_at = _T0 + timedelta(minutes=4)
        assert critical[("google_calendar", "update")] == ("deny", pending_at)

    async def test_org_permissions_resolve_runs_only_this_orgs_entries(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        """Org B's due entry stays pending when org A resolves."""
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)
        await _promote(svc, db, admin_b)
        before_b = _rows_of(db, OTHER_ORG_ID)
        db.calls.clear()

        done = await _resolve(svc, db, admin_a, _T0 + timedelta(hours=1))

        assert done == []
        assert _rows_of(db, OTHER_ORG_ID) == before_b
        assert not _bound(db, OTHER_ORG_ID)
        assert (await _critical(svc, db, admin_b))[("gmail", "send")] == ("deny", _T0)

    async def test_org_permissions_resolve_records_no_audit_row(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)
        audit = copy.deepcopy(db.audit)

        await _resolve(svc, db, admin, _T0 + _COOLDOWN)

        assert db.audit == audit

    async def test_org_permissions_resolve_without_pending_writes_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        before = _state(db)

        assert await _resolve(svc, db, admin, _T0) == []
        assert _writes(db) == []
        assert _state(db) == before

    async def test_org_permissions_resolve_creates_a_missing_row(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        """An org whose matrix lacks the pair gets it stored 'confirm' (an upsert)."""
        matrix = _default_matrix()
        del matrix["gmail"]["send"]
        db.add_permissions(ORG_ID, matrix)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)

        await _resolve(svc, db, admin, _T0 + _COOLDOWN)

        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "confirm"

    async def test_org_permissions_resolve_without_now_reads_current_time(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)
        monkeypatch.setattr(svc, "current_time", lambda: _T0 + timedelta(minutes=4))

        assert await svc.resolve_due_promotions(db.pool, _tenant(admin)) == []

        monkeypatch.setattr(svc, "current_time", lambda: _T0 + _COOLDOWN)

        assert await svc.resolve_due_promotions(db.pool, _tenant(admin)) == [("gmail", "send")]


# ---------------------------------------------------------------------------
# 10. cancel_promotion
# ---------------------------------------------------------------------------


class TestCancelPromotion:
    """A pending promotion can be cancelled (audited); nothing else can."""

    async def test_org_permissions_cancel_without_pending_is_refused(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        with pytest.raises(svc.NoPendingPromotionError):
            await svc.cancel_promotion(db.pool, actor=admin, tool="gmail", action="send", ip=_IP)

        assert db.audit == []

    @pytest.mark.parametrize(("tool", "action"), _NOT_PROMOTABLE)
    async def test_org_permissions_cancel_non_promotable_pair_is_refused(
        self, svc: ModuleType, db: FakeDb, tool: str, action: str
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        with pytest.raises(svc.NotPromotableError):
            await svc.cancel_promotion(db.pool, actor=admin, tool=tool, action=action, ip=_IP)

        assert db.audit == []

    async def test_org_permissions_cancel_drops_the_pending_entry(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        from admino.models import CriticalPermissionState

        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)

        result = await svc.cancel_promotion(
            db.pool, actor=admin, tool="gmail", action="send", ip=_IP
        )

        assert isinstance(result, CriticalPermissionState)
        assert (result.tool, result.action, result.state, result.pending_at) == (
            "gmail",
            "send",
            "deny",
            None,
        )
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", None)
        assert await _resolve(svc, db, admin, _T0 + timedelta(hours=1)) == []
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "deny"

    async def test_org_permissions_cancel_records_the_exact_audit_event(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin, "outlook", "send")

        await svc.cancel_promotion(
            db.pool, actor=admin, tool="outlook", action="send", ip=_OTHER_IP
        )

        _assert_org_event(
            _one(db.audit_rows("org.permission_promote_cancel")),
            action="org.permission_promote_cancel",
            actor=admin,
            org_id=ORG_ID,
            metadata={"tool": "outlook", "action": "send"},
            ip=_OTHER_IP,
        )

    async def test_org_permissions_cancel_audit_failure_keeps_the_entry_pending(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        """The cancel row is recorded first: a failed record cancels nothing."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await svc.cancel_promotion(db.pool, actor=admin, tool="gmail", action="send", ip=_IP)

        db.fail_audit = False
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", _T0)

    async def test_org_permissions_cancel_cant_reach_another_orgs_pending_entry(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)
        await _promote(svc, db, admin_b)

        with pytest.raises(svc.NoPendingPromotionError):
            await svc.cancel_promotion(db.pool, actor=admin_a, tool="gmail", action="send", ip=_IP)

        assert (await _critical(svc, db, admin_b))[("gmail", "send")] == ("deny", _T0)


# ---------------------------------------------------------------------------
# 11. demote
# ---------------------------------------------------------------------------


class TestDemote:
    """A promoted pair goes back to 'deny' at once, audited in the same transaction."""

    async def test_org_permissions_demote_sets_the_row_back_to_deny(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        from admino.models import CriticalPermissionState

        db.add_permissions(ORG_ID, _with(gmail__send="confirm"))
        admin = _actor(db, "org_admin")

        result = await svc.demote(db.pool, actor=admin, tool="gmail", action="send", ip=_IP)

        assert isinstance(result, CriticalPermissionState)
        assert (result.tool, result.action, result.state, result.pending_at) == (
            "gmail",
            "send",
            "deny",
            None,
        )
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "deny"
        reauth.assert_not_awaited()

    async def test_org_permissions_demote_records_the_exact_audit_event(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID, _with(google_calendar__update="confirm"))
        admin = _actor(db, "org_admin")

        await svc.demote(db.pool, actor=admin, tool="google_calendar", action="update", ip=_IP)

        _assert_org_event(
            _one(db.audit),
            action="org.permission_demote",
            actor=admin,
            org_id=ORG_ID,
            metadata={
                "tool": "google_calendar",
                "action": "update",
                "old": "confirm",
                "new": "deny",
            },
        )

    async def test_org_permissions_demote_locks_writes_and_audits_in_one_transaction(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID, _with(outlook__send="confirm"))
        admin = _actor(db, "org_admin")

        await svc.demote(db.pool, actor=admin, tool="outlook", action="send", ip=_IP)

        _assert_change_in_one_transaction(db)

    async def test_org_permissions_demote_of_an_unpromoted_pair_is_refused(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        before = _state(db)

        with pytest.raises(svc.NotPromotedError):
            await svc.demote(db.pool, actor=admin, tool="gmail", action="send", ip=_IP)

        assert _state(db) == before
        assert _writes(db) == []

    @pytest.mark.parametrize(("tool", "action"), _NOT_PROMOTABLE)
    async def test_org_permissions_demote_non_promotable_pair_is_refused(
        self, svc: ModuleType, db: FakeDb, tool: str, action: str
    ) -> None:
        db.add_permissions(ORG_ID, _with(gmail__read="confirm", google_calendar__create="confirm"))
        admin = _actor(db, "org_admin")
        before = _state(db)

        with pytest.raises(svc.NotPromotableError):
            await svc.demote(db.pool, actor=admin, tool=tool, action=action, ip=_IP)

        assert _state(db) == before

    async def test_org_permissions_demote_drops_a_pending_entry_of_the_pair(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        """A pending entry left next to a stored 'confirm' (e.g. a concurrent resolve) goes
        with the demotion: it can't re-promote the pair later."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)
        db.add_permissions(ORG_ID, {"gmail": {"send": "confirm"}})

        await svc.demote(db.pool, actor=admin, tool="gmail", action="send", ip=_IP)

        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", None)
        assert await _resolve(svc, db, admin, _T0 + timedelta(hours=1)) == []
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "deny"

    async def test_org_permissions_demote_audit_failure_rolls_back(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID, _with(gmail__send="confirm"))
        admin = _actor(db, "org_admin")
        before = _state(db)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await svc.demote(db.pool, actor=admin, tool="gmail", action="send", ip=_IP)

        assert _state(db) == before
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "confirm"


# ---------------------------------------------------------------------------
# 12. Isolation of the critical permissions between orgs
# ---------------------------------------------------------------------------


class TestPromotionIsolation:
    """Org A promoting, resolving, cancelling or demoting never changes org B."""

    async def test_org_permissions_promotion_cycle_of_one_org_leaves_another_untouched(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID, _with(outlook__send="confirm"), updated_at=_OLD)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)
        await _promote(svc, db, admin_b, "gmail", "send")
        rows_b = _rows_of(db, OTHER_ORG_ID)
        critical_b = await _critical(svc, db, admin_b)
        db.calls.clear()

        await _promote(svc, db, admin_a, "gmail", "send")
        await _promote(svc, db, admin_a, "outlook", "send")
        await svc.cancel_promotion(db.pool, actor=admin_a, tool="outlook", action="send", ip=_IP)
        await _resolve(svc, db, admin_a, _T0 + _COOLDOWN)
        await svc.demote(db.pool, actor=admin_a, tool="gmail", action="send", ip=_IP)

        assert not _bound(db, OTHER_ORG_ID)
        assert _rows_of(db, OTHER_ORG_ID) == rows_b
        assert await _critical(svc, db, admin_b) == critical_b

    async def test_org_permissions_promotion_of_one_org_isnt_promoted_in_another(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID)
        admin_a = _actor(db, "org_admin", ORG_ID)
        admin_b = _actor(db, "org_admin", OTHER_ORG_ID)
        await _promote(svc, db, admin_a)
        await _resolve(svc, db, admin_a, _T0 + _COOLDOWN)

        policy_b = await svc.load_tool_policy(db.pool, _tenant(admin_b))

        assert policy_b.promoted == frozenset()
        assert db.org_permissions(OTHER_ORG_ID)["gmail"]["send"] == "deny"


# ---------------------------------------------------------------------------
# 13. The re-authentication, for real (fast password stand-in)
# ---------------------------------------------------------------------------


@pytest.fixture()
def yielding_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every audit write yield to the event loop once, like a database round trip.

    FakeDb answers without suspending, so without this two concurrent calls never
    interleave across the audit write (security review of GH-161, finding 1).
    """
    from admino import audit_events

    original = audit_events.record

    async def record(*args: Any, **kwargs: Any) -> None:
        await asyncio.sleep(0)
        await original(*args, **kwargs)

    monkeypatch.setattr(audit_events, "record", record)


class TestConcurrentPromotionChanges:
    """Concurrent requests on one pending promotion: one audit row each, no lost cancel."""

    async def test_org_permissions_concurrent_requests_record_one_promotion(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, yielding_audit: None
    ) -> None:
        """A double submit (two tabs) starts one cooldown and writes one audit row."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")

        first, second = await asyncio.gather(
            _promote(svc, db, admin), _promote(svc, db, admin, now=_T0 + timedelta(seconds=1))
        )

        assert len(db.audit_rows("org.permission_promote")) == 1
        assert (first.state, first.pending_at) == ("deny", _T0)
        assert (second.state, second.pending_at) == ("deny", _T0)
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", _T0)

    async def test_org_permissions_concurrent_cancels_record_one_cancellation(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, yielding_audit: None
    ) -> None:
        """Two concurrent cancels: one succeeds with one audit row, the other finds nothing."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)

        results = await asyncio.gather(
            svc.cancel_promotion(db.pool, actor=admin, tool="gmail", action="send", ip=_IP),
            svc.cancel_promotion(db.pool, actor=admin, tool="gmail", action="send", ip=_IP),
            return_exceptions=True,
        )

        refused = [result for result in results if isinstance(result, svc.NoPendingPromotionError)]
        assert len(refused) == 1
        assert len(db.audit_rows("org.permission_promote_cancel")) == 1
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", None)

    async def test_org_permissions_cancel_wins_over_a_concurrent_completion(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, yielding_audit: None
    ) -> None:
        """A cancel recorded at the cooldown's end is never followed by the promotion."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)

        cancelled, completed = await asyncio.gather(
            svc.cancel_promotion(db.pool, actor=admin, tool="gmail", action="send", ip=_IP),
            _resolve(svc, db, admin, _T0 + _COOLDOWN),
        )

        assert cancelled.state == "deny"
        assert completed == []
        assert db.org_permissions(ORG_ID)["gmail"]["send"] == "deny"
        assert len(db.audit_rows("org.permission_promote_cancel")) == 1

    async def test_org_permissions_cancel_audit_failure_keeps_it_pending(
        self, svc: ModuleType, db: FakeDb, reauth: AsyncMock, yielding_audit: None
    ) -> None:
        """A cancel whose audit write fails leaves the promotion pending, as it was."""
        db.add_permissions(ORG_ID)
        admin = _actor(db, "org_admin")
        await _promote(svc, db, admin)
        db.fail_audit = True

        with pytest.raises(AuditRecordError):
            await svc.cancel_promotion(db.pool, actor=admin, tool="gmail", action="send", ip=_IP)

        db.fail_audit = False
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", _T0)


class _Verifier:
    """Fast stand-in for passwords.verify_password; records the passwords it checks."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, password: str, encoded: str) -> bool:
        self.calls.append(password)
        return encoded == fake_hash(password)


class TestPromotionWithRealReauth:
    """request_promotion through the real admino.auth.reauthenticate and login throttle."""

    @pytest.fixture()
    def verifier(self, monkeypatch: pytest.MonkeyPatch, login_delays: list[float]) -> _Verifier:
        spy = _Verifier()
        monkeypatch.setattr(passwords, "verify_password", spy)
        monkeypatch.setattr(passwords, "needs_rehash", lambda _encoded: False)
        return spy

    def _admin(self, db: FakeDb) -> Principal:
        return _principal(
            db, db.add_account(role="org_admin", email=_EMAIL, password_hash=fake_hash(_PASSWORD))
        )

    async def test_org_permissions_real_reauth_right_password_starts_the_cooldown(
        self, svc: ModuleType, db: FakeDb, verifier: _Verifier
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = self._admin(db)

        result = await _promote(svc, db, admin)

        assert (result.state, result.pending_at) == ("deny", _T0)
        assert verifier.calls == [_PASSWORD]
        assert len(db.audit_rows("org.permission_promote")) == 1

    async def test_org_permissions_real_reauth_wrong_password_counts_a_failure(
        self, svc: ModuleType, db: FakeDb, verifier: _Verifier
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = self._admin(db)

        with pytest.raises(svc.ReauthFailedError):
            await _promote(svc, db, admin, password=_WRONG)

        row = db.throttle_row("account", account_subject(_EMAIL))
        assert row is not None and row["failures"] == 1
        assert db.audit_rows("org.permission_promote") == []
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", None)

    async def test_org_permissions_real_reauth_locked_account_is_refused(
        self, svc: ModuleType, db: FakeDb, verifier: _Verifier
    ) -> None:
        db.add_permissions(ORG_ID)
        admin = self._admin(db)
        db.add_throttle(
            "account",
            account_subject(_EMAIL),
            locked_until=datetime.now(UTC) + timedelta(minutes=10),
        )

        with pytest.raises(svc.ReauthFailedError):
            await _promote(svc, db, admin)

        assert verifier.calls == []
        assert (await _critical(svc, db, admin))[("gmail", "send")] == ("deny", None)

    async def test_org_permissions_real_reauth_logs_no_password_or_email(
        self,
        svc: ModuleType,
        db: FakeDb,
        verifier: _Verifier,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        db.add_permissions(ORG_ID)
        admin = self._admin(db)

        with pytest.raises(svc.ReauthFailedError):
            await _promote(svc, db, admin, password=_WRONG)
        await _promote(svc, db, admin)

        text = "\n".join(
            f"{record.name} {record.getMessage()} {record.exc_text or ''}"
            for record in caplog.records
        ).lower()
        for marker in (_PASSWORD, _WRONG, _EMAIL):
            assert marker.lower() not in text


# ---------------------------------------------------------------------------
# 14. permissions_summary
# ---------------------------------------------------------------------------


def _summary_states(result: Any) -> dict[tuple[str, str], str]:
    return {(entry.tool, entry.action): entry.state for entry in result.permissions}


class TestPermissionsSummary:
    """The read-only view of the actor's org policy, as the agent would apply it."""

    async def test_org_permissions_summary_lists_every_stored_pair_sorted(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        editor = _actor(db, "editor")

        result = await svc.permissions_summary(db.pool, actor=editor)

        assert [(entry.tool, entry.action) for entry in result.permissions] == _DEFAULT_PAIRS

    async def test_org_permissions_summary_states_are_the_engines_decisions(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        editor = _actor(db, "editor")
        config = build_default_permissions_config()

        result = await svc.permissions_summary(db.pool, actor=editor)

        assert _summary_states(result) == {
            (tool, action): check_permission(tool, action, config).allowed
            for tool, action in _DEFAULT_PAIRS
        }

    async def test_org_permissions_summary_disabled_service_reads_disabled(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Every action of a switched-off service, hardcoded ones included."""
        db.add_permissions(ORG_ID)
        db.add_org_settings(ORG_ID, gmail=False)
        editor = _actor(db, "editor")

        states = _summary_states(await svc.permissions_summary(db.pool, actor=editor))

        assert {state for (tool, _), state in states.items() if tool == "gmail"} == {"disabled"}
        assert states[("outlook", "read")] == "allow"
        assert "disabled" not in {state for (tool, _), state in states.items() if tool != "gmail"}

    async def test_org_permissions_summary_hardcoded_pairs_read_deny(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Even a malformed stored 'allow' on a hardcoded pair reads 'deny'."""
        db.add_permissions(ORG_ID, _with(gmail__delete="allow", outlook__send="allow"))
        editor = _actor(db, "editor")

        states = _summary_states(await svc.permissions_summary(db.pool, actor=editor))

        assert {states[pair] for pair in _HARDCODED_IN_MATRIX} == {"deny"}

    async def test_org_permissions_summary_promoted_pair_reads_confirm(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID, _with(gmail__send="confirm"))
        editor = _actor(db, "editor")

        states = _summary_states(await svc.permissions_summary(db.pool, actor=editor))

        assert states[("gmail", "send")] == "confirm"
        assert states[("outlook", "send")] == "deny"

    async def test_org_permissions_summary_reflects_only_the_actors_org(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID, _with(gmail__send="confirm", memory__store="deny"))
        db.add_org_settings(OTHER_ORG_ID, outlook=False)
        editor = _actor(db, "editor", ORG_ID)

        states = _summary_states(await svc.permissions_summary(db.pool, actor=editor))

        assert states[("gmail", "send")] == "deny"
        assert states[("memory", "store")] == "allow"
        assert states[("outlook", "read")] == "allow"
        assert not _bound(db, OTHER_ORG_ID)

    async def test_org_permissions_summary_entries_are_summary_models(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        from admino.models import PermissionSummaryEntry

        db.add_permissions(ORG_ID, {"memory": {"store": "allow"}})
        editor = _actor(db, "editor")

        result = await svc.permissions_summary(db.pool, actor=editor)

        assert result.permissions == [
            PermissionSummaryEntry(tool="memory", action="store", state="allow")
        ]

    async def test_org_permissions_summary_writes_nothing(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        db.add_permissions(ORG_ID)
        editor = _actor(db, "editor")
        before = _state(db)

        await svc.permissions_summary(db.pool, actor=editor)

        assert _writes(db) == []
        assert _state(db) == before


# ---------------------------------------------------------------------------
# 15. permissions_summary under data residency (GH-162)
# ---------------------------------------------------------------------------


def _engine_states(tools: set[str]) -> dict[tuple[str, str], str]:
    """The engine's decisions of the default matrix for these tools' pairs."""
    config = build_default_permissions_config()
    return {
        (tool, action): check_permission(tool, action, config).allowed
        for tool, action in _DEFAULT_PAIRS
        if tool in tools
    }


class TestResidencySummary:
    """A residency org's summary reads "disabled" for every Google/Microsoft action and
    the engine's decisions for the other tools; another org is never affected."""

    async def test_org_permissions_summary_residency_org_reads_the_connector_tools_disabled(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Every action of the six tools (hardcoded ones included) reads "disabled";
        memory reads as before."""
        db.add_permissions(ORG_ID)
        _residency(db, ORG_ID, on=True)
        editor = _actor(db, "editor")

        states = _summary_states(await svc.permissions_summary(db.pool, actor=editor))

        assert sorted(states) == _DEFAULT_PAIRS
        for tool in _RESIDENCY_TOOLS:
            assert {state for (name, _), state in states.items() if name == tool} == {"disabled"}, (
                tool
            )
        memory = {pair: state for pair, state in states.items() if pair[0] == "memory"}
        assert memory == _engine_states({"memory"})

    async def test_org_permissions_summary_residency_beats_a_promoted_pair(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """A promoted tier-2 pair of a residency org reads "disabled", not "confirm"."""
        db.add_permissions(ORG_ID, _with(gmail__send="confirm", outlook_calendar__update="confirm"))
        _residency(db, ORG_ID, on=True)
        editor = _actor(db, "editor")

        states = _summary_states(await svc.permissions_summary(db.pool, actor=editor))

        assert states[("gmail", "send")] == "disabled"
        assert states[("outlook_calendar", "update")] == "disabled"

    async def test_org_permissions_summary_residency_of_another_org_changes_nothing_here(
        self, svc: ModuleType, db: FakeDb
    ) -> None:
        """Org B has residency on: B's connector actions read "disabled", org A's summary
        is the engine's decisions with nothing disabled."""
        db.add_permissions(ORG_ID)
        db.add_permissions(OTHER_ORG_ID)
        _residency(db, OTHER_ORG_ID, on=True)
        editor_a = _actor(db, "editor", ORG_ID)
        editor_b = _actor(db, "editor", OTHER_ORG_ID)

        states_a = _summary_states(await svc.permissions_summary(db.pool, actor=editor_a))
        states_b = _summary_states(await svc.permissions_summary(db.pool, actor=editor_b))

        assert states_a == _engine_states(set(DEFAULT_PERMISSIONS))
        assert "disabled" not in states_a.values()
        assert {state for (tool, _), state in states_b.items() if tool in _RESIDENCY_TOOLS} == {
            "disabled"
        }
