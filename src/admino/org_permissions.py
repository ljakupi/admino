"""Tool permissions per organization: the matrix, critical promotions, run policy (GH-161).

Migration 0016 recreated the ``permissions`` table org-scoped (primary key
``(org_id, tool, action)``, ON DELETE CASCADE from organizations). Each org's
Org Admin manages the org's own matrix and critical (tier-2) permissions, and
every chat run loads its own org's policy:

- Seeding: ``seed_org_permissions`` stores ``DEFAULT_PERMISSIONS`` (34 rows,
  hardcoded pairs as 'deny') for one org, never overwriting a row;
  ``organizations.create_org`` calls it inside its transaction.
  ``seed_missing_orgs`` (startup) seeds every org that has no rows.
- The run policy: ``load_tool_policy`` returns a frozen ``ToolPolicy``: the
  org's ``PermissionsConfig``, its promoted tier-2 pairs (stored 'confirm')
  and its tool switches (``scoped_settings.org_tools_enabled``). Residency
  gating (GH-162): when ``scoped_settings.org_residency`` is on, the Google
  and Microsoft tools (``RESIDENCY_BLOCKED_TOOLS``) read as switched off, so
  the run doesn't advertise them, dispatch refuses them and the summary
  shows them "disabled"; the stored switches are untouched. The same read
  sets the policy's ``data_residency`` (GH-242), which the agent checks
  before any LLM call: a residency org's run never reaches a non-Swiss
  provider. ``policy_from_rows`` is its pure conversion of the stored values,
  shared with the send path's one-statement turn setup
  (``turn_setup.load_turn_setup``, GH-244).
- The matrix (``Capability.ORG_PERMISSIONS_MANAGE``): ``get_org_permissions``
  reads it; ``update_org_permission`` changes one pair (the normalized value
  of ``validate_permissions_config``) and records ``org.permission_change``.
- Critical permissions (``Capability.ORG_PERMISSIONS_MANAGE``):
  ``request_promotion`` re-checks the Org Admin's password
  (``auth.reauthenticate``), records ``org.permission_promote`` and starts a
  ``PROMOTION_COOLDOWN`` (5 minutes); ``resolve_due_promotions`` stores the
  pairs whose cooldown has passed as 'confirm'; ``cancel_promotion`` drops a
  pending one (``org.permission_promote_cancel``); ``demote`` sets a promoted
  pair back to 'deny' at once (``org.permission_demote``, no password: it
  only reduces privilege). ``critical_permissions`` lists the four
  promotable pairs with their state and pending time. The pending promotions
  live in this process only, keyed by (org, tool, action): a restart cancels
  them (fail closed). ``clear_pending`` empties them.
- The read-only summary (``Capability.ORG_PERMISSIONS_VIEW``, every member
  role): ``permissions_summary`` gives each stored pair's effective state
  (the engine's decision, or "disabled" for a switched-off service, a
  residency-blocked one included).

Inputs: the database pool (or the caller's connection for the seed and the
policy), the acting ``Principal`` (from the session) or a ``TenantContext``,
the validated ``PermissionPatch``, a (tool, action) pair, the typed password,
the client IP and, for tests, the time (``now``; it defaults to
``current_time()``, the clock seam); for ``policy_from_rows``, an org's
stored rows, switches and residency flag.
Outputs: ``ToolPolicy``, ``PermissionsResponse``,
``CriticalPermissionsResponse``, ``CriticalPermissionState``,
``PermissionsSummaryResponse``, the resolved pairs and the number of orgs
seeded. Errors: ``PermissionError``, ``UnknownPermissionError``,
``HardcodedDenialError``, ``NotPromotableError``, ``NoPendingPromotionError``,
``NotPromotedError``, ``ReauthFailedError``, ``AuditRecordError``.

Security notes:
- Authorization through ``access.can`` before any statement: a refused actor
  gets ``PermissionError`` and nothing is read or written. The Super Admin
  reaches neither the matrix nor the summary (operator blindness);
  ``load_tool_policy`` has no check (the server loads it for a member's run).
- Tenant isolation: the org is always ``TenantContext.from_principal(actor)``
  (or the run's tenant), a bind parameter, never a request value; another
  org's rows and pending promotions are never read or changed.
- Hardcoded denials can't be changed through the matrix (either tier, any
  value); a tier-2 pair is promoted only by a fresh password plus the
  cooldown. Stored values can't escalate: the policy runs them through
  ``validate_permissions_config`` (a hardcoded pair reads 'deny', a
  write-mutating 'allow' reads 'confirm'), and only a tier-2 pair stored
  'confirm' counts as promoted.
- Fail closed: a matrix change or a demotion, its row lock (``FOR UPDATE``)
  and its audit event share one transaction, so a failed audit write rolls
  the change back. A promotion request is recorded before its cooldown
  starts, and a failed cancellation record puts the pending entry back, so a
  failed record changes nothing.
- Race-free promotions: requests of one pair run one at a time (a lock per
  org and pair), and a cancellation or a completion claims the pending entry
  before any await, so each promotion starts, ends or is cancelled once.
- No content in audit rows or logs: events carry tool, action and state
  tokens only; the password is only handed to ``auth.reauthenticate`` and
  never reaches a statement, a row or a log line. Errors carry no input.
- Parameterized SQL only: every statement is a constant, every value a bind
  parameter.
- Imports only access, tenancy, audit_events, permissions, models,
  scoped_settings and auth from admino: never the server, agent, LLM, tools,
  OAuth or database modules. The permission engine imports nothing from here.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final, Protocol

from admino import audit_events, auth, scoped_settings
from admino.access import Capability, Principal, can
from admino.audit_events import AuditAction, TargetType
from admino.models import (
    RESIDENCY_BLOCKED_TOOLS,
    CriticalPermissionEntry,
    CriticalPermissionsResponse,
    CriticalPermissionState,
    PermissionEntry,
    PermissionsResponse,
    PermissionsSummaryResponse,
    PermissionSummaryEntry,
    ToolPolicy,
)
from admino.permissions import (
    DEFAULT_PERMISSIONS,
    HARDCODED_DENIALS,
    PROMOTABLE_DENIALS,
    build_default_permissions_config,
    check_permission,
    validate_permissions_config,
)
from admino.tenancy import TenantContext

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from uuid import UUID

    import asyncpg

    from admino.audit_events import MetadataValue
    from admino.models import PermissionPatch
    from admino.permissions import PermissionState

PROMOTION_COOLDOWN: Final = timedelta(minutes=5)

_SEED_SQL: Final = """
    INSERT INTO permissions (org_id, tool, action, permission) VALUES ($1, $2, $3, $4)
    ON CONFLICT (org_id, tool, action) DO NOTHING
"""
_MISSING_ORGS_SQL: Final = """
    SELECT id FROM organizations WHERE id NOT IN (SELECT org_id FROM permissions)
"""
_ORG_ROWS_SQL: Final = "SELECT tool, action, permission FROM permissions WHERE org_id = $1"
_ROW_SQL: Final = """
    SELECT permission FROM permissions WHERE org_id = $1 AND tool = $2 AND action = $3
"""
# Locked until the transaction ends: concurrent changes of one pair serialize.
_LOCK_SQL: Final = """
    SELECT permission FROM permissions WHERE org_id = $1 AND tool = $2 AND action = $3
    FOR UPDATE
"""
_UPSERT_SQL: Final = """
    INSERT INTO permissions (org_id, tool, action, permission) VALUES ($1, $2, $3, $4)
    ON CONFLICT (org_id, tool, action) DO UPDATE
    SET permission = EXCLUDED.permission, updated_at = now()
"""

# A requested promotion's start, keyed by (org_id, tool, action). In this
# process only: a restart cancels every pending promotion.
_pending: Final[dict[tuple[UUID, str, str], datetime]] = {}
# One lock per (org_id, tool, action): concurrent promotion requests of a pair
# (a double submit, two tabs) run one after the other, so one cooldown starts
# and one event is recorded. At most four per org.
_request_locks: Final[dict[tuple[UUID, str, str], asyncio.Lock]] = {}


class Executor(Protocol):
    """What the seed and the policy read run through: an asyncpg pool or connection."""

    async def execute(self, query: str, *args: object) -> str:
        """Run one statement with bind parameters."""
        ...

    # Any: asyncpg returns untyped Records.
    async def fetch(self, query: str, *args: object) -> Any:
        """Run one query and return its rows."""
        ...

    async def fetchrow(self, query: str, *args: object) -> Any:
        """Run one query and return its first row, or None."""
        ...


class UnknownPermissionError(ValueError):
    """The (tool, action) pair is not a row of the default permission matrix."""

    def __init__(self) -> None:
        super().__init__("Unknown tool action.")


class HardcodedDenialError(ValueError):
    """The (tool, action) pair is a hardcoded denial; the matrix can't change it."""

    def __init__(self) -> None:
        super().__init__("This tool/action pair is a hardcoded denial and cannot be changed.")


class NotPromotableError(LookupError):
    """The (tool, action) pair is not a promotable (tier-2) denial."""

    def __init__(self) -> None:
        super().__init__("Not a promotable permission")


class NoPendingPromotionError(LookupError):
    """The org has no pending promotion of the (tool, action) pair."""

    def __init__(self) -> None:
        super().__init__("No pending promotion for this permission")


class NotPromotedError(LookupError):
    """The (tool, action) pair is not promoted in the org (stored state isn't 'confirm')."""

    def __init__(self) -> None:
        super().__init__("This permission is not promoted")


class ReauthFailedError(Exception):
    """The password re-authentication failed (wrong password, or a locked account or IP)."""

    def __init__(self) -> None:
        super().__init__("Re-authentication failed.")


def current_time() -> datetime:
    """Return the current time, timezone-aware UTC (the clock every ``now=None`` reads).

    Returns:
        ``datetime.now(UTC)``.
    """
    return datetime.now(UTC)


def clear_pending() -> None:
    """Forget every pending promotion of every org (and the request locks)."""
    _pending.clear()
    _request_locks.clear()


def _require(actor: Principal, capability: Capability) -> None:
    """Raise PermissionError unless the actor has the capability (before any query)."""
    if not can(actor, capability):
        msg = "Forbidden"
        raise PermissionError(msg)


def _org_of(actor: Principal) -> UUID:
    """The actor's own org (never a request value)."""
    return TenantContext.from_principal(actor).org_id


def _require_promotable(tool: str, action: str) -> None:
    """Raise NotPromotableError unless (tool, action) is a tier-2 denial."""
    if (tool, action) not in PROMOTABLE_DENIALS:
        raise NotPromotableError


def _matrix(rows: Sequence[Any]) -> PermissionsResponse:
    """The stored rows as a PermissionsResponse, sorted by (tool, action)."""
    ordered = sorted(rows, key=lambda row: (row["tool"], row["action"]))
    return PermissionsResponse(
        permissions=[
            PermissionEntry(tool=row["tool"], action=row["action"], permission=row["permission"])
            for row in ordered
        ]
    )


async def _record(
    executor: audit_events.Executor,
    action: AuditAction,
    *,
    actor: Principal,
    org_id: UUID,
    ip: str | None,
    metadata: dict[str, MetadataValue],
) -> None:
    """Record one org.permission_* event: the actor, their org's log, the org as target."""
    actor_kind, actor_user_id = audit_events.actor_columns(actor)
    await audit_events.record(
        executor,
        action=action,
        actor_kind=actor_kind,
        actor_user_id=actor_user_id,
        org_id=org_id,
        target_type=TargetType.ORGANIZATION,
        target_ids=(org_id,),
        ip=ip,
        metadata=metadata,
    )


async def seed_org_permissions(executor: Executor, org_id: UUID) -> None:
    """Store the default permission matrix for one org, never overwriting a stored row.

    One ``INSERT ... ON CONFLICT DO NOTHING`` per pair of
    ``build_default_permissions_config()`` (hardcoded pairs stored 'deny').
    No audit event: seeding is part of creating the org (or of startup).

    Args:
        executor: The caller's connection (``create_org``'s transaction) or the pool.
        org_id: The org to seed.
    """
    for tool, permissions in build_default_permissions_config().tools.items():
        for action, state in permissions.actions.items():
            await executor.execute(_SEED_SQL, org_id, tool, action, state)


async def seed_missing_orgs(pool: asyncpg.Pool) -> int:
    """Seed the default matrix for every org without permission rows (startup).

    Orgs that have rows are untouched; each seeded org gets its rows in one
    transaction.

    Args:
        pool: The database pool.

    Returns:
        The number of orgs seeded.
    """
    rows = await pool.fetch(_MISSING_ORGS_SQL)
    for row in rows:
        async with pool.acquire() as conn, conn.transaction():
            await seed_org_permissions(conn, row["id"])
    return len(rows)


async def load_tool_policy(executor: Executor, tenant: TenantContext) -> ToolPolicy:
    """Return the tenant org's tool policy for one agent run.

    No capability check: the server loads it for any member's run. Only the
    tenant org's rows, tool switches and residency policy are read; nothing
    is written. An org without rows gets an empty config (everything
    default-deny). For a residency org (GH-162: the fail-closed
    ``scoped_settings.org_residency``) every ``RESIDENCY_BLOCKED_TOOLS`` tool
    reads as switched off, whatever its stored switch says, so the run
    neither advertises nor dispatches it, and (GH-242) the policy's
    ``data_residency`` is True, so the run refuses a non-Swiss LLM provider.

    Args:
        executor: The pool, or a connection.
        tenant: The org scope of the run.

    Returns:
        The frozen ToolPolicy: the validated config of the org's rows, the
        tier-2 pairs it stores as 'confirm', its effective tool switches and
        its residency flag (True for a residency org and for a missing org
        row, fail closed; False otherwise).
    """
    rows = await executor.fetch(_ORG_ROWS_SQL, tenant.org_id)
    enabled_tools = await scoped_settings.org_tools_enabled(executor, tenant)
    data_residency = await scoped_settings.org_residency(executor, tenant)
    return policy_from_rows(
        [(row["tool"], row["action"], row["permission"]) for row in rows],
        enabled_tools=enabled_tools,
        data_residency=data_residency,
    )


def policy_from_rows(
    rows: Iterable[Sequence[str]], *, enabled_tools: dict[str, bool], data_residency: bool
) -> ToolPolicy:
    """Build an org's run policy from its stored permission rows, switches and residency.

    Pure: the conversion ``load_tool_policy`` and the send path's turn setup
    (``turn_setup.load_turn_setup``, GH-244) share, so both read a stored
    state as the same policy.

    Args:
        rows: The org's stored ``(tool, action, permission)`` rows.
        enabled_tools: The org's stored switches (tool name -> enabled).
        data_residency: The org's residency flag (True for a missing org row).

    Returns:
        The frozen ToolPolicy: the validated config of the rows (a hardcoded
        pair reads 'deny', a write-mutating 'allow' reads 'confirm'), the
        tier-2 pairs stored 'confirm' as ``promoted``, the switches with every
        ``RESIDENCY_BLOCKED_TOOLS`` tool off under residency, and the flag.
    """
    raw: dict[str, dict[str, str]] = {}
    promoted: set[tuple[str, str]] = set()
    for tool, action, state in rows:
        if (tool, action) in PROMOTABLE_DENIALS and state == "confirm":
            # A promotion lives in ``promoted``; the config keeps the hardcoded
            # 'deny' (validate_permissions_config would enforce it anyway).
            promoted.add((tool, action))
            state = "deny"
        raw.setdefault(tool, {})[action] = state
    if data_residency:
        enabled_tools = {**enabled_tools, **dict.fromkeys(RESIDENCY_BLOCKED_TOOLS, False)}
    return ToolPolicy(
        permissions=validate_permissions_config(raw),
        promoted=frozenset(promoted),
        enabled_tools=enabled_tools,
        data_residency=data_residency,
    )


async def get_org_permissions(pool: asyncpg.Pool, *, actor: Principal) -> PermissionsResponse:
    """Return the stored permission matrix of the actor's own org.

    Args:
        pool: The database pool.
        actor: The Org Admin asking.

    Returns:
        The org's rows sorted by (tool, action), with their stored states (a
        promoted pair shows 'confirm').

    Raises:
        PermissionError: Without ``Capability.ORG_PERMISSIONS_MANAGE``; no
            query is issued.
    """
    _require(actor, Capability.ORG_PERMISSIONS_MANAGE)
    return _matrix(await pool.fetch(_ORG_ROWS_SQL, _org_of(actor)))


async def update_org_permission(
    pool: asyncpg.Pool, *, actor: Principal, patch: PermissionPatch, ip: str | None
) -> PermissionsResponse:
    """Change one permission of the actor's own org; audit a real change.

    The stored value is the normalized one (``validate_permissions_config``:
    'allow' on a write-mutating action becomes 'confirm'). One transaction:
    the row is locked, a missing row reads as 'deny', and a change is upserted
    with its ``org.permission_change`` event. An unchanged value writes and
    records nothing.

    Args:
        pool: The database pool.
        actor: The Org Admin changing it.
        patch: The validated (tool, action, permission).
        ip: The client address, if known.

    Returns:
        The org's full matrix after the change.

    Raises:
        PermissionError: Without ``Capability.ORG_PERMISSIONS_MANAGE``.
        UnknownPermissionError: If the pair isn't in ``DEFAULT_PERMISSIONS``.
        HardcodedDenialError: If the pair is a hardcoded denial (either tier).
        AuditRecordError: If the audit event can't be recorded; nothing changes.
        (The first three are raised before any query.)
    """
    _require(actor, Capability.ORG_PERMISSIONS_MANAGE)
    org_id = _org_of(actor)
    tool, action = patch.tool, patch.action
    if action not in DEFAULT_PERMISSIONS.get(tool, {}):
        raise UnknownPermissionError
    if (tool, action) in HARDCODED_DENIALS:
        raise HardcodedDenialError
    normalized = validate_permissions_config({tool: {action: patch.permission}})
    new: PermissionState = normalized.tools[tool].actions[action]
    async with pool.acquire() as conn, conn.transaction():
        locked = await conn.fetchrow(_LOCK_SQL, org_id, tool, action)
        old: str = "deny" if locked is None else locked["permission"]
        if old != new:
            await conn.execute(_UPSERT_SQL, org_id, tool, action, new)
            await _record(
                conn,
                AuditAction.ORG_PERMISSION_CHANGE,
                actor=actor,
                org_id=org_id,
                ip=ip,
                metadata={"tool": tool, "action": action, "old": old, "new": new},
            )
        rows = await conn.fetch(_ORG_ROWS_SQL, org_id)
    return _matrix(rows)


async def resolve_due_promotions(
    pool: asyncpg.Pool, tenant: TenantContext, *, now: datetime | None = None
) -> list[tuple[str, str]]:
    """Complete the tenant org's pending promotions whose cooldown has passed.

    Each due pair is stored 'confirm' (an upsert) and leaves the pending
    state; other orgs' entries are untouched. No audit event (the request was
    audited). If the write fails, the entries stay pending.

    Args:
        pool: The database pool.
        tenant: The org whose promotions to resolve.
        now: The current time (default: ``current_time()``).

    Returns:
        The completed (tool, action) pairs, sorted.
    """
    moment = current_time() if now is None else now
    org_id = tenant.org_id
    due = sorted(
        (tool, action)
        for (pending_org, tool, action), pending_at in _pending.items()
        if pending_org == org_id and moment - pending_at >= PROMOTION_COOLDOWN
    )
    if not due:
        return []
    # Claimed before any await, so a concurrent resolve can't complete them twice.
    claimed = {pair: _pending.pop((org_id, *pair)) for pair in due}
    try:
        async with pool.acquire() as conn, conn.transaction():
            for tool, action in due:
                await conn.execute(_UPSERT_SQL, org_id, tool, action, "confirm")
    except BaseException:
        for (tool, action), pending_at in claimed.items():
            _pending.setdefault((org_id, tool, action), pending_at)
        raise
    return due


async def critical_permissions(
    pool: asyncpg.Pool, *, actor: Principal
) -> CriticalPermissionsResponse:
    """Return the four promotable pairs of the actor's own org, with their pending time.

    Doesn't resolve due promotions (the caller does that first).

    Args:
        pool: The database pool.
        actor: The Org Admin asking.

    Returns:
        The pairs sorted by (tool, action): 'confirm' only when stored
        'confirm' (else 'deny'), and the org's pending time of each, if any.

    Raises:
        PermissionError: Without ``Capability.ORG_PERMISSIONS_MANAGE``; no
            query is issued.
    """
    _require(actor, Capability.ORG_PERMISSIONS_MANAGE)
    org_id = _org_of(actor)
    rows = await pool.fetch(_ORG_ROWS_SQL, org_id)
    stored = {(row["tool"], row["action"]): row["permission"] for row in rows}
    return CriticalPermissionsResponse(
        permissions=[
            CriticalPermissionEntry(
                tool=tool,
                action=action,
                state="confirm" if stored.get((tool, action)) == "confirm" else "deny",
                pending_at=_pending.get((org_id, tool, action)),
            )
            for tool, action in sorted(PROMOTABLE_DENIALS)
        ]
    )


async def request_promotion(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    tool: str,
    action: str,
    password: str,
    ip: str | None,
    now: datetime | None = None,
) -> CriticalPermissionState:
    """Start the cooldown of a tier-2 promotion after re-checking the actor's password.

    An already promoted pair is returned as 'confirm', and an already pending
    one keeps its running cooldown; neither is audited again. Otherwise
    ``org.permission_promote`` is recorded first, then the cooldown starts.

    Args:
        pool: The database pool.
        actor: The Org Admin promoting it.
        tool: The tool name.
        action: The action name.
        password: The password the Org Admin typed.
        ip: The client address, if known.
        now: The current time (default: ``current_time()``).

    Returns:
        The pair's state: 'deny' with its pending time, or 'confirm' (no
        pending time) when already promoted.

    Raises:
        PermissionError: Without ``Capability.ORG_PERMISSIONS_MANAGE``; no
            query is issued.
        NotPromotableError: If the pair isn't a tier-2 denial (no re-auth).
        ReauthFailedError: If the password re-authentication fails; nothing
            is pending or recorded.
        AuditRecordError: If the event can't be recorded; nothing is pending.
    """
    _require(actor, Capability.ORG_PERMISSIONS_MANAGE)
    org_id = _org_of(actor)
    _require_promotable(tool, action)
    key = (org_id, tool, action)
    # Serialized per pair: a concurrent request waits, then finds this one pending.
    async with _request_locks.setdefault(key, asyncio.Lock()):
        if not await auth.reauthenticate(pool, principal=actor, password=password, ip=ip):
            raise ReauthFailedError
        row = await pool.fetchrow(_ROW_SQL, org_id, tool, action)
        if row is not None and row["permission"] == "confirm":
            return CriticalPermissionState(tool=tool, action=action, state="confirm")
        if key in _pending:
            return CriticalPermissionState(
                tool=tool, action=action, state="deny", pending_at=_pending[key]
            )
        await _record(
            pool,
            AuditAction.ORG_PERMISSION_PROMOTE,
            actor=actor,
            org_id=org_id,
            ip=ip,
            metadata={"tool": tool, "action": action, "old": "deny", "new": "confirm"},
        )
        pending_at = _pending.setdefault(key, current_time() if now is None else now)
    return CriticalPermissionState(tool=tool, action=action, state="deny", pending_at=pending_at)


async def cancel_promotion(
    pool: asyncpg.Pool, *, actor: Principal, tool: str, action: str, ip: str | None
) -> CriticalPermissionState:
    """Cancel the actor's org's pending promotion of a tier-2 pair.

    The entry is claimed before any await, so neither a concurrent cancel nor
    the cooldown's completion (``resolve_due_promotions``) can act on it too;
    then ``org.permission_promote_cancel`` is recorded. If the record fails,
    the entry is put back.

    Args:
        pool: The database pool.
        actor: The Org Admin cancelling it.
        tool: The tool name.
        action: The action name.
        ip: The client address, if known.

    Returns:
        The pair's state: 'deny', no pending time.

    Raises:
        PermissionError: Without ``Capability.ORG_PERMISSIONS_MANAGE``.
        NotPromotableError: If the pair isn't a tier-2 denial.
        NoPendingPromotionError: If the org has no pending promotion of it.
        AuditRecordError: If the event can't be recorded; it stays pending.
    """
    _require(actor, Capability.ORG_PERMISSIONS_MANAGE)
    org_id = _org_of(actor)
    _require_promotable(tool, action)
    key = (org_id, tool, action)
    # Claimed before any await (like resolve_due_promotions).
    pending_at = _pending.pop(key, None)
    if pending_at is None:
        raise NoPendingPromotionError
    try:
        await _record(
            pool,
            AuditAction.ORG_PERMISSION_PROMOTE_CANCEL,
            actor=actor,
            org_id=org_id,
            ip=ip,
            metadata={"tool": tool, "action": action},
        )
    except BaseException:
        _pending.setdefault(key, pending_at)
        raise
    return CriticalPermissionState(tool=tool, action=action, state="deny")


async def demote(
    pool: asyncpg.Pool, *, actor: Principal, tool: str, action: str, ip: str | None
) -> CriticalPermissionState:
    """Set a promoted tier-2 pair of the actor's own org back to 'deny' at once.

    No password: a demotion only reduces privilege. One transaction: the row
    is locked, set to 'deny' and ``org.permission_demote`` is recorded. A
    pending promotion of the pair is dropped, so it can't re-promote it.

    Args:
        pool: The database pool.
        actor: The Org Admin demoting it.
        tool: The tool name.
        action: The action name.
        ip: The client address, if known.

    Returns:
        The pair's state: 'deny', no pending time.

    Raises:
        PermissionError: Without ``Capability.ORG_PERMISSIONS_MANAGE``.
        NotPromotableError: If the pair isn't a tier-2 denial.
        NotPromotedError: If the org doesn't store it as 'confirm'.
        AuditRecordError: If the event can't be recorded; nothing changes.
    """
    _require(actor, Capability.ORG_PERMISSIONS_MANAGE)
    org_id = _org_of(actor)
    _require_promotable(tool, action)
    async with pool.acquire() as conn, conn.transaction():
        locked = await conn.fetchrow(_LOCK_SQL, org_id, tool, action)
        if locked is None or locked["permission"] != "confirm":
            raise NotPromotedError
        await conn.execute(_UPSERT_SQL, org_id, tool, action, "deny")
        await _record(
            conn,
            AuditAction.ORG_PERMISSION_DEMOTE,
            actor=actor,
            org_id=org_id,
            ip=ip,
            metadata={"tool": tool, "action": action, "old": "confirm", "new": "deny"},
        )
    _pending.pop((org_id, tool, action), None)
    return CriticalPermissionState(tool=tool, action=action, state="deny")


async def permissions_summary(
    pool: asyncpg.Pool, *, actor: Principal
) -> PermissionsSummaryResponse:
    """Return the effective state of each stored pair of the actor's own org (read-only).

    "disabled" when the org switched the tool's service off; otherwise the
    permission engine's decision for the org's policy (hardcoded pairs read
    'deny', a promoted tier-2 pair 'confirm').

    Args:
        pool: The database pool.
        actor: The member asking (Org Admin, Editor or Viewer).

    Returns:
        One entry per stored (tool, action), sorted.

    Raises:
        PermissionError: Without ``Capability.ORG_PERMISSIONS_VIEW`` (the
            Super Admin); no query is issued.
    """
    _require(actor, Capability.ORG_PERMISSIONS_VIEW)
    policy = await load_tool_policy(pool, TenantContext.from_principal(actor))
    pairs = sorted(
        (tool, action)
        for tool, permissions in policy.permissions.tools.items()
        for action in permissions.actions
    )
    entries = [
        PermissionSummaryEntry(
            tool=tool,
            action=action,
            state=(
                "disabled"
                if policy.enabled_tools.get(tool) is False
                else check_permission(
                    tool, action, policy.permissions, promoted=policy.promoted
                ).allowed
            ),
        )
        for tool, action in pairs
    ]
    return PermissionsSummaryResponse(permissions=entries)
