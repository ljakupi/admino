"""Organization lifecycle for the Super Admin: create, limits, status, deletion, purge (GH-154).

One service, two callers: the Super Admin's platform routes and the admin CLI
(``create-org``, acting as ``access.Operator``) call the same functions.

- ``create_org`` inserts the organization, seeds its tool permission matrix
  (GH-161: ``org_permissions.seed_org_permissions``, the default rows) and
  records ``org.create``, then invites its first Org Admin through #153's
  invitation code (``invitations.send_first_admin_invitation``), all in one
  transaction. The invitation email is queued unless ``queue_email`` is False
  (the CLI without SMTP); the returned ``CreatedOrg`` carries the one-time
  accept link.
- ``list_orgs`` returns every organization's metadata.
- ``update_limits`` changes the given plan limits (seats, monthly budget,
  storage quota); ``set_residency`` switches the data residency policy. Both
  are refused while a deletion is pending.
- Status transitions: ``deactivate_org`` (active -> deactivated),
  ``reactivate_org`` (deactivated -> active), ``schedule_deletion`` (active or
  deactivated -> pending_deletion, ``purge_after = now() +`` the stored
  platform default ``retention.org_deletion_grace_days`` (GH-160, 30 days by
  default; a change applies to the next scheduling only), the active Org
  Admins emailed) and ``cancel_deletion`` (pending_deletion ->
  deactivated, never active: the Super Admin reactivates explicitly).
  Deactivating and scheduling end every session of the org's users; content
  is kept. Login, sessions, resets and invitation links already refuse an org
  that isn't active.
- ``purge_due_orgs`` irreversibly removes every org whose grace period is
  over, each in its own transaction: its audit events (through the database
  function ``purge_org_audit_events`` of migration 0011), its users (the
  foreign keys cascade to their sessions, invitations, queued email and reset
  tokens), the org row (cascading to its settings and permission rows), then
  its directory under the attachments root. It
  records one platform ``org.purge`` event (no org, counts only). A failure
  rolls that org back; the next run retries it. ``run_org_purge_job`` runs it
  at startup and then hourly from the server lifespan.

Inputs: the database pool; the acting ``Principal`` (a Super Admin; the
Operator for ``create_org`` only), the org id, the validated request models
(``OrgCreateRequest``, ``OrgLimitsPatch``), the invitee's language, the
configured public URL and the client IP; the attachments root (purge); the
stored grace period (``scoped_settings.current_platform_settings``).
Outputs: ``OrgSummary`` (org metadata only), a list of them, ``CreatedOrg``,
the number of orgs purged. Errors: ``PermissionError``, ``OrgNotFoundError``,
``InvalidOrgStatusError``, ``accounts.DuplicateEmailError`` (a taken admin
email), ``AuditRecordError``.

Security notes:
- Authorization through ``access.can`` before any query: ``org.create`` (or
  the Operator, for ``create_org`` only), ``org.lifecycle.manage`` (list and
  status transitions), ``org.limits.manage``, ``org.residency.manage``. Only a
  Super Admin has them; every other function refuses the Operator.
- Fail closed: every change and its audit event share one transaction, so a
  failed audit write rolls the change back. A taken admin email rolls the
  whole creation back: no org, no permission rows, no account, no audit row.
- Race-free transitions: the org row is locked (``FOR UPDATE``) before its
  status is checked. The purge re-checks each due org under that lock, so a
  concurrent cancel wins; the database function refuses an org that isn't
  pending and due, a second, independent gate on the irreversible step.
- Files: ``<attachments_root>/<org_id>`` is removed in a worker thread, last
  inside the purge transaction, so a database failure never deletes files and
  a file failure rolls the database back. A symlink is unlinked, never
  followed; a missing directory is fine.
- Operator blindness and no content in logs or audit rows: events carry IDs,
  counts, bools and ints only; nothing is logged but a failed purge's
  exception class name (no names, emails, tokens, links, IDs or paths). The
  accept link travels only in the queued email or in ``CreatedOrg``, whose
  ``repr()`` hides it.
- Parameterized SQL only: values travel as bind parameters; dates are
  computed on the database clock.
- Builds no ``Principal`` or ``Operator`` and imports nothing from the
  server, agent, LLM, tools or OAuth layers.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Final

from admino import (
    audit_events,
    email_outbox,
    invitations,
    org_permissions,
    scoped_settings,
    sessions,
)
from admino.access import Capability, Operator, Principal, can
from admino.audit_events import AuditAction, TargetType
from admino.email_templates import OrgDeletionScheduledParams
from admino.models import OrgSummary

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping
    from decimal import Decimal
    from uuid import UUID

    import asyncpg
    from asyncpg import Record
    from asyncpg.pool import PoolConnectionProxy

    from admino.audit_events import MetadataValue
    from admino.email_templates import EmailLanguage
    from admino.models import InvitationSummary, OrgCreateRequest, OrgLimitsPatch

logger = logging.getLogger(__name__)

ATTACHMENTS_ROOT: Final = Path("/app/data/attachments")
PURGE_INTERVAL_SECONDS: Final = 3600
ORG_NOT_FOUND_MESSAGE: Final = "Organization not found"
INVALID_STATUS_MESSAGE: Final = "This change isn't possible in the organization's current status."

# The statuses each change starts from.
_ACTIVE: Final = frozenset({"active"})
_DEACTIVATED: Final = frozenset({"deactivated"})
_PENDING_DELETION: Final = frozenset({"pending_deletion"})
_NOT_PENDING_DELETION: Final = frozenset({"active", "deactivated"})

# data_residency, the deletion dates and the timestamps keep their defaults.
_INSERT_SQL: Final = """
    INSERT INTO organizations (name, status, seats, monthly_budget_chf, storage_quota_bytes)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING id, name, status, seats, monthly_budget_chf, storage_quota_bytes, data_residency,
              deletion_requested_at, purge_after, created_at, updated_at
"""
_LIST_SQL: Final = """
    SELECT id, name, status, seats, monthly_budget_chf, storage_quota_bytes, data_residency,
           deletion_requested_at, purge_after, created_at, updated_at
    FROM organizations
    ORDER BY created_at, id
"""
# Locked until the transaction ends: concurrent changes of one org serialize.
_LOCK_SQL: Final = """
    SELECT name, status, seats, monthly_budget_chf, storage_quota_bytes, data_residency
    FROM organizations
    WHERE id = $1
    FOR UPDATE
"""
# Deactivating, reactivating and cancelling: no deletion dates afterwards.
_SET_STATUS_SQL: Final = """
    UPDATE organizations
    SET status = $2, deletion_requested_at = NULL, purge_after = NULL, updated_at = now()
    WHERE id = $1
    RETURNING id, name, status, seats, monthly_budget_chf, storage_quota_bytes, data_residency,
              deletion_requested_at, purge_after, created_at, updated_at
"""
# The dates on the database clock; $2 is the grace period.
_SCHEDULE_SQL: Final = """
    UPDATE organizations
    SET status = 'pending_deletion',
        deletion_requested_at = now(),
        purge_after = now() + $2::interval,
        updated_at = now()
    WHERE id = $1
    RETURNING id, name, status, seats, monthly_budget_chf, storage_quota_bytes, data_residency,
              deletion_requested_at, purge_after, created_at, updated_at
"""
# A NULL limit is not given: the column keeps its value.
_LIMITS_SQL: Final = """
    UPDATE organizations
    SET seats = coalesce($2, seats),
        monthly_budget_chf = coalesce($3, monthly_budget_chf),
        storage_quota_bytes = coalesce($4, storage_quota_bytes),
        updated_at = now()
    WHERE id = $1
    RETURNING id, name, status, seats, monthly_budget_chf, storage_quota_bytes, data_residency,
              deletion_requested_at, purge_after, created_at, updated_at
"""
_RESIDENCY_SQL: Final = """
    UPDATE organizations
    SET data_residency = $2, updated_at = now()
    WHERE id = $1
    RETURNING id, name, status, seats, monthly_budget_chf, storage_quota_bytes, data_residency,
              deletion_requested_at, purge_after, created_at, updated_at
"""
# Who is told about a scheduled deletion: the org's active Org Admins.
_ACTIVE_ADMINS_SQL: Final = """
    SELECT id FROM users
    WHERE org_id = $1 AND role = 'org_admin' AND status = 'active' AND deleted_at IS NULL
    ORDER BY id
"""
_DUE_SQL: Final = """
    SELECT id FROM organizations
    WHERE status = 'pending_deletion' AND purge_after <= now()
    ORDER BY purge_after, id
"""
# The locked re-check: a deletion cancelled since the due lookup matches nothing.
_LOCK_DUE_SQL: Final = """
    SELECT id FROM organizations
    WHERE id = $1 AND status = 'pending_deletion' AND purge_after <= now()
    FOR UPDATE
"""
# Migration 0011's function: the only way an org's audit events leave.
_PURGE_AUDIT_SQL: Final = "SELECT purge_org_audit_events($1)"
# Every user of the org, whatever its status; the foreign keys cascade.
_DELETE_USERS_SQL: Final = "DELETE FROM users WHERE org_id = $1"
_DELETE_ORG_SQL: Final = "DELETE FROM organizations WHERE id = $1"


class OrgNotFoundError(Exception):
    """Raised when the organization doesn't exist; carries no ID."""

    def __init__(self) -> None:
        super().__init__(ORG_NOT_FOUND_MESSAGE)


class InvalidOrgStatusError(Exception):
    """Raised when the change isn't allowed from the organization's current status."""

    def __init__(self) -> None:
        super().__init__(INVALID_STATUS_MESSAGE)


@dataclass(frozen=True)
class CreatedOrg:
    """A new organization, its first Org Admin's invitation and the one-time accept link.

    The link is a secret: ``repr()`` leaves it out.
    """

    organization: OrgSummary
    invitation: InvitationSummary
    accept_link: str = field(repr=False)


def _require(actor: Principal | Operator, capability: Capability) -> None:
    """Raise PermissionError unless the actor is a Principal with the capability (before any
    query)."""
    if not isinstance(actor, Principal) or not can(actor, capability):
        msg = "Forbidden"
        raise PermissionError(msg)


def _summary(row: Record) -> OrgSummary:
    """The OrgSummary of an organizations row (the quota column is in bytes)."""
    return OrgSummary(
        id=row["id"],
        name=row["name"],
        status=row["status"],
        seats=row["seats"],
        monthly_budget_chf=row["monthly_budget_chf"],
        storage_quota=row["storage_quota_bytes"],
        data_residency=row["data_residency"],
        deletion_requested_at=row["deletion_requested_at"],
        purge_after=row["purge_after"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _cents(amount: Decimal) -> int:
    """A CHF amount (at most 2 decimals) in whole cents, for audit metadata."""
    return int(amount * 100)


def _deleted_count(status: str) -> int:
    """The row count of a DELETE command tag ('DELETE <n>')."""
    return int(status.rpartition(" ")[2])


async def _record(
    conn: PoolConnectionProxy,
    action: AuditAction,
    *,
    actor: Principal | Operator,
    org_id: UUID,
    ip: str | None,
    metadata: Mapping[str, MetadataValue],
) -> None:
    """Record an org event in the org's own log (its admins see it), targeting the org."""
    actor_kind, actor_user_id = audit_events.actor_columns(actor)
    await audit_events.record(
        conn,
        action=action,
        actor_kind=actor_kind,
        actor_user_id=actor_user_id,
        org_id=org_id,
        target_type=TargetType.ORGANIZATION,
        target_ids=(org_id,),
        ip=ip,
        metadata=metadata,
    )


@asynccontextmanager
async def _locked_org(
    pool: asyncpg.Pool, org_id: UUID, *, allowed: frozenset[str]
) -> AsyncIterator[tuple[PoolConnectionProxy, Record]]:
    """Open a transaction, lock the org row and check its status; yield the connection and row.

    Raises:
        OrgNotFoundError: If the org doesn't exist (nothing is written).
        InvalidOrgStatusError: If its status isn't in ``allowed`` (nothing is
            written).
    """
    async with pool.acquire() as conn, conn.transaction():
        org: Record | None = await conn.fetchrow(_LOCK_SQL, org_id)
        if org is None:
            raise OrgNotFoundError
        if org["status"] not in allowed:
            raise InvalidOrgStatusError
        yield conn, org


async def create_org(
    pool: asyncpg.Pool,
    *,
    actor: Principal | Operator,
    request: OrgCreateRequest,
    language: EmailLanguage,
    public_url: str,
    ip: str | None,
    queue_email: bool = True,
) -> CreatedOrg:
    """Create an organization and invite its first Org Admin, in one transaction.

    The new org's permission matrix is seeded with the defaults right after
    its INSERT, in the same transaction, so a rolled-back creation leaves no
    permission rows.

    Args:
        pool: The database pool.
        actor: A Super Admin, or the Operator at the server's terminal (the
            admin CLI).
        request: The validated name, first Org Admin email, limits and status.
        language: The invited Org Admin's UI language, used for the email too.
        public_url: The configured origin the accept link is built from
            (``server.public_url``), without a trailing slash.
        ip: The client address, if known (None for the CLI).
        queue_email: Whether to queue the invitation email; False hands the
            link only to the caller (the CLI without SMTP).

    Returns:
        The CreatedOrg: the new OrgSummary, the InvitationSummary and the
        one-time accept link.

    Raises:
        PermissionError: Unless the actor is the Operator or has
            ``Capability.ORG_CREATE``; no query is issued.
        DuplicateEmailError: If a user with the email already exists anywhere
            on the platform; nothing is written.
        AuditRecordError: If an audit event can't be recorded; nothing is
            written.
    """
    if type(actor) is not Operator:
        _require(actor, Capability.ORG_CREATE)
    async with pool.acquire() as conn, conn.transaction():
        # INSERT ... RETURNING (like an UPDATE of the locked org) yields exactly one row.
        (row,) = await conn.fetch(
            _INSERT_SQL,
            request.name,
            request.status,
            request.seats,
            request.monthly_budget_chf,
            request.storage_quota,
        )
        organization = _summary(row)
        await org_permissions.seed_org_permissions(conn, organization.id)
        await _record(
            conn,
            AuditAction.ORG_CREATE,
            actor=actor,
            org_id=organization.id,
            ip=ip,
            metadata={
                "seats": request.seats,
                "monthly_budget_chf_cents": _cents(request.monthly_budget_chf),
                "storage_quota_bytes": request.storage_quota,
                "active": request.status == "active",
            },
        )
        sent = await invitations.send_first_admin_invitation(
            conn,
            actor=actor,
            org_id=organization.id,
            email=request.primary_admin_email,
            language=language,
            public_url=public_url,
            ip=ip,
            queue_email=queue_email,
        )
    return CreatedOrg(
        organization=organization, invitation=sent.summary, accept_link=sent.accept_link
    )


async def list_orgs(pool: asyncpg.Pool, *, actor: Principal) -> list[OrgSummary]:
    """Return every organization, whatever its status, oldest first (then by id).

    Args:
        pool: The database pool.
        actor: The Super Admin asking.

    Returns:
        One OrgSummary per organization.

    Raises:
        PermissionError: Without ``Capability.ORG_LIFECYCLE_MANAGE``; no query
            is issued.
    """
    _require(actor, Capability.ORG_LIFECYCLE_MANAGE)
    return [_summary(row) for row in await pool.fetch(_LIST_SQL)]


async def update_limits(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    org_id: UUID,
    patch: OrgLimitsPatch,
    ip: str | None,
) -> OrgSummary:
    """Change the given plan limits of an active or deactivated organization.

    Seats may go below the seats in use (new invitations are then refused).
    ``org.limits_change`` records the old and new value of each given limit
    (the budget in cents).

    Args:
        pool: The database pool.
        actor: The Super Admin changing them.
        org_id: The organization.
        patch: The limits to change (a None limit is not given).
        ip: The client address, if known.

    Returns:
        The organization's OrgSummary after the change.

    Raises:
        PermissionError: Without ``Capability.ORG_LIMITS_MANAGE``; no query is
            issued.
        OrgNotFoundError: If the org doesn't exist.
        InvalidOrgStatusError: If a deletion is pending.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes.
    """
    _require(actor, Capability.ORG_LIMITS_MANAGE)
    async with _locked_org(pool, org_id, allowed=_NOT_PENDING_DELETION) as (conn, old):
        (row,) = await conn.fetch(
            _LIMITS_SQL, org_id, patch.seats, patch.monthly_budget_chf, patch.storage_quota
        )
        metadata: dict[str, MetadataValue] = {}
        if patch.seats is not None:
            metadata |= {"seats_old": old["seats"], "seats_new": row["seats"]}
        if patch.monthly_budget_chf is not None:
            metadata |= {
                "monthly_budget_chf_cents_old": _cents(old["monthly_budget_chf"]),
                "monthly_budget_chf_cents_new": _cents(row["monthly_budget_chf"]),
            }
        if patch.storage_quota is not None:
            metadata |= {
                "storage_quota_bytes_old": old["storage_quota_bytes"],
                "storage_quota_bytes_new": row["storage_quota_bytes"],
            }
        await _record(
            conn,
            AuditAction.ORG_LIMITS_CHANGE,
            actor=actor,
            org_id=org_id,
            ip=ip,
            metadata=metadata,
        )
    return _summary(row)


async def deactivate_org(
    pool: asyncpg.Pool, *, actor: Principal, org_id: UUID, ip: str | None
) -> OrgSummary:
    """Deactivate an active organization and end every session of its users.

    Its content is kept; its users can't log in until it is reactivated.

    Args:
        pool: The database pool.
        actor: The Super Admin deactivating it.
        org_id: The organization.
        ip: The client address, if known.

    Returns:
        The organization's OrgSummary after the change.

    Raises:
        PermissionError: Without ``Capability.ORG_LIFECYCLE_MANAGE``; no query
            is issued.
        OrgNotFoundError: If the org doesn't exist.
        InvalidOrgStatusError: If the org isn't active.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes.
    """
    _require(actor, Capability.ORG_LIFECYCLE_MANAGE)
    async with _locked_org(pool, org_id, allowed=_ACTIVE) as (conn, _):
        (row,) = await conn.fetch(_SET_STATUS_SQL, org_id, "deactivated")
        revoked = await sessions.revoke_org_sessions(conn, org_id)
        await _record(
            conn,
            AuditAction.ORG_DEACTIVATE,
            actor=actor,
            org_id=org_id,
            ip=ip,
            metadata={"sessions_revoked": revoked},
        )
    return _summary(row)


async def reactivate_org(
    pool: asyncpg.Pool, *, actor: Principal, org_id: UUID, ip: str | None
) -> OrgSummary:
    """Reactivate a deactivated organization.

    Args:
        pool: The database pool.
        actor: The Super Admin reactivating it.
        org_id: The organization.
        ip: The client address, if known.

    Returns:
        The organization's OrgSummary after the change.

    Raises:
        PermissionError: Without ``Capability.ORG_LIFECYCLE_MANAGE``; no query
            is issued.
        OrgNotFoundError: If the org doesn't exist.
        InvalidOrgStatusError: If the org isn't deactivated.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes.
    """
    _require(actor, Capability.ORG_LIFECYCLE_MANAGE)
    async with _locked_org(pool, org_id, allowed=_DEACTIVATED) as (conn, _):
        (row,) = await conn.fetch(_SET_STATUS_SQL, org_id, "active")
        await _record(
            conn, AuditAction.ORG_REACTIVATE, actor=actor, org_id=org_id, ip=ip, metadata={}
        )
    return _summary(row)


async def schedule_deletion(
    pool: asyncpg.Pool, *, actor: Principal, org_id: UUID, ip: str | None
) -> OrgSummary:
    """Mark an active or deactivated organization for deletion after the grace period.

    Sets ``deletion_requested_at = now()`` and ``purge_after = now() +`` the
    stored ``retention.org_deletion_grace_days`` (read once, after the
    authorization), ends every session of its users and queues an
    ``org_deletion_scheduled`` email to each of its active Org Admins. The
    ``org.deletion_schedule`` event's ``grace_days`` is that stored value.

    Args:
        pool: The database pool.
        actor: The Super Admin scheduling it.
        org_id: The organization.
        ip: The client address, if known.

    Returns:
        The organization's OrgSummary after the change.

    Raises:
        PermissionError: Without ``Capability.ORG_LIFECYCLE_MANAGE``; no query
            is issued.
        OrgNotFoundError: If the org doesn't exist.
        InvalidOrgStatusError: If a deletion is already pending.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes.
        RuntimeError: If the grace period can't be read (no platform row);
            nothing changes.
    """
    _require(actor, Capability.ORG_LIFECYCLE_MANAGE)
    retention = (await scoped_settings.current_platform_settings(pool)).retention
    grace_days = retention.org_deletion_grace_days
    async with _locked_org(pool, org_id, allowed=_NOT_PENDING_DELETION) as (conn, _):
        (row,) = await conn.fetch(_SCHEDULE_SQL, org_id, timedelta(days=grace_days))
        revoked = await sessions.revoke_org_sessions(conn, org_id)
        admins = await conn.fetch(_ACTIVE_ADMINS_SQL, org_id)
        params = OrgDeletionScheduledParams(org_name=row["name"], purge_after=row["purge_after"])
        for admin in admins:
            await email_outbox.enqueue_email(conn, user_id=admin["id"], params=params)
        await _record(
            conn,
            AuditAction.ORG_DELETION_SCHEDULE,
            actor=actor,
            org_id=org_id,
            ip=ip,
            metadata={
                "sessions_revoked": revoked,
                "emails_queued": len(admins),
                "grace_days": grace_days,
            },
        )
    return _summary(row)


async def cancel_deletion(
    pool: asyncpg.Pool, *, actor: Principal, org_id: UUID, ip: str | None
) -> OrgSummary:
    """Cancel a pending deletion; the organization becomes deactivated (never active).

    Works until the purge has run, also after ``purge_after`` has passed.

    Args:
        pool: The database pool.
        actor: The Super Admin cancelling it.
        org_id: The organization.
        ip: The client address, if known.

    Returns:
        The organization's OrgSummary after the change.

    Raises:
        PermissionError: Without ``Capability.ORG_LIFECYCLE_MANAGE``; no query
            is issued.
        OrgNotFoundError: If the org doesn't exist (or was purged).
        InvalidOrgStatusError: If no deletion is pending.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes.
    """
    _require(actor, Capability.ORG_LIFECYCLE_MANAGE)
    async with _locked_org(pool, org_id, allowed=_PENDING_DELETION) as (conn, _):
        (row,) = await conn.fetch(_SET_STATUS_SQL, org_id, "deactivated")
        await _record(
            conn, AuditAction.ORG_DELETION_CANCEL, actor=actor, org_id=org_id, ip=ip, metadata={}
        )
    return _summary(row)


async def set_residency(
    pool: asyncpg.Pool, *, actor: Principal, org_id: UUID, enabled: bool, ip: str | None
) -> OrgSummary:
    """Switch the data residency policy of an active or deactivated organization.

    ``org.residency_change`` lands in the org's own log (its admins see it),
    also when the value doesn't change.

    Args:
        pool: The database pool.
        actor: The Super Admin changing it.
        org_id: The organization.
        enabled: The new policy.
        ip: The client address, if known.

    Returns:
        The organization's OrgSummary after the change.

    Raises:
        PermissionError: Without ``Capability.ORG_RESIDENCY_MANAGE``; no query
            is issued.
        OrgNotFoundError: If the org doesn't exist.
        InvalidOrgStatusError: If a deletion is pending.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes.
    """
    _require(actor, Capability.ORG_RESIDENCY_MANAGE)
    async with _locked_org(pool, org_id, allowed=_NOT_PENDING_DELETION) as (conn, old):
        (row,) = await conn.fetch(_RESIDENCY_SQL, org_id, enabled)
        await _record(
            conn,
            AuditAction.ORG_RESIDENCY_CHANGE,
            actor=actor,
            org_id=org_id,
            ip=ip,
            metadata={"enabled": row["data_residency"], "previous": old["data_residency"]},
        )
    return _summary(row)


def _remove_org_files(path: Path) -> None:
    """Remove an org's directory and everything under it (in a worker thread).

    A symlink (or a stray file) is unlinked, never followed; ``shutil.rmtree``
    unlinks the symlinks inside without following them. A missing path is fine.
    """
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


async def _purge_org(pool: asyncpg.Pool, org_id: UUID, attachments_root: Path) -> bool:
    """Purge one due org in its own transaction; return False if it is no longer due."""
    async with pool.acquire() as conn, conn.transaction():
        if await conn.fetchval(_LOCK_DUE_SQL, org_id) is None:
            return False
        audit_purged: int = await conn.fetchval(_PURGE_AUDIT_SQL, org_id)
        users_purged = _deleted_count(await conn.execute(_DELETE_USERS_SQL, org_id))
        await conn.execute(_DELETE_ORG_SQL, org_id)
        await audit_events.record(
            conn,
            action=AuditAction.ORG_PURGE,
            actor_kind="system",
            actor_user_id=None,
            org_id=None,
            target_type=TargetType.ORGANIZATION,
            target_ids=(org_id,),
            metadata={"users_purged": users_purged, "audit_events_purged": audit_purged},
        )
        # Last: a database failure above never deletes files, and a failure here
        # rolls the database back.
        await asyncio.to_thread(_remove_org_files, attachments_root / str(org_id))
    return True


async def purge_due_orgs(pool: asyncpg.Pool, *, attachments_root: Path = ATTACHMENTS_ROOT) -> int:
    """Irreversibly purge every organization whose deletion grace period is over.

    Each due org is purged in its own transaction (see the module docstring);
    one that fails is rolled back, logged with the exception class name only,
    and retried at the next run, while the others are still purged.

    Args:
        pool: The database pool.
        attachments_root: The directory holding one directory per org.

    Returns:
        The number of organizations purged.
    """
    purged = 0
    for due in await pool.fetch(_DUE_SQL):
        try:
            if await _purge_org(pool, due["id"], attachments_root):
                purged += 1
        except Exception as exc:
            logger.warning("Organization purge failed (%s); retrying next run.", type(exc).__name__)
    return purged


async def run_org_purge_job(
    pool: asyncpg.Pool,
    *,
    attachments_root: Path = ATTACHMENTS_ROOT,
    interval_seconds: float = PURGE_INTERVAL_SECONDS,
) -> None:
    """Purge the due organizations now and then once per interval, until cancelled.

    A failed run is logged (class name only) and retried at the next interval;
    cancellation stops the job.

    Args:
        pool: The database pool.
        attachments_root: The directory holding one directory per org.
        interval_seconds: Seconds between runs (default: one hour).
    """
    while True:
        try:
            await purge_due_orgs(pool, attachments_root=attachments_root)
        except Exception as exc:
            logger.warning(
                "Organization purge run failed (%s); retrying next interval.", type(exc).__name__
            )
        await asyncio.sleep(interval_seconds)
