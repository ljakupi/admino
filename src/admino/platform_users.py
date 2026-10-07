"""Super Admin user administration and organization metadata (GH-167).

The Super Admin reads an org's accounts (``list_users``: active, deactivated
and invited) and its metadata (``org_metadata``: seats, storage, chat and file
counts), and acts on one account of that org: deactivates it
(``deactivate_user``), reactivates it (``reactivate_user``), sends it a
password reset link (``trigger_password_reset``) or, while the org has no
active Org Admin, re-invites its invited first Org Admin
(``reinvite_org_admin``).

Inputs: the database pool, the acting ``Principal`` (a Super Admin) and the
org id; for an action, the target user id and the client IP; the configured
public URL (``server.public_url``) for the reactivation, reset and invitation
links; for the re-invite, an optional new email and the Super Admin's session
language.
Outputs: a list of ``PlatformUserSummary`` (listing), an ``OrgMetadata``, one
``PlatformUserSummary`` (deactivation, reactivation), None (reset), an
``InvitationSummary`` (re-invite). Errors: ``PermissionError``,
``organizations.OrgNotFoundError``, ``organizations.InvalidOrgStatusError``,
``accounts.UserNotInOrgError``, ``accounts.LastAdminError``,
``org_users.InvalidUserStatusError``, ``invitations.SeatLimitError``,
``accounts.DuplicateEmailError``, ``OrgHasActiveAdminError`` and
``audit_events.AuditRecordError``.

The reads work in any org status and write nothing, so they aren't audited.
``seats.used`` is the invitation seat rule (``invitations._SEATS_TAKEN_SQL``,
#153): the org's active and invited users, expired invitations included; it
may exceed ``seats.limit``. ``chat_count`` is the org's chats that aren't
trashed, of every member (``chats.count_org_chats``, GH-176).
``file_count`` and ``storage_used_bytes`` are the org's attachments and the
bytes their originals and derived files use, trashed ones included
(``attachments.org_storage``, GH-187/GH-188): the figure the storage quota
is checked against.

A target is a users row of the org that isn't deleted, whatever its status.
Each action runs in one transaction on one connection: the checks, the
change, its email and its audit event commit or roll back together. The
refusals come in a fixed order: the org, the org's status, the target, the
target's status, then the action's own check.
- Deactivating works in any org status and runs the last-admin guard
  (``accounts.ensure_not_last_active_admin``): the Super Admin can't leave an
  org without an active Org Admin either. Then the status, every session of
  the user ends (``sessions.revoke_user_sessions``) and
  ``account_deactivated`` is queued. Connections, memory and settings are kept.
- Reactivating is refused while the org's deletion is pending; the user takes
  a free seat (``invitations.ensure_free_seat``) and gets ``account_activated``
  with the login link.
- A reset needs an active org (the link wouldn't work otherwise) and an
  active user; it is GH-151's link (``password_reset.queue_reset_link``).
- Re-inviting needs an active org, an invited Org Admin with a pending
  invitation (expired or not) and no active Org Admin in the org. Without an
  email it is #153's resend (``invitations.rotate_invitation``: a new link,
  the old one dead). With one, #153's revoke of the invited account
  (``invitations.revoke_pending_invitation``), then #153's send of an
  org_admin invitation to that address (``invitations.send_invitation``: the
  seat is checked after the old one is freed; the account and the email get
  the Super Admin's language). A taken email or a full org rolls the whole
  transaction back, so the old invitation and its link survive, and is then
  recorded as ``invitation.refuse`` (``invitations.record_refusal``).

Concurrency: deactivating runs the guard first, which locks the target's row
and the org's active Org Admin rows in id order. Reactivating and the reset
lock the target's row (``FOR UPDATE``) while they check its status; a
reactivation then locks the org row to count its seats, user row first, like
GH-164's reactivation. The re-invite locks the org row first, then the
target's row, so two re-invites of one org run one after the other.
- Why the two orders can't deadlock: after the org row, a re-invite locks only
  an invited Org Admin's row and its invitation. A reactivation asks for the
  org row only once its locked target is deactivated (an invited target is
  refused first), so it never holds a row a re-invite waits for. Deactivating
  and the reset never lock the org row. Keep this invariant: an action that
  locks the org row after a user row must never hold an invited account.
- The invitee's own accept (``invitations.accept_invitation``) locks the
  invitation, then the users row, the reverse of a re-invite; PostgreSQL
  aborts one of the two, and both roll back whole.
- A replacing re-invite locks the invited account's chats after the org row,
  the reverse of the promotion notice (chats, then the org row's key share).
  Invited users own no chats, so that lock matches no row and no cycle
  forms; if they ever do, lock the chats before the org row, like the purge.

Security notes:
- Authorization through ``access.can`` before any query: the reads need
  ``Capability.PLATFORM_ORG_METADATA_VIEW``, the actions
  ``Capability.PLATFORM_USERS_MANAGE``. Only a Super Admin has them; a member
  (an Org Admin of that very org included), the ``Operator`` and a malformed
  principal are refused.
- Org scope at the data layer: the org id is a bind parameter of every org
  and users lookup, and a target is looked up by its id and the org id
  together. Another org's user, an unknown id, a deleted account and a Super
  Admin answer alike (``UserNotInOrgError``); every error carries a fixed
  message, never an ID or an email.
- Operator blindness: summaries carry account metadata only and the metadata
  counts and sizes only; no statement reads org content or a password hash.
- No credential path: the reset and invitation tokens exist only in the
  queued emails, never in a return value. Nothing here sets a password,
  changes an existing user's email or acts as another user; the re-invite
  only replaces an invited account with a new one.
- Content-free audit and no logs (tracker #139 §5): every event is the Super
  Admin's (actor kind 'super_admin') in the affected org's log, with the
  target, the client IP, roles, bools, counts and IDs; never a name, an email,
  a token or a link. Nothing is logged.
- Fail closed: a failed audit write rolls the action back: no status change,
  no ended session, no token, no email.
- Parameterized SQL only: constant statements, values as bind parameters. No
  FastAPI, and nothing from the server, agent, LLM, tools or OAuth layers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from admino import (
    accounts,
    attachments,
    audit_events,
    chats,
    email_outbox,
    invitations,
    org_users,
    organizations,
    password_reset,
    sessions,
)
from admino.access import Capability, can
from admino.audit_events import AuditAction, TargetType
from admino.email_templates import AccountActivatedParams, AccountDeactivatedParams
from admino.models import OrgMetadata, OrgSeats, PlatformUserSummary

if TYPE_CHECKING:
    from uuid import UUID

    import asyncpg
    from asyncpg import Record
    from asyncpg.pool import PoolConnectionProxy

    from admino.access import Principal
    from admino.audit_events import MetadataValue
    from admino.email_templates import EmailLanguage
    from admino.models import InvitationSummary

HAS_ACTIVE_ADMIN_MESSAGE: Final = "The organization already has an active Org Admin."

# Every account of the org that isn't deleted: active, deactivated and invited
# (a Super Admin has no org).
_LIST_SQL: Final = """
    SELECT id, name, email, role, status, created_at, last_login_at
    FROM users
    WHERE org_id = $1 AND deleted_at IS NULL
    ORDER BY created_at, id
"""
# One account of the org, whatever its status, locked while it is checked and changed.
_TARGET_SQL: Final = """
    SELECT id, name, email, role, status, created_at, last_login_at
    FROM users
    WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
    FOR UPDATE
"""
_ORG_SQL: Final = "SELECT name, status, seats FROM organizations WHERE id = $1"
# The re-invite's lock, held until the transaction ends; a replacement's
# invitations.send_invitation reads the name and seats from it.
_LOCK_ORG_SQL: Final = "SELECT name, seats, status FROM organizations WHERE id = $1 FOR UPDATE"
_PENDING_INVITATION_SQL: Final = (
    "SELECT id FROM invitations WHERE user_id = $1 AND accepted_at IS NULL"
)
_HAS_ACTIVE_ADMIN_SQL: Final = """
    SELECT EXISTS (
        SELECT 1 FROM users
        WHERE org_id = $1 AND role = 'org_admin' AND status = 'active' AND deleted_at IS NULL
    )
"""


class OrgHasActiveAdminError(Exception):
    """Raised when a re-invite targets an org that already has an active Org Admin; no IDs."""

    def __init__(self) -> None:
        super().__init__(HAS_ACTIVE_ADMIN_MESSAGE)


def _authorize(actor: Principal, capability: Capability) -> None:
    """Raise PermissionError unless the actor has the capability (checked before any query)."""
    if not can(actor, capability):
        msg = "Forbidden"
        raise PermissionError(msg)


def _summary(row: Record) -> PlatformUserSummary:
    """The PlatformUserSummary of a users row."""
    return PlatformUserSummary.model_validate(dict(row))


async def _org(executor: asyncpg.Pool | PoolConnectionProxy, org_id: UUID) -> Record:
    """Return the org's name, status and seats.

    Raises:
        OrgNotFoundError: If the org doesn't exist.
    """
    org: Record | None = await executor.fetchrow(_ORG_SQL, org_id)
    if org is None:
        raise organizations.OrgNotFoundError
    return org


async def _locked_target(conn: PoolConnectionProxy, *, org_id: UUID, user_id: UUID) -> Record:
    """Lock and return a non-deleted account of the org, whatever its status.

    Raises:
        UserNotInOrgError: If the user is unknown, of another org, deleted or a
            Super Admin.
    """
    target: Record | None = await conn.fetchrow(_TARGET_SQL, user_id, org_id)
    if target is None:
        raise accounts.UserNotInOrgError
    return target


async def _record(
    conn: PoolConnectionProxy,
    *,
    action: AuditAction,
    actor: Principal,
    org_id: UUID,
    user_id: UUID,
    ip: str | None,
    metadata: dict[str, MetadataValue] | None = None,
) -> None:
    """Record the Super Admin's action on one user, in the affected org's log."""
    await audit_events.record(
        conn,
        action=action,
        actor_kind=actor.kind,
        actor_user_id=actor.user_id,
        org_id=org_id,
        target_type=TargetType.USER,
        target_ids=(user_id,),
        ip=ip,
        metadata=metadata,
    )


async def list_users(
    pool: asyncpg.Pool, *, actor: Principal, org_id: UUID
) -> list[PlatformUserSummary]:
    """Return every non-deleted account of an org, oldest first; read-only.

    Args:
        pool: The database pool.
        actor: The Super Admin listing.
        org_id: The org (any status).

    Returns:
        One summary per active, deactivated or invited account, ordered by
        created_at, then id; empty for an org without accounts.

    Raises:
        PermissionError: Without ``Capability.PLATFORM_ORG_METADATA_VIEW``; no
            query is issued.
        OrgNotFoundError: If the org doesn't exist.
    """
    _authorize(actor, Capability.PLATFORM_ORG_METADATA_VIEW)
    await _org(pool, org_id)
    rows = await pool.fetch(_LIST_SQL, org_id)
    return [_summary(row) for row in rows]


async def org_metadata(pool: asyncpg.Pool, *, actor: Principal, org_id: UUID) -> OrgMetadata:
    """Return an org's seat usage and counts; read-only.

    Args:
        pool: The database pool.
        actor: The Super Admin asking.
        org_id: The org (any status).

    Returns:
        The org's seats (``limit``) and its active and invited users that
        aren't deleted (``used``, which may exceed ``limit``); the number of
        the org's chats that aren't trashed (``chat_count``, a count only);
        the number of the org's attachments (``file_count``) and the bytes
        they use (``storage_used_bytes``), trashed ones included, never a
        file name; another org's files never count.

    Raises:
        PermissionError: Without ``Capability.PLATFORM_ORG_METADATA_VIEW``; no
            query is issued.
        OrgNotFoundError: If the org doesn't exist.
    """
    _authorize(actor, Capability.PLATFORM_ORG_METADATA_VIEW)
    org = await _org(pool, org_id)
    used = await pool.fetchval(invitations._SEATS_TAKEN_SQL, org_id)
    file_count, storage_used_bytes = await attachments.org_storage(pool, org_id)
    return OrgMetadata(
        seats=OrgSeats(used=used, limit=org["seats"]),
        storage_used_bytes=storage_used_bytes,
        chat_count=await chats.count_org_chats(pool, org_id),
        file_count=file_count,
    )


async def deactivate_user(
    pool: asyncpg.Pool, *, actor: Principal, org_id: UUID, user_id: UUID, ip: str | None
) -> PlatformUserSummary:
    """Deactivate an active user of an org, end their sessions and email them.

    Records ``user.deactivate`` with the number of sessions ended.

    Args:
        pool: The database pool.
        actor: The Super Admin deactivating the user.
        org_id: The user's org (any status).
        user_id: The user to deactivate.
        ip: The client address, if known.

    Returns:
        The user's summary, with status "deactivated".

    Raises:
        PermissionError: Without ``Capability.PLATFORM_USERS_MANAGE``; no query
            is issued.
        OrgNotFoundError: If the org doesn't exist.
        LastAdminError: If the user is the org's last active Org Admin.
        UserNotInOrgError: If the user isn't a non-deleted account of the org.
        InvalidUserStatusError: If the user is deactivated or invited.
        AuditRecordError: If the audit event can't be recorded; nothing changes.
    """
    _authorize(actor, Capability.PLATFORM_USERS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        org = await _org(conn, org_id)
        await accounts.ensure_not_last_active_admin(conn, org_id=org_id, user_id=user_id)
        target = await _locked_target(conn, org_id=org_id, user_id=user_id)
        if target["status"] != "active":
            raise org_users.InvalidUserStatusError
        (row,) = await conn.fetch(org_users._DEACTIVATE_SQL, user_id, org_id)
        revoked = await sessions.revoke_user_sessions(conn, user_id)
        await email_outbox.enqueue_email(
            conn, user_id=user_id, params=AccountDeactivatedParams(org_name=org["name"])
        )
        await _record(
            conn,
            action=AuditAction.USER_DEACTIVATE,
            actor=actor,
            org_id=org_id,
            user_id=user_id,
            ip=ip,
            metadata={"sessions_revoked": revoked},
        )
    return _summary(row)


async def reactivate_user(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    org_id: UUID,
    user_id: UUID,
    public_url: str,
    ip: str | None,
) -> PlatformUserSummary:
    """Reactivate a deactivated user of an org if it has a free seat, and email them.

    Records ``user.activate``.

    Args:
        pool: The database pool.
        actor: The Super Admin reactivating the user.
        org_id: The user's org (active or deactivated).
        user_id: The user to reactivate.
        public_url: The configured origin the login link is built from
            (``server.public_url``), without a trailing slash.
        ip: The client address, if known.

    Returns:
        The user's summary, with status "active".

    Raises:
        PermissionError: Without ``Capability.PLATFORM_USERS_MANAGE``; no query
            is issued.
        OrgNotFoundError: If the org doesn't exist.
        InvalidOrgStatusError: If the org's deletion is pending.
        UserNotInOrgError: If the user isn't a non-deleted account of the org.
        InvalidUserStatusError: If the user is active or invited.
        SeatLimitError: If the org's active and invited users fill every seat.
        AuditRecordError: If the audit event can't be recorded; nothing changes.
    """
    _authorize(actor, Capability.PLATFORM_USERS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        org = await _org(conn, org_id)
        if org["status"] == "pending_deletion":
            raise organizations.InvalidOrgStatusError
        target = await _locked_target(conn, org_id=org_id, user_id=user_id)
        if target["status"] != "deactivated":
            raise org_users.InvalidUserStatusError
        await invitations.ensure_free_seat(conn, org_id)
        (row,) = await conn.fetch(org_users._REACTIVATE_SQL, user_id, org_id)
        await email_outbox.enqueue_email(
            conn,
            user_id=user_id,
            params=AccountActivatedParams(org_name=org["name"], login_link=f"{public_url}/login"),
        )
        await _record(
            conn,
            action=AuditAction.USER_ACTIVATE,
            actor=actor,
            org_id=org_id,
            user_id=user_id,
            ip=ip,
        )
    return _summary(row)


async def trigger_password_reset(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    org_id: UUID,
    user_id: UUID,
    public_url: str,
    ip: str | None,
) -> None:
    """Email an active user of an active org a password reset link (GH-151's flow).

    Records ``password_reset.request`` with the Super Admin as the actor. The
    token and the link exist only in the queued email.

    Args:
        pool: The database pool.
        actor: The Super Admin triggering the reset.
        org_id: The user's org (must be active).
        user_id: The user who gets the link.
        public_url: The configured origin the link is built from
            (``server.public_url``), without a trailing slash.
        ip: The client address, if known.

    Raises:
        PermissionError: Without ``Capability.PLATFORM_USERS_MANAGE``; no query
            is issued.
        OrgNotFoundError: If the org doesn't exist.
        InvalidOrgStatusError: If the org isn't active.
        UserNotInOrgError: If the user isn't a non-deleted account of the org.
        InvalidUserStatusError: If the user is deactivated or invited.
        AuditRecordError: If the audit event can't be recorded; no token is
            stored and no email is queued.
    """
    _authorize(actor, Capability.PLATFORM_USERS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        org = await _org(conn, org_id)
        if org["status"] != "active":
            raise organizations.InvalidOrgStatusError
        target = await _locked_target(conn, org_id=org_id, user_id=user_id)
        if target["status"] != "active":
            raise org_users.InvalidUserStatusError
        await password_reset.queue_reset_link(conn, user_id=user_id, public_url=public_url)
        await _record(
            conn,
            action=AuditAction.PASSWORD_RESET_REQUEST,
            actor=actor,
            org_id=org_id,
            user_id=user_id,
            ip=ip,
            metadata={"email_sent": True},
        )


async def _pending_admin_invitation(
    conn: PoolConnectionProxy, *, org_id: UUID, user_id: UUID
) -> UUID:
    """Lock the target and return its pending invitation's id: it must be an invited Org Admin.

    Raises:
        UserNotInOrgError: If the user isn't a non-deleted account of the org.
        InvalidUserStatusError: If the user isn't an invited Org Admin with a
            pending invitation.
    """
    target = await _locked_target(conn, org_id=org_id, user_id=user_id)
    if target["role"] != "org_admin" or target["status"] != "invited":
        raise org_users.InvalidUserStatusError
    invitation_id: UUID | None = await conn.fetchval(_PENDING_INVITATION_SQL, user_id)
    if invitation_id is None:
        raise org_users.InvalidUserStatusError
    return invitation_id


async def reinvite_org_admin(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    org_id: UUID,
    user_id: UUID,
    email: str | None,
    language: EmailLanguage,
    public_url: str,
    ip: str | None,
) -> InvitationSummary:
    """Resend or replace the invitation of an org's invited Org Admin while it has no active one.

    Without an email, the invitation is sent again with a new link
    (``invitation.resend``). With an email, the invited account is revoked
    (``invitation.revoke``) and a new org_admin invitation is sent to that
    address (``invitation.create``), also when it is the same address.

    Lock order: the org row first (``_LOCK_ORG_SQL``), and only then, in the
    replacement, the revoke's lock on the invited account's chats
    (``invitations.revoke_pending_invitation``). That is the reverse of the
    promotion notice, which locks the org's chats and then key-shares the
    org row, and still can't deadlock: invited users own no chats. An
    account is created ``invited`` and never returns to that status, and a
    pending invitee can't log in, so the chat lock matches no row and can't
    form a cycle with the notice (GH-265). If invitees ever own chats, the
    chat lock must move before the org lock, as the org purge does.

    Args:
        pool: The database pool.
        actor: The Super Admin re-inviting.
        org_id: The org (must be active).
        user_id: The invited Org Admin.
        email: None to resend; the replacement's email (validated by
            ``PlatformReinviteRequest``) to replace.
        language: The Super Admin's session language: a replacement's UI and
            email language.
        public_url: The configured origin the link is built from
            (``server.public_url``), without a trailing slash.
        ip: The client address, if known.

    Returns:
        The InvitationSummary: the same invitation with its new dates
        (resend), or the new invitation (replace).

    Raises:
        PermissionError: Without ``Capability.PLATFORM_USERS_MANAGE``; no query
            is issued.
        OrgNotFoundError: If the org doesn't exist.
        InvalidOrgStatusError: If the org isn't active.
        UserNotInOrgError: If the user isn't a non-deleted account of the org.
        InvalidUserStatusError: If the user isn't an invited Org Admin with a
            pending invitation.
        OrgHasActiveAdminError: If the org has an active Org Admin.
        DuplicateEmailError: If a user with the replacement email (in any
            capitalization) exists elsewhere; nothing changes, and only the
            ``invitation.refuse`` event is recorded.
        SeatLimitError: If the org has no free seat even after the old one is
            freed; nothing changes, and only ``invitation.refuse`` is recorded.
        AuditRecordError: If an audit event can't be recorded; nothing changes.
    """
    _authorize(actor, Capability.PLATFORM_USERS_MANAGE)
    try:
        async with pool.acquire() as conn, conn.transaction():
            org: Record | None = await conn.fetchrow(_LOCK_ORG_SQL, org_id)
            if org is None:
                raise organizations.OrgNotFoundError
            if org["status"] != "active":
                raise organizations.InvalidOrgStatusError
            invitation_id = await _pending_admin_invitation(conn, org_id=org_id, user_id=user_id)
            if await conn.fetchval(_HAS_ACTIVE_ADMIN_SQL, org_id):
                raise OrgHasActiveAdminError
            if email is None:
                summary = await invitations.rotate_invitation(
                    conn,
                    actor=actor,
                    org_id=org_id,
                    invitation_id=invitation_id,
                    public_url=public_url,
                    ip=ip,
                )
            else:
                await invitations.revoke_pending_invitation(
                    conn, actor=actor, org_id=org_id, invitation_id=invitation_id, ip=ip
                )
                sent = await invitations.send_invitation(
                    conn,
                    org=org,
                    org_id=org_id,
                    actor=actor,
                    email=email,
                    role="org_admin",
                    language=language,
                    public_url=public_url,
                    ip=ip,
                    queue_email=True,
                )
                summary = sent.summary
    except (accounts.DuplicateEmailError, invitations.SeatLimitError) as exc:
        # After the rollback: the refused replacement is audited, content-free.
        await invitations.record_refusal(
            pool, actor=actor, org_id=org_id, role="org_admin", error=exc, ip=ip
        )
        raise
    return summary
