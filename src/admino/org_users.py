"""Org Admin user management: list, change, deactivate, reactivate and delete users (GH-164).

An Org Admin lists the users of their org (``list_org_users``) with its seat
usage (``seat_usage``, GH-165), changes one
user's role, name or email (``update_org_user``), deactivates or reactivates
them (``deactivate_org_user``, ``reactivate_org_user``), deletes them
(``delete_org_user``) or sends them a password reset link
(``trigger_password_reset``). A forced logout is
``admino.session_management.force_logout`` (GH-152).

Inputs: the database pool, the acting ``Principal`` (always the org's Org
Admin: the org is ``actor.org_id``), the target user id, the client IP, plus
an ``OrgUserPatch`` (a change) or the configured public URL
(``server.public_url``, for the reactivation and reset emails).
Outputs: a list of ``OrgUserSummary`` (listing), an ``OrgSeats`` (seat
usage), one ``OrgUserSummary`` (a change, a deactivation, a reactivation),
None (deletion, reset). Errors:
``PermissionError``, ``accounts.UserNotInOrgError``,
``accounts.LastAdminError``, ``accounts.DuplicateEmailError``,
``invitations.SeatLimitError``, ``InvalidUserStatusError`` and
``audit_events.AuditRecordError``.

A user here is an ``active`` or ``deactivated`` member of the actor's org.
An invited account (invitations have their own routes, GH-153), a deleted
one, a Super Admin and another org's user are all "not found". Each action
runs in one transaction on one connection: the checks, the change, its email
and its audit event commit or roll back together.
- The seat usage is two reads, no transaction: ``limit`` is the org's seats,
  ``used`` its active and invited users (expired invitations included), the
  rule a new invitation is checked against (``invitations._SEATS_TAKEN_SQL``,
  #153). Deactivated and deleted users don't count. Nothing is written,
  audited or logged.
- A change runs the last-admin guard first when the new role isn't
  org_admin. An email change queues the content-free ``email_changed`` notice
  before the UPDATE (the outbox copies the address from the users row, so it
  goes to the old address) and deletes the user's live reset token, so a link
  already sent to the old address stops working. Values equal to the stored
  ones are no change: nothing is written or audited. A role change deletes
  nothing: the role is read on every request (GH-162).
- Deactivating runs the last-admin guard first, then sets the status, ends
  every session of the user and queues ``account_deactivated``. Connections,
  memory and settings are kept.
- Reactivating locks the org row and counts its seats (active and invited
  users, ``invitations.ensure_free_seat``), then sets the status and queues
  ``account_activated``.
- Deleting runs the last-admin guard first, ends the sessions, locks the
  user's chats, collects the ids of their attachments (GH-187), then deletes
  the users row; the foreign keys cascade to its chats (with their messages
  and attachments), OAuth connections, memory, settings, reset token and
  queued emails. The audit event survives it. Once the deletion committed,
  the attachments' files (originals, partial uploads, derived artifacts) are
  removed from disk (``attachments.remove_files``); a refused or rolled-back
  deletion removes none.
- A reset reuses GH-151's link (``password_reset.queue_reset_link``) for an
  active user, with the admin as the event's actor.

Concurrency: the guard locks the target's row and the org's active Org Admin
rows in id order before anything else locks the target, so concurrent
demotions, deactivations and deletions serialize without deadlocking. The
other actions lock the target's row (``FOR UPDATE``) while they check its
status; a reactivation locks the org row after it. A deletion then locks the
user's chats in the org (trashed ones included) in id order before the users
row goes: the order of the org-wide promotion notice (``chats``' S12a lock),
so a deletion and a notice can't deadlock over them (GH-265).

Security notes:
- Authorization through ``access.can`` before any query: listing and the seat
  usage need ``Capability.ORG_USERS_VIEW``; every other action
  ``Capability.ORG_USERS_MANAGE``, and a role change also
  ``Capability.ORG_USERS_ROLE_CHANGE``. A Super Admin (no org) is refused.
- Tenant isolation at the data layer: every statement is scoped by the
  actor's org id (a bind parameter). Another org's user answers exactly like
  an unknown id (``UserNotInOrgError``, carrying no IDs), never forbidden.
- Content-free audit and no logs (tracker #139 §5): events carry the actor,
  the org, the target user, the client IP, role tokens, bools and counts;
  never a name, an email, a token or a link. Nothing is logged here
  (``attachments.remove_files`` logs a failed removal by class name only).
- Email uniqueness rests on the case-insensitive unique index: a taken email
  rolls the whole change back and raises ``DuplicateEmailError`` ``from
  None`` (the driver's message repeats the email). The refusal is recorded
  after the rollback (``{"email_taken": True}``), so probing for existing
  emails shows in the org's audit log; the server throttles refused changes.
- The reset token never reaches the admin: it exists only in the queued email.
- Fail closed: a failed audit write rolls the action back.
- Files: a deletion removes only the files of the attachment ids its own
  transaction read (the target's, in the actor's org), by id under the org's
  directory; never a file name, and nothing before the commit.
- Parameterized SQL only: values travel as bind parameters. No FastAPI, and
  nothing from the server, agent, LLM, tools or OAuth layers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import asyncpg

from admino import (
    accounts,
    attachments,
    audit_events,
    email_outbox,
    invitations,
    password_reset,
    sessions,
)
from admino.access import Capability, can
from admino.audit_events import AuditAction, TargetType
from admino.email_templates import (
    AccountActivatedParams,
    AccountDeactivatedParams,
    EmailChangedParams,
)
from admino.models import OrgSeats, OrgUserPatch, OrgUserSummary

if TYPE_CHECKING:
    from uuid import UUID

    from asyncpg import Record
    from asyncpg.pool import PoolConnectionProxy

    from admino.access import Principal
    from admino.audit_events import Executor, MetadataValue

USER_NOT_FOUND_MESSAGE: Final = "User not found"
INVALID_USER_STATUS_MESSAGE: Final = "This change isn't possible in the user's current status."

# The org's users: active and deactivated members, never an invited or deleted
# account (a Super Admin has no org).
_LIST_SQL: Final = """
    SELECT id, name, email, role, status, created_at, last_login_at
    FROM users
    WHERE org_id = $1 AND status IN ('active', 'deactivated') AND deleted_at IS NULL
    ORDER BY created_at, id
"""
# One user of the actor's org, locked while its status is checked and changed.
_TARGET_SQL: Final = """
    SELECT id, name, email, role, status, created_at, last_login_at
    FROM users
    WHERE id = $1 AND org_id = $2 AND status IN ('active', 'deactivated') AND deleted_at IS NULL
    FOR UPDATE
"""
_ORG_NAME_SQL: Final = "SELECT name FROM organizations WHERE id = $1"
_ORG_SEATS_SQL: Final = "SELECT seats FROM organizations WHERE id = $1"
# The status and profile UPDATEs match the locked target's row: exactly one row
# comes back. A NULL keeps the stored value: only the changed fields are written.
_UPDATE_SQL: Final = """
    UPDATE users
    SET role = coalesce($1, role), name = coalesce($2, name), email = coalesce($3, email)
    WHERE id = $4 AND org_id = $5
    RETURNING id, name, email, role, status, created_at, last_login_at
"""
_DEACTIVATE_SQL: Final = """
    UPDATE users SET status = 'deactivated'
    WHERE id = $1 AND org_id = $2
    RETURNING id, name, email, role, status, created_at, last_login_at
"""
_REACTIVATE_SQL: Final = """
    UPDATE users SET status = 'active'
    WHERE id = $1 AND org_id = $2
    RETURNING id, name, email, role, status, created_at, last_login_at
"""
# Every chat of the user in the org, trashed ones included (the cascade removes
# them all), locked in id order before the users row goes: the same order as
# the promotion notice's lock (chats S12a), so a deletion and a notice can't
# lock the same chats in opposite orders and deadlock (GH-265).
_LOCK_CHATS_SQL: Final = """
    SELECT id FROM chats
    WHERE org_id = $1 AND owner_user_id = $2
    ORDER BY id
    FOR UPDATE
"""
# A11 (GH-187): every attachment of the user in the org (trashed and unsent ones
# included), read after the chat lock in the deletion's transaction. The cascade removes
# the rows; their files are removed by these ids once the deletion committed.
_USER_ATTACHMENTS_SQL: Final = """
    SELECT id FROM attachments WHERE org_id = $1 AND owner_user_id = $2
"""
# The foreign keys cascade to the user's chats (with their messages and
# attachments), connections, memory, settings, reset token and queued emails.
_DELETE_SQL: Final = "DELETE FROM users WHERE id = $1 AND org_id = $2"
# A reset link already sent to the old address stops working.
_CANCEL_RESET_SQL: Final = "DELETE FROM password_reset_tokens WHERE user_id = $1"


class InvalidUserStatusError(Exception):
    """Raised when the action doesn't apply to the user's status; carries no IDs."""

    def __init__(self) -> None:
        super().__init__(INVALID_USER_STATUS_MESSAGE)


def _authorize(actor: Principal, capability: Capability) -> UUID:
    """Return the actor's org if the actor has the capability (checked before any query).

    Raises:
        PermissionError: Without the capability, or without an org.
    """
    if not can(actor, capability) or actor.org_id is None:
        msg = "Forbidden"
        raise PermissionError(msg)
    return actor.org_id


def _summary(row: Record) -> OrgUserSummary:
    """The OrgUserSummary of a users row."""
    return OrgUserSummary.model_validate(dict(row))


async def _locked_target(conn: PoolConnectionProxy, *, org_id: UUID, user_id: UUID) -> Record:
    """Lock and return an active or deactivated user of the org.

    Raises:
        UserNotInOrgError: If the user is unknown, of another org, invited or deleted.
    """
    target: Record | None = await conn.fetchrow(_TARGET_SQL, user_id, org_id)
    if target is None:
        raise accounts.UserNotInOrgError
    return target


async def _org_name(conn: PoolConnectionProxy, org_id: UUID) -> str:
    """The org's display name (for the email params)."""
    name: str = await conn.fetchval(_ORG_NAME_SQL, org_id)
    return name


async def _record(
    executor: Executor,
    *,
    action: AuditAction,
    actor: Principal,
    org_id: UUID,
    user_id: UUID,
    ip: str | None,
    metadata: dict[str, MetadataValue] | None = None,
) -> None:
    """Record an action of the Org Admin on one user of their org."""
    await audit_events.record(
        executor,
        action=action,
        actor_kind=actor.kind,
        actor_user_id=actor.user_id,
        org_id=org_id,
        target_type=TargetType.USER,
        target_ids=(user_id,),
        ip=ip,
        metadata=metadata,
    )


async def list_org_users(pool: asyncpg.Pool, *, actor: Principal) -> list[OrgUserSummary]:
    """Return the active and deactivated users of the actor's org, oldest first.

    Args:
        pool: The database pool.
        actor: The Org Admin listing (the org is theirs).

    Returns:
        One summary per user, ordered by created_at, then id.

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_VIEW``; no query is issued.
    """
    org_id = _authorize(actor, Capability.ORG_USERS_VIEW)
    rows = await pool.fetch(_LIST_SQL, org_id)
    return [_summary(row) for row in rows]


async def seat_usage(pool: asyncpg.Pool, *, actor: Principal) -> OrgSeats:
    """Return the seat usage of the actor's org; read-only (GH-165).

    Args:
        pool: The database pool.
        actor: The Org Admin listing (the org is theirs).

    Returns:
        The org's seats (``limit``) and its active and invited users that
        aren't deleted (``used``, the rule ``invitations.ensure_free_seat``
        checks). ``used`` may exceed ``limit`` after the seats were lowered.

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_VIEW``; no query is issued.
    """
    org_id = _authorize(actor, Capability.ORG_USERS_VIEW)
    limit = await pool.fetchval(_ORG_SEATS_SQL, org_id)
    used = await pool.fetchval(invitations._SEATS_TAKEN_SQL, org_id)
    return OrgSeats(used=used, limit=limit)


async def update_org_user(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    user_id: UUID,
    patch: OrgUserPatch,
    ip: str | None,
) -> OrgUserSummary:
    """Change a user's role, name or email and record what changed.

    A role change records ``user.role_change`` (the old and new role); a name
    or email change one ``user.profile_change`` (which of the two changed).
    Values equal to the stored ones are no change.

    Args:
        pool: The database pool.
        actor: The Org Admin changing the user (the org is theirs).
        user_id: The user to change (the actor themselves included).
        patch: The new role, name or email.
        ip: The client address, if known.

    Returns:
        The user's summary after the change.

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_MANAGE`` (and, for a
            role, ``Capability.ORG_USERS_ROLE_CHANGE``); no query is issued.
        UserNotInOrgError: If the user isn't an active or deactivated member
            of the actor's org; nothing changes.
        LastAdminError: If the change would demote the org's last active Org
            Admin; nothing changes.
        DuplicateEmailError: If a user with the new email (in any
            capitalization) exists; nothing changes, and only the
            ``{"email_taken": True}`` event is recorded.
        AuditRecordError: If an audit event can't be recorded; nothing changes.
    """
    org_id = _authorize(actor, Capability.ORG_USERS_MANAGE)
    if patch.role is not None:
        _authorize(actor, Capability.ORG_USERS_ROLE_CHANGE)
    try:
        async with pool.acquire() as conn, conn.transaction():
            if patch.role is not None and patch.role != "org_admin":
                await accounts.ensure_not_last_active_admin(conn, org_id=org_id, user_id=user_id)
            target = await _locked_target(conn, org_id=org_id, user_id=user_id)
            role = patch.role if patch.role != target["role"] else None
            name = patch.name if patch.name != target["name"] else None
            email = patch.email if patch.email != target["email"] else None
            if role is None and name is None and email is None:
                return _summary(target)
            if email is not None:
                # Queued before the UPDATE: the outbox copies the old address.
                await email_outbox.enqueue_email(
                    conn,
                    user_id=user_id,
                    params=EmailChangedParams(org_name=await _org_name(conn, org_id)),
                )
                await conn.execute(_CANCEL_RESET_SQL, user_id)
            try:
                (row,) = await conn.fetch(_UPDATE_SQL, role, name, email, user_id, org_id)
            except asyncpg.UniqueViolationError:
                # The driver's message repeats the email.
                raise accounts.DuplicateEmailError from None
            if role is not None:
                await _record(
                    conn,
                    action=AuditAction.USER_ROLE_CHANGE,
                    actor=actor,
                    org_id=org_id,
                    user_id=user_id,
                    ip=ip,
                    metadata={"old_role": target["role"], "new_role": role},
                )
            if name is not None or email is not None:
                await _record(
                    conn,
                    action=AuditAction.USER_PROFILE_CHANGE,
                    actor=actor,
                    org_id=org_id,
                    user_id=user_id,
                    ip=ip,
                    metadata={"name_changed": name is not None, "email_changed": email is not None},
                )
    except accounts.DuplicateEmailError:
        # After the rollback: the refused attempt is audited, content-free.
        await _record(
            pool,
            action=AuditAction.USER_PROFILE_CHANGE,
            actor=actor,
            org_id=org_id,
            user_id=user_id,
            ip=ip,
            metadata={"email_taken": True},
        )
        raise
    return _summary(row)


async def deactivate_org_user(
    pool: asyncpg.Pool, *, actor: Principal, user_id: UUID, ip: str | None
) -> OrgUserSummary:
    """Deactivate an active user, end their sessions and email them.

    Records ``user.deactivate`` with the number of sessions ended.

    Args:
        pool: The database pool.
        actor: The Org Admin deactivating the user (the org is theirs).
        user_id: The user to deactivate (the actor themselves included).
        ip: The client address, if known.

    Returns:
        The user's summary, with status "deactivated".

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_MANAGE``; no query is issued.
        UserNotInOrgError: If the user isn't an active or deactivated member
            of the actor's org; nothing changes.
        LastAdminError: If the user is the org's last active Org Admin.
        InvalidUserStatusError: If the user is already deactivated.
        AuditRecordError: If the audit event can't be recorded; nothing changes.
    """
    org_id = _authorize(actor, Capability.ORG_USERS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        await accounts.ensure_not_last_active_admin(conn, org_id=org_id, user_id=user_id)
        target = await _locked_target(conn, org_id=org_id, user_id=user_id)
        if target["status"] != "active":
            raise InvalidUserStatusError
        (row,) = await conn.fetch(_DEACTIVATE_SQL, user_id, org_id)
        revoked = await sessions.revoke_user_sessions(conn, user_id)
        await email_outbox.enqueue_email(
            conn,
            user_id=user_id,
            params=AccountDeactivatedParams(org_name=await _org_name(conn, org_id)),
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


async def reactivate_org_user(
    pool: asyncpg.Pool, *, actor: Principal, user_id: UUID, public_url: str, ip: str | None
) -> OrgUserSummary:
    """Reactivate a deactivated user if the org has a free seat, and email them.

    Records ``user.activate``.

    Args:
        pool: The database pool.
        actor: The Org Admin reactivating the user (the org is theirs).
        user_id: The user to reactivate.
        public_url: The configured origin the login link is built from
            (``server.public_url``), without a trailing slash.
        ip: The client address, if known.

    Returns:
        The user's summary, with status "active".

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_MANAGE``; no query is issued.
        UserNotInOrgError: If the user isn't an active or deactivated member
            of the actor's org; nothing changes.
        InvalidUserStatusError: If the user is active.
        SeatLimitError: If the org's active and invited users fill every seat.
        AuditRecordError: If the audit event can't be recorded; nothing changes.
    """
    org_id = _authorize(actor, Capability.ORG_USERS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        target = await _locked_target(conn, org_id=org_id, user_id=user_id)
        if target["status"] != "deactivated":
            raise InvalidUserStatusError
        org = await invitations.ensure_free_seat(conn, org_id)
        (row,) = await conn.fetch(_REACTIVATE_SQL, user_id, org_id)
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


async def delete_org_user(
    pool: asyncpg.Pool, *, actor: Principal, user_id: UUID, ip: str | None
) -> None:
    """Delete a user's account with everything of it, and record ``user.delete``.

    The sessions are ended first (their count is the event's metadata), then
    the user's chats in the org are locked in id order (the promotion notice's
    order, GH-265) and their attachment ids read (GH-187); the users row's
    foreign keys cascade to the chats with their messages and attachments, the
    OAuth connections, memory, settings, reset token and queued emails. The
    email is free again. After the commit, the attachments' files are removed
    (``attachments.remove_files``: a failure is logged there, never raised).

    Args:
        pool: The database pool.
        actor: The Org Admin deleting the user (the org is theirs).
        user_id: The user to delete (the actor themselves included).
        ip: The client address, if known.

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_MANAGE``; no query is issued.
        UserNotInOrgError: If the user isn't an active or deactivated member
            of the actor's org; nothing changes.
        LastAdminError: If the user is the org's last active Org Admin.
        AuditRecordError: If the audit event can't be recorded; nothing is
            deleted, no file removed.
    """
    org_id = _authorize(actor, Capability.ORG_USERS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        await accounts.ensure_not_last_active_admin(conn, org_id=org_id, user_id=user_id)
        await _locked_target(conn, org_id=org_id, user_id=user_id)
        revoked = await sessions.revoke_user_sessions(conn, user_id)
        await conn.fetch(_LOCK_CHATS_SQL, org_id, user_id)
        owned = await conn.fetch(_USER_ATTACHMENTS_SQL, org_id, user_id)
        attachment_ids = [row["id"] for row in owned]
        await conn.execute(_DELETE_SQL, user_id, org_id)
        await _record(
            conn,
            action=AuditAction.USER_DELETE,
            actor=actor,
            org_id=org_id,
            user_id=user_id,
            ip=ip,
            metadata={"sessions_revoked": revoked},
        )
    # Only after the commit: a rolled-back or refused deletion keeps every file.
    await attachments.remove_files(attachments.attachments_root(), org_id, attachment_ids)


async def trigger_password_reset(
    pool: asyncpg.Pool, *, actor: Principal, user_id: UUID, public_url: str, ip: str | None
) -> None:
    """Email an active user of the actor's org a password reset link (GH-151's flow).

    Records ``password_reset.request`` with the Org Admin as the actor. The
    token and the link exist only in the queued email.

    Args:
        pool: The database pool.
        actor: The Org Admin triggering the reset (the org is theirs).
        user_id: The user who gets the link.
        public_url: The configured origin the link is built from
            (``server.public_url``), without a trailing slash.
        ip: The client address, if known.

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_MANAGE``; no query is issued.
        UserNotInOrgError: If the user isn't an active or deactivated member
            of the actor's org; nothing changes.
        InvalidUserStatusError: If the user is deactivated.
        AuditRecordError: If the audit event can't be recorded; no token is
            stored and no email is queued.
    """
    org_id = _authorize(actor, Capability.ORG_USERS_MANAGE)
    async with pool.acquire() as conn, conn.transaction():
        target = await _locked_target(conn, org_id=org_id, user_id=user_id)
        if target["status"] != "active":
            raise InvalidUserStatusError
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
