"""Invitations: an Org Admin invites people into their org; the invitee accepts (GH-153).

An Org Admin sends an invitation (``create_invitation``), lists the org's
pending invitations (``list_invitations``), revokes one
(``revoke_invitation``) or sends it again with a new link
(``resend_invitation``). The invitee opens the emailed link
(``get_invitation``: the org name, the role and the email) and accepts it with
a name and a password (``accept_invitation``), which activates the account and
opens a session. A Super Admin invites the first Org Admin of an org that has
no users yet (``invite_first_org_admin``). Creating an organization (#154,
``admino.organizations.create_org``) invites its first Org Admin inside its
own transaction through ``send_first_admin_invitation``: the same rules, on
the caller's connection, by a Super Admin or the admin CLI's ``Operator``,
optionally without queueing the email; it hands the one-time accept link back
to the caller (the CLI shows it on the terminal when there is no SMTP).

Inputs: the database pool (or, for ``send_first_admin_invitation``, a
connection inside the caller's transaction); the acting ``Principal`` (or
``Operator``), the email, the member role, the invitee's language (the
inviting admin's session language), the configured public URL
(``server.public_url``) and the client IP (sending); an invitation id
(revoking, resending); the token from the link, plus the name, password,
client IP and user agent (accepting).
Outputs: an ``InvitationSummary`` (sending, resending), a ``SentInvitation``
(the summary and the accept link, from ``send_first_admin_invitation``), a
list of summaries (listing), None (revoking), an ``InvitationDetails``
(opening the link), an ``auth.LoginResult`` (accepting). Errors: ``PermissionError``,
``accounts.DuplicateEmailError``, ``SeatLimitError``,
``InvitationNotFoundError``, ``InvalidInvitationError``, ``OrgNotFoundError``,
``OrgHasUsersError`` and ``passwords.PasswordPolicyError``.

Sending runs in one transaction: the org row is locked (``FOR UPDATE``) and
the org's active and invited users are counted (an expired invitation keeps
its seat until it is revoked; deactivated and deleted users don't count). A
full org raises ``SeatLimitError`` before anything is written
(``ensure_free_seat``, which an Org Admin's reactivation of a deactivated
user reuses, GH-164's ``admino.org_users``). Then the
invitee's users row is inserted (a member of the org with the role, status
'invited', no name and no password, the given language), plus an
``invitations`` row with the SHA-256 hash of a fresh 256-bit token and
``expires_at = now() + 72 hours``; the ``invitation`` email is queued through
the outbox (#148) with the link ``{public_url}/accept-invitation#token=<token>``,
and ``invitation.create`` is recorded. An email that exists anywhere on the
platform (the case-insensitive unique index) raises
``accounts.DuplicateEmailError``. A refused send (a taken email or a full
org) is recorded as ``invitation.refuse`` after its transaction rolled back,
so probing for existing emails shows in the org's audit log.

Revoking deletes the invited users row; the foreign keys cascade to its
invitation, its queued email, its sessions and its reset token, which frees
the email and the seat. Resending rotates the token and resets ``sent_at`` and
``expires_at`` (also for an expired invitation, without a seat check),
cancels the invitation email still queued with the old link
(``email_outbox.cancel_pending``) and queues a new one. Accepting checks the
link, then the password policy, and then in one transaction marks the
invitation used, activates the user with
the name and the Argon2 hash, stamps ``last_login_at``, opens a session with
the org's session policy and records ``invitation.accept``.

Security notes:
- Authorization through ``access.can`` before any query: sending, revoking and
  resending need ``Capability.ORG_USERS_INVITE``, listing
  ``Capability.ORG_USERS_VIEW``, the first Org Admin ``Capability.ORG_CREATE``.
  ``send_first_admin_invitation`` runs inside its caller's transaction and
  leaves authorization to that caller (``organizations.create_org``). An
  ``Operator`` is audited as actor kind 'operator', with no user id.
- Tenant isolation at the data layer: every org statement is scoped by the
  actor's org id. Another org's invitation, an unknown id and an accepted one
  are the same ``InvitationNotFoundError``.
- Only the token's SHA-256 hash is stored or queried; the raw token travels
  only inside the queued email's link, or, from ``send_first_admin_invitation``,
  in the returned ``SentInvitation.accept_link`` (kept out of its ``repr()``).
  A value that can't be a
  ``secrets.token_urlsafe(32)`` token is refused without a query. Every link
  that can't be used (unknown, expired, used, revoked, rotated, an account no
  longer invited, an org that isn't active) is the one
  ``InvalidInvitationError``.
- Single use and expiry are enforced by the database: the accepting UPDATE
  only matches a pending, unexpired invitation, and the users UPDATE only an
  invited, non-deleted user, so two concurrent accepts can't both succeed.
  Expiries are computed on the database clock, like ``sent_at``, so the
  table's 72-hour CHECK holds exactly.
- Link poisoning: the link base is the configured public URL, never a request
  header.
- The link is checked before the password policy, and a policy failure writes
  nothing, so the link stays usable. Argon2 runs in a worker thread
  (``asyncio.to_thread``), outside the transaction.
- Content-free audit (tracker #139 §5): the events carry the actor, the org,
  the invitation id, the invited user's id, the role and the client IP. Neither
  the email, the name, the token, the link nor the password reaches an audit
  row, an error or a log line; errors carry fixed messages only, and the
  driver's unique violation (which repeats the email) is dropped (``from
  None``). Nothing is logged.
- Probing: the duplicate-email refusal tells an Org Admin that an email exists
  somewhere on the platform (the issue requires it). Every refusal is audited
  (content-free: the role and ``email_taken`` or ``seat_limit``), and the
  server throttles refused sends per user.
- Fail closed: every change and its audit event share one transaction, so a
  failed audit write rolls the change back.
- Parameterized SQL only: values travel as bind parameters.
- Builds no ``Principal`` and imports nothing from the server, agent, LLM,
  tools or OAuth layers.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Final

import asyncpg

from admino import (
    accounts,
    audit_events,
    auth,
    email_outbox,
    passwords,
    scoped_settings,
    sessions,
)
from admino.access import Capability, MemberRole, can
from admino.audit_events import AuditAction, TargetType
from admino.email_templates import EmailLanguage, EmailTemplate, InvitationParams
from admino.models import InvitationDetails, InvitationSummary

if TYPE_CHECKING:
    from uuid import UUID

    from asyncpg import Record
    from asyncpg.pool import PoolConnectionProxy

    from admino.access import Operator, Principal

INVITATION_LIFETIME: Final = timedelta(hours=72)
INVALID_INVITATION_MESSAGE: Final = "This invitation link is invalid or has expired."
INVITATION_NOT_FOUND_MESSAGE: Final = "Invitation not found"
SEAT_LIMIT_MESSAGE: Final = "The organization has no free seats."

_TOKEN_BYTES: Final = 32  # 256 bits
# What secrets.token_urlsafe(32) produces: 43 URL-safe base64 characters.
_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9_-]{43}")

# Locked until the transaction ends: two concurrent sends can't both take the
# last seat.
_LOCK_ORG_SQL: Final = "SELECT name, seats FROM organizations WHERE id = $1 FOR UPDATE"
# The seats taken: active and invited users (expired invitations included).
_SEATS_TAKEN_SQL: Final = """
    SELECT count(*) FROM users
    WHERE org_id = $1 AND status IN ('active', 'invited') AND deleted_at IS NULL
"""
# Any users row at all, whatever its status (the first Org Admin).
_ORG_HAS_USERS_SQL: Final = "SELECT EXISTS (SELECT 1 FROM users WHERE org_id = $1)"
_INSERT_USER_SQL: Final = """
    INSERT INTO users (email, kind, org_id, role, status, ui_language)
    VALUES ($1, 'member', $2, $3, 'invited', $4)
    RETURNING id
"""
# The expiry is computed on the database clock, like sent_at.
_INSERT_INVITATION_SQL: Final = """
    INSERT INTO invitations (user_id, token_hash, expires_at)
    VALUES ($1, $2, now() + $3::interval)
    RETURNING id, sent_at, expires_at
"""
_LIST_SQL: Final = """
    SELECT i.id, u.email, u.role, i.sent_at, i.expires_at, i.expires_at <= now() AS expired
    FROM invitations i
    JOIN users u ON u.id = i.user_id
    WHERE u.org_id = $1 AND i.accepted_at IS NULL
    ORDER BY i.sent_at DESC
"""
# Pending invitations of the actor's org only; the foreign keys cascade.
_REVOKE_SQL: Final = """
    DELETE FROM users u
    USING invitations i
    WHERE i.user_id = u.id
      AND i.id = $1
      AND u.org_id = $2
      AND u.status = 'invited'
      AND i.accepted_at IS NULL
    RETURNING u.id
"""
_RESEND_SQL: Final = """
    UPDATE invitations i
    SET token_hash = $1, sent_at = now(), expires_at = now() + $2::interval
    FROM users u
    JOIN organizations o ON o.id = u.org_id
    WHERE u.id = i.user_id
      AND i.id = $3
      AND u.org_id = $4
      AND u.status = 'invited'
      AND i.accepted_at IS NULL
    RETURNING i.id, i.user_id, u.email, u.role, i.sent_at, i.expires_at, o.name AS org_name
"""
# Only a usable link matches: pending, unexpired, an invited account that
# isn't deleted, an active org.
_LOOKUP_SQL: Final = """
    SELECT i.user_id, u.email, u.role, u.org_id, o.name AS org_name
    FROM invitations i
    JOIN users u ON u.id = i.user_id
    JOIN organizations o ON o.id = u.org_id
    WHERE i.token_hash = $1
      AND i.accepted_at IS NULL
      AND i.expires_at > now()
      AND u.status = 'invited'
      AND u.deleted_at IS NULL
      AND o.status = 'active'
"""
# Atomic single use: no row comes back if the link was used, rotated, revoked
# or expired since the lookup.
_MARK_ACCEPTED_SQL: Final = """
    UPDATE invitations SET accepted_at = now()
    WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()
    RETURNING id
"""
_ACTIVATE_SQL: Final = """
    UPDATE users
    SET name = $1, password_hash = $2, status = 'active', last_login_at = now()
    WHERE id = $3 AND status = 'invited' AND deleted_at IS NULL
    RETURNING id
"""


class InvalidInvitationError(Exception):
    """Raised for every invitation link that can't be used, whatever the cause; carries no input."""

    def __init__(self) -> None:
        super().__init__(INVALID_INVITATION_MESSAGE)


class InvitationNotFoundError(Exception):
    """Raised when the id isn't a pending invitation of the actor's org; carries no IDs."""

    def __init__(self) -> None:
        super().__init__(INVITATION_NOT_FOUND_MESSAGE)


class SeatLimitError(Exception):
    """Raised when the org has no free seat for another invitation."""

    def __init__(self) -> None:
        super().__init__(SEAT_LIMIT_MESSAGE)


class OrgNotFoundError(Exception):
    """Raised when the org of a first Org Admin invitation doesn't exist."""

    def __init__(self) -> None:
        super().__init__("Organization not found")


class OrgHasUsersError(Exception):
    """Raised when the org of a first Org Admin invitation already has a users row."""

    def __init__(self) -> None:
        super().__init__("The organization already has users.")


@dataclass(frozen=True)
class SentInvitation:
    """A sent invitation and its one-time accept link (a secret: not in ``repr()``)."""

    summary: InvitationSummary
    accept_link: str = field(repr=False)


def _hash_token(token: str) -> bytes:
    """Return the 32-byte SHA-256 digest of a token: what the database stores."""
    return hashlib.sha256(token.encode()).digest()


def _is_plausible_token(token: object) -> bool:
    """True when ``token`` could be a ``secrets.token_urlsafe(32)`` value."""
    return isinstance(token, str) and _TOKEN_RE.fullmatch(token) is not None


def _require(actor: Principal, capability: Capability) -> None:
    """Raise PermissionError unless the actor has the capability (before any query)."""
    if not can(actor, capability):
        msg = "Forbidden"
        raise PermissionError(msg)


def _accept_link(public_url: str, token: str) -> str:
    """The link the invitee opens: ``{public_url}/accept-invitation#token=<token>``."""
    return f"{public_url}/accept-invitation#token={token}"


def _params(org_name: str, accept_link: str, expires_at: datetime) -> InvitationParams:
    """The invitation email's params: the org name, the link and the expiry."""
    return InvitationParams(org_name=org_name, accept_link=accept_link, expires_at=expires_at)


async def _record_refusal(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    org_id: UUID | None,
    role: MemberRole,
    error: Exception,
    ip: str | None,
) -> None:
    """Record a refused send as ``invitation.refuse``, after its transaction rolled back.

    Content-free: the role and which refusal it was, never the email.

    Raises:
        AuditRecordError: If the event can't be recorded.
    """
    reason = "email_taken" if isinstance(error, accounts.DuplicateEmailError) else "seat_limit"
    await audit_events.record(
        pool,
        action=AuditAction.INVITATION_REFUSE,
        actor_kind=actor.kind,
        actor_user_id=actor.user_id,
        org_id=org_id,
        ip=ip,
        metadata={"role": role, reason: True},
    )


async def _lock_org(conn: PoolConnectionProxy, org_id: UUID | None) -> Record:
    """Lock the org row until the transaction ends and return its name and seats.

    Raises:
        OrgNotFoundError: If the org doesn't exist.
    """
    org: Record | None = await conn.fetchrow(_LOCK_ORG_SQL, org_id)
    if org is None:
        raise OrgNotFoundError
    return org


async def _check_free_seat(conn: PoolConnectionProxy, *, org: Record, org_id: UUID | None) -> None:
    """Refuse one more user in a locked org whose active and invited users fill every seat.

    Raises:
        SeatLimitError: If the org has no free seat.
    """
    if await conn.fetchval(_SEATS_TAKEN_SQL, org_id) + 1 > org["seats"]:
        raise SeatLimitError


async def ensure_free_seat(conn: PoolConnectionProxy, org_id: UUID) -> Record:
    """Lock an org row until the transaction ends and check it has a free seat.

    Active and invited users take a seat (an expired invitation keeps its seat
    until it is revoked); deactivated and deleted users don't. The lock makes
    concurrent sends and reactivations count one after the other, so they
    can't both take the last seat.

    Args:
        conn: An asyncpg connection inside the caller's transaction.
        org_id: The organization (a bind parameter).

    Returns:
        The locked org's name and seats.

    Raises:
        OrgNotFoundError: If the org doesn't exist.
        SeatLimitError: If the org has no free seat for one more user.
    """
    org = await _lock_org(conn, org_id)
    await _check_free_seat(conn, org=org, org_id=org_id)
    return org


async def _send(
    conn: PoolConnectionProxy,
    *,
    org: Record,
    org_id: UUID | None,
    actor: Principal | Operator,
    email: str,
    role: MemberRole,
    language: EmailLanguage,
    public_url: str,
    ip: str | None,
    queue_email: bool,
) -> SentInvitation:
    """Send an invitation into a locked org, inside the caller's transaction.

    Checks the seats, inserts the invited users row and the invitation, queues
    the email (unless ``queue_email`` is False) and records
    ``invitation.create`` (see the module docstring).

    Raises:
        SeatLimitError: If the org has no free seat (nothing is inserted).
        DuplicateEmailError: If a user with the email already exists.
    """
    await _check_free_seat(conn, org=org, org_id=org_id)
    try:
        user_id = await conn.fetchval(_INSERT_USER_SQL, email, org_id, role, language)
    except asyncpg.UniqueViolationError:
        # The driver's message repeats the email.
        raise accounts.DuplicateEmailError from None
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    # INSERT ... VALUES ... RETURNING yields exactly one row.
    (invitation,) = await conn.fetch(
        _INSERT_INVITATION_SQL, user_id, _hash_token(token), INVITATION_LIFETIME
    )
    accept_link = _accept_link(public_url, token)
    if queue_email:
        await email_outbox.enqueue_email(
            conn,
            user_id=user_id,
            params=_params(org["name"], accept_link, invitation["expires_at"]),
        )
    actor_kind, actor_user_id = audit_events.actor_columns(actor)
    await audit_events.record(
        conn,
        action=AuditAction.INVITATION_CREATE,
        actor_kind=actor_kind,
        actor_user_id=actor_user_id,
        org_id=org_id,
        target_type=TargetType.INVITATION,
        target_ids=(invitation["id"],),
        ip=ip,
        metadata={"role": role, "user_id": user_id},
    )
    summary = InvitationSummary(
        id=invitation["id"],
        email=email,
        role=role,
        sent_at=invitation["sent_at"],
        expires_at=invitation["expires_at"],
        expired=False,
    )
    return SentInvitation(summary=summary, accept_link=accept_link)


async def create_invitation(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    email: str,
    role: MemberRole,
    language: EmailLanguage,
    public_url: str,
    ip: str | None,
) -> InvitationSummary:
    """Invite an email into the actor's org with a member role.

    Args:
        pool: The database pool.
        actor: The Org Admin sending the invitation (the org is theirs).
        email: The invitee's email (validated by ``InvitationCreateRequest``).
        role: The member role the invitee gets.
        language: The invitee's UI language (the inviting admin's), used for
            the email too.
        public_url: The configured origin the link is built from
            (``server.public_url``), without a trailing slash.
        ip: The client address, if known.

    Returns:
        The new invitation's InvitationSummary.

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_INVITE``; no query is
            issued.
        SeatLimitError: If the org has no free seat; only the
            ``invitation.refuse`` event is written.
        DuplicateEmailError: If a user with the email (in any capitalization)
            already exists; only the ``invitation.refuse`` event is written.
        AuditRecordError: If an audit event can't be recorded; nothing is
            written.
    """
    _require(actor, Capability.ORG_USERS_INVITE)
    try:
        async with pool.acquire() as conn, conn.transaction():
            sent = await _send(
                conn,
                org=await _lock_org(conn, actor.org_id),
                org_id=actor.org_id,
                actor=actor,
                email=email,
                role=role,
                language=language,
                public_url=public_url,
                ip=ip,
                queue_email=True,
            )
    except (accounts.DuplicateEmailError, SeatLimitError) as exc:
        await _record_refusal(pool, actor=actor, org_id=actor.org_id, role=role, error=exc, ip=ip)
        raise
    return sent.summary


async def send_first_admin_invitation(
    conn: PoolConnectionProxy,
    *,
    actor: Principal | Operator,
    org_id: UUID,
    email: str,
    language: EmailLanguage,
    public_url: str,
    ip: str | None,
    queue_email: bool,
) -> SentInvitation:
    """Invite the first user of an org without users, as its Org Admin, on the caller's connection.

    Must run inside the caller's transaction, which also decides the
    authorization (a Super Admin with ``Capability.ORG_CREATE`` or the admin
    CLI's Operator): the org row is locked, the org must have no users row at
    all, and the invitation is sent with ``invitation.create`` recorded by
    ``actor`` in that org's log. Nothing is recorded for a refusal: the
    caller's transaction rolls back.

    Args:
        conn: A connection inside the caller's transaction.
        actor: Who invites: a Super Admin, or the Operator at the terminal.
        org_id: The org to invite into.
        email: The invitee's email.
        language: The invitee's UI language, used for the email too.
        public_url: The configured origin the link is built from.
        ip: The client address, if known.
        queue_email: Whether to queue the invitation email (False: the caller
            hands the returned link over itself).

    Returns:
        The SentInvitation: the InvitationSummary and the one-time accept link.

    Raises:
        OrgNotFoundError: If the org doesn't exist.
        OrgHasUsersError: If the org has any users row (any status, deleted or
            not).
        SeatLimitError, DuplicateEmailError: As for ``create_invitation``.
        AuditRecordError: If the audit event can't be recorded.
    """
    # Locked first: two concurrent first-admin invites can't both see no users.
    org = await _lock_org(conn, org_id)
    if await conn.fetchval(_ORG_HAS_USERS_SQL, org_id):
        raise OrgHasUsersError
    return await _send(
        conn,
        org=org,
        org_id=org_id,
        actor=actor,
        email=email,
        role="org_admin",
        language=language,
        public_url=public_url,
        ip=ip,
        queue_email=queue_email,
    )


async def invite_first_org_admin(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    org_id: UUID,
    email: str,
    language: EmailLanguage,
    public_url: str,
    ip: str | None,
) -> InvitationSummary:
    """Invite the first user of an org without users, always as its Org Admin.

    Audited as ``invitation.create`` by the Super Admin, in that org's log.

    Args:
        pool: The database pool.
        actor: The Super Admin sending the invitation.
        org_id: The org to invite into.
        email: The invitee's email.
        language: The invitee's UI language, used for the email too.
        public_url: The configured origin the link is built from.
        ip: The client address, if known.

    Returns:
        The new invitation's InvitationSummary.

    Raises:
        PermissionError: Without ``Capability.ORG_CREATE``; no query is issued.
        OrgNotFoundError: If the org doesn't exist.
        OrgHasUsersError: If the org has any users row (any status, deleted or
            not); nothing is written.
        SeatLimitError, DuplicateEmailError, AuditRecordError: As for
            ``create_invitation`` (a refusal writes only ``invitation.refuse``).
    """
    _require(actor, Capability.ORG_CREATE)
    try:
        async with pool.acquire() as conn, conn.transaction():
            sent = await send_first_admin_invitation(
                conn,
                actor=actor,
                org_id=org_id,
                email=email,
                language=language,
                public_url=public_url,
                ip=ip,
                queue_email=True,
            )
    except (accounts.DuplicateEmailError, SeatLimitError) as exc:
        await _record_refusal(pool, actor=actor, org_id=org_id, role="org_admin", error=exc, ip=ip)
        raise
    return sent.summary


async def list_invitations(pool: asyncpg.Pool, *, actor: Principal) -> list[InvitationSummary]:
    """Return the pending invitations of the actor's org, the most recently sent first.

    Args:
        pool: The database pool.
        actor: The Org Admin asking.

    Returns:
        One InvitationSummary per pending invitation, expired ones included
        (flagged ``expired``).

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_VIEW``; no query is
            issued.
    """
    _require(actor, Capability.ORG_USERS_VIEW)
    rows = await pool.fetch(_LIST_SQL, actor.org_id)
    return [
        InvitationSummary(
            id=row["id"],
            email=row["email"],
            role=row["role"],
            sent_at=row["sent_at"],
            expires_at=row["expires_at"],
            expired=row["expired"],
        )
        for row in rows
    ]


async def revoke_invitation(
    pool: asyncpg.Pool, *, actor: Principal, invitation_id: UUID, ip: str | None
) -> None:
    """Revoke a pending invitation of the actor's org by deleting the invited account.

    Args:
        pool: The database pool.
        actor: The Org Admin revoking it.
        invitation_id: The invitation to revoke (expired ones included).
        ip: The client address, if known.

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_INVITE``; no query is
            issued.
        InvitationNotFoundError: If it isn't a pending invitation of the
            actor's org; nothing is deleted or audited.
        AuditRecordError: If the audit event can't be recorded; nothing is
            deleted.
    """
    _require(actor, Capability.ORG_USERS_INVITE)
    async with pool.acquire() as conn, conn.transaction():
        user_id = await conn.fetchval(_REVOKE_SQL, invitation_id, actor.org_id)
        if user_id is None:
            raise InvitationNotFoundError
        await audit_events.record(
            conn,
            action=AuditAction.INVITATION_REVOKE,
            actor_kind=actor.kind,
            actor_user_id=actor.user_id,
            org_id=actor.org_id,
            target_type=TargetType.INVITATION,
            target_ids=(invitation_id,),
            ip=ip,
            metadata={"user_id": user_id},
        )


async def resend_invitation(
    pool: asyncpg.Pool,
    *,
    actor: Principal,
    invitation_id: UUID,
    public_url: str,
    ip: str | None,
) -> InvitationSummary:
    """Send a pending invitation of the actor's org again, with a new link.

    The token is rotated (the old link stops working), ``sent_at`` becomes now
    and ``expires_at`` 72 hours later; no free seat is needed.

    Args:
        pool: The database pool.
        actor: The Org Admin resending it.
        invitation_id: The invitation to resend (expired ones included).
        public_url: The configured origin the link is built from.
        ip: The client address, if known.

    Returns:
        The invitation's InvitationSummary with the new dates.

    Raises:
        PermissionError: Without ``Capability.ORG_USERS_INVITE``; no query is
            issued.
        InvitationNotFoundError: If it isn't a pending invitation of the
            actor's org; nothing changes.
        AuditRecordError: If the audit event can't be recorded; nothing
            changes and the old link keeps working.
    """
    _require(actor, Capability.ORG_USERS_INVITE)
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    async with pool.acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            _RESEND_SQL, _hash_token(token), INVITATION_LIFETIME, invitation_id, actor.org_id
        )
        if row is None:
            raise InvitationNotFoundError
        # The old link no longer works: its still-queued email must not go out.
        await email_outbox.cancel_pending(
            conn, user_id=row["user_id"], template=EmailTemplate.INVITATION
        )
        await email_outbox.enqueue_email(
            conn,
            user_id=row["user_id"],
            params=_params(row["org_name"], _accept_link(public_url, token), row["expires_at"]),
        )
        await audit_events.record(
            conn,
            action=AuditAction.INVITATION_RESEND,
            actor_kind=actor.kind,
            actor_user_id=actor.user_id,
            org_id=actor.org_id,
            target_type=TargetType.INVITATION,
            target_ids=(row["id"],),
            ip=ip,
            metadata={"role": row["role"], "user_id": row["user_id"]},
        )
    return InvitationSummary(
        id=row["id"],
        email=row["email"],
        role=row["role"],
        sent_at=row["sent_at"],
        expires_at=row["expires_at"],
        expired=False,
    )


async def get_invitation(pool: asyncpg.Pool, token: str) -> InvitationDetails:
    """Return what the acceptance page shows for a usable invitation link.

    Args:
        pool: The database pool.
        token: The token from the link.

    Returns:
        The InvitationDetails: the org name, the role and the email.

    Raises:
        InvalidInvitationError: If the link can't be used (a malformed token
            is refused without a query).
    """
    if not _is_plausible_token(token):
        raise InvalidInvitationError
    row = await pool.fetchrow(_LOOKUP_SQL, _hash_token(token))
    if row is None:
        raise InvalidInvitationError
    return InvitationDetails(org_name=row["org_name"], role=row["role"], email=row["email"])


async def accept_invitation(
    pool: asyncpg.Pool,
    *,
    token: str,
    name: str,
    password: str,
    ip: str | None,
    user_agent: str | None,
) -> auth.LoginResult:
    """Accept an invitation: activate the account and open a session.

    Args:
        pool: The database pool.
        token: The token from the link.
        name: The invitee's display name (validated by
            ``InvitationAcceptRequest``).
        password: The chosen password.
        ip: The client address, if known.
        user_agent: The client's User-Agent header, if any.

    Returns:
        The LoginResult: the raw session token, for the session cookie, and
        the cookie's Max-Age (the org session policy's lifetime, in seconds).

    Raises:
        InvalidInvitationError: If the link can't be used, also when it is
            used, rotated, revoked or expires concurrently, or the account
            stops being invited; nothing is written.
        PasswordPolicyError: If the policy refuses the password; nothing is
            written and the link stays usable.
        AuditRecordError: If the audit event can't be recorded; nothing is
            written and the link stays usable.
    """
    if not _is_plausible_token(token):
        raise InvalidInvitationError
    token_hash = _hash_token(token)
    row = await pool.fetchrow(_LOOKUP_SQL, token_hash)
    if row is None:
        raise InvalidInvitationError
    passwords.check_password_policy(password, email=row["email"])
    new_hash = await asyncio.to_thread(passwords.hash_password, password)

    user_id = row["user_id"]
    policy = await scoped_settings.session_policy_for(pool, "member")
    async with pool.acquire() as conn, conn.transaction():
        invitation_id = await conn.fetchval(_MARK_ACCEPTED_SQL, token_hash)
        if invitation_id is None:
            raise InvalidInvitationError
        if await conn.fetchval(_ACTIVATE_SQL, name, new_hash, user_id) is None:
            raise InvalidInvitationError
        session_token = await sessions.create_session(
            conn, user_id=user_id, policy=policy, ip=ip, user_agent=user_agent
        )
        await audit_events.record(
            conn,
            action=AuditAction.INVITATION_ACCEPT,
            actor_kind="member",
            actor_user_id=user_id,
            org_id=row["org_id"],
            target_type=TargetType.INVITATION,
            target_ids=(invitation_id,),
            ip=ip,
            metadata={"role": row["role"]},
        )
    return auth.LoginResult(
        token=session_token, max_age_seconds=int(policy.max_lifetime.total_seconds())
    )
