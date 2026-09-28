"""Session management: list and end your own sessions, force a user's logout (GH-152).

A user sees their live sessions (``list_user_sessions``) and can end any one
of them, the current one included (``revoke_own_session``). An Org Admin can
log a user of their org out of every device (``force_logout``). Ending a
session deletes its row (``admino.sessions``), so the cookie stops working on
its next request.

Inputs: a database executor or the pool, plus the user id and current
session id of the caller (the list); the caller's ``Principal``, a session id
and the client IP (ending one's own session); the acting ``Principal``, the
target user id and the client IP (a forced logout).
Outputs: a list of ``models.SessionSummary`` (the list); None, or
``SessionNotFoundError`` (ending one's own session); the number of sessions
deleted, ``PermissionError`` or ``accounts.UserNotInOrgError`` (a forced
logout). Ending a session records ``session.revoke``, a forced logout
``session.force_logout``.

Security notes:
- Tenant isolation at the data layer: every statement is scoped by the
  caller's user id or the actor's org id. Another user's session is "not
  found", like an unknown id, and so is a user of another org, a deleted user
  or a Super Admin for a forced logout (the routes answer 404, never 403), so
  existence isn't revealed.
- A forced logout needs ``Capability.ORG_USERS_MANAGE`` (``access.can``); it
  is checked before any query.
- The list never reads token hashes; errors carry no IDs; nothing is logged.
- Content-free audit (tracker #139 §5): the actor, their org, the target user,
  the client IP, and a session id or a count.
- Fail closed: the deletion and its audit event share one transaction, so a
  failed audit write rolls the deletion back.
- Parameterized SQL only: values travel as bind parameters.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from admino import accounts, audit_events, sessions
from admino.access import Capability, can
from admino.audit_events import AuditAction, TargetType
from admino.models import SessionSummary

if TYPE_CHECKING:
    from uuid import UUID

    import asyncpg

    from admino.access import Principal

SESSION_NOT_FOUND_MESSAGE: Final = "Session not found"

# Live sessions only: the rows the purge job hasn't deleted yet are left out.
_LIST_SQL: Final = """
    SELECT id, created_at, last_seen_at, expires_at, ip, user_agent
    FROM sessions
    WHERE user_id = $1
      AND expires_at > now()
      AND last_seen_at + make_interval(mins => idle_timeout_minutes) > now()
    ORDER BY last_seen_at DESC
"""

# Ownership is part of the statement: another user's session matches nothing.
_REVOKE_OWN_SQL: Final = """
    DELETE FROM sessions
    WHERE id = $1 AND user_id = $2
    RETURNING id
"""

# A user of the actor's org that isn't deleted (a Super Admin has no org).
_ORG_USER_SQL: Final = """
    SELECT id FROM users
    WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
"""


class SessionNotFoundError(Exception):
    """Raised when the session isn't one of the caller's; carries no IDs."""

    def __init__(self) -> None:
        super().__init__(SESSION_NOT_FOUND_MESSAGE)


async def list_user_sessions(
    executor: asyncpg.Pool | asyncpg.Connection,
    *,
    user_id: UUID,
    current_session_id: UUID | None,
) -> list[SessionSummary]:
    """Return a user's live sessions, the most recently active first.

    Args:
        executor: The pool or a connection.
        user_id: The user whose sessions are listed (the only bind parameter).
        current_session_id: The session of the request, marked ``current``.

    Returns:
        One SessionSummary per session that is neither expired nor idle.
    """
    rows = await executor.fetch(_LIST_SQL, user_id)
    return [
        SessionSummary(
            id=row["id"],
            created_at=row["created_at"],
            last_seen_at=row["last_seen_at"],
            expires_at=row["expires_at"],
            # asyncpg returns INET as an ipaddress object.
            ip=None if row["ip"] is None else str(row["ip"]),
            user_agent=row["user_agent"],
            current=row["id"] == current_session_id,
        )
        for row in rows
    ]


async def revoke_own_session(
    pool: asyncpg.Pool, *, principal: Principal, session_id: UUID, ip: str | None
) -> None:
    """End one of the caller's own sessions and record ``session.revoke``.

    Args:
        pool: The database pool.
        principal: The caller.
        session_id: The session to end (may be the request's own).
        ip: The client address, if known.

    Raises:
        SessionNotFoundError: If the session doesn't exist or isn't the
            caller's; nothing is deleted or audited.
        AuditRecordError: If the audit event can't be recorded; the session
            isn't deleted.
    """
    async with pool.acquire() as conn, conn.transaction():
        if await conn.fetchval(_REVOKE_OWN_SQL, session_id, principal.user_id) is None:
            raise SessionNotFoundError
        await audit_events.record(
            conn,
            action=AuditAction.SESSION_REVOKE,
            actor_kind=principal.kind,
            actor_user_id=principal.user_id,
            org_id=principal.org_id,
            target_type=TargetType.USER,
            target_ids=(principal.user_id,),
            ip=ip,
            metadata={"session_id": session_id},
        )


async def force_logout(
    pool: asyncpg.Pool, *, actor: Principal, user_id: UUID, ip: str | None
) -> int:
    """End every session of a user of the actor's org and record ``session.force_logout``.

    Args:
        pool: The database pool.
        actor: The Org Admin forcing the logout.
        user_id: The user to log out (the actor themselves included).
        ip: The client address, if known.

    Returns:
        The number of sessions deleted (0 is audited too).

    Raises:
        PermissionError: If the actor lacks ``Capability.ORG_USERS_MANAGE``;
            no query is issued.
        UserNotInOrgError: If the user isn't a (non-deleted) member of the
            actor's org; nothing is deleted or audited.
        AuditRecordError: If the audit event can't be recorded; no session is
            deleted.
    """
    if not can(actor, Capability.ORG_USERS_MANAGE):
        msg = "Forbidden"
        raise PermissionError(msg)
    async with pool.acquire() as conn, conn.transaction():
        if await conn.fetchval(_ORG_USER_SQL, user_id, actor.org_id) is None:
            raise accounts.UserNotInOrgError
        revoked = await sessions.revoke_user_sessions(conn, user_id)
        await audit_events.record(
            conn,
            action=AuditAction.SESSION_FORCE_LOGOUT,
            actor_kind=actor.kind,
            actor_user_id=actor.user_id,
            org_id=actor.org_id,
            target_type=TargetType.USER,
            target_ids=(user_id,),
            ip=ip,
            metadata={"sessions_revoked": revoked},
        )
    return revoked
