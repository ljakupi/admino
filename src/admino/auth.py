"""Email/password login and logout (GH-149).

Inputs: the database pool, plus the email, password, client IP and user agent
of a login attempt, or the raw session token of a logout.
Outputs: ``login`` returns the raw session token for the ``admino_session``
cookie, or raises ``LoginFailedError``; ``logout`` revokes the session.

A login succeeds when the account exists, the password matches, the user is
active and not deleted, and the user is a Super Admin or a member of an active
organization. It then re-hashes a password stored with older Argon2
parameters, stamps ``last_login_at``, opens a session and records
``login.success``, all in one transaction. Every other outcome records
``login.failure`` and raises the same ``LoginFailedError``.

Security notes:
- No user enumeration: one message ("Invalid email or password") for every
  failure cause, and exactly one Argon2 verification on every path. Without
  an account or a stored hash, the password is checked against a dummy hash
  with the current parameters, so the check costs the same. The account's
  status is only decided after the verification.
- Argon2 is CPU-bound (~200 ms): it runs in a worker thread
  (``asyncio.to_thread``) so logins don't stall the event loop.
- Content-free audit (tracker #139 §5): the events carry the actor's kind,
  user id and org (a ``system`` actor for an unknown email) and the client
  IP. Neither the email nor the password reaches an audit row, another
  statement or a log line; the email is only the lookup's bind parameter.
- Fail closed: a failed ``login.success`` record rolls the session back, so
  no session is handed out unaudited.
- Parameterized SQL only: values travel as bind parameters.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import TYPE_CHECKING, Any, Final

from admino import audit_events, passwords, sessions
from admino.audit_events import AuditAction

if TYPE_CHECKING:
    import asyncpg

LOGIN_FAILED_MESSAGE: Final = "Invalid email or password"

# Case-insensitive, matching the users_email_lower_key unique index. LEFT JOIN:
# a Super Admin belongs to no organization.
_LOOKUP_SQL: Final = """
    SELECT u.id, u.kind, u.org_id, u.role, u.status, u.deleted_at, u.password_hash,
           o.status AS org_status
    FROM users u
    LEFT JOIN organizations o ON o.id = u.org_id
    WHERE lower(u.email) = lower($1)
"""
_REHASH_SQL: Final = "UPDATE users SET password_hash = $1 WHERE id = $2"
_LAST_LOGIN_SQL: Final = "UPDATE users SET last_login_at = now() WHERE id = $1"

# Verified when there is no account or no stored hash: the current parameters,
# so the check costs what a real one costs. Its digest is random, so no
# password matches it.
_DUMMY_HASH: Final = passwords.encode_phc(
    memory_cost=passwords.ARGON2_MEMORY_COST_KIB,
    iterations=passwords.ARGON2_ITERATIONS,
    lanes=passwords.ARGON2_LANES,
    salt=secrets.token_bytes(passwords.ARGON2_SALT_BYTES),
    digest=secrets.token_bytes(passwords.ARGON2_HASH_BYTES),
)


class LoginFailedError(Exception):
    """Raised for every failed login, whatever the cause; carries no input."""

    def __init__(self) -> None:
        super().__init__(LOGIN_FAILED_MESSAGE)


def _may_log_in(account: Any) -> bool:
    """True when an existing account may open a session (the password aside)."""
    if account["status"] != "active" or account["deleted_at"] is not None:
        return False
    return bool(
        account["kind"] == "super_admin"
        or (account["kind"] == "member" and account["org_status"] == "active")
    )


async def login(
    pool: asyncpg.Pool, *, email: str, password: str, ip: str | None, user_agent: str | None
) -> str:
    """Check an email and password and open a session.

    Args:
        pool: The database pool.
        email: The email the user typed (matched case-insensitively).
        password: The password the user typed.
        ip: The client address, if known.
        user_agent: The client's User-Agent header, if any.

    Returns:
        The raw session token, for the session cookie.

    Raises:
        LoginFailedError: For every failure (unknown email, wrong password, an
            invited, deactivated or deleted user, a user of an inactive org).
        AuditRecordError: If the audit event can't be recorded; no session is
            opened.
    """
    account = await pool.fetchrow(_LOOKUP_SQL, email)
    stored_hash = None if account is None else account["password_hash"]
    matches = await asyncio.to_thread(
        passwords.verify_password, password, stored_hash or _DUMMY_HASH
    )
    if account is None or not stored_hash or not matches or not _may_log_in(account):
        await audit_events.record(
            pool,
            action=AuditAction.LOGIN_FAILURE,
            actor_kind="system" if account is None else account["kind"],
            actor_user_id=None if account is None else account["id"],
            org_id=None if account is None else account["org_id"],
            ip=ip,
        )
        raise LoginFailedError

    user_id = account["id"]
    new_hash = None
    if passwords.needs_rehash(stored_hash):
        new_hash = await asyncio.to_thread(passwords.hash_password, password)
    async with pool.acquire() as conn, conn.transaction():
        if new_hash is not None:
            await conn.execute(_REHASH_SQL, new_hash, user_id)
        await conn.execute(_LAST_LOGIN_SQL, user_id)
        token = await sessions.create_session(conn, user_id=user_id, ip=ip, user_agent=user_agent)
        await audit_events.record(
            conn,
            action=AuditAction.LOGIN_SUCCESS,
            actor_kind=account["kind"],
            actor_user_id=user_id,
            org_id=account["org_id"],
            ip=ip,
        )
    return token


async def logout(pool: asyncpg.Pool, token: str) -> None:
    """Revoke the session behind a session token.

    Args:
        pool: The database pool.
        token: The raw token from the session cookie.
    """
    await sessions.revoke_session(pool, token)
