"""Email/password login and logout (GH-149, GH-152, GH-157).

Inputs: the database pool, plus the email, password, client IP and user agent
of a login attempt, or the raw session token of a logout.
Outputs: ``login`` returns a ``LoginResult`` (the raw session token for the
``admino_session`` cookie and the cookie's Max-Age), or raises
``LoginFailedError``; ``logout`` deletes the session.

Every attempt first goes through the brute-force protection
(``admino.login_throttle``, GH-157): the account (the typed email) and the
client IP each count one failure before the password is checked, and from the
third failure in 15 minutes the attempt waits (1, 2, 4, then 8 seconds). A
locked account or IP (10 failures in 15 minutes lock it for 15 minutes) is
refused without checking the password, with the same ``LoginFailedError``,
and records ``login.failure`` with ``{"locked": true}``.

A login succeeds when the account exists, the password matches, the user is
active and not deleted, and the user is a Super Admin or a member of an active
organization. It then re-hashes a password stored with older Argon2
parameters, stamps ``last_login_at``, opens a session with the account's
session policy (``sessions.session_policy_for``: the org policy for a member,
the platform policy for a Super Admin), resets the account's failure count,
releases its own IP reservation and records ``login.success``, all in one
transaction. Every other outcome records ``login.failure`` and raises the
same ``LoginFailedError``; the 10th failure then locks the account and/or the
IP and records a ``login.lockout`` per lock (account first, then IP).

Security notes:
- No user enumeration: one message ("Invalid email or password") for every
  failure cause, a lockout included, and exactly one Argon2 verification on
  every unlocked path. Without an account or a stored hash, the password is
  checked against a dummy hash with the current parameters, so the check
  costs the same. The account's status is only decided after the
  verification. The throttle counts, delays and locks a known and an unknown
  email alike.
- Fail closed: if the failure counters can't be written, the password is
  never checked; an error after the reservation leaves the failure counted.
- Argon2 is CPU-bound (~200 ms): it runs in a worker thread
  (``asyncio.to_thread``) so logins don't stall the event loop.
- Content-free audit (tracker #139 §5): the events carry the actor's kind,
  user id and org (a ``system`` actor for an unknown email) and the client
  IP. Neither the email nor the password reaches an audit row, another
  statement or a log line; the email is only a bind parameter of the lookup
  and of the throttle's account digest (computed by the database).
- A failed ``login.success`` record rolls the session back (and the counter
  reset with it), so no session is handed out unaudited.
- ``LoginResult`` keeps the token out of its repr, so it can't end up in a
  log line or traceback.
- Parameterized SQL only: values travel as bind parameters.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field

from admino import audit_events, login_throttle, passwords, sessions
from admino.audit_events import AuditAction

if TYPE_CHECKING:
    from uuid import UUID

    import asyncpg

    from admino.audit_events import ActorKind

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


class LoginResult(BaseModel):
    """A successful login: the session token and how long its cookie may live."""

    model_config = ConfigDict(frozen=True)

    # repr=False: never shown by repr() or str().
    token: str = Field(repr=False)
    max_age_seconds: int


class LoginFailedError(Exception):
    """Raised for every failed login, whatever the cause; carries no input."""

    def __init__(self) -> None:
        super().__init__(LOGIN_FAILED_MESSAGE)


def _actor(account: Any) -> tuple[ActorKind, UUID | None, UUID | None]:
    """The audit actor columns of an attempt: the account's, or ``system`` for none.

    Args:
        account: The lookup's users row, or None for an unknown email.

    Returns:
        (actor kind, actor user id, org id).
    """
    if account is None:
        return "system", None, None
    return account["kind"], account["id"], account["org_id"]


def may_log_in(account: Any) -> bool:
    """True when an existing account may open a session (the password aside).

    The account must be active and not deleted, and be a Super Admin or a
    member of an active org. ``admino.password_reset`` applies the same rule.

    Args:
        account: A users row with ``status``, ``deleted_at``, ``kind`` and the
            org's status as ``org_status``.
    """
    if account["status"] != "active" or account["deleted_at"] is not None:
        return False
    return bool(
        account["kind"] == "super_admin"
        or (account["kind"] == "member" and account["org_status"] == "active")
    )


async def login(
    pool: asyncpg.Pool, *, email: str, password: str, ip: str | None, user_agent: str | None
) -> LoginResult:
    """Check an email and password and open a session with the account's policy.

    Args:
        pool: The database pool.
        email: The email the user typed (matched case-insensitively).
        password: The password the user typed.
        ip: The client address, if known.
        user_agent: The client's User-Agent header, if any.

    Returns:
        The LoginResult: the raw session token, for the session cookie, and
        the cookie's Max-Age (the policy's lifetime, in seconds).

    Raises:
        LoginFailedError: For every failure (unknown email, wrong password, an
            invited, deactivated or deleted user, a user of an inactive org, a
            locked account or IP).
        AuditRecordError: If an audit event can't be recorded; no session is
            opened.
        asyncpg.PostgresError: If the failure counters can't be written; the
            password is not checked.
    """
    account = await pool.fetchrow(_LOOKUP_SQL, email)
    actor_kind, actor_user_id, org_id = _actor(account)
    # Counts this attempt as a failure until it succeeds, and waits out the
    # delay, before the password is checked.
    attempt = await login_throttle.begin(pool, email=email, ip=ip)
    if attempt.locked:
        await audit_events.record(
            pool,
            action=AuditAction.LOGIN_FAILURE,
            actor_kind=actor_kind,
            actor_user_id=actor_user_id,
            org_id=org_id,
            ip=ip,
            metadata={"locked": True},
        )
        raise LoginFailedError

    stored_hash = None if account is None else account["password_hash"]
    matches = await asyncio.to_thread(
        passwords.verify_password, password, stored_hash or _DUMMY_HASH
    )
    if account is None or not stored_hash or not matches or not may_log_in(account):
        await audit_events.record(
            pool,
            action=AuditAction.LOGIN_FAILURE,
            actor_kind=actor_kind,
            actor_user_id=actor_user_id,
            org_id=org_id,
            ip=ip,
        )
        await login_throttle.fail(
            pool,
            attempt,
            ip=ip,
            actor_kind=actor_kind,
            actor_user_id=actor_user_id,
            org_id=org_id,
        )
        raise LoginFailedError

    user_id = account["id"]
    policy = sessions.session_policy_for(account["kind"])
    new_hash = None
    if passwords.needs_rehash(stored_hash):
        new_hash = await asyncio.to_thread(passwords.hash_password, password)
    async with pool.acquire() as conn, conn.transaction():
        if new_hash is not None:
            await conn.execute(_REHASH_SQL, new_hash, user_id)
        await conn.execute(_LAST_LOGIN_SQL, user_id)
        token = await sessions.create_session(
            conn, user_id=user_id, policy=policy, ip=ip, user_agent=user_agent
        )
        await login_throttle.succeed(conn, attempt)
        await audit_events.record(
            conn,
            action=AuditAction.LOGIN_SUCCESS,
            actor_kind=account["kind"],
            actor_user_id=user_id,
            org_id=account["org_id"],
            ip=ip,
        )
    return LoginResult(token=token, max_age_seconds=int(policy.max_lifetime.total_seconds()))


async def logout(pool: asyncpg.Pool, token: str) -> None:
    """End the session behind a session token by deleting its row.

    Args:
        pool: The database pool.
        token: The raw token from the session cookie.
    """
    await sessions.revoke_session(pool, token)
