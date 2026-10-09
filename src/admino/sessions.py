"""Server-side login sessions and their policies, and the one place a ``Principal`` is built.

A login creates a ``sessions`` row (migrations 0007 and 0009) holding the
SHA-256 hash of a random 256-bit token; the raw token only lives in the
``admino_session`` cookie. Every request resolves the cookie back to its
session, re-reading the user's row, and builds the ``Principal`` from that row
(GH-149).

Session policies (GH-152): a session ends after an idle timeout (15 to 480
minutes, default 60) or at the end of its lifetime (1 to 72 hours, default
12), whichever comes first. A member gets their org's policy stored in
``org_settings`` (GH-169), a Super Admin the platform policy stored in
``platform_settings`` (GH-160); ``scoped_settings.session_policy_for`` picks
a kind's policy. Each row stores its own idle timeout and expiry, set at
login. A changed org policy re-times the org's live sessions
(``apply_org_policy``), a changed platform policy every open Super Admin
session (``apply_super_admin_policy``). Ending a session deletes its row, and
a background job purges the rows that expired or went idle.

The OAuth callback (GH-162) re-resolves the session that started an
authorization by its row id (``resolve_session_by_id``): the same checks as
the token lookup, but it never touches ``last_seen_at``.

An approval (GH-298) re-reads its caller's account under its chat's hold
(``recheck_principal``): the account rules of the session lookup, applied to
the users row as it is now, so a change made while the approval waited
refuses it.

Inputs: a database executor (the pool or a connection) plus a raw session
token or (the OAuth callback) a session id, or a member's Principal to
re-check; the user id, policy, client IP and user agent of a new session;
the user or org whose sessions all end; the new Super Admin policy, or an
org and its new policy.
Outputs: the raw token of a new session (``create_session``), the
``AuthenticatedSession`` of a usable session or None (``resolve_session``,
``resolve_session_by_id``), the account's current Principal or None
(``recheck_principal``), nothing (``revoke_session``), the number of rows deleted
(``revoke_user_sessions``, ``revoke_org_sessions``,
``purge_expired_sessions``) or re-timed (``apply_super_admin_policy``,
``apply_org_policy``).

Security notes:
- The one Principal builder: this is the only module that builds an
  ``access.Principal`` (tests/test_access.py allowlists it), and it builds it
  from a users row only, never from request data.
  ``resolve_session`` takes nothing but the executor and the token,
  ``resolve_session_by_id`` nothing but the executor and the session id
  (which the OAuth state binding stored server-side, never a request value),
  ``recheck_principal`` nothing but the executor and a Principal this module
  built (its user id and org id are the binds).
- The re-check (GH-298) is one read of the users row within the principal's
  org, with the org's status, and writes nothing. It fails closed: a missing
  row, a user that isn't active or is deleted, a row that isn't a member's,
  an org that isn't active, an invalid Principal or another user, kind or
  org is None.
- Re-checked on every request: one query re-reads the session, the user and
  the org, and the decision is made here on each call. A deleted, expired or
  idle session (past the row's own timeout), a user that isn't active or is
  deleted, or a member of an org that isn't active (deactivated, pending
  deletion) resolves to None at once.
- Fail closed: a row with malformed timestamps or idle timeout, or one that
  fails Principal validation, resolves to None.
- ``last_seen_at`` is written at most once a minute per session, keyed by the
  session id, and only for a session that resolved through its token; the
  lookup by id writes nothing (the OAuth redirect can't keep a session alive).
- The expiry is computed on the database clock (``now() + $n::interval``),
  like ``created_at``, so the 72-hour CHECK of migration 0009 holds exactly.
  The policy bounds mirror that migration's CHECKs.
- A Super Admin policy change applies at once: the expiry becomes
  ``created_at`` plus the new lifetime, so a session older than it, or idle
  past the new timeout, stops resolving. Members' sessions are never touched.
- An org policy change (GH-169) applies the same way to the live sessions of
  that org's users only, the org a bind parameter: never another org's or a
  Super Admin's. A session that had already ended (expired, or idle past its
  old timeout) but isn't purged yet is left alone, so a longer policy never
  revives it.
- Only the token's hash is stored or queried; the raw token is never logged
  and never sent to the database. A token that can't be a
  ``secrets.token_urlsafe(32)`` value is refused without a query. Logs carry
  no token, hash, ID, IP or user agent (a failed purge: the class name only).
- Parameterized SQL only: values travel as bind parameters.
- Imports nothing from the server, agent, LLM, tools or OAuth layers.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import secrets
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol

from pydantic import Field, StrictInt, ValidationError

from admino.access import PlainUUID, Principal, SealedModel

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME: Final = "admino_session"
USER_AGENT_MAX_LENGTH: Final = 256

# Session policy bounds and defaults (mirrored by migration 0009's CHECKs).
MIN_IDLE_TIMEOUT_MINUTES: Final = 15
MAX_IDLE_TIMEOUT_MINUTES: Final = 480
DEFAULT_IDLE_TIMEOUT_MINUTES: Final = 60
MIN_LIFETIME_HOURS: Final = 1
MAX_LIFETIME_HOURS: Final = 72
DEFAULT_LIFETIME_HOURS: Final = 12

# last_seen_at is written at most this often per session.
LAST_SEEN_UPDATE_INTERVAL: Final = timedelta(minutes=1)
# Seconds between two runs of the expired-session purge.
PURGE_INTERVAL_SECONDS: Final = 3600

_TOKEN_BYTES: Final = 32  # 256 bits
# What secrets.token_urlsafe(32) produces: 43 URL-safe base64 characters.
_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9_-]{43}")

# The expiry is computed on the database clock, like created_at.
_INSERT_SQL: Final = """
    INSERT INTO sessions (token_hash, user_id, expires_at, idle_timeout_minutes, ip, user_agent)
    VALUES ($1, $2, now() + $3::interval, $4, $5::inet, $6)
"""

# A session with its user and org. LEFT JOIN: a Super Admin belongs to no organization.
_RESOLVE_SELECT: Final = """
    SELECT s.id AS session_id,
           s.expires_at,
           s.last_seen_at,
           s.idle_timeout_minutes,
           u.id AS user_id,
           u.kind,
           u.org_id,
           u.role,
           u.status,
           u.deleted_at,
           u.ui_language,
           u.response_language,
           o.status AS org_status
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    LEFT JOIN organizations o ON o.id = u.org_id
"""
_RESOLVE_SQL: Final = _RESOLVE_SELECT + "    WHERE s.token_hash = $1\n"
# GH-162: the OAuth callback re-resolves the initiating session by its row id.
_RESOLVE_BY_ID_SQL: Final = _RESOLVE_SELECT + "    WHERE s.id = $1\n"

_TOUCH_SQL: Final = "UPDATE sessions SET last_seen_at = now() WHERE id = $1"

# GH-298: an approval re-reads its caller's account, with the org's status, under
# the chat's hold. Bound to the request principal's org too: an account no longer in
# it has no row.
_ACCOUNT_SQL: Final = """
    SELECT u.id AS user_id, u.kind, u.org_id, u.role, u.status, u.deleted_at,
           o.status AS org_status
    FROM users u
    JOIN organizations o ON o.id = u.org_id
    WHERE u.id = $1 AND u.org_id = $2
"""

_REVOKE_SQL: Final = "DELETE FROM sessions WHERE token_hash = $1"

# Every session of one user (a password change, a forced logout, a deactivation).
_REVOKE_USER_SQL: Final = "DELETE FROM sessions WHERE user_id = $1"

# Every session of an org's users (an org deactivation).
_REVOKE_ORG_SQL: Final = """
    DELETE FROM sessions
    WHERE user_id IN (SELECT id FROM users WHERE org_id = $1)
"""

# Every open Super Admin session takes the new platform policy (GH-160). The
# expiry counts from the session's start, so an old one ends at once.
_SUPER_ADMIN_POLICY_SQL: Final = """
    UPDATE sessions
    SET idle_timeout_minutes = $1,
        expires_at = created_at + make_interval(hours => $2)
    WHERE user_id IN (SELECT id FROM users WHERE kind = 'super_admin')
"""

# GH-169: every LIVE session of one org's users takes the org's new policy.
# The live predicates read the old row values, so a session that had already
# ended (not purged yet) is never re-timed back to life.
_ORG_POLICY_SQL: Final = """
    UPDATE sessions
    SET idle_timeout_minutes = $2,
        expires_at = created_at + make_interval(hours => $3)
    WHERE user_id IN (SELECT id FROM users WHERE org_id = $1)
      AND expires_at > now()
      AND last_seen_at + make_interval(mins => idle_timeout_minutes) > now()
"""

# The same boundaries resolve_session applies: "<=" means gone.
_PURGE_SQL: Final = """
    DELETE FROM sessions
    WHERE expires_at <= now()
       OR last_seen_at + make_interval(mins => idle_timeout_minutes) <= now()
"""


class Executor(Protocol):
    """What the session functions run through: an asyncpg pool or connection."""

    async def execute(self, query: str, *args: object) -> str:
        """Run one statement with bind parameters."""
        ...

    # Any: asyncpg returns an untyped Record (or None).
    async def fetchrow(self, query: str, *args: object) -> Any:
        """Run one query and return its first row, or None."""
        ...


class SessionPolicy(SealedModel):
    """How long a session may stay idle, and how long it may live at most."""

    idle_timeout_minutes: StrictInt = Field(
        default=DEFAULT_IDLE_TIMEOUT_MINUTES,
        ge=MIN_IDLE_TIMEOUT_MINUTES,
        le=MAX_IDLE_TIMEOUT_MINUTES,
    )
    max_lifetime_hours: StrictInt = Field(
        default=DEFAULT_LIFETIME_HOURS, ge=MIN_LIFETIME_HOURS, le=MAX_LIFETIME_HOURS
    )

    @property
    def idle_timeout(self) -> timedelta:
        """The idle timeout as a timedelta."""
        return timedelta(minutes=self.idle_timeout_minutes)

    @property
    def max_lifetime(self) -> timedelta:
        """The maximum lifetime as a timedelta."""
        return timedelta(hours=self.max_lifetime_hours)


class AuthenticatedSession(SealedModel):
    """A resolved, usable session: who is logged in and their languages."""

    session_id: PlainUUID
    principal: Principal
    ui_language: Literal["de", "fr", "en"]
    response_language: Literal["de", "fr", "it", "en"] | None


def new_session_token() -> str:
    """Return a fresh random session token (256 bits, 43 URL-safe characters)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_session_token(token: str) -> bytes:
    """Return the 32-byte SHA-256 digest of a token: what the database stores."""
    return hashlib.sha256(token.encode()).digest()


def _is_plausible_token(token: object) -> bool:
    """True when ``token`` could be a ``secrets.token_urlsafe(32)`` value."""
    return isinstance(token, str) and _TOKEN_RE.fullmatch(token) is not None


def _is_aware(value: object) -> bool:
    """True when ``value`` is a timezone-aware datetime."""
    return isinstance(value, datetime) and value.tzinfo is not None


def _row_count(status: str) -> int:
    """The row count of asyncpg's status string ("DELETE <count>", "UPDATE <count>")."""
    return int(status.rpartition(" ")[2])


def _client_ip(ip: str | None) -> IPv4Address | IPv6Address | None:
    """Parse the client IP; a peer that isn't an IP address (e.g. 'testclient') is None.

    The address is rebuilt from its packed bytes, which drops an IPv6 scope ID.
    """
    if not ip:
        return None
    try:
        return ip_address(ip_address(ip).packed)
    except ValueError:
        return None


# Any: asyncpg returns an untyped Record.
def _active_account(row: Any) -> bool:
    """True when a row's user is active and not deleted, and a member's org is active.

    The account rules session resolution and ``recheck_principal`` share.
    """
    if row["status"] != "active" or row["deleted_at"] is not None:
        return False
    return not (row["kind"] == "member" and row["org_status"] != "active")


# Any: asyncpg returns an untyped Record.
def _row_principal(row: Any) -> Principal:
    """Build the Principal of a users row; raises ``ValidationError`` when it isn't one."""
    return Principal(
        user_id=row["user_id"], kind=row["kind"], org_id=row["org_id"], role=row["role"]
    )


# Any: asyncpg returns an untyped Record (or None).
def _usable_session(row: Any, now: datetime) -> AuthenticatedSession | None:
    """Build the AuthenticatedSession of a resolve row, or None when it isn't usable.

    The one decision both lookups share: None for a missing row, malformed
    timestamps or idle timeout, an expired session or one idle past its own
    timeout (``<=`` means gone), a user that isn't active or is deleted, a
    member of an org that isn't active, or a row that doesn't form a valid
    Principal. Writes nothing.
    """
    if row is None:
        return None
    expires_at = row["expires_at"]
    last_seen_at = row["last_seen_at"]
    idle_minutes = row["idle_timeout_minutes"]
    if not _is_aware(expires_at) or not _is_aware(last_seen_at):
        return None
    if (
        type(idle_minutes) is not int
        or not MIN_IDLE_TIMEOUT_MINUTES <= idle_minutes <= MAX_IDLE_TIMEOUT_MINUTES
    ):
        return None
    if expires_at <= now or last_seen_at + timedelta(minutes=idle_minutes) <= now:
        return None
    if not _active_account(row):
        return None
    try:
        return AuthenticatedSession(
            session_id=row["session_id"],
            principal=_row_principal(row),
            ui_language=row["ui_language"],
            response_language=row["response_language"],
        )
    except ValidationError:
        # No IDs or values: the row is inconsistent, and access is refused.
        logger.warning("A session row failed validation; the session is refused.")
        return None


async def create_session(
    executor: Executor,
    *,
    user_id: UUID,
    policy: SessionPolicy,
    ip: str | None,
    user_agent: str | None,
) -> str:
    """Open a session for a user and return its raw token (for the cookie).

    One parameterized INSERT stores the token's hash, the user id, the expiry
    (``now()`` plus the policy's lifetime, on the database clock), the
    policy's idle timeout, the client IP (NULL when it isn't an IP address)
    and the user agent truncated to ``USER_AGENT_MAX_LENGTH`` characters. The
    raw token is never stored or logged.

    Args:
        executor: The pool or a connection (inside the caller's transaction).
        user_id: The account the session belongs to.
        policy: The session policy of the account
            (``scoped_settings.session_policy_for``).
        ip: The client address, if known.
        user_agent: The client's User-Agent header, if any.

    Returns:
        The raw session token.
    """
    token = new_session_token()
    await executor.execute(
        _INSERT_SQL,
        hash_session_token(token),
        user_id,
        policy.max_lifetime,
        policy.idle_timeout_minutes,
        _client_ip(ip),
        None if user_agent is None else user_agent[:USER_AGENT_MAX_LENGTH],
    )
    return token


async def resolve_session(executor: Executor, token: str) -> AuthenticatedSession | None:
    """Resolve a session token to its logged-in user, re-checking the account.

    A usable session last seen at least ``LAST_SEEN_UPDATE_INTERVAL`` ago gets
    its ``last_seen_at`` set to now (one UPDATE by session id).

    Args:
        executor: The pool or a connection.
        token: The raw token from the session cookie.

    Returns:
        The AuthenticatedSession, or None when the token is malformed or
        unknown (never issued, or its session was deleted), the session is
        expired or idle past its own timeout, the row's timestamps or timeout
        are malformed, the user isn't active or is deleted, the user is a
        member of an org that isn't active, or the row doesn't form a valid
        Principal.
    """
    if not _is_plausible_token(token):
        return None
    row = await executor.fetchrow(_RESOLVE_SQL, hash_session_token(token))
    now = datetime.now(UTC)
    session = _usable_session(row, now)
    if session is None:
        return None
    if now - row["last_seen_at"] >= LAST_SEEN_UPDATE_INTERVAL:
        await executor.execute(_TOUCH_SQL, session.session_id)
    return session


async def resolve_session_by_id(
    executor: Executor, session_id: UUID
) -> AuthenticatedSession | None:
    """Resolve a session by its row id, with the same checks as ``resolve_session`` (GH-162).

    Only the OAuth callback uses it: the provider's cross-site redirect
    carries no session cookie, so the callback re-resolves the session that
    started the authorization. It never writes: ``last_seen_at`` is left as
    it is, so the redirect can't keep a session alive.

    Args:
        executor: The pool or a connection.
        session_id: The id of the initiating session's row.

    Returns:
        The AuthenticatedSession, or None in every case ``resolve_session``
        refuses (unknown or deleted session, expired or idle past its own
        timeout, malformed row, user not active or deleted, member of an org
        that isn't active, invalid Principal).
    """
    row = await executor.fetchrow(_RESOLVE_BY_ID_SQL, session_id)
    return _usable_session(row, datetime.now(UTC))


async def recheck_principal(executor: Executor, principal: Principal) -> Principal | None:
    """Re-read a member's account and return its current Principal (GH-298).

    An approval (``POST /api/confirm``) calls it first under its chat's hold,
    so a change made to the caller's account while the request waited
    refuses it like a request sent after the change. The caller compares the
    returned role with the capability it needs; the request keeps the
    principal it arrived with.

    Args:
        executor: The pool or a connection.
        principal: The request's principal, built by ``resolve_session``
            from its session row (never request data).

    Returns:
        The Principal built from the account as it is now, or None (fail
        closed) when ``principal`` isn't a member, the account has no row in
        the principal's org (deleted, or no longer a member of it), the user
        isn't active or is deleted, the row isn't a member's, the org isn't
        active (deactivated, pending deletion), the row doesn't form a valid
        Principal, or it isn't the same user, kind and org as ``principal``.

    Security notes: one parameterized read of the users row by the
    principal's user id and org id, joined with the org's status; it writes
    nothing (no ``last_seen_at``, no session). Logs carry no ID or value.
    """
    if principal.kind != "member" or principal.org_id is None:
        return None
    row = await executor.fetchrow(_ACCOUNT_SQL, principal.user_id, principal.org_id)
    if row is None or row["kind"] != "member" or not _active_account(row):
        return None
    try:
        current = _row_principal(row)
    except ValidationError:
        # No IDs or values: the row is inconsistent, and the request is refused.
        logger.warning("An account row failed validation; the request is refused.")
        return None
    if (current.user_id, current.kind, current.org_id) != (
        principal.user_id,
        principal.kind,
        principal.org_id,
    ):
        return None
    return current


async def revoke_session(executor: Executor, token: str) -> None:
    """Delete the session behind a token (a malformed token touches nothing).

    Args:
        executor: The pool or a connection.
        token: The raw token from the session cookie.
    """
    if not _is_plausible_token(token):
        return
    await executor.execute(_REVOKE_SQL, hash_session_token(token))


async def revoke_user_sessions(executor: Executor, user_id: UUID) -> int:
    """Delete every session of a user with one DELETE.

    Used when a password changes (a reset, and the account-page change of
    #166), for a forced logout, and when a user is deactivated (#164): every
    device is logged out, the caller's own included.

    Args:
        executor: The pool or a connection (inside the caller's transaction).
        user_id: The account whose sessions end.

    Returns:
        The number of session rows deleted.
    """
    return _row_count(await executor.execute(_REVOKE_USER_SQL, user_id))


async def revoke_org_sessions(executor: Executor, org_id: UUID) -> int:
    """Delete every session of every user of an org with one DELETE.

    Used when an organization is deactivated (#154, #167).

    Args:
        executor: The pool or a connection (inside the caller's transaction).
        org_id: The organization whose users' sessions end.

    Returns:
        The number of session rows deleted.
    """
    return _row_count(await executor.execute(_REVOKE_ORG_SQL, org_id))


async def apply_super_admin_policy(executor: Executor, policy: SessionPolicy) -> int:
    """Give every open Super Admin session a new policy with one UPDATE (GH-160).

    Each Super Admin session takes the policy's idle timeout and expires at
    its ``created_at`` plus the policy's lifetime (on the database clock), so
    a session older than the new lifetime, or idle past the new timeout, ends
    at once. Members' sessions are untouched.

    Args:
        executor: The pool or a connection (inside the caller's transaction).
        policy: The new platform session policy.

    Returns:
        The number of session rows updated.
    """
    status = await executor.execute(
        _SUPER_ADMIN_POLICY_SQL, policy.idle_timeout_minutes, policy.max_lifetime_hours
    )
    return _row_count(status)


async def apply_org_policy(executor: Executor, org_id: UUID, policy: SessionPolicy) -> int:
    """Give every live session of an org's users the org's new policy with one UPDATE (GH-169).

    Each live session of a user of that org (any role or status) takes the
    policy's idle timeout and expires at its ``created_at`` plus the policy's
    lifetime (on the database clock), so a session older than the new
    lifetime, or idle past the new timeout, ends at once. A session that had
    already ended (expired, or idle past its old timeout) is neither changed
    nor counted. Another org's sessions and the Super Admin's are untouched.

    Args:
        executor: The pool or a connection (inside the caller's transaction).
        org_id: The organization whose users' sessions follow the policy.
        policy: The org's new session policy.

    Returns:
        The number of session rows updated.
    """
    status = await executor.execute(
        _ORG_POLICY_SQL, org_id, policy.idle_timeout_minutes, policy.max_lifetime_hours
    )
    return _row_count(status)


async def purge_expired_sessions(executor: Executor) -> int:
    """Delete the sessions past their expiry or idle past their own timeout.

    Args:
        executor: The pool or a connection.

    Returns:
        The number of session rows deleted.
    """
    return _row_count(await executor.execute(_PURGE_SQL))


async def run_session_purge_job(
    pool: Executor, *, interval_seconds: float = PURGE_INTERVAL_SECONDS
) -> None:
    """Purge expired and idle sessions now and then once per interval, until cancelled.

    A failed purge is logged (class name only) and retried at the next
    interval; cancellation stops the job.

    Args:
        pool: The database pool.
        interval_seconds: Seconds between purges (default: one hour).
    """
    while True:
        try:
            await purge_expired_sessions(pool)
        except Exception as exc:
            logger.warning("Session purge failed (%s); retrying next interval.", type(exc).__name__)
        await asyncio.sleep(interval_seconds)
