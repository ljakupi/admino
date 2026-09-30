"""Brute-force protection: failed-attempt counters, progressive delays and lockouts (GH-157).

Every login attempt runs through this module, and so does every attempt on
the public password reset and invitation links (``admino.server``). Failed
attempts are counted in the ``login_throttle`` table (migration 0012), one row
per subject, so the counters survive a restart:
- the account (scope ``'account'``): the digest
  ``sha256(convert_to(lower(<typed email>), 'UTF8'))``, computed by PostgreSQL
  with the same ``lower()`` as the login lookup and the
  ``users_email_lower_key`` index. Every spelling of an email shares one
  counter, and an unknown email is counted exactly like a known one;
- the client IP (scope ``'ip'``): ``ip_subject``, a digest of the IPv4 address
  (an IPv4-mapped IPv6 address counts as its IPv4 address) or of the /64
  network of an IPv6 address. A peer that isn't an IP address has no IP
  counter. The link routes count the IP only, sharing the login's counter.

The rules (constants for now; #160 makes them configurable):
- Failures count within a 15-minute window (``FAILURE_WINDOW``) that starts at
  a subject's first counted failure; once it ends, the count starts again.
- From 3 failures on (``DELAY_AFTER_FAILURES``) an attempt waits before its
  check: 1, 2, 4, then 8 seconds (``delay_seconds``).
- The 10th failure in the window (``LOCKOUT_AFTER_FAILURES``) locks the
  subject for 15 minutes (``LOCKOUT_DURATION``) and records one
  ``login.lockout`` audit event. The lock expires on its own.

The reservation model (``begin``, then ``fail`` or ``succeed``):
- ``begin`` locks the attempt's rows FOR UPDATE in one transaction, account
  first, then IP (a fixed order, so concurrent attempts can't deadlock),
  creating a missing row first. A subject with an active lock, or with 10
  failures in its window and no lock, makes the attempt locked: the
  transaction is rolled back, so nothing is written. Otherwise every subject
  counts one failure at once (the reservation), before the password or token
  is checked, so concurrent attempts see each other and can't outrun the
  lockout. After the commit, never inside the transaction, the attempt waits
  out the delay of the highest count it found.
- ``fail`` keeps the reservation; a subject whose reservation was its 10th
  failure is locked, and its ``login.lockout`` event is recorded in the same
  transaction.
- ``succeed`` resets the account counter and releases the attempt's own IP
  reservation only (so a success with an attacker's own account never
  clears the other failures of the IP).
- ``admit`` (the password reset request) reads the IP counter without
  counting: a locked IP is refused, any other waits out its delay.
- ``run_purge_job`` deletes the rows past ``expires_at`` hourly.

Inputs: the database pool (or a connection or the pool for single
statements), the typed email of a login (None on the link routes), the client
IP, and the actor columns of an account lockout.
Outputs: an ``Attempt`` (locked, or the reservations it made); ``admit``
answers whether the IP may go on; ``purge_expired`` the number of rows
deleted.

Security notes:
- No user enumeration: the account subject is a digest of whatever was typed,
  so a known and an unknown email are counted, delayed and locked alike. A
  lockout is announced by the caller with its usual generic failure.
- Fail closed: a database error before the check propagates (the password is
  never checked), and an error after the reservation leaves it counted. A
  failed lockout record rolls the lock back, but the 10 counted failures
  keep the subject refused until the window ends.
- No email or IP text: the table holds digests and counts only. The digests
  are unsalted, so they are pseudonymous, not anonymous: whoever can read the
  table can recover an email or IPv4 address by guessing and hashing
  candidates. They stay out of logs and ``repr()``, and a row is purged
  within about 30 minutes of its last effect (an accepted trade-off: the
  audit log already holds client IPs, and the users table account emails).
  The audit events carry the actor columns, the client IP and
  ``{"per_ip", "lockout_minutes"}`` only. Logs carry exception class names
  only.
- Slow guessing never locks (an accepted property of any "10 failures in 15
  minutes" rule): an attacker who stops at 9 failures per window can keep
  going at about 36 guesses an hour per account or IP, each one audited as
  ``login.failure``. The password policy (12+ characters, common passwords
  refused) makes that rate negligible.
- The clock is the app's (``datetime.now(UTC)``, bound as parameters); the
  purge uses the database's ``now()``.
- Parameterized SQL only: values travel as bind parameters.
- Imports nothing from the server, agent, LLM, tools, OAuth or permission
  layers.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import math
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from admino import audit_events
from admino.audit_events import AuditAction

if TYPE_CHECKING:
    from uuid import UUID

    import asyncpg

    from admino.audit_events import ActorKind

logger = logging.getLogger(__name__)

FAILURE_WINDOW: Final = timedelta(minutes=15)
DELAY_AFTER_FAILURES: Final = 3
LOCKOUT_AFTER_FAILURES: Final = 10
LOCKOUT_DURATION: Final = timedelta(minutes=15)
DELAY_BASE_SECONDS: Final = 1.0
DELAY_MAX_SECONDS: Final = 8.0
# Seconds between two runs of the expired-row purge.
PURGE_INTERVAL_SECONDS: Final = 3600
TOO_MANY_ATTEMPTS_MESSAGE: Final = "Too many attempts. Try again later."

# The only path the progressive delay is awaited through (tests replace it).
sleep = asyncio.sleep

Scope = Literal["account", "ip"]

# The doublings from the base delay to the cap: counting stops there, so a huge
# failure count can't overflow.
_MAX_DOUBLINGS: Final = math.ceil(math.log2(DELAY_MAX_SECONDS / DELAY_BASE_SECONDS))
_LOCKOUT_MINUTES: Final = int(LOCKOUT_DURATION / timedelta(minutes=1))
# Separates the IP digests from any other SHA-256 use.
_IP_DIGEST_PREFIX: Final = b"admino.login_throttle.ip:"

# Computed by the database, with the lower() of the login lookup.
_ACCOUNT_SUBJECT_SQL: Final = "SELECT sha256(convert_to(lower($1::text), 'UTF8'))"
_ENSURE_SQL: Final = """
    INSERT INTO login_throttle (scope, subject, failures, window_started_at, expires_at)
    VALUES ($1, $2, 0, $3, $4)
    ON CONFLICT (scope, subject) DO NOTHING
"""
_LOCK_SQL: Final = """
    SELECT failures, window_started_at, locked_until
    FROM login_throttle
    WHERE scope = $1 AND subject = $2
    FOR UPDATE
"""
# A reservation is only written when no lock is active: an ended one is cleared.
_RESERVE_SQL: Final = """
    UPDATE login_throttle
    SET failures = $3, window_started_at = $4, locked_until = NULL, expires_at = $5
    WHERE scope = $1 AND subject = $2
"""
_LOCKOUT_SQL: Final = """
    UPDATE login_throttle
    SET failures = 0, locked_until = $3, expires_at = $4
    WHERE scope = $1 AND subject = $2
"""
_RESET_ACCOUNT_SQL: Final = """
    UPDATE login_throttle SET failures = 0 WHERE scope = 'account' AND subject = $1
"""
_RELEASE_IP_SQL: Final = """
    UPDATE login_throttle SET failures = greatest(failures - 1, 0)
    WHERE scope = 'ip' AND subject = $1
"""
_READ_IP_SQL: Final = """
    SELECT failures, window_started_at, locked_until
    FROM login_throttle
    WHERE scope = 'ip' AND subject = $1
"""
_PURGE_SQL: Final = "DELETE FROM login_throttle WHERE expires_at <= now()"


class Executor(Protocol):
    """What a single throttle statement runs through: an asyncpg pool or connection."""

    async def execute(self, query: str, *args: object) -> str:
        """Run one statement with bind parameters."""
        ...

    # Any: asyncpg returns an untyped Record (or None).
    async def fetchrow(self, query: str, *args: object) -> Any:
        """Run one query and return its first row, or None."""
        ...


class Reservation(BaseModel):
    """One failure an attempt counted on one subject before its outcome was known."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope: Scope
    # repr=False: a digest, but a guessable one; kept out of logs and tracebacks.
    subject: bytes = Field(repr=False, min_length=32, max_length=32)
    # The subject's count with this reservation included.
    failures: int = Field(ge=1)


class Attempt(BaseModel):
    """The throttle's answer to ``begin``: locked, or the failures the attempt reserved."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    locked: bool
    reservations: tuple[Reservation, ...] = ()


class _LockedError(Exception):
    """Raised inside ``begin``'s transaction to roll it back: the attempt is locked."""


def delay_seconds(failures: int) -> float:
    """The progressive delay before an attempt's check, for a subject's prior failures.

    Args:
        failures: The failures already counted in the window.

    Returns:
        0.0 below ``DELAY_AFTER_FAILURES``, then ``DELAY_BASE_SECONDS``
        doubling with each failure, capped at ``DELAY_MAX_SECONDS``.
    """
    if failures < DELAY_AFTER_FAILURES:
        return 0.0
    doublings = min(failures - DELAY_AFTER_FAILURES, _MAX_DOUBLINGS)
    return min(DELAY_MAX_SECONDS, math.ldexp(DELAY_BASE_SECONDS, doublings))


def ip_subject(ip: str | None) -> bytes | None:
    """The subject of a client IP's counter: a 32-byte digest, the same in every process.

    An IPv4 address keys by itself (an IPv4-mapped IPv6 address like its IPv4
    address); any other IPv6 address keys by its /64 network, the block one
    client usually holds. Every spelling of an address gives the same digest,
    and an IPv6 scope ID is dropped.

    Args:
        ip: The client address (the peer, or the one the trusted proxy forwarded).

    Returns:
        The digest, or None when ``ip`` is None or not an IP address (no IP
        counter).
    """
    if ip is None:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if isinstance(address, ipaddress.IPv4Address):
        key = b"4" + address.packed
    else:
        key = b"6" + address.packed[:8]
    return hashlib.sha256(_IP_DIGEST_PREFIX + key).digest()


def _counted(row: Any, now: datetime) -> tuple[int, datetime]:
    """The failures that still count and the start of their window.

    Once the row's window has ended, the count starts again: (0, now).
    """
    started: datetime = row["window_started_at"]
    if started + FAILURE_WINDOW <= now:
        return 0, now
    return int(row["failures"]), started


def _is_locked(row: Any, failures: int, now: datetime) -> bool:
    """True for an active lock, or for the limit reached without one.

    The limit without a lock means in-flight attempts hold the last
    reservations, or a lockout's record failed: refused either way.
    """
    locked_until: datetime | None = row["locked_until"]
    return (locked_until is not None and locked_until > now) or failures >= LOCKOUT_AFTER_FAILURES


async def _wait_out(failures: int) -> None:
    """Await the progressive delay of a prior failure count, if it has one."""
    delay = delay_seconds(failures)
    if delay > 0:
        await sleep(delay)


async def _reserve(
    conn: Any, subjects: list[tuple[Scope, bytes]], now: datetime
) -> tuple[tuple[Reservation, ...], int]:
    """Lock each subject's row in order and count one failure on every one.

    Runs inside the caller's transaction. Raises ``_LockedError`` (before
    writing any count) when a subject is locked.

    Returns:
        The reservations, and the highest failure count found before them.
    """
    counted: list[tuple[Scope, bytes, int, datetime]] = []
    for scope, subject in subjects:
        await conn.execute(_ENSURE_SQL, scope, subject, now, now + FAILURE_WINDOW)
        row = await conn.fetchrow(_LOCK_SQL, scope, subject)
        failures, started = _counted(row, now)
        if _is_locked(row, failures, now):
            raise _LockedError
        counted.append((scope, subject, failures, started))
    reservations = []
    for scope, subject, failures, started in counted:
        await conn.execute(
            _RESERVE_SQL, scope, subject, failures + 1, started, started + FAILURE_WINDOW
        )
        reservations.append(Reservation(scope=scope, subject=subject, failures=failures + 1))
    return tuple(reservations), max((failures for _, _, failures, _ in counted), default=0)


async def begin(pool: asyncpg.Pool, *, email: str | None, ip: str | None) -> Attempt:
    """Start an attempt: refuse it when locked, else reserve a failure and wait out the delay.

    Call it before checking the password or token, then report the outcome
    with ``fail`` or ``succeed``.

    Args:
        pool: The database pool.
        email: The email typed at the login (the account counter); None on the
            link routes, which count the IP only.
        ip: The client address; no IP counter when it isn't an IP address.

    Returns:
        ``Attempt(locked=True)`` when a subject is locked (nothing written, no
        delay), otherwise the attempt's reservations, after its delay.

    Raises:
        asyncpg.PostgresError: If the counters can't be read or written; the
            caller must not go on to the check.
    """
    ip_key = ip_subject(ip)
    if email is None and ip_key is None:
        return Attempt(locked=False)
    now = datetime.now(UTC)
    try:
        async with pool.acquire() as conn, conn.transaction():
            subjects: list[tuple[Scope, bytes]] = []
            if email is not None:
                subjects.append(("account", await conn.fetchval(_ACCOUNT_SUBJECT_SQL, email)))
            if ip_key is not None:
                subjects.append(("ip", ip_key))
            reservations, prior = await _reserve(conn, subjects, now)
    except _LockedError:
        return Attempt(locked=True)
    await _wait_out(prior)
    return Attempt(locked=False, reservations=reservations)


async def fail(
    pool: asyncpg.Pool,
    attempt: Attempt,
    *,
    ip: str | None,
    actor_kind: ActorKind = "system",
    actor_user_id: UUID | None = None,
    org_id: UUID | None = None,
) -> None:
    """Record a failed attempt: its reservations stay, and a subject at the limit locks.

    Each subject whose reservation was its ``LOCKOUT_AFTER_FAILURES``-th
    failure (and that no concurrent attempt locked or reset meanwhile) is
    locked for ``LOCKOUT_DURATION`` with its count reset, and one
    ``login.lockout`` event is recorded on the same connection (account
    first, then IP). A failed record rolls the lock back; the counted
    failures keep the subject refused.

    Args:
        pool: The database pool.
        attempt: The unlocked attempt from ``begin``.
        ip: The client address, for the audit events.
        actor_kind: The account lockout's actor: the account the email belongs
            to, or ``system`` for an unknown email. An IP lockout is always a
            platform event (``system``, no user, no org).
        actor_user_id: The account's id, if the email belongs to one.
        org_id: The account's org, for a member (its org's audit log).

    Raises:
        AuditRecordError: If a lockout event can't be recorded (the lock is
            rolled back).
    """
    due = [r for r in attempt.reservations if r.failures >= LOCKOUT_AFTER_FAILURES]
    if not due:
        return
    locked_until = datetime.now(UTC) + LOCKOUT_DURATION
    async with pool.acquire() as conn, conn.transaction():
        for reservation in due:
            row = await conn.fetchrow(_LOCK_SQL, reservation.scope, reservation.subject)
            if row is None or row["failures"] < LOCKOUT_AFTER_FAILURES:
                # Purged, or a concurrent attempt locked or reset it meanwhile.
                continue
            expires_at = max(row["window_started_at"] + FAILURE_WINDOW, locked_until)
            await conn.execute(
                _LOCKOUT_SQL, reservation.scope, reservation.subject, locked_until, expires_at
            )
            per_ip = reservation.scope == "ip"
            await audit_events.record(
                conn,
                action=AuditAction.LOGIN_LOCKOUT,
                actor_kind="system" if per_ip else actor_kind,
                actor_user_id=None if per_ip else actor_user_id,
                org_id=None if per_ip else org_id,
                ip=ip,
                metadata={"per_ip": per_ip, "lockout_minutes": _LOCKOUT_MINUTES},
            )


async def succeed(executor: Executor, attempt: Attempt) -> None:
    """Record a successful attempt: reset the account counter, release the IP reservation.

    The IP counter only loses this attempt's own reservation (never below
    zero), so the IP's other failures still count.

    Args:
        executor: The pool, or the connection of the caller's transaction (the
            login's session transaction).
        attempt: The unlocked attempt from ``begin``.
    """
    for reservation in attempt.reservations:
        sql = _RESET_ACCOUNT_SQL if reservation.scope == "account" else _RELEASE_IP_SQL
        await executor.execute(sql, reservation.subject)


async def admit(executor: Executor, *, ip: str | None) -> bool:
    """Check a client IP's counter without counting (the password reset request).

    Args:
        executor: The pool or a connection.
        ip: The client address; always admitted when it isn't an IP address.

    Returns:
        False when the IP is locked (nothing is waited); otherwise True, after
        waiting out the IP's progressive delay.
    """
    subject = ip_subject(ip)
    if subject is None:
        return True
    row = await executor.fetchrow(_READ_IP_SQL, subject)
    if row is None:
        return True
    now = datetime.now(UTC)
    failures, _ = _counted(row, now)
    if _is_locked(row, failures, now):
        return False
    await _wait_out(failures)
    return True


async def purge_expired(executor: Executor) -> int:
    """Delete the rows past ``expires_at`` (a live lock never is: see migration 0012).

    Args:
        executor: The pool or a connection.

    Returns:
        The number of rows deleted.
    """
    status = await executor.execute(_PURGE_SQL)
    return int(status.rpartition(" ")[2])


async def run_purge_job(
    pool: Executor, *, interval_seconds: float = PURGE_INTERVAL_SECONDS
) -> None:
    """Purge the expired rows now and then once per interval, until cancelled.

    A failed purge is logged (class name only) and retried at the next
    interval; cancellation stops the job.

    Args:
        pool: The database pool.
        interval_seconds: Seconds between purges (default: one hour).
    """
    while True:
        try:
            await purge_expired(pool)
        except Exception as exc:
            logger.warning(
                "Login throttle purge failed (%s); retrying next interval.", type(exc).__name__
            )
        await asyncio.sleep(interval_seconds)
