"""Transactional email outbox: enqueue, the background sender and the retention purge (GH-148).

Request handlers never talk to SMTP. ``enqueue_email()`` writes one outbox
row (migration 0006) and returns; ``run_outbox_sender()``, started by the
server lifespan when SMTP is configured, delivers due rows in the background
with retries and exponential backoff, so a slow or failing mail server never
breaks or delays a request.

Inputs: ``enqueue_email()`` takes a database executor (the caller's
connection or the pool), the recipient's user ID and a ``TemplateParams``.
``deliver_due()`` and ``run_outbox_sender()`` take the pool and the
``SmtpConfig``; ``purge_finished()`` takes the pool and a retention in days.
Outputs: the new outbox ID; the number of messages a sender pass sent; the
number of finished rows purged.

Lifecycle of a row: pending, then sent, or failed once its attempts are used
up (MAX_ATTEMPTS, with a backoff doubling from 60 s up to 6 h) or at once when
it can never be sent (unknown template or language, invalid stored params, a
message the transport refuses). Each attempt claims the row with FOR UPDATE
SKIP LOCKED and a lease, so two senders never send one row twice. Sent and
failed rows are purged after FINISHED_RETENTION_DAYS.

Security notes:
- The recipient address and language come from the users row (users.email,
  users.ui_language) in the same statement that queues the row; the caller
  can't pick them, and a deleted user gets no mail.
- No content in logs (tracker #139 §5): outbox IDs, attempt counts and
  exception class names only. Never an address, a link, an org name, SMTP
  credentials or an exception's text (SMTP and database errors echo addresses
  and rows).
- One-time links don't outlive delivery: params are scrubbed to '{}' when a
  row is sent or finally fails; a retry keeps them. The database refuses a
  finished row that still holds params.
- Parameterized SQL only: every value travels as a bind parameter.
- Imports only the standard library, asyncpg, pydantic and admino's template
  and mailer modules; SMTP lives in ``admino.mailer``. The permission engine
  never imports this module.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Protocol

from admino import mailer
from admino.email_templates import TemplateParams, params_for, render

if TYPE_CHECKING:
    from email.message import EmailMessage
    from uuid import UUID

    import asyncpg

    from admino.mailer import SmtpConfig

logger = logging.getLogger(__name__)

MAX_ATTEMPTS: Final = 10
BACKOFF_BASE_SECONDS: Final = 60
BACKOFF_MAX_SECONDS: Final = 21600
# Longer than any SMTP attempt (a few socket timeouts), so a slow send isn't claimed twice.
SEND_LEASE_SECONDS: Final = 600
BATCH_SIZE: Final = 10
POLL_INTERVAL_SECONDS: Final = 10
PURGE_INTERVAL_SECONDS: Final = 86400
FINISHED_RETENTION_DAYS: Final = 30
_MIN_RETENTION_DAYS: Final = 1
_MAX_RETENTION_DAYS: Final = 3650

# The recipient address and language are copied from the live users row.
_ENQUEUE_SQL: Final = """
    INSERT INTO email_outbox
        (recipient_user_id, recipient_address, language, template_key, params)
    SELECT id, email, ui_language, $2, $3::jsonb
    FROM users
    WHERE id = $1 AND deleted_at IS NULL
    RETURNING id
"""
# Rows whose last allowed attempt never reported back (its lease ran out).
_SWEEP_SQL: Final = """
    UPDATE email_outbox
    SET status = 'failed', params = '{}'::jsonb, finished_at = now()
    WHERE status = 'pending' AND attempts >= $1 AND next_attempt_at <= now()
"""
# Counts the attempt and leases the row until now() + $2 seconds.
_CLAIM_SQL: Final = """
    UPDATE email_outbox
    SET attempts = attempts + 1, next_attempt_at = now() + make_interval(secs => $2)
    WHERE id IN (
        SELECT id FROM email_outbox
        WHERE status = 'pending' AND next_attempt_at <= now() AND attempts < $3
        ORDER BY next_attempt_at
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id, recipient_address, template_key, language, params, attempts
"""
_SENT_SQL: Final = """
    UPDATE email_outbox
    SET status = 'sent', params = '{}'::jsonb, finished_at = now()
    WHERE id = $1 AND status = 'pending'
"""
_FAILED_SQL: Final = """
    UPDATE email_outbox
    SET status = 'failed', params = '{}'::jsonb, finished_at = now()
    WHERE id = $1 AND status = 'pending'
"""
_RETRY_SQL: Final = """
    UPDATE email_outbox
    SET next_attempt_at = now() + make_interval(secs => $2)
    WHERE id = $1 AND status = 'pending'
"""
_PURGE_SQL: Final = """
    DELETE FROM email_outbox
    WHERE status IN ('sent', 'failed') AND finished_at < now() - make_interval(days => $1)
"""


class OutboxStatus(StrEnum):
    """The states of an outbox row."""

    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class RecipientNotFoundError(Exception):
    """Raised when the recipient has no live user account; nothing is queued."""

    def __init__(self, message: str = "The recipient has no live user account.") -> None:
        super().__init__(message)


class Executor(Protocol):
    """What enqueue_email() writes through: an asyncpg connection, pool or pooled connection."""

    # Any: asyncpg returns the column value untyped.
    async def fetchval(self, query: str, *args: object) -> Any:
        """Run one statement and return the first column of its first row."""
        ...


def backoff_seconds(attempts: int) -> int:
    """Return the wait after a failed attempt: 60 s doubling per attempt, at most 6 h.

    Args:
        attempts: The attempts made so far, including the failed one (1 or more).

    Raises:
        ValueError: If attempts is below 1.
    """
    if attempts < 1:
        msg = "There is no backoff before the first attempt."
        raise ValueError(msg)
    # base << n == base * 2**n, typed as an int.
    return min(BACKOFF_BASE_SECONDS << (attempts - 1), BACKOFF_MAX_SECONDS)


async def enqueue_email(executor: Executor, *, user_id: UUID, params: TemplateParams) -> UUID:
    """Queue one email to a user with a single parameterized statement.

    Never touches SMTP, so a mail server outage never breaks the request. The
    address and language come from the users row, not from the caller.

    Args:
        executor: The caller's connection (inside its transaction) or the pool.
        user_id: The recipient's user ID.
        params: The validated params of the email's template.

    Returns:
        The new outbox row's ID.

    Raises:
        TypeError: If params is not a TemplateParams (nothing is written).
        RecipientNotFoundError: If the user doesn't exist or is deleted.
    """
    if not isinstance(params, TemplateParams):
        msg = "params must be a TemplateParams instance."
        raise TypeError(msg)
    outbox_id: UUID | None = await executor.fetchval(
        _ENQUEUE_SQL, user_id, params.template.value, params.model_dump_json()
    )
    if outbox_id is None:
        raise RecipientNotFoundError
    return outbox_id


async def deliver_due(pool: asyncpg.Pool, config: SmtpConfig) -> int:
    """Run one sender pass: fail exhausted rows, claim a batch of due rows, send each.

    A row that is sent is marked sent; a failed delivery is retried after a
    backoff, or marked failed when it was the last allowed attempt; a row that
    can never be sent is marked failed at once. One row's failure never stops
    the rest of the batch.

    Args:
        pool: The database pool.
        config: The platform SMTP account.

    Returns:
        The number of messages sent.
    """
    await pool.execute(_SWEEP_SQL, MAX_ATTEMPTS)
    rows = await pool.fetch(_CLAIM_SQL, BATCH_SIZE, SEND_LEASE_SECONDS, MAX_ATTEMPTS)
    sent = 0
    for row in rows:
        if await _send_row(pool, config, row):
            sent += 1
    return sent


async def _send_row(pool: asyncpg.Pool, config: SmtpConfig, row: asyncpg.Record) -> bool:
    """Deliver one claimed row and record the outcome; return True if it was sent."""
    outbox_id = row["id"]
    try:
        message = _message_for(config, row)
    # Anything here (bad JSON, invalid params, unknown template or language, a
    # refused header) will fail again on every attempt.
    except Exception as exc:
        logger.warning(
            "Outbox email %s can't be sent (%s); marked failed.", outbox_id, type(exc).__name__
        )
        await pool.execute(_FAILED_SQL, outbox_id)
        return False
    try:
        await mailer.deliver(config, message)
    except Exception as exc:
        await _record_delivery_failure(pool, outbox_id, row["attempts"], exc)
        return False
    await pool.execute(_SENT_SQL, outbox_id)
    logger.info("Outbox email %s sent.", outbox_id)
    return True


def _message_for(config: SmtpConfig, row: asyncpg.Record) -> EmailMessage:
    """Restore the params of a claimed row, render them and build the message."""
    stored = row["params"]
    # asyncpg returns jsonb as JSON text unless a codec decodes it.
    data = json.loads(stored) if isinstance(stored, str) else stored
    if not isinstance(data, dict):
        msg = "Stored params must be a JSON object."
        raise TypeError(msg)
    rendered = render(params_for(row["template_key"], data), row["language"])
    return mailer.build_message(config, to=row["recipient_address"], rendered=rendered)


async def _record_delivery_failure(
    pool: asyncpg.Pool, outbox_id: UUID, attempts: int, exc: Exception
) -> None:
    """Back a failed row off, or fail it for good after its last allowed attempt."""
    if attempts >= MAX_ATTEMPTS:
        logger.warning(
            "Outbox email %s: attempt %d failed (%s); no attempts left, marked failed.",
            outbox_id,
            attempts,
            type(exc).__name__,
        )
        await pool.execute(_FAILED_SQL, outbox_id)
        return
    delay = backoff_seconds(attempts)
    logger.warning(
        "Outbox email %s: attempt %d failed (%s); retrying in %d s.",
        outbox_id,
        attempts,
        type(exc).__name__,
        delay,
    )
    await pool.execute(_RETRY_SQL, outbox_id, delay)


async def purge_finished(pool: asyncpg.Pool, retention_days: int = FINISHED_RETENTION_DAYS) -> int:
    """Delete sent and failed rows that finished more than retention_days ago.

    Args:
        pool: The database pool.
        retention_days: How many days to keep finished rows (1 to 3650).

    Returns:
        The number of rows removed.

    Raises:
        ValueError: If retention_days isn't an int from 1 to 3650 (the pool
            isn't touched).
    """
    if (
        type(retention_days) is not int
        or not _MIN_RETENTION_DAYS <= retention_days <= _MAX_RETENTION_DAYS
    ):
        msg = "The outbox retention must be a whole number of days from 1 to 3650."
        raise ValueError(msg)
    status = await pool.execute(_PURGE_SQL, retention_days)
    return int(status.rpartition(" ")[2])


async def run_outbox_sender(
    pool: asyncpg.Pool,
    config: SmtpConfig,
    *,
    interval_seconds: float = POLL_INTERVAL_SECONDS,
) -> None:
    """Deliver due email every interval and purge finished rows daily, until cancelled.

    The purge runs on the first pass and then once PURGE_INTERVAL_SECONDS have
    passed. A failed pass or purge is logged (class name only) and retried
    later; neither skips the other. Cancellation stops the loop.

    Args:
        pool: The database pool.
        config: The platform SMTP account.
        interval_seconds: Seconds to sleep between passes.
    """
    last_purge: float | None = None
    while True:
        now = time.monotonic()
        if last_purge is None or now - last_purge >= PURGE_INTERVAL_SECONDS:
            last_purge = now
            try:
                await purge_finished(pool)
            except Exception as exc:
                logger.warning(
                    "Outbox purge failed (%s); retrying next interval.", type(exc).__name__
                )
        try:
            await deliver_due(pool, config)
        except Exception as exc:
            logger.warning("Outbox sender pass failed (%s); retrying.", type(exc).__name__)
        await asyncio.sleep(interval_seconds)
