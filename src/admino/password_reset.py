"""Self-service password reset by email (GH-151), also sent by an Org Admin (GH-164).

A user who forgot their password asks for a reset link (``request_reset``);
an account that may log in gets an email with a single-use link, valid for
30 minutes. Opening the link and choosing a new password (``confirm_reset``)
stores the new password and ends every session of the account. An Org Admin
can send the same link to an active user of their org
(``admino.org_users.trigger_password_reset``); both flows issue it through
``queue_reset_link``.

Inputs: ``request_reset`` takes the database pool, the email the user typed,
the configured public URL (``server.public_url``) and the client IP.
``queue_reset_link`` takes a connection inside the caller's transaction, the
user id and the public URL. ``confirm_reset`` takes the pool, the token from
the link, the new password and the client IP.
Outputs: all return None. ``confirm_reset`` raises ``InvalidResetTokenError``
for a link that can't be used and ``passwords.PasswordPolicyError`` for a new
password the policy refuses.

A request looks the account up by email (case-insensitively). Only an account
that may log in (``auth.may_log_in``: active, not deleted, a Super Admin or a
member of an active org) gets a token: in one transaction, the SHA-256 hash of
a fresh 256-bit token replaces the user's previous one (one live token per
user, so a newer request invalidates the older link), the ``password_reset``
email is queued through the outbox (#148) with the link
``{public_url}/reset-password#token=<token>``, and ``password_reset.request``
is recorded. A confirm checks the token and the account again, applies the
password policy, and then, in one transaction, consumes the token, stores
the new Argon2 hash, ends every session of the user (deletes its rows,
``sessions.revoke_user_sessions``) and records ``password_reset.complete``.

Security notes:
- No user enumeration: ``request_reset`` returns None and raises nothing for
  an unknown email or an account that may not log in, like for an eligible
  one. Neither its caller (the HTTP route) nor an Org Admin triggering a
  reset ever sees the token: ``queue_reset_link`` returns nothing.
- Reset-link poisoning: the link base is the configured public URL, never a
  request header.
- Only the token's SHA-256 hash is stored or queried; the raw token travels
  only inside the queued email's link. A value that can't be a
  ``secrets.token_urlsafe(32)`` token is refused without a query.
- Single use and expiry are enforced by the database: the consuming DELETE
  only matches a row with the same hash and user that hasn't expired, so two
  concurrent confirms can't both succeed. The expiry is computed in SQL on
  the transaction's clock (``now()``), like ``created_at``, so the table's
  30-minute CHECK holds exactly.
- The token is checked before the password policy, and a policy failure
  writes nothing, so the link stays usable for another try.
- Argon2 is CPU-bound (~200 ms): it runs in a worker thread
  (``asyncio.to_thread``), outside the transaction.
- Content-free audit (tracker #139 §5): the events carry the actor, the
  target user, the client IP and a bool or a count. Neither the email, the
  token, the link nor the password reaches an audit row, another statement,
  an error or a log line; the email is only the lookup's bind parameter.
- Fail closed: a failed audit record rolls the transaction back, so no reset
  email is queued and no password changes unaudited.
- Parameterized SQL only: values travel as bind parameters.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

from admino import audit_events, auth, email_outbox, passwords, sessions
from admino.audit_events import AuditAction, TargetType
from admino.email_templates import PasswordResetParams

if TYPE_CHECKING:
    from uuid import UUID

    import asyncpg
    from asyncpg.pool import PoolConnectionProxy

RESET_TOKEN_LIFETIME: Final = timedelta(minutes=30)
INVALID_RESET_TOKEN_MESSAGE: Final = "This reset link is invalid or has expired."  # noqa: S105 - a message, not a secret

_TOKEN_BYTES: Final = 32  # 256 bits
# What secrets.token_urlsafe(32) produces: 43 URL-safe base64 characters.
_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9_-]{43}")

# Case-insensitive, matching the users_email_lower_key unique index. LEFT JOIN:
# a Super Admin belongs to no organization.
_ACCOUNT_SQL: Final = """
    SELECT u.id, u.kind, u.org_id, u.status, u.deleted_at, o.status AS org_status
    FROM users u
    LEFT JOIN organizations o ON o.id = u.org_id
    WHERE lower(u.email) = lower($1)
"""
# One row per user: a newer request replaces the hash (the older link stops
# working). The expiry is computed on the transaction clock, like created_at.
_UPSERT_SQL: Final = """
    INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
    VALUES ($1, $2, now() + $3::interval)
    ON CONFLICT (user_id) DO UPDATE
    SET token_hash = EXCLUDED.token_hash,
        created_at = now(),
        expires_at = EXCLUDED.expires_at
    RETURNING expires_at
"""
_LINK_LOOKUP_SQL: Final = """
    SELECT t.user_id, t.expires_at, u.email, u.kind, u.org_id, u.status, u.deleted_at,
           o.status AS org_status
    FROM password_reset_tokens t
    JOIN users u ON u.id = t.user_id
    LEFT JOIN organizations o ON o.id = u.org_id
    WHERE t.token_hash = $1
"""
# Atomic single use: no row comes back if the token was used, replaced or
# expired since the lookup.
_CONSUME_SQL: Final = """
    DELETE FROM password_reset_tokens
    WHERE token_hash = $1 AND user_id = $2 AND expires_at > now()
    RETURNING user_id
"""
_UPDATE_HASH_SQL: Final = "UPDATE users SET password_hash = $1 WHERE id = $2"


class InvalidResetTokenError(Exception):
    """Raised for every reset link that can't be used, whatever the cause; carries no input."""

    def __init__(self) -> None:
        super().__init__(INVALID_RESET_TOKEN_MESSAGE)


def _hash_token(token: str) -> bytes:
    """Return the 32-byte SHA-256 digest of a token: what the database stores."""
    return hashlib.sha256(token.encode()).digest()


def _is_plausible_token(token: object) -> bool:
    """True when ``token`` could be a ``secrets.token_urlsafe(32)`` value."""
    return isinstance(token, str) and _TOKEN_RE.fullmatch(token) is not None


def _is_live(expires_at: object) -> bool:
    """True when a token's expiry is an aware datetime still in the future."""
    return (
        isinstance(expires_at, datetime)
        and expires_at.tzinfo is not None
        and expires_at > datetime.now(UTC)
    )


async def queue_reset_link(
    conn: asyncpg.Connection | PoolConnectionProxy, *, user_id: UUID, public_url: str
) -> None:
    """Replace a user's reset token with a fresh one and queue the email with its link.

    The SHA-256 hash of a new 256-bit token replaces the user's previous one
    (one live token per user, expiring 30 minutes from now on the database
    clock), and the ``password_reset`` email is queued with the link
    ``{public_url}/reset-password#token=<token>``. The raw token exists only
    in that queued email. The caller records ``password_reset.request`` on the
    same connection, inside the same transaction, so a failed audit write
    stores and queues nothing.

    Args:
        conn: An asyncpg connection inside the caller's transaction.
        user_id: The account the link is for.
        public_url: The configured origin the link is built from
            (``server.public_url``), without a trailing slash.

    Raises:
        RecipientNotFoundError: If the user doesn't exist or is deleted.
    """
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    expires_at = await conn.fetchval(_UPSERT_SQL, user_id, _hash_token(token), RESET_TOKEN_LIFETIME)
    await email_outbox.enqueue_email(
        conn,
        user_id=user_id,
        params=PasswordResetParams(
            reset_link=f"{public_url}/reset-password#token={token}", expires_at=expires_at
        ),
    )


async def request_reset(pool: asyncpg.Pool, *, email: str, public_url: str, ip: str | None) -> None:
    """Email a password reset link to the account of an email, if it may log in.

    Behaves the same for the caller whatever the email: it returns None and
    raises nothing for an unknown email or an account that may not log in.
    Every request records ``password_reset.request`` (``email_sent`` tells
    whether a link was queued).

    Args:
        pool: The database pool.
        email: The email the user typed (matched case-insensitively).
        public_url: The configured origin the link is built from
            (``server.public_url``), without a trailing slash.
        ip: The client address, if known.

    Raises:
        AuditRecordError: If the audit event can't be recorded; no token is
            stored and no email is queued.
    """
    account = await pool.fetchrow(_ACCOUNT_SQL, email)
    if account is None:
        await audit_events.record(
            pool,
            action=AuditAction.PASSWORD_RESET_REQUEST,
            actor_kind="system",
            actor_user_id=None,
            org_id=None,
            ip=ip,
            metadata={"email_sent": False},
        )
        return

    user_id = account["id"]
    if not auth.may_log_in(account):
        await audit_events.record(
            pool,
            action=AuditAction.PASSWORD_RESET_REQUEST,
            actor_kind=account["kind"],
            actor_user_id=user_id,
            org_id=account["org_id"],
            target_type=TargetType.USER,
            target_ids=(user_id,),
            ip=ip,
            metadata={"email_sent": False},
        )
        return

    async with pool.acquire() as conn, conn.transaction():
        await queue_reset_link(conn, user_id=user_id, public_url=public_url)
        await audit_events.record(
            conn,
            action=AuditAction.PASSWORD_RESET_REQUEST,
            actor_kind=account["kind"],
            actor_user_id=user_id,
            org_id=account["org_id"],
            target_type=TargetType.USER,
            target_ids=(user_id,),
            ip=ip,
            metadata={"email_sent": True},
        )


async def confirm_reset(
    pool: asyncpg.Pool, *, token: str, new_password: str, ip: str | None
) -> None:
    """Set a new password with a reset token, and end every session of the account.

    Args:
        pool: The database pool.
        token: The token from the reset link.
        new_password: The new password.
        ip: The client address, if known.

    Raises:
        InvalidResetTokenError: If the token is malformed, unknown, expired,
            already used or replaced by a newer request, or the account may no
            longer log in. Nothing is written.
        PasswordPolicyError: If the policy refuses the new password. Nothing
            is written and the token stays usable.
        AuditRecordError: If the audit event can't be recorded; nothing is
            changed and the token stays usable.
    """
    if not _is_plausible_token(token):
        raise InvalidResetTokenError
    token_hash = _hash_token(token)
    row = await pool.fetchrow(_LINK_LOOKUP_SQL, token_hash)
    if row is None or not _is_live(row["expires_at"]) or not auth.may_log_in(row):
        raise InvalidResetTokenError
    passwords.check_password_policy(new_password, email=row["email"])
    new_hash = await asyncio.to_thread(passwords.hash_password, new_password)

    user_id = row["user_id"]
    async with pool.acquire() as conn, conn.transaction():
        if await conn.fetchval(_CONSUME_SQL, token_hash, user_id) is None:
            raise InvalidResetTokenError
        await conn.execute(_UPDATE_HASH_SQL, new_hash, user_id)
        revoked = await sessions.revoke_user_sessions(conn, user_id)
        await audit_events.record(
            conn,
            action=AuditAction.PASSWORD_RESET_COMPLETE,
            actor_kind=row["kind"],
            actor_user_id=user_id,
            org_id=row["org_id"],
            target_type=TargetType.USER,
            target_ids=(user_id,),
            ip=ip,
            metadata={"sessions_revoked": revoked},
        )
