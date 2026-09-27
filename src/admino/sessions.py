"""Server-side login sessions, and the one place a ``Principal`` is built (GH-149).

A login creates a ``sessions`` row (migration 0007) holding the SHA-256 hash
of a random 256-bit token; the raw token only lives in the ``admino_session``
cookie. Every request resolves the cookie back to its session, re-reading the
user's row, and builds the ``Principal`` from that row.

Inputs: a database executor (the pool or a connection) plus a raw session
token, or the user id, client IP and user agent of a new session.
Outputs: the raw token of a new session (``create_session``), the
``AuthenticatedSession`` of a usable session or None (``resolve_session``),
nothing (``revoke_session``).

Security notes:
- The one Principal builder: this is the only module that builds an
  ``access.Principal`` (tests/test_access.py allowlists it), and it builds it
  from the session's users row only, never from request data.
  ``resolve_session`` takes nothing but the executor and the token.
- Re-checked on every request: one query re-reads the session, the user and
  the org, and the decision is made here on each call. A revoked or expired
  session, a user that isn't active or is deleted, or a member of an org that
  isn't active (deactivated, pending deletion) resolves to None at once.
- Fail closed: a row that fails Principal validation resolves to None.
- Only the token's hash is stored or queried; the raw token is never logged
  and never sent to the database. A token that can't be a
  ``secrets.token_urlsafe(32)`` value is refused without a query.
- Parameterized SQL only: values travel as bind parameters.
- Imports nothing from the server, agent, LLM, tools or OAuth layers.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol

from pydantic import ValidationError

from admino.access import PlainUUID, Principal, SealedModel

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME: Final = "admino_session"
SESSION_LIFETIME: Final = timedelta(hours=12)
USER_AGENT_MAX_LENGTH: Final = 256

_TOKEN_BYTES: Final = 32  # 256 bits
# What secrets.token_urlsafe(32) produces: 43 URL-safe base64 characters.
_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9_-]{43}")

_INSERT_SQL: Final = """
    INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent)
    VALUES ($1, $2, $3, $4::inet, $5)
"""

# LEFT JOIN: a Super Admin belongs to no organization.
_RESOLVE_SQL: Final = """
    SELECT s.id AS session_id,
           s.revoked_at,
           s.expires_at,
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
    WHERE s.token_hash = $1
"""

_REVOKE_SQL: Final = """
    UPDATE sessions SET revoked_at = now()
    WHERE token_hash = $1 AND revoked_at IS NULL
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


async def create_session(
    executor: Executor, *, user_id: UUID, ip: str | None, user_agent: str | None
) -> str:
    """Open a session for a user and return its raw token (for the cookie).

    One parameterized INSERT stores the token's hash, the user id, the expiry
    (now + ``SESSION_LIFETIME``), the client IP (NULL when it isn't an IP
    address) and the user agent truncated to ``USER_AGENT_MAX_LENGTH``
    characters. The raw token is never stored or logged.

    Args:
        executor: The pool or a connection (inside the caller's transaction).
        user_id: The account the session belongs to.
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
        datetime.now(UTC) + SESSION_LIFETIME,
        _client_ip(ip),
        None if user_agent is None else user_agent[:USER_AGENT_MAX_LENGTH],
    )
    return token


async def resolve_session(executor: Executor, token: str) -> AuthenticatedSession | None:
    """Resolve a session token to its logged-in user, re-checking the account.

    Args:
        executor: The pool or a connection.
        token: The raw token from the session cookie.

    Returns:
        The AuthenticatedSession, or None when the token is malformed or
        unknown, the session is revoked or expired, the user isn't active or
        is deleted, the user is a member of an org that isn't active, or the
        row doesn't form a valid Principal.
    """
    if not _is_plausible_token(token):
        return None
    row = await executor.fetchrow(_RESOLVE_SQL, hash_session_token(token))
    if row is None or row["revoked_at"] is not None:
        return None
    expires_at = row["expires_at"]
    if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
        return None
    if expires_at <= datetime.now(UTC):
        return None
    if row["status"] != "active" or row["deleted_at"] is not None:
        return None
    if row["kind"] == "member" and row["org_status"] != "active":
        return None
    try:
        principal = Principal(
            user_id=row["user_id"], kind=row["kind"], org_id=row["org_id"], role=row["role"]
        )
        return AuthenticatedSession(
            session_id=row["session_id"],
            principal=principal,
            ui_language=row["ui_language"],
            response_language=row["response_language"],
        )
    except ValidationError:
        # No IDs or values: the row is inconsistent, and access is refused.
        logger.warning("A session row failed validation; the session is refused.")
        return None


async def revoke_session(executor: Executor, token: str) -> None:
    """Revoke the session behind a token (a malformed token touches nothing).

    Args:
        executor: The pool or a connection.
        token: The raw token from the session cookie.
    """
    if not _is_plausible_token(token):
        return
    await executor.execute(_REVOKE_SQL, hash_session_token(token))
