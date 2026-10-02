"""OAuth token management for admino: per-user connections and access tokens.

Handles encrypted storage of OAuth refresh tokens for Google and Microsoft
using Fernet symmetric encryption, manages token refresh via each
provider's OAuth2 token endpoint, and caches the short-lived access tokens
per user.

Storage (GH-86, GH-162): refresh tokens live in the PostgreSQL
``oauth_tokens`` table (migration 0017), one row per user and provider: each
user connects their own Google and Microsoft accounts. Only the Fernet
ciphertext is stored in the database — the plaintext refresh token never
touches the DB, and the encryption key stays in the ``OAUTH_ENCRYPTION_KEY``
environment variable, never persisted.

Inputs: an asyncpg ``Pool`` and the caller's ``TenantContext`` (every
persistence and refresh function takes both, in that order), a provider
(``"google"`` or ``"microsoft"``, no default), an httpx client for the
provider calls. Outputs: ``OAuthToken`` rows, (connected, healthy) flags,
access tokens. Errors: ``OAuthError`` / ``OAuthRefreshError`` with safe
messages.

Access tokens (GH-162): never stored in the database. ``access_tokens`` is
the one process-wide ``AccessTokenCache``, keyed by (user_id, provider):
bounded LRU (``ACCESS_TOKEN_CACHE_MAX`` entries), one lock per key, and
``invalidate`` drops a user's entry on connect and disconnect.

Security notes:
- Tenant isolation: every statement on ``oauth_tokens`` binds the caller's
  user_id AND org_id, both taken from the ``TenantContext`` (never from a
  token model or a request value), so one user's row is never read, used,
  changed or deleted for another user, or for the right user in another org.
- The access-token cache never hands one key's token to another key: keys
  are (user_id, provider), different keys never wait on each other, and an
  invalidation during an in-flight refresh keeps that refresh's token out of
  the cache. Errors propagate unchanged and cache nothing.
- The Fernet encryption key is read exclusively from the
  ``OAUTH_ENCRYPTION_KEY`` environment variable. It is never logged,
  stored in the database in plaintext, or included in error messages.
- All SQL is parameterized ($1, $2, ...) — no string interpolation.
- No credentials (access tokens, refresh tokens, client secrets, Fernet
  keys), emails or user ids appear in log output or raised exception
  messages.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Final, Literal
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, Field, ValidationError

if TYPE_CHECKING:
    from uuid import UUID

    import asyncpg

    from admino.tenancy import TenantContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider type
# ---------------------------------------------------------------------------

OAuthProvider = Literal["google", "microsoft"]

# ---------------------------------------------------------------------------
# Google OAuth2 endpoints and scopes
# ---------------------------------------------------------------------------

GOOGLE_TOKEN_ENDPOINT: str = "https://oauth2.googleapis.com/token"  # noqa: S105
GOOGLE_AUTH_ENDPOINT: str = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_USERINFO_ENDPOINT: str = "https://www.googleapis.com/oauth2/v2/userinfo"
GOOGLE_REVOKE_ENDPOINT: str = "https://oauth2.googleapis.com/revoke"

# Scopes: broad at the API level — the agent's permission engine (permissions.py
# hardcoded denials + the DB-backed permission rules) is the actual access
# control layer.
# This avoids re-running the OAuth consent flow when enabling new agent actions.
# gmail.modify: read + send + draft + label (no permanent delete via API).
# calendar.events: read + create + update + delete.
# drive: full read/write/delete.
GOOGLE_SCOPES: list[str] = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/drive",
]

# ---------------------------------------------------------------------------
# Microsoft OAuth2 endpoints and scopes (Azure AD v2.0)
# ---------------------------------------------------------------------------

MICROSOFT_TOKEN_ENDPOINT: str = "https://login.microsoftonline.com/common/oauth2/v2.0/token"  # noqa: S105
MICROSOFT_AUTH_ENDPOINT: str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"

# Scopes: broad at the API level — the agent's permission engine is the actual
# access control layer. This avoids re-running OAuth consent when enabling new actions.
# Mail.ReadWrite: read + draft + CRUD. Mail.Send: required for /me/sendMail.
# Calendars.ReadWrite: read + create + update + delete.
# Files.ReadWrite: read + write + delete. offline_access: allows token refresh.
MICROSOFT_SCOPES: list[str] = [
    "Mail.ReadWrite",
    "Mail.Send",
    "Calendars.ReadWrite",
    "Files.ReadWrite",
    "offline_access",
]

# ---------------------------------------------------------------------------
# Known providers
# ---------------------------------------------------------------------------

_KNOWN_PROVIDERS: frozenset[str] = frozenset({"google", "microsoft"})

# Refresh buffer: refresh if token expires within this many seconds
_EXPIRY_BUFFER_SECONDS: int = 60

# Maximum accepted expires_in from token endpoint (seconds).
# Google's standard is 3600. Microsoft's default is 3600-5400.
_MAX_TOKEN_LIFETIME_S: int = 7200


class OAuthError(Exception):
    """Raised when an OAuth operation fails.

    Error messages are safe for logging — they never contain credentials,
    tokens, or encryption keys.
    """


class OAuthRefreshError(OAuthError):
    """Raised when an access-token refresh fails.

    The ``terminal`` flag distinguishes a permanently dead authorization
    (e.g. the refresh token was revoked or expired — ``invalid_grant``),
    which requires the user to reconnect the account, from a transient
    failure (network error, provider 5xx) that may succeed on retry.

    Only terminal failures cause the on-disk token to be flagged invalid.
    """

    def __init__(self, message: str, *, terminal: bool) -> None:
        super().__init__(message)
        self.terminal = terminal


# Token-endpoint error codes that mean the refresh token is permanently dead.
# Both Google and Microsoft return ``invalid_grant`` for expired/revoked
# refresh tokens. Anything else (5xx, rate limits, network) is transient.
_TERMINAL_REFRESH_ERRORS: frozenset[str] = frozenset({"invalid_grant"})


class OAuthToken(BaseModel):
    """Database-backed representation of an encrypted OAuth token.

    Mirrors a row of the ``oauth_tokens`` table, without its owner: the
    user_id and org_id always come from the caller's ``TenantContext``. The
    ``encrypted_refresh_token`` field holds the Fernet-encrypted refresh
    token as a string (ciphertext only). Access tokens are never stored in
    this model or in the database.
    """

    provider: str = Field(
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]*$",
        description="OAuth provider identifier (google or microsoft).",
    )
    scopes: list[Annotated[str, Field(max_length=512)]] = Field(
        max_length=50,
        description="OAuth scopes granted by the user (provider-controlled, bounded).",
    )
    encrypted_refresh_token: str = Field(
        min_length=1,
        max_length=4096,
        description="Fernet-encrypted refresh token (base64-encoded ciphertext).",
    )
    email: str | None = Field(
        default=None,
        max_length=254,
        description="The connected account's email address, for display only.",
    )
    created_at: datetime = Field(
        description="UTC timestamp when the token was first created.",
    )
    last_refreshed_at: datetime = Field(
        description="UTC timestamp of the most recent token refresh.",
    )
    healthy: bool = Field(
        default=True,
        description=(
            "True if the refresh token is believed valid. Flipped to False "
            "on a terminal invalid_grant refresh failure (the saved "
            "authorization was revoked or expired), which the UI surfaces "
            "as a reconnect-required state."
        ),
    )


# ---------------------------------------------------------------------------
# Fernet encryption helpers
# ---------------------------------------------------------------------------


def _get_fernet() -> Fernet:
    """Create a Fernet instance from the OAUTH_ENCRYPTION_KEY env var.

    Returns:
        A Fernet instance for encryption/decryption.

    Raises:
        OAuthError: If the env var is missing or not a valid Fernet key.
    """
    key = os.environ.get("OAUTH_ENCRYPTION_KEY")
    if not key:
        msg = "OAUTH_ENCRYPTION_KEY environment variable is not set."
        raise OAuthError(msg)
    try:
        # Strip whitespace to tolerate trailing newlines from copy-paste or .env files
        return Fernet(key.strip().encode())
    except (ValueError, TypeError) as exc:
        msg = "OAUTH_ENCRYPTION_KEY is not a valid Fernet key."
        raise OAuthError(msg) from exc


def encrypt_refresh_token(refresh_token: str) -> str:
    """Encrypt a refresh token using Fernet.

    Args:
        refresh_token: The plaintext refresh token.

    Returns:
        The Fernet-encrypted token as a string.

    Raises:
        OAuthError: If the encryption key is missing or invalid.
    """
    fernet = _get_fernet()
    return fernet.encrypt(refresh_token.encode()).decode("utf-8")


def decrypt_refresh_token(token: OAuthToken) -> str:
    """Decrypt the refresh token from an OAuthToken.

    Args:
        token: A loaded OAuthToken with an encrypted refresh token.

    Returns:
        The decrypted refresh token string.

    Raises:
        OAuthError: If decryption fails (bad key or corrupted ciphertext).
    """
    fernet = _get_fernet()
    try:
        decrypted = fernet.decrypt(token.encrypted_refresh_token.encode())
        return decrypted.decode("utf-8")
    except InvalidToken as exc:
        msg = "Failed to decrypt refresh token. Check OAUTH_ENCRYPTION_KEY."
        raise OAuthError(msg) from exc


# ---------------------------------------------------------------------------
# Token persistence (PostgreSQL, one row per user and provider)
# ---------------------------------------------------------------------------

_LOAD_SQL: Final = """
    SELECT provider, scopes, encrypted_refresh_token, email, healthy, created_at,
           last_refreshed_at
    FROM oauth_tokens
    WHERE user_id = $1 AND org_id = $2 AND provider = $3
"""
# The upsert never changes the row's owner, provider or created_at.
_SAVE_SQL: Final = """
    INSERT INTO oauth_tokens (user_id, org_id, provider, encrypted_refresh_token, email,
                              scopes, healthy, created_at, last_refreshed_at)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
    ON CONFLICT (user_id, provider) DO UPDATE SET
        encrypted_refresh_token = EXCLUDED.encrypted_refresh_token,
        email = EXCLUDED.email,
        scopes = EXCLUDED.scopes,
        healthy = EXCLUDED.healthy,
        last_refreshed_at = EXCLUDED.last_refreshed_at
"""
_DELETE_SQL: Final = """
    DELETE FROM oauth_tokens WHERE user_id = $1 AND org_id = $2 AND provider = $3
"""


async def load_token(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    provider: OAuthProvider,
) -> OAuthToken | None:
    """Read the caller's own token row for a provider.

    The ``encrypted_refresh_token`` field remains encrypted in the returned
    model. Use ``decrypt_refresh_token`` to obtain the plaintext.

    Args:
        pool: An asyncpg connection pool.
        tenant: The caller's org scope (its user_id and org_id are bound).
        provider: OAuth provider name.

    Returns:
        An OAuthToken instance, or None if the caller has no row for the
        provider in their org.

    Raises:
        OAuthError: If a row exists but cannot be parsed.
    """
    row = await pool.fetchrow(_LOAD_SQL, tenant.user_id, tenant.org_id, provider)
    if row is None:
        return None
    try:
        # asyncpg may return the JSONB scopes column as a JSON string or as
        # an already-decoded list depending on codec configuration.
        raw_scopes = row["scopes"]
        scopes = json.loads(raw_scopes) if isinstance(raw_scopes, str) else raw_scopes
        return OAuthToken(
            provider=row["provider"],
            scopes=scopes,
            encrypted_refresh_token=row["encrypted_refresh_token"],
            email=row["email"],
            healthy=row["healthy"],
            created_at=row["created_at"],
            last_refreshed_at=row["last_refreshed_at"],
        )
    except (json.JSONDecodeError, ValueError, ValidationError) as exc:
        msg = f"Failed to parse {provider} token row."
        raise OAuthError(msg) from exc


async def save_token(pool: asyncpg.Pool, tenant: TenantContext, token: OAuthToken) -> None:
    """Persist the caller's token row via an UPSERT keyed on (user_id, provider).

    Args:
        pool: An asyncpg connection pool.
        tenant: The caller's org scope: the row is stored under its user_id
            and org_id.
        token: The OAuthToken to persist. The ``encrypted_refresh_token``
            field must already be encrypted.

    Raises:
        OAuthError: If the provider is unknown (before any statement) or the
            write fails.

    Security notes:
        Only the Fernet ciphertext is written — the plaintext refresh token
        never reaches the database. All values are bound as parameters; an
        existing row keeps its owner and created_at.
    """
    import asyncpg

    if token.provider not in _KNOWN_PROVIDERS:
        msg = f"Unknown provider: {token.provider}"
        raise OAuthError(msg)

    try:
        await pool.execute(
            _SAVE_SQL,
            tenant.user_id,
            tenant.org_id,
            token.provider,
            token.encrypted_refresh_token,
            token.email,
            json.dumps(token.scopes),
            token.healthy,
            token.created_at,
            token.last_refreshed_at,
        )
    except asyncpg.PostgresError as exc:
        msg = "Failed to persist token."
        raise OAuthError(msg) from exc


async def delete_token(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    provider: OAuthProvider,
) -> bool:
    """Delete the caller's own token row for a provider.

    Args:
        pool: An asyncpg connection pool.
        tenant: The caller's org scope (its user_id and org_id are bound).
        provider: OAuth provider name.

    Returns:
        True if the caller's row existed and was deleted, False otherwise.

    Raises:
        OAuthError: If the DELETE fails.

    Security notes:
        No credentials are logged or included in error messages.
    """
    import asyncpg

    try:
        status = await pool.execute(_DELETE_SQL, tenant.user_id, tenant.org_id, provider)
    except asyncpg.PostgresError as exc:
        msg = "Failed to delete token."
        raise OAuthError(msg) from exc
    # asyncpg returns a status tag like "DELETE 1"; the trailing integer is
    # the number of rows removed.
    try:
        count = int(status.rsplit(" ", 1)[-1])
    except (ValueError, AttributeError):  # pragma: no cover - defensive
        return False
    return count > 0


async def revoke_and_delete_token(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    provider: OAuthProvider,
    http_client: httpx.AsyncClient,
) -> bool:
    """Revoke the caller's refresh token at the provider, then delete their row.

    Decrypts the refresh token from the caller's row, POSTs it to the
    provider's revocation endpoint (best-effort), then deletes the row. This
    ensures both the provider-side credential and the local copy are
    invalidated during account disconnection. Without a row of the caller's,
    nothing is revoked or deleted.

    If revocation fails (network error, provider error), the row is still
    deleted and a warning is logged. The disconnect proceeds regardless so
    the user is not stuck.

    Args:
        pool: An asyncpg connection pool.
        tenant: The caller's org scope (its user_id and org_id are bound).
        provider: OAuth provider name (``"google"`` or ``"microsoft"``).
        http_client: An httpx async client for the revocation request.

    Returns:
        True if the caller's row existed and was deleted, False if none
        existed.

    Raises:
        OAuthError: If the row exists but deletion fails.

    Security notes:
        No credentials are logged or included in error messages.
    """
    token = await load_token(pool, tenant, provider)
    if token is None:
        return False

    # Best-effort revocation: decrypt and POST to provider endpoint.
    try:
        refresh_tok = decrypt_refresh_token(token)
        if provider == "google":
            await _revoke_google_token(refresh_tok, http_client)
        else:
            await _revoke_microsoft_token(refresh_tok, http_client)
    except OAuthError:
        logger.warning(
            "Provider-side token revocation failed for %s; proceeding with local delete.",
            provider,
        )

    # Always delete the DB row regardless of revocation outcome.
    return await delete_token(pool, tenant, provider)


async def _revoke_google_token(
    token: str,
    http_client: httpx.AsyncClient,
) -> None:
    """Revoke a Google OAuth token via the revocation endpoint.

    Args:
        token: The refresh (or access) token to revoke.
        http_client: An httpx async client.

    Raises:
        OAuthError: If the HTTP request fails or the provider returns an error.

    Security notes:
        No credentials are logged or included in error messages.
    """
    try:
        response = await http_client.post(
            GOOGLE_REVOKE_ENDPOINT,
            data={"token": token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except httpx.HTTPError as exc:
        msg = "HTTP request to Google revocation endpoint failed."
        raise OAuthError(msg) from exc

    if response.status_code != 200:
        error_code = _safe_error_code(response)
        logger.warning(
            "Google token revocation returned status %d (error=%s).",
            response.status_code,
            error_code,
        )
        msg = "Google token revocation failed."
        raise OAuthError(msg)

    logger.info("Google token revoked at provider.")


async def _revoke_microsoft_token(
    refresh_token: str,
    http_client: httpx.AsyncClient,
) -> None:
    """Revoke a Microsoft OAuth refresh token via the logout endpoint.

    Microsoft's OAuth2 v2.0 does not have a dedicated per-token
    revocation endpoint. We call the logout endpoint for defense-in-depth.
    The refresh token parameter is accepted for API symmetry with the
    Google revocation function but is not sent to Microsoft.

    Args:
        refresh_token: The decrypted refresh token (unused by Microsoft).
        http_client: An httpx async client.

    Raises:
        OAuthError: If the HTTP request fails.

    Security notes:
        No credentials are logged or included in error messages.
    """
    try:
        response = await http_client.get(
            "https://login.microsoftonline.com/common/oauth2/v2.0/logout",
        )
    except httpx.HTTPError as exc:
        msg = "HTTP request to Microsoft logout endpoint failed."
        raise OAuthError(msg) from exc

    # Microsoft logout endpoint typically returns 200 or 302; either is acceptable.
    if response.status_code >= 400:
        logger.warning("Microsoft logout endpoint returned status %d.", response.status_code)
        msg = "Microsoft token revocation failed."
        raise OAuthError(msg)

    logger.info("Microsoft logout endpoint called successfully.")


def _safe_error_code(response: httpx.Response) -> str:
    """Extract the ``error`` field from a JSON error response.

    Returns the error code string (e.g. ``invalid_grant``) or ``"unknown"``
    if the response is not JSON or lacks an ``error`` field. Never returns
    credential material — only the error code.
    """
    try:
        body = response.json()
        if isinstance(body, dict):
            code = body.get("error", "unknown")
            # Strip control characters (newlines, ANSI escapes) and Unicode format
            # characters (BiDi overrides, zero-width spaces) to prevent log injection.
            sanitized = "".join(
                c for c in str(code) if c.isprintable() and unicodedata.category(c) != "Cf"
            )
            return sanitized[:64]
    except (json.JSONDecodeError, ValueError):
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Google OAuth helpers
# ---------------------------------------------------------------------------


def _get_google_client_credentials() -> tuple[str, str]:
    """Read Google OAuth client credentials from environment variables.

    Returns:
        A (client_id, client_secret) tuple.

    Raises:
        OAuthError: If either env var is missing.
    """
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    if not client_id:
        msg = "GOOGLE_CLIENT_ID environment variable is not set."
        raise OAuthError(msg)
    if not client_secret:
        msg = "GOOGLE_CLIENT_SECRET environment variable is not set."
        raise OAuthError(msg)
    return client_id, client_secret


def build_google_consent_url(redirect_uri: str) -> tuple[str, str]:
    """Build the Google OAuth consent URL with CSRF ``state`` parameter.

    A cryptographically random ``state`` token is generated and included
    in the URL for CSRF protection (RFC 6749 section 10.12).

    Args:
        redirect_uri: The redirect URI for the OAuth callback.

    Returns:
        A (url, state) tuple.

    Raises:
        OAuthError: If GOOGLE_CLIENT_ID is not set.
    """
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    if not client_id:
        msg = "GOOGLE_CLIENT_ID environment variable is not set."
        raise OAuthError(msg)

    state = secrets.token_urlsafe(32)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(GOOGLE_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}", state


async def exchange_google_code(
    code: str,
    redirect_uri: str,
    http_client: httpx.AsyncClient,
) -> tuple[str, str, list[str]]:
    """Exchange a Google authorization code for access and refresh tokens.

    Args:
        code: The authorization code from the OAuth consent flow.
        redirect_uri: The redirect URI used in the consent URL.
        http_client: An httpx async client for making the HTTP request.

    Returns:
        A tuple of (access_token, refresh_token, scopes).

    Raises:
        OAuthError: If the exchange fails or the response is malformed.
    """
    client_id, client_secret = _get_google_client_credentials()

    try:
        response = await http_client.post(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except httpx.HTTPError as exc:
        msg = "HTTP request to Google token endpoint failed during code exchange."
        raise OAuthError(msg) from exc

    if response.status_code != 200:
        error_code = _safe_error_code(response)
        logger.error(
            "Google token exchange failed with status %d (error=%s).",
            response.status_code,
            error_code,
        )
        msg = "Google token exchange failed. Check client credentials and auth code."
        raise OAuthError(msg)

    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        msg = "Google token endpoint returned invalid JSON."
        raise OAuthError(msg) from exc

    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    scope_str = data.get("scope", "")

    if not access_token or not refresh_token:
        msg = "Google token endpoint response missing access_token or refresh_token."
        raise OAuthError(msg)

    scopes = scope_str.split() if scope_str else []
    return access_token, refresh_token, scopes


async def _refresh_google_token(
    refresh_token: str,
    http_client: httpx.AsyncClient,
) -> tuple[str, int]:
    """Refresh a Google access token using the refresh token.

    Args:
        refresh_token: The decrypted refresh token.
        http_client: An httpx async client.

    Returns:
        A (access_token, expires_in_seconds) tuple.

    Raises:
        OAuthError: If refresh fails.
    """
    client_id, client_secret = _get_google_client_credentials()

    try:
        response = await http_client.post(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except httpx.HTTPError as exc:
        msg = "HTTP request to Google token endpoint failed during refresh."
        raise OAuthError(msg) from exc

    if response.status_code != 200:
        error_code = _safe_error_code(response)
        logger.error(
            "Google token refresh failed with status %d (error=%s).",
            response.status_code,
            error_code,
        )
        terminal = error_code in _TERMINAL_REFRESH_ERRORS
        if terminal:
            msg = (
                "Google token refresh failed: the saved authorization has expired or been revoked."
            )
        else:
            msg = "Google token refresh failed due to a transient token-endpoint error."
        raise OAuthRefreshError(msg, terminal=terminal)

    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        msg = "Google token endpoint returned invalid JSON during refresh."
        raise OAuthError(msg) from exc

    access_token = data.get("access_token")
    expires_in = data.get("expires_in")

    if not access_token:
        msg = "Google token refresh response missing access_token."
        raise OAuthError(msg)

    if not isinstance(expires_in, int) or expires_in <= 0:
        expires_in = 3600

    return access_token, min(expires_in, _MAX_TOKEN_LIFETIME_S)


async def get_google_user_email(
    access_token: str,
    http_client: httpx.AsyncClient,
) -> str | None:
    """Fetch the authenticated Google user's email address.

    Calls the Google userinfo endpoint with the provided access token
    and returns the ``email`` field from the JSON response.

    This function never raises — all errors are caught and logged, and
    ``None`` is returned on any failure. This makes it safe to call in
    non-critical paths (e.g. displaying the connected account) without
    risking an unhandled exception.

    Args:
        access_token: A valid Google OAuth2 access token.
        http_client: An httpx async client for making the HTTP request.

    Returns:
        The user's email address as a string, or None on any failure.

    Security notes:
        No credentials (access tokens) are included in log output.
    """
    try:
        response = await http_client.get(
            GOOGLE_USERINFO_ENDPOINT,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    except httpx.HTTPError:
        logger.warning("HTTP request to Google userinfo endpoint failed.")
        return None

    if response.status_code != 200:
        logger.warning(
            "Google userinfo endpoint returned status %d.",
            response.status_code,
        )
        return None

    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError):
        logger.warning("Google userinfo endpoint returned invalid JSON.")
        return None

    email = data.get("email") if isinstance(data, dict) else None
    if not isinstance(email, str) or not email:
        logger.warning("Google userinfo response missing email field.")
        return None

    return email


# ---------------------------------------------------------------------------
# Microsoft OAuth helpers
# ---------------------------------------------------------------------------


def _get_microsoft_client_credentials() -> tuple[str, str]:
    """Read Microsoft OAuth client credentials from environment variables.

    Returns:
        A (client_id, client_secret) tuple.

    Raises:
        OAuthError: If either env var is missing.
    """
    client_id = os.environ.get("MICROSOFT_CLIENT_ID")
    client_secret = os.environ.get("MICROSOFT_CLIENT_SECRET")
    if not client_id:
        msg = "MICROSOFT_CLIENT_ID environment variable is not set."
        raise OAuthError(msg)
    if not client_secret:
        msg = "MICROSOFT_CLIENT_SECRET environment variable is not set."
        raise OAuthError(msg)
    return client_id, client_secret


def build_microsoft_consent_url(redirect_uri: str) -> tuple[str, str]:
    """Build the Microsoft OAuth consent URL with CSRF ``state`` parameter.

    Uses the Azure AD v2.0 authorization endpoint.

    Args:
        redirect_uri: The redirect URI for the OAuth callback.

    Returns:
        A (url, state) tuple.

    Raises:
        OAuthError: If MICROSOFT_CLIENT_ID is not set.
    """
    client_id = os.environ.get("MICROSOFT_CLIENT_ID")
    if not client_id:
        msg = "MICROSOFT_CLIENT_ID environment variable is not set."
        raise OAuthError(msg)

    state = secrets.token_urlsafe(32)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(MICROSOFT_SCOPES),
        "response_mode": "query",
        "prompt": "consent",
        "state": state,
    }
    return f"{MICROSOFT_AUTH_ENDPOINT}?{urlencode(params)}", state


async def exchange_microsoft_code(
    code: str,
    redirect_uri: str,
    http_client: httpx.AsyncClient,
) -> tuple[str, str, list[str]]:
    """Exchange a Microsoft authorization code for access and refresh tokens.

    Args:
        code: The authorization code from the OAuth consent flow.
        redirect_uri: The redirect URI used in the consent URL.
        http_client: An httpx async client for making the HTTP request.

    Returns:
        A tuple of (access_token, refresh_token, scopes).

    Raises:
        OAuthError: If the exchange fails or the response is malformed.
    """
    client_id, client_secret = _get_microsoft_client_credentials()

    try:
        response = await http_client.post(
            MICROSOFT_TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "scope": " ".join(MICROSOFT_SCOPES),
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except httpx.HTTPError as exc:
        msg = "HTTP request to Microsoft token endpoint failed during code exchange."
        raise OAuthError(msg) from exc

    if response.status_code != 200:
        error_code = _safe_error_code(response)
        logger.error(
            "Microsoft token exchange failed with status %d (error=%s).",
            response.status_code,
            error_code,
        )
        msg = "Microsoft token exchange failed. Check client credentials and auth code."
        raise OAuthError(msg)

    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        msg = "Microsoft token endpoint returned invalid JSON."
        raise OAuthError(msg) from exc

    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    scope_str = data.get("scope", "")

    if not access_token or not refresh_token:
        msg = "Microsoft token endpoint response missing access_token or refresh_token."
        raise OAuthError(msg)

    scopes = scope_str.split() if scope_str else []
    return access_token, refresh_token, scopes


async def _refresh_microsoft_token(
    refresh_token: str,
    http_client: httpx.AsyncClient,
) -> tuple[str, int]:
    """Refresh a Microsoft access token using the refresh token.

    Args:
        refresh_token: The decrypted refresh token.
        http_client: An httpx async client.

    Returns:
        A (access_token, expires_in_seconds) tuple.

    Raises:
        OAuthError: If refresh fails.
    """
    client_id, client_secret = _get_microsoft_client_credentials()

    try:
        response = await http_client.post(
            MICROSOFT_TOKEN_ENDPOINT,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "scope": " ".join(MICROSOFT_SCOPES),
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except httpx.HTTPError as exc:
        msg = "HTTP request to Microsoft token endpoint failed during refresh."
        raise OAuthError(msg) from exc

    if response.status_code != 200:
        error_code = _safe_error_code(response)
        logger.error(
            "Microsoft token refresh failed with status %d (error=%s).",
            response.status_code,
            error_code,
        )
        terminal = error_code in _TERMINAL_REFRESH_ERRORS
        if terminal:
            msg = (
                "Microsoft token refresh failed: the saved authorization has expired "
                "or been revoked."
            )
        else:
            msg = "Microsoft token refresh failed due to a transient token-endpoint error."
        raise OAuthRefreshError(msg, terminal=terminal)

    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        msg = "Microsoft token endpoint returned invalid JSON during refresh."
        raise OAuthError(msg) from exc

    access_token = data.get("access_token")
    expires_in = data.get("expires_in")

    if not access_token:
        msg = "Microsoft token refresh response missing access_token."
        raise OAuthError(msg)

    if not isinstance(expires_in, int) or expires_in <= 0:
        expires_in = 3600

    return access_token, min(expires_in, _MAX_TOKEN_LIFETIME_S)


# ---------------------------------------------------------------------------
# Unified token refresh (used by tool modules)
# ---------------------------------------------------------------------------


async def get_valid_access_token(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    provider: OAuthProvider,
    cached_token: str | None,
    cached_expires_at: datetime | None,
    http_client: httpx.AsyncClient,
) -> tuple[str, datetime]:
    """Return a valid access token for the caller's connection, refreshing if needed.

    If ``cached_token`` is still valid (not expired within the 60-second
    buffer), it is returned as-is. Otherwise, the caller's own refresh token
    is loaded from the database, decrypted, and used to obtain a new access
    token from the provider's token endpoint. The outcome (a terminal failure
    flags the row unhealthy, a success marks it healthy and refreshed) is
    written to the caller's row only.

    Args:
        pool: An asyncpg connection pool.
        tenant: The caller's org scope (whose connection is used).
        provider: OAuth provider ("google" or "microsoft").
        cached_token: The caller's currently cached access token, or None.
        cached_expires_at: Expiry time of the cached token, or None.
        http_client: An httpx async client for the refresh request.

    Returns:
        A (access_token, expires_at) tuple. The caller must cache these
        and pass them back on the next call (``AccessTokenCache`` does).

    Raises:
        OAuthError: If the caller has no token row or refresh fails.
    """
    now = datetime.now(UTC)

    # Return cached token if still valid (with 60-second buffer)
    if (
        cached_token is not None
        and cached_expires_at is not None
        and cached_expires_at > now + timedelta(seconds=_EXPIRY_BUFFER_SECONDS)
    ):
        return cached_token, cached_expires_at

    # Need to refresh — load and decrypt the refresh token
    token = await load_token(pool, tenant, provider)
    if token is None:
        msg = f"No {provider} account is connected."
        raise OAuthError(msg)

    refresh_tok = decrypt_refresh_token(token)

    # Dispatch to provider-specific refresh. A terminal failure (the refresh
    # token is dead) flags the token unhealthy in the DB so the UI can surface
    # a reconnect-required state; transient failures leave the flag untouched.
    try:
        if provider == "google":
            access_token, expires_in = await _refresh_google_token(refresh_tok, http_client)
        else:
            access_token, expires_in = await _refresh_microsoft_token(refresh_tok, http_client)
    except OAuthRefreshError as exc:
        if exc.terminal and token.healthy:
            token.healthy = False
            try:
                await save_token(pool, tenant, token)
            except OAuthError:
                logger.warning("Failed to persist unhealthy flag for %s token.", provider)
        raise

    expires_at = now + timedelta(seconds=expires_in)

    # Refresh succeeded — clear any stale unhealthy flag (recovery) and update
    # last_refreshed_at in the DB.
    token.healthy = True
    token.last_refreshed_at = now
    try:
        await save_token(pool, tenant, token)
    except OAuthError:
        # Non-fatal: log but don't fail the refresh
        logger.warning("Failed to update last_refreshed_at for %s token.", provider)

    logger.info("%s OAuth access token refreshed successfully.", provider.capitalize())
    return access_token, expires_at


async def get_connection_status(
    pool: asyncpg.Pool,
    tenant: TenantContext,
    provider: OAuthProvider,
) -> tuple[bool, bool]:
    """Return ``(connected, healthy)`` of the caller's connection from DB state only.

    ``connected`` is True when the caller has a token row for the provider
    (another user's row never counts).
    ``healthy`` is True when that row exists and its ``healthy`` flag is set
    (its refresh token is still believed valid). A dead/revoked refresh
    token — detected at tool-call time and persisted via ``healthy=False`` —
    or a row whose ciphertext cannot be decrypted yields ``(True, False)``,
    which the UI renders as "Not connected".

    This reads only the DB row and performs no network calls, so it never
    blocks the settings page load.

    Args:
        pool: An asyncpg connection pool.
        tenant: The caller's org scope (its user_id and org_id are bound).
        provider: OAuth provider name.

    Returns:
        A ``(connected, healthy)`` tuple.

    Security notes:
        No credentials are read into the response — only the boolean flags.
    """
    try:
        token = await load_token(pool, tenant, provider)
    except OAuthError:
        # A corrupt/unparseable token row exists but cannot be trusted —
        # report connected-but-unhealthy so the UI prompts a reconnect.
        return True, False
    if token is None:
        return False, False
    if not token.healthy:
        return True, False
    # A row that cannot be decrypted (e.g. rotated key) is connected but
    # unhealthy — surface a reconnect prompt rather than a hard failure.
    try:
        decrypt_refresh_token(token)
    except OAuthError:
        return True, False
    return True, True


# ---------------------------------------------------------------------------
# Per-user access-token cache (used by the tool modules)
# ---------------------------------------------------------------------------

# At most this many (user_id, provider) access tokens are cached at once.
ACCESS_TOKEN_CACHE_MAX: Final[int] = 512

# (user_id, provider)
type _CacheKey = tuple[UUID, str]


@dataclass(slots=True)
class _KeyState:
    """The lock of one cache key while gets of it are in flight.

    ``holders`` counts the gets holding or waiting for the lock (the state is
    dropped when it reaches 0, so the states stay bounded by the in-flight
    gets). ``generation`` grows on every invalidation of the key: a refresh
    that started under an older generation doesn't store its token.
    """

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    holders: int = 0
    generation: int = 0


class AccessTokenCache:
    """Short-lived access tokens per (user_id, provider): bounded LRU, one lock per key.

    ``get`` refreshes through ``get_valid_access_token`` with the key's cached
    token and expiry (which hands a still-valid token back as it is) and
    caches the result. Concurrent gets of one key run one at a time; gets of
    different keys never wait on each other. Access tokens live in this
    process's memory only and are never logged.
    """

    def __init__(self, max_entries: int = ACCESS_TOKEN_CACHE_MAX) -> None:
        """Create an empty cache holding at most ``max_entries`` keys."""
        self._max_entries = max_entries
        self._entries: OrderedDict[_CacheKey, tuple[str, datetime]] = OrderedDict()
        self._states: dict[_CacheKey, _KeyState] = {}

    async def get(
        self,
        pool: asyncpg.Pool,
        tenant: TenantContext,
        provider: OAuthProvider,
        http_client: httpx.AsyncClient,
    ) -> str:
        """Return a valid access token for the caller's connection to a provider.

        Marks the key most recently used; adding a key beyond the bound evicts
        the least recently used one.

        Args:
            pool: An asyncpg connection pool.
            tenant: The caller's org scope; its user_id keys the cache.
            provider: OAuth provider name.
            http_client: An httpx async client for the refresh request.

        Returns:
            The access token.

        Raises:
            OAuthError: Unchanged from ``get_valid_access_token`` (no
                connection, refresh failure); nothing is cached.
        """
        key: _CacheKey = (tenant.user_id, provider)
        state = self._states.get(key)
        if state is None:
            state = self._states[key] = _KeyState()
        state.holders += 1
        try:
            async with state.lock:
                generation = state.generation
                cached_token, cached_expires_at = self._entries.get(key, (None, None))
                token, expires_at = await get_valid_access_token(
                    pool, tenant, provider, cached_token, cached_expires_at, http_client
                )
                # An invalidation while the refresh ran (a disconnect, a
                # reconnect) keeps this token out of the cache.
                if state.generation == generation:
                    self._store(key, token, expires_at)
                return token
        finally:
            state.holders -= 1
            if state.holders == 0:
                del self._states[key]

    async def invalidate(self, user_id: UUID, provider: OAuthProvider) -> None:
        """Drop one user's cached token for a provider (connect and disconnect).

        A refresh of that key already in flight won't put its token back: the
        next ``get`` loads the connection from the database again.

        Args:
            user_id: The user whose entry goes.
            provider: OAuth provider name.
        """
        key: _CacheKey = (user_id, provider)
        self._entries.pop(key, None)
        state = self._states.get(key)
        if state is not None:
            state.generation += 1

    def clear(self) -> None:
        """Drop every entry (tests, shutdown); in-flight refreshes cache nothing."""
        self._entries.clear()
        for state in self._states.values():
            state.generation += 1

    def __len__(self) -> int:
        """Return the number of cached (user_id, provider) entries."""
        return len(self._entries)

    def _store(self, key: _CacheKey, token: str, expires_at: datetime) -> None:
        """Cache a key's token as the most recently used; evict beyond the bound."""
        self._entries[key] = (token, expires_at)
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)


# The process-wide cache the tool modules use.
access_tokens: Final[AccessTokenCache] = AccessTokenCache()
