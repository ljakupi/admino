"""OAuth token management for admino.

Handles encrypted storage of Google OAuth refresh tokens using Fernet
symmetric encryption, and manages token refresh via Google's OAuth2
token endpoint.

Storage format (on disk as ``{tokens_dir}/google.json``):
- ``provider``, ``scopes``, ``encrypted_refresh_token``, ``created_at``,
  ``last_refreshed_at``.
- Access tokens are NEVER written to disk — they are held in-memory only
  by the caller.

Security notes:
- The Fernet encryption key is read exclusively from the
  ``OAUTH_ENCRYPTION_KEY`` environment variable. It is never logged,
  stored on disk in plaintext, or included in error messages.
- Token files are created with mode 0o600 (owner read/write only).
- The tokens directory is created with mode 0o700 if it does not exist.
- No credentials (access tokens, refresh tokens, client secrets, Fernet
  keys) appear in log output or raised exception messages.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, Field, ValidationError

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# Google OAuth2 endpoints
GOOGLE_TOKEN_ENDPOINT: str = "https://oauth2.googleapis.com/token"  # noqa: S105
GOOGLE_AUTH_ENDPOINT: str = "https://accounts.google.com/o/oauth2/v2/auth"

# Scopes: narrowest possible per SEC-11.
# calendar.events covers both read and create (needed for calendar.create).
# calendar.events.readonly is intentionally omitted — it is a strict subset
# of calendar.events, so requesting both is redundant.
GOOGLE_SCOPES: list[str] = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/calendar.events",
]

# Token file name per provider
_TOKEN_FILENAME: str = "google.json"  # noqa: S105

# Refresh buffer: refresh if token expires within this many seconds
_EXPIRY_BUFFER_SECONDS: int = 60

# Maximum accepted expires_in from token endpoint (seconds).
# Google's standard is 3600. Anything higher is suspicious.
_MAX_TOKEN_LIFETIME_S: int = 3600


class OAuthError(Exception):
    """Raised when an OAuth operation fails.

    Error messages are safe for logging — they never contain credentials,
    tokens, or encryption keys.
    """


class TokenFile(BaseModel):
    """On-disk representation of an encrypted OAuth token file.

    Matches the storage format defined in Section 3.6 of the requirements.
    The ``encrypted_refresh_token`` field holds the Fernet-encrypted refresh
    token as a string. Access tokens are never stored in this model.
    """

    provider: str = Field(
        default="google",
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]*$",
        description="OAuth provider identifier.",
    )
    scopes: list[str] = Field(
        description="OAuth scopes granted by the user.",
    )
    encrypted_refresh_token: str = Field(
        min_length=1,
        max_length=4096,
        description="Fernet-encrypted refresh token (base64-encoded ciphertext).",
    )
    created_at: datetime = Field(
        description="UTC timestamp when the token was first created.",
    )
    last_refreshed_at: datetime = Field(
        description="UTC timestamp of the most recent token refresh.",
    )


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


def _get_client_credentials() -> tuple[str, str]:
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


def _token_file_path(tokens_dir: Path) -> Path:
    """Return the path to the Google token file.

    Args:
        tokens_dir: Directory where token files are stored.

    Returns:
        Path to ``google.json`` within the tokens directory.
    """
    return tokens_dir / _TOKEN_FILENAME


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
            # Truncate to prevent log injection from oversized error strings
            return str(code)[:64]
    except (json.JSONDecodeError, ValueError):
        pass
    return "unknown"


def load_token(tokens_dir: Path) -> TokenFile | None:
    """Read and parse the token file from disk.

    The ``encrypted_refresh_token`` field remains encrypted in the returned
    model. Use ``decrypt_refresh_token`` to obtain the plaintext.

    Args:
        tokens_dir: Directory containing token files.

    Returns:
        A TokenFile instance, or None if no token file exists.

    Raises:
        OAuthError: If the file exists but cannot be parsed.
    """
    path = _token_file_path(tokens_dir)
    if not path.is_file():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        return TokenFile.model_validate(data)
    except (json.JSONDecodeError, OSError, ValidationError) as exc:
        msg = "Failed to read or parse token file."
        raise OAuthError(msg) from exc


def decrypt_refresh_token(token_file: TokenFile) -> str:
    """Decrypt the refresh token from a TokenFile.

    Args:
        token_file: A loaded TokenFile with an encrypted refresh token.

    Returns:
        The decrypted refresh token string.

    Raises:
        OAuthError: If decryption fails (bad key or corrupted ciphertext).
    """
    fernet = _get_fernet()
    try:
        decrypted = fernet.decrypt(token_file.encrypted_refresh_token.encode())
        return decrypted.decode("utf-8")
    except InvalidToken as exc:
        msg = "Failed to decrypt refresh token. Check OAUTH_ENCRYPTION_KEY."
        raise OAuthError(msg) from exc


def save_token(tokens_dir: Path, token: TokenFile) -> None:
    """Write the token file to disk with restricted permissions.

    Creates the tokens directory (mode 0o700) if it does not exist.
    The token file is written with mode 0o600 (owner read/write only).

    Args:
        tokens_dir: Directory for token files.
        token: The TokenFile to persist. The ``encrypted_refresh_token``
            field must already be encrypted.

    Raises:
        OAuthError: If the file cannot be written.
    """
    try:
        tokens_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Explicit chmod to override umask — mkdir's mode parameter is
        # subject to the process umask, so the actual permissions may differ.
        tokens_dir.chmod(0o700)
    except OSError as exc:
        msg = "Failed to create tokens directory."
        raise OAuthError(msg) from exc

    path = _token_file_path(tokens_dir)
    try:
        data = token.model_dump_json(indent=2)
        # Atomic-permission write: open with 0o600 from the start to avoid
        # a TOCTOU window where the file is briefly world-readable.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
    except OSError as exc:
        msg = "Failed to write token file."
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


async def exchange_code(
    code: str,
    redirect_uri: str,
    http_client: httpx.AsyncClient,
) -> tuple[str, str, list[str]]:
    """Exchange an authorization code for access and refresh tokens.

    Posts to Google's token endpoint with the authorization code and
    client credentials.

    Args:
        code: The authorization code from the OAuth consent flow.
        redirect_uri: The redirect URI used in the consent URL.
        http_client: An httpx async client for making the HTTP request.

    Returns:
        A tuple of (access_token, refresh_token, scopes).

    Raises:
        OAuthError: If the exchange fails or the response is malformed.
    """
    client_id, client_secret = _get_client_credentials()

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
        msg = "HTTP request to token endpoint failed during code exchange."
        raise OAuthError(msg) from exc

    if response.status_code != 200:
        error_code = _safe_error_code(response)
        logger.error(
            "Token exchange failed with status %d (error=%s).",
            response.status_code,
            error_code,
        )
        msg = "Token exchange failed. Check client credentials and auth code."
        raise OAuthError(msg)

    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        msg = "Token endpoint returned invalid JSON."
        raise OAuthError(msg) from exc

    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    scope_str = data.get("scope", "")

    if not access_token or not refresh_token:
        msg = "Token endpoint response missing access_token or refresh_token."
        raise OAuthError(msg)

    scopes = scope_str.split() if scope_str else []
    return access_token, refresh_token, scopes


async def get_valid_access_token(
    tokens_dir: Path,
    cached_token: str | None,
    cached_expires_at: datetime | None,
    http_client: httpx.AsyncClient,
) -> tuple[str, datetime]:
    """Return a valid access token, refreshing if needed.

    If ``cached_token`` is still valid (not expired within the 60-second
    buffer), it is returned as-is. Otherwise, the refresh token is
    decrypted from disk and used to obtain a new access token from
    Google's token endpoint.

    Args:
        tokens_dir: Directory containing the encrypted token file.
        cached_token: The currently cached access token, or None.
        cached_expires_at: Expiry time of the cached token, or None.
        http_client: An httpx async client for the refresh request.

    Returns:
        A (access_token, expires_at) tuple. The caller must cache these
        and pass them back on the next call.

    Raises:
        OAuthError: If no token file exists or refresh fails.
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
    token_file = load_token(tokens_dir)
    if token_file is None:
        msg = "No OAuth token file found. Run oauth_setup first."
        raise OAuthError(msg)

    refresh_token = decrypt_refresh_token(token_file)
    client_id, client_secret = _get_client_credentials()

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
        msg = "HTTP request to token endpoint failed during refresh."
        raise OAuthError(msg) from exc

    if response.status_code != 200:
        error_code = _safe_error_code(response)
        logger.error(
            "Token refresh failed with status %d (error=%s).",
            response.status_code,
            error_code,
        )
        msg = "Token refresh failed. The refresh token may have been revoked."
        raise OAuthError(msg)

    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        msg = "Token endpoint returned invalid JSON during refresh."
        raise OAuthError(msg) from exc

    access_token = data.get("access_token")
    expires_in = data.get("expires_in")

    if not access_token:
        msg = "Token refresh response missing access_token."
        raise OAuthError(msg)

    if not isinstance(expires_in, int) or expires_in <= 0:
        # Default to 1 hour if expires_in is missing or invalid
        expires_in = 3600

    # Cap to 1 hour — Google's standard is 3600s; anything higher is
    # suspicious and could cause stale token caching.
    expires_in = min(expires_in, _MAX_TOKEN_LIFETIME_S)

    expires_at = now + timedelta(seconds=expires_in)

    # Update last_refreshed_at in the token file on disk
    token_file.last_refreshed_at = now
    try:
        save_token(tokens_dir, token_file)
    except OAuthError:
        # Non-fatal: log but don't fail the refresh
        logger.warning("Failed to update last_refreshed_at in token file.")

    logger.info("OAuth access token refreshed successfully.")
    return access_token, expires_at


def build_consent_url(redirect_uri: str) -> tuple[str, str]:
    """Build the Google OAuth consent URL with CSRF ``state`` parameter.

    Only ``GOOGLE_CLIENT_ID`` is required — the client secret is not
    included in consent URLs (it is server-side only).

    A cryptographically random ``state`` token is generated and included
    in the URL for CSRF protection (RFC 6749 §10.12). The caller must
    verify this ``state`` matches when the authorization code is received.

    Args:
        redirect_uri: The redirect URI for the OAuth callback.

    Returns:
        A (url, state) tuple. The caller must store ``state`` and verify
        it matches the value returned by Google's redirect.

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
