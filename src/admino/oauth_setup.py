"""CLI script for one-time OAuth consent bootstrapping (Google & Microsoft).

Run as ``python -m admino.oauth_setup google`` or
``python -m admino.oauth_setup microsoft`` to initiate the OAuth consent
flow for the respective provider.

The script:
1. Builds the provider's OAuth consent URL with the required scopes.
2. Prints the URL for the user to open in a browser.
3. Prompts the user to paste the authorization code.
4. Exchanges the auth code for access and refresh tokens.
5. Encrypts the refresh token with Fernet and persists it to PostgreSQL
   (the ``oauth_tokens`` table) via an asyncpg pool.
6. Prints a confirmation message.

Security notes:
- Client credentials and the Fernet key (OAUTH_ENCRYPTION_KEY) are read from
  environment variables only. They are never printed, logged, or stored in
  plaintext.
- The access token obtained during setup is discarded — it is never persisted.
- Only the Fernet ciphertext of the refresh token is written to the database;
  the plaintext refresh token never reaches the DB.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime

import httpx

from admino.database import close_pool, database_url_from_env, init_pool, run_migrations
from admino.oauth import (
    GOOGLE_SCOPES,
    MICROSOFT_SCOPES,
    OAuthError,
    OAuthProvider,
    OAuthToken,
    build_google_consent_url,
    build_microsoft_consent_url,
    encrypt_refresh_token,
    exchange_google_code,
    exchange_microsoft_code,
    save_token,
)

# Default redirect URI for the OAuth callback
_DEFAULT_REDIRECT_URI: str = "http://localhost:8000/oauth/callback"


def _build_dsn() -> str:
    """Build a PostgreSQL DSN from the PG_* env vars, or exit when PG_PASSWORD is missing.

    Uses ``admino.database.database_url_from_env`` (the DSN the server starts
    with). If PG_PASSWORD is missing an error is printed to stderr and the
    process exits with code 1.

    Returns:
        A ``postgresql://`` connection string.

    Raises:
        SystemExit: If PG_PASSWORD is not set.
    """
    dsn = database_url_from_env()
    if dsn is None:
        print(
            "Error: PG_PASSWORD environment variable is not set.",
            file=sys.stderr,
        )
        sys.exit(1)
    return dsn


def _get_redirect_uri() -> str:
    """Resolve the OAuth redirect URI from env var or default.

    Validates that the URI starts with http:// or https:// to prevent
    misconfigured env vars from being submitted to OAuth providers.

    Returns:
        The redirect URI string.

    Raises:
        SystemExit: If the redirect URI is not a valid HTTP(S) URL.
    """
    uri = os.environ.get("OAUTH_REDIRECT_URI", _DEFAULT_REDIRECT_URI)
    if not uri.startswith(("http://", "https://")):
        print(
            f"Error: OAUTH_REDIRECT_URI must start with http:// or https://, got: {uri}",
            file=sys.stderr,
        )
        sys.exit(1)
    return uri


async def _persist_token(token: OAuthToken) -> None:
    """Open a pool, run migrations, save the token, and close the pool.

    Args:
        token: The OAuthToken to persist (encrypted refresh token).

    Raises:
        SystemExit: If PG_PASSWORD is missing.
        OAuthError: If the save fails.
    """
    dsn = _build_dsn()
    pool = await init_pool(dsn)
    try:
        await run_migrations(pool)
        await save_token(pool, token)
    finally:
        await close_pool()


async def _run_google_setup() -> None:
    """Execute the Google OAuth setup flow.

    Raises:
        OAuthError: If any step of the OAuth flow fails.
        SystemExit: On user cancellation (KeyboardInterrupt, EOF) or
            missing PG_PASSWORD.
    """
    redirect_uri = _get_redirect_uri()

    # Step 1-2: Build and display consent URL
    try:
        consent_url, _state = build_google_consent_url(redirect_uri)
    except OAuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print()
    print("=" * 60)
    print("  admino -- Google OAuth Setup")
    print("=" * 60)
    print()
    print("Open the following URL in your browser to grant access:")
    print()
    print(f"  {consent_url}")
    print()
    print(f"After granting consent, Google will redirect to: {redirect_uri}")
    # State token intentionally not printed — no value to user in manual flow
    print()
    print("Copy the authorization code from the URL and paste it below.")
    print()

    # Step 3: Get auth code from user
    try:
        code = input("Authorization code: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled.", file=sys.stderr)
        sys.exit(1)

    if not code:
        print("Error: No authorization code provided.", file=sys.stderr)
        sys.exit(1)

    # Step 4: Exchange auth code for tokens
    print()
    print("Exchanging authorization code for tokens...")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            access_token, refresh_token, scopes = await exchange_google_code(
                code=code,
                redirect_uri=redirect_uri,
                http_client=client,
            )
        except OAuthError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    # Auth code is single-use and no longer needed — discard immediately
    del code

    # Step 5: Encrypt the refresh token and persist it to the database
    try:
        encrypted = encrypt_refresh_token(refresh_token)
    except OAuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Plaintext tokens are no longer needed — discard before any await/exit
    # so they do not linger as live locals across suspension points.
    del access_token, refresh_token

    now = datetime.now(UTC)
    token = OAuthToken(
        provider="google",
        scopes=scopes if scopes else GOOGLE_SCOPES,
        encrypted_refresh_token=encrypted,
        email=None,
        created_at=now,
        last_refreshed_at=now,
    )

    try:
        await _persist_token(token)
    except OAuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Step 6: Confirmation
    print()
    print("Google OAuth setup complete.")
    print("Encrypted refresh token saved to database.")
    print(f"Scopes granted: {', '.join(token.scopes)}")
    print()


async def _run_microsoft_setup() -> None:
    """Execute the Microsoft OAuth setup flow.

    Raises:
        OAuthError: If any step of the OAuth flow fails.
        SystemExit: On user cancellation (KeyboardInterrupt, EOF) or
            missing PG_PASSWORD.
    """
    redirect_uri = _get_redirect_uri()

    # Step 1-2: Build and display consent URL
    try:
        consent_url, _state = build_microsoft_consent_url(redirect_uri)
    except OAuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print()
    print("=" * 60)
    print("  admino -- Microsoft OAuth Setup")
    print("=" * 60)
    print()
    print("Open the following URL in your browser to grant access:")
    print()
    print(f"  {consent_url}")
    print()
    print(f"After granting consent, Microsoft will redirect to: {redirect_uri}")
    # State token intentionally not printed — no value to user in manual flow
    print()
    print("Copy the authorization code from the URL and paste it below.")
    print()

    # Step 3: Get auth code from user
    try:
        code = input("Authorization code: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled.", file=sys.stderr)
        sys.exit(1)

    if not code:
        print("Error: No authorization code provided.", file=sys.stderr)
        sys.exit(1)

    # Step 4: Exchange auth code for tokens
    print()
    print("Exchanging authorization code for tokens...")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            access_token, refresh_token, scopes = await exchange_microsoft_code(
                code=code,
                redirect_uri=redirect_uri,
                http_client=client,
            )
        except OAuthError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    del code

    # Step 5: Encrypt the refresh token and persist it to the database
    try:
        encrypted = encrypt_refresh_token(refresh_token)
    except OAuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Plaintext tokens are no longer needed — discard before any await/exit
    # so they do not linger as live locals across suspension points.
    del access_token, refresh_token

    now = datetime.now(UTC)
    token = OAuthToken(
        provider="microsoft",
        scopes=scopes if scopes else MICROSOFT_SCOPES,
        encrypted_refresh_token=encrypted,
        email=None,
        created_at=now,
        last_refreshed_at=now,
    )

    try:
        await _persist_token(token)
    except OAuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Step 6: Confirmation
    print()
    print("Microsoft OAuth setup complete.")
    print("Encrypted refresh token saved to database.")
    print(f"Scopes granted: {', '.join(token.scopes)}")
    print()


def main() -> None:
    """Entry point for ``python -m admino.oauth_setup <provider>``.

    Usage:
        python -m admino.oauth_setup google
        python -m admino.oauth_setup microsoft
    """
    if len(sys.argv) < 2 or sys.argv[1] not in ("google", "microsoft"):
        print(
            "Usage: python -m admino.oauth_setup <provider>\n  Providers: google, microsoft",
            file=sys.stderr,
        )
        sys.exit(1)

    provider: OAuthProvider = sys.argv[1]  # type: ignore[assignment]

    if provider == "google":
        asyncio.run(_run_google_setup())
    else:
        asyncio.run(_run_microsoft_setup())


if __name__ == "__main__":
    main()
