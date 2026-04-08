"""CLI script for one-time Google OAuth consent bootstrapping.

Run as ``python -m admino.oauth_setup`` to initiate the OAuth consent
flow. The script:

1. Builds a Google OAuth consent URL with the required scopes.
2. Prints the URL for the user to open in a browser.
3. Prompts the user to paste the authorization code.
4. Exchanges the auth code for access and refresh tokens.
5. Encrypts the refresh token with Fernet and saves it to the
   tokens directory.
6. Prints a confirmation message.

Security notes:
- Client credentials (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET) and the
  Fernet key (OAUTH_ENCRYPTION_KEY) are read from environment variables
  only. They are never printed, logged, or stored in plaintext on disk.
- The access token obtained during setup is discarded — it is not
  written to disk.
- The tokens directory is created with mode 0o700; the token file with
  mode 0o600.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

from admino.oauth import (
    OAuthError,
    TokenFile,
    build_consent_url,
    encrypt_refresh_token,
    exchange_code,
    save_token,
)

# Default tokens directory; overridable via TOKENS_DIR env var
_DEFAULT_TOKENS_DIR: str = "/app/data/tokens"

# Default redirect URI for the OAuth callback
_DEFAULT_REDIRECT_URI: str = "http://localhost:8000/oauth/callback"


def _get_tokens_dir() -> Path:
    """Resolve the tokens directory from env var or default.

    Returns:
        Absolute path to the tokens directory.
    """
    return Path(os.environ.get("TOKENS_DIR", _DEFAULT_TOKENS_DIR)).resolve()


def _get_redirect_uri() -> str:
    """Resolve the OAuth redirect URI from env var or default.

    Returns:
        The redirect URI string.
    """
    return os.environ.get("OAUTH_REDIRECT_URI", _DEFAULT_REDIRECT_URI)


async def _run_setup() -> None:
    """Execute the OAuth setup flow.

    Raises:
        OAuthError: If any step of the OAuth flow fails.
        SystemExit: On user cancellation (KeyboardInterrupt, EOF).
    """
    redirect_uri = _get_redirect_uri()
    tokens_dir = _get_tokens_dir()

    # Step 1-2: Build and display consent URL
    try:
        consent_url, state = build_consent_url(redirect_uri)
    except OAuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Note: the consent URL contains client_id as a query parameter.
    # client_id is NOT a secret in OAuth 2.0 — only client_secret is.
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
    print(f"(CSRF state token: {state})")
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
            access_token, refresh_token, scopes = await exchange_code(
                code=code,
                redirect_uri=redirect_uri,
                http_client=client,
            )
        except OAuthError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    # Auth code is single-use and no longer needed — discard immediately
    del code

    # Step 5: Encrypt and save the refresh token
    # Access token is intentionally discarded -- never written to disk
    try:
        encrypted = encrypt_refresh_token(refresh_token)
    except OAuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    now = datetime.now(UTC)
    default_scopes = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/calendar.events",
    ]
    token_file = TokenFile(
        provider="google",
        scopes=scopes if scopes else default_scopes,
        encrypted_refresh_token=encrypted,
        created_at=now,
        last_refreshed_at=now,
    )

    try:
        save_token(tokens_dir, token_file)
    except OAuthError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Step 6: Confirmation
    print()
    print("OAuth setup complete.")
    print(f"Encrypted refresh token saved to: {tokens_dir / 'google.json'}")
    print(f"Scopes granted: {', '.join(token_file.scopes)}")
    print()
    # Explicitly discard the access token reference
    del access_token, refresh_token


def main() -> None:
    """Entry point for ``python -m admino.oauth_setup``."""
    asyncio.run(_run_setup())


if __name__ == "__main__":
    main()
