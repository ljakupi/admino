"""Tests for the OAuth setup CLI module (admino.oauth_setup).

GH-86: the CLI now persists the encrypted refresh token to PostgreSQL
instead of an on-disk file. It builds a DSN from the PG_* env vars,
opens an asyncpg pool via ``admino.database.init_pool``, runs migrations,
then calls the async ``save_token(pool, token)``.

Covers the full consent flow (happy path), PG env var handling
(missing PG_PASSWORD must error), user input edge cases, per-step error
handling, and security checks that plaintext tokens never reach stdout.

Security notes:
- All OAuth/network/DB dependencies are mocked — no real API or DB calls.
"""

from __future__ import annotations

from contextlib import ExitStack
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from admino.oauth import OAuthError

# ---------------------------------------------------------------------------
# Constants for test fixtures
# ---------------------------------------------------------------------------

_FAKE_CONSENT_URL: str = "https://accounts.google.com/o/oauth2/v2/auth?client_id=test"
_FAKE_MS_CONSENT_URL: str = (
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test"
)
_FAKE_STATE: str = "fake-csrf-state-token"
_FAKE_ACCESS_TOKEN: str = "access-token-secret-abc123"
_FAKE_REFRESH_TOKEN: str = "refresh-token-secret-xyz789"
_FAKE_ENCRYPTED: str = "gAAAAABencrypted_data_here"
_FAKE_SCOPES: list[str] = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar.events",
]
_FAKE_MS_SCOPES: list[str] = [
    "Mail.ReadWrite",
    "Calendars.ReadWrite",
]
_FAKE_AUTH_CODE: str = "4/0AX4XfWh-test-auth-code"


@pytest.fixture()
def pg_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the PG_* env vars needed to build a DSN, including PG_PASSWORD."""
    monkeypatch.setenv("PG_HOST", "localhost")
    monkeypatch.setenv("PG_PORT", "5432")
    monkeypatch.setenv("PG_USER", "admino")
    monkeypatch.setenv("PG_DATABASE", "admino")
    monkeypatch.setenv("PG_PASSWORD", "s3cr3t/p@ss")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patch_setup_deps(
    *,
    provider: str = "google",
    consent_url: str | None = None,
    exchange_return: tuple[str, str, list[str]] | None = None,
    encrypted: str = _FAKE_ENCRYPTED,
    build_side_effect: Exception | None = None,
    exchange_side_effect: Exception | None = None,
    encrypt_side_effect: Exception | None = None,
    save_side_effect: Exception | None = None,
) -> dict[str, Any]:
    """Build patchers for all oauth_setup dependencies.

    Returns a dict of context managers keyed by role, so tests can enter
    them and inspect the resulting mocks. ``init_pool`` and ``run_migrations``
    are mocked so no real DB connection is attempted.
    """
    if provider == "google":
        build_target = "admino.oauth_setup.build_google_consent_url"
        exchange_target = "admino.oauth_setup.exchange_google_code"
        default_url = _FAKE_CONSENT_URL
        default_scopes = list(_FAKE_SCOPES)
    else:
        build_target = "admino.oauth_setup.build_microsoft_consent_url"
        exchange_target = "admino.oauth_setup.exchange_microsoft_code"
        default_url = _FAKE_MS_CONSENT_URL
        default_scopes = list(_FAKE_MS_SCOPES)

    url = consent_url if consent_url is not None else default_url
    build_return = (url, _FAKE_STATE)
    mock_build = (
        patch(build_target, side_effect=build_side_effect)
        if build_side_effect
        else patch(build_target, return_value=build_return)
    )

    if exchange_return is None:
        exchange_return = (_FAKE_ACCESS_TOKEN, _FAKE_REFRESH_TOKEN, default_scopes)
    mock_exchange = patch(
        exchange_target,
        new_callable=AsyncMock,
        side_effect=exchange_side_effect,
        return_value=exchange_return if not exchange_side_effect else None,
    )

    mock_encrypt = patch(
        "admino.oauth_setup.encrypt_refresh_token",
        side_effect=encrypt_side_effect,
        return_value=encrypted if not encrypt_side_effect else None,
    )

    mock_save = patch(
        "admino.oauth_setup.save_token",
        new_callable=AsyncMock,
        side_effect=save_side_effect,
    )

    mock_init_pool = patch(
        "admino.oauth_setup.init_pool",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    )
    mock_run_migrations = patch(
        "admino.oauth_setup.run_migrations",
        new_callable=AsyncMock,
    )

    return {
        "build": mock_build,
        "exchange": mock_exchange,
        "encrypt": mock_encrypt,
        "save": mock_save,
        "init_pool": mock_init_pool,
        "run_migrations": mock_run_migrations,
    }


def _enter_all(stack: ExitStack, patchers: dict[str, Any]) -> dict[str, Any]:
    """Enter every patcher and return the entered mocks by role."""
    return {role: stack.enter_context(p) for role, p in patchers.items()}


# ---------------------------------------------------------------------------
# 1. Happy path: full end-to-end flow (Google)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("pg_env")
class TestHappyPath:
    """Full Google setup flow with all deps mocked."""

    pytestmark = pytest.mark.asyncio

    async def test_full_flow_prints_confirmation(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Successful flow prints consent URL and confirmation message."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        captured = capsys.readouterr()
        assert _FAKE_CONSENT_URL in captured.out
        assert "OAuth setup complete" in captured.out

    async def test_build_consent_url_called_with_redirect_uri(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """build_consent_url receives the correct redirect URI."""
        redirect = "http://custom:9999/callback"
        monkeypatch.setenv("OAUTH_REDIRECT_URI", redirect)
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            mocks = _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        mocks["build"].assert_called_once_with(redirect)

    async def test_save_token_called_with_pool_and_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """save_token is called with the pool and an OAuthToken for google."""
        from admino.oauth import OAuthToken

        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            mocks = _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        call = mocks["save"].call_args
        assert call is not None
        pool_arg, token_arg = call.args[0], call.args[1]
        assert pool_arg is mocks["init_pool"].return_value
        assert isinstance(token_arg, OAuthToken)
        assert token_arg.provider == "google"

    async def test_init_pool_and_migrations_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The pool is initialised and migrations are run before saving."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            mocks = _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        mocks["init_pool"].assert_awaited_once()
        mocks["run_migrations"].assert_awaited_once()

    async def test_dsn_url_encodes_pg_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The DSN passed to init_pool URL-encodes the PG_PASSWORD."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            mocks = _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        dsn = mocks["init_pool"].call_args.args[0]
        # The raw password contains "/" and "@" which must be percent-encoded,
        # so the literal secret must not appear verbatim in the DSN.
        assert "s3cr3t/p@ss" not in dsn
        assert "s3cr3t%2Fp%40ss" in dsn

    async def test_scopes_listed_in_confirmation(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Confirmation output lists the granted scopes."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        captured = capsys.readouterr()
        assert "gmail.modify" in captured.out


# ---------------------------------------------------------------------------
# 2. PG env var handling — missing PG_PASSWORD must error
# ---------------------------------------------------------------------------


class TestPgEnvVars:
    """Missing PG_PASSWORD errors out before any DB work."""

    pytestmark = pytest.mark.asyncio

    async def test_missing_pg_password_exits(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No PG_PASSWORD prints an error to stderr and exits with code 1."""
        monkeypatch.delenv("PG_PASSWORD", raising=False)
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_google_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "PG_PASSWORD" in captured.err

    async def test_missing_pg_password_does_not_save(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When PG_PASSWORD is missing, save_token is never called."""
        monkeypatch.delenv("PG_PASSWORD", raising=False)
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            mocks = _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit):
                await _run_google_setup()

        mocks["save"].assert_not_called()


# ---------------------------------------------------------------------------
# 3. OAUTH_REDIRECT_URI handling
# ---------------------------------------------------------------------------


class TestRedirectUri:
    """OAUTH_REDIRECT_URI env var behavior."""

    def test_redirect_uri_env_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """OAUTH_REDIRECT_URI env var overrides the default."""
        monkeypatch.setenv("OAUTH_REDIRECT_URI", "http://custom:9999/cb")
        from admino.oauth_setup import _get_redirect_uri

        assert _get_redirect_uri() == "http://custom:9999/cb"

    def test_redirect_uri_default_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Default redirect URI used when OAUTH_REDIRECT_URI is not set."""
        monkeypatch.delenv("OAUTH_REDIRECT_URI", raising=False)
        from admino.oauth_setup import _get_redirect_uri

        assert _get_redirect_uri() == "http://localhost:8000/oauth/callback"


# ---------------------------------------------------------------------------
# 4. User input handling
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("pg_env")
class TestUserInputHandling:
    """Edge cases for the authorization code input prompt."""

    pytestmark = pytest.mark.asyncio

    async def test_empty_auth_code_exits_with_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Empty authorization code prints error and exits with code 1."""
        monkeypatch.setattr("builtins.input", lambda _prompt: "")

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_google_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "No authorization code" in captured.err

    async def test_whitespace_only_auth_code_exits_with_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Whitespace-only authorization code treated as empty."""
        monkeypatch.setattr("builtins.input", lambda _prompt: "   \t  ")

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_google_setup()

        assert exc_info.value.code == 1

    async def test_keyboard_interrupt_exits_with_cancellation(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """KeyboardInterrupt during input prints cancellation and exits."""

        def raise_keyboard_interrupt(_prompt: str) -> str:
            raise KeyboardInterrupt

        monkeypatch.setattr("builtins.input", raise_keyboard_interrupt)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_google_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "cancelled" in captured.err.lower()

    async def test_eof_error_exits_with_cancellation(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """EOFError during input prints cancellation and exits."""

        def raise_eof(_prompt: str) -> str:
            raise EOFError

        monkeypatch.setattr("builtins.input", raise_eof)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_google_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "cancelled" in captured.err.lower()


# ---------------------------------------------------------------------------
# 5. Error handling for each OAuth step
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("pg_env")
class TestErrorHandling:
    """Each OAuth step failure prints error to stderr and exits with code 1."""

    pytestmark = pytest.mark.asyncio

    async def test_build_consent_url_error_exits(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """OAuthError from build_consent_url prints error and exits."""
        with ExitStack() as stack:
            _enter_all(
                stack,
                _patch_setup_deps(build_side_effect=OAuthError("GOOGLE_CLIENT_ID not set")),
            )
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_google_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "GOOGLE_CLIENT_ID not set" in captured.err

    async def test_exchange_code_error_exits(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """OAuthError from exchange_code prints error and exits."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(
                stack,
                _patch_setup_deps(exchange_side_effect=OAuthError("Token exchange failed")),
            )
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_google_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Token exchange failed" in captured.err

    async def test_encrypt_refresh_token_error_exits(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """OAuthError from encrypt_refresh_token prints error and exits."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(
                stack,
                _patch_setup_deps(encrypt_side_effect=OAuthError("Encryption key missing")),
            )
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_google_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Encryption key missing" in captured.err

    async def test_save_token_error_exits(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """OAuthError from save_token prints error and exits."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(
                stack,
                _patch_setup_deps(save_side_effect=OAuthError("Failed to persist token")),
            )
            from admino.oauth_setup import _run_google_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_google_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Failed to persist token" in captured.err


# ---------------------------------------------------------------------------
# 6. Security / adversarial — tokens never leak to stdout
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("pg_env")
class TestSecurityTokenLeakage:
    """Verify plaintext tokens never appear in stdout output."""

    pytestmark = pytest.mark.asyncio

    async def test_access_token_not_in_stdout(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The access token must never appear in stdout output."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        captured = capsys.readouterr()
        assert _FAKE_ACCESS_TOKEN not in captured.out
        assert _FAKE_ACCESS_TOKEN not in captured.err

    async def test_refresh_token_not_in_stdout(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The plaintext refresh token must never appear in stdout output."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        captured = capsys.readouterr()
        assert _FAKE_REFRESH_TOKEN not in captured.out
        assert _FAKE_REFRESH_TOKEN not in captured.err

    async def test_encrypted_token_saved_not_plaintext(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """save_token receives the encrypted value, not plaintext."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            mocks = _enter_all(stack, _patch_setup_deps())
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        token = mocks["save"].call_args.args[1]
        assert token.encrypted_refresh_token == _FAKE_ENCRYPTED
        assert _FAKE_REFRESH_TOKEN not in token.encrypted_refresh_token


# ---------------------------------------------------------------------------
# 7. Default scopes fallback (Google)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("pg_env")
class TestScopesFallback:
    """When exchange_code returns empty scopes, default scopes are used."""

    pytestmark = pytest.mark.asyncio

    async def test_empty_scopes_uses_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Empty scopes from exchange_code triggers default scopes."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            mocks = _enter_all(
                stack,
                _patch_setup_deps(
                    exchange_return=(_FAKE_ACCESS_TOKEN, _FAKE_REFRESH_TOKEN, []),
                ),
            )
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        token = mocks["save"].call_args.args[1]
        assert len(token.scopes) == 3
        assert "gmail.modify" in token.scopes[0]

    async def test_provided_scopes_used_when_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-empty scopes from exchange_code are used as-is."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        custom_scopes = ["https://www.googleapis.com/auth/gmail.modify"]
        with ExitStack() as stack:
            mocks = _enter_all(
                stack,
                _patch_setup_deps(
                    exchange_return=(_FAKE_ACCESS_TOKEN, _FAKE_REFRESH_TOKEN, custom_scopes),
                ),
            )
            from admino.oauth_setup import _run_google_setup

            await _run_google_setup()

        token = mocks["save"].call_args.args[1]
        assert token.scopes == custom_scopes


# ===========================================================================
# Microsoft OAuth Setup Tests
# ===========================================================================


@pytest.mark.usefixtures("pg_env")
class TestMicrosoftHappyPath:
    """Full Microsoft setup flow with all deps mocked."""

    pytestmark = pytest.mark.asyncio

    async def test_full_flow_prints_confirmation(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Successful Microsoft flow prints consent URL and confirmation."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps(provider="microsoft"))
            from admino.oauth_setup import _run_microsoft_setup

            await _run_microsoft_setup()

        captured = capsys.readouterr()
        assert _FAKE_MS_CONSENT_URL in captured.out
        assert "Microsoft OAuth setup complete" in captured.out

    async def test_save_token_receives_microsoft_provider(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """save_token is called with an OAuthToken for provider='microsoft'."""
        from admino.oauth import OAuthToken

        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            mocks = _enter_all(stack, _patch_setup_deps(provider="microsoft"))
            from admino.oauth_setup import _run_microsoft_setup

            await _run_microsoft_setup()

        token = mocks["save"].call_args.args[1]
        assert isinstance(token, OAuthToken)
        assert token.provider == "microsoft"

    async def test_microsoft_scopes_listed_in_confirmation(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Confirmation output lists Microsoft scopes."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps(provider="microsoft"))
            from admino.oauth_setup import _run_microsoft_setup

            await _run_microsoft_setup()

        captured = capsys.readouterr()
        assert "Mail.ReadWrite" in captured.out


@pytest.mark.usefixtures("pg_env")
class TestMicrosoftUserInput:
    """Edge cases for Microsoft authorization code input."""

    pytestmark = pytest.mark.asyncio

    async def test_empty_auth_code_exits(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Empty authorization code exits with code 1."""
        monkeypatch.setattr("builtins.input", lambda _prompt: "")

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps(provider="microsoft"))
            from admino.oauth_setup import _run_microsoft_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_microsoft_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "No authorization code" in captured.err


class TestMicrosoftPgEnvVars:
    """Missing PG_PASSWORD errors out on the Microsoft flow too."""

    pytestmark = pytest.mark.asyncio

    async def test_missing_pg_password_exits(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No PG_PASSWORD prints an error to stderr and exits with code 1."""
        monkeypatch.delenv("PG_PASSWORD", raising=False)
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(stack, _patch_setup_deps(provider="microsoft"))
            from admino.oauth_setup import _run_microsoft_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_microsoft_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "PG_PASSWORD" in captured.err


@pytest.mark.usefixtures("pg_env")
class TestMicrosoftErrorHandling:
    """Each Microsoft OAuth step failure exits with code 1."""

    pytestmark = pytest.mark.asyncio

    async def test_exchange_code_error_exits(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """OAuthError from exchange_microsoft_code exits."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(
                stack,
                _patch_setup_deps(
                    provider="microsoft",
                    exchange_side_effect=OAuthError("Microsoft token exchange failed"),
                ),
            )
            from admino.oauth_setup import _run_microsoft_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_microsoft_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Microsoft token exchange failed" in captured.err

    async def test_save_token_error_exits(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """OAuthError from save_token exits."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            _enter_all(
                stack,
                _patch_setup_deps(
                    provider="microsoft",
                    save_side_effect=OAuthError("Failed to persist token"),
                ),
            )
            from admino.oauth_setup import _run_microsoft_setup

            with pytest.raises(SystemExit) as exc_info:
                await _run_microsoft_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Failed to persist token" in captured.err


@pytest.mark.usefixtures("pg_env")
class TestMicrosoftScopesFallback:
    """When exchange returns empty scopes, Microsoft defaults are used."""

    pytestmark = pytest.mark.asyncio

    async def test_empty_scopes_uses_microsoft_defaults(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty scopes from exchange triggers default Microsoft scopes."""
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        with ExitStack() as stack:
            mocks = _enter_all(
                stack,
                _patch_setup_deps(
                    provider="microsoft",
                    exchange_return=(_FAKE_ACCESS_TOKEN, _FAKE_REFRESH_TOKEN, []),
                ),
            )
            from admino.oauth_setup import _run_microsoft_setup

            await _run_microsoft_setup()

        token = mocks["save"].call_args.args[1]
        assert len(token.scopes) == 5
        assert "Mail.ReadWrite" in token.scopes
        assert "Mail.Send" in token.scopes


# ---------------------------------------------------------------------------
# main() entry point
# ---------------------------------------------------------------------------


class TestMainEntryPoint:
    """The main() function dispatches to the right provider setup."""

    def test_main_calls_google_setup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """main() delegates to asyncio.run with _run_google_setup."""
        from admino.oauth_setup import main

        async def fake_setup() -> None:
            return None

        monkeypatch.setattr("admino.oauth_setup._run_google_setup", fake_setup)
        monkeypatch.setattr("sys.argv", ["oauth_setup", "google"])

        def _consume(coro: Any) -> None:
            coro.close()

        with patch("admino.oauth_setup.asyncio.run", side_effect=_consume) as mock_run:
            main()
            mock_run.assert_called_once()

    def test_main_calls_microsoft_setup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """main() delegates to asyncio.run with _run_microsoft_setup."""
        from admino.oauth_setup import main

        async def fake_setup() -> None:
            return None

        monkeypatch.setattr("admino.oauth_setup._run_microsoft_setup", fake_setup)
        monkeypatch.setattr("sys.argv", ["oauth_setup", "microsoft"])

        def _consume(coro: Any) -> None:
            coro.close()

        with patch("admino.oauth_setup.asyncio.run", side_effect=_consume) as mock_run:
            main()
            mock_run.assert_called_once()

    def test_main_invalid_provider_exits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """main() with invalid provider prints usage and exits."""
        from admino.oauth_setup import main

        monkeypatch.setattr("sys.argv", ["oauth_setup", "invalid_provider"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

    def test_main_no_args_exits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """main() with no arguments prints usage and exits."""
        from admino.oauth_setup import main

        monkeypatch.setattr("sys.argv", ["oauth_setup"])

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
