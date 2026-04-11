"""Tests for the OAuth setup CLI module (admino.oauth_setup).

Covers the full consent flow (happy path), environment variable handling,
user input edge cases, error handling for each OAuth step, and security
checks that plaintext tokens are never leaked to stdout or disk.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from admino.oauth import OAuthError

# ---------------------------------------------------------------------------
# Constants for test fixtures
# ---------------------------------------------------------------------------

_FAKE_CONSENT_URL: str = "https://accounts.google.com/o/oauth2/v2/auth?client_id=test"
_FAKE_STATE: str = "fake-csrf-state-token"
_FAKE_ACCESS_TOKEN: str = "access-token-secret-abc123"
_FAKE_REFRESH_TOKEN: str = "refresh-token-secret-xyz789"
_FAKE_ENCRYPTED: str = "gAAAAABencrypted_data_here"
_FAKE_SCOPES: list[str] = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/calendar.events",
]
_FAKE_AUTH_CODE: str = "4/0AX4XfWh-test-auth-code"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patch_setup_deps(
    *,
    consent_url: str = _FAKE_CONSENT_URL,
    exchange_return: tuple[str, str, list[str]] | None = None,
    encrypted: str = _FAKE_ENCRYPTED,
    build_side_effect: Exception | None = None,
    exchange_side_effect: Exception | None = None,
    encrypt_side_effect: Exception | None = None,
    save_side_effect: Exception | None = None,
) -> tuple[AsyncMock, ...]:
    """Create mocks for all oauth functions used by oauth_setup.

    Returns (mock_build, mock_exchange, mock_encrypt, mock_save).
    """
    # build_consent_url now returns (url, state) tuple
    build_return = (consent_url, _FAKE_STATE)
    mock_build = (
        patch("admino.oauth_setup.build_consent_url", side_effect=build_side_effect)
        if build_side_effect
        else patch("admino.oauth_setup.build_consent_url", return_value=build_return)
    )

    if exchange_return is None:
        exchange_return = (_FAKE_ACCESS_TOKEN, _FAKE_REFRESH_TOKEN, list(_FAKE_SCOPES))
    mock_exchange = patch(
        "admino.oauth_setup.exchange_code",
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
        side_effect=save_side_effect,
    )

    return mock_build, mock_exchange, mock_encrypt, mock_save


# ---------------------------------------------------------------------------
# 1. Happy path: full end-to-end flow
# ---------------------------------------------------------------------------


class TestHappyPath:
    """Full setup flow with all deps mocked."""

    async def test_full_flow_prints_confirmation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Successful flow prints consent URL and confirmation message."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with mock_build, mock_exchange, mock_encrypt, mock_save:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        captured = capsys.readouterr()
        assert _FAKE_CONSENT_URL in captured.out
        assert "OAuth setup complete" in captured.out

    async def test_build_consent_url_called_with_redirect_uri(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """build_consent_url receives the correct redirect URI."""
        redirect = "http://custom:9999/callback"
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setenv("OAUTH_REDIRECT_URI", redirect)
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with mock_build as mb, mock_exchange, mock_encrypt, mock_save:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        mb.assert_called_once_with(redirect)

    async def test_save_token_called_with_tokens_dir(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """save_token is called with the resolved tokens directory."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with mock_build, mock_exchange, mock_encrypt, mock_save as ms:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        call_args = ms.call_args
        assert call_args is not None
        saved_dir = call_args[0][0]
        assert saved_dir == tmp_path.resolve()

    async def test_scopes_listed_in_confirmation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Confirmation output lists the granted scopes."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with mock_build, mock_exchange, mock_encrypt, mock_save:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        captured = capsys.readouterr()
        assert "gmail.readonly" in captured.out

    async def test_token_file_path_shown_in_confirmation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Confirmation output shows the token file path."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with mock_build, mock_exchange, mock_encrypt, mock_save:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        captured = capsys.readouterr()
        assert "google.json" in captured.out


# ---------------------------------------------------------------------------
# 2. Environment variable handling
# ---------------------------------------------------------------------------


class TestEnvironmentVariables:
    """TOKENS_DIR and OAUTH_REDIRECT_URI env var behavior."""

    def test_tokens_dir_env_overrides_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """TOKENS_DIR env var overrides the default /app/data/tokens."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path / "custom_tokens"))
        from admino.oauth_setup import _get_tokens_dir

        result = _get_tokens_dir()
        assert result == (tmp_path / "custom_tokens").resolve()

    def test_tokens_dir_default_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Default tokens dir is /app/data/tokens when TOKENS_DIR is not set."""
        monkeypatch.delenv("TOKENS_DIR", raising=False)
        from admino.oauth_setup import _get_tokens_dir

        result = _get_tokens_dir()
        assert result == Path("/app/data/tokens").resolve()

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
# 3. User input handling
# ---------------------------------------------------------------------------


class TestUserInputHandling:
    """Edge cases for the authorization code input prompt."""

    async def test_empty_auth_code_exits_with_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Empty authorization code prints error and exits with code 1."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: "")

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with (
            mock_build,
            mock_exchange,
            mock_encrypt,
            mock_save,
            pytest.raises(SystemExit) as exc_info,
        ):
            from admino.oauth_setup import _run_setup

            await _run_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "No authorization code" in captured.err

    async def test_whitespace_only_auth_code_exits_with_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Whitespace-only authorization code treated as empty."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: "   \t  ")

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with (
            mock_build,
            mock_exchange,
            mock_encrypt,
            mock_save,
            pytest.raises(SystemExit) as exc_info,
        ):
            from admino.oauth_setup import _run_setup

            await _run_setup()

        assert exc_info.value.code == 1

    async def test_keyboard_interrupt_exits_with_cancellation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """KeyboardInterrupt during input prints cancellation and exits."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))

        def raise_keyboard_interrupt(_prompt: str) -> str:
            raise KeyboardInterrupt

        monkeypatch.setattr("builtins.input", raise_keyboard_interrupt)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with (
            mock_build,
            mock_exchange,
            mock_encrypt,
            mock_save,
            pytest.raises(SystemExit) as exc_info,
        ):
            from admino.oauth_setup import _run_setup

            await _run_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "cancelled" in captured.err.lower()

    async def test_eof_error_exits_with_cancellation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """EOFError during input prints cancellation and exits."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))

        def raise_eof(_prompt: str) -> str:
            raise EOFError

        monkeypatch.setattr("builtins.input", raise_eof)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with (
            mock_build,
            mock_exchange,
            mock_encrypt,
            mock_save,
            pytest.raises(SystemExit) as exc_info,
        ):
            from admino.oauth_setup import _run_setup

            await _run_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "cancelled" in captured.err.lower()


# ---------------------------------------------------------------------------
# 4. Error handling for each OAuth step
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Each OAuth step failure prints error to stderr and exits with code 1."""

    async def test_build_consent_url_error_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """OAuthError from build_consent_url prints error and exits."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps(
            build_side_effect=OAuthError("GOOGLE_CLIENT_ID not set"),
        )

        with (
            mock_build,
            mock_exchange,
            mock_encrypt,
            mock_save,
            pytest.raises(SystemExit) as exc_info,
        ):
            from admino.oauth_setup import _run_setup

            await _run_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "GOOGLE_CLIENT_ID not set" in captured.err

    async def test_exchange_code_error_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """OAuthError from exchange_code prints error and exits."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps(
            exchange_side_effect=OAuthError("Token exchange failed"),
        )

        with (
            mock_build,
            mock_exchange,
            mock_encrypt,
            mock_save,
            pytest.raises(SystemExit) as exc_info,
        ):
            from admino.oauth_setup import _run_setup

            await _run_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Token exchange failed" in captured.err

    async def test_encrypt_refresh_token_error_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """OAuthError from encrypt_refresh_token prints error and exits."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps(
            encrypt_side_effect=OAuthError("Encryption key missing"),
        )

        with (
            mock_build,
            mock_exchange,
            mock_encrypt,
            mock_save,
            pytest.raises(SystemExit) as exc_info,
        ):
            from admino.oauth_setup import _run_setup

            await _run_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Encryption key missing" in captured.err

    async def test_save_token_error_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """OAuthError from save_token prints error and exits."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps(
            save_side_effect=OAuthError("Failed to write token file"),
        )

        with (
            mock_build,
            mock_exchange,
            mock_encrypt,
            mock_save,
            pytest.raises(SystemExit) as exc_info,
        ):
            from admino.oauth_setup import _run_setup

            await _run_setup()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Failed to write token file" in captured.err


# ---------------------------------------------------------------------------
# 5. Security / adversarial
# ---------------------------------------------------------------------------


class TestSecurityTokenLeakage:
    """Verify plaintext tokens never appear in stdout output."""

    async def test_access_token_not_in_stdout(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The access token must never appear in stdout output."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with mock_build, mock_exchange, mock_encrypt, mock_save:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        captured = capsys.readouterr()
        assert _FAKE_ACCESS_TOKEN not in captured.out
        assert _FAKE_ACCESS_TOKEN not in captured.err

    async def test_refresh_token_not_in_stdout(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The plaintext refresh token must never appear in stdout output."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with mock_build, mock_exchange, mock_encrypt, mock_save:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        captured = capsys.readouterr()
        assert _FAKE_REFRESH_TOKEN not in captured.out
        assert _FAKE_REFRESH_TOKEN not in captured.err

    async def test_del_tokens_reached_on_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """After successful setup, the function completes (del is reached).

        The ``del access_token, refresh_token`` statement is at the end of
        _run_setup. If we reach the end without error, the del was executed.
        We verify this indirectly by confirming no exception is raised and
        the function returns normally.
        """
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with mock_build, mock_exchange, mock_encrypt, mock_save:
            from admino.oauth_setup import _run_setup

            # Should complete without error — del statement is reached
            await _run_setup()

    async def test_encrypted_token_saved_not_plaintext(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """save_token receives the encrypted value, not plaintext."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps()

        with mock_build, mock_exchange, mock_encrypt, mock_save as ms:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        call_args = ms.call_args
        assert call_args is not None
        token_file = call_args[0][1]
        assert token_file.encrypted_refresh_token == _FAKE_ENCRYPTED
        assert _FAKE_REFRESH_TOKEN not in token_file.encrypted_refresh_token


# ---------------------------------------------------------------------------
# 6. main() entry point
# ---------------------------------------------------------------------------


class TestMainEntryPoint:
    """The main() function calls asyncio.run(_run_setup)."""

    def test_main_calls_asyncio_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """main() delegates to asyncio.run with _run_setup."""
        from admino.oauth_setup import main

        async def fake_setup() -> None:
            return None

        monkeypatch.setattr("admino.oauth_setup._run_setup", fake_setup)

        # Close the coroutine inside the mock so it is not left un-awaited,
        # which would otherwise raise a RuntimeWarning at GC time.
        def _consume(coro: Any) -> None:
            coro.close()

        with patch("admino.oauth_setup.asyncio.run", side_effect=_consume) as mock_run:
            main()
            mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# 7. Default scopes fallback
# ---------------------------------------------------------------------------


class TestScopesFallback:
    """When exchange_code returns empty scopes, default scopes are used."""

    async def test_empty_scopes_uses_defaults(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Empty scopes from exchange_code triggers default scopes."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps(
            exchange_return=(_FAKE_ACCESS_TOKEN, _FAKE_REFRESH_TOKEN, []),
        )

        with mock_build, mock_exchange, mock_encrypt, mock_save as ms:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        call_args = ms.call_args
        assert call_args is not None
        token_file = call_args[0][1]
        assert len(token_file.scopes) == 2
        assert "gmail.readonly" in token_file.scopes[0]

    async def test_provided_scopes_used_when_present(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Non-empty scopes from exchange_code are used as-is."""
        monkeypatch.setenv("TOKENS_DIR", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda _prompt: _FAKE_AUTH_CODE)

        custom_scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        mock_build, mock_exchange, mock_encrypt, mock_save = _patch_setup_deps(
            exchange_return=(_FAKE_ACCESS_TOKEN, _FAKE_REFRESH_TOKEN, custom_scopes),
        )

        with mock_build, mock_exchange, mock_encrypt, mock_save as ms:
            from admino.oauth_setup import _run_setup

            await _run_setup()

        call_args = ms.call_args
        assert call_args is not None
        token_file = call_args[0][1]
        assert token_file.scopes == custom_scopes
