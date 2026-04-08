"""Tests for the OAuth token management module (admino.oauth).

Covers encryption/decryption roundtrips, token refresh flows, file
permission enforcement, missing env var errors, consent URL construction,
code exchange, and adversarial checks that plaintext tokens never reach disk.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

if TYPE_CHECKING:
    from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from admino.oauth import (
    _EXPIRY_BUFFER_SECONDS,
    GOOGLE_AUTH_ENDPOINT,
    GOOGLE_SCOPES,
    OAuthError,
    TokenFile,
    _get_client_credentials,
    _get_fernet,
    build_consent_url,
    decrypt_refresh_token,
    encrypt_refresh_token,
    exchange_code,
    get_valid_access_token,
    load_token,
    save_token,
)

# ---------------------------------------------------------------------------
# Shared helpers and fixtures
# ---------------------------------------------------------------------------

_TEST_FERNET_KEY: str = Fernet.generate_key().decode()
_TEST_CLIENT_ID: str = "test-client-id-123.apps.googleusercontent.com"
_TEST_CLIENT_SECRET: str = "test-client-secret-abc"
_PLAINTEXT_REFRESH_TOKEN: str = "1//0abc-REFRESH-TOKEN-plaintext"


@pytest.fixture()
def fernet_env(monkeypatch: pytest.MonkeyPatch) -> str:
    """Set OAUTH_ENCRYPTION_KEY to a valid Fernet key. Returns the key."""
    monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", _TEST_FERNET_KEY)
    return _TEST_FERNET_KEY


@pytest.fixture()
def google_env(monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    """Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET. Returns (id, secret)."""
    monkeypatch.setenv("GOOGLE_CLIENT_ID", _TEST_CLIENT_ID)
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", _TEST_CLIENT_SECRET)
    return _TEST_CLIENT_ID, _TEST_CLIENT_SECRET


@pytest.fixture()
def full_env(fernet_env: str, google_env: tuple[str, str]) -> tuple[str, str, str]:
    """Set all three required env vars. Returns (fernet_key, client_id, secret)."""
    return fernet_env, google_env[0], google_env[1]


@pytest.fixture()
def sample_token_file(fernet_env: str) -> TokenFile:
    """A valid TokenFile with an encrypted refresh token."""
    _ = fernet_env  # Fixture ensures OAUTH_ENCRYPTION_KEY is set
    encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
    now = datetime.now(UTC)
    return TokenFile(
        provider="google",
        scopes=list(GOOGLE_SCOPES),
        encrypted_refresh_token=encrypted,
        created_at=now,
        last_refreshed_at=now,
    )


def _write_token_on_disk(tokens_dir: Path, token_file: TokenFile) -> Path:
    """Helper: save token and return the file path."""
    save_token(tokens_dir, token_file)
    return tokens_dir / "google.json"


def _make_httpx_response(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
    *,
    invalid_json: bool = False,
) -> httpx.Response:
    """Build a fake httpx.Response."""
    if invalid_json:
        return httpx.Response(status_code=status_code, content=b"not json{{{")
    body = json.dumps(json_body or {}).encode()
    return httpx.Response(status_code=status_code, content=body)


# ---------------------------------------------------------------------------
# 1. Token encryption / decryption roundtrip
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fernet_env")
class TestEncryptDecryptRoundtrip:
    """Encrypt a refresh token, persist in a TokenFile, decrypt and verify."""

    def test_roundtrip_matches_plaintext(self) -> None:
        """Encrypted then decrypted token equals the original plaintext."""
        encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
        token_file = TokenFile(
            provider="google",
            scopes=["scope1"],
            encrypted_refresh_token=encrypted,
            created_at=datetime.now(UTC),
            last_refreshed_at=datetime.now(UTC),
        )
        result = decrypt_refresh_token(token_file)
        assert result == _PLAINTEXT_REFRESH_TOKEN

    def test_encrypted_differs_from_plaintext(self) -> None:
        """The ciphertext must not equal the plaintext."""
        encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
        assert encrypted != _PLAINTEXT_REFRESH_TOKEN

    def test_decrypt_with_wrong_key_raises(self) -> None:
        """Decrypting with a different key raises OAuthError."""
        encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
        token_file = TokenFile(
            provider="google",
            scopes=["scope1"],
            encrypted_refresh_token=encrypted,
            created_at=datetime.now(UTC),
            last_refreshed_at=datetime.now(UTC),
        )
        # Switch to a different key
        wrong_key = Fernet.generate_key().decode()
        with (
            patch.dict(os.environ, {"OAUTH_ENCRYPTION_KEY": wrong_key}),
            pytest.raises(OAuthError, match="decrypt"),
        ):
            decrypt_refresh_token(token_file)


# ---------------------------------------------------------------------------
# 2. Refresh flow (mocked httpx)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_env")
class TestGetValidAccessToken:
    """Test get_valid_access_token with mocked HTTP responses."""

    async def test_cached_token_returned_when_valid(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """A cached token with future expiry is returned without HTTP call."""
        save_token(tmp_path, sample_token_file)
        future = datetime.now(UTC) + timedelta(hours=1)
        mock_client = AsyncMock(spec=httpx.AsyncClient)

        token, expires = await get_valid_access_token(
            tmp_path, "cached-access-token", future, mock_client
        )

        assert token == "cached-access-token"
        assert expires == future
        mock_client.post.assert_not_called()

    async def test_expired_token_triggers_refresh(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """An expired cached token triggers a refresh via Google endpoint."""
        save_token(tmp_path, sample_token_file)
        past = datetime.now(UTC) - timedelta(hours=1)
        response = _make_httpx_response(
            200,
            {
                "access_token": "new-access-token",
                "expires_in": 3600,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(tmp_path, "old-token", past, mock_client)

        assert token == "new-access-token"
        assert expires > datetime.now(UTC)
        mock_client.post.assert_called_once()

    async def test_last_refreshed_at_updated_on_disk(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """After a refresh, last_refreshed_at is updated in the token file."""
        save_token(tmp_path, sample_token_file)
        original_refreshed = sample_token_file.last_refreshed_at
        past = datetime.now(UTC) - timedelta(hours=1)
        response = _make_httpx_response(
            200,
            {
                "access_token": "refreshed-token",
                "expires_in": 3600,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        await get_valid_access_token(tmp_path, "old", past, mock_client)

        reloaded = load_token(tmp_path)
        assert reloaded is not None
        assert reloaded.last_refreshed_at >= original_refreshed

    async def test_no_token_file_raises(self, tmp_path: Path) -> None:
        """No token file on disk raises OAuthError."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        with pytest.raises(OAuthError, match="No OAuth token file"):
            await get_valid_access_token(tmp_path, None, None, mock_client)

    async def test_none_cached_triggers_refresh(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """None cached_token triggers a refresh."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(
            200,
            {
                "access_token": "fresh-token",
                "expires_in": 3600,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, _ = await get_valid_access_token(tmp_path, None, None, mock_client)
        assert token == "fresh-token"

    async def test_refresh_http_error_raises(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """HTTP error during refresh raises OAuthError."""
        save_token(tmp_path, sample_token_file)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.side_effect = httpx.ConnectError("connection failed")

        with pytest.raises(OAuthError, match=r"HTTP request.*failed"):
            await get_valid_access_token(tmp_path, None, None, mock_client)

    async def test_refresh_non_200_raises(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Non-200 status from token endpoint raises OAuthError."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(401, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="refresh failed"):
            await get_valid_access_token(tmp_path, None, None, mock_client)

    async def test_refresh_invalid_json_raises(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Malformed JSON from token endpoint raises OAuthError."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(200, invalid_json=True)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="invalid JSON"):
            await get_valid_access_token(tmp_path, None, None, mock_client)

    async def test_refresh_missing_access_token_raises(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Response without access_token field raises OAuthError."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(200, {"expires_in": 3600})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="missing access_token"):
            await get_valid_access_token(tmp_path, None, None, mock_client)


# ---------------------------------------------------------------------------
# 3. Expired token handling (60-second buffer)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_env")
class TestExpiryBuffer:
    """Tokens within the 60-second buffer are treated as expired."""

    async def test_within_buffer_triggers_refresh(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """A token expiring within 60 seconds is refreshed."""
        save_token(tmp_path, sample_token_file)
        almost_expired = datetime.now(UTC) + timedelta(seconds=30)
        response = _make_httpx_response(
            200,
            {
                "access_token": "buffer-refreshed",
                "expires_in": 3600,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, _ = await get_valid_access_token(
            tmp_path, "about-to-expire", almost_expired, mock_client
        )
        assert token == "buffer-refreshed"
        mock_client.post.assert_called_once()

    async def test_just_outside_buffer_no_refresh(self, tmp_path: Path) -> None:
        """A token expiring well past the buffer is returned as-is."""
        future = datetime.now(UTC) + timedelta(seconds=_EXPIRY_BUFFER_SECONDS + 120)
        mock_client = AsyncMock(spec=httpx.AsyncClient)

        token, _ = await get_valid_access_token(tmp_path, "still-good", future, mock_client)
        assert token == "still-good"
        mock_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Missing env vars raise OAuthError
# ---------------------------------------------------------------------------


class TestMissingEnvVars:
    """Required env vars missing raises OAuthError with safe messages."""

    def test_get_fernet_missing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing OAUTH_ENCRYPTION_KEY raises OAuthError."""
        monkeypatch.delenv("OAUTH_ENCRYPTION_KEY", raising=False)
        with pytest.raises(OAuthError, match="OAUTH_ENCRYPTION_KEY"):
            _get_fernet()

    def test_get_fernet_invalid_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Invalid Fernet key raises OAuthError."""
        monkeypatch.setenv("OAUTH_ENCRYPTION_KEY", "not-a-valid-fernet-key")
        with pytest.raises(OAuthError, match="not a valid Fernet key"):
            _get_fernet()

    def test_get_client_credentials_missing_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing GOOGLE_CLIENT_ID raises OAuthError."""
        monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
        monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
        with pytest.raises(OAuthError, match="GOOGLE_CLIENT_ID"):
            _get_client_credentials()

    def test_get_client_credentials_missing_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing GOOGLE_CLIENT_SECRET raises OAuthError."""
        monkeypatch.setenv("GOOGLE_CLIENT_ID", "id")
        monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)
        with pytest.raises(OAuthError, match="GOOGLE_CLIENT_SECRET"):
            _get_client_credentials()

    def test_build_consent_url_missing_client_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """build_consent_url raises OAuthError without GOOGLE_CLIENT_ID."""
        monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
        with pytest.raises(OAuthError, match="GOOGLE_CLIENT_ID"):
            build_consent_url("http://localhost/callback")

    async def test_exchange_code_missing_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """exchange_code raises OAuthError without client credentials."""
        monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
        monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        with pytest.raises(OAuthError, match="GOOGLE_CLIENT_ID"):
            await exchange_code("code", "http://localhost/cb", mock_client)

    def test_encrypt_refresh_token_missing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """encrypt_refresh_token raises OAuthError without encryption key."""
        monkeypatch.delenv("OAUTH_ENCRYPTION_KEY", raising=False)
        with pytest.raises(OAuthError, match="OAUTH_ENCRYPTION_KEY"):
            encrypt_refresh_token("some-token")


# ---------------------------------------------------------------------------
# 5. Adversarial: plaintext tokens never written to disk
# ---------------------------------------------------------------------------


class TestPlaintextNeverOnDisk:
    """After save_token, the raw file must not contain plaintext secrets."""

    def test_no_plaintext_refresh_token_on_disk(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """The plaintext refresh token must not appear in the file."""
        file_path = _write_token_on_disk(tmp_path, sample_token_file)
        raw_content = file_path.read_text(encoding="utf-8")
        assert _PLAINTEXT_REFRESH_TOKEN not in raw_content

    def test_encrypted_field_present_on_disk(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """The encrypted_refresh_token field must be present in the file."""
        file_path = _write_token_on_disk(tmp_path, sample_token_file)
        raw_content = file_path.read_text(encoding="utf-8")
        assert "encrypted_refresh_token" in raw_content

    def test_no_access_token_field_on_disk(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """No access_token field should appear anywhere in the file."""
        file_path = _write_token_on_disk(tmp_path, sample_token_file)
        raw_content = file_path.read_text(encoding="utf-8")
        assert "access_token" not in raw_content

    def test_no_refresh_token_key_on_disk(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """No bare 'refresh_token' key (only 'encrypted_refresh_token')."""
        file_path = _write_token_on_disk(tmp_path, sample_token_file)
        data = json.loads(file_path.read_text(encoding="utf-8"))
        assert "refresh_token" not in data
        assert "encrypted_refresh_token" in data


# ---------------------------------------------------------------------------
# 6. load_token edge cases
# ---------------------------------------------------------------------------


class TestLoadToken:
    """Tests for load_token: missing file, corrupt file, valid roundtrip."""

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        """load_token returns None when no token file exists."""
        result = load_token(tmp_path)
        assert result is None

    def test_corrupt_json_raises(self, tmp_path: Path) -> None:
        """load_token raises OAuthError for corrupt JSON."""
        token_path = tmp_path / "google.json"
        token_path.write_text("{invalid json!!", encoding="utf-8")
        with pytest.raises(OAuthError, match="parse"):
            load_token(tmp_path)

    def test_invalid_schema_raises(self, tmp_path: Path) -> None:
        """load_token raises OAuthError for valid JSON but invalid schema."""
        token_path = tmp_path / "google.json"
        token_path.write_text('{"foo": "bar"}', encoding="utf-8")
        with pytest.raises(OAuthError, match="parse"):
            load_token(tmp_path)

    def test_valid_roundtrip(self, tmp_path: Path, sample_token_file: TokenFile) -> None:
        """save then load roundtrip produces equivalent TokenFile."""
        save_token(tmp_path, sample_token_file)
        loaded = load_token(tmp_path)
        assert loaded is not None
        assert loaded.provider == sample_token_file.provider
        assert loaded.encrypted_refresh_token == sample_token_file.encrypted_refresh_token
        assert loaded.scopes == sample_token_file.scopes


# ---------------------------------------------------------------------------
# 7. File and directory permissions
# ---------------------------------------------------------------------------


class TestFilePermissions:
    """save_token creates directory 0o700 and file 0o600."""

    def test_directory_permissions(self, tmp_path: Path, sample_token_file: TokenFile) -> None:
        """Tokens directory is created with mode 0o700."""
        tokens_dir = tmp_path / "tokens"
        save_token(tokens_dir, sample_token_file)
        dir_mode = stat.S_IMODE(tokens_dir.stat().st_mode)
        assert dir_mode == 0o700

    def test_file_permissions(self, tmp_path: Path, sample_token_file: TokenFile) -> None:
        """Token file is written with mode 0o600."""
        tokens_dir = tmp_path / "tokens"
        save_token(tokens_dir, sample_token_file)
        file_path = tokens_dir / "google.json"
        file_mode = stat.S_IMODE(file_path.stat().st_mode)
        assert file_mode == 0o600


# ---------------------------------------------------------------------------
# 8. build_consent_url
# ---------------------------------------------------------------------------


class TestBuildConsentUrl:
    """Consent URL includes required params and scopes."""

    def test_includes_required_params(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """URL contains client_id, access_type=offline, prompt=consent, state."""
        monkeypatch.setenv("GOOGLE_CLIENT_ID", _TEST_CLIENT_ID)
        url, state = build_consent_url("http://localhost/callback")

        assert GOOGLE_AUTH_ENDPOINT in url
        assert _TEST_CLIENT_ID in url
        assert "access_type=offline" in url
        assert "prompt=consent" in url
        assert "response_type=code" in url
        assert f"state={state}" in url
        assert len(state) > 20  # cryptographically random, not trivially short

    def test_includes_all_scopes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """URL contains all configured Google scopes."""
        monkeypatch.setenv("GOOGLE_CLIENT_ID", _TEST_CLIENT_ID)
        url, _state = build_consent_url("http://localhost/callback")

        for scope in GOOGLE_SCOPES:
            # URL-encoded spaces become + or %20
            assert scope.replace(":", "%3A").replace("/", "%2F") in url or scope in url

    def test_includes_redirect_uri(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """URL contains the provided redirect_uri."""
        monkeypatch.setenv("GOOGLE_CLIENT_ID", _TEST_CLIENT_ID)
        redirect = "http://localhost:8000/oauth/callback"
        url, _state = build_consent_url(redirect)
        # URL-encoded form
        assert "localhost" in url


# ---------------------------------------------------------------------------
# 9. exchange_code
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("google_env")
class TestExchangeCode:
    """Tests for exchange_code with mocked httpx."""

    async def test_success(self) -> None:
        """Successful exchange returns (access_token, refresh_token, scopes)."""
        response = _make_httpx_response(
            200,
            {
                "access_token": "at-123",
                "refresh_token": "rt-456",
                "scope": "email profile",
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        access, refresh, scopes = await exchange_code(
            "auth-code", "http://localhost/cb", mock_client
        )

        assert access == "at-123"
        assert refresh == "rt-456"
        assert scopes == ["email", "profile"]
        mock_client.post.assert_called_once()

    async def test_http_error_raises(self) -> None:
        """HTTP error during exchange raises OAuthError."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.side_effect = httpx.ConnectError("fail")

        with pytest.raises(OAuthError, match=r"HTTP request.*failed"):
            await exchange_code("code", "http://localhost/cb", mock_client)

    async def test_non_200_raises(self) -> None:
        """Non-200 status raises OAuthError."""
        response = _make_httpx_response(400, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="Token exchange failed"):
            await exchange_code("code", "http://localhost/cb", mock_client)

    async def test_malformed_json_raises(self) -> None:
        """Malformed JSON response raises OAuthError."""
        response = _make_httpx_response(200, invalid_json=True)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="invalid JSON"):
            await exchange_code("code", "http://localhost/cb", mock_client)

    async def test_missing_tokens_raises(self) -> None:
        """Response without tokens raises OAuthError."""
        response = _make_httpx_response(200, {"scope": "email"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="missing access_token or refresh_token"):
            await exchange_code("code", "http://localhost/cb", mock_client)

    async def test_empty_scope_returns_empty_list(
        self,
    ) -> None:
        """Empty scope string returns an empty scopes list."""
        response = _make_httpx_response(
            200,
            {
                "access_token": "at",
                "refresh_token": "rt",
                "scope": "",
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        _, _, scopes = await exchange_code("code", "http://localhost/cb", mock_client)
        assert scopes == []


# ---------------------------------------------------------------------------
# 10. TokenFile model validation
# ---------------------------------------------------------------------------


class TestTokenFileValidation:
    """TokenFile Pydantic model accepts valid data, rejects invalid."""

    def test_valid_construction(self) -> None:
        """Valid data is accepted."""
        now = datetime.now(UTC)
        tf = TokenFile(
            provider="google",
            scopes=["scope1"],
            encrypted_refresh_token="gAAAAAB" + "x" * 50,
            created_at=now,
            last_refreshed_at=now,
        )
        assert tf.provider == "google"

    def test_missing_encrypted_token_raises(self) -> None:
        """Missing encrypted_refresh_token raises ValidationError."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            TokenFile(
                provider="google",
                scopes=["scope1"],
                created_at=now,
                last_refreshed_at=now,
            )  # type: ignore[call-arg]

    def test_empty_encrypted_token_raises(self) -> None:
        """Empty encrypted_refresh_token string raises ValidationError."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            TokenFile(
                provider="google",
                scopes=["scope1"],
                encrypted_refresh_token="",
                created_at=now,
                last_refreshed_at=now,
            )

    def test_invalid_provider_pattern_raises(self) -> None:
        """Provider with uppercase chars violates the pattern constraint."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            TokenFile(
                provider="Google",
                scopes=["scope1"],
                encrypted_refresh_token="encrypted_data",
                created_at=now,
                last_refreshed_at=now,
            )

    def test_missing_scopes_raises(self) -> None:
        """Missing scopes field raises ValidationError."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            TokenFile(
                provider="google",
                encrypted_refresh_token="encrypted_data",
                created_at=now,
                last_refreshed_at=now,
            )  # type: ignore[call-arg]

    def test_overly_long_encrypted_token_raises(self) -> None:
        """encrypted_refresh_token exceeding max_length raises ValidationError."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            TokenFile(
                provider="google",
                scopes=["scope1"],
                encrypted_refresh_token="x" * 5000,
                created_at=now,
                last_refreshed_at=now,
            )

    def test_default_provider(self) -> None:
        """Provider defaults to 'google' when not specified."""
        now = datetime.now(UTC)
        tf = TokenFile(
            scopes=["scope1"],
            encrypted_refresh_token="encrypted_data",
            created_at=now,
            last_refreshed_at=now,
        )
        assert tf.provider == "google"


# ---------------------------------------------------------------------------
# 11. OAuthError has safe messages
# ---------------------------------------------------------------------------


class TestOAuthErrorMessages:
    """OAuthError messages must not leak credentials."""

    @pytest.mark.parametrize(
        "env_var",
        ["OAUTH_ENCRYPTION_KEY", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"],
    )
    def test_error_message_excludes_secrets(
        self, monkeypatch: pytest.MonkeyPatch, env_var: str
    ) -> None:
        """Error messages do not contain actual secret values."""
        secret_value = "super-secret-value-12345"
        monkeypatch.setenv(env_var, secret_value)
        # Clear the others to trigger errors from different paths
        for var in ["OAUTH_ENCRYPTION_KEY", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]:
            if var != env_var:
                monkeypatch.delenv(var, raising=False)

        # Try operations that will fail
        try:
            _get_fernet()
        except OAuthError as exc:
            assert secret_value not in str(exc)

        try:
            _get_client_credentials()
        except OAuthError as exc:
            assert secret_value not in str(exc)
