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
    MICROSOFT_AUTH_ENDPOINT,
    MICROSOFT_SCOPES,
    OAuthError,
    OAuthRefreshError,
    TokenFile,
    _get_client_credentials,
    _get_fernet,
    _get_microsoft_client_credentials,
    _safe_error_code,
    build_consent_url,
    build_microsoft_consent_url,
    decrypt_refresh_token,
    encrypt_refresh_token,
    exchange_code,
    exchange_microsoft_code,
    get_connection_status,
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
_TEST_MS_CLIENT_ID: str = "ms-test-client-id-456"
_TEST_MS_CLIENT_SECRET: str = "ms-test-client-secret-def"
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
def microsoft_env(monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    """Set MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET. Returns (id, secret)."""
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", _TEST_MS_CLIENT_ID)
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", _TEST_MS_CLIENT_SECRET)
    return _TEST_MS_CLIENT_ID, _TEST_MS_CLIENT_SECRET


@pytest.fixture()
def full_env(fernet_env: str, google_env: tuple[str, str]) -> tuple[str, str, str]:
    """Set all three required env vars. Returns (fernet_key, client_id, secret)."""
    return fernet_env, google_env[0], google_env[1]


@pytest.fixture()
def full_microsoft_env(fernet_env: str, microsoft_env: tuple[str, str]) -> tuple[str, str, str]:
    """Set Fernet + Microsoft env vars. Returns (fernet_key, client_id, secret)."""
    return fernet_env, microsoft_env[0], microsoft_env[1]


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


@pytest.fixture()
def microsoft_token_file(fernet_env: str) -> TokenFile:
    """A valid TokenFile with an encrypted refresh token for Microsoft."""
    _ = fernet_env
    encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
    now = datetime.now(UTC)
    return TokenFile(
        provider="microsoft",
        scopes=list(MICROSOFT_SCOPES),
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
            tmp_path, "google", "cached-access-token", future, mock_client
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

        token, expires = await get_valid_access_token(
            tmp_path, "google", "old-token", past, mock_client
        )

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

        await get_valid_access_token(tmp_path, "google", "old", past, mock_client)

        reloaded = load_token(tmp_path)
        assert reloaded is not None
        assert reloaded.last_refreshed_at >= original_refreshed

    async def test_no_token_file_raises(self, tmp_path: Path) -> None:
        """No token file on disk raises OAuthError."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        with pytest.raises(OAuthError, match="No google OAuth token file"):
            await get_valid_access_token(tmp_path, "google", None, None, mock_client)

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

        token, _ = await get_valid_access_token(tmp_path, "google", None, None, mock_client)
        assert token == "fresh-token"

    async def test_refresh_http_error_raises(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """HTTP error during refresh raises OAuthError."""
        save_token(tmp_path, sample_token_file)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.side_effect = httpx.ConnectError("connection failed")

        with pytest.raises(OAuthError, match=r"HTTP request.*failed"):
            await get_valid_access_token(tmp_path, "google", None, None, mock_client)

    async def test_refresh_non_200_raises(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Non-200 status from token endpoint raises OAuthError."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(401, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="refresh failed"):
            await get_valid_access_token(tmp_path, "google", None, None, mock_client)

    async def test_refresh_invalid_json_raises(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Malformed JSON from token endpoint raises OAuthError."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(200, invalid_json=True)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="invalid JSON"):
            await get_valid_access_token(tmp_path, "google", None, None, mock_client)

    async def test_refresh_missing_access_token_raises(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Response without access_token field raises OAuthError."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(200, {"expires_in": 3600})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="missing access_token"):
            await get_valid_access_token(tmp_path, "google", None, None, mock_client)


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
            tmp_path, "google", "about-to-expire", almost_expired, mock_client
        )
        assert token == "buffer-refreshed"
        mock_client.post.assert_called_once()

    async def test_just_outside_buffer_no_refresh(self, tmp_path: Path) -> None:
        """A token expiring well past the buffer is returned as-is."""
        future = datetime.now(UTC) + timedelta(seconds=_EXPIRY_BUFFER_SECONDS + 120)
        mock_client = AsyncMock(spec=httpx.AsyncClient)

        token, _ = await get_valid_access_token(
            tmp_path, "google", "still-good", future, mock_client
        )
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

        with pytest.raises(OAuthError, match="token exchange failed"):
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

    def test_explicit_provider(self) -> None:
        """Provider field accepts 'google' and 'microsoft'."""
        now = datetime.now(UTC)
        for provider in ("google", "microsoft"):
            tf = TokenFile(
                provider=provider,
                scopes=["scope1"],
                encrypted_refresh_token="encrypted_data",
                created_at=now,
                last_refreshed_at=now,
            )
            assert tf.provider == provider


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


# ---------------------------------------------------------------------------
# 12. _get_microsoft_client_credentials
# ---------------------------------------------------------------------------


class TestGetMicrosoftClientCredentials:
    """Missing Microsoft client env vars raise OAuthError."""

    def test_missing_client_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing MICROSOFT_CLIENT_ID raises OAuthError."""
        monkeypatch.delenv("MICROSOFT_CLIENT_ID", raising=False)
        monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "secret")
        with pytest.raises(OAuthError, match="MICROSOFT_CLIENT_ID"):
            _get_microsoft_client_credentials()

    def test_missing_client_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing MICROSOFT_CLIENT_SECRET raises OAuthError."""
        monkeypatch.setenv("MICROSOFT_CLIENT_ID", "id")
        monkeypatch.delenv("MICROSOFT_CLIENT_SECRET", raising=False)
        with pytest.raises(OAuthError, match="MICROSOFT_CLIENT_SECRET"):
            _get_microsoft_client_credentials()

    def test_both_present_returns_tuple(self, microsoft_env: tuple[str, str]) -> None:
        """Both env vars set returns (client_id, client_secret)."""
        cid, csecret = _get_microsoft_client_credentials()
        assert cid == _TEST_MS_CLIENT_ID
        assert csecret == _TEST_MS_CLIENT_SECRET


# ---------------------------------------------------------------------------
# 13. build_microsoft_consent_url
# ---------------------------------------------------------------------------


class TestBuildMicrosoftConsentUrl:
    """Microsoft consent URL construction."""

    def test_includes_required_params(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """URL contains client_id, response_mode, response_type, state."""
        monkeypatch.setenv("MICROSOFT_CLIENT_ID", _TEST_MS_CLIENT_ID)
        url, state = build_microsoft_consent_url("http://localhost/callback")

        assert MICROSOFT_AUTH_ENDPOINT in url
        assert _TEST_MS_CLIENT_ID in url
        assert "response_type=code" in url
        assert "response_mode=query" in url
        assert f"state={state}" in url
        assert len(state) > 20

    def test_includes_all_scopes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """URL contains all configured Microsoft scopes."""
        monkeypatch.setenv("MICROSOFT_CLIENT_ID", _TEST_MS_CLIENT_ID)
        url, _state = build_microsoft_consent_url("http://localhost/callback")

        for scope in MICROSOFT_SCOPES:
            assert scope in url or scope.replace(".", "%2E") in url

    def test_mail_send_scope_present(self) -> None:
        """Mail.Send scope is required for /me/sendMail — GH-61."""
        assert "Mail.Send" in MICROSOFT_SCOPES

    def test_includes_redirect_uri(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """URL contains the provided redirect_uri."""
        monkeypatch.setenv("MICROSOFT_CLIENT_ID", _TEST_MS_CLIENT_ID)
        redirect = "http://localhost:8000/oauth/callback"
        url, _state = build_microsoft_consent_url(redirect)
        assert "localhost" in url

    def test_missing_client_id_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing MICROSOFT_CLIENT_ID raises OAuthError."""
        monkeypatch.delenv("MICROSOFT_CLIENT_ID", raising=False)
        with pytest.raises(OAuthError, match="MICROSOFT_CLIENT_ID"):
            build_microsoft_consent_url("http://localhost/callback")


# ---------------------------------------------------------------------------
# 14. exchange_microsoft_code
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("microsoft_env")
class TestExchangeMicrosoftCode:
    """Tests for exchange_microsoft_code with mocked httpx."""

    async def test_success(self) -> None:
        """Successful exchange returns (access_token, refresh_token, scopes)."""
        response = _make_httpx_response(
            200,
            {
                "access_token": "ms-at-123",
                "refresh_token": "ms-rt-456",
                "scope": "Mail.Read Calendars.ReadWrite",
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        access, refresh, scopes = await exchange_microsoft_code(
            "auth-code", "http://localhost/cb", mock_client
        )

        assert access == "ms-at-123"
        assert refresh == "ms-rt-456"
        assert scopes == ["Mail.Read", "Calendars.ReadWrite"]
        mock_client.post.assert_called_once()

    async def test_http_error_raises(self) -> None:
        """HTTP error during exchange raises OAuthError."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.side_effect = httpx.ConnectError("fail")

        with pytest.raises(OAuthError, match=r"HTTP request.*Microsoft.*failed"):
            await exchange_microsoft_code("code", "http://localhost/cb", mock_client)

    async def test_non_200_raises(self) -> None:
        """Non-200 status raises OAuthError."""
        response = _make_httpx_response(400, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="Microsoft token exchange failed"):
            await exchange_microsoft_code("code", "http://localhost/cb", mock_client)

    async def test_malformed_json_raises(self) -> None:
        """Malformed JSON response raises OAuthError."""
        response = _make_httpx_response(200, invalid_json=True)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="invalid JSON"):
            await exchange_microsoft_code("code", "http://localhost/cb", mock_client)

    async def test_missing_tokens_raises(self) -> None:
        """Response without tokens raises OAuthError."""
        response = _make_httpx_response(200, {"scope": "Mail.Read"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="missing access_token or refresh_token"):
            await exchange_microsoft_code("code", "http://localhost/cb", mock_client)

    async def test_empty_scope_returns_empty_list(self) -> None:
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

        _, _, scopes = await exchange_microsoft_code("code", "http://localhost/cb", mock_client)
        assert scopes == []


# ---------------------------------------------------------------------------
# 15. _refresh_microsoft_token (via get_valid_access_token)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_microsoft_env")
class TestRefreshMicrosoftToken:
    """Test Microsoft token refresh through get_valid_access_token."""

    async def test_expired_token_triggers_microsoft_refresh(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """An expired Microsoft token triggers refresh via Microsoft endpoint."""
        save_token(tmp_path, microsoft_token_file)
        past = datetime.now(UTC) - timedelta(hours=1)
        response = _make_httpx_response(
            200,
            {
                "access_token": "ms-new-access-token",
                "expires_in": 3600,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(
            tmp_path, "microsoft", "old-ms-token", past, mock_client
        )

        assert token == "ms-new-access-token"
        assert expires > datetime.now(UTC)
        mock_client.post.assert_called_once()

    async def test_none_cached_triggers_microsoft_refresh(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """None cached_token triggers a Microsoft refresh."""
        save_token(tmp_path, microsoft_token_file)
        response = _make_httpx_response(
            200,
            {
                "access_token": "ms-fresh-token",
                "expires_in": 3600,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, _ = await get_valid_access_token(tmp_path, "microsoft", None, None, mock_client)
        assert token == "ms-fresh-token"

    async def test_no_microsoft_token_file_raises(self, tmp_path: Path) -> None:
        """No Microsoft token file on disk raises OAuthError."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        with pytest.raises(OAuthError, match="No microsoft OAuth token file"):
            await get_valid_access_token(tmp_path, "microsoft", None, None, mock_client)

    async def test_microsoft_refresh_http_error_raises(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """HTTP error during Microsoft refresh raises OAuthError."""
        save_token(tmp_path, microsoft_token_file)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.side_effect = httpx.ConnectError("connection failed")

        with pytest.raises(OAuthError, match=r"HTTP request.*Microsoft.*failed"):
            await get_valid_access_token(tmp_path, "microsoft", None, None, mock_client)

    async def test_microsoft_refresh_non_200_raises(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """Non-200 status from Microsoft token endpoint raises OAuthError."""
        save_token(tmp_path, microsoft_token_file)
        response = _make_httpx_response(401, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="Microsoft token refresh failed"):
            await get_valid_access_token(tmp_path, "microsoft", None, None, mock_client)

    async def test_microsoft_refresh_invalid_json_raises(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """Malformed JSON from Microsoft token endpoint raises OAuthError."""
        save_token(tmp_path, microsoft_token_file)
        response = _make_httpx_response(200, invalid_json=True)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="invalid JSON"):
            await get_valid_access_token(tmp_path, "microsoft", None, None, mock_client)

    async def test_microsoft_refresh_missing_access_token_raises(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """Response without access_token from Microsoft raises OAuthError."""
        save_token(tmp_path, microsoft_token_file)
        response = _make_httpx_response(200, {"expires_in": 3600})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="missing access_token"):
            await get_valid_access_token(tmp_path, "microsoft", None, None, mock_client)

    async def test_microsoft_refresh_invalid_expires_in_defaults(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """Invalid expires_in defaults to 3600."""
        save_token(tmp_path, microsoft_token_file)
        response = _make_httpx_response(
            200,
            {
                "access_token": "ms-token",
                "expires_in": -1,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(
            tmp_path, "microsoft", None, None, mock_client
        )
        assert token == "ms-token"
        expected_min = datetime.now(UTC) + timedelta(seconds=3500)
        assert expires > expected_min

    async def test_microsoft_last_refreshed_at_updated(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """After Microsoft refresh, last_refreshed_at is updated in the token file."""
        save_token(tmp_path, microsoft_token_file)
        original_refreshed = microsoft_token_file.last_refreshed_at
        response = _make_httpx_response(
            200,
            {
                "access_token": "ms-refreshed",
                "expires_in": 3600,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        await get_valid_access_token(tmp_path, "microsoft", None, None, mock_client)

        reloaded = load_token(tmp_path, "microsoft")
        assert reloaded is not None
        assert reloaded.last_refreshed_at >= original_refreshed


# ---------------------------------------------------------------------------
# 16. load_token with provider="microsoft"
# ---------------------------------------------------------------------------


class TestLoadTokenMicrosoft:
    """Tests for load_token with Microsoft provider."""

    def test_missing_microsoft_file_returns_none(self, tmp_path: Path) -> None:
        """load_token returns None when no microsoft.json exists."""
        result = load_token(tmp_path, "microsoft")
        assert result is None

    def test_corrupt_microsoft_json_raises(self, tmp_path: Path) -> None:
        """load_token raises OAuthError for corrupt microsoft.json."""
        token_path = tmp_path / "microsoft.json"
        token_path.write_text("{invalid json!!", encoding="utf-8")
        with pytest.raises(OAuthError, match="parse"):
            load_token(tmp_path, "microsoft")

    def test_valid_microsoft_roundtrip(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """save then load roundtrip for Microsoft produces equivalent TokenFile."""
        save_token(tmp_path, microsoft_token_file)
        loaded = load_token(tmp_path, "microsoft")
        assert loaded is not None
        assert loaded.provider == "microsoft"
        assert loaded.encrypted_refresh_token == microsoft_token_file.encrypted_refresh_token
        assert loaded.scopes == microsoft_token_file.scopes


# ---------------------------------------------------------------------------
# 17. save_token OSError paths
# ---------------------------------------------------------------------------


class TestSaveTokenErrors:
    """save_token raises OAuthError on directory or file write failures."""

    def test_mkdir_failure_raises(self, tmp_path: Path, sample_token_file: TokenFile) -> None:
        """OSError during mkdir raises OAuthError."""
        bad_dir = tmp_path / "tokens"
        # Create a file at the path so mkdir fails
        bad_dir.write_text("not a directory", encoding="utf-8")
        with pytest.raises(OAuthError, match=r"create tokens directory|write token file"):
            save_token(bad_dir, sample_token_file)

    def test_write_failure_raises(self, tmp_path: Path, sample_token_file: TokenFile) -> None:
        """OSError during file write raises OAuthError."""
        tokens_dir = tmp_path / "tokens"
        tokens_dir.mkdir(mode=0o700)
        # Create a subdirectory where the file should be, causing os.open to fail
        file_path = tokens_dir / "google.json"
        file_path.mkdir()
        with pytest.raises(OAuthError, match="write token file"):
            save_token(tokens_dir, sample_token_file)


# ---------------------------------------------------------------------------
# 18. _safe_error_code edge cases
# ---------------------------------------------------------------------------


class TestSafeErrorCode:
    """_safe_error_code handles various response bodies."""

    def test_valid_json_with_error_field(self) -> None:
        """Returns the error field from JSON body."""
        response = _make_httpx_response(400, {"error": "invalid_grant"})
        assert _safe_error_code(response) == "invalid_grant"

    def test_non_json_response_returns_unknown(self) -> None:
        """Non-JSON response returns 'unknown'."""
        response = _make_httpx_response(500, invalid_json=True)
        assert _safe_error_code(response) == "unknown"

    def test_json_without_error_field_returns_unknown(self) -> None:
        """JSON without 'error' field returns 'unknown'."""
        response = _make_httpx_response(400, {"message": "something"})
        assert _safe_error_code(response) == "unknown"

    def test_truncates_long_error_codes(self) -> None:
        """Error codes longer than 64 chars are truncated."""
        long_error = "x" * 100
        response = _make_httpx_response(400, {"error": long_error})
        result = _safe_error_code(response)
        assert len(result) == 64


# ---------------------------------------------------------------------------
# 19. save_token failure in get_valid_access_token is non-fatal
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_env")
class TestSaveTokenNonFatalInRefresh:
    """save_token failure during refresh does not prevent token return."""

    async def test_save_failure_logs_but_returns_token(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """If save_token fails after refresh, the access token is still returned."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(
            200,
            {
                "access_token": "refreshed-despite-save-fail",
                "expires_in": 3600,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with patch("admino.oauth.save_token", side_effect=OAuthError("disk full")):
            token, expires = await get_valid_access_token(
                tmp_path, "google", None, None, mock_client
            )

        assert token == "refreshed-despite-save-fail"
        assert expires > datetime.now(UTC)


# ---------------------------------------------------------------------------
# 20. Google refresh with invalid expires_in
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_env")
class TestGoogleRefreshExpiresInEdgeCases:
    """Edge cases for expires_in in Google token refresh."""

    async def test_invalid_expires_in_defaults_to_3600(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Non-integer expires_in defaults to 3600 seconds."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(
            200,
            {
                "access_token": "token-with-bad-expiry",
                "expires_in": "not-an-int",
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(tmp_path, "google", None, None, mock_client)
        assert token == "token-with-bad-expiry"
        expected_min = datetime.now(UTC) + timedelta(seconds=3500)
        assert expires > expected_min

    async def test_zero_expires_in_defaults_to_3600(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """Zero expires_in defaults to 3600 seconds."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(
            200,
            {
                "access_token": "token-zero-expiry",
                "expires_in": 0,
            },
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(tmp_path, "google", None, None, mock_client)
        assert token == "token-zero-expiry"
        expected_min = datetime.now(UTC) + timedelta(seconds=3500)
        assert expires > expected_min


# ---------------------------------------------------------------------------
# 21. Invalid-token marking (reconnect-required state) — GH-36 / GH-64
# ---------------------------------------------------------------------------


class TestTokenFileInvalidField:
    """The TokenFile model carries an `invalid` flag, defaulting to False."""

    def test_invalid_defaults_to_false(self, sample_token_file: TokenFile) -> None:
        """A freshly constructed TokenFile is not flagged invalid."""
        assert sample_token_file.invalid is False

    def test_legacy_token_file_without_invalid_loads_as_false(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """A token file written before the field existed loads with invalid=False."""
        save_token(tmp_path, sample_token_file)
        path = tmp_path / "google.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data.pop("invalid", None)
        path.write_text(json.dumps(data), encoding="utf-8")

        reloaded = load_token(tmp_path)
        assert reloaded is not None
        assert reloaded.invalid is False


@pytest.mark.usefixtures("google_env")
class TestTerminalRefreshMarksInvalid:
    """A terminal (invalid_grant) refresh failure persists invalid=True."""

    async def test_invalid_grant_raises_terminal_refresh_error(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """A 400 invalid_grant refresh failure raises a terminal OAuthRefreshError."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(400, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthRefreshError) as exc_info:
            await get_valid_access_token(tmp_path, "google", None, None, mock_client)
        assert exc_info.value.terminal is True

    async def test_invalid_grant_persists_invalid_flag_on_disk(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """After a terminal refresh failure the token file is flagged invalid=True."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(400, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthRefreshError):
            await get_valid_access_token(tmp_path, "google", None, None, mock_client)

        reloaded = load_token(tmp_path)
        assert reloaded is not None
        assert reloaded.invalid is True

    async def test_microsoft_invalid_grant_persists_invalid_flag(
        self,
        tmp_path: Path,
        microsoft_token_file: TokenFile,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Microsoft terminal refresh failure also flags the token invalid."""
        monkeypatch.setenv("MICROSOFT_CLIENT_ID", _TEST_MS_CLIENT_ID)
        monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", _TEST_MS_CLIENT_SECRET)
        save_token(tmp_path, microsoft_token_file)
        response = _make_httpx_response(400, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthRefreshError):
            await get_valid_access_token(tmp_path, "microsoft", None, None, mock_client)

        reloaded = load_token(tmp_path, "microsoft")
        assert reloaded is not None
        assert reloaded.invalid is True


@pytest.mark.usefixtures("google_env")
class TestTransientRefreshDoesNotMarkInvalid:
    """Transient failures (network, 5xx) must NOT flag the token invalid."""

    async def test_http_error_does_not_mark_invalid(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """A network error during refresh leaves invalid=False."""
        save_token(tmp_path, sample_token_file)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.side_effect = httpx.ConnectError("connection failed")

        with pytest.raises(OAuthError):
            await get_valid_access_token(tmp_path, "google", None, None, mock_client)

        reloaded = load_token(tmp_path)
        assert reloaded is not None
        assert reloaded.invalid is False

    async def test_server_error_does_not_mark_invalid(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """A 503 from the token endpoint is transient and leaves invalid=False."""
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(503, {"error": "temporarily_unavailable"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError) as exc_info:
            await get_valid_access_token(tmp_path, "google", None, None, mock_client)
        if isinstance(exc_info.value, OAuthRefreshError):
            assert exc_info.value.terminal is False

        reloaded = load_token(tmp_path)
        assert reloaded is not None
        assert reloaded.invalid is False


@pytest.mark.usefixtures("google_env")
class TestSuccessfulRefreshClearsInvalid:
    """A successful refresh clears a previously-set invalid flag (recovery)."""

    async def test_successful_refresh_resets_invalid_to_false(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """If a token was flagged invalid, a later successful refresh clears it."""
        sample_token_file.invalid = True
        save_token(tmp_path, sample_token_file)
        response = _make_httpx_response(200, {"access_token": "ok", "expires_in": 3600})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, _ = await get_valid_access_token(tmp_path, "google", None, None, mock_client)
        assert token == "ok"

        reloaded = load_token(tmp_path)
        assert reloaded is not None
        assert reloaded.invalid is False


@pytest.mark.usefixtures("microsoft_env")
class TestMicrosoftTransientRefresh:
    """Non-invalid_grant Microsoft refresh failures are transient, not terminal."""

    async def test_microsoft_transient_error_is_not_terminal(
        self, tmp_path: Path, microsoft_token_file: TokenFile
    ) -> None:
        """A 503 from the Microsoft token endpoint raises a non-terminal error."""
        save_token(tmp_path, microsoft_token_file)
        response = _make_httpx_response(503, {"error": "temporarily_unavailable"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthRefreshError) as exc_info:
            await get_valid_access_token(tmp_path, "microsoft", None, None, mock_client)
        assert exc_info.value.terminal is False

        reloaded = load_token(tmp_path, "microsoft")
        assert reloaded is not None
        assert reloaded.invalid is False


class TestGetConnectionStatus:
    """get_connection_status reports (connected, healthy) from local state only."""

    def test_no_token_file_is_not_connected(self, tmp_path: Path) -> None:
        """No token file → (False, False)."""
        assert get_connection_status(tmp_path, "google") == (False, False)

    def test_valid_token_is_connected_and_healthy(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """A token file that is not flagged invalid → (True, True)."""
        save_token(tmp_path, sample_token_file)
        assert get_connection_status(tmp_path, "google") == (True, True)

    def test_invalid_token_is_connected_but_unhealthy(
        self, tmp_path: Path, sample_token_file: TokenFile
    ) -> None:
        """A token file flagged invalid → (True, False)."""
        sample_token_file.invalid = True
        save_token(tmp_path, sample_token_file)
        assert get_connection_status(tmp_path, "google") == (True, False)

    def test_corrupt_token_file_is_connected_but_unhealthy(self, tmp_path: Path) -> None:
        """An unparseable token file → (True, False) so the UI prompts reconnect."""
        path = tmp_path / "google.json"
        path.write_text("not valid json{{{", encoding="utf-8")
        assert get_connection_status(tmp_path, "google") == (True, False)
