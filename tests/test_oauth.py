"""Tests for the OAuth token management module (admino.oauth).

Covers encryption/decryption roundtrips, token refresh flows, DB-backed
token persistence (load/save/delete via asyncpg pool), healthy-flag
transitions, connection status, revocation, missing env var errors,
consent URL construction, code exchange, and adversarial checks that
plaintext refresh tokens are never persisted in cleartext.

GH-86: refresh tokens moved from encrypted files into PostgreSQL. These
tests target the DB-backed contract (async functions taking an asyncpg
pool as the first argument), NOT the removed file-based implementation.

Security notes:
- All HTTP clients are mocked — no real Google/Microsoft API calls.
- The database pool is mocked (``mock_pool`` fixture) — no real DB.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

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
    OAuthToken,
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

if TYPE_CHECKING:
    from unittest.mock import MagicMock

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
def sample_token(fernet_env: str) -> OAuthToken:
    """A valid Google OAuthToken with an encrypted refresh token."""
    _ = fernet_env  # Fixture ensures OAUTH_ENCRYPTION_KEY is set
    encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
    now = datetime.now(UTC)
    return OAuthToken(
        provider="google",
        scopes=list(GOOGLE_SCOPES),
        encrypted_refresh_token=encrypted,
        email="user@gmail.com",
        created_at=now,
        last_refreshed_at=now,
    )


@pytest.fixture()
def microsoft_token(fernet_env: str) -> OAuthToken:
    """A valid Microsoft OAuthToken with an encrypted refresh token."""
    _ = fernet_env
    encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
    now = datetime.now(UTC)
    return OAuthToken(
        provider="microsoft",
        scopes=list(MICROSOFT_SCOPES),
        encrypted_refresh_token=encrypted,
        email=None,
        created_at=now,
        last_refreshed_at=now,
    )


def _row_from_token(token: OAuthToken) -> dict[str, Any]:
    """Build an asyncpg-style row dict mirroring the oauth_tokens columns.

    asyncpg Records support mapping access (``row["col"]``); a plain dict is
    an adequate stand-in for the mocked pool. ``scopes`` is stored as JSONB,
    which asyncpg returns as a JSON string, so we serialise it here.
    """
    return {
        "provider": token.provider,
        "encrypted_refresh_token": token.encrypted_refresh_token,
        "email": token.email,
        "scopes": json.dumps(token.scopes),
        "healthy": token.healthy,
        "created_at": token.created_at,
        "last_refreshed_at": token.last_refreshed_at,
    }


def _prime_fetchrow(mock_pool: MagicMock, row: dict[str, Any] | None) -> None:
    """Configure both pool.fetchrow and the acquired-connection fetchrow."""
    mock_pool.fetchrow = AsyncMock(return_value=row)
    mock_pool._mock_conn.fetchrow = AsyncMock(return_value=row)


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
    """Encrypt a refresh token, hold in an OAuthToken, decrypt and verify."""

    def test_roundtrip_matches_plaintext(self) -> None:
        """Encrypted then decrypted token equals the original plaintext."""
        encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
        token = OAuthToken(
            provider="google",
            scopes=["scope1"],
            encrypted_refresh_token=encrypted,
            created_at=datetime.now(UTC),
            last_refreshed_at=datetime.now(UTC),
        )
        result = decrypt_refresh_token(token)
        assert result == _PLAINTEXT_REFRESH_TOKEN

    def test_encrypted_differs_from_plaintext(self) -> None:
        """The ciphertext must not equal the plaintext."""
        encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
        assert encrypted != _PLAINTEXT_REFRESH_TOKEN

    def test_decrypt_with_wrong_key_raises(self) -> None:
        """Decrypting with a different key raises OAuthError."""
        encrypted = encrypt_refresh_token(_PLAINTEXT_REFRESH_TOKEN)
        token = OAuthToken(
            provider="google",
            scopes=["scope1"],
            encrypted_refresh_token=encrypted,
            created_at=datetime.now(UTC),
            last_refreshed_at=datetime.now(UTC),
        )
        wrong_key = Fernet.generate_key().decode()
        with (
            patch.dict("os.environ", {"OAUTH_ENCRYPTION_KEY": wrong_key}),
            pytest.raises(OAuthError, match="decrypt"),
        ):
            decrypt_refresh_token(token)


# ---------------------------------------------------------------------------
# 2. load_token (DB-backed)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fernet_env")
class TestLoadToken:
    """load_token reads a row via the pool and returns an OAuthToken or None."""

    pytestmark = pytest.mark.asyncio

    async def test_returns_token_from_row(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A fetched row is mapped to an OAuthToken."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))

        result = await load_token(mock_pool, "google")

        assert result is not None
        assert result.provider == "google"
        assert result.encrypted_refresh_token == sample_token.encrypted_refresh_token
        assert result.scopes == sample_token.scopes

    async def test_returns_none_when_no_row(self, mock_pool: MagicMock) -> None:
        """No matching row returns None."""
        _prime_fetchrow(mock_pool, None)

        result = await load_token(mock_pool, "google")

        assert result is None

    async def test_select_is_parameterized_with_provider(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """The SELECT passes the provider as a bound parameter, not interpolated."""
        row = _row_from_token(sample_token)
        _prime_fetchrow(mock_pool, row)

        await load_token(mock_pool, "google")

        # Whichever fetchrow was used, "google" must be a bound argument and
        # the SQL text must use a positional placeholder ($1), never the raw value.
        call = mock_pool.fetchrow.call_args or mock_pool._mock_conn.fetchrow.call_args
        assert call is not None
        sql = call.args[0]
        assert "$1" in sql
        assert "google" in call.args[1:]
        assert "google" not in sql

    async def test_healthy_flag_read_from_row(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """An unhealthy row loads with healthy=False."""
        row = _row_from_token(sample_token)
        row["healthy"] = False
        _prime_fetchrow(mock_pool, row)

        result = await load_token(mock_pool, "google")

        assert result is not None
        assert result.healthy is False


# ---------------------------------------------------------------------------
# 3. save_token (DB-backed UPSERT)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fernet_env")
class TestSaveToken:
    """save_token issues a parameterized UPSERT."""

    pytestmark = pytest.mark.asyncio

    def _executed_call(self, mock_pool: MagicMock) -> Any:
        """Return whichever execute mock was invoked (pool or connection)."""
        return mock_pool.execute.call_args or mock_pool._mock_conn.execute.call_args

    async def test_upsert_on_conflict(self, mock_pool: MagicMock, sample_token: OAuthToken) -> None:
        """save_token issues an INSERT ... ON CONFLICT (provider) DO UPDATE."""
        await save_token(mock_pool, sample_token)

        call = self._executed_call(mock_pool)
        assert call is not None
        sql = call.args[0].upper()
        assert "INSERT INTO" in sql
        assert "ON CONFLICT" in sql
        assert "DO UPDATE" in sql

    async def test_query_is_parameterized(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """The UPSERT uses positional placeholders, not string interpolation."""
        await save_token(mock_pool, sample_token)

        call = self._executed_call(mock_pool)
        assert call is not None
        sql = call.args[0]
        assert "$1" in sql
        # The encrypted secret must never be interpolated into the SQL text.
        assert sample_token.encrypted_refresh_token not in sql

    async def test_encrypted_token_and_email_passed_through(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """The encrypted token and email are bound as parameters."""
        await save_token(mock_pool, sample_token)

        call = self._executed_call(mock_pool)
        assert call is not None
        args = call.args[1:]
        assert sample_token.encrypted_refresh_token in args
        assert sample_token.email in args

    async def test_scopes_serialized_as_json(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """scopes are serialised to a JSON string for the JSONB column."""
        await save_token(mock_pool, sample_token)

        call = self._executed_call(mock_pool)
        assert call is not None
        args = call.args[1:]
        serialized = json.dumps(sample_token.scopes)
        assert serialized in args


# ---------------------------------------------------------------------------
# 4. delete_token (DB-backed)
# ---------------------------------------------------------------------------


class TestDeleteToken:
    """delete_token returns True/False based on the DELETE status tag."""

    pytestmark = pytest.mark.asyncio

    def _prime_execute(self, mock_pool: MagicMock, status: str) -> None:
        mock_pool.execute = AsyncMock(return_value=status)
        mock_pool._mock_conn.execute = AsyncMock(return_value=status)

    async def test_returns_true_when_row_deleted(self, mock_pool: MagicMock) -> None:
        """A 'DELETE 1' status tag means a row existed and was removed."""
        from admino.oauth import delete_token

        self._prime_execute(mock_pool, "DELETE 1")

        result = await delete_token(mock_pool, "google")

        assert result is True

    async def test_returns_false_when_no_row(self, mock_pool: MagicMock) -> None:
        """A 'DELETE 0' status tag means nothing was deleted."""
        from admino.oauth import delete_token

        self._prime_execute(mock_pool, "DELETE 0")

        result = await delete_token(mock_pool, "google")

        assert result is False

    async def test_delete_is_parameterized(self, mock_pool: MagicMock) -> None:
        """The DELETE binds the provider as a parameter."""
        from admino.oauth import delete_token

        self._prime_execute(mock_pool, "DELETE 1")

        await delete_token(mock_pool, "google")

        call = mock_pool.execute.call_args or mock_pool._mock_conn.execute.call_args
        assert call is not None
        sql = call.args[0].upper()
        assert "DELETE FROM" in sql
        assert "$1" in call.args[0]
        assert "google" in call.args[1:]


# ---------------------------------------------------------------------------
# 5. get_valid_access_token — refresh flow (DB-backed)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_env")
class TestGetValidAccessToken:
    """get_valid_access_token loads/saves via the pool and refreshes as needed."""

    pytestmark = pytest.mark.asyncio

    async def test_cached_token_returned_when_valid(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A cached token with future expiry is returned without HTTP or DB read."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        future = datetime.now(UTC) + timedelta(hours=1)
        mock_client = AsyncMock(spec=httpx.AsyncClient)

        token, expires = await get_valid_access_token(
            mock_pool, "google", "cached-access-token", future, mock_client
        )

        assert token == "cached-access-token"
        assert expires == future
        mock_client.post.assert_not_called()

    async def test_expired_token_triggers_refresh(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """An expired cached token triggers a refresh via the Google endpoint."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        past = datetime.now(UTC) - timedelta(hours=1)
        response = _make_httpx_response(
            200, {"access_token": "new-access-token", "expires_in": 3600}
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(
            mock_pool, "google", "old-token", past, mock_client
        )

        assert token == "new-access-token"
        assert expires > datetime.now(UTC)
        mock_client.post.assert_called_once()

    async def test_no_token_row_raises(self, mock_pool: MagicMock) -> None:
        """No token row raises OAuthError."""
        _prime_fetchrow(mock_pool, None)
        mock_client = AsyncMock(spec=httpx.AsyncClient)

        with pytest.raises(OAuthError, match="No google account is connected"):
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)

    async def test_none_cached_triggers_refresh(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """None cached_token triggers a refresh."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(200, {"access_token": "fresh-token", "expires_in": 3600})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, _ = await get_valid_access_token(mock_pool, "google", None, None, mock_client)
        assert token == "fresh-token"

    async def test_refresh_http_error_raises(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """HTTP error during refresh raises OAuthError."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.side_effect = httpx.ConnectError("connection failed")

        with pytest.raises(OAuthError, match=r"HTTP request.*failed"):
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)

    async def test_refresh_invalid_json_raises(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """Malformed JSON from the token endpoint raises OAuthError."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(200, invalid_json=True)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="invalid JSON"):
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)

    async def test_refresh_missing_access_token_raises(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A response without access_token raises OAuthError."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(200, {"expires_in": 3600})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="missing access_token"):
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)


# ---------------------------------------------------------------------------
# 6. Expiry buffer
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_env")
class TestExpiryBuffer:
    """Tokens within the 60-second buffer are treated as expired."""

    pytestmark = pytest.mark.asyncio

    async def test_within_buffer_triggers_refresh(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A token expiring within 60 seconds is refreshed."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        almost_expired = datetime.now(UTC) + timedelta(seconds=30)
        response = _make_httpx_response(
            200, {"access_token": "buffer-refreshed", "expires_in": 3600}
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, _ = await get_valid_access_token(
            mock_pool, "google", "about-to-expire", almost_expired, mock_client
        )
        assert token == "buffer-refreshed"
        mock_client.post.assert_called_once()

    async def test_just_outside_buffer_no_refresh(self, mock_pool: MagicMock) -> None:
        """A token expiring well past the buffer is returned as-is."""
        future = datetime.now(UTC) + timedelta(seconds=_EXPIRY_BUFFER_SECONDS + 120)
        mock_client = AsyncMock(spec=httpx.AsyncClient)

        token, _ = await get_valid_access_token(
            mock_pool, "google", "still-good", future, mock_client
        )
        assert token == "still-good"
        mock_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# 7. Missing env vars raise OAuthError
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
# 8. Adversarial: plaintext refresh tokens never persisted
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fernet_env")
class TestPlaintextNeverPersisted:
    """save_token must never pass the plaintext refresh token to the DB."""

    pytestmark = pytest.mark.asyncio

    async def test_no_plaintext_in_execute_args(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """The plaintext refresh token must not appear in any bound parameter."""
        await save_token(mock_pool, sample_token)

        call = mock_pool.execute.call_args or mock_pool._mock_conn.execute.call_args
        assert call is not None
        for arg in call.args:
            assert _PLAINTEXT_REFRESH_TOKEN not in str(arg)

    async def test_no_plaintext_in_sql_text(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """The plaintext refresh token must not be interpolated into the SQL."""
        await save_token(mock_pool, sample_token)

        call = mock_pool.execute.call_args or mock_pool._mock_conn.execute.call_args
        assert call is not None
        assert _PLAINTEXT_REFRESH_TOKEN not in call.args[0]


# ---------------------------------------------------------------------------
# 9. build_consent_url
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
        assert len(state) > 20

    def test_includes_all_scopes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """URL contains all configured Google scopes."""
        monkeypatch.setenv("GOOGLE_CLIENT_ID", _TEST_CLIENT_ID)
        url, _state = build_consent_url("http://localhost/callback")

        for scope in GOOGLE_SCOPES:
            assert scope.replace(":", "%3A").replace("/", "%2F") in url or scope in url

    def test_includes_redirect_uri(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """URL contains the provided redirect_uri host."""
        monkeypatch.setenv("GOOGLE_CLIENT_ID", _TEST_CLIENT_ID)
        url, _state = build_consent_url("http://localhost:8000/oauth/callback")
        assert "localhost" in url


# ---------------------------------------------------------------------------
# 10. exchange_code (Google)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("google_env")
class TestExchangeCode:
    """Tests for exchange_code with mocked httpx."""

    pytestmark = pytest.mark.asyncio

    async def test_success(self) -> None:
        """Successful exchange returns (access_token, refresh_token, scopes)."""
        response = _make_httpx_response(
            200,
            {"access_token": "at-123", "refresh_token": "rt-456", "scope": "email profile"},
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

    async def test_empty_scope_returns_empty_list(self) -> None:
        """Empty scope string returns an empty scopes list."""
        response = _make_httpx_response(
            200, {"access_token": "at", "refresh_token": "rt", "scope": ""}
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        _, _, scopes = await exchange_code("code", "http://localhost/cb", mock_client)
        assert scopes == []


# ---------------------------------------------------------------------------
# 11. OAuthToken model validation
# ---------------------------------------------------------------------------


class TestOAuthTokenValidation:
    """OAuthToken Pydantic model accepts valid data, rejects invalid."""

    def test_valid_construction(self) -> None:
        """Valid data is accepted."""
        now = datetime.now(UTC)
        tok = OAuthToken(
            provider="google",
            scopes=["scope1"],
            encrypted_refresh_token="gAAAAAB" + "x" * 50,
            created_at=now,
            last_refreshed_at=now,
        )
        assert tok.provider == "google"

    def test_email_defaults_to_none(self) -> None:
        """email is optional and defaults to None."""
        now = datetime.now(UTC)
        tok = OAuthToken(
            provider="google",
            scopes=["scope1"],
            encrypted_refresh_token="encrypted_data",
            created_at=now,
            last_refreshed_at=now,
        )
        assert tok.email is None

    def test_healthy_defaults_to_true(self) -> None:
        """The healthy flag defaults to True (token believed valid)."""
        now = datetime.now(UTC)
        tok = OAuthToken(
            provider="google",
            scopes=["scope1"],
            encrypted_refresh_token="encrypted_data",
            created_at=now,
            last_refreshed_at=now,
        )
        assert tok.healthy is True

    def test_missing_encrypted_token_raises(self) -> None:
        """Missing encrypted_refresh_token raises ValidationError."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            OAuthToken(
                provider="google",
                scopes=["scope1"],
                created_at=now,
                last_refreshed_at=now,
            )  # type: ignore[call-arg]

    def test_empty_encrypted_token_raises(self) -> None:
        """Empty encrypted_refresh_token string raises ValidationError."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            OAuthToken(
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
            OAuthToken(
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
            OAuthToken(
                provider="google",
                encrypted_refresh_token="encrypted_data",
                created_at=now,
                last_refreshed_at=now,
            )  # type: ignore[call-arg]

    def test_overly_long_encrypted_token_raises(self) -> None:
        """encrypted_refresh_token exceeding max_length raises ValidationError."""
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            OAuthToken(
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
            tok = OAuthToken(
                provider=provider,
                scopes=["scope1"],
                encrypted_refresh_token="encrypted_data",
                created_at=now,
                last_refreshed_at=now,
            )
            assert tok.provider == provider


# ---------------------------------------------------------------------------
# 12. OAuthError has safe messages
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
        for var in ["OAUTH_ENCRYPTION_KEY", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]:
            if var != env_var:
                monkeypatch.delenv(var, raising=False)

        try:
            _get_fernet()
        except OAuthError as exc:
            assert secret_value not in str(exc)

        try:
            _get_client_credentials()
        except OAuthError as exc:
            assert secret_value not in str(exc)


# ---------------------------------------------------------------------------
# 13. _get_microsoft_client_credentials
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
# 14. build_microsoft_consent_url
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
        """URL contains the provided redirect_uri host."""
        monkeypatch.setenv("MICROSOFT_CLIENT_ID", _TEST_MS_CLIENT_ID)
        url, _state = build_microsoft_consent_url("http://localhost:8000/oauth/callback")
        assert "localhost" in url

    def test_missing_client_id_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing MICROSOFT_CLIENT_ID raises OAuthError."""
        monkeypatch.delenv("MICROSOFT_CLIENT_ID", raising=False)
        with pytest.raises(OAuthError, match="MICROSOFT_CLIENT_ID"):
            build_microsoft_consent_url("http://localhost/callback")


# ---------------------------------------------------------------------------
# 15. exchange_microsoft_code
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("microsoft_env")
class TestExchangeMicrosoftCode:
    """Tests for exchange_microsoft_code with mocked httpx."""

    pytestmark = pytest.mark.asyncio

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
            200, {"access_token": "at", "refresh_token": "rt", "scope": ""}
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        _, _, scopes = await exchange_microsoft_code("code", "http://localhost/cb", mock_client)
        assert scopes == []


# ---------------------------------------------------------------------------
# 16. Microsoft refresh via get_valid_access_token
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_microsoft_env")
class TestRefreshMicrosoftToken:
    """Test Microsoft token refresh through get_valid_access_token (DB-backed)."""

    pytestmark = pytest.mark.asyncio

    async def test_expired_token_triggers_microsoft_refresh(
        self, mock_pool: MagicMock, microsoft_token: OAuthToken
    ) -> None:
        """An expired Microsoft token triggers refresh via the Microsoft endpoint."""
        _prime_fetchrow(mock_pool, _row_from_token(microsoft_token))
        past = datetime.now(UTC) - timedelta(hours=1)
        response = _make_httpx_response(
            200, {"access_token": "ms-new-access-token", "expires_in": 3600}
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(
            mock_pool, "microsoft", "old-ms-token", past, mock_client
        )

        assert token == "ms-new-access-token"
        assert expires > datetime.now(UTC)
        mock_client.post.assert_called_once()

    async def test_no_microsoft_token_row_raises(self, mock_pool: MagicMock) -> None:
        """No Microsoft token row raises OAuthError."""
        _prime_fetchrow(mock_pool, None)
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        with pytest.raises(OAuthError, match="No microsoft account is connected"):
            await get_valid_access_token(mock_pool, "microsoft", None, None, mock_client)

    async def test_microsoft_refresh_non_200_raises(
        self, mock_pool: MagicMock, microsoft_token: OAuthToken
    ) -> None:
        """Non-200 status from the Microsoft token endpoint raises OAuthError."""
        _prime_fetchrow(mock_pool, _row_from_token(microsoft_token))
        response = _make_httpx_response(401, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthError, match="Microsoft token refresh failed"):
            await get_valid_access_token(mock_pool, "microsoft", None, None, mock_client)

    async def test_microsoft_refresh_invalid_expires_in_defaults(
        self, mock_pool: MagicMock, microsoft_token: OAuthToken
    ) -> None:
        """Invalid expires_in defaults to 3600."""
        _prime_fetchrow(mock_pool, _row_from_token(microsoft_token))
        response = _make_httpx_response(200, {"access_token": "ms-token", "expires_in": -1})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(
            mock_pool, "microsoft", None, None, mock_client
        )
        assert token == "ms-token"
        expected_min = datetime.now(UTC) + timedelta(seconds=3500)
        assert expires > expected_min


# ---------------------------------------------------------------------------
# 17. Google refresh expires_in edge cases
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_env")
class TestGoogleRefreshExpiresInEdgeCases:
    """Edge cases for expires_in in Google token refresh."""

    pytestmark = pytest.mark.asyncio

    async def test_invalid_expires_in_defaults_to_3600(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """Non-integer expires_in defaults to 3600 seconds."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(
            200, {"access_token": "token-with-bad-expiry", "expires_in": "not-an-int"}
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(mock_pool, "google", None, None, mock_client)
        assert token == "token-with-bad-expiry"
        expected_min = datetime.now(UTC) + timedelta(seconds=3500)
        assert expires > expected_min

    async def test_zero_expires_in_defaults_to_3600(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """Zero expires_in defaults to 3600 seconds."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(200, {"access_token": "token-zero-expiry", "expires_in": 0})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        token, expires = await get_valid_access_token(mock_pool, "google", None, None, mock_client)
        assert token == "token-zero-expiry"
        expected_min = datetime.now(UTC) + timedelta(seconds=3500)
        assert expires > expected_min


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
# 19. save_token failure during refresh is non-fatal
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("full_env")
class TestSaveTokenNonFatalInRefresh:
    """save_token failure during refresh does not prevent token return."""

    pytestmark = pytest.mark.asyncio

    async def test_save_failure_logs_but_returns_token(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """If save_token fails after refresh, the access token is still returned."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(
            200, {"access_token": "refreshed-despite-save-fail", "expires_in": 3600}
        )
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with patch("admino.oauth.save_token", new=AsyncMock(side_effect=OAuthError("db down"))):
            token, expires = await get_valid_access_token(
                mock_pool, "google", None, None, mock_client
            )

        assert token == "refreshed-despite-save-fail"
        assert expires > datetime.now(UTC)


# ---------------------------------------------------------------------------
# 20. Healthy-flag transitions (GH-86)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("google_env")
class TestTerminalRefreshMarksUnhealthy:
    """A terminal (invalid_grant) refresh failure persists healthy=False."""

    pytestmark = pytest.mark.asyncio

    async def test_invalid_grant_raises_terminal_refresh_error(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A 400 invalid_grant refresh failure raises a terminal OAuthRefreshError."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(400, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        with pytest.raises(OAuthRefreshError) as exc_info:
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)
        assert exc_info.value.terminal is True

    async def test_invalid_grant_saves_healthy_false(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A terminal refresh failure saves a token with healthy=False."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(400, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        saved: list[OAuthToken] = []

        async def _capture(_pool: Any, token: OAuthToken) -> None:
            saved.append(token)

        with (
            patch("admino.oauth.save_token", new=AsyncMock(side_effect=_capture)),
            pytest.raises(OAuthRefreshError),
        ):
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)

        assert saved, "save_token was not called to persist the unhealthy flag"
        assert saved[-1].healthy is False

    async def test_microsoft_invalid_grant_saves_healthy_false(
        self,
        mock_pool: MagicMock,
        microsoft_token: OAuthToken,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A Microsoft terminal refresh failure also saves healthy=False."""
        monkeypatch.setenv("MICROSOFT_CLIENT_ID", _TEST_MS_CLIENT_ID)
        monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", _TEST_MS_CLIENT_SECRET)
        _prime_fetchrow(mock_pool, _row_from_token(microsoft_token))
        response = _make_httpx_response(400, {"error": "invalid_grant"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        saved: list[OAuthToken] = []

        async def _capture(_pool: Any, token: OAuthToken) -> None:
            saved.append(token)

        with (
            patch("admino.oauth.save_token", new=AsyncMock(side_effect=_capture)),
            pytest.raises(OAuthRefreshError),
        ):
            await get_valid_access_token(mock_pool, "microsoft", None, None, mock_client)

        assert saved
        assert saved[-1].healthy is False


@pytest.mark.usefixtures("google_env")
class TestTransientRefreshKeepsHealthy:
    """Transient failures (network, 5xx) must NOT flip healthy to False."""

    pytestmark = pytest.mark.asyncio

    async def test_http_error_does_not_save_unhealthy(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A network error during refresh does not persist healthy=False."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.side_effect = httpx.ConnectError("connection failed")

        saved: list[OAuthToken] = []

        async def _capture(_pool: Any, token: OAuthToken) -> None:
            saved.append(token)

        with (
            patch("admino.oauth.save_token", new=AsyncMock(side_effect=_capture)),
            pytest.raises(OAuthError),
        ):
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)

        assert all(t.healthy is not False for t in saved)

    async def test_server_error_does_not_save_unhealthy(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A 503 from the token endpoint is transient and does not save healthy=False."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(503, {"error": "temporarily_unavailable"})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        saved: list[OAuthToken] = []

        async def _capture(_pool: Any, token: OAuthToken) -> None:
            saved.append(token)

        with (
            patch("admino.oauth.save_token", new=AsyncMock(side_effect=_capture)),
            pytest.raises(OAuthError) as exc_info,
        ):
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)
        if isinstance(exc_info.value, OAuthRefreshError):
            assert exc_info.value.terminal is False

        assert all(t.healthy is not False for t in saved)


@pytest.mark.usefixtures("google_env")
class TestSuccessfulRefreshMarksHealthy:
    """A successful refresh sets healthy=True and updates last_refreshed_at."""

    pytestmark = pytest.mark.asyncio

    async def test_successful_refresh_saves_healthy_true(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A previously-unhealthy token is recovered to healthy=True on success."""
        row = _row_from_token(sample_token)
        row["healthy"] = False
        _prime_fetchrow(mock_pool, row)
        response = _make_httpx_response(200, {"access_token": "ok", "expires_in": 3600})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        saved: list[OAuthToken] = []

        async def _capture(_pool: Any, token: OAuthToken) -> None:
            saved.append(token)

        with patch("admino.oauth.save_token", new=AsyncMock(side_effect=_capture)):
            token, _ = await get_valid_access_token(mock_pool, "google", None, None, mock_client)

        assert token == "ok"
        assert saved, "save_token was not called after successful refresh"
        assert saved[-1].healthy is True

    async def test_successful_refresh_updates_last_refreshed_at(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A successful refresh advances last_refreshed_at before saving."""
        original = sample_token.last_refreshed_at - timedelta(days=1)
        row = _row_from_token(sample_token)
        row["last_refreshed_at"] = original
        _prime_fetchrow(mock_pool, row)
        response = _make_httpx_response(200, {"access_token": "ok", "expires_in": 3600})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response

        saved: list[OAuthToken] = []

        async def _capture(_pool: Any, token: OAuthToken) -> None:
            saved.append(token)

        with patch("admino.oauth.save_token", new=AsyncMock(side_effect=_capture)):
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)

        assert saved
        assert saved[-1].last_refreshed_at > original


# ---------------------------------------------------------------------------
# 21. Decrypt-failure path
# ---------------------------------------------------------------------------


class TestDecryptFailurePath:
    """A row whose ciphertext cannot be decrypted is surfaced as unhealthy."""

    pytestmark = pytest.mark.asyncio

    async def test_get_valid_access_token_raises_on_undecryptable(
        self, mock_pool: MagicMock, fernet_env: str, sample_token: OAuthToken
    ) -> None:
        """A row encrypted under a different key raises OAuthError on refresh."""
        _ = fernet_env
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        mock_client = AsyncMock(spec=httpx.AsyncClient)

        # Switch the active key so the stored ciphertext can no longer be decrypted.
        wrong_key = Fernet.generate_key().decode()
        with (
            patch.dict("os.environ", {"OAUTH_ENCRYPTION_KEY": wrong_key}),
            pytest.raises(OAuthError, match="decrypt"),
        ):
            await get_valid_access_token(mock_pool, "google", None, None, mock_client)

    async def test_get_connection_status_reports_unhealthy_on_undecryptable(
        self, mock_pool: MagicMock, fernet_env: str, sample_token: OAuthToken
    ) -> None:
        """A row that cannot be decrypted yields (True, False)."""
        _ = fernet_env
        row = _row_from_token(sample_token)
        # Corrupt the ciphertext so decryption fails while the row still exists.
        row["encrypted_refresh_token"] = "not-valid-fernet-ciphertext"
        _prime_fetchrow(mock_pool, row)

        result = await get_connection_status(mock_pool, "google")

        assert result == (True, False)


# ---------------------------------------------------------------------------
# 22. get_connection_status (DB-backed)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fernet_env")
class TestGetConnectionStatus:
    """get_connection_status reports (connected, healthy) from a DB row."""

    pytestmark = pytest.mark.asyncio

    async def test_no_row_is_not_connected(self, mock_pool: MagicMock) -> None:
        """No row → (False, False)."""
        _prime_fetchrow(mock_pool, None)
        assert await get_connection_status(mock_pool, "google") == (False, False)

    async def test_healthy_row_is_connected_and_healthy(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A healthy row → (True, True)."""
        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        assert await get_connection_status(mock_pool, "google") == (True, True)

    async def test_unhealthy_row_is_connected_but_unhealthy(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """A row with healthy=False → (True, False)."""
        row = _row_from_token(sample_token)
        row["healthy"] = False
        _prime_fetchrow(mock_pool, row)
        assert await get_connection_status(mock_pool, "google") == (True, False)


# ---------------------------------------------------------------------------
# 23. revoke_and_delete_token (DB-backed)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("fernet_env")
class TestRevokeAndDeleteToken:
    """revoke_and_delete_token best-effort revokes then deletes the DB row."""

    pytestmark = pytest.mark.asyncio

    async def test_returns_false_when_no_token(self, mock_pool: MagicMock) -> None:
        """When no token row exists, returns False and does not delete."""
        from admino.oauth import revoke_and_delete_token

        _prime_fetchrow(mock_pool, None)
        mock_client = AsyncMock(spec=httpx.AsyncClient)

        result = await revoke_and_delete_token(mock_pool, "google", mock_client)

        assert result is False

    async def test_deletes_and_returns_true_when_present(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """When a token exists, revoke is attempted and the row is deleted."""
        from admino.oauth import revoke_and_delete_token

        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        response = _make_httpx_response(200, {})
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.return_value = response
        mock_client.get.return_value = response

        with patch("admino.oauth.delete_token", new=AsyncMock(return_value=True)) as mock_delete:
            result = await revoke_and_delete_token(mock_pool, "google", mock_client)

        assert result is True
        mock_delete.assert_awaited_once()

    async def test_provider_revoke_failure_still_deletes(
        self, mock_pool: MagicMock, sample_token: OAuthToken
    ) -> None:
        """If the provider revocation call fails, the row is still deleted."""
        from admino.oauth import revoke_and_delete_token

        _prime_fetchrow(mock_pool, _row_from_token(sample_token))
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post.side_effect = httpx.ConnectError("revoke failed")
        mock_client.get.side_effect = httpx.ConnectError("revoke failed")

        with patch("admino.oauth.delete_token", new=AsyncMock(return_value=True)) as mock_delete:
            result = await revoke_and_delete_token(mock_pool, "google", mock_client)

        assert result is True
        mock_delete.assert_awaited_once()
