"""Tests for the Settings API endpoints (GET/PATCH /api/settings).

Covers:
- GET /api/settings: returns current settings with masked API keys
- PATCH /api/settings: partial updates, validation, LLM re-init
- Auth enforcement on both endpoints
- Adversarial inputs: oversized values, SQL injection, wrong types
- Immutable fields (server section) cannot be changed via PATCH
- GH-142: the Infomaniak provider (model, token-configured flag, live model
  list), re-init rules for infomaniak_model, and switching to a provider whose
  key is missing now succeeds (chat explains what to set)

Security notes:
- All tests use mocked database and config — no real DB or API calls.
- Auth token is a known test value, never a real secret.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from admino.server import create_app

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEST_TOKEN = "a" * 48 + "BcDeFgHiJkLmNoPqRsTuVwXyZ"  # >48 chars, >20 unique
_INFOMANIAK_MODEL = "Qwen/Qwen3.5-397B-A17B-FP8"
_AUTH_HEADER = {"Authorization": f"Bearer {_TEST_TOKEN}"}

# Default settings returned by mocked load_settings_from_db.
_DEFAULT_DB_SETTINGS: dict[str, Any] = {
    "llm": {
        "provider": "anthropic",
        "anthropic_model": "claude-sonnet-4-6",
        "openai_model": "gpt-4o",
        "vllm_model": "mlx-community/gemma-4-12B-it-4bit",
    },
    "appearance": {"theme": "light"},
    "notifications": {"enabled": True},
    "limits": {
        "max_tool_calls_per_message": 10,
        "confirmation_timeout_s": 300,
        "max_message_length": 4000,
    },
    "server": {"host": "0.0.0.0", "port": 8000},  # noqa: S104
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(*, auth_mode: str = "token", token: str | None = _TEST_TOKEN) -> MagicMock:
    """Build a minimal mock AppConfig for settings tests."""
    config = MagicMock()
    # Concrete (str) model so the live-config fallback for infomaniak_model is
    # realistic rather than a MagicMock attribute.
    config.llm.infomaniak_model = _INFOMANIAK_MODEL
    config.auth.mode = auth_mode
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    if token is not None:
        config.auth.token = SecretStr(token)
    else:
        config.auth.token = None
    return config


def _make_app(
    agent: Any = None, *, auth_mode: str = "token", token: str | None = _TEST_TOKEN
) -> Any:
    """Create a FastAPI app with mock agent and config."""
    if agent is None:
        agent = MagicMock()
    config = _make_config(auth_mode=auth_mode, token=token)
    return create_app(agent=agent, config=config)


def _mock_load_settings(settings: dict[str, Any] | None = None) -> AsyncMock:
    """Return an AsyncMock for load_settings_from_db."""
    data = settings if settings is not None else dict(_DEFAULT_DB_SETTINGS)
    return AsyncMock(return_value=data)


def _mock_get_pool(mock_pool: MagicMock | None = None) -> MagicMock:
    """Return a mock for database.get_pool."""
    return MagicMock(return_value=mock_pool or MagicMock())


def _conn_status(
    *,
    google: tuple[bool, bool] = (False, False),
    microsoft: tuple[bool, bool] = (False, False),
) -> Any:
    """Build a fake async get_connection_status returning (connected, healthy) per provider.

    GH-86: get_connection_status is now async and takes the asyncpg pool as
    its first argument instead of a tokens directory.
    """

    async def _side(_pool: Any, provider: str) -> tuple[bool, bool]:
        return google if provider == "google" else microsoft

    return _side


# ---------------------------------------------------------------------------
# GET /api/settings
# ---------------------------------------------------------------------------


class TestGetSettings:
    """GET /api/settings — returns current settings with masked secrets."""

    pytestmark = pytest.mark.asyncio

    async def test_get_settings_returns_current_settings(self) -> None:
        """Response includes all settings sections with correct values."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        body = resp.json()
        assert body["llm"]["provider"] == "anthropic"
        assert body["llm"]["anthropic_model"] == "claude-sonnet-4-6"
        assert body["appearance"]["theme"] == "light"
        assert body["notifications"]["enabled"] is True
        assert body["limits"]["max_tool_calls_per_message"] == 10
        assert body["server"]["host"] == "0.0.0.0"  # noqa: S104
        assert body["server"]["port"] == 8000

    async def test_get_settings_anthropic_without_openai_model_returns_200(self) -> None:
        """GET must not 500 when an inactive-provider model is unset.

        On an anthropic deployment the openai model is None (no hardcoded
        default), so SettingsLLM receives a blank value for it. The response
        must still validate and return 200.
        """
        from admino import server

        app = _make_app()
        assert server._config is not None
        server._config.llm.provider = "anthropic"
        server._config.llm.anthropic_model = "claude-sonnet-4-6"
        server._config.llm.openai_model = None

        db_settings = dict(_DEFAULT_DB_SETTINGS)
        db_settings["llm"] = {
            "provider": "anthropic",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": None,
        }
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings(db_settings)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        body = resp.json()
        assert body["llm"]["provider"] == "anthropic"
        assert body["llm"]["anthropic_model"] == "claude-sonnet-4-6"
        assert body["llm"]["openai_model"] == ""

    async def test_get_settings_shows_vllm_provider_without_coercion(self) -> None:
        """A vllm deployment reports provider='vllm' — GET must NOT coerce to anthropic."""
        from admino import server

        app = _make_app()
        assert server._config is not None
        server._config.llm.provider = "vllm"

        db_settings = dict(_DEFAULT_DB_SETTINGS)
        db_settings["llm"] = {
            "provider": "vllm",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
        }
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings(db_settings)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        assert resp.json()["llm"]["provider"] == "vllm"

    async def test_get_settings_includes_vllm_model(self) -> None:
        """GET LLM payload surfaces vllm_model from config/db (issue #134)."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch(
                "admino.server._get_vllm_available_models",
                AsyncMock(return_value=[]),
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        assert resp.json()["llm"]["vllm_model"] == "mlx-community/gemma-4-12B-it-4bit"

    async def test_get_settings_surfaces_vllm_available_models(self) -> None:
        """vllm_available_models reflects what the probe helper returns (issue #134)."""
        app = _make_app()
        probed = ["mlx-community/gemma-4-12B-it-4bit", "org/other-model"]
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch(
                "admino.server._get_vllm_available_models",
                AsyncMock(return_value=probed),
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        assert resp.json()["llm"]["vllm_available_models"] == probed

    async def test_get_settings_vllm_available_models_degrades_to_empty(self) -> None:
        """When the probe helper returns [] (unreachable), the list is empty, not an error."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch(
                "admino.server._get_vllm_available_models",
                AsyncMock(return_value=[]),
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        assert resp.json()["llm"]["vllm_available_models"] == []

    async def test_get_settings_masks_api_keys_when_not_set(self) -> None:
        """API key fields are boolean flags, not actual values. False when unset."""
        app = _make_app()
        env = {"ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": ""}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        body = resp.json()
        assert body["llm"]["anthropic_key_configured"] is False
        assert body["llm"]["openai_key_configured"] is False
        # Must not contain actual key values.
        assert "ANTHROPIC_API_KEY" not in json.dumps(body)

    async def test_get_settings_masks_api_keys_when_set(self) -> None:
        """API key flags are True when env vars are set, but no key value leaks."""
        app = _make_app()
        env = {"ANTHROPIC_API_KEY": "sk-secret-123", "OPENAI_API_KEY": "sk-openai-456"}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        body = resp.json()
        assert body["llm"]["anthropic_key_configured"] is True
        assert body["llm"]["openai_key_configured"] is True
        raw = json.dumps(body)
        assert "sk-secret-123" not in raw
        assert "sk-openai-456" not in raw

    async def test_get_settings_requires_auth(self) -> None:
        """GET /api/settings without Authorization header returns 401."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/settings")
        assert resp.status_code == 401

    async def test_get_settings_connected_accounts_no_tokens(self) -> None:
        """When no token files exist, connected_accounts shows disconnected."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.server.get_connection_status", _conn_status()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        body = resp.json()
        assert body["connected_accounts"]["google"]["connected"] is False
        assert body["connected_accounts"]["google"]["healthy"] is False
        assert body["connected_accounts"]["microsoft"]["connected"] is False
        assert body["connected_accounts"]["microsoft"]["healthy"] is False

    async def test_get_settings_connected_accounts_with_google_token(self) -> None:
        """A healthy google token shows connected, healthy, and services."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.server.get_connection_status", _conn_status(google=(True, True))),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        body = resp.json()
        assert body["connected_accounts"]["google"]["connected"] is True
        assert body["connected_accounts"]["google"]["healthy"] is True
        assert "gmail" in body["connected_accounts"]["google"]["services"]

    async def test_get_settings_expired_token_is_connected_but_unhealthy(self) -> None:
        """An expired/revoked refresh token shows connected=True, healthy=False."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.server.get_connection_status", _conn_status(google=(True, False))),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        body = resp.json()
        assert body["connected_accounts"]["google"]["connected"] is True
        assert body["connected_accounts"]["google"]["healthy"] is False


# ---------------------------------------------------------------------------
# PATCH /api/settings
# ---------------------------------------------------------------------------


class TestPatchSettings:
    """PATCH /api/settings — partial update of settings."""

    pytestmark = pytest.mark.asyncio

    async def test_patch_settings_updates_llm_provider(self) -> None:
        """Changing llm.provider triggers LLM client re-init."""
        app = _make_app()
        mock_update = AsyncMock()
        mock_load = _mock_load_settings()
        mock_create_llm = MagicMock()

        env = {"ANTHROPIC_API_KEY": "sk-test-key"}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "anthropic"}},
                )

        assert resp.status_code == 200
        # update_setting should have been called for the "llm" section.
        mock_update.assert_called()
        # Find the call that updated "llm".
        llm_calls = [c for c in mock_update.call_args_list if c[0][1] == "llm"]
        assert len(llm_calls) == 1
        updated_llm = llm_calls[0][0][2]
        assert updated_llm["provider"] == "anthropic"
        assert updated_llm["anthropic_model"] == "claude-sonnet-4-6"

    async def test_patch_settings_to_vllm_returns_200(self) -> None:
        """PATCH to provider='vllm' succeeds with no API key and persists 'vllm'."""
        app = _make_app()
        mock_update = AsyncMock()
        mock_load = _mock_load_settings()
        mock_create_llm = MagicMock()

        env = {"ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": ""}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "vllm"}},
                )

        assert resp.status_code == 200
        # The "llm" section was persisted with the new provider.
        llm_calls = [c for c in mock_update.call_args_list if c[0][1] == "llm"]
        assert len(llm_calls) == 1
        assert llm_calls[0][0][2]["provider"] == "vllm"

    async def test_patch_settings_vllm_model_change_reinits_client(self) -> None:
        """Changing vllm_model while provider is vllm re-inits the LLM client (issue #134).

        The provider-change re-init path is extended: a vllm_model change (with
        provider already vllm) must also rebuild the agent's LLM client.
        """
        old_client = MagicMock()
        old_client.close = AsyncMock()
        agent = MagicMock()
        agent._llm = old_client
        app = _make_app(agent=agent)

        # DB is already on vllm with the shipped model; the patch changes only
        # vllm_model (provider stays vllm) → must re-init.
        db_settings = dict(_DEFAULT_DB_SETTINGS)
        db_settings["llm"] = {
            "provider": "vllm",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
            "vllm_model": "mlx-community/gemma-4-12B-it-4bit",
        }
        mock_load = _mock_load_settings(db_settings)
        new_client = MagicMock()
        new_client.close = AsyncMock()
        mock_create_llm = MagicMock(return_value=new_client)

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", AsyncMock()),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch("admino.server._get_vllm_available_models", AsyncMock(return_value=[])),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"vllm_model": "org/new-served-model"}},
                )

        assert resp.status_code == 200
        mock_create_llm.assert_called_once()
        assert agent._llm is new_client

    async def test_patch_settings_vllm_model_persisted(self) -> None:
        """PATCH llm.vllm_model persists the new value under the 'llm' section."""
        app = _make_app()
        mock_update = AsyncMock()

        db_settings = dict(_DEFAULT_DB_SETTINGS)
        db_settings["llm"] = {
            "provider": "vllm",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
            "vllm_model": "mlx-community/gemma-4-12B-it-4bit",
        }
        mock_load = _mock_load_settings(db_settings)

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
            patch("admino.llm.create_llm_client", MagicMock()),
            patch("admino.server._get_vllm_available_models", AsyncMock(return_value=[])),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"vllm_model": "org/new-served-model"}},
                )

        assert resp.status_code == 200
        llm_calls = [c for c in mock_update.call_args_list if c[0][1] == "llm"]
        assert len(llm_calls) == 1
        assert llm_calls[0][0][2]["vllm_model"] == "org/new-served-model"

    async def test_patch_settings_vllm_model_noop_does_not_reinit(self) -> None:
        """Re-sending the SAME vllm_model (a no-op) must NOT rebuild the client (issue #134)."""
        old_client = MagicMock()
        old_client.close = AsyncMock()
        agent = MagicMock()
        agent._llm = old_client
        app = _make_app(agent=agent)

        db_settings = dict(_DEFAULT_DB_SETTINGS)
        db_settings["llm"] = {
            "provider": "vllm",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
            "vllm_model": "mlx-community/gemma-4-12B-it-4bit",
        }
        mock_load = _mock_load_settings(db_settings)
        mock_create_llm = MagicMock()

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", AsyncMock()),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch("admino.server._get_vllm_available_models", AsyncMock(return_value=[])),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"vllm_model": "mlx-community/gemma-4-12B-it-4bit"}},
                )

        assert resp.status_code == 200
        mock_create_llm.assert_not_called()
        assert agent._llm is old_client

    async def test_patch_settings_provider_change_closes_old_client(self) -> None:
        """Switching provider retires the old LLM client by awaiting its close()."""
        old_client = MagicMock()
        old_client.close = AsyncMock()
        agent = MagicMock()
        agent._llm = old_client
        app = _make_app(agent=agent)

        # DB currently on openai; the patch switches to anthropic → provider_changed.
        db_settings = dict(_DEFAULT_DB_SETTINGS)
        db_settings["llm"] = {
            "provider": "openai",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
        }
        mock_load = _mock_load_settings(db_settings)
        new_client = MagicMock()
        new_client.close = AsyncMock()
        mock_create_llm = MagicMock(return_value=new_client)

        env = {"ANTHROPIC_API_KEY": "sk-test-key"}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", AsyncMock()),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "anthropic"}},
                )

        assert resp.status_code == 200
        # The retired client's connection pool is released, and the running
        # agent now holds the freshly-built client.
        old_client.close.assert_awaited_once()
        assert agent._llm is new_client

    async def test_patch_settings_provider_change_survives_old_client_close_error(self) -> None:
        """A close() failure on the retired client must not fail the settings update."""
        old_client = MagicMock()
        old_client.close = AsyncMock(side_effect=RuntimeError("teardown boom"))
        agent = MagicMock()
        agent._llm = old_client
        app = _make_app(agent=agent)

        db_settings = dict(_DEFAULT_DB_SETTINGS)
        db_settings["llm"] = {
            "provider": "openai",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
        }
        mock_load = _mock_load_settings(db_settings)
        new_client = MagicMock()
        mock_create_llm = MagicMock(return_value=new_client)

        env = {"ANTHROPIC_API_KEY": "sk-test-key"}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", AsyncMock()),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "anthropic"}},
                )

        # The teardown error is swallowed; the swap still completes with 200.
        assert resp.status_code == 200
        old_client.close.assert_awaited_once()
        assert agent._llm is new_client

    async def test_patch_settings_to_openai_with_key_returns_200(self) -> None:
        """PATCH to provider='openai' with a key set persists 'openai' + gpt-4o.

        GH-115 regression lock: the backend key-guard is correct — when
        OPENAI_API_KEY is present and openai_model is non-empty (gpt-4o), the
        provider switch validates, persists, and returns 200.
        """
        app = _make_app()
        mock_update = AsyncMock()
        mock_load = _mock_load_settings()
        mock_create_llm = MagicMock()

        env = {"OPENAI_API_KEY": "sk-openai-test-key"}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "openai"}},
                )

        assert resp.status_code == 200
        llm_calls = [c for c in mock_update.call_args_list if c[0][1] == "llm"]
        assert len(llm_calls) == 1
        updated_llm = llm_calls[0][0][2]
        assert updated_llm["provider"] == "openai"
        assert updated_llm["openai_model"] == "gpt-4o"

    async def test_patch_settings_to_openai_without_key_returns_200(self) -> None:
        """PATCH to 'openai' with no key now succeeds (GH-142 — chat explains what to set).

        Supersedes the GH-115 400 lock: a missing key no longer blocks a
        provider switch for any provider.
        """
        app = _make_app()
        mock_update = AsyncMock()
        mock_load = _mock_load_settings()
        mock_create_llm = MagicMock()

        env = {"OPENAI_API_KEY": ""}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "openai"}},
                )

        assert resp.status_code == 200

    async def test_patch_settings_to_openai_without_key_persists_and_reinits(self) -> None:
        """The keyless 'openai' switch is persisted and the client is rebuilt (GH-142)."""
        app = _make_app()
        mock_update = AsyncMock()
        mock_load = _mock_load_settings()
        mock_create_llm = MagicMock()

        env = {"OPENAI_API_KEY": ""}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "openai"}},
                )

        assert resp.status_code == 200
        llm_calls = [call for call in mock_update.call_args_list if call[0][1] == "llm"]
        assert len(llm_calls) == 1
        assert llm_calls[0][0][2]["provider"] == "openai"
        mock_create_llm.assert_called_once()

    async def test_patch_settings_to_anthropic_without_key_returns_200(self) -> None:
        """PATCH to 'anthropic' with no key also succeeds now (GH-142)."""
        app = _make_app()
        db_settings = dict(_DEFAULT_DB_SETTINGS)
        db_settings["llm"] = {
            "provider": "openai",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
        }
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings(db_settings)),
            patch("admino.database.update_setting", AsyncMock()),
            patch("admino.llm.create_llm_client", MagicMock()),
            patch.dict("os.environ", {"ANTHROPIC_API_KEY": ""}, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "anthropic"}},
                )

        assert resp.status_code == 200

    async def test_patch_settings_to_anthropic_with_key_returns_200(self) -> None:
        """Switching back to 'anthropic' with a key set still returns 200.

        GH-115 no-regression guard: the fix for the openai path must not break
        the anthropic path. DB is currently on openai; the patch switches to
        anthropic and persists 'anthropic'.
        """
        app = _make_app()
        mock_update = AsyncMock()

        db_settings = dict(_DEFAULT_DB_SETTINGS)
        db_settings["llm"] = {
            "provider": "openai",
            "anthropic_model": "claude-sonnet-4-6",
            "openai_model": "gpt-4o",
        }
        mock_load = _mock_load_settings(db_settings)
        mock_create_llm = MagicMock()

        env = {"ANTHROPIC_API_KEY": "sk-ant-test-key"}
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
            patch("admino.llm.create_llm_client", mock_create_llm),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "anthropic"}},
                )

        assert resp.status_code == 200
        llm_calls = [c for c in mock_update.call_args_list if c[0][1] == "llm"]
        assert len(llm_calls) == 1
        assert llm_calls[0][0][2]["provider"] == "anthropic"

    async def test_patch_settings_partial_update_appearance(self) -> None:
        """Patching only appearance.theme should not affect other sections."""
        app = _make_app()
        mock_update = AsyncMock()

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"appearance": {"theme": "dark"}},
                )

        assert resp.status_code == 200
        # Only appearance section should have been updated.
        assert mock_update.call_count == 1
        call_args = mock_update.call_args
        assert call_args[0][1] == "appearance"
        assert call_args[0][2]["theme"] == "dark"

    async def test_patch_settings_returns_updated_response(self) -> None:
        """After patching, the response contains the new values."""
        app = _make_app()

        # First call returns current settings; second call (after update) returns updated.
        updated_settings = dict(_DEFAULT_DB_SETTINGS)
        updated_settings["appearance"] = {"theme": "dark"}
        mock_load = AsyncMock(
            side_effect=[
                dict(_DEFAULT_DB_SETTINGS),  # for reading current
                updated_settings,  # for building response
            ]
        )

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", AsyncMock()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"appearance": {"theme": "dark"}},
                )

        assert resp.status_code == 200
        assert resp.json()["appearance"]["theme"] == "dark"

    async def test_patch_settings_requires_auth(self) -> None:
        """PATCH /api/settings without Authorization header returns 401."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.patch("/api/settings", json={"appearance": {"theme": "dark"}})
        assert resp.status_code == 401

    async def test_patch_settings_invalid_provider_returns_400(self) -> None:
        """Setting an invalid provider value should return 422 from Pydantic."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": "invalid_provider"}},
                )
        assert resp.status_code == 422

    async def test_patch_settings_notifications_update(self) -> None:
        """Patching notifications.enabled persists correctly."""
        app = _make_app()
        mock_update = AsyncMock()

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"notifications": {"enabled": False}},
                )

        assert resp.status_code == 200
        call_args = mock_update.call_args
        assert call_args[0][1] == "notifications"
        assert call_args[0][2]["enabled"] is False

    async def test_patch_settings_empty_body_no_updates(self) -> None:
        """An empty PATCH body should not call update_setting."""
        app = _make_app()
        mock_update = AsyncMock()

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch("/api/settings", headers=_AUTH_HEADER, json={})

        assert resp.status_code == 200
        mock_update.assert_not_called()


# ---------------------------------------------------------------------------
# GH-142: Infomaniak provider in the Settings API
# ---------------------------------------------------------------------------


def _infomaniak_db_settings(**llm_overrides: Any) -> dict[str, Any]:
    """DB settings whose llm section selects infomaniak."""
    settings = dict(_DEFAULT_DB_SETTINGS)
    llm: dict[str, Any] = {
        "provider": "infomaniak",
        "anthropic_model": "claude-sonnet-4-6",
        "openai_model": "gpt-4o",
        "vllm_model": "mlx-community/gemma-4-12B-it-4bit",
        "infomaniak_model": _INFOMANIAK_MODEL,
    }
    llm.update(llm_overrides)
    settings["llm"] = llm
    return settings


def _live_infomaniak_client(models: list[str]) -> MagicMock:
    """A stand-in for a live InfomaniakClient whose list_models() returns ``models``."""
    from admino.llm_infomaniak import InfomaniakClient

    live = MagicMock(spec=InfomaniakClient)
    live.list_models = AsyncMock(return_value=models)
    live.close = AsyncMock()
    return live


class TestInfomaniakSettingsGet:
    """GET /api/settings surfaces the Infomaniak provider state (never the token)."""

    pytestmark = pytest.mark.asyncio

    async def _get(self, app: Any, settings: dict[str, Any], env: dict[str, str]) -> Any:
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings(settings)),
            patch.dict("os.environ", env, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                return await c.get("/api/settings", headers=_AUTH_HEADER)

    async def test_get_settings_reports_infomaniak_provider_and_model(self) -> None:
        """provider='infomaniak' and infomaniak_model come back from the DB."""
        from admino import server

        agent = MagicMock()
        agent._llm = _live_infomaniak_client([])
        app = _make_app(agent=agent)
        assert server._config is not None
        server._config.llm.provider = "infomaniak"

        settings = _infomaniak_db_settings(infomaniak_model="mistralai/Mistral-Small-3.2")
        resp = await self._get(app, settings, {"INFOMANIAK_API_TOKEN": ""})

        assert resp.status_code == 200
        llm = resp.json()["llm"]
        assert llm["provider"] == "infomaniak"
        assert llm["infomaniak_model"] == "mistralai/Mistral-Small-3.2"

    async def test_get_settings_infomaniak_model_falls_back_to_live_config(self) -> None:
        """Without a DB value, infomaniak_model falls back to the live config."""
        app = _make_app()
        settings = dict(_DEFAULT_DB_SETTINGS)  # no infomaniak_model stored
        resp = await self._get(app, settings, {})

        assert resp.status_code == 200
        assert resp.json()["llm"]["infomaniak_model"] == _INFOMANIAK_MODEL

    async def test_get_settings_infomaniak_token_configured_true(self) -> None:
        """infomaniak_token_configured is True when INFOMANIAK_API_TOKEN is set."""
        app = _make_app()
        resp = await self._get(
            app, _infomaniak_db_settings(), {"INFOMANIAK_API_TOKEN": "ik-get-token-marker"}
        )
        assert resp.json()["llm"]["infomaniak_token_configured"] is True

    async def test_get_settings_infomaniak_token_configured_false(self) -> None:
        """infomaniak_token_configured is False when INFOMANIAK_API_TOKEN is empty/unset."""
        app = _make_app()
        resp = await self._get(app, _infomaniak_db_settings(), {"INFOMANIAK_API_TOKEN": ""})
        assert resp.json()["llm"]["infomaniak_token_configured"] is False

    async def test_get_settings_never_returns_infomaniak_token(self) -> None:
        """The token value never appears anywhere in the response."""
        from admino import server

        secret = "ik-SETTINGS-TOKEN-VALUE-MARKER-5e2f"
        agent = MagicMock()
        agent._llm = _live_infomaniak_client([_INFOMANIAK_MODEL])
        app = _make_app(agent=agent)
        assert server._config is not None
        server._config.llm.provider = "infomaniak"

        resp = await self._get(app, _infomaniak_db_settings(), {"INFOMANIAK_API_TOKEN": secret})

        assert resp.status_code == 200
        assert secret not in resp.text

    async def test_get_settings_infomaniak_available_models_from_live_client(self) -> None:
        """With infomaniak active, the list comes from the live client, allowlist-filtered."""
        from admino import server

        agent = MagicMock()
        agent._llm = _live_infomaniak_client(
            [_INFOMANIAK_MODEL, "bad id; rm -rf /", "mistralai/Mistral-Small-3.2"]
        )
        app = _make_app(agent=agent)
        assert server._config is not None
        server._config.llm.provider = "infomaniak"

        resp = await self._get(app, _infomaniak_db_settings(), {"INFOMANIAK_API_TOKEN": "t"})

        assert resp.status_code == 200
        assert resp.json()["llm"]["infomaniak_available_models"] == [
            _INFOMANIAK_MODEL,
            "mistralai/Mistral-Small-3.2",
        ]
        agent._llm.list_models.assert_awaited_once()

    async def test_get_settings_infomaniak_available_models_empty_for_other_provider(
        self,
    ) -> None:
        """When another provider is active, the list is [] and no listing is attempted."""
        from admino import server

        agent = MagicMock()
        agent._llm = _live_infomaniak_client([_INFOMANIAK_MODEL])
        app = _make_app(agent=agent)
        assert server._config is not None
        server._config.llm.provider = "anthropic"

        settings = dict(_DEFAULT_DB_SETTINGS)  # provider: anthropic
        resp = await self._get(app, settings, {})

        assert resp.status_code == 200
        assert resp.json()["llm"]["infomaniak_available_models"] == []
        agent._llm.list_models.assert_not_awaited()

    async def test_get_settings_infomaniak_available_models_empty_without_live_client(
        self,
    ) -> None:
        """infomaniak active but the live client is not an InfomaniakClient → []."""
        from admino import server

        agent = MagicMock()
        agent._llm = MagicMock()
        agent._llm.list_models = AsyncMock(return_value=[_INFOMANIAK_MODEL])
        app = _make_app(agent=agent)
        assert server._config is not None
        server._config.llm.provider = "infomaniak"

        resp = await self._get(app, _infomaniak_db_settings(), {})

        assert resp.status_code == 200
        assert resp.json()["llm"]["infomaniak_available_models"] == []


class TestInfomaniakSettingsPatch:
    """PATCH /api/settings accepts the Infomaniak provider and model."""

    pytestmark = pytest.mark.asyncio

    async def _patch(
        self,
        app: Any,
        settings: dict[str, Any],
        body: dict[str, Any],
        *,
        update: AsyncMock | None = None,
        create_llm: MagicMock | None = None,
    ) -> Any:
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings(settings)),
            patch("admino.database.update_setting", update or AsyncMock()),
            patch("admino.llm.create_llm_client", create_llm or MagicMock()),
            patch.dict("os.environ", {"INFOMANIAK_API_TOKEN": ""}, clear=False),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                return await c.patch("/api/settings", headers=_AUTH_HEADER, json=body)

    async def test_patch_settings_to_infomaniak_returns_200_and_persists(self) -> None:
        """Switching to 'infomaniak' (even without a token) succeeds and is persisted."""
        app = _make_app()
        update = AsyncMock()

        resp = await self._patch(
            app, dict(_DEFAULT_DB_SETTINGS), {"llm": {"provider": "infomaniak"}}, update=update
        )

        assert resp.status_code == 200
        llm_calls = [call for call in update.call_args_list if call[0][1] == "llm"]
        assert len(llm_calls) == 1
        assert llm_calls[0][0][2]["provider"] == "infomaniak"

    async def test_patch_settings_to_infomaniak_reinits_client(self) -> None:
        """A provider change to infomaniak rebuilds the agent's LLM client."""
        old_client = MagicMock()
        old_client.close = AsyncMock()
        agent = MagicMock()
        agent._llm = old_client
        app = _make_app(agent=agent)
        new_client = MagicMock()
        new_client.close = AsyncMock()
        create_llm = MagicMock(return_value=new_client)

        resp = await self._patch(
            app,
            dict(_DEFAULT_DB_SETTINGS),
            {"llm": {"provider": "infomaniak"}},
            create_llm=create_llm,
        )

        assert resp.status_code == 200
        create_llm.assert_called_once()
        assert create_llm.call_args.args[0].provider == "infomaniak"
        assert agent._llm is new_client

    async def test_patch_settings_infomaniak_model_change_reinits_client(self) -> None:
        """Changing infomaniak_model while infomaniak is active rebuilds the client."""
        old_client = MagicMock()
        old_client.close = AsyncMock()
        agent = MagicMock()
        agent._llm = old_client
        app = _make_app(agent=agent)
        new_client = MagicMock()
        new_client.close = AsyncMock()
        create_llm = MagicMock(return_value=new_client)
        update = AsyncMock()

        resp = await self._patch(
            app,
            _infomaniak_db_settings(),
            {"llm": {"infomaniak_model": "mistralai/Mistral-Small-3.2"}},
            update=update,
            create_llm=create_llm,
        )

        assert resp.status_code == 200
        create_llm.assert_called_once()
        assert create_llm.call_args.args[0].infomaniak_model == "mistralai/Mistral-Small-3.2"
        assert agent._llm is new_client
        llm_calls = [call for call in update.call_args_list if call[0][1] == "llm"]
        assert llm_calls[0][0][2]["infomaniak_model"] == "mistralai/Mistral-Small-3.2"

    async def test_patch_settings_infomaniak_model_noop_does_not_reinit(self) -> None:
        """Re-sending the same infomaniak_model does not rebuild the client."""
        old_client = MagicMock()
        old_client.close = AsyncMock()
        agent = MagicMock()
        agent._llm = old_client
        app = _make_app(agent=agent)
        create_llm = MagicMock()

        resp = await self._patch(
            app,
            _infomaniak_db_settings(),
            {"llm": {"infomaniak_model": _INFOMANIAK_MODEL}},
            create_llm=create_llm,
        )

        assert resp.status_code == 200
        create_llm.assert_not_called()
        assert agent._llm is old_client

    async def test_patch_settings_infomaniak_model_change_other_provider_no_reinit(
        self,
    ) -> None:
        """Changing infomaniak_model while another provider is active persists it only."""
        old_client = MagicMock()
        old_client.close = AsyncMock()
        agent = MagicMock()
        agent._llm = old_client
        app = _make_app(agent=agent)
        create_llm = MagicMock()
        update = AsyncMock()

        resp = await self._patch(
            app,
            dict(_DEFAULT_DB_SETTINGS),  # provider: anthropic
            {"llm": {"infomaniak_model": "mistralai/Mistral-Small-3.2"}},
            update=update,
            create_llm=create_llm,
        )

        assert resp.status_code == 200
        create_llm.assert_not_called()
        assert agent._llm is old_client
        llm_calls = [call for call in update.call_args_list if call[0][1] == "llm"]
        assert llm_calls[0][0][2]["infomaniak_model"] == "mistralai/Mistral-Small-3.2"

    @pytest.mark.parametrize(
        "bad_model", ["evil; rm -rf /", "model$(id)", "../../etc/passwd", "a" * 201]
    )
    async def test_patch_settings_invalid_infomaniak_model_rejected(self, bad_model: str) -> None:
        """An infomaniak_model with shell metacharacters / over-length is rejected (422)."""
        app = _make_app()
        update = AsyncMock()

        resp = await self._patch(
            app,
            _infomaniak_db_settings(),
            {"llm": {"infomaniak_model": bad_model}},
            update=update,
        )

        assert resp.status_code == 422
        assert not any(call[0][1] == "llm" for call in update.call_args_list)


# ---------------------------------------------------------------------------
# Immutable fields
# ---------------------------------------------------------------------------


class TestSettingsImmutableFields:
    """Server section is immutable — PATCH with server data is ignored."""

    pytestmark = pytest.mark.asyncio

    async def test_patch_settings_cannot_change_server(self) -> None:
        """SettingsPatch model strips extra fields; server section is not patchable."""
        app = _make_app()
        mock_update = AsyncMock()

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"server": {"host": "evil.example.com", "port": 9999}},
                )

        # Should succeed (extra fields ignored), no update_setting calls.
        assert resp.status_code == 200
        mock_update.assert_not_called()


# ---------------------------------------------------------------------------
# Auth enforcement
# ---------------------------------------------------------------------------


class TestSettingsAuth:
    """Both settings endpoints require authentication."""

    pytestmark = pytest.mark.asyncio

    async def test_get_settings_401_without_token(self) -> None:
        """GET /api/settings without any header returns 401."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/settings")
        assert resp.status_code == 401

    async def test_patch_settings_401_without_token(self) -> None:
        """PATCH /api/settings without any header returns 401."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.patch("/api/settings", json={"appearance": {"theme": "dark"}})
        assert resp.status_code == 401

    async def test_get_settings_401_wrong_token(self) -> None:
        """GET /api/settings with wrong token returns 401."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/api/settings",
                headers={"Authorization": "Bearer wrong-token-value"},
            )
        assert resp.status_code == 401

    async def test_patch_settings_401_wrong_token(self) -> None:
        """PATCH /api/settings with wrong token returns 401."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.patch(
                "/api/settings",
                headers={"Authorization": "Bearer wrong-token-value"},
                json={"appearance": {"theme": "dark"}},
            )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tools settings (per-tool enable/disable)
# ---------------------------------------------------------------------------


class TestToolsSettings:
    """GET/PATCH /api/settings — tools section for per-tool enable/disable."""

    pytestmark = pytest.mark.asyncio

    async def test_get_settings_includes_tools_all_enabled_by_default(self) -> None:
        """When DB settings have no 'tools' key, all tools default to enabled."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        tools = resp.json()["tools"]
        for tool_name in (
            "gmail",
            "google_calendar",
            "google_drive",
            "outlook",
            "outlook_calendar",
            "onedrive",
            "memory",
        ):
            assert tools[tool_name] is True, f"{tool_name} should default to True"
        # GH-143: the local files tool is gone, so it has no toggle.
        assert "files" not in tools

    async def test_get_settings_includes_tools_with_custom_state(self) -> None:
        """When DB settings have tools with gmail=False, response reflects that."""
        settings = dict(_DEFAULT_DB_SETTINGS)
        settings["tools"] = {"gmail": False}
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch(
                "admino.database.load_settings_from_db",
                _mock_load_settings(settings),
            ),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        tools = resp.json()["tools"]
        assert tools["gmail"] is False
        # Other tools still default to True.
        assert tools["google_calendar"] is True
        assert tools["memory"] is True

    async def test_patch_settings_disables_tool(self) -> None:
        """PATCH with gmail=false persists the change and GET reflects it."""
        app = _make_app()
        mock_update = AsyncMock()

        # After the PATCH, load_settings returns updated tools.
        updated = dict(_DEFAULT_DB_SETTINGS)
        updated["tools"] = {"gmail": False}
        mock_load = AsyncMock(
            side_effect=[
                dict(_DEFAULT_DB_SETTINGS),  # read current settings
                updated,  # build response after update
            ]
        )

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"gmail": False}},
                )

        assert resp.status_code == 200
        # Verify update_setting was called for the tools section.
        tools_calls = [c for c in mock_update.call_args_list if c[0][1] == "tools"]
        assert len(tools_calls) == 1
        assert tools_calls[0][0][2]["gmail"] is False
        # Response should show gmail disabled.
        assert resp.json()["tools"]["gmail"] is False

    async def test_patch_settings_tool_toggle_is_audit_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Toggling a service writes an audit log line with old→new state.

        Mirrors the permission-change audit trail: every DB-mutating config
        action from the UI must be traceable. gmail starts enabled (default),
        so toggling it off logs tool=gmail old=True new=False.
        """
        app = _make_app()
        mock_update = AsyncMock()

        updated = dict(_DEFAULT_DB_SETTINGS)
        updated["tools"] = {"gmail": False}
        mock_load = AsyncMock(side_effect=[dict(_DEFAULT_DB_SETTINGS), updated])

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
            caplog.at_level(logging.WARNING, logger="admino.server"),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"gmail": False}},
                )

        assert resp.status_code == 200
        assert "Service toggled" in caplog.text
        assert "gmail" in caplog.text
        assert "old=True" in caplog.text
        assert "new=False" in caplog.text

    async def test_patch_settings_tool_toggle_no_change_not_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A no-op toggle (value unchanged) writes no audit line.

        gmail is already enabled by default, so a PATCH setting gmail=True
        changes nothing and must not produce a spurious 'toggled' record.
        """
        app = _make_app()
        mock_update = AsyncMock()
        mock_load = AsyncMock(side_effect=[dict(_DEFAULT_DB_SETTINGS), dict(_DEFAULT_DB_SETTINGS)])

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
            caplog.at_level(logging.WARNING, logger="admino.server"),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"gmail": True}},
                )

        assert resp.status_code == 200
        assert "Service toggled" not in caplog.text

    async def test_patch_settings_enables_tool(self) -> None:
        """PATCH with gmail=true re-enables a previously disabled tool."""
        app = _make_app()
        mock_update = AsyncMock()

        # Current settings have gmail disabled.
        current = dict(_DEFAULT_DB_SETTINGS)
        current["tools"] = {"gmail": False}
        # After update, gmail is re-enabled.
        updated = dict(_DEFAULT_DB_SETTINGS)
        updated["tools"] = {"gmail": True}
        mock_load = AsyncMock(side_effect=[current, updated])

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"gmail": True}},
                )

        assert resp.status_code == 200
        tools_calls = [c for c in mock_update.call_args_list if c[0][1] == "tools"]
        assert len(tools_calls) == 1
        assert tools_calls[0][0][2]["gmail"] is True
        assert resp.json()["tools"]["gmail"] is True

    async def test_patch_settings_tools_partial_update(self) -> None:
        """Patching one tool does not affect the stored state of others."""
        app = _make_app()
        mock_update = AsyncMock()

        # Current settings have gmail and outlook disabled.
        current = dict(_DEFAULT_DB_SETTINGS)
        current["tools"] = {"gmail": False, "outlook": False}
        mock_load = AsyncMock(
            side_effect=[
                current,
                current,  # response re-read (outlook still disabled)
            ]
        )

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", mock_load),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"gmail": True}},
                )

        assert resp.status_code == 200
        # The merged dict sent to update_setting should have gmail=True
        # AND preserve outlook=False from the current state.
        tools_calls = [c for c in mock_update.call_args_list if c[0][1] == "tools"]
        assert len(tools_calls) == 1
        saved = tools_calls[0][0][2]
        assert saved["gmail"] is True
        assert saved["outlook"] is False

    async def test_patch_settings_tools_rejects_non_boolean(self) -> None:
        """PATCH with non-boolean tool value returns 422 Pydantic validation error.

        SettingsPatchTools uses strict=True so string coercion is rejected.
        """
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"gmail": "notabool"}},
                )

        assert resp.status_code == 422

    async def test_patch_settings_tools_rejects_string_true(self) -> None:
        """PATCH with string 'true' is rejected — strict mode requires JSON boolean."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"gmail": "true"}},
                )

        assert resp.status_code == 422

    async def test_patch_settings_tools_ignores_unknown_fields(self) -> None:
        """PATCH with an unknown tool name is silently ignored (Pydantic drops it)."""
        app = _make_app()
        mock_update = AsyncMock()

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"unknown_tool": True}},
                )

        # Should succeed — unknown field is simply dropped by Pydantic.
        assert resp.status_code == 200
        # No tools update should be persisted since exclude_none leaves
        # nothing after the unknown field is stripped.
        tools_calls = [c for c in mock_update.call_args_list if c[0][1] == "tools"]
        # The handler still calls update_setting for the tools section,
        # but the merged dict should have no new fields from the patch.
        # Either no call (if handler checks for empty patch) or an empty merge.
        if tools_calls:
            saved = tools_calls[0][0][2]
            assert "unknown_tool" not in saved

    async def test_patch_settings_tools_ignores_removed_files_toggle(self) -> None:
        """PATCH {"tools": {"files": false}} is silently ignored (GH-143).

        The files tool no longer exists, so its toggle is an unknown field:
        the request succeeds and nothing about 'files' is persisted.
        """
        app = _make_app()
        mock_update = AsyncMock()

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"files": False}},
                )

        assert resp.status_code == 200
        saved_tools = [c[0][2] for c in mock_update.call_args_list if c[0][1] == "tools"]
        assert all("files" not in saved for saved in saved_tools)

    async def test_patch_settings_tools_drops_legacy_files_key_from_db(self) -> None:
        """A legacy 'files' key already stored in the DB is not written back (GH-143)."""
        settings = dict(_DEFAULT_DB_SETTINGS)
        settings["tools"] = {"files": False}
        app = _make_app()
        mock_update = AsyncMock()

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings(settings)),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"gmail": False}},
                )

        assert resp.status_code == 200
        saved_tools = [c[0][2] for c in mock_update.call_args_list if c[0][1] == "tools"]
        assert len(saved_tools) == 1
        assert saved_tools[0]["gmail"] is False
        assert "files" not in saved_tools[0]

    async def test_get_settings_tools_omits_legacy_files_key_from_db(self) -> None:
        """GET never reports a 'files' toggle, even if the DB still stores one."""
        settings = dict(_DEFAULT_DB_SETTINGS)
        settings["tools"] = {"files": False, "gmail": False}
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings(settings)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        tools = resp.json()["tools"]
        assert "files" not in tools
        assert tools["gmail"] is False

    async def test_get_settings_tools_fallback_on_corrupt_db(self) -> None:
        """GET with corrupt tools JSONB in DB falls back to all-enabled defaults."""
        corrupt_settings = dict(_DEFAULT_DB_SETTINGS)
        corrupt_settings["tools"] = {"gmail": [1, 2, 3]}  # not a bool

        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings(corrupt_settings)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        tools = resp.json()["tools"]
        # All tools should be at their default (True) after fallback.
        assert tools["gmail"] is True
        assert tools["memory"] is True

    async def test_get_settings_tools_string_value_does_not_coerce_to_enabled(self) -> None:
        """A non-boolean string in the DB tools column must NOT coerce to True.

        Security (GH-80): ToolsSettings is strict, so a corrupt/migrated
        ``"false"`` string raises ValidationError and trips the all-enabled
        fallback rather than being silently coerced to ``True``. The point is
        that string coercion never silently re-enables a service — it forces
        the explicit, auditable fallback path instead.
        """
        corrupt_settings = dict(_DEFAULT_DB_SETTINGS)
        corrupt_settings["tools"] = {"gmail": "false"}  # string, not a JSON bool

        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings(corrupt_settings)),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/settings", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        # Strict validation rejected the string and the whole section fell back
        # to defaults — gmail is the default True, NOT a coerced value.
        assert resp.json()["tools"]["gmail"] is True

    async def test_patch_tools_hotreloads_agent_tools_enabled(self) -> None:
        """PATCH /api/settings tools section updates agent._tools_enabled in-place.

        When the user disables a tool via the settings UI, the agent must
        immediately reflect the change so subsequent dispatches respect it.
        """
        agent = MagicMock()
        agent._tools_enabled = {}

        app = _make_app(agent=agent)
        mock_update = AsyncMock()

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
            patch("admino.database.update_setting", mock_update),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"tools": {"gmail": False}},
                )

        assert resp.status_code == 200
        assert agent._tools_enabled["gmail"] is False


# ---------------------------------------------------------------------------
# Adversarial inputs
# ---------------------------------------------------------------------------


class TestSettingsAdversarial:
    """Adversarial inputs: oversized, injection, wrong types."""

    pytestmark = pytest.mark.asyncio

    async def test_patch_settings_oversized_model_name(self) -> None:
        """Model name exceeding max_length (200) returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"anthropic_model": "a" * 201}},
                )
        assert resp.status_code == 422

    async def test_patch_settings_sql_injection_in_model_name(self) -> None:
        """Model name with SQL injection is rejected by validation regex."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"anthropic_model": "'; DROP TABLE settings; --"}},
                )
        assert resp.status_code == 422

    async def test_patch_settings_wrong_type_for_provider(self) -> None:
        """Sending integer for provider field returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"provider": 123}},
                )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "model_name",
        [
            "model; rm -rf /",
            "model$(whoami)",
            "model`id`",
            "model|cat /etc/passwd",
            "model&& echo pwned",
        ],
        ids=[
            "semicolon_injection",
            "dollar_subshell",
            "backtick_subshell",
            "pipe_injection",
            "ampersand_chain",
        ],
    )
    async def test_patch_settings_shell_metachar_in_model_name(self, model_name: str) -> None:
        """Model names with shell metacharacters are rejected by Pydantic."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"anthropic_model": model_name}},
                )
        assert resp.status_code == 422

    async def test_patch_settings_wrong_type_for_theme(self) -> None:
        """Sending non-string for appearance.theme returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"appearance": {"theme": "invalid_theme_value"}},
                )
        assert resp.status_code == 422

    async def test_patch_settings_wrong_type_for_notifications(self) -> None:
        """Sending a list for notifications.enabled returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"notifications": {"enabled": [1, 2, 3]}},
                )
        assert resp.status_code == 422
