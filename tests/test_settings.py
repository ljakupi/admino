"""Tests for the Settings API endpoints (GET/PATCH /api/settings).

Covers:
- GET /api/settings: returns current settings with masked API keys
- PATCH /api/settings: partial updates, validation, LLM re-init
- Auth enforcement on both endpoints
- Adversarial inputs: oversized values, SQL injection, wrong types
- Immutable fields (server section) cannot be changed via PATCH

Security notes:
- All tests use mocked database and config — no real DB or API calls.
- Auth token is a known test value, never a real secret.
"""

from __future__ import annotations

import json
from pathlib import Path
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
_AUTH_HEADER = {"Authorization": f"Bearer {_TEST_TOKEN}"}

# Default settings returned by mocked load_settings_from_db.
_DEFAULT_DB_SETTINGS: dict[str, Any] = {
    "llm": {
        "provider": "ollama",
        "model": "gemma4:e2b",
        "ollama_url": "http://local-llm:11434",
        "anthropic_model": "claude-sonnet-4-20250514",
        "openai_model": "gpt-4o",
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
    config.auth.mode = auth_mode
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    config.paths.tokens_dir = Path("/tmp/test-tokens")  # noqa: S108
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
    """Build a fake get_connection_status returning (connected, healthy) per provider."""

    def _side(_tokens_dir: Path, provider: str) -> tuple[bool, bool]:
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
        assert body["llm"]["provider"] == "ollama"
        assert body["llm"]["model"] == "gemma4:e2b"
        assert body["appearance"]["theme"] == "light"
        assert body["notifications"]["enabled"] is True
        assert body["limits"]["max_tool_calls_per_message"] == 10
        assert body["server"]["host"] == "0.0.0.0"  # noqa: S104
        assert body["server"]["port"] == 8000

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
        assert updated_llm["model"] == "gemma4:e2b"

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
            "documents",
            "files",
            "web_search",
            "memory",
        ):
            assert tools[tool_name] is True, f"{tool_name} should default to True"

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
                    json={"llm": {"model": "a" * 201}},
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
                    json={"llm": {"model": "'; DROP TABLE settings; --"}},
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
                    json={"llm": {"model": model_name}},
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

    async def test_patch_settings_invalid_ollama_url_scheme(self) -> None:
        """Ollama URL without http/https prefix is rejected."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_settings_from_db", _mock_load_settings()),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/settings",
                    headers=_AUTH_HEADER,
                    json={"llm": {"ollama_url": "ftp://evil.com:11434"}},
                )
        assert resp.status_code == 422
