"""Tests for the Permissions API endpoints (GET/PATCH /api/permissions).

Covers:
- GET /api/permissions: returns full permission matrix from DB
- PATCH /api/permissions: updates single permission, rejects hardcoded denials
- Auth enforcement on both endpoints (401 without/wrong token)
- Validation: invalid identifiers (422), invalid permission values (422)
- Immediate effect: agent._permissions updated after PATCH
- Adversarial inputs: oversized identifiers, control characters, injection

Security notes:
- All tests use mocked database — no real DB or API calls.
- Auth token is a known test value, never a real secret.
- Hardcoded denials cannot be overridden regardless of config.
"""

from __future__ import annotations

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

# Mocked permission data from load_permissions_from_db.
_DEFAULT_PERMISSIONS: dict[str, dict[str, str]] = {
    "gmail": {"read": "allow", "list": "allow", "send": "deny"},
    "files": {"read": "allow", "delete": "deny"},
}

# All hardcoded denials from the spec.
_HARDCODED_DENIALS: list[tuple[str, str]] = [
    ("gmail", "send"),
    ("gmail", "delete"),
    ("google_calendar", "delete"),
    ("google_calendar", "update"),
    ("google_drive", "delete"),
    ("outlook", "send"),
    ("outlook", "delete"),
    ("outlook_calendar", "delete"),
    ("outlook_calendar", "update"),
    ("onedrive", "delete"),
    ("documents", "delete"),
    ("files", "delete"),
    ("files", "overwrite"),
    ("memory", "delete"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    *, auth_mode: str = "token", token: str | None = _TEST_TOKEN
) -> MagicMock:
    """Build a minimal mock AppConfig."""
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


def _mock_load_permissions(
    data: dict[str, dict[str, str]] | None = None,
) -> AsyncMock:
    """Return an AsyncMock for load_permissions_from_db."""
    return AsyncMock(return_value=data if data is not None else dict(_DEFAULT_PERMISSIONS))


def _mock_get_pool() -> MagicMock:
    """Return a mock for database.get_pool."""
    return MagicMock(return_value=MagicMock())


# ---------------------------------------------------------------------------
# GET /api/permissions
# ---------------------------------------------------------------------------


class TestGetPermissions:
    """GET /api/permissions — returns full permission matrix."""

    pytestmark = pytest.mark.asyncio

    async def test_get_permissions_returns_flat_list(self) -> None:
        """Response contains all permissions as a flat list of entries."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/permissions", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        body = resp.json()
        assert "permissions" in body
        assert isinstance(body["permissions"], list)

    async def test_get_permissions_entries_have_correct_structure(self) -> None:
        """Each entry has tool, action, and permission keys."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/permissions", headers=_AUTH_HEADER)

        entries = resp.json()["permissions"]
        for entry in entries:
            assert "tool" in entry
            assert "action" in entry
            assert "permission" in entry

    async def test_get_permissions_returns_all_db_entries(self) -> None:
        """All tool/action pairs from DB appear in the response."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/permissions", headers=_AUTH_HEADER)

        entries = resp.json()["permissions"]
        # _DEFAULT_PERMISSIONS has 5 total entries (gmail:3, files:2)
        assert len(entries) == 5

    async def test_get_permissions_entries_sorted_by_tool_then_action(self) -> None:
        """Entries are sorted alphabetically by tool, then action."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/permissions", headers=_AUTH_HEADER)

        entries = resp.json()["permissions"]
        tools_actions = [(e["tool"], e["action"]) for e in entries]
        assert tools_actions == sorted(tools_actions)

    async def test_get_permissions_specific_values(self) -> None:
        """Verify specific permission values match mocked DB data."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/permissions", headers=_AUTH_HEADER)

        entries = resp.json()["permissions"]
        lookup = {(e["tool"], e["action"]): e["permission"] for e in entries}
        assert lookup[("gmail", "read")] == "allow"
        assert lookup[("gmail", "send")] == "deny"
        assert lookup[("files", "delete")] == "deny"

    async def test_get_permissions_requires_auth(self) -> None:
        """GET /api/permissions without Authorization header returns 401."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/permissions")
        assert resp.status_code == 401

    async def test_get_permissions_wrong_token_returns_401(self) -> None:
        """GET /api/permissions with incorrect token returns 401."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get(
                "/api/permissions",
                headers={"Authorization": "Bearer wrong-token-value"},
            )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PATCH /api/permissions
# ---------------------------------------------------------------------------


class TestPatchPermissions:
    """PATCH /api/permissions — update a single permission."""

    pytestmark = pytest.mark.asyncio

    async def test_patch_permissions_updates_and_returns_matrix(self) -> None:
        """Successful PATCH returns updated full permission matrix."""
        app = _make_app()
        mock_update = AsyncMock()
        mock_load_config = AsyncMock(return_value=MagicMock())

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
            patch("admino.database.update_permission", mock_update),
            patch("admino.config.load_permissions_config_from_db", mock_load_config),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": "read", "permission": "confirm"},
                )

        assert resp.status_code == 200
        assert "permissions" in resp.json()

    async def test_patch_permissions_calls_update_permission(self) -> None:
        """PATCH calls update_permission with correct tool, action, permission."""
        app = _make_app()
        mock_update = AsyncMock()
        mock_load_config = AsyncMock(return_value=MagicMock())

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
            patch("admino.database.update_permission", mock_update),
            patch("admino.config.load_permissions_config_from_db", mock_load_config),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": "list", "permission": "deny"},
                )

        # update_permission is called with (pool, tool, action, permission)
        call_args = mock_update.call_args[0]
        assert call_args[1] == "gmail"
        assert call_args[2] == "list"
        assert call_args[3] == "deny"

    async def test_patch_permissions_updates_agent_permissions(self) -> None:
        """After PATCH, agent._permissions is updated immediately."""
        agent = MagicMock()
        app = _make_app(agent=agent)
        mock_load_config = AsyncMock(return_value=MagicMock(name="new_permissions"))

        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
            patch("admino.database.update_permission", AsyncMock()),
            patch("admino.config.load_permissions_config_from_db", mock_load_config),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "files", "action": "read", "permission": "confirm"},
                )

        assert agent._permissions == mock_load_config.return_value

    async def test_patch_permissions_requires_auth(self) -> None:
        """PATCH /api/permissions without Authorization header returns 401."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.patch(
                "/api/permissions",
                json={"tool": "gmail", "action": "read", "permission": "allow"},
            )
        assert resp.status_code == 401

    async def test_patch_permissions_wrong_token_returns_401(self) -> None:
        """PATCH /api/permissions with incorrect token returns 401."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.patch(
                "/api/permissions",
                headers={"Authorization": "Bearer wrong-token-value"},
                json={"tool": "gmail", "action": "read", "permission": "allow"},
            )
        assert resp.status_code == 401

    async def test_patch_permissions_allow_value_accepted(self) -> None:
        """Permission value 'allow' is accepted."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
            patch("admino.database.update_permission", AsyncMock()),
            patch(
                "admino.config.load_permissions_config_from_db",
                AsyncMock(return_value=MagicMock()),
            ),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": "read", "permission": "allow"},
                )
        assert resp.status_code == 200

    async def test_patch_permissions_confirm_value_accepted(self) -> None:
        """Permission value 'confirm' is accepted."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
            patch("admino.database.update_permission", AsyncMock()),
            patch(
                "admino.config.load_permissions_config_from_db",
                AsyncMock(return_value=MagicMock()),
            ),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": "read", "permission": "confirm"},
                )
        assert resp.status_code == 200

    async def test_patch_permissions_deny_value_accepted(self) -> None:
        """Permission value 'deny' is accepted."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
            patch("admino.database.update_permission", AsyncMock()),
            patch(
                "admino.config.load_permissions_config_from_db",
                AsyncMock(return_value=MagicMock()),
            ),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": "read", "permission": "deny"},
                )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Hardcoded denials — cannot be overridden
# ---------------------------------------------------------------------------


class TestPatchPermissionsHardcodedDenials:
    """PATCH /api/permissions rejects overrides for hardcoded denials."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize(
        ("tool", "action"),
        _HARDCODED_DENIALS,
        ids=[f"{t}.{a}" for t, a in _HARDCODED_DENIALS],
    )
    async def test_patch_hardcoded_denial_to_allow_returns_400(
        self, tool: str, action: str
    ) -> None:
        """Setting a hardcoded denial to 'allow' returns 400."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": tool, "action": action, "permission": "allow"},
                )
        assert resp.status_code == 400

    @pytest.mark.parametrize(
        ("tool", "action"),
        _HARDCODED_DENIALS,
        ids=[f"{t}.{a}" for t, a in _HARDCODED_DENIALS],
    )
    async def test_patch_hardcoded_denial_to_confirm_returns_400(
        self, tool: str, action: str
    ) -> None:
        """Setting a hardcoded denial to 'confirm' returns 400."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": tool, "action": action, "permission": "confirm"},
                )
        assert resp.status_code == 400

    @pytest.mark.parametrize(
        ("tool", "action"),
        _HARDCODED_DENIALS,
        ids=[f"{t}.{a}" for t, a in _HARDCODED_DENIALS],
    )
    async def test_patch_hardcoded_denial_to_deny_succeeds(
        self, tool: str, action: str
    ) -> None:
        """Setting a hardcoded denial to 'deny' is valid (no-op but not an error)."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
            patch("admino.database.update_permission", AsyncMock()),
            patch(
                "admino.config.load_permissions_config_from_db",
                AsyncMock(return_value=MagicMock()),
            ),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": tool, "action": action, "permission": "deny"},
                )
        assert resp.status_code == 200

    async def test_patch_hardcoded_denial_error_message_includes_details(self) -> None:
        """Error response for hardcoded denial uses generic message (no input echo)."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": "send", "permission": "allow"},
                )
        body = resp.json()
        assert "hardcoded denial" in body["detail"]
        # User input must NOT be echoed in the error message.
        assert "gmail" not in body["detail"]
        assert "send" not in body["detail"]


# ---------------------------------------------------------------------------
# Validation — invalid identifiers and permission values
# ---------------------------------------------------------------------------


class TestPatchPermissionsValidation:
    """PATCH /api/permissions input validation (422 errors)."""

    pytestmark = pytest.mark.asyncio

    async def test_patch_invalid_permission_value_returns_422(self) -> None:
        """Permission value not in allow/confirm/deny returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": "read", "permission": "block"},
                )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "tool_name",
        [
            "Gmail",           # uppercase
            "123tool",         # starts with digit
            "tool-name",       # contains hyphen
            "tool name",       # contains space
            "tool.name",       # contains dot
            "",                # empty
            "a" * 64,          # too long (max 63)
        ],
        ids=[
            "uppercase",
            "starts_with_digit",
            "hyphen",
            "space",
            "dot",
            "empty",
            "too_long",
        ],
    )
    async def test_patch_invalid_tool_identifier_returns_422(
        self, tool_name: str
    ) -> None:
        """Tool identifiers not matching ^[a-z][a-z0-9_]{0,62}$ return 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": tool_name, "action": "read", "permission": "allow"},
                )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "action_name",
        [
            "Read",            # uppercase
            "0action",         # starts with digit
            "action-name",     # contains hyphen
            "act ion",         # contains space
            "",                # empty
            "b" * 64,          # too long (max 63)
        ],
        ids=[
            "uppercase",
            "starts_with_digit",
            "hyphen",
            "space",
            "empty",
            "too_long",
        ],
    )
    async def test_patch_invalid_action_identifier_returns_422(
        self, action_name: str
    ) -> None:
        """Action identifiers not matching ^[a-z][a-z0-9_]{0,62}$ return 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": action_name, "permission": "allow"},
                )
        assert resp.status_code == 422

    async def test_patch_missing_tool_field_returns_422(self) -> None:
        """Request body without 'tool' field returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"action": "read", "permission": "allow"},
                )
        assert resp.status_code == 422

    async def test_patch_missing_action_field_returns_422(self) -> None:
        """Request body without 'action' field returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "permission": "allow"},
                )
        assert resp.status_code == 422

    async def test_patch_missing_permission_field_returns_422(self) -> None:
        """Request body without 'permission' field returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": "read"},
                )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Adversarial inputs
# ---------------------------------------------------------------------------


class TestPermissionsAdversarial:
    """Adversarial inputs to permissions endpoints."""

    pytestmark = pytest.mark.asyncio

    async def test_patch_sql_injection_in_tool_name_returns_422(self) -> None:
        """SQL injection attempt in tool name is rejected by Pydantic regex."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={
                        "tool": "'; DROP TABLE permissions; --",
                        "action": "read",
                        "permission": "allow",
                    },
                )
        assert resp.status_code == 422

    async def test_patch_sql_injection_in_action_name_returns_422(self) -> None:
        """SQL injection attempt in action name is rejected by Pydantic regex."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={
                        "tool": "gmail",
                        "action": "read OR 1=1",
                        "permission": "allow",
                    },
                )
        assert resp.status_code == 422

    async def test_patch_control_characters_in_tool_name_returns_422(self) -> None:
        """Control characters in tool name are rejected by pattern."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={
                        "tool": "gmail\x00",
                        "action": "read",
                        "permission": "allow",
                    },
                )
        assert resp.status_code == 422

    async def test_patch_unicode_in_tool_name_returns_422(self) -> None:
        """Unicode characters in tool name are rejected by ascii-only pattern."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={
                        "tool": "gm\u0430il",  # Cyrillic 'a' (homoglyph)
                        "action": "read",
                        "permission": "allow",
                    },
                )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "permission_value",
        [
            "ALLOW",
            "Allow",
            "permit",
            "true",
            "1",
            "yes",
            "deny; rm -rf /",
        ],
        ids=[
            "uppercase_allow",
            "capitalized_allow",
            "permit",
            "true_string",
            "numeric_one",
            "yes_string",
            "shell_injection",
        ],
    )
    async def test_patch_invalid_permission_variants_return_422(
        self, permission_value: str
    ) -> None:
        """Only exact 'allow', 'confirm', 'deny' are accepted."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={
                        "tool": "gmail",
                        "action": "read",
                        "permission": permission_value,
                    },
                )
        assert resp.status_code == 422

    async def test_patch_integer_permission_value_returns_422(self) -> None:
        """Integer permission value (not a string) returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={"tool": "gmail", "action": "read", "permission": 1},
                )
        assert resp.status_code == 422

    async def test_patch_empty_body_returns_422(self) -> None:
        """Empty JSON body (missing all required fields) returns 422."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={},
                )
        assert resp.status_code == 422

    async def test_patch_extra_fields_ignored_successfully(self) -> None:
        """Extra fields in request body are ignored; valid request succeeds."""
        app = _make_app()
        with (
            patch("admino.database.get_pool", _mock_get_pool()),
            patch("admino.database.load_permissions_from_db", _mock_load_permissions()),
            patch("admino.database.update_permission", AsyncMock()),
            patch(
                "admino.config.load_permissions_config_from_db",
                AsyncMock(return_value=MagicMock()),
            ),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/permissions",
                    headers=_AUTH_HEADER,
                    json={
                        "tool": "gmail",
                        "action": "read",
                        "permission": "allow",
                        "extra_field": "should_be_ignored",
                        "hack": True,
                    },
                )
        assert resp.status_code == 200
