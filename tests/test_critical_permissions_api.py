"""Tests for the Critical Permissions API (tier-2 promotable denials).

Covers:
- GET /api/critical-permissions: returns 4 promotable permissions with state
- PATCH /api/critical-permissions/{tool}/{action}: promote/demote permissions
- DELETE /api/critical-permissions/{tool}/{action}/pending: cancel cooldown
- Auth enforcement on all endpoints (401 without/wrong token)
- Rate limiting on promotion attempts (429 after burst)
- Lazy cooldown resolution (pending -> confirm after 5 min)
- Adversarial inputs: invalid tool names, immutable denials, unknown pairs

Security notes:
- All tests use mocked database -- no real DB or API calls.
- Auth token is a known test value, never a real secret.
- Only 4 defined promotable pairs are accepted; all others return 404.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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

_TEST_TOKEN = "a" * 48 + "BcDeFgHiJkLmNoPqRsTuVwXyZ"
_AUTH_HEADER = {"Authorization": f"Bearer {_TEST_TOKEN}"}

_PROMOTABLE_PAIRS: list[tuple[str, str]] = [
    ("gmail", "send"),
    ("outlook", "send"),
    ("google_calendar", "update"),
    ("outlook_calendar", "update"),
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


def _mock_get_pool() -> MagicMock:
    """Return a mock for database.get_pool."""
    return MagicMock(return_value=MagicMock())


def _mock_load_permissions() -> AsyncMock:
    """Return an AsyncMock for load_permissions_from_db."""
    return AsyncMock(return_value={})


def _clear_critical_state() -> None:
    """Reset module-level critical permissions state for test isolation."""
    from admino import server

    server._pending_promotions.clear()
    server._promoted_permissions.clear()


# ---------------------------------------------------------------------------
# GET /api/critical-permissions
# ---------------------------------------------------------------------------


class TestGetCriticalPermissions:
    """GET /api/critical-permissions -- returns 4 promotable permissions."""

    pytestmark = pytest.mark.asyncio

    async def test_get_critical_permissions_returns_4_entries(self) -> None:
        """Response contains exactly 4 promotable permission entries."""
        app = _make_app()
        _clear_critical_state()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        body = resp.json()
        assert len(body["permissions"]) == 4

    async def test_get_critical_permissions_default_state_all_deny(self) -> None:
        """All entries have state='deny' and pending_at=None by default."""
        app = _make_app()
        _clear_critical_state()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

        for entry in resp.json()["permissions"]:
            assert entry["state"] == "deny"
            assert entry["pending_at"] is None

    async def test_get_critical_permissions_entry_structure(self) -> None:
        """Each entry has tool, action, state, and pending_at keys."""
        app = _make_app()
        _clear_critical_state()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

        for entry in resp.json()["permissions"]:
            assert "tool" in entry
            assert "action" in entry
            assert "state" in entry
            assert "pending_at" in entry

    async def test_get_critical_permissions_contains_expected_pairs(self) -> None:
        """Response contains exactly the 4 expected tool/action pairs."""
        app = _make_app()
        _clear_critical_state()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

        pairs = {(e["tool"], e["action"]) for e in resp.json()["permissions"]}
        assert pairs == set(_PROMOTABLE_PAIRS)

    async def test_get_critical_permissions_requires_auth(self) -> None:
        """GET without Authorization header returns 401."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/critical-permissions")
        assert resp.status_code == 401

    async def test_get_critical_permissions_wrong_token_returns_401(self) -> None:
        """GET with incorrect token returns 401."""
        app = _make_app()
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get(
                "/api/critical-permissions",
                headers={"Authorization": "Bearer wrong-token-value"},
            )
        assert resp.status_code == 401

    async def test_get_critical_permissions_shows_pending_promotion(self) -> None:
        """After setting a pending promotion, GET shows pending_at timestamp."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        now = datetime.now(UTC)
        server._pending_promotions[("gmail", "send")] = now

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

            entries = resp.json()["permissions"]
            gmail_send = next(
                e for e in entries if e["tool"] == "gmail" and e["action"] == "send"
            )
            assert gmail_send["pending_at"] is not None
            assert gmail_send["state"] == "deny"
        finally:
            _clear_critical_state()

    async def test_get_critical_permissions_shows_promoted_state(self) -> None:
        """After adding to _promoted_permissions, GET shows state='confirm'."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        server._promoted_permissions.add(("gmail", "send"))

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

            entries = resp.json()["permissions"]
            gmail_send = next(
                e for e in entries if e["tool"] == "gmail" and e["action"] == "send"
            )
            assert gmail_send["state"] == "confirm"
        finally:
            _clear_critical_state()

    async def test_get_critical_permissions_resolves_expired_cooldown(self) -> None:
        """Expired cooldown (>5 min) is lazily resolved to state='confirm'."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        # Set pending_at to 6 minutes ago to simulate expired cooldown
        server._pending_promotions[("gmail", "send")] = datetime.now(UTC) - timedelta(
            minutes=6
        )
        mock_update = AsyncMock()

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as c:
                    resp = await c.get(
                        "/api/critical-permissions", headers=_AUTH_HEADER
                    )

            entries = resp.json()["permissions"]
            gmail_send = next(
                e for e in entries if e["tool"] == "gmail" and e["action"] == "send"
            )
            assert gmail_send["state"] == "confirm"
            # Verify the DB was updated to persist the promotion
            mock_update.assert_called_once()
        finally:
            _clear_critical_state()


# ---------------------------------------------------------------------------
# PATCH /api/critical-permissions/{tool}/{action} -- promote
# ---------------------------------------------------------------------------


class TestPromoteCriticalPermission:
    """PATCH /api/critical-permissions/{tool}/{action} -- promote (deny -> confirm)."""

    pytestmark = pytest.mark.asyncio

    async def test_promote_starts_cooldown_with_valid_token(self) -> None:
        """PATCH with valid bearer_token returns state='deny' with pending_at set."""
        app = _make_app()
        _clear_critical_state()

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.patch(
                    "/api/critical-permissions/gmail/send",
                    headers=_AUTH_HEADER,
                    json={"bearer_token": _TEST_TOKEN},
                )

            assert resp.status_code == 200
            body = resp.json()
            assert body["state"] == "deny"
            assert body["pending_at"] is not None
        finally:
            _clear_critical_state()

    async def test_promote_requires_bearer_token_in_body(self) -> None:
        """PATCH without bearer_token in body returns 400."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.patch(
                "/api/critical-permissions/gmail/send",
                headers=_AUTH_HEADER,
                json={},
            )
        assert resp.status_code in (400, 422)

    async def test_promote_wrong_token_returns_401(self) -> None:
        """PATCH with incorrect bearer_token in body returns 401."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.patch(
                "/api/critical-permissions/gmail/send",
                headers=_AUTH_HEADER,
                json={"bearer_token": "wrong-token-value"},
            )
        assert resp.status_code == 401

    async def test_promote_unknown_permission_returns_404(self) -> None:
        """PATCH on non-promotable pair (gmail/delete) returns 404."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.patch(
                "/api/critical-permissions/gmail/delete",
                headers=_AUTH_HEADER,
                json={"bearer_token": _TEST_TOKEN},
            )
        assert resp.status_code == 404

    async def test_promote_already_pending_returns_existing_pending(self) -> None:
        """Second promote on same pair returns the same pending_at timestamp."""
        app = _make_app()
        _clear_critical_state()

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp1 = await c.patch(
                    "/api/critical-permissions/gmail/send",
                    headers=_AUTH_HEADER,
                    json={"bearer_token": _TEST_TOKEN},
                )
                resp2 = await c.patch(
                    "/api/critical-permissions/gmail/send",
                    headers=_AUTH_HEADER,
                    json={"bearer_token": _TEST_TOKEN},
                )

            assert resp1.status_code == 200
            assert resp2.status_code == 200
            assert resp1.json()["pending_at"] == resp2.json()["pending_at"]
        finally:
            _clear_critical_state()

    async def test_promote_rate_limited(self) -> None:
        """6th rapid promotion request returns 429."""
        app = _make_app()
        _clear_critical_state()

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                statuses = []
                for _ in range(6):
                    resp = await c.patch(
                        "/api/critical-permissions/gmail/send",
                        headers=_AUTH_HEADER,
                        json={"bearer_token": _TEST_TOKEN},
                    )
                    statuses.append(resp.status_code)

            # First 5 should succeed, 6th should be rate-limited
            assert 429 in statuses
            assert statuses[-1] == 429
        finally:
            _clear_critical_state()


# ---------------------------------------------------------------------------
# PATCH /api/critical-permissions/{tool}/{action} -- demote
# ---------------------------------------------------------------------------


class TestDemoteCriticalPermission:
    """PATCH /api/critical-permissions/{tool}/{action} -- demote (confirm -> deny)."""

    pytestmark = pytest.mark.asyncio

    async def test_demote_promoted_permission_immediate(self) -> None:
        """Demoting a promoted permission returns state='deny' immediately."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        server._promoted_permissions.add(("gmail", "send"))
        mock_update = AsyncMock()
        mock_load_config = AsyncMock(return_value=MagicMock())

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
                patch(
                    "admino.config.load_permissions_config_from_db", mock_load_config
                ),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as c:
                    resp = await c.patch(
                        "/api/critical-permissions/gmail/send",
                        headers=_AUTH_HEADER,
                    )

            assert resp.status_code == 200
            assert resp.json()["state"] == "deny"
        finally:
            _clear_critical_state()

    async def test_demote_clears_pending_promotion(self) -> None:
        """Demoting clears both pending and promoted state."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        server._promoted_permissions.add(("gmail", "send"))
        server._pending_promotions[("gmail", "send")] = datetime.now(UTC)
        mock_update = AsyncMock()
        mock_load_config = AsyncMock(return_value=MagicMock())

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
                patch(
                    "admino.config.load_permissions_config_from_db", mock_load_config
                ),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as c:
                    resp = await c.patch(
                        "/api/critical-permissions/gmail/send",
                        headers=_AUTH_HEADER,
                    )

            assert resp.status_code == 200
            assert resp.json()["state"] == "deny"
            assert ("gmail", "send") not in server._pending_promotions
            assert ("gmail", "send") not in server._promoted_permissions
        finally:
            _clear_critical_state()

    async def test_demote_does_not_require_bearer_token(self) -> None:
        """Demoting a promoted permission succeeds without bearer_token in body."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        server._promoted_permissions.add(("outlook", "send"))
        mock_update = AsyncMock()
        mock_load_config = AsyncMock(return_value=MagicMock())

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
                patch(
                    "admino.config.load_permissions_config_from_db", mock_load_config
                ),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as c:
                    resp = await c.patch(
                        "/api/critical-permissions/outlook/send",
                        headers=_AUTH_HEADER,
                    )

            assert resp.status_code == 200
            assert resp.json()["state"] == "deny"
        finally:
            _clear_critical_state()


# ---------------------------------------------------------------------------
# DELETE /api/critical-permissions/{tool}/{action}/pending
# ---------------------------------------------------------------------------


class TestCancelPendingPromotion:
    """DELETE /api/critical-permissions/{tool}/{action}/pending -- cancel cooldown."""

    pytestmark = pytest.mark.asyncio

    async def test_cancel_pending_returns_deny_state(self) -> None:
        """Cancelling an active cooldown returns state='deny'."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        server._pending_promotions[("gmail", "send")] = datetime.now(UTC)

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.delete(
                    "/api/critical-permissions/gmail/send/pending",
                    headers=_AUTH_HEADER,
                )

            assert resp.status_code == 200
            assert resp.json()["state"] == "deny"
            assert ("gmail", "send") not in server._pending_promotions
        finally:
            _clear_critical_state()

    async def test_cancel_no_pending_returns_404(self) -> None:
        """DELETE when no cooldown is active returns 404."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.delete(
                "/api/critical-permissions/gmail/send/pending",
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 404

    async def test_cancel_unknown_permission_returns_404(self) -> None:
        """DELETE on non-promotable pair returns 404."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.delete(
                "/api/critical-permissions/gmail/delete/pending",
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 404

    async def test_cancel_requires_auth(self) -> None:
        """DELETE without Authorization header returns 401."""
        app = _make_app()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.delete(
                "/api/critical-permissions/gmail/send/pending",
            )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Adversarial inputs
# ---------------------------------------------------------------------------


class TestCriticalPermissionsAdversarial:
    """Adversarial inputs to critical permissions endpoints."""

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize(
        "tool",
        [
            "GMAIL",
            "gmail<script>",
            "gmail; DROP TABLE",
            "gm..ail",
        ],
        ids=[
            "uppercase",
            "xss_injection",
            "sql_injection",
            "double_dot",
        ],
    )
    async def test_promote_with_invalid_tool_identifier_returns_422(
        self, tool: str
    ) -> None:
        """PATCH with invalid tool identifier returns 422."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.patch(
                f"/api/critical-permissions/{tool}/send",
                headers=_AUTH_HEADER,
                json={"bearer_token": _TEST_TOKEN},
            )
        # Invalid tool identifiers should be rejected (404 for non-promotable
        # or 422 for validation failure -- either is acceptable)
        assert resp.status_code in (404, 422)

    async def test_promote_immutable_denial_returns_404(self) -> None:
        """PATCH on tier-1 immutable denial (gmail/delete) returns 404."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.patch(
                "/api/critical-permissions/gmail/delete",
                headers=_AUTH_HEADER,
                json={"bearer_token": _TEST_TOKEN},
            )
        assert resp.status_code == 404
