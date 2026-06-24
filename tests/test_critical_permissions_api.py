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


def _make_config(*, auth_mode: str = "token", token: str | None = _TEST_TOKEN) -> MagicMock:
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
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

        assert resp.status_code == 200
        body = resp.json()
        assert len(body["permissions"]) == 4

    async def test_get_critical_permissions_default_state_all_deny(self) -> None:
        """All entries have state='deny' and pending_at=None by default."""
        app = _make_app()
        _clear_critical_state()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

        for entry in resp.json()["permissions"]:
            assert entry["state"] == "deny"
            assert entry["pending_at"] is None

    async def test_get_critical_permissions_entry_structure(self) -> None:
        """Each entry has tool, action, state, and pending_at keys."""
        app = _make_app()
        _clear_critical_state()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

        pairs = {(e["tool"], e["action"]) for e in resp.json()["permissions"]}
        assert pairs == set(_PROMOTABLE_PAIRS)

    async def test_get_critical_permissions_requires_auth(self) -> None:
        """GET without Authorization header returns 401."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/critical-permissions")
        assert resp.status_code == 401

    async def test_get_critical_permissions_wrong_token_returns_401(self) -> None:
        """GET with incorrect token returns 401."""
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

            entries = resp.json()["permissions"]
            gmail_send = next(e for e in entries if e["tool"] == "gmail" and e["action"] == "send")
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
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

            entries = resp.json()["permissions"]
            gmail_send = next(e for e in entries if e["tool"] == "gmail" and e["action"] == "send")
            assert gmail_send["state"] == "confirm"
        finally:
            _clear_critical_state()

    async def test_get_critical_permissions_resolves_expired_cooldown(self) -> None:
        """Expired cooldown (>5 min) is lazily resolved to state='confirm'."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        # Set pending_at to 6 minutes ago to simulate expired cooldown
        server._pending_promotions[("gmail", "send")] = datetime.now(UTC) - timedelta(minutes=6)
        mock_update = AsyncMock()

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as c:
                    resp = await c.get("/api/critical-permissions", headers=_AUTH_HEADER)

            entries = resp.json()["permissions"]
            gmail_send = next(e for e in entries if e["tool"] == "gmail" and e["action"] == "send")
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
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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
                patch("admino.config.load_permissions_config_from_db", mock_load_config),
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
                patch("admino.config.load_permissions_config_from_db", mock_load_config),
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
                patch("admino.config.load_permissions_config_from_db", mock_load_config),
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
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                "/api/critical-permissions/gmail/send/pending",
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 404

    async def test_cancel_unknown_permission_returns_404(self) -> None:
        """DELETE on non-promotable pair returns 404."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                "/api/critical-permissions/gmail/delete/pending",
                headers=_AUTH_HEADER,
            )
        assert resp.status_code == 404

    async def test_cancel_requires_auth(self) -> None:
        """DELETE without Authorization header returns 401."""
        app = _make_app()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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
    async def test_promote_with_invalid_tool_identifier_returns_422(self, tool: str) -> None:
        """PATCH with invalid tool identifier returns 422."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
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

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.patch(
                "/api/critical-permissions/gmail/delete",
                headers=_AUTH_HEADER,
                json={"bearer_token": _TEST_TOKEN},
            )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Bug-fix regression: _resolve_pending_promotions called on POST /api/message
# ---------------------------------------------------------------------------


class TestPostMessageResolvesPromotions:
    """POST /api/message must call _resolve_pending_promotions so expired
    cooldowns are resolved before the agent processes the request."""

    pytestmark = pytest.mark.asyncio

    async def test_post_message_resolves_expired_cooldown(self) -> None:
        """An expired pending promotion is resolved when POST /api/message fires."""
        from admino import server
        from admino.models import AgentResult, LLMMessage

        result = AgentResult(
            status="final",
            response="ok",
            history=[
                LLMMessage(role="user", content="hi"),
                LLMMessage(role="assistant", content="ok"),
            ],
            tool_calls=[],
            pending_confirmation=None,
        )

        agent = MagicMock()
        agent.run = AsyncMock(return_value=result)
        agent._promoted = frozenset()
        agent._tools_enabled = {}

        app = _make_app(agent=agent)
        _clear_critical_state()

        # Set a pending promotion that expired 6 minutes ago.
        server._pending_promotions[("gmail", "send")] = datetime.now(UTC) - timedelta(minutes=6)
        mock_update = AsyncMock()

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as c:
                    resp = await c.post(
                        "/api/message",
                        headers=_AUTH_HEADER,
                        json={"message": "hello", "session_id": "sess-1"},
                    )

            assert resp.status_code == 200
            assert ("gmail", "send") in server._promoted_permissions
            assert ("gmail", "send") not in server._pending_promotions
            # Agent's _promoted field should also be updated.
            assert ("gmail", "send") in agent._promoted
            mock_update.assert_called_once()
        finally:
            _clear_critical_state()

    async def test_post_message_no_resolution_when_cooldown_not_expired(self) -> None:
        """A pending promotion whose cooldown has NOT expired stays pending."""
        from admino import server
        from admino.models import AgentResult, LLMMessage

        result = AgentResult(
            status="final",
            response="ok",
            history=[
                LLMMessage(role="user", content="hi"),
                LLMMessage(role="assistant", content="ok"),
            ],
            tool_calls=[],
            pending_confirmation=None,
        )

        agent = MagicMock()
        agent.run = AsyncMock(return_value=result)
        agent._promoted = frozenset()
        agent._tools_enabled = {}

        app = _make_app(agent=agent)
        _clear_critical_state()

        # Set a pending promotion that is only 1 minute old (not expired).
        server._pending_promotions[("gmail", "send")] = datetime.now(UTC) - timedelta(minutes=1)

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", AsyncMock()),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as c:
                    resp = await c.post(
                        "/api/message",
                        headers=_AUTH_HEADER,
                        json={"message": "hello", "session_id": "sess-2"},
                    )

            assert resp.status_code == 200
            # Still pending — not yet promoted.
            assert ("gmail", "send") in server._pending_promotions
            assert ("gmail", "send") not in server._promoted_permissions
        finally:
            _clear_critical_state()

    async def test_post_message_promotes_multiple_expired_cooldowns(self) -> None:
        """Multiple expired cooldowns are all resolved in a single request."""
        from admino import server
        from admino.models import AgentResult, LLMMessage

        result = AgentResult(
            status="final",
            response="ok",
            history=[
                LLMMessage(role="user", content="hi"),
                LLMMessage(role="assistant", content="ok"),
            ],
            tool_calls=[],
            pending_confirmation=None,
        )

        agent = MagicMock()
        agent.run = AsyncMock(return_value=result)
        agent._promoted = frozenset()
        agent._tools_enabled = {}

        app = _make_app(agent=agent)
        _clear_critical_state()

        expired_time = datetime.now(UTC) - timedelta(minutes=6)
        server._pending_promotions[("gmail", "send")] = expired_time
        server._pending_promotions[("outlook", "send")] = expired_time
        mock_update = AsyncMock()

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as c:
                    resp = await c.post(
                        "/api/message",
                        headers=_AUTH_HEADER,
                        json={"message": "hello", "session_id": "sess-3"},
                    )

            assert resp.status_code == 200
            assert ("gmail", "send") in server._promoted_permissions
            assert ("outlook", "send") in server._promoted_permissions
            assert mock_update.call_count == 2
        finally:
            _clear_critical_state()


# ---------------------------------------------------------------------------
# Bug-fix regression: _promoted_permissions loaded from DB on startup
# ---------------------------------------------------------------------------


class TestLifespanLoadsPromotedPermissions:
    """The lifespan startup must load previously-promoted permissions from the
    database so that tier-2 promotions survive server restarts."""

    pytestmark = pytest.mark.asyncio

    async def test_lifespan_loads_promoted_permission_from_db(self) -> None:
        """When the DB has gmail.send as 'confirm', lifespan populates the
        _promoted_permissions set and the agent's _promoted field."""
        from admino import server
        from admino.server import _lifespan

        agent = MagicMock()
        agent._promoted = frozenset()
        agent._tools_enabled = {}

        app = _make_app(agent=agent)
        _clear_critical_state()

        # Mock DB to return gmail.send as promoted.
        db_perms: dict[str, dict[str, str]] = {
            "gmail": {"send": "confirm"},
        }
        mock_load_perms = AsyncMock(return_value=db_perms)
        mock_load_settings = AsyncMock(return_value={})
        mock_init = AsyncMock()
        mock_close = AsyncMock()

        try:
            with (
                patch("admino.database.init_pool", mock_init),
                patch("admino.database.close_pool", mock_close),
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.load_permissions_from_db", mock_load_perms),
                patch("admino.database.load_settings_from_db", mock_load_settings),
            ):
                # Drive the lifespan context manager directly.
                async with _lifespan(app):
                    assert ("gmail", "send") in server._promoted_permissions
                    assert ("gmail", "send") in agent._promoted
        finally:
            _clear_critical_state()

    async def test_lifespan_ignores_non_promotable_permissions_from_db(self) -> None:
        """Only PROMOTABLE_DENIALS pairs are loaded; other DB rows are ignored."""
        from admino import server
        from admino.server import _lifespan

        agent = MagicMock()
        agent._promoted = frozenset()
        agent._tools_enabled = {}

        app = _make_app(agent=agent)
        _clear_critical_state()

        # gmail.delete is an immutable denial, not promotable — must be ignored.
        db_perms: dict[str, dict[str, str]] = {
            "gmail": {"send": "confirm", "delete": "confirm"},
        }
        mock_load_perms = AsyncMock(return_value=db_perms)
        mock_load_settings = AsyncMock(return_value={})
        mock_init = AsyncMock()
        mock_close = AsyncMock()

        try:
            with (
                patch("admino.database.init_pool", mock_init),
                patch("admino.database.close_pool", mock_close),
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.load_permissions_from_db", mock_load_perms),
                patch("admino.database.load_settings_from_db", mock_load_settings),
            ):
                async with _lifespan(app):
                    # gmail.send is promotable — should be loaded.
                    assert ("gmail", "send") in server._promoted_permissions
                    # gmail.delete is NOT promotable — must not appear.
                    assert ("gmail", "delete") not in server._promoted_permissions
        finally:
            _clear_critical_state()


# ---------------------------------------------------------------------------
# Bug-fix regression: session notification on promotion resolution
# ---------------------------------------------------------------------------


class TestPromotionSessionNotification:
    """When _resolve_pending_promotions() resolves expired cooldowns, a
    notification message must be injected into every active session in
    _sessions so the LLM knows the permission changed and won't refuse based
    on stale denials.

    GH-66: the notification must use a non-system role so it survives the
    agent's ``_filter_mid_system`` prompt-injection defence, which drops every
    mid-conversation ``system``-role message. A ``system``-role notification
    would be silently discarded before reaching the LLM.
    """

    pytestmark = pytest.mark.asyncio

    async def test_resolve_promotions_injects_notification_into_sessions(
        self,
    ) -> None:
        """Expired cooldown resolution appends a notification LLMMessage to all sessions."""
        from admino import server
        from admino.models import LLMMessage
        from admino.server import _resolve_pending_promotions

        _clear_critical_state()

        # Populate two active sessions with some existing history.
        sess1_history: list[LLMMessage] = [
            LLMMessage(role="user", content="hello"),
        ]
        sess2_history: list[LLMMessage] = [
            LLMMessage(role="user", content="send an email"),
            LLMMessage(role="assistant", content="I cannot do that yet."),
        ]
        server._sessions["sess-a"] = sess1_history
        server._sessions["sess-b"] = sess2_history

        # Set an expired pending promotion (6 minutes ago).
        server._pending_promotions[("gmail", "send")] = datetime.now(UTC) - timedelta(minutes=6)

        mock_update = AsyncMock()
        agent_mock = MagicMock()
        agent_mock._promoted = frozenset()
        server._agent = agent_mock

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
            ):
                await _resolve_pending_promotions()

            # Both sessions should have gained exactly one new message.
            assert len(sess1_history) == 2
            assert len(sess2_history) == 3

            injected_1 = sess1_history[-1]
            injected_2 = sess2_history[-1]

            # GH-66: must NOT be a system message — those are dropped mid-conversation
            # by the agent's prompt-injection filter, silently discarding the notice.
            assert injected_1.role != "system"
            assert injected_2.role != "system"
            assert "gmail.send" in injected_1.content
            assert "gmail.send" in injected_2.content
        finally:
            server._sessions.clear()
            server._agent = None
            _clear_critical_state()

    async def test_promotion_notification_survives_filter_mid_system(self) -> None:
        """GH-66 end-to-end: the injected notification must survive _trim_context.

        ``_trim_context`` runs ``_filter_mid_system`` over the non-leading
        history, which drops every mid-conversation ``system``-role message.
        The promotion notification must reach the LLM, so it must still be
        present after trimming.
        """
        from admino import server
        from admino.agent import _trim_context
        from admino.models import LLMMessage
        from admino.server import _resolve_pending_promotions

        _clear_critical_state()

        history: list[LLMMessage] = [
            LLMMessage(role="system", content="leading system prompt"),
            LLMMessage(role="user", content="send an email"),
            LLMMessage(role="assistant", content="I cannot do that yet."),
        ]
        server._sessions["sess-e2e"] = history

        server._pending_promotions[("gmail", "send")] = datetime.now(UTC) - timedelta(minutes=6)

        mock_update = AsyncMock()
        agent_mock = MagicMock()
        agent_mock._promoted = frozenset()
        server._agent = agent_mock

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
            ):
                await _resolve_pending_promotions()

            trimmed = _trim_context(history, max_messages=40)

            # The notification mentioning gmail.send must survive the filter.
            assert any("gmail.send" in m.content for m in trimmed)
        finally:
            server._sessions.clear()
            server._agent = None
            _clear_critical_state()

    async def test_resolve_promotions_no_injection_when_no_expired(self) -> None:
        """When no pending promotions have expired, sessions remain unchanged."""
        from admino import server
        from admino.models import LLMMessage
        from admino.server import _resolve_pending_promotions

        _clear_critical_state()

        # Populate a session.
        sess_history: list[LLMMessage] = [
            LLMMessage(role="user", content="hello"),
        ]
        server._sessions["sess-x"] = sess_history

        # Set a pending promotion only 1 minute old (not expired).
        server._pending_promotions[("gmail", "send")] = datetime.now(UTC) - timedelta(minutes=1)

        try:
            await _resolve_pending_promotions()

            # Session should be untouched — still just the one user message.
            assert len(sess_history) == 1
            assert sess_history[0].role == "user"
        finally:
            server._sessions.clear()
            _clear_critical_state()


# ---------------------------------------------------------------------------
# Bug-fix regression: system prompt includes dynamic permission guidance
# ---------------------------------------------------------------------------


class TestSystemPromptDynamicPermissionGuidance:
    """The system prompt built by _build_system_prompt() must tell the LLM
    that permissions can change during a conversation so it doesn't refuse
    tool calls based on stale denial messages in the history."""

    pytestmark = pytest.mark.asyncio

    async def test_system_prompt_includes_dynamic_permission_guidance(self) -> None:
        """System prompt contains guidance about permissions changing mid-conversation."""
        import os

        from admino.config import AppConfig
        from admino.main import _build_system_prompt
        from admino.tools.registry import ToolDescription

        # AppConfig requires AUTH_TOKEN >= 48 chars with >= 20 unique chars.
        fake_token = _TEST_TOKEN
        fake_tool = ToolDescription(
            tool="gmail",
            action="send",
            description="Send an email.",
            parameters_schema={"type": "object", "properties": {}},
        )

        with (
            patch.dict(os.environ, {"AUTH_TOKEN": fake_token}),
            patch(
                "admino.tools.registry.get_registered_tools",
                return_value=[fake_tool],
            ),
        ):
            config = AppConfig()
            prompt = _build_system_prompt(config)

        assert "permissions can change during a conversation" in prompt.lower()
        assert "never refuse based on earlier" in prompt.lower()
