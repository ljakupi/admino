"""Tests for the Critical Permissions API (tier-2 promotable denials).

Covers:
- GET /api/critical-permissions: returns 4 promotable permissions with state
- PATCH /api/critical-permissions/{tool}/{action}:
  - GH-149 (decision 1): promotions are disabled until #161 brings password
    re-auth. PATCH on a promotable permission that is NOT currently promoted
    answers 403 ``{"detail": "Critical permission promotions are temporarily
    unavailable."}`` and starts no cooldown. The ``bearer_token`` request body
    (``CriticalPermissionPromote``) is gone.
  - demote (PATCH on a promoted permission) keeps working, with no body
- DELETE /api/critical-permissions/{tool}/{action}/pending: cancel cooldown
- Session enforcement on all endpoints (401 without a valid session cookie)
- Rate limiting on promotion attempts (429 after burst, per caller)
- Lazy cooldown resolution (pending -> confirm after 5 min)
- Adversarial inputs: invalid tool names, immutable denials, unknown pairs

Security notes:
- All tests use mocked database -- no real DB or API calls.
- Callers are logged in with tests.auth_helpers (an Org Admin by default); the
  session token is a known fake value, never a real secret.
- Only 4 defined promotable pairs are accepted; all others return 404.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from admino.server import create_app
from tests.auth_helpers import login, member_session, resolved_session, session_cookie

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UNAUTHORIZED = {"detail": "Unauthorized"}
_PROMOTIONS_UNAVAILABLE = {"detail": "Critical permission promotions are temporarily unavailable."}

_PROMOTABLE_PAIRS: list[tuple[str, str]] = [
    ("gmail", "send"),
    ("outlook", "send"),
    ("google_calendar", "update"),
    ("outlook_calendar", "update"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> MagicMock:
    """Build a minimal mock AppConfig (no ``auth`` section: GH-149 removed it)."""
    config = MagicMock()
    del config.auth
    config.limits.max_message_length = 4000
    config.server.host = "0.0.0.0"  # noqa: S104
    config.server.port = 8000
    return config


def _make_app(agent: Any = None, *, anonymous: bool = False) -> Any:
    """Create a FastAPI app with mock agent and config; log an Org Admin in unless anonymous."""
    if agent is None:
        agent = MagicMock()
    app = create_app(agent=agent, config=_make_config())
    if not anonymous:
        login(app, member_session("org_admin"))
    return app


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
            resp = await c.get("/api/critical-permissions")

        assert resp.status_code == 200
        body = resp.json()
        assert len(body["permissions"]) == 4

    async def test_get_critical_permissions_default_state_all_deny(self) -> None:
        """All entries have state='deny' and pending_at=None by default."""
        app = _make_app()
        _clear_critical_state()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/critical-permissions")

        for entry in resp.json()["permissions"]:
            assert entry["state"] == "deny"
            assert entry["pending_at"] is None

    async def test_get_critical_permissions_entry_structure(self) -> None:
        """Each entry has tool, action, state, and pending_at keys."""
        app = _make_app()
        _clear_critical_state()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/critical-permissions")

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
            resp = await c.get("/api/critical-permissions")

        pairs = {(e["tool"], e["action"]) for e in resp.json()["permissions"]}
        assert pairs == set(_PROMOTABLE_PAIRS)

    async def test_get_critical_permissions_requires_auth(self) -> None:
        """GET without a session cookie returns 401."""
        app = _make_app(anonymous=True)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/critical-permissions")
        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    async def test_get_critical_permissions_unknown_session_returns_401(self) -> None:
        """GET with a cookie that resolves to no session returns 401."""
        app = _make_app(anonymous=True)
        with resolved_session(None):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/critical-permissions", headers=session_cookie())
        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    async def test_get_critical_permissions_shows_pending_promotion(self) -> None:
        """After setting a pending promotion, GET shows pending_at timestamp."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        now = datetime.now(UTC)
        server._pending_promotions[("gmail", "send")] = now

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get("/api/critical-permissions")

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
                resp = await c.get("/api/critical-permissions")

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
                    resp = await c.get("/api/critical-permissions")

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
    """PATCH /api/critical-permissions/{tool}/{action} -- promotion is disabled (GH-149).

    Until #161 adds password re-auth, a PATCH on a promotable permission that is
    not currently promoted answers 403 and starts no cooldown.
    """

    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize(("tool", "action"), _PROMOTABLE_PAIRS)
    async def test_promote_returns_403_temporarily_unavailable(
        self, tool: str, action: str
    ) -> None:
        """PATCH on a non-promoted promotable permission -> 403 with the fixed message."""
        app = _make_app()
        _clear_critical_state()

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(f"/api/critical-permissions/{tool}/{action}")

            assert resp.status_code == 403
            assert resp.json() == _PROMOTIONS_UNAVAILABLE
        finally:
            _clear_critical_state()

    async def test_promote_starts_no_cooldown(self) -> None:
        """A refused promotion leaves no pending cooldown behind."""
        from admino import server

        app = _make_app()
        _clear_critical_state()

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                await c.patch("/api/critical-permissions/gmail/send")
                listing = await c.get("/api/critical-permissions")

            assert server._pending_promotions == {}
            assert server._promoted_permissions == set()
            gmail_send = next(
                e
                for e in listing.json()["permissions"]
                if (e["tool"], e["action"]) == ("gmail", "send")
            )
            assert (gmail_send["state"], gmail_send["pending_at"]) == ("deny", None)
        finally:
            _clear_critical_state()

    async def test_promote_does_not_touch_the_database(self) -> None:
        """A refused promotion writes nothing."""
        app = _make_app()
        _clear_critical_state()
        mock_update = AsyncMock()

        try:
            with (
                patch("admino.database.get_pool", _mock_get_pool()),
                patch("admino.database.update_permission", mock_update),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as c:
                    resp = await c.patch("/api/critical-permissions/gmail/send")

            assert resp.status_code == 403
            mock_update.assert_not_awaited()
        finally:
            _clear_critical_state()

    async def test_promote_legacy_bearer_token_body_still_refused(self) -> None:
        """The removed re-auth body no longer unlocks anything: still 403, no cooldown."""
        from admino import server

        app = _make_app()
        _clear_critical_state()

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch(
                    "/api/critical-permissions/gmail/send",
                    json={"bearer_token": "a" * 48 + "BcDeFgHiJkLmNoPqRsTuVwXyZ"},
                )

            assert resp.status_code == 403
            assert resp.json() == _PROMOTIONS_UNAVAILABLE
            assert server._pending_promotions == {}
        finally:
            _clear_critical_state()

    async def test_promote_already_pending_returns_403_and_keeps_pending(self) -> None:
        """A cooldown started before GH-149 is not promoted; PATCH is refused and leaves it."""
        from admino import server

        app = _make_app()
        _clear_critical_state()
        pending_at = datetime.now(UTC) - timedelta(minutes=1)
        server._pending_promotions[("gmail", "send")] = pending_at

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch("/api/critical-permissions/gmail/send")

            assert resp.status_code == 403
            assert resp.json() == _PROMOTIONS_UNAVAILABLE
            assert server._pending_promotions == {("gmail", "send"): pending_at}
        finally:
            _clear_critical_state()

    async def test_promote_requires_auth(self) -> None:
        """PATCH without a session cookie returns 401 (authentication comes first)."""
        app = _make_app(anonymous=True)
        _clear_critical_state()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.patch("/api/critical-permissions/gmail/send")
        assert resp.status_code == 401
        assert resp.json() == _UNAUTHORIZED

    async def test_models_critical_permission_promote_removed(self) -> None:
        """The bearer_token request model is gone (replaced by password re-auth in #161)."""
        from admino import models

        assert not hasattr(models, "CriticalPermissionPromote")

    async def test_promote_unknown_permission_returns_404(self) -> None:
        """PATCH on non-promotable pair (gmail/delete) returns 404."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.patch("/api/critical-permissions/gmail/delete")
        assert resp.status_code == 404

    async def test_promote_rate_limited(self) -> None:
        """6th rapid promotion request returns 429 (the first five are refused with 403)."""
        app = _make_app()
        _clear_critical_state()

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                statuses = []
                for _ in range(6):
                    resp = await c.patch("/api/critical-permissions/gmail/send")
                    statuses.append(resp.status_code)

            # First 5 are refused (promotions disabled), 6th is rate-limited
            assert statuses[0] == 403
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

    async def test_demote_requires_auth(self) -> None:
        """Demoting also needs a session: no cookie -> 401 and the promotion stays."""
        from admino import server

        app = _make_app(anonymous=True)
        _clear_critical_state()
        server._promoted_permissions.add(("gmail", "send"))

        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.patch("/api/critical-permissions/gmail/send")

            assert resp.status_code == 401
            assert ("gmail", "send") in server._promoted_permissions
        finally:
            _clear_critical_state()

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
                    )

            assert resp.status_code == 200
            assert resp.json()["state"] == "deny"
            assert ("gmail", "send") not in server._pending_promotions
            assert ("gmail", "send") not in server._promoted_permissions
        finally:
            _clear_critical_state()

    async def test_demote_needs_no_request_body(self) -> None:
        """Demoting a promoted permission succeeds with no request body."""
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
            )
        assert resp.status_code == 404

    async def test_cancel_unknown_permission_returns_404(self) -> None:
        """DELETE on non-promotable pair returns 404."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(
                "/api/critical-permissions/gmail/delete/pending",
            )
        assert resp.status_code == 404

    async def test_cancel_requires_auth(self) -> None:
        """DELETE without a session cookie returns 401."""
        app = _make_app(anonymous=True)

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
            resp = await c.patch(f"/api/critical-permissions/{tool}/send")
        # Invalid tool identifiers should be rejected (404 for non-promotable
        # or 422 for validation failure -- either is acceptable)
        assert resp.status_code in (404, 422)

    async def test_promote_immutable_denial_returns_404(self) -> None:
        """PATCH on tier-1 immutable denial (gmail/delete) returns 404."""
        app = _make_app()
        _clear_critical_state()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.patch("/api/critical-permissions/gmail/delete")
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
        from admino.config import AppConfig, LLMConfig
        from admino.main import _build_system_prompt
        from admino.tools.registry import ToolDescription

        fake_tool = ToolDescription(
            tool="gmail",
            action="send",
            description="Send an email.",
            parameters_schema={"type": "object", "properties": {}},
        )

        with patch(
            "admino.tools.registry.get_registered_tools",
            return_value=[fake_tool],
        ):
            config = AppConfig(
                llm=LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
            )
            prompt = _build_system_prompt(config)

        assert "permissions can change during a conversation" in prompt.lower()
        assert "never refuse based on earlier" in prompt.lower()

    async def test_system_prompt_includes_no_substitution_guardrail(self) -> None:
        """System prompt forbids substituting a different tool when one is unavailable.

        GH-77 defence-in-depth: the prompt must instruct the LLM never to
        substitute a different action (e.g. create instead of update) when the
        requested tool is not available. The existing dynamic-permission
        guidance must remain alongside this new guardrail.
        """
        from admino.config import AppConfig, LLMConfig
        from admino.main import _build_system_prompt
        from admino.tools.registry import ToolDescription

        fake_tool = ToolDescription(
            tool="google_calendar",
            action="read",
            description="Read events.",
            parameters_schema={"type": "object", "properties": {}},
        )

        with patch(
            "admino.tools.registry.get_registered_tools",
            return_value=[fake_tool],
        ):
            config = AppConfig(
                llm=LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
            )
            prompt = _build_system_prompt(config)

        lowered = prompt.lower()
        assert "never substitute" in lowered
        assert "not available" in lowered or "isn't available" in lowered
        # The pre-existing dynamic-permission guidance must remain.
        assert "permissions can change during a conversation" in lowered

    async def test_system_prompt_tool_summary_excludes_denied_actions(self) -> None:
        """The tool summary must not advertise permission-denied actions.

        GH-77 security follow-up: when a permissions config is supplied, the
        summary in the system prompt is filtered through the permission engine
        so it matches the per-turn tool payload. A hardcoded-denied action
        (``gmail.delete``) must never appear as available, while an allowed
        sibling (``gmail.read``) must.
        """
        from pydantic import BaseModel, Field

        from admino.config import AppConfig, LLMConfig
        from admino.main import _build_system_prompt
        from admino.permissions import PermissionsConfig, ToolPermissions
        from admino.tools.registry import clear_registry, register_tool

        class _Args(BaseModel):
            q: str = Field(min_length=1, max_length=10)

        async def _handler(args: _Args, *, session_id: str) -> str:
            return "ok"

        clear_registry()
        try:
            register_tool("gmail", "read", "Read mail", _Args)(_handler)
            register_tool("gmail", "delete", "Delete mail", _Args)(_handler)
            permissions = PermissionsConfig(
                tools={"gmail": ToolPermissions(actions={"read": "allow"})}
            )
            config = AppConfig(
                llm=LLMConfig(provider="anthropic", anthropic_model="claude-sonnet-4-6")
            )
            prompt = _build_system_prompt(config, permissions)
        finally:
            clear_registry()

        assert "read" in prompt
        assert "delete" not in prompt
