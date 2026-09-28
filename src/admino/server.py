"""FastAPI web server for admino — the HTTP/SSE boundary layer.

Exposes the REST API and SSE streaming endpoint that clients interact with.
All user input enters through this module and all responses leave through it.
The server is a thin HTTP layer that delegates business logic to the agent.

Routes:
- POST /api/auth/login    — Email/password login; sets the session cookie (public).
- POST /api/auth/password-reset — Emails a password reset link; always 202 (public).
- POST /api/auth/password-reset/confirm — Sets a new password with a reset link's
  token, ends every session of the account, clears the cookie (public).
- POST /api/auth/logout   — Ends (deletes) the current session and clears the cookie.
- GET  /api/auth/me       — The logged-in account (from the resolved session).
- GET  /api/me/sessions   — The caller's live sessions, the current one marked.
- DELETE /api/me/sessions/{session_id} — Ends one of the caller's sessions
  (clears the cookie when it is the current one); audited.
- POST /api/org/users/{user_id}/logout — An Org Admin ends every session of a
  user of their org; audited.
- POST /api/message       — Send a user message; returns ChatResponse.
- GET  /api/events        — SSE stream for a chat session.
- POST /api/confirm/{cid} — Approve or deny a pending confirmation.
- /api/settings, /api/permissions, /api/critical-permissions, /api/oauth/* —
  settings, permissions and account connections.
- GET  /health            — Health check (public).
- GET  /api/oauth/callback — The OAuth provider's redirect (public, state-checked).
- /                       — Static PWA files (public).

Security notes:
- Authentication is a server-side session (GH-149): the ``admino_session``
  cookie (HttpOnly, SameSite=Strict, Path=/, Secure unless
  ``server.cookie_secure`` is off) carries an opaque token that
  ``sessions.resolve_session`` checks against the database on every request,
  re-reading the account, so a deactivated user or org is refused at once.
  A session ends after its idle timeout or at the end of its lifetime (its
  policy, GH-152); the cookie's Max-Age is that lifetime. Ending a session
  deletes its row, so the cookie is refused on its next request.
  Every route except the public ones above depends on ``require_session``; the
  ``Principal`` always comes from the session row, never from request data.
  There is no bearer-token or VPN mode, and ``Authorization`` headers
  authenticate nothing.
- The chat routes also need ``Capability.CHAT_SEND`` (403 for a Viewer or a
  Super Admin); the principal is passed to ``agent.run``.
- Session management: ``/api/me/sessions`` needs ``Capability.ACCOUNT_MANAGE``
  and only ever reads or deletes the caller's own sessions; a forced logout
  needs ``Capability.ORG_USERS_MANAGE`` and only reaches users of the Org
  Admin's own org. Another user's session, or a user outside the org, is the
  same 404 as an unknown id. Path ids are typed as UUIDs: anything else is a
  422 that doesn't include the input value.
- CSRF: ``CrossOriginProtectionMiddleware`` implements Go's
  CrossOriginProtection check on every non-GET/HEAD/OPTIONS request, before
  authentication and handlers (the login included): ``Sec-Fetch-Site`` must be
  ``same-origin``/``none``; without it, an ``Origin`` must match ``Host``.
  Refusals are 403 ``{"detail": "Cross-origin request refused"}``.
- Login failures are one generic 401 for every cause (no user enumeration);
  the email, password and session token are never logged or echoed.
- A password reset request answers the same empty 202 for every email, before
  any account work: the service runs as a background task after the response,
  so neither the body nor the timing tells whether the account exists. Reset
  links are built from ``server.public_url`` only, never from the request's
  Host or X-Forwarded-* headers. A failed confirm is one generic 400 for every
  link that can't be used; the email, token, link and password are never
  logged or echoed.
- Rate limits are per caller: one token bucket per (route, ``user:<id>``) on
  session routes and per (route, ``ip:<host>``) on public routes, so one caller
  can't throttle another. Idle buckets are evicted and the map is capped (LRU).
  Cookies that resolve to no session spend a per-IP budget, so a stream of
  random cookies is refused (429) before it costs database lookups.
- No raw user content, assistant text, or tool args logged at INFO or below.
- Error responses use generic messages; never leak internal paths or config.
- CORS restricted to localhost origins by default; no credentials, and only
  ``Content-Type`` as an allowed request header. ``/openapi.json``, Swagger UI
  and ReDoc are disabled.
- HSTS is not set (plain HTTP local deployment). When deploying behind a
  TLS-terminating reverse proxy, configure HSTS at the proxy layer.
- Does NOT import check_permission — permission decisions live in agent/registry.
- Does NOT import from permissions.py except PermissionsConfig type (via TYPE_CHECKING).

Deployment note:
- This module uses module-level dicts (_sessions, _pending_confirmations,
  _rate_buckets) for in-memory state. This requires a **single-worker** ASGI
  deployment. Running multiple workers (e.g. uvicorn --workers 2) will silently
  split state across processes. Use ``--workers 1`` (the default).

Chat session ID note:
- Chat session IDs are client-provided until #176 and validated by Pydantic
  (alphanumeric, hyphens, underscores, max 64 chars).
  In-memory chat state is keyed by ``_chat_key(user_id, session_id)``, so a
  user reusing another user's session_id sees an empty history and can neither
  confirm nor cancel the other user's pending tool call.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path as PathLib
from typing import TYPE_CHECKING, Annotated, Any, Final
from urllib.parse import urlsplit
from uuid import UUID  # noqa: TC003 — FastAPI resolves path parameter annotations at runtime

import httpx
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from pydantic import ValidationError
from starlette.background import BackgroundTask
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware

from admino import accounts, auth, password_reset, passwords, session_management, sessions
from admino.access import Capability, Principal, can
from admino.models import (
    AgentResult,
    ChatRequest,
    ChatResponse,
    ConfirmRequest,
    CriticalPermissionEntry,
    CriticalPermissionsResponse,
    CriticalPermissionState,
    LLMMessage,
    LoginRequest,
    MeResponse,
    OAuthAuthorizeResponse,
    OAuthConnectionStatus,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    PendingConfirmation,
    PendingConfirmationSummary,
    PermissionEntry,
    PermissionPatch,
    PermissionsResponse,
    SessionListResponse,
    SettingsAppearance,
    SettingsConnectedAccounts,
    SettingsImmutable,
    SettingsLimits,
    SettingsLLM,
    SettingsNotifications,
    SettingsPatch,
    SettingsResponse,
    SSEEvent,
    ToolsSettings,
)
from admino.oauth import (
    OAuthError,
    OAuthProvider,
    OAuthToken,
    build_google_consent_url,
    build_microsoft_consent_url,
    encrypt_refresh_token,
    exchange_google_code,
    exchange_microsoft_code,
    get_connection_status,
    get_google_user_email,
    revoke_and_delete_token,
    save_token,
)
from admino.tools.gmail import clear_token_cache as _clear_gmail_cache
from admino.tools.google_calendar import clear_token_cache as _clear_gcal_cache
from admino.tools.google_drive import clear_token_cache as _clear_gdrive_cache
from admino.tools.onedrive import clear_token_cache as _clear_onedrive_cache
from admino.tools.outlook import clear_token_cache as _clear_outlook_cache
from admino.tools.outlook_calendar import clear_token_cache as _clear_outcal_cache

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from starlette.types import ASGIApp, Receive, Scope, Send

    from admino.agent import Agent
    from admino.config import AppConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects security response headers on every HTTP response.

    Mitigates XSS (CSP), clickjacking (X-Frame-Options), MIME-sniffing
    (X-Content-Type-Options), and information leakage (Referrer-Policy,
    Permissions-Policy). Applied even for local-only deployments because
    the PWA runs in a browser that respects these headers.

    Note: ``Strict-Transport-Security`` (HSTS) is intentionally omitted.
    This app serves over plain HTTP for local deployment. When deployed
    behind a TLS-terminating reverse proxy (nginx, Caddy), HSTS must be
    configured at the proxy layer — not here.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Add security headers to every response."""
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
            "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        return response


# ---------------------------------------------------------------------------
# CSRF: cross-origin protection
# ---------------------------------------------------------------------------

# Methods that never change state: exempt from the cross-origin check.
_SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})
# Sec-Fetch-Site values a browser sends for a same-origin or user-initiated request.
_SAME_ORIGIN_FETCH_SITES: Final = frozenset({"same-origin", "none"})
_CSRF_REFUSED_DETAIL: Final = "Cross-origin request refused"


def _is_cross_origin_request(method: str, headers: Headers) -> bool:
    """Return True when a request must be refused as cross-origin (CSRF).

    Go 1.25 ``CrossOriginProtection`` algorithm:
    1. GET, HEAD and OPTIONS are safe by method and always pass.
    2. If ``Sec-Fetch-Site`` is present, only ``same-origin`` and ``none``
       (a user-initiated navigation) pass; any other value is refused.
    3. Otherwise, if ``Origin`` is present, it passes only when its
       host[:port] equals the ``Host`` header (the scheme is ignored: TLS
       terminates at the proxy). ``Origin: null`` or a malformed origin is refused.
    4. With neither header the request doesn't come from a browser and passes;
       the SameSite=Strict session cookie covers older browsers.

    Args:
        method: The HTTP request method.
        headers: The request headers.

    Returns:
        True if the request is cross-origin and must be refused.
    """
    if method.upper() in _SAFE_METHODS:
        return False
    fetch_site = headers.get("sec-fetch-site")
    if fetch_site is not None:
        return fetch_site.strip().lower() not in _SAME_ORIGIN_FETCH_SITES
    origin = headers.get("origin")
    if origin is None:
        return False
    try:
        origin_host = urlsplit(origin.strip()).netloc
    except ValueError:
        return True
    host = headers.get("host", "")
    return not origin_host or origin_host.lower() != host.strip().lower()


class CrossOriginProtectionMiddleware:
    """Refuses cross-origin state-changing requests before routing (CSRF defence).

    A pure ASGI middleware, so the refusal happens before authentication,
    rate limiting and handlers run, the login included (login CSRF). A refused
    request gets 403 ``{"detail": "Cross-origin request refused"}``; nothing
    from the request is echoed or logged.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Pass the request on, or answer 403 when it is cross-origin."""
        if scope["type"] == "http" and _is_cross_origin_request(
            scope["method"], Headers(scope=scope)
        ):
            response = JSONResponse(status_code=403, content={"detail": _CSRF_REFUSED_DETAIL})
            await response(scope, receive, send)
            return
        await self._app(scope, receive, send)


# ---------------------------------------------------------------------------
# Rate limiter (per route and caller)
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Simple in-process token-bucket rate limiter for one (route, caller).

    Limits requests per second to prevent resource exhaustion (LLM inference,
    memory, Argon2 CPU). Not shared across workers — requires single-worker
    deployment (already required by the in-memory chat state).

    Args:
        rate: Tokens added per second.
        capacity: Maximum burst capacity.
        now: The current ``time.monotonic()`` value.
    """

    __slots__ = ("_capacity", "_rate", "_tokens", "last_used")

    def __init__(self, rate: float, capacity: int, now: float) -> None:
        self._rate = rate
        self._capacity = capacity
        self._tokens = float(capacity)
        self.last_used = now

    def _refill(self, now: float) -> None:
        """Add the tokens earned since the last use, up to the burst capacity."""
        elapsed = max(0.0, now - self.last_used)
        self._tokens = min(float(self._capacity), self._tokens + elapsed * self._rate)
        self.last_used = now

    def allow(self, now: float) -> bool:
        """Refill for the time elapsed, then consume one token if there is one."""
        self._refill(now)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def has_token(self, now: float) -> bool:
        """Refill for the time elapsed and report whether a token is left, consuming none."""
        self._refill(now)
        return self._tokens >= 1.0


# Per-route (tokens per second, burst). Route keys are stable strings, not
# URL paths with parameters. Read when a bucket is created.
_RATE_LIMITS: dict[str, tuple[float, int]] = {
    "/api/message": (0.5, 5),
    "/api/confirm": (0.5, 5),
    "/api/events": (0.17, 3),
    "/api/settings/get": (1.0, 5),
    "/api/settings/patch": (0.2, 2),
    "/api/permissions/get": (1.0, 5),
    "/api/permissions/patch": (0.2, 2),
    "/api/oauth/google/authorize": (0.2, 2),
    "/api/oauth/microsoft/authorize": (0.2, 2),
    "/api/oauth/callback": (0.2, 2),
    "/api/oauth/google/status": (1.0, 5),
    "/api/oauth/microsoft/status": (1.0, 5),
    "/api/oauth/google/disconnect": (0.2, 2),
    "/api/oauth/microsoft/disconnect": (0.2, 2),
    "/api/critical-permissions/get": (1.0, 5),
    "/api/critical-permissions/promote": (5 / 60, 5),
    "/api/critical-permissions/cancel": (0.5, 5),
    "/api/auth/login": (0.2, 5),
    # One reset email per minute per IP after a burst of 3 (limits inbox flooding).
    "/api/auth/password-reset": (1 / 60, 3),
    "/api/auth/password-reset/confirm": (0.2, 5),
    "/api/auth/logout": (0.5, 5),
    "/api/auth/me": (1.0, 10),
    # Cookies that resolve to no session, per client IP (see require_session).
    "/api/auth/session": (1.0, 20),
    # Session management (GH-152), per user.
    "/api/me/sessions/get": (1.0, 10),
    "/api/me/sessions/delete": (0.5, 5),
    "/api/org/users/logout": (0.5, 5),
}
# Routes without their own entry still get a bucket per caller.
_DEFAULT_RATE_LIMIT: tuple[float, int] = (1.0, 10)
# A bucket unused this long has fully refilled, so dropping it loses nothing.
_BUCKET_IDLE_TTL_S: float = 900.0
# Upper bound on the bucket map (least-recently-used buckets are dropped first).
_MAX_RATE_BUCKETS: int = 10_000

# (route, caller) -> bucket, in least-recently-used order. The caller is
# "user:<user_id>" on session routes and "ip:<client host>" on public routes
# and for failed session resolutions.
_rate_buckets: OrderedDict[tuple[str, str], _TokenBucket] = OrderedDict()
# The route key of the per-IP budget for cookies that resolve to no session.
_SESSION_FAILURE_ROUTE: Final = "/api/auth/session"


def _evict_idle_buckets(now: float) -> None:
    """Drop buckets unused for at least ``_BUCKET_IDLE_TTL_S`` seconds.

    ``_rate_buckets`` is kept in least-recently-used order, so the idle
    buckets are at the front.
    """
    while _rate_buckets:
        oldest_key = next(iter(_rate_buckets))
        if now - _rate_buckets[oldest_key].last_used < _BUCKET_IDLE_TTL_S:
            return
        del _rate_buckets[oldest_key]


def _check_rate_limit(route: str, caller: str) -> None:
    """Consume one token from ``caller``'s bucket for ``route``; 429 when empty.

    Each (route, caller) pair has its own bucket, so one user (or IP)
    exhausting a route never throttles another. Routes without an entry in
    ``_RATE_LIMITS`` use ``_DEFAULT_RATE_LIMIT``. Idle buckets are evicted
    and the map never exceeds ``_MAX_RATE_BUCKETS`` entries.

    Args:
        route: The route key (e.g. ``"/api/message"``).
        caller: ``"user:<user_id>"`` or ``"ip:<client host>"``.

    Raises:
        HTTPException: 429 if the caller's bucket is empty.
    """
    now = time.monotonic()
    if not _bucket_for(route, caller, now).allow(now):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def _bucket_for(route: str, caller: str, now: float) -> _TokenBucket:
    """Return (creating it if needed) the bucket of ``(route, caller)``, marked most recent.

    Evicts idle buckets first, and keeps the map within ``_MAX_RATE_BUCKETS``.
    """
    _evict_idle_buckets(now)
    key = (route, caller)
    bucket = _rate_buckets.get(key)
    if bucket is None:
        rate, burst = _RATE_LIMITS.get(route, _DEFAULT_RATE_LIMIT)
        while _rate_buckets and len(_rate_buckets) >= _MAX_RATE_BUCKETS:
            _rate_buckets.popitem(last=False)
        bucket = _TokenBucket(rate, burst, now)
        _rate_buckets[key] = bucket
    else:
        _rate_buckets.move_to_end(key)
    return bucket


def _session_failures_exhausted(caller: str) -> bool:
    """True when ``caller`` has spent its budget of cookies that resolve to no session.

    Only reads the bucket: an IP whose sessions keep resolving never gets one.
    """
    bucket = _rate_buckets.get((_SESSION_FAILURE_ROUTE, caller))
    return bucket is not None and not bucket.has_token(time.monotonic())


def _note_session_failure(caller: str) -> None:
    """Spend one token of ``caller``'s budget for cookies that resolve to no session."""
    now = time.monotonic()
    _bucket_for(_SESSION_FAILURE_ROUTE, caller, now).allow(now)


def _user_caller(principal: Principal) -> str:
    """The rate-limit caller key of a logged-in principal."""
    return f"user:{principal.user_id}"


def _client_ip(request: Request) -> str:
    """The peer address of the request (``"unknown"`` when the server has none)."""
    return request.client.host if request.client is not None else "unknown"


# ---------------------------------------------------------------------------
# Module-level state — set during create_app()
# ---------------------------------------------------------------------------

# Maximum number of concurrent chat sessions before LRU eviction kicks in.
_MAX_SESSIONS: int = 256

# In-memory chat state is keyed by _chat_key(user_id, session_id): the chat
# session id is client-provided (until #176), so keying by it alone would let
# one user read, confirm or cancel another user's chat.

# Conversation history per chat. No persistence across restarts.
# OrderedDict enables O(1) LRU eviction when _MAX_SESSIONS is exceeded.
_sessions: OrderedDict[tuple[UUID, str], list[LLMMessage]] = OrderedDict()

# Pending confirmation per chat — only one at a time. A new confirmation for
# the same chat overwrites the previous one. This prevents confirmation queue
# buildup and simplifies the confirmation UX.
_pending_confirmations: dict[tuple[UUID, str], PendingConfirmation] = {}

# Per-chat asyncio locks to serialise concurrent requests for the same chat.
# Prevents race conditions where two concurrent POST /api/message requests
# read the same history snapshot, both run the agent, and the second write
# silently overwrites the first's result. Also protects the confirmation flow
# from interleaving with new messages. Entries are lazily created and cleaned
# up on LRU eviction in _touch_session, keeping them bounded by _MAX_SESSIONS.
_session_locks: dict[tuple[UUID, str], asyncio.Lock] = {}

# OAuth CSRF state tokens: maps state string -> (timestamp, provider, redirect_uri).
# Entries expire after _OAUTH_STATE_TTL_S seconds. Reaped on each authorize call.
_OAUTH_STATE_TTL_S: int = 600  # 10 minutes
_OAUTH_PENDING_STATES_MAX: int = 50
_oauth_pending_states: dict[str, tuple[float, OAuthProvider, str]] = {}

# ---------------------------------------------------------------------------
# Critical permissions state (tier-2 promotable denials)
# ---------------------------------------------------------------------------

# Pending promotion cooldowns: (tool, action) -> pending_at datetime.
# In-memory only — lost on restart (acceptable per spec). During cooldown,
# the permission stays deny; it flips to confirm when the cooldown expires.
_pending_promotions: dict[tuple[str, str], datetime] = {}

# Completed promotions: set of (tool, action) pairs promoted to confirm.
# Loaded from DB on startup, updated when cooldowns expire or demotions occur.
_promoted_permissions: set[tuple[str, str]] = set()

_PROMOTION_COOLDOWN_S: int = 300  # 5 minutes

# Injected at app creation time by create_app().
_agent: Agent | None = None
_config: AppConfig | None = None


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------


def _chat_key(user_id: UUID, session_id: str) -> tuple[UUID, str]:
    """The key of one user's chat in the in-memory chat state.

    Args:
        user_id: The logged-in principal's user id (from the session).
        session_id: The client-provided chat session id.

    Returns:
        The ``(user_id, session_id)`` pair.
    """
    return (user_id, session_id)


def _get_session_lock(key: tuple[UUID, str]) -> asyncio.Lock:
    """Get or create the asyncio lock of one chat.

    Lazily creates locks on first access. Cleaned up when chats are
    LRU-evicted in ``_touch_session``, keeping the dict bounded by
    ``_MAX_SESSIONS``.

    Args:
        key: The chat key from ``_chat_key``.

    Returns:
        The asyncio.Lock for the given chat.
    """
    if key not in _session_locks:
        _session_locks[key] = asyncio.Lock()
    return _session_locks[key]


def _touch_session(key: tuple[UUID, str], history: list[LLMMessage]) -> None:
    """Insert or update a chat's history, maintaining LRU order.

    If the chat store exceeds _MAX_SESSIONS, the least-recently-used chat is
    evicted. This bounds memory usage and prevents DoS via unbounded session
    creation.

    Args:
        key: The chat key from ``_chat_key``.
        history: The conversation history to store.
    """
    # Move to end if exists (mark as recently used), then update.
    if key in _sessions:
        _sessions.move_to_end(key)
    _sessions[key] = history

    # Evict oldest chats if over capacity.
    while len(_sessions) > _MAX_SESSIONS:
        evicted_key, _ = _sessions.popitem(last=False)
        # Also clean up any pending confirmation and lock for the evicted chat.
        _pending_confirmations.pop(evicted_key, None)
        _session_locks.pop(evicted_key, None)
        logger.info("Evicted session %s (session cap %d reached)", evicted_key[1], _MAX_SESSIONS)


def _reap_expired_confirmations() -> None:
    """Remove all expired pending confirmations.

    Called unconditionally at the top of ``post_message`` and
    ``post_confirm`` (before acquiring per-chat locks) to prevent
    stale confirmations from accumulating. This is the enforcement point
    for confirmation_timeout_s configured in LimitsConfig.

    IMPORTANT: This function must remain synchronous (no ``await`` calls).
    Callers invoke it outside per-chat locks, so it must complete
    atomically within a single event-loop tick to avoid cross-chat
    race conditions on ``_pending_confirmations``.
    """
    now = datetime.now(UTC)
    expired = [key for key, pc in _pending_confirmations.items() if now >= pc.expires_at]
    for key in expired:
        logger.info("Reaped expired confirmation for session %s", key[1])
        del _pending_confirmations[key]


_CANCELLED_TOOL_RESULT_MSG = "Tool call cancelled — user sent a new message instead of confirming."


def _summarise_pending(pending: PendingConfirmation) -> PendingConfirmationSummary:
    """Project a ``PendingConfirmation`` into the API-safe summary.

    Includes sanitized tool arguments so the PWA can display call details
    in the confirmation card. Excludes the internal ``session_id``.
    Credential patterns in string argument values are stripped by the
    ``PendingConfirmationSummary`` validator.
    """
    return PendingConfirmationSummary(
        confirmation_id=pending.confirmation_id,
        tool=pending.tool_call.tool,
        action=pending.tool_call.action,
        args=pending.tool_call.args,
        expires_at=pending.expires_at,
    )


def _close_dangling_tool_use(history: list[LLMMessage]) -> list[LLMMessage]:
    """Append synthetic cancelled tool_result messages for any dangling tool_use.

    Anthropic's API rejects a conversation where an assistant message with
    ``tool_use`` blocks is not immediately followed by matching ``tool_result``
    blocks. That situation arises when the agent short-circuits on a pending
    confirmation (see ``agent.py`` returning ``awaiting_confirmation`` after
    appending the assistant turn): the stored history now ends with a
    trailing ``tool_use`` that has no companion result.

    If the user then posts a new ``/api/message`` (instead of using
    ``/api/confirm/{id}``), the next LLM call would fail with HTTP 400. This
    helper rewrites the history so the contract holds: for each tool_use_block
    in the last assistant message without a matching ``tool`` message after
    it, append a synthetic ``tool`` message stating the call was cancelled.

    Returns a new list; the input is not mutated.
    """
    if not history:
        return history

    # Walk from the end collecting trailing tool messages, until we hit
    # the most recent assistant turn. A user/system message before reaching
    # an assistant means there is nothing to close.
    trailing_tool_ids: set[str] = set()
    assistant_idx: int | None = None
    for i in range(len(history) - 1, -1, -1):
        msg = history[i]
        if msg.role == "tool":
            if msg.tool_call_id:
                trailing_tool_ids.add(msg.tool_call_id)
            continue
        if msg.role == "assistant":
            assistant_idx = i
            break
        # user or system — no dangling tool_use in play.
        return history

    if assistant_idx is None:
        return history

    assistant = history[assistant_idx]
    if not assistant.tool_use_blocks:
        return history

    dangling_ids: list[str] = []
    for block in assistant.tool_use_blocks:
        block_id = block.get("id")
        if isinstance(block_id, str) and block_id and block_id not in trailing_tool_ids:
            dangling_ids.append(block_id)

    if not dangling_ids:
        return history

    cleaned = list(history)
    for block_id in dangling_ids:
        cleaned.append(
            LLMMessage(
                role="tool",
                content=_CANCELLED_TOOL_RESULT_MSG,
                tool_call_id=block_id,
            )
        )
    return cleaned


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------

_UNAUTHORIZED_DETAIL: Final = "Unauthorized"


async def require_session(request: Request) -> sessions.AuthenticatedSession:
    """FastAPI dependency: the session the ``admino_session`` cookie belongs to.

    ``sessions.resolve_session`` re-checks the session and its account in the
    database on every request (a deleted, expired or idle session, a
    deactivated user or org all resolve to nothing) and refreshes its
    ``last_seen_at`` at most once a minute. Other cookies and ``Authorization``
    headers are ignored.

    Args:
        request: The incoming request.

    Returns:
        The resolved ``AuthenticatedSession`` (with its ``Principal``).

    Per-user rate limits only engage once a session resolves, so cookies that
    resolve to no session are budgeted per client IP instead: each one spends a
    token, and an IP that has spent its budget gets 429 before any database
    lookup. A request without a cookie costs no lookup and spends nothing.

    Raises:
        HTTPException: 401 ``Unauthorized`` without a cookie or when the token
            resolves to no usable session; 429 when the client IP has spent
            its budget of unresolved cookies. The token is never logged.
    """
    from admino.database import get_pool

    token = request.cookies.get(sessions.SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail=_UNAUTHORIZED_DETAIL)
    caller = f"ip:{_client_ip(request)}"
    if _session_failures_exhausted(caller):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    session = await sessions.resolve_session(get_pool(), token)
    if session is None:
        _note_session_failure(caller)
        raise HTTPException(status_code=401, detail=_UNAUTHORIZED_DETAIL)
    return session


# The resolved session of the caller (401 without one).
_SessionDep = Annotated[sessions.AuthenticatedSession, Depends(require_session)]


async def require_principal(session: _SessionDep) -> Principal:
    """FastAPI dependency: the logged-in ``Principal`` (401 without a session)."""
    return session.principal


# The logged-in principal (401 without a session).
_PrincipalDep = Annotated[Principal, Depends(require_principal)]


async def require_chat_sender(principal: _PrincipalDep) -> Principal:
    """FastAPI dependency: a logged-in principal allowed to chat.

    Raises:
        HTTPException: 403 ``Forbidden`` unless the principal has
            ``Capability.CHAT_SEND`` (a Viewer or a Super Admin has not).
    """
    if not can(principal, Capability.CHAT_SEND):
        raise HTTPException(status_code=403, detail="Forbidden")
    return principal


# A logged-in principal with chat.send (401 without a session, 403 without the role).
_ChatSenderDep = Annotated[Principal, Depends(require_chat_sender)]


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------


def _format_sse(event: SSEEvent) -> str:
    """Format an SSEEvent model into a wire-format SSE frame.

    Args:
        event: Validated SSE event with event type and JSON data.

    Returns:
        A string in SSE wire format: ``event: <type>\\ndata: <data>\\n\\n``.
    """
    return f"event: {event.event}\ndata: {event.data}\n\n"


def _make_sse_event(event_type: str, payload: dict[str, object]) -> str:
    """Create and format an SSE frame from an event type and payload dict.

    Args:
        event_type: The SSE event name (e.g. 'message', 'status', 'done').
        payload: JSON-serializable dict for the data field.

    Returns:
        Wire-format SSE string.
    """
    sse = SSEEvent(event=event_type, data=json.dumps(payload, default=str))
    return _format_sse(sse)


async def _stream_agent_result(result: AgentResult) -> AsyncIterator[str]:
    """Convert an AgentResult into a sequence of SSE frames.

    Streams:
    - status: processing
    - tool_call: for each tool call in the result
    - message: the final text response (or confirm/error as appropriate)
    - done: stream end signal

    Args:
        result: The completed agent result to stream.

    Yields:
        SSE wire-format strings.
    """
    # 1. Status: processing
    yield _make_sse_event("status", {"status": "processing"})

    # 2. Tool call summaries
    for tc in result.tool_calls:
        yield _make_sse_event(
            "tool_call",
            {
                "tool": tc.tool,
                "action": tc.action,
                "success": tc.success,
            },
        )

    # 3. Main result based on status
    if result.status == "awaiting_confirmation" and result.pending_confirmation is not None:
        yield _make_sse_event(
            "confirm",
            {
                "confirmation_id": result.pending_confirmation.confirmation_id,
                "tool": result.pending_confirmation.tool_call.tool,
                "action": result.pending_confirmation.tool_call.action,
            },
        )
    elif result.status == "error":
        yield _make_sse_event("error", {"message": result.response})
    else:
        yield _make_sse_event("message", {"content": result.response})

    # 4. Done signal
    yield _make_sse_event("done", {})


# ---------------------------------------------------------------------------
# LLM (vLLM) endpoint probes
# ---------------------------------------------------------------------------


async def _get_vllm_available_models() -> list[str]:
    """Probe the local vLLM endpoint for its served model IDs.

    Only runs when the active provider is ``vllm``. Issues a short-timeout
    ``GET {vllm_base_url}/models`` and returns the list of model ``id`` strings.
    On ANY exception (unreachable, still loading, malformed payload) or a
    non-vllm provider, returns an empty list. Never raises, never logs response
    bodies.

    Returns:
        The served model IDs, or ``[]`` when the probe fails or vllm is inactive.
    """
    if _config is None or _config.llm.provider != "vllm":
        return []

    from admino.llm import strip_control_chars

    base_url = _config.llm.vllm_base_url.rstrip("/")
    url = f"{base_url}/models"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=2.0, read=3.0, write=2.0, pool=2.0),
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            payload = resp.json()
    except (httpx.HTTPError, ValueError, TypeError):
        # Unreachable, still loading, non-2xx, or non-JSON body — degrade to [].
        return []

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return []
    models: list[str] = []
    for entry in data:
        if isinstance(entry, dict):
            model_id = entry.get("id")
            if isinstance(model_id, str) and model_id:
                models.append(strip_control_chars(model_id)[:200])
    return models


async def _get_infomaniak_available_models(provider: str) -> list[str]:
    """List the models offered by the live Infomaniak client's product.

    Only runs when ``provider`` (the effective provider shown in Settings) is
    ``infomaniak`` AND the agent's live LLM client is an ``InfomaniakClient``
    (imported lazily, so no other provider loads it). Otherwise returns ``[]``.
    ``InfomaniakClient.list_models()`` never raises and returns ``[]`` on a
    missing token or any failure; ids are allowlist-filtered again by
    ``SettingsLLM``. The token is never part of the result.

    Args:
        provider: The effective LLM provider for the settings response.

    Returns:
        The listed model IDs, or ``[]``.
    """
    if provider != "infomaniak" or _agent is None:
        return []

    from admino.llm_infomaniak import InfomaniakClient

    client = _agent._llm
    if not isinstance(client, InfomaniakClient):
        return []
    return await client.list_models()


async def _check_llm_reachable() -> bool:
    """Return whether the active LLM provider looks reachable.

    For ``vllm`` this is True iff the ``/models`` probe returns a non-empty
    list within a short timeout. For cloud providers this returns True (setup
    problems such as a missing key surface as chat replies). Never raises.

    Returns:
        True if the provider is reachable (or is a cloud provider), else False.
    """
    if _config is None:
        return False
    if _config.llm.provider == "vllm":
        return bool(await _get_vllm_available_models())
    return True


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


async def health_check() -> dict[str, str | bool]:
    """Health check endpoint. Public (no session). Checks database connectivity.

    Reports the active LLM provider/model and whether it is reachable. The DB
    check still gates the 503; an unreachable LLM does not fail the check (it is
    reported via ``llm_reachable=False``).

    Returns:
        A status dict with ``status``, ``provider``, ``model``, ``llm_reachable``.

    Raises:
        HTTPException: 503 if the database is unreachable.
    """
    from admino.database import check_health

    db_ok = await check_health()
    if not db_ok:
        raise HTTPException(status_code=503, detail="Database unreachable")
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    return {
        "status": "ok",
        "provider": _config.llm.provider,
        "model": _config.llm.active_model_name,
        "llm_reachable": await _check_llm_reachable(),
    }


# ---------------------------------------------------------------------------
# Auth route handlers
# ---------------------------------------------------------------------------


def _clear_session_cookie(response: Response) -> None:
    """Make the browser drop the ``admino_session`` cookie (Max-Age=0)."""
    response.delete_cookie(
        key=sessions.SESSION_COOKIE_NAME,
        path="/",
        secure=_config.server.cookie_secure if _config is not None else True,
        httponly=True,
        samesite="strict",
    )


async def post_login(request: Request, body: LoginRequest) -> Response:
    """Handle POST /api/auth/login — email/password login (public).

    Rate-limited per client IP. On success opens a server-side session and
    answers 204 with the ``admino_session`` cookie (HttpOnly, SameSite=Strict,
    Path=/, Max-Age = the lifetime of the account's session policy, Secure iff
    ``server.cookie_secure``). Every failure cause (unknown email, wrong
    password, inactive account or organization) is the same 401, and no cookie
    is set.

    Args:
        request: The incoming request (client IP and User-Agent for the session).
        body: Validated LoginRequest; the password is a SecretStr.

    Returns:
        An empty 204 response carrying the session cookie.

    Raises:
        HTTPException: 401 on any login failure, 429 when rate-limited.

    Security notes:
        The email, password and token are never logged or echoed; the 401 body
        is identical for every cause (no user enumeration).
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/auth/login", f"ip:{_client_ip(request)}")

    from admino.database import get_pool

    try:
        result = await auth.login(
            get_pool(),
            email=body.email,
            password=body.password.get_secret_value(),
            ip=request.client.host if request.client is not None else None,
            user_agent=request.headers.get("user-agent"),
        )
    except auth.LoginFailedError:
        raise HTTPException(status_code=401, detail=auth.LOGIN_FAILED_MESSAGE) from None

    response = Response(status_code=204)
    response.set_cookie(
        key=sessions.SESSION_COOKIE_NAME,
        value=result.token,
        max_age=result.max_age_seconds,
        path="/",
        secure=_config.server.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return response


async def _request_reset_in_background(*, email: str, public_url: str, ip: str | None) -> None:
    """Run ``password_reset.request_reset`` after the 202 has been sent.

    A failure can't reach the caller any more (and must not: it would tell
    whether the account exists), so it is logged by exception class name only:
    no message text, no traceback, no email.
    """
    from admino.database import get_pool

    try:
        await password_reset.request_reset(get_pool(), email=email, public_url=public_url, ip=ip)
    except Exception as exc:
        logger.error("Password reset request failed (%s).", type(exc).__name__)


async def post_password_reset(request: Request, body: PasswordResetRequest) -> Response:
    """Handle POST /api/auth/password-reset — email a password reset link (public).

    Rate-limited per client IP. Always answers an empty 202: the account
    lookup, the token and the email happen in a background task after the
    response, so the answer is the same, and as fast, for every email.

    Args:
        request: The incoming request (the client IP for the audit event).
        body: Validated PasswordResetRequest.

    Returns:
        An empty 202 response carrying the background task.

    Raises:
        HTTPException: 429 when rate-limited.

    Security notes:
        The link base is ``server.public_url``, never a request header. The
        email is never logged or echoed.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/auth/password-reset", f"ip:{_client_ip(request)}")

    return Response(
        status_code=202,
        background=BackgroundTask(
            _request_reset_in_background,
            email=body.email,
            public_url=_config.server.public_url,
            ip=request.client.host if request.client is not None else None,
        ),
    )


async def post_password_reset_confirm(
    request: Request, body: PasswordResetConfirmRequest
) -> Response:
    """Handle POST /api/auth/password-reset/confirm — set a new password (public).

    Rate-limited per client IP. On success the password is changed and every
    session of the account ends, this browser's included: answers 204 and
    clears the session cookie.

    Args:
        request: The incoming request (the client IP for the audit event).
        body: Validated PasswordResetConfirmRequest; token and password are SecretStr.

    Returns:
        An empty 204 response that clears the session cookie, or a 422
        ``{"detail": <policy message>, "reason": <reason>}`` when the password
        policy refuses the new password (the link stays usable).

    Raises:
        HTTPException: 400 for every link that can't be used (malformed,
            unknown, expired, used or replaced token, or an account that may no
            longer log in), 429 when rate-limited.

    Security notes:
        The token and password are never logged or echoed.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/auth/password-reset/confirm", f"ip:{_client_ip(request)}")

    from admino.database import get_pool

    try:
        await password_reset.confirm_reset(
            get_pool(),
            token=body.token.get_secret_value(),
            new_password=body.new_password.get_secret_value(),
            ip=request.client.host if request.client is not None else None,
        )
    except password_reset.InvalidResetTokenError:
        raise HTTPException(
            status_code=400, detail=password_reset.INVALID_RESET_TOKEN_MESSAGE
        ) from None
    except passwords.PasswordPolicyError as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc), "reason": exc.reason})

    response = Response(status_code=204)
    _clear_session_cookie(response)
    return response


async def post_logout(
    request: Request,
    session: _SessionDep,
) -> Response:
    """Handle POST /api/auth/logout — end the current session.

    Only the session of this cookie ends: its row is deleted (the user's other
    devices stay logged in). Answers 204 and clears the cookie. Not audited.

    Args:
        request: The incoming request (its session cookie's session ends).
        session: The resolved session (401 without one).

    Returns:
        An empty 204 response that clears the session cookie.
    """
    _check_rate_limit("/api/auth/logout", _user_caller(session.principal))

    from admino.database import get_pool

    token = request.cookies.get(sessions.SESSION_COOKIE_NAME)
    if token:
        await auth.logout(get_pool(), token)

    response = Response(status_code=204)
    _clear_session_cookie(response)
    return response


async def get_me(
    session: _SessionDep,
) -> MeResponse:
    """Handle GET /api/auth/me — the logged-in account and its languages.

    Every value comes from the resolved session (the database), never from the
    request.

    Args:
        session: The resolved session (401 without one).

    Returns:
        MeResponse with the principal's ids, kind, role and languages.
    """
    principal = session.principal
    _check_rate_limit("/api/auth/me", _user_caller(principal))
    return MeResponse(
        user_id=principal.user_id,
        kind=principal.kind,
        org_id=principal.org_id,
        role=principal.role,
        ui_language=session.ui_language,
        response_language=session.response_language,
    )


# ---------------------------------------------------------------------------
# Session management route handlers (GH-152)
# ---------------------------------------------------------------------------


async def get_my_sessions(session: _SessionDep) -> SessionListResponse:
    """Handle GET /api/me/sessions — the caller's live sessions.

    Args:
        session: The resolved session (401 without one); its session is marked
            ``current``.

    Returns:
        SessionListResponse, the most recently active session first. No token
        or token hash is included.

    Raises:
        HTTPException: 403 without ``Capability.ACCOUNT_MANAGE``, 429 when
            rate-limited.
    """
    principal = session.principal
    if not can(principal, Capability.ACCOUNT_MANAGE):
        raise HTTPException(status_code=403, detail="Forbidden")
    _check_rate_limit("/api/me/sessions/get", _user_caller(principal))

    from admino.database import get_pool

    return SessionListResponse(
        sessions=await session_management.list_user_sessions(
            get_pool(), user_id=principal.user_id, current_session_id=session.session_id
        )
    )


async def delete_my_session(
    request: Request,
    session: _SessionDep,
    session_id: UUID,
) -> Response:
    """Handle DELETE /api/me/sessions/{session_id} — end one of the caller's sessions.

    The session's row is deleted and ``session.revoke`` is recorded. Ending the
    request's own session also clears the cookie.

    Args:
        request: The incoming request (the client IP for the audit event).
        session: The resolved session (401 without one).
        session_id: The session to end (a UUID; anything else is a 422).

    Returns:
        An empty 204 response.

    Raises:
        HTTPException: 403 without ``Capability.ACCOUNT_MANAGE``; 404 when the
            session doesn't exist or isn't the caller's (the same body either
            way); 429 when rate-limited.
    """
    principal = session.principal
    if not can(principal, Capability.ACCOUNT_MANAGE):
        raise HTTPException(status_code=403, detail="Forbidden")
    _check_rate_limit("/api/me/sessions/delete", _user_caller(principal))

    from admino.database import get_pool

    try:
        await session_management.revoke_own_session(
            get_pool(),
            principal=principal,
            session_id=session_id,
            ip=request.client.host if request.client is not None else None,
        )
    except session_management.SessionNotFoundError:
        raise HTTPException(
            status_code=404, detail=session_management.SESSION_NOT_FOUND_MESSAGE
        ) from None

    response = Response(status_code=204)
    if session_id == session.session_id:
        _clear_session_cookie(response)
    return response


async def post_org_user_logout(
    request: Request,
    principal: _PrincipalDep,
    user_id: UUID,
) -> Response:
    """Handle POST /api/org/users/{user_id}/logout — log a user of the org out everywhere.

    Every session of the user is deleted and ``session.force_logout`` is
    recorded (also when there was none).

    Args:
        request: The incoming request (the client IP for the audit event).
        principal: The logged-in principal (401 without a session).
        user_id: The user to log out (a UUID; anything else is a 422).

    Returns:
        An empty 204 response.

    Raises:
        HTTPException: 403 without ``Capability.ORG_USERS_MANAGE``; 404 when
            the user isn't a member of the caller's org, is deleted or doesn't
            exist (the same body either way); 429 when rate-limited.
    """
    _check_rate_limit("/api/org/users/logout", _user_caller(principal))

    from admino.database import get_pool

    try:
        await session_management.force_logout(
            get_pool(),
            actor=principal,
            user_id=user_id,
            ip=request.client.host if request.client is not None else None,
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    except accounts.UserNotInOrgError:
        raise HTTPException(status_code=404, detail="User not found") from None
    return Response(status_code=204)


async def post_message(
    body: ChatRequest,
    principal: _ChatSenderDep,
) -> ChatResponse:
    """Handle POST /api/message — send a user message to the agent.

    Validates the request, retrieves or creates the caller's chat, runs the
    agent with the caller's principal, updates chat state, and returns the
    response.

    Args:
        body: Validated ChatRequest with message and session_id.
        principal: The logged-in principal (needs ``chat.send``).

    Returns:
        ChatResponse with the agent's reply and tool call summary.
    """
    if _agent is None or _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/message", _user_caller(principal))
    _reap_expired_confirmations()
    await _resolve_pending_promotions()

    # Enforce max_message_length from config (tighter than Pydantic's 32768).
    max_len = _config.limits.max_message_length
    if len(body.message) > max_len:
        raise HTTPException(
            status_code=422,
            detail=f"Message exceeds maximum length of {max_len} characters",
        )

    session_id = body.session_id
    key = _chat_key(principal.user_id, session_id)

    # Per-chat lock serialises concurrent requests for the same chat,
    # preventing lost conversation turns from interleaved read-modify-write.
    async with _get_session_lock(key):
        history = _sessions.get(key, [])

        # If a confirmation was pending for this chat, the user has
        # implicitly cancelled it by sending a new chat message. Drop the
        # pending record and close any dangling ``tool_use`` in the stored
        # history so the next LLM call is well-formed. We also call the
        # cleanup unconditionally as a defence-in-depth step — it is a
        # no-op on a well-formed history.
        if key in _pending_confirmations:
            logger.info(
                "Session %s sent a new message while confirmation was pending — "
                "cancelling the pending tool call",
                session_id,
            )
            del _pending_confirmations[key]
        history = _close_dangling_tool_use(history)

        logger.info("Processing message for session %s", session_id)

        try:
            result = await _agent.run(
                user_message=body.message,
                session_id=session_id,
                history=history,
                principal=principal,
            )
        except (MemoryError, RecursionError):
            raise
        except Exception:
            logger.error("Agent run failed for session %s", session_id)
            raise HTTPException(status_code=500, detail="Internal error") from None

        # Update chat history from the agent's returned history (LRU-tracked).
        _touch_session(key, result.history)

        # Store pending confirmation if the agent is awaiting one.
        pending_summary: PendingConfirmationSummary | None = None
        if result.status == "awaiting_confirmation" and result.pending_confirmation is not None:
            _pending_confirmations[key] = result.pending_confirmation
            pending_summary = _summarise_pending(result.pending_confirmation)

        logger.info(
            "Completed message for session %s: status=%s, tool_calls=%d",
            session_id,
            result.status,
            len(result.tool_calls),
        )

        return ChatResponse(
            session_id=session_id,
            response=result.response,
            tool_calls=result.tool_calls,
            status=result.status,
            pending_confirmation=pending_summary,
        )


async def get_events(
    principal: _ChatSenderDep,
    session_id: str = Query(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Session identifier. Alphanumeric, hyphens, underscores only.",
    ),
) -> StreamingResponse:
    """Handle GET /api/events — SSE stream for one of the caller's chats.

    For v1, this is a stub that returns session status. ``_stream_agent_result``
    is implemented and tested but not yet wired into this endpoint — it will
    be connected in v2 when full SSE streaming is completed.

    Args:
        principal: The logged-in principal (needs ``chat.send``).
        session_id: Session identifier from query parameter (Pydantic-validated).

    Returns:
        StreamingResponse with text/event-stream content type.
    """
    if _agent is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/events", _user_caller(principal))

    history = _sessions.get(_chat_key(principal.user_id, session_id), [])
    if not history:
        # No messages in session yet — stream an empty done.
        async def _empty_stream() -> AsyncIterator[str]:
            yield _make_sse_event("done", {})

        return StreamingResponse(
            _empty_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # For v1, find the last user message and re-run if needed.
    # The SSE endpoint primarily streams results of previous POST /api/message calls.
    # Build a result from current session state.
    async def _session_stream() -> AsyncIterator[str]:
        yield _make_sse_event("status", {"status": "connected"})
        yield _make_sse_event("done", {})

    return StreamingResponse(
        _session_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def post_confirm(
    principal: _ChatSenderDep,
    confirmation_id: str = Path(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Confirmation identifier. Alphanumeric, hyphens, underscores only.",
    ),
    body: ConfirmRequest = ...,  # type: ignore[assignment]
) -> ChatResponse:
    """Handle POST /api/confirm/{confirmation_id} — approve or deny a pending action.

    Looks up the caller's pending confirmation by session_id, verifies the
    confirmation_id matches, checks expiry, and if approved, resumes the agent
    run with the caller's principal. Another user's pending confirmation is
    never found (404).

    Args:
        principal: The logged-in principal (needs ``chat.send``).
        confirmation_id: The confirmation ID from the URL path (Pydantic-validated).
        body: Validated ConfirmRequest with session_id and approved flag.

    Returns:
        ChatResponse with the result of the resumed agent run.

    Raises:
        HTTPException: 404 if confirmation not found, 400 if IDs mismatch,
                       410 if confirmation has expired.
    """
    if _agent is None or _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/confirm", _user_caller(principal))
    _reap_expired_confirmations()
    await _resolve_pending_promotions()

    session_id = body.session_id
    key = _chat_key(principal.user_id, session_id)

    # Per-chat lock serialises with concurrent POST /api/message requests.
    async with _get_session_lock(key):
        pending = _pending_confirmations.get(key)

        if pending is None:
            raise HTTPException(status_code=404, detail="No pending confirmation for this session")

        if pending.confirmation_id != confirmation_id:
            raise HTTPException(status_code=404, detail="Confirmation not found")

        # Confirmation ID from body must also match (defence-in-depth).
        if body.confirmation_id != confirmation_id:
            raise HTTPException(status_code=400, detail="Confirmation ID mismatch")

        # Check expiry at server layer — avoids a full agent round trip for
        # expired confirmations that the registry would also reject.
        if datetime.now(UTC) >= pending.expires_at:
            del _pending_confirmations[key]
            raise HTTPException(status_code=410, detail="Confirmation has expired")

        # Remove the pending confirmation regardless of approval/denial.
        del _pending_confirmations[key]

        if not body.approved:
            logger.info("Confirmation %s denied for session %s", confirmation_id, session_id)
            # The dangling tool_use in session history will be closed the next
            # time the user sends a chat message (see _close_dangling_tool_use
            # in post_message). We could also close it eagerly here, but the
            # lazy approach keeps the denial path minimal.
            # Safe f-string: tool and action are Pydantic-validated with
            # pattern=r"^[a-z][a-z0-9_]{0,62}$", restricting to alphanumeric/
            # underscore. ChatResponse.sanitize_response provides defence-in-depth.
            return ChatResponse(
                session_id=session_id,
                response=f"Action {pending.tool_call.tool}.{pending.tool_call.action} was denied.",
                tool_calls=[],
                status="final",
                pending_confirmation=None,
            )

        # Approved — resume the agent with the pending confirmation.
        history = _sessions.get(key, [])

        logger.info(
            "Resuming agent for session %s after confirmation %s",
            session_id,
            confirmation_id,
        )

        try:
            result = await _agent.run(
                user_message="",
                session_id=session_id,
                history=history,
                principal=principal,
                pending_confirmation=pending,
            )
        except (MemoryError, RecursionError):
            raise
        except Exception:
            logger.error("Agent resume failed for session %s", session_id)
            raise HTTPException(status_code=500, detail="Internal error") from None

        _touch_session(key, result.history)

        pending_summary: PendingConfirmationSummary | None = None
        if result.status == "awaiting_confirmation" and result.pending_confirmation is not None:
            _pending_confirmations[key] = result.pending_confirmation
            pending_summary = _summarise_pending(result.pending_confirmation)

        return ChatResponse(
            session_id=session_id,
            response=result.response,
            tool_calls=result.tool_calls,
            status=result.status,
            pending_confirmation=pending_summary,
        )


# ---------------------------------------------------------------------------
# Settings helpers
# ---------------------------------------------------------------------------


async def _build_settings_response() -> SettingsResponse:
    """Load settings from DB and construct the SettingsResponse.

    Masks sensitive fields (API keys replaced by boolean flags).
    Reads OAuth connection status from the DB for connected_accounts.

    Returns:
        A fully populated SettingsResponse.

    Raises:
        HTTPException: 500 if DB or config is unavailable.
    """
    from admino.database import get_pool, load_settings_from_db

    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    pool = get_pool()
    settings = await load_settings_from_db(pool)

    # LLM section with masked key flags. Fall back to the live config
    # (config.yaml-driven) rather than hardcoded literals so the displayed
    # values reflect the authoritative source.
    llm_data = settings.get("llm", {})
    # The SettingsLLM provider Literal includes every provider ("infomaniak",
    # "anthropic", "openai", "vllm"), so no coercion is needed — the stored
    # provider always displays as the selected one.
    provider = llm_data.get("provider") or _config.llm.provider
    config_vllm_model = _config.llm.vllm_model
    config_infomaniak_model = _config.llm.infomaniak_model
    llm_section = SettingsLLM(
        provider=provider,
        anthropic_model=llm_data.get("anthropic_model") or _config.llm.anthropic_model or "",
        openai_model=llm_data.get("openai_model") or _config.llm.openai_model or "",
        infomaniak_model=llm_data.get("infomaniak_model")
        or (config_infomaniak_model if isinstance(config_infomaniak_model, str) else "")
        or "",
        infomaniak_available_models=await _get_infomaniak_available_models(provider),
        vllm_model=llm_data.get("vllm_model")
        or (config_vllm_model if isinstance(config_vllm_model, str) else "")
        or "",
        vllm_available_models=await _get_vllm_available_models(),
        # Presence flags only — credential values never leave the server.
        anthropic_key_configured=bool(os.environ.get("ANTHROPIC_API_KEY")),
        openai_key_configured=bool(os.environ.get("OPENAI_API_KEY")),
        infomaniak_token_configured=bool(os.environ.get("INFOMANIAK_API_TOKEN")),
    )

    # Appearance section (default to light if missing).
    appearance_data = settings.get("appearance", {})
    appearance_section = SettingsAppearance(
        theme=appearance_data.get("theme", "light"),
    )

    # Notifications section (default to enabled if missing).
    notifications_data = settings.get("notifications", {})
    notifications_section = SettingsNotifications(
        enabled=notifications_data.get("enabled", True),
    )

    # Limits section.
    limits_data = settings.get("limits", {})
    limits_section = SettingsLimits(
        max_tool_calls_per_message=limits_data.get("max_tool_calls_per_message", 10),
        confirmation_timeout_s=limits_data.get("confirmation_timeout_s", 300),
        max_message_length=limits_data.get("max_message_length", 4000),
    )

    # Server section (immutable, read-only).
    server_data = settings.get("server", {})
    server_section = SettingsImmutable(
        host=server_data.get("host", _config.server.host),
        port=server_data.get("port", _config.server.port),
    )

    # Connected accounts — report connection AND health (a dead refresh token
    # is connected-but-unhealthy, which the UI renders as "Not connected").
    # get_connection_status reads only the DB row, so it never blocks load.
    # A connection-status lookup failure must never 500 the settings page —
    # fall back to "disconnected" so the page still renders.
    connected = SettingsConnectedAccounts()
    try:
        google_connected, google_healthy = await get_connection_status(get_pool(), "google")
        microsoft_connected, microsoft_healthy = await get_connection_status(
            get_pool(), "microsoft"
        )
    except (OAuthError, OSError, TypeError) as exc:
        # A pool that is unavailable or misconfigured must not 500 the
        # settings page — degrade to "disconnected" and log the failure.
        logger.warning("Failed to read OAuth connection status: %s", type(exc).__name__)
        google_connected = google_healthy = False
        microsoft_connected = microsoft_healthy = False
    if google_connected:
        connected.google = OAuthConnectionStatus(
            connected=True,
            healthy=google_healthy,
            services=["gmail", "google_calendar", "google_drive"],
        )
    if microsoft_connected:
        connected.microsoft = OAuthConnectionStatus(
            connected=True,
            healthy=microsoft_healthy,
            services=["outlook", "outlook_calendar", "onedrive"],
        )

    # Tools section — per-tool enabled/disabled state.
    # Defensive: fall back to defaults if DB data is corrupted.
    tools_data = settings.get("tools", {})
    try:
        tools_section = ToolsSettings(**tools_data)
    except ValidationError:
        logger.warning("Corrupt tools settings in DB — falling back to defaults")
        tools_section = ToolsSettings()

    return SettingsResponse(
        llm=llm_section,
        appearance=appearance_section,
        notifications=notifications_section,
        limits=limits_section,
        server=server_section,
        connected_accounts=connected,
        tools=tools_section,
    )


# ---------------------------------------------------------------------------
# Settings route handlers
# ---------------------------------------------------------------------------


async def get_settings(
    principal: _PrincipalDep,
) -> SettingsResponse:
    """Handle GET /api/settings — return current settings with masked secrets.

    Loads settings from the database, maps them to the response model, and
    replaces sensitive fields (API keys) with boolean flags.

    Args:
        principal: The logged-in principal (from the session).

    Returns:
        SettingsResponse with current settings.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/settings/get", _user_caller(principal))
    return await _build_settings_response()


async def patch_settings(
    body: SettingsPatch,
    principal: _PrincipalDep,
) -> SettingsResponse:
    """Handle PATCH /api/settings — partially update settings.

    Validates the patch, merges with current DB values, validates the merged
    result against the full config model, persists, and re-initialises the LLM
    client when the provider changes, or when the active provider's model
    (``vllm_model`` / ``infomaniak_model``) changes. A missing API key/token or
    model never blocks the switch: chat replies explain what to set.

    Args:
        body: Validated SettingsPatch with optional sections.
        principal: The logged-in principal (from the session).

    Returns:
        Updated SettingsResponse after applying the patch.

    Raises:
        HTTPException: 400 on validation errors, 500 on server errors.
    """
    from admino.config import LLMConfig
    from admino.database import get_pool, load_settings_from_db, update_setting
    from admino.llm import create_llm_client

    if _agent is None or _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/settings/patch", _user_caller(principal))

    pool = get_pool()
    current_settings = await load_settings_from_db(pool)
    llm_reinit_needed = False
    # The LLMConfig produced by validating the merged patch, captured so the
    # re-init block below reuses it directly instead of re-reading the DB (which,
    # right after update_setting, is the same authoritative value).
    new_llm_config: LLMConfig | None = None

    # --- LLM section ---
    if body.llm is not None:
        llm_current: dict[str, Any] = dict(current_settings.get("llm", {}))
        patch_fields = body.llm.model_dump(exclude_none=True)

        # Track whether the running LLM client must be rebuilt. A provider
        # change always requires it. A changed vllm_model / infomaniak_model
        # requires it too when the effective provider is (or becomes) that
        # provider — the model, and therefore the client, changed. A no-op
        # (same value) must NOT re-init.
        if "provider" in patch_fields and patch_fields["provider"] != llm_current.get("provider"):
            llm_reinit_needed = True
        effective_provider = patch_fields.get("provider", llm_current.get("provider"))
        model_field = f"{effective_provider}_model"
        if (
            effective_provider in ("vllm", "infomaniak")
            and model_field in patch_fields
            and patch_fields[model_field] != llm_current.get(model_field)
        ):
            llm_reinit_needed = True

        # Merge non-None patch fields into current values.
        for key, value in patch_fields.items():
            llm_current[key] = value

        # Validate merged result against the full LLMConfig model. Backfill
        # from the live config (config.yaml) so model fields not stored in the
        # DB are sourced from the authoritative config rather than defaults.
        try:
            new_llm_config = LLMConfig.model_validate(
                {**_config.llm.model_dump(mode="json"), **llm_current}
            )
        except ValidationError as exc:
            safe_errors = []
            for err in exc.errors(include_input=False):
                safe_errors.append(
                    {
                        "loc": [str(loc) for loc in err["loc"]],
                        "msg": err["msg"],
                        "type": err["type"],
                    }
                )
            raise HTTPException(status_code=400, detail=safe_errors) from None

        await update_setting(pool, "llm", llm_current)

    # --- Appearance section ---
    if body.appearance is not None:
        appearance_current: dict[str, Any] = dict(current_settings.get("appearance", {}))
        patch_fields = body.appearance.model_dump(exclude_none=True)
        for key, value in patch_fields.items():
            appearance_current[key] = value
        await update_setting(pool, "appearance", appearance_current)

    # --- Notifications section ---
    if body.notifications is not None:
        notifications_current: dict[str, Any] = dict(
            current_settings.get("notifications", {}),
        )
        patch_fields = body.notifications.model_dump(exclude_none=True)
        for key, value in patch_fields.items():
            notifications_current[key] = value
        await update_setting(pool, "notifications", notifications_current)

    # --- Tools section ---
    if body.tools is not None:
        tools_current: dict[str, Any] = dict(current_settings.get("tools", {}))
        patch_fields = body.tools.model_dump(exclude_none=True)
        for key, value in patch_fields.items():
            tools_current[key] = value
        # Validate through ToolsSettings to strip unknown keys and ensure
        # all values are proper booleans before persisting and hot-reloading.
        validated_tools = ToolsSettings.model_validate(tools_current).model_dump()
        # Audit log: record each real on/off change (skip no-ops) at WARNING so
        # every DB-mutating service toggle from the UI is traceable, mirroring
        # the permission-change audit trail. A tool with no stored value
        # defaults to enabled, matching ToolsSettings defaults.
        for key, new_value in patch_fields.items():
            old_value = current_settings.get("tools", {}).get(key, True)
            if old_value != new_value:
                logger.warning(
                    "Service toggled: tool=%s old=%s new=%s",
                    key,
                    old_value,
                    new_value,
                )
        await update_setting(pool, "tools", validated_tools)
        # Hot-reload: push updated tools-enabled state to the running agent
        # so the next dispatch respects the change immediately.
        if _agent is not None:
            _agent._tools_enabled = validated_tools

    # --- Re-initialise LLM client if the provider or the active model changed ---
    if llm_reinit_needed and new_llm_config is not None:
        try:
            new_client = create_llm_client(new_llm_config)
        except (ValueError, ImportError) as exc:
            logger.error("Failed to create LLM client: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400,
                detail="Failed to create LLM client for the selected provider",
            ) from None
        # Single-user, single-worker deployment: concurrent requests are
        # serialised by the event loop, so this reference swap is atomic.
        # Retire the previous client AFTER swapping so its HTTP connection pool
        # is released instead of leaked across repeated provider switches.
        # Teardown is best-effort: a close() failure on the now-unreferenced
        # client must never fail the settings update.
        old_client = _agent._llm
        _agent._llm = new_client
        try:
            await old_client.close()
        except Exception:
            logger.warning("Failed to close retired LLM client after LLM settings change")
        logger.info("LLM client re-initialised for provider: %s", new_llm_config.provider)

    return await _build_settings_response()


# ---------------------------------------------------------------------------
# Permissions route handlers
# ---------------------------------------------------------------------------


async def get_permissions(
    principal: _PrincipalDep,
) -> PermissionsResponse:
    """Handle GET /api/permissions — return full permission matrix.

    Loads all permission rows from the database and returns them as a flat
    list of (tool, action, permission) entries.

    Args:
        principal: The logged-in principal (from the session).

    Returns:
        PermissionsResponse with all configured permissions.
    """
    from admino.database import get_pool, load_permissions_from_db

    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/permissions/get", _user_caller(principal))

    pool = get_pool()
    raw = await load_permissions_from_db(pool)

    entries: list[PermissionEntry] = []
    for tool, actions in sorted(raw.items()):
        for action, permission in sorted(actions.items()):
            entries.append(
                PermissionEntry(tool=tool, action=action, permission=permission)  # type: ignore[arg-type]
            )

    return PermissionsResponse(permissions=entries)


async def patch_permissions(
    body: PermissionPatch,
    principal: _PrincipalDep,
) -> PermissionsResponse:
    """Handle PATCH /api/permissions — update a single permission.

    Validates that the update does not attempt to override a hardcoded denial,
    persists the change to the database, reloads the permissions config into
    the running agent, and returns the updated full permission matrix.

    Args:
        body: Validated PermissionPatch with tool, action, permission.
        principal: The logged-in principal (from the session).

    Returns:
        Updated PermissionsResponse after applying the change.

    Raises:
        HTTPException: 400 if attempting to override a hardcoded denial,
                       500 if server not configured.
    """
    from admino.config import load_permissions_config_from_db
    from admino.database import get_pool, load_permissions_from_db, update_permission
    from admino.permissions import HARDCODED_DENIALS

    if _agent is None or _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/permissions/patch", _user_caller(principal))

    # Enforce hardcoded denials: these cannot be set to anything other than "deny".
    if (body.tool, body.action) in HARDCODED_DENIALS and body.permission != "deny":
        raise HTTPException(
            status_code=400,
            detail="This tool/action pair is a hardcoded denial and cannot be changed.",
        )

    pool = get_pool()

    # Load old value for audit trail before mutation.
    old_permissions = await load_permissions_from_db(pool)
    old_value = old_permissions.get(body.tool, {}).get(body.action, "deny")

    await update_permission(pool, body.tool, body.action, body.permission)

    # Audit log: record the permission change at WARNING level.
    logger.warning(
        "Permission changed: tool=%s action=%s old=%s new=%s",
        body.tool,
        body.action,
        old_value,
        body.permission,
    )

    # Reload permissions config and update the running agent immediately.
    new_permissions = await load_permissions_config_from_db(pool)
    _agent._permissions = new_permissions

    # Return updated full matrix.
    raw = await load_permissions_from_db(pool)
    entries: list[PermissionEntry] = []
    for tool, actions in sorted(raw.items()):
        for action, permission in sorted(actions.items()):
            entries.append(
                PermissionEntry(tool=tool, action=action, permission=permission)  # type: ignore[arg-type]
            )

    return PermissionsResponse(permissions=entries)


# ---------------------------------------------------------------------------
# Critical permissions route handlers (tier-2 promotable denials)
# ---------------------------------------------------------------------------


async def _resolve_pending_promotions() -> None:
    """Check pending promotions and complete any whose cooldown has expired.

    Mutates ``_pending_promotions`` and ``_promoted_permissions`` in place.
    Persists completed promotions to the database. This is a lazy resolution
    — called on GET and PATCH to avoid background asyncio tasks.

    When promotions complete, a ``user``-role notification is injected into all
    active sessions so the LLM is aware the permission changed and will not
    refuse based on stale denial messages in the conversation history. A
    ``user`` role (not ``system``) is required so the notice survives the
    agent's ``_drop_system_messages`` prompt-injection defence (see GH-66,
    GH-140).

    Safety: builds a list of expired keys first, then mutates the dict in a
    separate loop to avoid ``RuntimeError`` from modifying a dict during
    iteration.
    """
    now = datetime.now(UTC)
    expired: list[tuple[str, str]] = [
        key
        for key, pending_at in _pending_promotions.items()
        if (now - pending_at).total_seconds() >= _PROMOTION_COOLDOWN_S
    ]

    if not expired:
        return

    from admino.database import get_pool, update_permission

    pool = get_pool()
    for key in expired:
        tool, action = key
        _pending_promotions.pop(key, None)
        _promoted_permissions.add(key)
        await update_permission(pool, tool, action, "confirm")
        logger.warning(
            "Critical permission promoted: tool=%s action=%s (cooldown expired)",
            tool,
            action,
        )

    # Update agent's promoted set so check_permission sees the change.
    if _agent is not None:
        _agent._promoted = frozenset(_promoted_permissions)

    # Inject a notification into all active sessions so the LLM knows the
    # permission changed and won't refuse based on stale denial messages in
    # the conversation history.
    #
    # GH-66: this MUST use a non-system role. The agent's ``_drop_system_messages``
    # prompt-injection defence drops every ``system``-role message in
    # caller-supplied history (GH-140), so a ``system``-role notification would be
    # silently discarded before reaching the LLM. A ``user``-role message is
    # informational (not a trusted directive) and survives the filter.
    promoted_names = ", ".join(f"{t}.{a}" for t, a in expired)
    # Phrased as a neutral, factual notice rather than a directive: it occupies
    # the human turn slot, so it must not read as a standing instruction to act
    # (GH-66 security review, Finding 1).
    notification = LLMMessage(
        role="user",
        content=(
            f"PERMISSION UPDATE: The following actions are now available with "
            f"user confirmation: {promoted_names}. Earlier denials for these "
            f"actions no longer apply."
        ),
    )
    for history in _sessions.values():
        history.append(notification)


async def get_critical_permissions(
    principal: _PrincipalDep,
) -> CriticalPermissionsResponse:
    """Return the 4 promotable permissions with current state and cooldown info."""
    from admino.permissions import PROMOTABLE_DENIALS

    _check_rate_limit("/api/critical-permissions/get", _user_caller(principal))
    await _resolve_pending_promotions()

    entries: list[CriticalPermissionEntry] = []
    for tool, action in sorted(PROMOTABLE_DENIALS):
        key = (tool, action)
        state: str = "confirm" if key in _promoted_permissions else "deny"
        pending_at = _pending_promotions.get(key)
        entries.append(
            CriticalPermissionEntry(
                tool=tool,
                action=action,
                state=state,  # type: ignore[arg-type]
                pending_at=pending_at,
            )
        )
    return CriticalPermissionsResponse(permissions=entries)


async def patch_critical_permission(
    principal: _PrincipalDep,
    tool: str = Path(pattern=r"^[a-z][a-z0-9_]{0,62}$"),
    action: str = Path(pattern=r"^[a-z][a-z0-9_]{0,62}$"),
) -> CriticalPermissionState:
    """Demote a promoted critical permission (confirm -> deny).

    Promotion (deny -> confirm) is disabled until #161 adds password re-auth:
    a PATCH on a permission that isn't currently promoted answers 403 and
    starts no cooldown. Any request body is ignored.

    Raises:
        HTTPException: 404 for a non-promotable pair, 403 for a promotion.
    """
    from admino.permissions import PROMOTABLE_DENIALS

    if (tool, action) not in PROMOTABLE_DENIALS:
        raise HTTPException(status_code=404, detail="Not a promotable permission")

    key = (tool, action)

    # Rate-limit before any await to prevent concurrent requests from
    # racing past the limiter while a coroutine is suspended.
    _check_rate_limit("/api/critical-permissions/promote", _user_caller(principal))

    # Resolve any expired cooldowns before deciding the current state.
    await _resolve_pending_promotions()

    # PROMOTE path: disabled until #161 (password re-auth).
    if key not in _promoted_permissions:
        raise HTTPException(
            status_code=403,
            detail="Critical permission promotions are temporarily unavailable.",
        )

    # DEMOTE path: currently promoted, revert to deny immediately.
    _promoted_permissions.discard(key)
    _pending_promotions.pop(key, None)

    from admino.config import load_permissions_config_from_db
    from admino.database import get_pool, update_permission

    pool = get_pool()
    await update_permission(pool, tool, action, "deny")
    new_perms = await load_permissions_config_from_db(pool)
    if _agent is not None:
        _agent._permissions = new_perms
        _agent._promoted = frozenset(_promoted_permissions)

    logger.warning("Critical permission demoted: tool=%s action=%s", tool, action)
    return CriticalPermissionState(tool=tool, action=action, state="deny")


async def cancel_critical_permission_pending(
    principal: _PrincipalDep,
    tool: str = Path(pattern=r"^[a-z][a-z0-9_]{0,62}$"),
    action: str = Path(pattern=r"^[a-z][a-z0-9_]{0,62}$"),
) -> CriticalPermissionState:
    """Cancel a pending promotion cooldown and revert to deny."""
    from admino.permissions import PROMOTABLE_DENIALS

    _check_rate_limit("/api/critical-permissions/cancel", _user_caller(principal))

    if (tool, action) not in PROMOTABLE_DENIALS:
        raise HTTPException(status_code=404, detail="Not a promotable permission")

    key = (tool, action)
    if key not in _pending_promotions:
        raise HTTPException(status_code=404, detail="No pending promotion for this permission")

    del _pending_promotions[key]
    logger.warning("Critical permission promotion cancelled: tool=%s action=%s", tool, action)
    return CriticalPermissionState(tool=tool, action=action, state="deny")


# ---------------------------------------------------------------------------
# OAuth route handlers
# ---------------------------------------------------------------------------


def _reap_oauth_states() -> None:
    """Reap expired CSRF state tokens and enforce the capacity cap.

    Removes all entries older than ``_OAUTH_STATE_TTL_S`` seconds,
    then evicts the oldest entry if the dict is at capacity. This is
    a synchronous function (no ``await``) to ensure atomicity within
    the single-threaded asyncio event loop.
    """
    now = time.time()
    expired = [
        s for s, (ts, _p, _u) in _oauth_pending_states.items() if now - ts > _OAUTH_STATE_TTL_S
    ]
    for s in expired:
        del _oauth_pending_states[s]
    if len(_oauth_pending_states) >= _OAUTH_PENDING_STATES_MAX:
        oldest = min(_oauth_pending_states, key=lambda s: _oauth_pending_states[s][0])
        del _oauth_pending_states[oldest]


def _build_oauth_redirect_uri() -> str:
    """Build the OAuth callback redirect URI.

    Reads ``OAUTH_REDIRECT_URI`` from the environment if set (preferred —
    must match the URI registered in the OAuth provider's console). Falls
    back to constructing from server config (host + port).

    Returns:
        The fully-qualified callback URL string.

    Security notes:
        The redirect URI is deterministic from config/env — never derived
        from untrusted request headers (Host, X-Forwarded-*).
    """
    env_uri = os.environ.get("OAUTH_REDIRECT_URI")
    if env_uri:
        return env_uri
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")
    host = "localhost" if _config.server.host == "0.0.0.0" else _config.server.host  # noqa: S104
    return f"http://{host}:{_config.server.port}/api/oauth/callback"


async def oauth_google_authorize(
    principal: _PrincipalDep,
) -> OAuthAuthorizeResponse:
    """Build and return a Google OAuth consent URL.

    Generates a CSRF state token, stores it in ``_oauth_pending_states``,
    and returns the consent URL for the frontend to redirect the user.
    Expired state tokens are reaped on each call.

    Returns:
        OAuthAuthorizeResponse with the consent URL.

    Raises:
        HTTPException: 500 if OAuth env vars are not configured.

    Security notes:
        - Requires a session.
        - Rate limited to prevent state-token flooding.
        - State tokens expire after ``_OAUTH_STATE_TTL_S`` seconds.
        - Never logs credentials or tokens.
    """
    _check_rate_limit("/api/oauth/google/authorize", _user_caller(principal))
    _reap_oauth_states()

    redirect_uri = _build_oauth_redirect_uri()
    try:
        url, state = build_google_consent_url(redirect_uri)
    except OAuthError:
        logger.error("Failed to build Google consent URL — check OAuth env vars.")
        raise HTTPException(status_code=500, detail="OAuth configuration error.")  # noqa: B904

    _oauth_pending_states[state] = (time.time(), "google", redirect_uri)
    logger.info("Google OAuth authorize URL generated.")
    return OAuthAuthorizeResponse(url=url)


async def oauth_microsoft_authorize(
    principal: _PrincipalDep,
) -> OAuthAuthorizeResponse:
    """Build and return a Microsoft OAuth consent URL.

    Generates a CSRF state token, stores it in ``_oauth_pending_states``,
    and returns the consent URL for the frontend to redirect the user.
    Expired state tokens are reaped on each call.

    Returns:
        OAuthAuthorizeResponse with the consent URL.

    Raises:
        HTTPException: 500 if OAuth env vars are not configured.

    Security notes:
        - Requires a session.
        - Rate limited to prevent state-token flooding.
        - State tokens expire after ``_OAUTH_STATE_TTL_S`` seconds.
        - Never logs credentials or tokens.
    """
    _check_rate_limit("/api/oauth/microsoft/authorize", _user_caller(principal))
    _reap_oauth_states()

    redirect_uri = _build_oauth_redirect_uri()
    try:
        url, state = build_microsoft_consent_url(redirect_uri)
    except OAuthError:
        logger.error("Failed to build Microsoft consent URL — check OAuth env vars.")
        raise HTTPException(status_code=500, detail="OAuth configuration error.")  # noqa: B904

    _oauth_pending_states[state] = (time.time(), "microsoft", redirect_uri)
    logger.info("Microsoft OAuth authorize URL generated.")
    return OAuthAuthorizeResponse(url=url)


async def oauth_callback(
    request: Request,
    code: str | None = Query(default=None, max_length=2048, pattern=r"^[A-Za-z0-9/_.\-+=!*~,]+$"),
    state: str | None = Query(default=None, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$"),
    error: str | None = Query(default=None, max_length=64, pattern=r"^[A-Za-z0-9_]+$"),
) -> RedirectResponse:
    """Handle the OAuth callback redirect for Google and Microsoft.

    Validates the CSRF state, determines the provider from the stored state,
    exchanges the authorization code for tokens, encrypts the refresh token,
    and persists it to the database (oauth_tokens table).

    No session required — this endpoint is the provider's cross-site redirect
    (a SameSite=Strict session cookie isn't sent on it); the OAuth state token
    protects it instead. Rate-limited per client IP.

    Args:
        request: The incoming request (its client IP keys the rate limit).
        code: Authorization code from the provider (present on success).
        state: CSRF state token (must match a pending state).
        error: Error string from the provider (present on user denial).

    Returns:
        RedirectResponse to the tools page with oauth status query params.

    Security notes:
        - CSRF protection via state token validation.
        - Rate limited to prevent brute-force code replay.
        - Tokens are Fernet-encrypted before being written to the database.
        - Never logs credentials, tokens, or authorization codes.
    """
    _check_rate_limit("/api/oauth/callback", f"ip:{_client_ip(request)}")

    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    # Validate CSRF state first (RFC 6749 §10.12) — before inspecting any
    # other parameter, including the error parameter from the provider.
    if not state or state not in _oauth_pending_states:
        logger.warning("OAuth callback received invalid or missing state.")
        return RedirectResponse(url="/tools?oauth=error&reason=invalid_state", status_code=307)

    # Pop and validate state expiry.
    created_at, provider, redirect_uri = _oauth_pending_states.pop(state)
    if time.time() - created_at > _OAUTH_STATE_TTL_S:
        logger.warning("%s OAuth callback received expired state token.", provider.capitalize())
        return RedirectResponse(url="/tools?oauth=error&reason=invalid_state", status_code=307)

    # Provider denied consent.
    if error:
        logger.info("%s OAuth callback received denial from user.", provider.capitalize())
        return RedirectResponse(url="/tools?oauth=error&reason=denied", status_code=307)

    # Missing authorization code.
    if not code:
        logger.warning("%s OAuth callback missing authorization code.", provider.capitalize())
        return RedirectResponse(url="/tools?oauth=error&reason=missing_code", status_code=307)

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0),
        ) as client:
            if provider == "google":
                access_token, refresh_token, scopes = await exchange_google_code(
                    code, redirect_uri, client
                )
                # Best-effort: fetch user email for display purposes.
                email = await get_google_user_email(access_token, client)
            else:
                access_token, refresh_token, scopes = await exchange_microsoft_code(
                    code, redirect_uri, client
                )
                email = None

            # Access token is only needed for the best-effort email lookup
            # above; it is never persisted. Drop it before encrypting the
            # refresh token to minimise in-memory exposure of plaintext tokens.
            del access_token

            # Encrypt and persist the refresh token, then clear plaintext
            # from the local scope to minimise in-memory exposure.
            encrypted = encrypt_refresh_token(refresh_token)
            del refresh_token
            now_utc = datetime.now(UTC)
            token = OAuthToken(
                provider=provider,
                scopes=scopes,
                encrypted_refresh_token=encrypted,
                email=email,
                created_at=now_utc,
                last_refreshed_at=now_utc,
            )
            from admino.database import get_pool

            await save_token(get_pool(), token)
    except OAuthError:
        logger.error("%s OAuth token exchange or storage failed.", provider.capitalize())
        return RedirectResponse(url="/tools?oauth=error&reason=exchange_failed", status_code=307)

    if email:
        logger.info("%s OAuth connected successfully for user.", provider.capitalize())
    else:
        logger.info("%s OAuth connected successfully (email not retrieved).", provider.capitalize())

    return RedirectResponse(url="/tools?oauth=success", status_code=307)


async def oauth_google_status(
    principal: _PrincipalDep,
) -> OAuthConnectionStatus:
    """Return the connection status for the Google OAuth account.

    Reads the Google token row from the database.

    Returns:
        OAuthConnectionStatus indicating whether Google is connected.

    Security notes:
        - Requires a session.
        - Never exposes token contents in the response.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/oauth/google/status", _user_caller(principal))

    from admino.database import get_pool

    connected, _healthy = await get_connection_status(get_pool(), "google")
    if connected:
        return OAuthConnectionStatus(
            connected=True,
            services=["gmail", "google_calendar", "google_drive"],
        )
    return OAuthConnectionStatus(connected=False)


async def oauth_microsoft_status(
    principal: _PrincipalDep,
) -> OAuthConnectionStatus:
    """Return the connection status for the Microsoft OAuth account.

    Reads the Microsoft token row from the database.

    Returns:
        OAuthConnectionStatus indicating whether Microsoft is connected.

    Security notes:
        - Requires a session.
        - Never exposes token contents in the response.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/oauth/microsoft/status", _user_caller(principal))

    from admino.database import get_pool

    connected, _healthy = await get_connection_status(get_pool(), "microsoft")
    if connected:
        return OAuthConnectionStatus(
            connected=True,
            services=["outlook", "outlook_calendar", "onedrive"],
        )
    return OAuthConnectionStatus(connected=False)


async def oauth_google_disconnect(
    principal: _PrincipalDep,
) -> dict[str, str]:
    """Disconnect the Google OAuth account by deleting its token row.

    Removes the encrypted token row from the database. Returns 404 if no
    Google account is connected.

    Returns:
        A dict with ``{"status": "disconnected"}`` on success.

    Raises:
        HTTPException: 404 if not connected, 500 if deletion fails.

    Security notes:
        - Requires a session.
        - Rate limited to prevent abuse.
        - Never logs token contents.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/oauth/google/disconnect", _user_caller(principal))

    from admino.database import get_pool

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=5.0),
        ) as client:
            deleted = await revoke_and_delete_token(get_pool(), "google", client)
    except OAuthError:
        logger.error("Failed to disconnect Google account.")
        raise HTTPException(status_code=500, detail="Failed to disconnect.")  # noqa: B904

    if not deleted:
        raise HTTPException(status_code=404, detail="Google account is not connected.")

    # Invalidate in-memory cached access tokens so tool modules stop
    # reusing a stale token after the refresh token row is gone.
    await _clear_gmail_cache()
    await _clear_gcal_cache()
    await _clear_gdrive_cache()

    logger.info("Google OAuth account disconnected.")
    return {"status": "disconnected"}


async def oauth_microsoft_disconnect(
    principal: _PrincipalDep,
) -> dict[str, str]:
    """Disconnect the Microsoft OAuth account by deleting its token row.

    Removes the encrypted token row from the database and invalidates all
    in-memory cached access tokens for Microsoft tool modules.
    Returns 404 if no Microsoft account is connected.

    Returns:
        A dict with ``{"status": "disconnected"}`` on success.

    Raises:
        HTTPException: 404 if not connected, 500 if deletion fails.

    Security notes:
        - Requires a session.
        - Rate limited to prevent abuse.
        - Never logs token contents.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/oauth/microsoft/disconnect", _user_caller(principal))

    from admino.database import get_pool

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=5.0),
        ) as client:
            deleted = await revoke_and_delete_token(get_pool(), "microsoft", client)
    except OAuthError:
        logger.error("Failed to disconnect Microsoft account.")
        raise HTTPException(status_code=500, detail="Failed to disconnect.")  # noqa: B904

    if not deleted:
        raise HTTPException(status_code=404, detail="Microsoft account is not connected.")

    # Invalidate in-memory cached access tokens so tool modules stop
    # reusing a stale token after the refresh token row is gone.
    await _clear_outlook_cache()
    await _clear_outcal_cache()
    await _clear_onedrive_cache()

    logger.info("Microsoft OAuth account disconnected.")
    return {"status": "disconnected"}


# ---------------------------------------------------------------------------
# Validation error handler
# ---------------------------------------------------------------------------


async def _validation_error_handler(
    request: Request,
    exc: ValidationError,
) -> JSONResponse:
    """Handle Pydantic validation errors without leaking input values.

    Returns a generic 422 response. Raw input values are never included
    in the response body.

    Args:
        request: The incoming request (unused but required by FastAPI).
        exc: The Pydantic ValidationError.

    Returns:
        JSONResponse with safe error details.
    """
    safe_errors = []
    for err in exc.errors(include_input=False):
        safe_errors.append(
            {
                "loc": [str(loc) for loc in err["loc"]],
                "msg": err["msg"],
                "type": err["type"],
            }
        )
    return JSONResponse(status_code=422, content={"detail": safe_errors})


async def _request_validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Handle FastAPI request validation errors without leaking input values.

    FastAPI raises RequestValidationError (not pydantic.ValidationError)
    for request body/query/path validation failures. We extract only the
    safe fields (loc, msg, type) and explicitly exclude 'input', 'ctx',
    and 'url' to prevent raw user values from appearing in the response.

    Args:
        request: The incoming request (unused but required by FastAPI).
        exc: The FastAPI RequestValidationError wrapping Pydantic errors.

    Returns:
        JSONResponse with safe error details (no raw input values).
    """
    safe_errors = []
    for err in exc.errors():
        safe_errors.append(
            {
                "loc": [str(loc) for loc in err.get("loc", [])],
                "msg": err.get("msg", "Validation error"),
                "type": err.get("type", "value_error"),
            }
        )
    return JSONResponse(status_code=422, content={"detail": safe_errors})


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage application lifespan — init DB pool, the audit retention job, the
    expired-session purge and, when SMTP is configured, the email outbox sender
    on startup; stop the background tasks, then close the pool, on shutdown.

    The pool must be created here (on uvicorn's event loop), not in main(),
    because asyncio.run() closes its event loop on return, which would
    invalidate any connections created there.
    """
    import os
    from urllib.parse import quote_plus

    from admino.audit_events import run_retention_job
    from admino.database import close_pool, get_pool, init_pool
    from admino.email_outbox import run_outbox_sender
    from admino.mailer import load_smtp_config

    password = os.environ.get("PG_PASSWORD", "")
    host = os.environ.get("PG_HOST", "localhost")
    port = os.environ.get("PG_PORT", "5432")
    user = os.environ.get("PG_USER", "admino")
    database = os.environ.get("PG_DATABASE", "admino")
    database_url = f"postgresql://{user}:{quote_plus(password)}@{host}:{port}/{database}"

    await init_pool(database_url)

    # GH-146: the daily audit retention purge runs while the app is up. The
    # task stays referenced here and is cancelled before the pool closes.
    retention_task = asyncio.create_task(run_retention_job(get_pool()))

    # GH-152: expired and idle session rows are purged hourly while the app is
    # up. Looked up at call time, like the retention job; cancelled before the
    # pool closes.
    session_purge_task = asyncio.create_task(sessions.run_session_purge_job(get_pool()))

    # GH-148: the outbox sender delivers queued transactional email while the
    # app is up. Without SMTP config (load_smtp_config logs which variables are
    # missing) nothing starts and mail stays queued. Cancelled before the pool
    # closes, like the retention task.
    smtp_config = load_smtp_config()
    sender_task = (
        asyncio.create_task(run_outbox_sender(get_pool(), smtp_config))
        if smtp_config is not None
        else None
    )

    # Defense-in-depth (GH-80): the Agent is already seeded with the persisted
    # tools-enabled state at construction (main._async_startup). This reload on
    # the runtime pool is a redundant safety net so a disabled service stays
    # gated even if the construction-time seed is ever bypassed. Both paths use
    # ToolsSettings validation, so they cannot diverge.
    if _agent is not None:
        try:
            from admino.database import get_pool, load_settings_from_db

            pool = get_pool()
            db_settings = await load_settings_from_db(pool)
            tools_data = db_settings.get("tools", {})
            if isinstance(tools_data, dict):
                validated = ToolsSettings.model_validate(tools_data)
                _agent._tools_enabled = validated.model_dump()
        except Exception:
            # The construction-time seed from main._async_startup remains in
            # effect, so a disabled tool stays gated — this reload is only a
            # defense-in-depth refresh, not the primary gate.
            logger.warning(
                "Lifespan tools-settings reload failed — construction-time gate remains active."
            )

    # Load previously-promoted critical permissions from the database so
    # tier-2 promotions survive server restarts.
    try:
        from admino.database import get_pool, load_permissions_from_db
        from admino.permissions import PROMOTABLE_DENIALS

        pool = get_pool()
        db_perms = await load_permissions_from_db(pool)
        for tool, action in PROMOTABLE_DENIALS:
            if db_perms.get(tool, {}).get(action) == "confirm":
                _promoted_permissions.add((tool, action))
        if _agent is not None and _promoted_permissions:
            _agent._promoted = frozenset(_promoted_permissions)
            logger.info(
                "Loaded %d promoted permission(s) from database: %s",
                len(_promoted_permissions),
                sorted(f"{t}.{a}" for t, a in _promoted_permissions),
            )
    except Exception:
        logger.warning("Failed to load promoted permissions on startup; defaulting to none.")

    yield
    retention_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await retention_task
    session_purge_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await session_purge_task
    if sender_task is not None:
        sender_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sender_task
    await close_pool()


def create_app(
    *,
    agent: Agent,
    config: AppConfig,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Wires up routes, middleware, error handlers, and module-level state.
    The agent and config are injected to support testing with fakes.

    Args:
        agent: The Agent instance to handle user messages.
        config: Application configuration (server, limits, LLM, etc.).

    Returns:
        A configured FastAPI application ready to serve.
    """
    global _agent, _config
    _agent = agent
    _config = config

    # Clear session state on app creation (supports test isolation).
    _sessions.clear()
    _pending_confirmations.clear()
    _session_locks.clear()
    _oauth_pending_states.clear()
    _pending_promotions.clear()
    _promoted_permissions.clear()

    # Rate-limit buckets start empty (fresh process state, test isolation).
    _rate_buckets.clear()

    app = FastAPI(
        title="admino",
        description="Local-only, security-first personal AI agent",
        version="0.1.0",
        docs_url=None,  # Disable Swagger UI in production
        redoc_url=None,  # Disable ReDoc in production
        openapi_url=None,  # No anonymous map of the API surface
        lifespan=_lifespan,
    )

    # --- Middleware ---
    # Starlette wraps the LAST added middleware outermost. Resulting order for a
    # request: CORS -> security headers -> cross-origin protection -> routes.
    # Cross-origin protection (CSRF) therefore refuses a cross-origin write
    # before authentication, rate limiting and handlers run, and its 403 still
    # gets the security headers.
    app.add_middleware(CrossOriginProtectionMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # --- CORS middleware ---
    # Default to localhost-only origins for local-first security. The PWA is
    # served same-origin, so the session cookie never needs a cross-origin
    # credentialed request: allow_credentials stays False, and Content-Type is
    # the only allowed request header (no Authorization: there is no bearer auth).
    cors_origins = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type"],
    )

    # --- Error handlers ---
    # RequestValidationError: raised by FastAPI for request body/query/path validation.
    app.add_exception_handler(RequestValidationError, _request_validation_error_handler)  # type: ignore[arg-type]
    # ValidationError: raised by Pydantic inside route handlers (e.g. response model construction).
    app.add_exception_handler(ValidationError, _validation_error_handler)  # type: ignore[arg-type]

    # --- Routes ---
    # Public: health check, login, password reset and the OAuth callback (plus
    # static files). Every other route depends on require_session.
    app.get("/health")(health_check)
    app.post("/api/auth/login", status_code=204, response_model=None)(post_login)
    app.post("/api/auth/password-reset", status_code=202, response_model=None)(post_password_reset)
    app.post("/api/auth/password-reset/confirm", status_code=204, response_model=None)(
        post_password_reset_confirm
    )

    # API routes — session required.
    app.post("/api/auth/logout", status_code=204, response_model=None)(post_logout)
    app.get("/api/auth/me", response_model=MeResponse)(get_me)
    app.get("/api/me/sessions", response_model=SessionListResponse)(get_my_sessions)
    app.delete("/api/me/sessions/{session_id}", status_code=204, response_model=None)(
        delete_my_session
    )
    app.post("/api/org/users/{user_id}/logout", status_code=204, response_model=None)(
        post_org_user_logout
    )
    app.post("/api/message", response_model=ChatResponse)(post_message)
    app.get("/api/events")(get_events)
    app.post("/api/confirm/{confirmation_id}", response_model=ChatResponse)(post_confirm)
    app.get("/api/settings", response_model=SettingsResponse)(get_settings)
    app.patch("/api/settings", response_model=SettingsResponse)(patch_settings)
    app.get("/api/permissions", response_model=PermissionsResponse)(get_permissions)
    app.patch("/api/permissions", response_model=PermissionsResponse)(patch_permissions)
    app.get("/api/critical-permissions", response_model=CriticalPermissionsResponse)(
        get_critical_permissions
    )
    app.patch(
        "/api/critical-permissions/{tool}/{action}",
        response_model=CriticalPermissionState,
    )(patch_critical_permission)
    app.delete(
        "/api/critical-permissions/{tool}/{action}/pending",
        response_model=CriticalPermissionState,
    )(cancel_critical_permission_pending)

    # OAuth routes.
    app.get("/api/oauth/google/authorize", response_model=OAuthAuthorizeResponse)(
        oauth_google_authorize
    )
    app.get("/api/oauth/microsoft/authorize", response_model=OAuthAuthorizeResponse)(
        oauth_microsoft_authorize
    )
    app.get("/api/oauth/callback")(oauth_callback)  # public, state-checked
    app.get("/api/oauth/google/status", response_model=OAuthConnectionStatus)(oauth_google_status)
    app.get("/api/oauth/microsoft/status", response_model=OAuthConnectionStatus)(
        oauth_microsoft_status
    )
    app.delete("/api/oauth/google")(oauth_google_disconnect)
    app.delete("/api/oauth/microsoft")(oauth_microsoft_disconnect)

    # --- Static files (MUST be last so API routes take priority) ---
    # Resolve the PWA static directory. Checked in order:
    #   1. ADMINO_STATIC_DIR env var (explicit override, e.g. for tests)
    #   2. /app/static (Docker image layout — copied by Dockerfile)
    #   3. <repo>/static (dev layout: src/admino/server.py -> repo root -> static)
    # Mount only if a directory is found; skip silently in tests.
    static_dir: PathLib | None = None
    env_static = os.environ.get("ADMINO_STATIC_DIR")
    candidates: list[PathLib] = []
    if env_static:
        candidates.append(PathLib(env_static))
    candidates.append(PathLib("/app/static"))
    candidates.append(PathLib(__file__).parent.parent.parent / "static")
    for candidate in candidates:
        if candidate.is_dir():
            static_dir = candidate
            break
    if static_dir is not None:
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app
