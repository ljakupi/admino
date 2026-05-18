"""FastAPI web server for admino — the HTTP/SSE boundary layer.

Exposes the REST API and SSE streaming endpoint that clients interact with.
All user input enters through this module and all responses leave through it.
The server is a thin HTTP layer that delegates business logic to the agent.

Routes:
- POST /api/message       — Send a user message; returns ChatResponse.
- GET  /api/events        — SSE stream for a session.
- POST /api/confirm/{cid} — Approve or deny a pending confirmation.
- GET  /health            — Health check (no auth required).
- /                       — Static PWA files (no auth required).

Security notes:
- Bearer token auth via FastAPI dependency; constant-time comparison (hmac).
- No raw user content, assistant text, or tool args logged at INFO or below.
- Error responses use generic messages; never leak internal paths or config.
- CORS restricted to localhost origins by default.
- HSTS is not set (plain HTTP local deployment). When deploying behind a
  TLS-terminating reverse proxy, configure HSTS at the proxy layer.
- Does NOT import check_permission — permission decisions live in agent/registry.
- Does NOT import from permissions.py except PermissionsConfig type (via TYPE_CHECKING).

Deployment note:
- This module uses module-level dicts (_sessions, _pending_confirmations) for
  in-memory state. This requires a **single-worker** ASGI deployment. Running
  multiple workers (e.g. uvicorn --workers 2) will silently split state across
  processes. Use ``--workers 1`` (the default).

Session ID note:
- Session IDs are client-provided and validated by Pydantic (alphanumeric,
  hyphens, underscores, max 64 chars). The server does not generate session IDs.
  This is by design: the client is the only user (local-first, single-tenant).
  Two clients sharing the same token AND same session_id will share history —
  this is acceptable for the single-user threat model.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path as PathLib
from typing import TYPE_CHECKING, Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware

from admino.models import (
    AgentResult,
    ChatRequest,
    ChatResponse,
    ConfirmRequest,
    LLMMessage,
    OAuthAuthorizeResponse,
    OAuthConnectionStatus,
    PendingConfirmation,
    PendingConfirmationSummary,
    PermissionEntry,
    PermissionPatch,
    PermissionsResponse,
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
    TokenFile,
    build_google_consent_url,
    build_microsoft_consent_url,
    encrypt_refresh_token,
    exchange_google_code,
    exchange_microsoft_code,
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

    from starlette.responses import Response

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
# Rate limiter
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Simple in-process token-bucket rate limiter.

    Designed for single-user local deployment. Limits requests per second
    to prevent resource exhaustion (Ollama inference, memory). Not shared
    across workers — requires single-worker deployment (already required
    by the in-memory session store).

    Args:
        rate: Tokens added per second.
        capacity: Maximum burst capacity.
    """

    __slots__ = ("_capacity", "_last_refill", "_rate", "_tokens")

    def __init__(self, rate: float, capacity: int) -> None:
        self._rate = rate
        self._capacity = capacity
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()

    def allow(self) -> bool:
        """Consume one token. Returns True if the request is allowed."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


# Per-path rate limiters. Configured for single-user local use:
# - POST /api/message: 30 req/min (0.5/s) with burst of 5
# - POST /api/confirm: 30 req/min (0.5/s) with burst of 5
# - GET  /api/events:  10 req/min (~0.17/s) with burst of 3 (SSE connections)
# A global fallback bucket catches any future routes that lack a specific limiter.
_rate_limiters: dict[str, _TokenBucket] = {}
_global_rate_limiter: _TokenBucket | None = None


def _check_rate_limit(path: str) -> None:
    """Check rate limit for a given path. Raises 429 if exceeded.

    Uses the path-specific limiter if one exists, otherwise falls back
    to the global limiter. This ensures new routes are rate-limited by
    default even if no specific limiter is configured.

    Args:
        path: The request path to rate-limit.

    Raises:
        HTTPException: 429 if rate limit exceeded.
    """
    bucket = _rate_limiters.get(path, _global_rate_limiter)
    if bucket is not None and not bucket.allow():
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


# ---------------------------------------------------------------------------
# Module-level state — set during create_app()
# ---------------------------------------------------------------------------

# Maximum number of concurrent sessions before LRU eviction kicks in.
# Sized for single-user local deployment with generous headroom.
_MAX_SESSIONS: int = 256

# In-memory session store: session_id -> conversation history.
# No persistence across restarts (privacy-first design).
# OrderedDict enables O(1) LRU eviction when _MAX_SESSIONS is exceeded.
_sessions: OrderedDict[str, list[LLMMessage]] = OrderedDict()

# Pending confirmations per session: session_id -> PendingConfirmation.
# Keyed by session_id intentionally — only one pending confirmation per session.
# A new confirmation for the same session overwrites the previous one. This
# prevents confirmation queue buildup and simplifies the confirmation UX.
_pending_confirmations: dict[str, PendingConfirmation] = {}

# Per-session asyncio locks to serialise concurrent requests for the same
# session. Prevents race conditions where two concurrent POST /api/message
# requests read the same history snapshot, both run the agent, and the
# second write silently overwrites the first's result. Also protects the
# confirmation flow from interleaving with new messages.
# Keyed by session_id; entries are lazily created and cleaned up on LRU
# eviction in _touch_session, keeping them bounded by _MAX_SESSIONS.
_session_locks: dict[str, asyncio.Lock] = {}

# OAuth CSRF state tokens: maps state string -> (timestamp, provider, redirect_uri).
# Entries expire after _OAUTH_STATE_TTL_S seconds. Reaped on each authorize call.
_OAUTH_STATE_TTL_S: int = 600  # 10 minutes
_OAUTH_PENDING_STATES_MAX: int = 50
_oauth_pending_states: dict[str, tuple[float, OAuthProvider, str]] = {}

# Injected at app creation time by create_app().
_agent: Agent | None = None
_config: AppConfig | None = None


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------


def _get_session_lock(session_id: str) -> asyncio.Lock:
    """Get or create a per-session asyncio lock.

    Lazily creates locks on first access. Cleaned up when sessions are
    LRU-evicted in ``_touch_session``, keeping the dict bounded by
    ``_MAX_SESSIONS``.

    Args:
        session_id: The session identifier.

    Returns:
        The asyncio.Lock for the given session.
    """
    if session_id not in _session_locks:
        _session_locks[session_id] = asyncio.Lock()
    return _session_locks[session_id]


def _touch_session(session_id: str, history: list[LLMMessage]) -> None:
    """Insert or update a session, maintaining LRU order.

    If the session store exceeds _MAX_SESSIONS, the least-recently-used
    session is evicted. This bounds memory usage and prevents DoS via
    unbounded session creation.

    Args:
        session_id: The session identifier.
        history: The conversation history to store.
    """
    # Move to end if exists (mark as recently used), then update.
    if session_id in _sessions:
        _sessions.move_to_end(session_id)
    _sessions[session_id] = history

    # Evict oldest sessions if over capacity.
    while len(_sessions) > _MAX_SESSIONS:
        evicted_id, _ = _sessions.popitem(last=False)
        # Also clean up any pending confirmation and lock for the evicted session.
        _pending_confirmations.pop(evicted_id, None)
        _session_locks.pop(evicted_id, None)
        logger.info("Evicted session %s (session cap %d reached)", evicted_id, _MAX_SESSIONS)


def _reap_expired_confirmations() -> None:
    """Remove all expired pending confirmations.

    Called unconditionally at the top of ``post_message`` and
    ``post_confirm`` (before acquiring per-session locks) to prevent
    stale confirmations from accumulating. This is the enforcement point
    for confirmation_timeout_s configured in LimitsConfig.

    IMPORTANT: This function must remain synchronous (no ``await`` calls).
    Callers invoke it outside per-session locks, so it must complete
    atomically within a single event-loop tick to avoid cross-session
    race conditions on ``_pending_confirmations``.
    """
    now = datetime.now(UTC)
    expired = [sid for sid, pc in _pending_confirmations.items() if now >= pc.expires_at]
    for sid in expired:
        logger.info("Reaped expired confirmation for session %s", sid)
        del _pending_confirmations[sid]


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
# Auth dependency
# ---------------------------------------------------------------------------


def _get_bearer_token(request: Request) -> str | None:
    """Extract Bearer token from the Authorization header.

    Returns:
        The token string, or None if the header is missing or malformed.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header[7:]


async def require_auth(request: Request) -> None:
    """FastAPI dependency that enforces Bearer token authentication.

    Skipped for health check and static file routes. Uses constant-time
    comparison to prevent timing attacks on the token.

    Raises:
        HTTPException: 401 if the token is missing or invalid.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    # VPN mode: all connections trusted, no token required.
    # Logged at WARNING so operators see it at default log level (INFO).
    if _config.auth.mode == "vpn":
        logger.warning(
            "VPN mode: skipping auth for %s %s — all connections trusted",
            request.method,
            request.url.path,
        )
        return

    # Token mode: require a valid Bearer token.
    expected_token = _config.auth.token
    if expected_token is None:
        raise HTTPException(status_code=500, detail="Server misconfigured")

    provided = _get_bearer_token(request)
    if provided is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Constant-time comparison to prevent timing attacks.
    if not hmac.compare_digest(provided, expected_token.get_secret_value()):
        raise HTTPException(status_code=401, detail="Unauthorized")


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
# Route handlers
# ---------------------------------------------------------------------------


async def health_check() -> dict[str, str]:
    """Health check endpoint. No auth required. Checks database connectivity.

    Returns:
        Simple status dict.

    Raises:
        HTTPException: 503 if the database is unreachable.
    """
    from admino.database import check_health

    db_ok = await check_health()
    if not db_ok:
        raise HTTPException(status_code=503, detail="Database unreachable")
    return {"status": "ok"}


async def post_message(
    body: ChatRequest,
    _auth: None = Depends(require_auth),
) -> ChatResponse:
    """Handle POST /api/message — send a user message to the agent.

    Validates the request, retrieves or creates a session, runs the agent,
    updates session state, and returns the response.

    Args:
        body: Validated ChatRequest with message and session_id.
        _auth: Auth dependency (side-effect only).

    Returns:
        ChatResponse with the agent's reply and tool call summary.
    """
    if _agent is None or _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/message")
    _reap_expired_confirmations()

    # Enforce max_message_length from config (tighter than Pydantic's 32768).
    max_len = _config.limits.max_message_length
    if len(body.message) > max_len:
        raise HTTPException(
            status_code=422,
            detail=f"Message exceeds maximum length of {max_len} characters",
        )

    session_id = body.session_id

    # Per-session lock serialises concurrent requests for the same session,
    # preventing lost conversation turns from interleaved read-modify-write.
    async with _get_session_lock(session_id):
        history = _sessions.get(session_id, [])

        # If a confirmation was pending for this session, the user has
        # implicitly cancelled it by sending a new chat message. Drop the
        # pending record and close any dangling ``tool_use`` in the stored
        # history so the next LLM call is well-formed. We also call the
        # cleanup unconditionally as a defence-in-depth step — it is a
        # no-op on a well-formed history.
        if session_id in _pending_confirmations:
            logger.info(
                "Session %s sent a new message while confirmation was pending — "
                "cancelling the pending tool call",
                session_id,
            )
            del _pending_confirmations[session_id]
        history = _close_dangling_tool_use(history)

        logger.info("Processing message for session %s", session_id)

        try:
            result = await _agent.run(
                user_message=body.message,
                session_id=session_id,
                history=history,
            )
        except (MemoryError, RecursionError):
            raise
        except Exception:
            logger.error("Agent run failed for session %s", session_id)
            raise HTTPException(status_code=500, detail="Internal error") from None

        # Update session history from the agent's returned history (LRU-tracked).
        _touch_session(session_id, result.history)

        # Store pending confirmation if the agent is awaiting one.
        pending_summary: PendingConfirmationSummary | None = None
        if result.status == "awaiting_confirmation" and result.pending_confirmation is not None:
            _pending_confirmations[session_id] = result.pending_confirmation
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
    session_id: str = Query(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Session identifier. Alphanumeric, hyphens, underscores only.",
    ),
    _auth: None = Depends(require_auth),
) -> StreamingResponse:
    """Handle GET /api/events — SSE stream for a session.

    For v1, this is a stub that returns session status. ``_stream_agent_result``
    is implemented and tested but not yet wired into this endpoint — it will
    be connected in v2 when full SSE streaming is completed.

    Args:
        session_id: Session identifier from query parameter (Pydantic-validated).
        _auth: Auth dependency (side-effect only).

    Returns:
        StreamingResponse with text/event-stream content type.
    """
    if _agent is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/events")

    history = _sessions.get(session_id, [])
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
    confirmation_id: str = Path(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Confirmation identifier. Alphanumeric, hyphens, underscores only.",
    ),
    body: ConfirmRequest = ...,  # type: ignore[assignment]
    _auth: None = Depends(require_auth),
) -> ChatResponse:
    """Handle POST /api/confirm/{confirmation_id} — approve or deny a pending action.

    Looks up the pending confirmation by session_id, verifies the confirmation_id
    matches, checks expiry, and if approved, resumes the agent run.

    Args:
        confirmation_id: The confirmation ID from the URL path (Pydantic-validated).
        body: Validated ConfirmRequest with session_id and approved flag.
        _auth: Auth dependency (side-effect only).

    Returns:
        ChatResponse with the result of the resumed agent run.

    Raises:
        HTTPException: 404 if confirmation not found, 400 if IDs mismatch,
                       410 if confirmation has expired.
    """
    if _agent is None or _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/confirm")
    _reap_expired_confirmations()

    session_id = body.session_id

    # Per-session lock serialises with concurrent POST /api/message requests.
    async with _get_session_lock(session_id):
        pending = _pending_confirmations.get(session_id)

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
            del _pending_confirmations[session_id]
            raise HTTPException(status_code=410, detail="Confirmation has expired")

        # Remove the pending confirmation regardless of approval/denial.
        del _pending_confirmations[session_id]

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
        history = _sessions.get(session_id, [])

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
                pending_confirmation=pending,
            )
        except (MemoryError, RecursionError):
            raise
        except Exception:
            logger.error("Agent resume failed for session %s", session_id)
            raise HTTPException(status_code=500, detail="Internal error") from None

        _touch_session(session_id, result.history)

        pending_summary: PendingConfirmationSummary | None = None
        if result.status == "awaiting_confirmation" and result.pending_confirmation is not None:
            _pending_confirmations[session_id] = result.pending_confirmation
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
    Checks OAuth token file existence for connected_accounts.

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

    # LLM section with masked key flags.
    llm_data = settings.get("llm", {})
    llm_section = SettingsLLM(
        provider=llm_data.get("provider", "ollama"),
        model=llm_data.get("model", "gemma4:e2b"),
        ollama_url=llm_data.get("ollama_url", "http://local-llm:11434"),
        anthropic_model=llm_data.get("anthropic_model", "claude-sonnet-4-20250514"),
        openai_model=llm_data.get("openai_model", "gpt-4o"),
        anthropic_key_configured=bool(os.environ.get("ANTHROPIC_API_KEY")),
        openai_key_configured=bool(os.environ.get("OPENAI_API_KEY")),
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

    # Connected accounts — check token file existence.
    connected = SettingsConnectedAccounts()
    tokens_dir = _config.paths.tokens_dir
    google_token = tokens_dir / "google.json"
    microsoft_token = tokens_dir / "microsoft.json"
    if google_token.exists():
        connected.google = OAuthConnectionStatus(
            connected=True,
            services=["gmail", "google_calendar", "google_drive"],
        )
    if microsoft_token.exists():
        connected.microsoft = OAuthConnectionStatus(
            connected=True,
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
    _auth: None = Depends(require_auth),
) -> SettingsResponse:
    """Handle GET /api/settings — return current settings with masked secrets.

    Loads settings from the database, maps them to the response model, and
    replaces sensitive fields (API keys) with boolean flags.

    Args:
        _auth: Auth dependency (side-effect only).

    Returns:
        SettingsResponse with current settings.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/settings/get")
    return await _build_settings_response()


async def patch_settings(
    body: SettingsPatch,
    _auth: None = Depends(require_auth),
) -> SettingsResponse:
    """Handle PATCH /api/settings — partially update settings.

    Validates the patch, merges with current DB values, validates the merged
    result against the full config model, persists, and optionally re-initialises
    the LLM client if the provider changed.

    Args:
        body: Validated SettingsPatch with optional sections.
        _auth: Auth dependency (side-effect only).

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

    _check_rate_limit("/api/settings/patch")

    pool = get_pool()
    current_settings = await load_settings_from_db(pool)
    provider_changed = False

    # --- LLM section ---
    if body.llm is not None:
        llm_current: dict[str, Any] = dict(current_settings.get("llm", {}))
        patch_fields = body.llm.model_dump(exclude_none=True)

        # Track whether provider changed before merging.
        if "provider" in patch_fields and patch_fields["provider"] != llm_current.get("provider"):
            provider_changed = True

        # Merge non-None patch fields into current values.
        for key, value in patch_fields.items():
            llm_current[key] = value

        # Validate merged result against the full LLMConfig model.
        try:
            LLMConfig.model_validate(llm_current)
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
        await update_setting(pool, "tools", tools_current)

    # --- Re-initialise LLM client if provider changed ---
    if provider_changed:
        refreshed_settings = await load_settings_from_db(pool)
        llm_data = refreshed_settings.get("llm", {})
        try:
            new_llm_config = LLMConfig.model_validate(llm_data)
        except ValidationError:
            logger.error("Failed to reconstruct LLMConfig after provider change")
            raise HTTPException(
                status_code=500,
                detail="Failed to re-initialise LLM client",
            ) from None
        try:
            new_client = create_llm_client(new_llm_config)
        except (ValueError, ImportError) as exc:
            logger.error("Failed to create LLM client: %s", type(exc).__name__)
            raise HTTPException(
                status_code=400,
                detail="Failed to create LLM client for the selected provider",
            ) from None
        # Single-user, single-worker deployment: concurrent requests are
        # serialised by the event loop, so this plain assignment is safe.
        # The GIL guarantees the reference swap is atomic.
        _agent._llm = new_client
        logger.info("LLM client re-initialised for provider: %s", new_llm_config.provider)

    return await _build_settings_response()


# ---------------------------------------------------------------------------
# Permissions route handlers
# ---------------------------------------------------------------------------


async def get_permissions(
    _auth: None = Depends(require_auth),
) -> PermissionsResponse:
    """Handle GET /api/permissions — return full permission matrix.

    Loads all permission rows from the database and returns them as a flat
    list of (tool, action, permission) entries.

    Args:
        _auth: Auth dependency (side-effect only).

    Returns:
        PermissionsResponse with all configured permissions.
    """
    from admino.database import get_pool, load_permissions_from_db

    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/permissions/get")

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
    _auth: None = Depends(require_auth),
) -> PermissionsResponse:
    """Handle PATCH /api/permissions — update a single permission.

    Validates that the update does not attempt to override a hardcoded denial,
    persists the change to the database, reloads the permissions config into
    the running agent, and returns the updated full permission matrix.

    Args:
        body: Validated PermissionPatch with tool, action, permission.
        _auth: Auth dependency (side-effect only).

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

    _check_rate_limit("/api/permissions/patch")

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
        s for s, (ts, _p, _u) in _oauth_pending_states.items()
        if now - ts > _OAUTH_STATE_TTL_S
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
    _auth: None = Depends(require_auth),
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
        - Requires Bearer auth.
        - Rate limited to prevent state-token flooding.
        - State tokens expire after ``_OAUTH_STATE_TTL_S`` seconds.
        - Never logs credentials or tokens.
    """
    _check_rate_limit("/api/oauth/google/authorize")
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
    _auth: None = Depends(require_auth),
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
        - Requires Bearer auth.
        - Rate limited to prevent state-token flooding.
        - State tokens expire after ``_OAUTH_STATE_TTL_S`` seconds.
        - Never logs credentials or tokens.
    """
    _check_rate_limit("/api/oauth/microsoft/authorize")
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
    code: str | None = Query(default=None, max_length=2048, pattern=r"^[A-Za-z0-9/_.\-+=]+$"),
    state: str | None = Query(default=None, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$"),
    error: str | None = Query(default=None, max_length=64, pattern=r"^[A-Za-z0-9_]+$"),
) -> RedirectResponse:
    """Handle the OAuth callback redirect for Google and Microsoft.

    Validates the CSRF state, determines the provider from the stored state,
    exchanges the authorization code for tokens, encrypts the refresh token,
    and persists it to disk.

    No auth required — this endpoint is called by the provider's redirect,
    not by the authenticated frontend.

    Args:
        code: Authorization code from the provider (present on success).
        state: CSRF state token (must match a pending state).
        error: Error string from the provider (present on user denial).

    Returns:
        RedirectResponse to the settings page with status query params.

    Security notes:
        - CSRF protection via state token validation.
        - Rate limited to prevent brute-force code replay.
        - Tokens are encrypted before disk write.
        - Never logs credentials, tokens, or authorization codes.
    """
    _check_rate_limit("/api/oauth/callback")

    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    # Validate CSRF state first (RFC 6749 §10.12) — before inspecting any
    # other parameter, including the error parameter from the provider.
    if not state or state not in _oauth_pending_states:
        logger.warning("OAuth callback received invalid or missing state.")
        return RedirectResponse(url="/settings?oauth=error&reason=invalid_state", status_code=307)

    # Pop and validate state expiry.
    created_at, provider, redirect_uri = _oauth_pending_states.pop(state)
    if time.time() - created_at > _OAUTH_STATE_TTL_S:
        logger.warning("%s OAuth callback received expired state token.", provider.capitalize())
        return RedirectResponse(url="/settings?oauth=error&reason=invalid_state", status_code=307)

    # Provider denied consent.
    if error:
        logger.info("%s OAuth callback received denial from user.", provider.capitalize())
        return RedirectResponse(url="/settings?oauth=error&reason=denied", status_code=307)

    # Missing authorization code.
    if not code:
        logger.warning("%s OAuth callback missing authorization code.", provider.capitalize())
        return RedirectResponse(url="/settings?oauth=error&reason=missing_code", status_code=307)

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

            # Encrypt and persist the refresh token, then clear plaintext
            # from the local scope to minimise in-memory exposure.
            encrypted = encrypt_refresh_token(refresh_token)
            del refresh_token
            now_utc = datetime.now(UTC)
            token_file = TokenFile(
                provider=provider,
                scopes=scopes,
                encrypted_refresh_token=encrypted,
                created_at=now_utc,
                last_refreshed_at=now_utc,
            )
            save_token(_config.paths.tokens_dir, token_file)
    except OAuthError:
        logger.error("%s OAuth token exchange or storage failed.", provider.capitalize())
        return RedirectResponse(
            url="/settings?oauth=error&reason=exchange_failed", status_code=307
        )

    if email:
        logger.info("%s OAuth connected successfully for user.", provider.capitalize())
    else:
        logger.info("%s OAuth connected successfully (email not retrieved).", provider.capitalize())

    return RedirectResponse(url="/settings?oauth=success", status_code=307)


async def oauth_google_status(
    _auth: None = Depends(require_auth),
) -> OAuthConnectionStatus:
    """Return the connection status for the Google OAuth account.

    Checks whether an encrypted token file exists on disk for Google.

    Returns:
        OAuthConnectionStatus indicating whether Google is connected.

    Security notes:
        - Requires Bearer auth.
        - Never exposes token contents or file paths in the response.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/oauth/google/status")

    token_path = _config.paths.tokens_dir / "google.json"
    if token_path.is_file():
        return OAuthConnectionStatus(
            connected=True,
            services=["gmail", "google_calendar", "google_drive"],
        )
    return OAuthConnectionStatus(connected=False)


async def oauth_microsoft_status(
    _auth: None = Depends(require_auth),
) -> OAuthConnectionStatus:
    """Return the connection status for the Microsoft OAuth account.

    Checks whether an encrypted token file exists on disk for Microsoft.

    Returns:
        OAuthConnectionStatus indicating whether Microsoft is connected.

    Security notes:
        - Requires Bearer auth.
        - Never exposes token contents or file paths in the response.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/oauth/microsoft/status")

    token_path = _config.paths.tokens_dir / "microsoft.json"
    if token_path.is_file():
        return OAuthConnectionStatus(
            connected=True,
            services=["outlook", "outlook_calendar", "onedrive"],
        )
    return OAuthConnectionStatus(connected=False)


async def oauth_google_disconnect(
    _auth: None = Depends(require_auth),
) -> dict[str, str]:
    """Disconnect the Google OAuth account by deleting the token file.

    Removes the encrypted token file from disk. Returns 404 if no
    Google account is connected.

    Returns:
        A dict with ``{"status": "disconnected"}`` on success.

    Raises:
        HTTPException: 404 if not connected, 500 if deletion fails.

    Security notes:
        - Requires Bearer auth.
        - Rate limited to prevent abuse.
        - Never logs token contents.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/oauth/google/disconnect")

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=5.0),
        ) as client:
            deleted = await revoke_and_delete_token(_config.paths.tokens_dir, "google", client)
    except OAuthError:
        logger.error("Failed to disconnect Google account.")
        raise HTTPException(status_code=500, detail="Failed to disconnect.")  # noqa: B904

    if not deleted:
        raise HTTPException(status_code=404, detail="Google account is not connected.")

    # Invalidate in-memory cached access tokens so tool modules stop
    # reusing a stale token after the refresh token file is gone.
    await _clear_gmail_cache()
    await _clear_gcal_cache()
    await _clear_gdrive_cache()

    logger.info("Google OAuth account disconnected.")
    return {"status": "disconnected"}


async def oauth_microsoft_disconnect(
    _auth: None = Depends(require_auth),
) -> dict[str, str]:
    """Disconnect the Microsoft OAuth account by deleting the token file.

    Removes the encrypted token file from disk and invalidates all
    in-memory cached access tokens for Microsoft tool modules.
    Returns 404 if no Microsoft account is connected.

    Returns:
        A dict with ``{"status": "disconnected"}`` on success.

    Raises:
        HTTPException: 404 if not connected, 500 if deletion fails.

    Security notes:
        - Requires Bearer auth.
        - Rate limited to prevent abuse.
        - Never logs token contents.
    """
    if _config is None:
        raise HTTPException(status_code=500, detail="Server not configured")

    _check_rate_limit("/api/oauth/microsoft/disconnect")

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=5.0),
        ) as client:
            deleted = await revoke_and_delete_token(_config.paths.tokens_dir, "microsoft", client)
    except OAuthError:
        logger.error("Failed to disconnect Microsoft account.")
        raise HTTPException(status_code=500, detail="Failed to disconnect.")  # noqa: B904

    if not deleted:
        raise HTTPException(status_code=404, detail="Microsoft account is not connected.")

    # Invalidate in-memory cached access tokens so tool modules stop
    # reusing a stale token after the refresh token file is gone.
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
    """Manage application lifespan — init DB pool on startup, close on shutdown.

    The pool must be created here (on uvicorn's event loop), not in main(),
    because asyncio.run() closes its event loop on return, which would
    invalidate any connections created there.
    """
    import os
    from urllib.parse import quote_plus

    from admino.database import close_pool, init_pool

    password = os.environ.get("PG_PASSWORD", "")
    host = os.environ.get("PG_HOST", "localhost")
    port = os.environ.get("PG_PORT", "5432")
    user = os.environ.get("PG_USER", "admino")
    database = os.environ.get("PG_DATABASE", "admino")
    database_url = f"postgresql://{user}:{quote_plus(password)}@{host}:{port}/{database}"

    await init_pool(database_url)
    yield
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
        config: Application configuration (server, auth, CORS, etc.).

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

    # Initialize rate limiters (reset on app creation for test isolation).
    global _global_rate_limiter
    _rate_limiters.clear()
    _rate_limiters["/api/message"] = _TokenBucket(rate=0.5, capacity=5)
    _rate_limiters["/api/confirm"] = _TokenBucket(rate=0.5, capacity=5)
    _rate_limiters["/api/events"] = _TokenBucket(rate=0.17, capacity=3)
    _rate_limiters["/api/settings/get"] = _TokenBucket(rate=1.0, capacity=5)
    _rate_limiters["/api/settings/patch"] = _TokenBucket(rate=0.2, capacity=2)
    _rate_limiters["/api/permissions/get"] = _TokenBucket(rate=1.0, capacity=5)
    _rate_limiters["/api/permissions/patch"] = _TokenBucket(rate=0.2, capacity=2)
    _rate_limiters["/api/oauth/google/authorize"] = _TokenBucket(rate=0.2, capacity=2)
    _rate_limiters["/api/oauth/microsoft/authorize"] = _TokenBucket(rate=0.2, capacity=2)
    _rate_limiters["/api/oauth/callback"] = _TokenBucket(rate=0.2, capacity=2)
    _rate_limiters["/api/oauth/google/status"] = _TokenBucket(rate=1.0, capacity=5)
    _rate_limiters["/api/oauth/microsoft/status"] = _TokenBucket(rate=1.0, capacity=5)
    _rate_limiters["/api/oauth/google/disconnect"] = _TokenBucket(rate=0.2, capacity=2)
    _rate_limiters["/api/oauth/microsoft/disconnect"] = _TokenBucket(rate=0.2, capacity=2)
    _global_rate_limiter = _TokenBucket(rate=1.0, capacity=10)

    # Log VPN mode warning at server startup.
    if config.auth.mode == "vpn":
        logger.warning(
            "Server running in VPN mode — all requests are trusted without "
            "authentication. Ensure network-level access controls are in place."
        )

    app = FastAPI(
        title="admino",
        description="Local-only, security-first personal AI agent",
        version="0.1.0",
        docs_url=None,  # Disable Swagger UI in production
        redoc_url=None,  # Disable ReDoc in production
        lifespan=_lifespan,
    )

    # --- Security headers middleware ---
    # Starlette processes add_middleware calls in LIFO order: first added =
    # outermost wrapper = last to touch the response. By adding
    # SecurityHeadersMiddleware first, it wraps the entire stack and injects
    # headers on every response (including CORS preflight 200s).
    app.add_middleware(SecurityHeadersMiddleware)

    # --- CORS middleware ---
    # Default to localhost-only origins for local-first security.
    # allow_credentials=False: Bearer auth uses Authorization header, not
    # cookies. Setting True would widen the attack surface for no benefit.
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
        allow_headers=["Authorization", "Content-Type"],
    )

    # --- Error handlers ---
    # RequestValidationError: raised by FastAPI for request body/query/path validation.
    app.add_exception_handler(RequestValidationError, _request_validation_error_handler)  # type: ignore[arg-type]
    # ValidationError: raised by Pydantic inside route handlers (e.g. response model construction).
    app.add_exception_handler(ValidationError, _validation_error_handler)  # type: ignore[arg-type]

    # --- Routes ---
    # Health check — no auth.
    app.get("/health")(health_check)

    # API routes — auth required.
    app.post("/api/message", response_model=ChatResponse)(post_message)
    app.get("/api/events")(get_events)
    app.post("/api/confirm/{confirmation_id}", response_model=ChatResponse)(post_confirm)
    app.get("/api/settings", response_model=SettingsResponse)(get_settings)
    app.patch("/api/settings", response_model=SettingsResponse)(patch_settings)
    app.get("/api/permissions", response_model=PermissionsResponse)(get_permissions)
    app.patch("/api/permissions", response_model=PermissionsResponse)(patch_permissions)

    # OAuth routes.
    app.get("/api/oauth/google/authorize", response_model=OAuthAuthorizeResponse)(
        oauth_google_authorize
    )
    app.get("/api/oauth/microsoft/authorize", response_model=OAuthAuthorizeResponse)(
        oauth_microsoft_authorize
    )
    app.get("/api/oauth/callback")(oauth_callback)
    app.get("/api/oauth/google/status", response_model=OAuthConnectionStatus)(
        oauth_google_status
    )
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
