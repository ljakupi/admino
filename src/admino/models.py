"""Shared Pydantic models for tool args, API types, and agent messages.

This module defines all structured data types shared across admino modules:
- API request/response models (used by server.py)
- Agent and LLM message models (used by agent.py and llm.py)

Tool-call audit events are not modelled here: they are content-free rows of
the ``audit_events`` table, validated by ``admino.audit_events``.

Security notes:
- No secrets, tokens, passwords, or credentials are stored in any model field,
  except ``LoginRequest.password``, ``PasswordResetConfirmRequest.token`` /
  ``new_password``, ``InvitationAcceptRequest.password`` and
  ``CriticalPermissionPromote.password``: ``SecretStr`` values (hidden from
  repr/str) that live only for their request and are never logged or echoed.
  Invitation models carry no token, hash or link.
- Organization models (GH-154) carry org metadata only: no content, and
  ``OrgCreateResponse`` no token or link. ``OrgCreateRequest`` and
  ``OrgLimitsPatch`` hide their input from validation errors (an org name or
  admin email never reaches a log or a 422 body); seats, quotas and the
  residency switch are strict ints and bools.
- Org user management (GH-164): ``OrgUserSummary`` carries account metadata
  only (no hash, token, org id or kind); ``OrgUserPatch`` refuses unknown keys
  (the org, the target, the status and the kind come from the session, the
  path and the dedicated routes) and hides its input from validation errors.
  ``OrgSeats`` (GH-165) carries two counts only: the org's used seats and its
  limit.
- ``PlatformDiagnosticsResponse`` (GH-158) carries the LLM provider, model
  and statuses only, for the Super Admin; the public /health is status-only.
- Settings scopes (GH-159): ``UserSettingsPatch``, ``OrgSettingsPatch`` and
  ``PlatformSettingsPatch`` refuse unknown keys at every level (another
  scope's key, an org id, an LLM endpoint), take strict bools, need at least
  one value and hide their input from validation errors. Model names must
  fully match the model-name rule, the same as migration 0013's CHECK.
  ``SettingsLLM`` shows key presence flags only, never a key.
- Tool permissions per org (GH-161): ``PermissionPatch`` and
  ``CriticalPermissionPromote`` refuse unknown keys (an org id included: the
  org always comes from the session) and hide their input from validation
  errors. ``ToolPolicy`` (one org's permissions for one agent run) is frozen,
  so a loaded policy can't be changed. ``PermissionSummaryEntry`` carries a
  (tool, action) pair and its effective state only.
- Per-user connections (GH-162): ``PROVIDER_TOOLS`` (a read-only mapping)
  and ``RESIDENCY_BLOCKED_TOOLS`` (a frozenset) drive residency gating and
  can't be widened or emptied at runtime; memory is not residency-blocked.
  ``OAuthServiceStatus.tool`` is a closed Literal (``ConnectorTool``), and
  ``OAuthConnectionStatus`` / ``OrgSettingsResponse`` carry the org's
  residency flag only, never a token.
- Platform defaults (GH-160): the section patch models of
  ``PlatformSettingsPatch`` take strict ints only (a bool, float or numeric
  string is refused, never coerced) within bounds that mirror migration
  0014's CHECKs; the session and audit retention bounds are the
  ``admino.sessions`` and ``admino.audit_events`` constants.
- Models that surface free text to users (ChatResponse, ToolCallRecord,
  PendingConfirmationSummary) strip credential patterns (OAuth tokens, JWTs,
  Bearer headers) and dangerous Unicode via field validators. ``SessionSummary``
  strips control and direction-override characters from the stored user agent.
- All user-facing string fields have max_length constraints to prevent abuse.
- ToolCall.args uses dict[str, Any] because LLM output is untyped JSON;
  individual tools validate args via their own Pydantic models before execution.

Caller responsibility — ValidationError logging:
- When logging Pydantic ValidationErrors from these models, callers MUST use
  ``exc.errors(include_input=False)`` to avoid leaking raw input values.
- Never log ``str(exc)`` directly, as it embeds the offending input by default.
- This cannot be enforced inside models.py; it is a caller-side obligation.

Credential redaction limitations (defence-in-depth, not primary barrier):
- Generic ``password=`` / ``token=`` key-value pairs are not pattern-matched.
- Fernet keys (44-char base64) removed due to false-positive risk; defended by
  never formatting the key into loggable strings.
- JWT pattern only matches tokens whose first segment starts with ``ey``.
- Primary defence is never placing raw credentials in loggable fields;
  ``_strip_credentials`` is a secondary safety net.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from decimal import Decimal
from types import MappingProxyType
from typing import Annotated, Any, Final, Literal
from uuid import UUID  # noqa: TC003 — Pydantic resolves field annotations at runtime

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from admino import audit_events, sessions
from admino.access import (  # noqa: TC001 — Pydantic resolves field annotations at runtime
    MemberRole,
    PlainUUID,
    UserKind,
)
from admino.permissions import (  # noqa: TC001 — Pydantic resolves field annotations at runtime
    PermissionsConfig,
)

# Control characters to strip from free text shown to users (chat responses,
# tool-call records, confirmation summaries) and from tool output.
# Keeps tab (0x09), newline (0x0A), carriage return (0x0D) because they are
# legitimate in content.
# Strips Unicode direction-override and zero-width characters that could
# spoof displayed text in confirmation dialogs or log viewers.
_CONTROL_CHAR_TABLE: MappingProxyType[int, None] = MappingProxyType(
    dict.fromkeys(
        # C0 controls (0x00-0x1F) except tab (0x09), LF (0x0A), CR (0x0D).
        [i for i in range(32) if i not in (9, 10, 13)]
        # C1 controls (0x80-0x9F). Includes U+009B (CSI — Control Sequence
        # Introducer) which can trigger terminal escape sequences in log
        # viewers, and U+0085 (NEL) which is a Unicode line break.
        + list(range(0x80, 0xA0))
        + [
            0x200B,  # ZERO WIDTH SPACE
            0x200C,  # ZERO WIDTH NON-JOINER
            0x200D,  # ZERO WIDTH JOINER
            0x200E,  # LEFT-TO-RIGHT MARK
            0x200F,  # RIGHT-TO-LEFT MARK
            0x202A,  # LEFT-TO-RIGHT EMBEDDING
            0x202B,  # RIGHT-TO-LEFT EMBEDDING
            0x202C,  # POP DIRECTIONAL FORMATTING
            0x202D,  # LEFT-TO-RIGHT OVERRIDE
            0x202E,  # RIGHT-TO-LEFT OVERRIDE
            0x2028,  # LINE SEPARATOR
            0x2029,  # PARAGRAPH SEPARATOR
            0x2066,  # LEFT-TO-RIGHT ISOLATE
            0x2067,  # RIGHT-TO-LEFT ISOLATE
            0x2068,  # FIRST STRONG ISOLATE
            0x2069,  # POP DIRECTIONAL ISOLATE
            0xFEFF,  # BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
        ]
    )
)

# JWTs: three dot-separated base64url segments (header.payload.signature)
# Upper bound of 2048 per segment covers all real JWTs and caps worst-case scanning.
# Character class excludes = since RFC 7515 prohibits base64url padding in JWTs.
# Limitation: only matches tokens whose first segment starts with 'ey'.
# Named separately so _strip_credentials can skip it via a cheap pre-filter
# to avoid O(n^2) backtracking on long dot-free strings.
_JWT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"ey[A-Za-z0-9_\-]{16,2048}\.[A-Za-z0-9_\-]{16,2048}\.[A-Za-z0-9_\-]{16,2048}"
)

# Credential patterns redacted from free text shown to users.
# Immutable tuple prevents accidental mutation under concurrent access.
_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"1//[A-Za-z0-9_\-]{20,512}"),  # Google OAuth refresh tokens
    re.compile(r"ya29\.[A-Za-z0-9_\-]{20,512}"),  # Google OAuth access tokens (bounded)
    _JWT_PATTERN,
    # NOTE: Fernet key pattern removed — regex-based redaction is unreliable for
    # 44-char base64 strings (false positives on UUIDs/hashes, false negatives when
    # embedded in longer base64 blobs). Defence: never format the key into any
    # loggable string; keep it exclusively in memory from the env var.
    re.compile(r"Bearer\s+\S{1,2048}"),  # Bearer token header values (bounded)
    re.compile(r"GOCSPX-[A-Za-z0-9_\-]{20,80}"),  # Google OAuth client secrets
    re.compile(r"\bsk-[A-Za-z0-9\-]{20,100}\b"),  # Generic API keys (OpenAI sk-proj-*, Stripe)
    re.compile(r"rk_live_[A-Za-z0-9]{20,200}"),  # Stripe restricted keys (live)
    re.compile(r"rk_test_[A-Za-z0-9]{20,200}"),  # Stripe restricted keys (test)
    re.compile(r"gh[ps]_[A-Za-z0-9]{36,255}"),  # GitHub PATs and server tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key IDs
    # NOTE: AWS secret access keys (40-char mixed alphanumeric) are intentionally
    # omitted — the character set overlaps too broadly with UUIDs, hashes, and
    # other benign strings, causing unacceptable false-positive rates.
    re.compile(r"xox[a-z]-[A-Za-z0-9\-]{10,255}"),  # Slack tokens (all types)
)
_REDACTED: Final[str] = "[CREDENTIAL_REDACTED]"
_SANITIZED_PLACEHOLDER: Final[str] = "[SANITIZED]"


def _strip_credentials(value: str) -> str:
    """Replace known credential patterns in a string with a redaction marker.

    Applies NFKC normalization first to collapse Unicode compatibility
    characters (e.g. fullwidth Latin letters). Note: NFKC does NOT collapse
    confusable characters across scripts (e.g. Cyrillic 'a' -> Latin 'a').
    Homoglyph attacks on credential prefixes are out of scope for this
    secondary safety net. Primary defence: never place raw credentials in
    loggable fields (see module docstring).
    """
    value = unicodedata.normalize("NFKC", value)
    for pattern in _CREDENTIAL_PATTERNS:
        # Skip JWT regex on strings that cannot possibly contain a JWT
        # (no "ey" prefix or fewer than 2 dots). This avoids O(n^2)
        # backtracking in CPython's re engine on long dot-free base64
        # and prevents slow linear scans on URL-bearing strings with
        # exactly two dots.
        if pattern is _JWT_PATTERN and ("ey" not in value or value.count(".") < 2):
            continue
        value = pattern.sub(_REDACTED, value)
    return value


# ---------------------------------------------------------------------------
# API request/response models (server.py imports these)
# ---------------------------------------------------------------------------


class ChatMessage(BaseModel):
    """A single message in a conversation history.

    Note: content is NOT sanitised for control characters here. Sanitisation
    occurs at the display boundary (server.py SSE rendering). This model is used in conversation
    history and must preserve the original content for LLM context fidelity.
    """

    role: Literal["user", "assistant", "system"] = Field(
        description="The role of the message sender.",
    )
    content: str = Field(
        max_length=32768,
        description=(
            "The message content. Empty strings are allowed for"
            " assistant messages with tool-call-only responses."
        ),
    )

    @field_validator("content")
    @classmethod
    def strip_null_bytes(cls, v: str) -> str:
        """Remove null bytes which can cause silent truncation in C-based parsers."""
        return v.replace("\x00", "")


class ChatRequest(BaseModel):
    """Incoming POST /chat request body.

    Validated on receipt by the ASGI server before any processing. Unknown
    fields (e.g. a smuggled ``org_id`` or ``user_id``) are refused with a 422:
    whose chat it is comes from the session only (GH-163).
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    message: str = Field(
        min_length=1,
        max_length=32768,
        description="The user's message text.",
    )
    session_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Session identifier. Alphanumeric, hyphens, and underscores only.",
    )


class ToolCallRecord(BaseModel):
    """Summary of a tool call included in a chat response.

    The ``args`` dict is sanitized via ``_sanitize_args`` to strip known
    credential patterns from string values before the record reaches the
    API layer or any log sink.
    """

    tool: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The tool name.",
    )
    action: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The action name.",
    )
    # Any is justified here: tool call arguments are arbitrary JSON objects
    # whose schema varies per tool. Values are sanitized by _sanitize_args.
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized tool call arguments for UI display.",
    )
    permission: Literal["allow", "confirm", "deny", "disabled"] = Field(
        description="The permission decision for this tool call.",
    )
    success: bool = Field(
        description="Whether the tool call executed successfully.",
    )
    duration_ms: int | None = Field(
        default=None,
        ge=0,
        description="Execution duration in milliseconds, if available.",
    )

    @field_validator("args", mode="before")
    @classmethod
    def _sanitize_args(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Strip credential patterns from string values in args."""
        return {k: _strip_credentials(val) if isinstance(val, str) else val for k, val in v.items()}


class PendingConfirmationSummary(BaseModel):
    """Subset of ``PendingConfirmation`` safe to expose over the HTTP API.

    Excludes the internal session_id. Includes sanitized tool arguments so
    the PWA can display call details (e.g. ``query``, ``max_results``) in the
    confirmation card. The PWA also needs the confirmation ID (to POST
    /api/confirm), the tool/action being confirmed, and the expiry so it
    can show a countdown.
    """

    confirmation_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Pending confirmation identifier.",
    )
    tool: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The tool name awaiting confirmation.",
    )
    action: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The action name awaiting confirmation.",
    )
    # Any is justified here: tool call arguments are arbitrary JSON objects
    # whose schema varies per tool. Values are sanitized by _sanitize_args.
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool call arguments for display in the confirmation card.",
    )
    expires_at: datetime = Field(
        description="UTC timestamp after which this confirmation is auto-denied.",
    )

    @field_validator("args", mode="before")
    @classmethod
    def _sanitize_args(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Strip credential patterns from string values in args."""
        return {k: _strip_credentials(val) if isinstance(val, str) else val for k, val in v.items()}


class ChatResponse(BaseModel):
    """Response body from POST /chat."""

    session_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="The session identifier for this conversation.",
    )

    @field_validator("session_id")
    @classmethod
    def redact_credentials_in_session_id(cls, v: str) -> str:
        """Defence-in-depth: strip credentials from session_id."""
        return _strip_credentials(v)

    response: str = Field(
        max_length=65536,
        description="The assistant's text response.",
    )

    @field_validator("response")
    @classmethod
    def sanitize_response(cls, v: str) -> str:
        """Strip control characters and credentials from assistant response.

        Prevents XSS via LLM output containing script tags or Unicode
        direction-override characters. This is defence-in-depth — the PWA
        must also use textContent (not innerHTML) when rendering responses.
        """
        v = v.translate(_CONTROL_CHAR_TABLE)
        return _strip_credentials(v)

    tool_calls: list[ToolCallRecord] = Field(
        default_factory=list,
        max_length=50,
        description="Summary of tool calls made during this response.",
    )

    status: Literal["final", "awaiting_confirmation", "limit_reached", "error"] = Field(
        default="final",
        description=(
            "Terminal status of this agent run. When 'awaiting_confirmation', "
            "``pending_confirmation`` describes the action the user must "
            "approve or deny via POST /api/confirm/{confirmation_id}."
        ),
    )

    pending_confirmation: PendingConfirmationSummary | None = Field(
        default=None,
        description=(
            "Present only when ``status='awaiting_confirmation'``. Carries the "
            "information the PWA needs to render a confirmation card and call "
            "POST /api/confirm/{confirmation_id}. Deliberately excludes tool "
            "arguments — those may contain secrets or large content and are "
            "already summarised in ``tool_calls``."
        ),
    )


class ConfirmRequest(BaseModel):
    """Incoming POST /confirm request body.

    Used when the user approves or denies a pending confirmation. Unknown
    fields (e.g. a smuggled ``org_id`` or ``user_id``) are refused with a 422:
    whose confirmation it is comes from the session only (GH-163).
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    session_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Session identifier.",
    )
    confirmation_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Pending confirmation identifier. Alphanumeric, hyphens, underscores only.",
    )
    approved: bool = Field(
        description="Whether the user approved (True) or denied (False) the action.",
    )


class SSEEvent(BaseModel):
    """Server-sent event envelope for streaming responses."""

    event: str = Field(
        max_length=64,
        pattern=r"^[a-zA-Z0-9_.:-]+$",
        description="SSE event type. No newlines — prevents SSE frame injection.",
    )
    data: str = Field(
        max_length=65536,
        description="The JSON-encoded event payload.",
    )

    @field_validator("data")
    @classmethod
    def sanitize_sse_data(cls, v: str) -> str:
        """Encode bare newlines to prevent SSE frame injection.

        SSE uses '\\n\\n' as a frame delimiter. Literal newlines in data
        would inject synthetic SSE frames. This validator replaces them with
        the two-character literal sequence backslash-n.

        Contract: callers write ev.data directly into SSE 'data:' lines
        (one data: prefix per logical line). The sanitised value is safe for
        raw text insertion. If callers JSON-encode ev.data first, the backslash
        is further escaped by JSON serialisation -- consumers must decode JSON
        before interpreting newlines.

        Pre-existing literal backslash-n sequences in input are preserved
        unchanged (they are not real newlines and pose no injection risk).

        Control characters are stripped first via _CONTROL_CHAR_TABLE to prevent
        U+0085 NEL and U+2028/U+2029 line/paragraph separators from bypassing
        the newline sanitisation (they are removed before newline replacement).
        """
        v = v.translate(_CONTROL_CHAR_TABLE)
        return v.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")


# ---------------------------------------------------------------------------
# Agent / LLM models (agent.py and llm.py import these)
# ---------------------------------------------------------------------------


class ToolCall(BaseModel):
    """A tool call requested by the LLM.

    The args field uses dict[str, Any] because LLM output is untyped JSON.
    Individual tool executors validate args against their own Pydantic schemas
    before execution, so type safety is enforced at the tool boundary.
    """

    tool: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="Tool name — lowercase alphanumeric and underscores only (e.g. 'gmail').",
    )
    action: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="Action name — lowercase alphanumeric and underscores only (e.g. 'read').",
    )
    # Any is justified here: LLM tool-call arguments are arbitrary JSON objects.
    # Each tool validates its own args via a dedicated Pydantic model before execution.
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw arguments from the LLM. Validated by individual tool schemas.",
    )
    tool_call_id: str | None = Field(
        default=None,
        max_length=128,
        description=(
            "Provider-assigned ID linking this tool call to its result. "
            "Required by Anthropic (tool_use id) and OpenAI (tool_calls[].id) "
            "for multi-turn tool calling."
        ),
    )

    @field_validator("args")
    @classmethod
    def limit_args_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Reject args payloads exceeding 64 KiB to prevent memory abuse."""
        import json

        if len(json.dumps(v, default=str)) > 65536:
            msg = "args payload exceeds 64 KiB limit"
            raise ValueError(msg)
        return v


class LLMMessage(BaseModel):
    """A message in the LLM context window.

    Represents messages sent to and received from the LLM provider's chat API.

    Note: content is NOT sanitised for control characters at this layer.
    Sanitisation is applied at the LLM client boundary (llm.py
    _strip_control_chars). Raw content is preserved here for context-window fidelity.
    """

    role: Literal["user", "assistant", "system", "tool"] = Field(
        description="The role of the message in the LLM context.",
    )
    content: str = Field(
        max_length=65536,
        description=(
            "The message content. Empty strings are valid for tool responses with empty results."
        ),
    )
    tool_call_id: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Identifier linking a tool response to its originating call.",
    )
    tool_use_blocks: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "Structured tool_use blocks for providers that require them in the assistant "
            "message (e.g. Anthropic). Each entry has type, id, name (dot notation), "
            "and input. The OpenAI-compatible serializer replays them as tool_calls."
        ),
    )


class AgentConfig(BaseModel):
    """Runtime configuration for the agent loop.

    Separate from AppConfig (which covers the full application). AgentConfig
    controls agent-specific behavior limits. Its bounds hold every stored
    platform limit (GH-160), so a run's config can be built from them.
    """

    max_tool_calls: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum tool calls the agent may make per user message.",
    )
    max_context_messages: int = Field(
        default=40,
        ge=1,
        le=200,
        description=(
            "Maximum conversation messages sent as LLM context. The system"
            " prompt and the current user message are always sent."
        ),
    )
    confirmation_timeout_s: float = Field(
        default=30.0,
        ge=1.0,
        le=3600.0,
        description="Seconds before an unconfirmed action is automatically denied.",
    )


class PendingConfirmation(BaseModel):
    """A tool call awaiting user confirmation.

    Created when the permission engine returns 'confirm' for a tool call.
    The user must approve or deny before expires_at.
    """

    confirmation_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Unique identifier for this pending confirmation.",
    )
    session_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Session in which this confirmation was requested.",
    )
    tool_call: ToolCall = Field(
        description="The tool call awaiting confirmation.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of when the confirmation was created.",
    )
    expires_at: datetime = Field(
        description="UTC timestamp after which the confirmation is auto-denied.",
    )

    @model_validator(mode="after")
    def validate_expiry(self) -> PendingConfirmation:
        """Ensure expires_at is timezone-aware and after created_at."""
        if self.expires_at.tzinfo is None:
            msg = "expires_at must be timezone-aware"
            raise ValueError(msg)
        if self.expires_at <= self.created_at:
            msg = "expires_at must be after created_at"
            raise ValueError(msg)
        return self


AgentStatus = Literal["final", "awaiting_confirmation", "limit_reached", "error"]
"""Terminal status of an agent run.

- ``final``: the LLM produced a plain text response; history contains it.
- ``awaiting_confirmation``: a tool call requires user confirmation; the caller
  must resume by calling ``Agent.run`` again with ``pending_confirmation`` set.
- ``limit_reached``: the agent exhausted ``AgentConfig.max_tool_calls`` without
  producing a final text response.
- ``error``: an upstream error (e.g. LLM client failure) prevented completion;
  ``response`` contains a safe human-readable message, never raw exception data.
"""


class AgentResult(BaseModel):
    """Result of a single ``Agent.run`` invocation.

    The caller owns conversation history: the agent returns the full updated
    ``history`` (user turn + any assistant/tool turns added during the run) so
    the caller can persist it. It never contains ``system`` messages — the
    agent adds its system prompt to each LLM call itself, so feeding the
    history back cannot duplicate it. ``tool_calls`` is a summary for the HTTP
    response layer; the authoritative, content-free record of each dispatch is
    its ``tool.call`` audit event.
    """

    status: AgentStatus = Field(
        description="Terminal status of the agent run.",
    )
    response: str = Field(
        default="",
        max_length=65536,
        description=(
            "Assistant text to surface to the user. Empty when the agent"
            " terminates without producing text (should not happen in"
            " practice — always populated with a terminal message)."
        ),
    )
    history: list[LLMMessage] = Field(
        default_factory=list,
        max_length=1000,
        description=(
            "Updated conversation history including this turn's additions."
            " User/assistant/tool messages only; excludes the system prompt."
        ),
    )
    tool_calls: list[ToolCallRecord] = Field(
        default_factory=list,
        max_length=50,
        description="Summary of tool calls dispatched during this run.",
    )
    pending_confirmation: PendingConfirmation | None = Field(
        default=None,
        description=(
            "Set when ``status == 'awaiting_confirmation'``. The caller must"
            " persist this and pass it back on the resumption call."
        ),
    )


# ---------------------------------------------------------------------------
# Tool argument models (individual tools import these)
# ---------------------------------------------------------------------------


class MemoryStoreArgs(BaseModel):
    """Arguments for the memory.store action (upsert a key-value note)."""

    key: str = Field(
        max_length=200,
        pattern=r"^[a-zA-Z0-9_.\- ]+$",
        description="Unique key for the memory entry. Alphanumeric, dots, hyphens, underscores.",
    )
    value: str = Field(
        max_length=2000,
        description="The value to store.",
    )


class MemoryRecallArgs(BaseModel):
    """Arguments for the memory.recall action (retrieve a value by key)."""

    key: str = Field(
        max_length=200,
        pattern=r"^[a-zA-Z0-9_.\- ]+$",
        description="The key to look up. Alphanumeric, dots, hyphens, underscores.",
    )


class MemoryListArgs(BaseModel):
    """Arguments for the memory.list action (list all stored keys)."""


# ---------------------------------------------------------------------------
# Shared email validation helpers (used by GmailSendArgs, OutlookSendArgs)
# ---------------------------------------------------------------------------

_EMAIL_ADDRESS_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)


def _validate_email_list(v: list[str]) -> list[str]:
    """Validate each email address in a list.

    Rejects addresses with control characters, newlines, or missing @.
    Intentionally strict to prevent header injection.
    """
    for addr in v:
        if not isinstance(addr, str) or not _EMAIL_ADDRESS_RE.match(addr):
            msg = f"Invalid email address: {addr!r}"
            raise ValueError(msg)
    return v


def _reject_control_chars(v: str, field_name: str) -> str:
    """Reject strings containing CR, LF, or null bytes.

    Defence-in-depth against header injection and log spoofing. The email
    transport layer (stdlib EmailMessage for Gmail, JSON for Graph) also
    prevents injection, but we reject at the model boundary.
    """
    if "\r" in v or "\n" in v or "\x00" in v:
        msg = f"{field_name} must not contain CR, LF, or null bytes"
        raise ValueError(msg)
    return v


# ---------------------------------------------------------------------------
# Gmail tool argument models (tools/gmail.py imports these)
# ---------------------------------------------------------------------------


class GmailSearchArgs(BaseModel):
    """Arguments for the gmail.search action."""

    query: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[\x20-\x7E]+$",
        description="Gmail search query (printable ASCII only).",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of messages to return.",
    )


class GmailReadArgs(BaseModel):
    """Arguments for the gmail.read action."""

    message_id: str = Field(
        pattern=r"^[a-zA-Z0-9]+$",
        max_length=64,
        description="Gmail message ID.",
    )


class GmailListArgs(BaseModel):
    """Arguments for the gmail.list action."""

    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of messages to return.",
    )


class GmailSendArgs(BaseModel):
    """Arguments for the gmail.send action (requires promotion + confirm).

    Email addresses are validated with a basic pattern that rejects obvious
    injection attempts (newlines, control chars). The stdlib ``email`` module
    handles RFC 2822 encoding safely.
    """

    to: list[str] = Field(
        min_length=1,
        max_length=20,
        description="Recipient email addresses (1-20).",
    )
    subject: str = Field(
        default="",
        max_length=500,
        description="Email subject line.",
    )
    body: str = Field(
        max_length=50_000,
        description="Plain-text email body (max 50 000 chars).",
    )
    cc: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="CC recipients (optional, max 20).",
    )
    bcc: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="BCC recipients (optional, max 20).",
    )

    @field_validator("to", "cc", "bcc", mode="before")
    @classmethod
    def _validate_email_addresses(cls, v: list[str]) -> list[str]:
        return _validate_email_list(v)

    @field_validator("subject", mode="after")
    @classmethod
    def _validate_subject(cls, v: str) -> str:
        return _reject_control_chars(v, "subject")

    @field_validator("body", mode="after")
    @classmethod
    def _validate_body(cls, v: str) -> str:
        return _reject_control_chars(v, "body")


# ---------------------------------------------------------------------------
# Google Calendar tool argument models (tools/google_calendar.py imports these)
# ---------------------------------------------------------------------------


class GoogleCalendarListArgs(BaseModel):
    """Arguments for the google_calendar.list action."""

    time_min: datetime = Field(
        description="Start of the time range (ISO 8601 UTC).",
    )
    time_max: datetime = Field(
        description="End of the time range (ISO 8601 UTC).",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of events to return.",
    )


class GoogleCalendarReadArgs(BaseModel):
    """Arguments for the google_calendar.read action."""

    event_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_]+$",
        description="Google Calendar event ID.",
    )


class GoogleCalendarCreateArgs(BaseModel):
    """Arguments for the google_calendar.create action (requires confirm)."""

    summary: str = Field(
        max_length=200,
        description="Event title.",
    )
    start: datetime = Field(
        description="Event start time (ISO 8601 UTC).",
    )
    end: datetime = Field(
        description="Event end time (ISO 8601 UTC).",
    )
    description: str = Field(
        default="",
        max_length=1000,
        description="Event description.",
    )
    location: str = Field(
        default="",
        max_length=200,
        description="Event location.",
    )


class GoogleCalendarUpdateArgs(BaseModel):
    """Arguments for the google_calendar.update action (tier-2, requires promotion + confirm).

    All fields except ``event_id`` are optional; only the provided fields are
    sent in the partial (PATCH) update. ``event_id`` is constrained to safe
    characters to prevent path traversal in the Calendar API URL, and attendee
    addresses are validated to reject injection.
    """

    event_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_]+$",
        description="Google Calendar event ID to update.",
    )
    summary: str | None = Field(
        default=None,
        max_length=200,
        description="New event title.",
    )
    description: str | None = Field(
        default=None,
        max_length=1000,
        description="New event description.",
    )
    start: datetime | None = Field(
        default=None,
        description="New event start time (ISO 8601 UTC).",
    )
    end: datetime | None = Field(
        default=None,
        description="New event end time (ISO 8601 UTC).",
    )
    location: str | None = Field(
        default=None,
        max_length=200,
        description="New event location.",
    )
    attendees: list[str] | None = Field(
        default=None,
        max_length=50,
        description="Replacement attendee email addresses (max 50).",
    )

    @field_validator("attendees", mode="before")
    @classmethod
    def _validate_attendees(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return _validate_email_list(v)


# ---------------------------------------------------------------------------
# Google Drive tool argument models (tools/google_drive.py imports these)
# ---------------------------------------------------------------------------


class GoogleDriveListArgs(BaseModel):
    """Arguments for the google_drive.list action."""

    # SECURITY: The pattern MUST exclude single quotes — folder_id is interpolated
    # into a Drive API q= query string in google_drive.py google_drive_list().
    folder_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Folder ID to list. None = root. Only alphanumeric, hyphens, underscores.",
    )
    max_results: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of files to return.",
    )


class GoogleDriveReadArgs(BaseModel):
    """Arguments for the google_drive.read action."""

    file_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Google Drive file ID.",
    )


class GoogleDriveSearchArgs(BaseModel):
    """Arguments for the google_drive.search action."""

    query: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[^'\\]+$",
        description="Search query for Google Drive files. No quotes or backslashes.",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of results to return.",
    )


# ---------------------------------------------------------------------------
# Outlook (Microsoft Graph) tool argument models (tools/outlook.py imports these)
# ---------------------------------------------------------------------------


class OutlookSearchArgs(BaseModel):
    """Arguments for the outlook.search action."""

    query: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[a-zA-Z0-9 ._@\-]+$",
        description="Search query for Outlook messages. Alphanumeric, spaces, dots, @, hyphens.",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of messages to return.",
    )


# ---------------------------------------------------------------------------
# Microsoft Graph resource ID validation
# ---------------------------------------------------------------------------
# Graph message/drive-item IDs are base64/base64url and contain '=', '+', '/';
# OneDrive *personal* item IDs may also contain '!'. These IDs are URL-encoded
# with quote(safe="") before being interpolated into the Graph request path
# (see outlook.py / onedrive.py), so the characters cannot alter the URL path.
# The bounded, anchored patterns below are defense-in-depth; the length cap
# matches the calendar event-ID cap since Graph IDs can exceed 200 chars. The
# first character is restricted to a non-slash so a value cannot begin with '/'
# (real Graph IDs never do); '.' is excluded entirely to block '..' sequences.
_GRAPH_ID_MAX_LEN: Final[int] = 512
_GRAPH_MESSAGE_ID_PATTERN: Final[str] = r"^[A-Za-z0-9_\-][A-Za-z0-9_\-=+/]*$"
_GRAPH_ITEM_ID_PATTERN: Final[str] = r"^[A-Za-z0-9_\-!][A-Za-z0-9_\-=+/!]*$"


class OutlookReadArgs(BaseModel):
    """Arguments for the outlook.read action."""

    message_id: str = Field(
        min_length=1,
        max_length=_GRAPH_ID_MAX_LEN,
        pattern=_GRAPH_MESSAGE_ID_PATTERN,
        description="Outlook message ID.",
    )


class OutlookListArgs(BaseModel):
    """Arguments for the outlook.list action."""

    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of messages to return.",
    )


class OutlookSendArgs(BaseModel):
    """Arguments for the outlook.send action (requires promotion + confirm).

    Email addresses are validated with a basic pattern that rejects obvious
    injection attempts (newlines, control chars). The JSON payload structure
    of Microsoft Graph prevents header injection by design.
    """

    to: list[str] = Field(
        min_length=1,
        max_length=20,
        description="Recipient email addresses (1-20).",
    )
    subject: str = Field(
        default="",
        max_length=500,
        description="Email subject line.",
    )
    body: str = Field(
        max_length=50_000,
        description="Plain-text email body (max 50 000 chars).",
    )
    cc: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="CC recipients (optional, max 20).",
    )
    bcc: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="BCC recipients (optional, max 20).",
    )

    @field_validator("to", "cc", "bcc", mode="before")
    @classmethod
    def _validate_email_addresses(cls, v: list[str]) -> list[str]:
        return _validate_email_list(v)

    @field_validator("subject", mode="after")
    @classmethod
    def _validate_subject(cls, v: str) -> str:
        return _reject_control_chars(v, "subject")

    @field_validator("body", mode="after")
    @classmethod
    def _validate_body(cls, v: str) -> str:
        return _reject_control_chars(v, "body")


# ---------------------------------------------------------------------------
# Outlook Calendar (Microsoft Graph) tool argument models
# ---------------------------------------------------------------------------


class OutlookCalendarListArgs(BaseModel):
    """Arguments for the outlook_calendar.list action."""

    time_min: datetime = Field(
        description="Start of the time range (ISO 8601 UTC).",
    )
    time_max: datetime = Field(
        description="End of the time range (ISO 8601 UTC).",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of events to return.",
    )


# Microsoft Graph event IDs are base64 strings that legitimately contain
# '=', '/', and '+' (as well as '-' and '_'). They are interpolated into the
# Graph REST path, so the tool handlers URL-encode them (urllib.parse.quote,
# safe="") before use — that encoding, not this charset, is the path-traversal
# defence. This pattern is a permissive allow-list that still rejects
# whitespace, control characters, '.', and other unexpected input. The length
# cap is generous because recurring-instance / immutable IDs can be long.
_GRAPH_EVENT_ID_PATTERN: Final[str] = r"^[A-Za-z0-9_\-=+/]+$"
_GRAPH_EVENT_ID_MAX_LEN: Final[int] = 512


class OutlookCalendarReadArgs(BaseModel):
    """Arguments for the outlook_calendar.read action."""

    event_id: str = Field(
        min_length=1,
        max_length=_GRAPH_EVENT_ID_MAX_LEN,
        pattern=_GRAPH_EVENT_ID_PATTERN,
        description="Outlook Calendar event ID.",
    )


class OutlookCalendarCreateArgs(BaseModel):
    """Arguments for the outlook_calendar.create action (requires confirm)."""

    subject: str = Field(
        max_length=200,
        description="Event subject.",
    )
    start: datetime = Field(
        description="Event start time (ISO 8601 UTC).",
    )
    end: datetime = Field(
        description="Event end time (ISO 8601 UTC).",
    )
    body: str = Field(
        default="",
        max_length=1000,
        description="Event body/description.",
    )
    location: str = Field(
        default="",
        max_length=200,
        description="Event location.",
    )


class OutlookCalendarUpdateArgs(BaseModel):
    """Arguments for the outlook_calendar.update action (tier-2, requires promotion + confirm).

    All fields except ``event_id`` are optional; only the provided fields are
    sent in the partial (PATCH) update. ``event_id`` allows the Microsoft Graph
    base64 charset; the handler URL-encodes it to prevent path traversal in the
    Graph API URL, and attendee addresses are validated to reject injection.
    """

    event_id: str = Field(
        min_length=1,
        max_length=_GRAPH_EVENT_ID_MAX_LEN,
        pattern=_GRAPH_EVENT_ID_PATTERN,
        description="Outlook Calendar event ID to update.",
    )
    subject: str | None = Field(
        default=None,
        max_length=200,
        description="New event subject.",
    )
    body: str | None = Field(
        default=None,
        max_length=1000,
        description="New event body/description.",
    )
    start: datetime | None = Field(
        default=None,
        description="New event start time (ISO 8601 UTC).",
    )
    end: datetime | None = Field(
        default=None,
        description="New event end time (ISO 8601 UTC).",
    )
    location: str | None = Field(
        default=None,
        max_length=200,
        description="New event location.",
    )
    attendees: list[str] | None = Field(
        default=None,
        max_length=50,
        description="Replacement attendee email addresses (max 50).",
    )

    @field_validator("attendees", mode="before")
    @classmethod
    def _validate_attendees(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return _validate_email_list(v)


# ---------------------------------------------------------------------------
# OneDrive (Microsoft Graph) tool argument models (tools/onedrive.py imports these)
# ---------------------------------------------------------------------------


class OneDriveListArgs(BaseModel):
    """Arguments for the onedrive.list action."""

    folder_path: str | None = Field(
        default=None,
        min_length=1,
        max_length=500,
        pattern=r"^[a-zA-Z0-9 ._/\-]+$",
        description="Folder path to list. None = root. Only safe path chars allowed.",
    )
    max_results: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of items to return.",
    )


class OneDriveReadArgs(BaseModel):
    """Arguments for the onedrive.read action."""

    item_id: str = Field(
        min_length=1,
        max_length=_GRAPH_ID_MAX_LEN,
        pattern=_GRAPH_ITEM_ID_PATTERN,
        description="OneDrive item ID.",
    )


class OneDriveSearchArgs(BaseModel):
    """Arguments for the onedrive.search action."""

    query: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[^'\\]+$",
        description="Search query for OneDrive files. No quotes or backslashes.",
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of results to return.",
    )


# ---------------------------------------------------------------------------
# Settings API models: the user, org and platform scopes (GH-159)
# ---------------------------------------------------------------------------

# A model name: letters, digits, '_', '.', ':', '/' and '-', starting with a
# letter or digit, at most 200 characters. Always used with fullmatch (Python's
# '$' would accept a trailing newline). Migration 0013's CHECK on the
# platform_settings model columns is the same rule.
_MODEL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}")
_MODEL_NAME_ERROR: Final = "Model name contains invalid characters."


class SettingsLLM(BaseModel):
    """The platform LLM as GET/PATCH /api/platform/settings shows it (Super Admin).

    Credentials are never exposed: only ``*_configured`` boolean flags.
    """

    provider: Literal["infomaniak", "anthropic", "openai", "vllm"]
    anthropic_model: str = Field(max_length=200)
    openai_model: str = Field(max_length=200)
    infomaniak_model: str = Field(default="", max_length=200)
    # Model IDs the Infomaniak product lists (empty unless infomaniak is active
    # and reachable).
    infomaniak_available_models: list[str] = Field(default_factory=list)
    vllm_model: str = Field(default="", max_length=200)
    # Model IDs the local vLLM endpoint reports as served (empty if unreachable).
    vllm_available_models: list[str] = Field(default_factory=list)
    # Boolean flags — never expose actual API key or token values.
    anthropic_key_configured: bool = False
    openai_key_configured: bool = False
    infomaniak_token_configured: bool = False

    @field_validator("anthropic_model", "openai_model", "infomaniak_model", "vllm_model")
    @classmethod
    def validate_model_name(cls, v: str) -> str:
        """Reject model names containing shell metacharacters or control chars.

        An empty string is allowed: a model that isn't set (NULL in
        ``platform_settings``) is shown blank.
        """
        if v and _MODEL_NAME_RE.fullmatch(v) is None:
            raise ValueError(_MODEL_NAME_ERROR)
        return v

    @field_validator("vllm_available_models", "infomaniak_available_models")
    @classmethod
    def filter_available_models(cls, v: list[str]) -> list[str]:
        """Drop served-model ids that are not well-formed model names.

        ``vllm_available_models`` is populated from the local vLLM server's
        ``/v1/models`` response and ``infomaniak_available_models`` from the
        Infomaniak models endpoint — input from outside admino's trust
        boundary. A rogue or compromised server (or a MITM on the non-TLS
        local vLLM connection) could return ids with unexpected characters.
        Keep only ids matching the same allowlist enforced on user-supplied
        model names, and bound the count, so a malicious server cannot spoof
        the settings response or smuggle characters past downstream sanitisers.
        """
        return [m for m in v if isinstance(m, str) and _MODEL_NAME_RE.fullmatch(m)][:64]


class SettingsAppearance(BaseModel):
    """Appearance settings (user scope)."""

    theme: Literal["light", "dark", "system"] = "light"


class SettingsNotifications(BaseModel):
    """Notification preferences (user scope).

    ``enabled``: the tool-approval pings (on by default). ``task_done``: the
    task-done pings (GH-35), off by default because switching them on asks the
    browser for notification permission. Neither is a master switch for the other.
    """

    enabled: bool = True
    task_done: bool = False


class OAuthAuthorizeResponse(BaseModel):
    """GET /api/oauth/google/authorize response — consent URL for the frontend."""

    url: str = Field(max_length=2048, pattern=r"^https://")


# The tools of the Google and Microsoft OAuth providers (their "services", GH-162).
ConnectorTool = Literal[
    "gmail", "google_calendar", "google_drive", "outlook", "outlook_calendar", "onedrive"
]

# Each OAuth provider's tools, in the order the connection status lists them.
PROVIDER_TOOLS: Final[MappingProxyType[str, tuple[ConnectorTool, ...]]] = MappingProxyType(
    {
        "google": ("gmail", "google_calendar", "google_drive"),
        "microsoft": ("outlook", "outlook_calendar", "onedrive"),
    }
)

# The tools an org's data residency policy switches off: every provider's tools
# (memory stays on: it never leaves the server).
RESIDENCY_BLOCKED_TOOLS: Final[frozenset[str]] = frozenset(
    tool for tools in PROVIDER_TOOLS.values() for tool in tools
)


class OAuthServiceStatus(BaseModel):
    """One service of an OAuth provider and the org's stored switch for it (GH-162)."""

    tool: ConnectorTool
    enabled: bool


class OAuthConnectionStatus(BaseModel):
    """The caller's own connection to an OAuth provider (GH-162: per user).

    ``connected`` means the caller has a token row for the provider.
    ``healthy`` means the stored refresh token is still believed valid (not
    flagged dead after a terminal refresh failure). The frontend treats
    ``connected and not healthy`` the same as "Not connected" — prompting a
    fresh Connect. ``data_residency`` is the caller's org's residency policy:
    connecting is refused and a stored connection is inactive. ``services``
    lists the provider's tools (``PROVIDER_TOOLS`` order), each with the
    org's stored switch.
    """

    connected: bool = False
    healthy: bool = False
    email: str | None = Field(
        default=None,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    )
    data_residency: bool = False
    services: list[OAuthServiceStatus] = Field(default_factory=list)


class ToolsSettings(BaseModel):
    """Per-tool enabled/disabled state (the org scope's tool services).

    Each field corresponds to a registered tool name and maps to an
    ``org_settings.<tool>_enabled`` column. Default is True (enabled) for
    all tools, like the column defaults of migration 0013.

    strict=True: a non-boolean value (e.g. a ``"false"`` string) raises
    ``ValidationError`` instead of being silently coerced to ``True`` and
    re-enabling a service that was turned off (GH-80 security gate).

    Unknown keys are dropped, so a legacy ``files`` toggle (removed in
    GH-143) is never reported.
    """

    model_config = ConfigDict(strict=True)

    gmail: bool = True
    google_calendar: bool = True
    google_drive: bool = True
    outlook: bool = True
    outlook_calendar: bool = True
    onedrive: bool = True
    memory: bool = True


class SettingsPatchLLM(BaseModel):
    """Partial platform LLM settings for PATCH /api/platform/settings.

    Only the provider and the four model names can be changed: every other
    key (an endpoint URL, a timeout, a key) is refused. A model name must
    fully match ``[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,199}``, the database CHECK of
    migration 0013 (so a trailing newline is refused here, not by the
    database). Validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    provider: Literal["infomaniak", "anthropic", "openai", "vllm"] | None = None
    anthropic_model: str | None = Field(default=None, max_length=200)
    openai_model: str | None = Field(default=None, max_length=200)
    infomaniak_model: str | None = Field(default=None, max_length=200)
    vllm_model: str | None = Field(default=None, max_length=200)

    @field_validator("anthropic_model", "openai_model", "infomaniak_model", "vllm_model")
    @classmethod
    def validate_model_name(cls, v: str | None) -> str | None:
        """Refuse a model name that isn't a full match of the model-name rule.

        Runs after the type and length checks: a non-string or a name over 200
        characters is already a validation error. The message never includes
        the value.
        """
        if v is None:
            return v
        if not isinstance(v, str) or _MODEL_NAME_RE.fullmatch(v) is None:
            raise ValueError(_MODEL_NAME_ERROR)
        return v


class SettingsPatchAppearance(BaseModel):
    """Partial appearance settings for PATCH /api/me/settings."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    theme: Literal["light", "dark", "system"] | None = None


class SettingsPatchNotifications(BaseModel):
    """Partial notification settings for PATCH /api/me/settings (strict bools)."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    enabled: StrictBool | None = None
    task_done: StrictBool | None = None


class UserSettingsResponse(BaseModel):
    """GET/PATCH /api/me/settings response: the caller's own theme and notifications."""

    appearance: SettingsAppearance
    notifications: SettingsNotifications


class UserSettingsPatch(BaseModel):
    """PATCH /api/me/settings request body: the caller's theme and/or notifications.

    Another scope's key (llm, tools, limits), a language or a user id is
    refused, never ignored. A null counts as not given, and at least one value
    must be given. Validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    appearance: SettingsPatchAppearance | None = None
    notifications: SettingsPatchNotifications | None = None

    @model_validator(mode="after")
    def _check_something_given(self) -> UserSettingsPatch:
        """Refuse a patch that changes nothing."""
        theme = None if self.appearance is None else self.appearance.theme
        notifications = self.notifications or SettingsPatchNotifications()
        if theme is None and notifications.enabled is None and notifications.task_done is None:
            msg = "Give at least one setting to change."
            raise ValueError(msg)
        return self


class OrgSettingsResponse(BaseModel):
    """GET/PATCH /api/org/settings response: the Org Admin's own org's tool services.

    ``data_residency`` (GH-162) is the org's residency policy, read-only here:
    when on, the Google and Microsoft services are off for every run whatever
    their stored switch says.
    """

    tools: ToolsSettings
    data_residency: bool


class OrgToolsPatch(BaseModel):
    """The tool services to switch on or off; a null (or a missing tool) is not given.

    Strict bools only; an unknown tool (e.g. the removed ``files`` toggle) is
    refused, never ignored.
    """

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    gmail: bool | None = None
    google_calendar: bool | None = None
    google_drive: bool | None = None
    outlook: bool | None = None
    outlook_calendar: bool | None = None
    onedrive: bool | None = None
    memory: bool | None = None


class OrgSettingsPatch(BaseModel):
    """PATCH /api/org/settings request body: at least one tool service to change.

    The org is always the caller's own: an ``org_id`` (or any other key) in
    the body is refused. Validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    tools: OrgToolsPatch

    @model_validator(mode="after")
    def _check_something_given(self) -> OrgSettingsPatch:
        """Refuse a patch that names no tool."""
        if not self.tools.model_dump(exclude_none=True):
            msg = "Give at least one tool to change."
            raise ValueError(msg)
        return self


# The bounds of each platform default (GH-160), shared by its response and
# patch fields and mirrored by migration 0013's (limits) and 0014's CHECKs.
_ToolCallsPerMessage = Annotated[int, Field(ge=1, le=100)]
_PendingConfirmations = Annotated[int, Field(ge=1, le=50)]
_ConfirmationTimeoutS = Annotated[int, Field(ge=10, le=3600)]
_MessageLength = Annotated[int, Field(ge=1, le=100_000)]
_ContextMessages = Annotated[int, Field(ge=1, le=200)]
_FileSizeMb = Annotated[int, Field(ge=1, le=500)]
_FilesPerMessage = Annotated[int, Field(ge=1, le=50)]
_PagesPerFile = Annotated[int, Field(ge=1, le=1000)]
_RenderDpi = Annotated[int, Field(ge=72, le=300)]
_TrashDays = Annotated[int, Field(ge=0, le=90)]
_AuditMonths = Annotated[
    int,
    Field(ge=audit_events.MIN_RETENTION_MONTHS, le=audit_events.MAX_RETENTION_MONTHS),
]
_GraceDays = Annotated[int, Field(ge=7, le=90)]
_RequestsPerMinute = Annotated[int, Field(ge=1, le=600)]
_LockoutFailures = Annotated[int, Field(ge=3, le=100)]
_LockoutMinutes = Annotated[int, Field(ge=1, le=1440)]
_IdleTimeoutMinutes = Annotated[
    int,
    Field(ge=sessions.MIN_IDLE_TIMEOUT_MINUTES, le=sessions.MAX_IDLE_TIMEOUT_MINUTES),
]
_LifetimeHours = Annotated[
    int, Field(ge=sessions.MIN_LIFETIME_HOURS, le=sessions.MAX_LIFETIME_HOURS)
]
_TRASH_ORDER_ERROR: Final = "The trash retention minimum can't exceed the maximum."


class PlatformLimits(BaseModel):
    """The platform limits, with ``LimitsConfig``'s bounds (editable since GH-160)."""

    max_tool_calls_per_message: _ToolCallsPerMessage
    max_pending_confirmations: _PendingConfirmations
    confirmation_timeout_s: _ConfirmationTimeoutS
    max_message_length: _MessageLength
    max_context_messages: _ContextMessages


class PlatformFiles(BaseModel):
    """The platform file limits (GH-160): size in MB, files per message, pages, render DPI."""

    max_file_size_mb: _FileSizeMb = 50
    max_files_per_message: _FilesPerMessage = 10
    max_pages_per_file: _PagesPerFile = 100
    render_dpi: _RenderDpi = 150


class PlatformRetention(BaseModel):
    """The platform retention (GH-160): trash bounds in days, audit months, grace days.

    The trash minimum can't exceed the maximum; the message never repeats the
    values.
    """

    trash_min_days: _TrashDays = 0
    trash_max_days: _TrashDays = 90
    audit_months: _AuditMonths = audit_events.DEFAULT_RETENTION_MONTHS
    org_deletion_grace_days: _GraceDays = 30

    @model_validator(mode="after")
    def _check_trash_order(self) -> PlatformRetention:
        """Refuse a trash minimum above the trash maximum."""
        if self.trash_min_days > self.trash_max_days:
            raise ValueError(_TRASH_ORDER_ERROR)
        return self


class PlatformSecurity(BaseModel):
    """The platform security (GH-160): rate limit, login lockout, Super Admin sessions.

    The session bounds are ``admino.sessions``' (migration 0009's CHECKs).
    """

    rate_limit_per_minute: _RequestsPerMinute = 20
    lockout_after_failures: _LockoutFailures = 10
    lockout_window_minutes: _LockoutMinutes = 15
    lockout_minutes: _LockoutMinutes = 15
    session_idle_timeout_minutes: _IdleTimeoutMinutes = sessions.DEFAULT_IDLE_TIMEOUT_MINUTES
    session_max_lifetime_hours: _LifetimeHours = sessions.DEFAULT_LIFETIME_HOURS


class PlatformSettingsResponse(BaseModel):
    """GET/PATCH /api/platform/settings response (Super Admin): the five sections.

    No content and no secret: key presence flags only.
    """

    llm: SettingsLLM
    limits: PlatformLimits
    files: PlatformFiles
    retention: PlatformRetention
    security: PlatformSecurity


class PlatformLimitsPatch(BaseModel):
    """The platform limits to change: strict ints within the bounds, a null not given."""

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    max_tool_calls_per_message: _ToolCallsPerMessage | None = None
    max_pending_confirmations: _PendingConfirmations | None = None
    confirmation_timeout_s: _ConfirmationTimeoutS | None = None
    max_message_length: _MessageLength | None = None
    max_context_messages: _ContextMessages | None = None


class PlatformFilesPatch(BaseModel):
    """The platform file limits to change: strict ints within the bounds, a null not given."""

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    max_file_size_mb: _FileSizeMb | None = None
    max_files_per_message: _FilesPerMessage | None = None
    max_pages_per_file: _PagesPerFile | None = None
    render_dpi: _RenderDpi | None = None


class PlatformRetentionPatch(BaseModel):
    """The platform retention to change: strict ints within the bounds, a null not given.

    The trash order isn't checked here: the service checks the patch merged
    into the stored values.
    """

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    trash_min_days: _TrashDays | None = None
    trash_max_days: _TrashDays | None = None
    audit_months: _AuditMonths | None = None
    org_deletion_grace_days: _GraceDays | None = None


class PlatformSecurityPatch(BaseModel):
    """The platform security to change: strict ints within the bounds, a null not given."""

    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)

    rate_limit_per_minute: _RequestsPerMinute | None = None
    lockout_after_failures: _LockoutFailures | None = None
    lockout_window_minutes: _LockoutMinutes | None = None
    lockout_minutes: _LockoutMinutes | None = None
    session_idle_timeout_minutes: _IdleTimeoutMinutes | None = None
    session_max_lifetime_hours: _LifetimeHours | None = None


class PlatformSettingsPatch(BaseModel):
    """PATCH /api/platform/settings request body: the platform defaults to change.

    Five optional sections (llm, limits, files, retention, security); any
    other key, top-level or nested, is refused. At least one value must be
    given: an empty section or a null counts as not given. Validation errors
    never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    llm: SettingsPatchLLM | None = None
    limits: PlatformLimitsPatch | None = None
    files: PlatformFilesPatch | None = None
    retention: PlatformRetentionPatch | None = None
    security: PlatformSecurityPatch | None = None

    @model_validator(mode="after")
    def _check_something_given(self) -> PlatformSettingsPatch:
        """Refuse a patch that gives no value in any section."""
        sections = (self.llm, self.limits, self.files, self.retention, self.security)
        if not any(section.model_dump(exclude_none=True) for section in sections if section):
            msg = "Give at least one setting to change."
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# Permissions API models
# ---------------------------------------------------------------------------


class ToolPolicy(BaseModel):
    """One org's tool policy for one agent run (GH-161).

    Loaded per run by ``admino.org_permissions.load_tool_policy`` from the
    org's stored permission rows and tool switches, so concurrent runs of
    different orgs never share a policy. Frozen: a loaded policy can't be
    changed.
    """

    model_config = ConfigDict(frozen=True)

    permissions: PermissionsConfig
    # The tier-2 (tool, action) pairs the org promoted from deny to confirm.
    promoted: frozenset[tuple[str, str]] = frozenset()
    # Every tool name -> whether the org enabled the service.
    enabled_tools: dict[str, bool] = Field(default_factory=dict)


class PermissionEntry(BaseModel):
    """A single permission row: (tool, action) → permission state."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    permission: Literal["allow", "confirm", "deny"]


class PermissionsResponse(BaseModel):
    """GET and PATCH /api/org/permissions response — the org's full permission matrix."""

    permissions: list[PermissionEntry]


class PermissionPatch(BaseModel):
    """PATCH /api/org/permissions request body — update one permission of the caller's org.

    Unknown keys (an org id included) are refused, and validation errors never
    repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    permission: Literal["allow", "confirm", "deny"]


class PermissionSummaryEntry(BaseModel):
    """One row of the read-only summary: a (tool, action) pair and its effective state.

    ``disabled`` when the org switched the tool's service off; otherwise the
    permission engine's decision for the org's policy.
    """

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    state: Literal["allow", "confirm", "deny", "disabled"]


class PermissionsSummaryResponse(BaseModel):
    """GET /api/permissions/summary response — the caller's org policy, read-only."""

    permissions: list[PermissionSummaryEntry]


# ---------------------------------------------------------------------------
# Critical permissions (tier-2 promotable denials)
# ---------------------------------------------------------------------------


class CriticalPermissionPromote(BaseModel):
    """PATCH /api/org/critical-permissions/{tool}/{action} body of a promotion.

    The Org Admin's own password, re-checked before the cooldown starts. A
    ``SecretStr``: ``repr()``/``str()`` never show it, validation errors never
    repeat it, and unknown fields are refused.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    password: SecretStr = Field(min_length=1, max_length=128)


class CriticalPermissionEntry(BaseModel):
    """A single promotable permission with current state and optional cooldown."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    state: Literal["deny", "confirm"]
    pending_at: datetime | None = Field(
        default=None,
        description="ISO 8601 timestamp when promotion cooldown started.",
    )


class CriticalPermissionsResponse(BaseModel):
    """GET /api/org/critical-permissions response."""

    permissions: list[CriticalPermissionEntry]


class CriticalPermissionState(BaseModel):
    """Response after PATCH /api/org/critical-permissions/{tool}/{action} or DELETE .../pending."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    state: Literal["deny", "confirm"]
    pending_at: datetime | None = None


# ---------------------------------------------------------------------------
# Authentication API models (GH-149)
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """POST /api/auth/login request body.

    The email is matched case-insensitively by ``admino.auth``; its format is
    not validated here (an unknown address fails like a wrong password). The
    password is a ``SecretStr``: ``repr()``/``str()`` never show it, and the
    422 handler never echoes request input. Unknown fields are refused.
    """

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: SecretStr = Field(min_length=1, max_length=128)


class PasswordResetRequest(BaseModel):
    """POST /api/auth/password-reset request body.

    The email is matched case-insensitively by ``admino.password_reset``; its
    format is not validated here (an unknown address gets the same 202 as a
    known one). The 422 handler never echoes request input. Unknown fields are
    refused.
    """

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)


class PasswordResetConfirmRequest(BaseModel):
    """POST /api/auth/password-reset/confirm request body.

    The token (from the emailed link) and the new password are ``SecretStr``:
    ``repr()``/``str()`` never show them, and the 422 handler never echoes
    request input. The bounds only cap the body: ``admino.password_reset``
    decides whether the token can exist, and the password policy decides the
    password. Unknown fields are refused.
    """

    model_config = ConfigDict(extra="forbid")

    token: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=1, max_length=1024)


class MeResponse(BaseModel):
    """GET /api/auth/me response: the logged-in account, from the resolved session.

    Every value comes from the server-side session and users row, never from
    the request. A Super Admin has no ``org_id`` and no ``role``.
    """

    user_id: UUID
    kind: UserKind
    org_id: UUID | None
    role: MemberRole | None
    ui_language: Literal["de", "fr", "en"]
    response_language: Literal["de", "fr", "it", "en"] | None


# ---------------------------------------------------------------------------
# Session management API models (GH-152)
# ---------------------------------------------------------------------------


class SessionSummary(BaseModel):
    """One of the caller's live sessions (GET /api/me/sessions).

    No token or token hash: a session is identified by its id only. The IP and
    the user agent are what the browser sent when the session was opened; the
    user agent (client-supplied text) is stripped of control and
    direction-override characters. ``current`` marks the session of the
    request.
    """

    id: PlainUUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip: str | None = Field(max_length=45)
    user_agent: str | None = Field(max_length=256)
    current: bool

    @field_validator("user_agent")
    @classmethod
    def _strip_control_chars(cls, value: str | None) -> str | None:
        """Remove control and direction-override characters from the user agent."""
        return None if value is None else value.translate(_CONTROL_CHAR_TABLE)


class SessionListResponse(BaseModel):
    """GET /api/me/sessions response: the caller's live sessions, most recently active first."""

    sessions: list[SessionSummary]


# ---------------------------------------------------------------------------
# Invitation API models (GH-153)
# ---------------------------------------------------------------------------

# Characters a display name may not contain: control (Cc), format (Cf, e.g.
# direction overrides and zero-width characters) and line/paragraph separators.
_NAME_BANNED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zl", "Zp"})
# An invite email refuses the same, plus surrogates (Cs): it is shown on the
# acceptance page and in the org's invitation list.
_EMAIL_BANNED_CATEGORIES: Final = _NAME_BANNED_CATEGORIES | {"Cs"}


def _strip_if_str(value: object) -> object:
    """Strip surrounding whitespace from a string; leave anything else to the type check."""
    return value.strip() if isinstance(value, str) else value


def _check_invite_email(value: str) -> str:
    """Accept a plausible single invitee address; the messages never include it.

    No whitespace, control, format, separator or surrogate characters; exactly
    one '@' after a non-empty local part, and a '.' inside the domain (not its
    first or last character).
    """
    if any(
        char.isspace() or unicodedata.category(char) in _EMAIL_BANNED_CATEGORIES for char in value
    ):
        msg = "The email must not contain whitespace, control or invisible characters."
        raise ValueError(msg)
    local, at, domain = value.partition("@")
    if not at or not local or "@" in domain or "." not in domain[1:-1]:
        msg = "The email must look like name@example.com."
        raise ValueError(msg)
    return value


class InvitationCreateRequest(BaseModel):
    """POST /api/org/invitations request body: who to invite, with which role.

    The email is stripped, then must be 3 to 254 characters without
    whitespace, control, format (zero-width, direction override), separator or
    surrogate characters, with exactly one '@' after a non-empty
    local part and a '.' inside the domain (not its first or last character).
    Capitalization is kept (the unique index ignores it). The org is always the
    caller's and the language the caller's session language: unknown fields
    are refused. Validation messages never repeat the email.
    """

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    role: MemberRole

    @field_validator("email", mode="before")
    @classmethod
    def _strip_email(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("email")
    @classmethod
    def _check_email(cls, value: str) -> str:
        """Accept a plausible single address; the messages never include it."""
        return _check_invite_email(value)


class InvitationSummary(BaseModel):
    """One pending invitation of the caller's org (list, create and resend responses).

    No token, token hash or link: an invitation is identified by its id only.
    ``expired`` is True once ``expires_at`` has passed; an expired invitation
    still holds its seat until it is revoked or sent again.
    """

    id: PlainUUID
    email: str = Field(max_length=254)
    role: MemberRole
    sent_at: datetime
    expires_at: datetime
    expired: bool


class InvitationListResponse(BaseModel):
    """GET /api/org/invitations response: the org's pending invitations, newest first."""

    invitations: list[InvitationSummary]


class InvitationDetails(BaseModel):
    """GET /api/auth/invitations/{token} response: what the acceptance page shows.

    The minimum: the org's display name, the offered role and the invited
    email. No ids, dates or token.
    """

    org_name: str = Field(max_length=120)
    role: MemberRole
    email: str = Field(max_length=254)


class InvitationAcceptRequest(BaseModel):
    """POST /api/auth/invitations/{token}/accept request body.

    The name is stripped, then must be 1 to 120 characters without control,
    format or line/paragraph separator characters. The password is a
    ``SecretStr``: ``repr()``/``str()`` never show it, and the 422 handler never
    echoes request input; its bounds only cap the body (the password policy
    decides the rest). Unknown fields are refused.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    password: SecretStr = Field(min_length=1, max_length=1024)

    @field_validator("name", mode="before")
    @classmethod
    def _strip_name(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        """Refuse control, format and line/paragraph separator characters."""
        if any(unicodedata.category(char) in _NAME_BANNED_CATEGORIES for char in value):
            msg = "The name must not contain control or formatting characters."
            raise ValueError(msg)
        return value


# ---------------------------------------------------------------------------
# Organization lifecycle API models (GH-154): org metadata only, no content
# ---------------------------------------------------------------------------

OrgStatus = Literal["active", "deactivated", "pending_deletion"]

# The plan limits, shared by the create request and the limits patch. The
# budget fits the organizations column NUMERIC(12,2): at most 10 digits before
# the point and 2 after; NaN and infinities are refused. The quota is in bytes
# and stays exact for a JSON reader (2**53 - 1).
Seats = Annotated[StrictInt, Field(ge=1, le=100_000)]
BudgetChf = Annotated[Decimal, Field(ge=0, max_digits=12, decimal_places=2, allow_inf_nan=False)]
StorageQuotaBytes = Annotated[StrictInt, Field(ge=0, le=2**53 - 1)]

# An org name reaches the invitation email's Subject header: the
# email_templates org-name rule refuses control, format, surrogate and
# line/paragraph separator characters.
_ORG_NAME_BANNED_CATEGORIES: Final = _NAME_BANNED_CATEGORIES | {"Cs"}


class OrgCreateRequest(BaseModel):
    """POST /api/platform/orgs request body (and the create-org CLI's input).

    The name is stripped, then must be 1 to 120 characters without control,
    format, surrogate or line/paragraph separator characters. The first Org
    Admin's email follows ``InvitationCreateRequest.email``'s rules exactly.
    Seats and the storage quota (bytes) are strict ints; the monthly budget in
    CHF is a JSON number or numeric string with at most 2 decimals. An org
    starts active or deactivated, never pending deletion. Residency keeps its
    default and the invitee's language is the caller's: unknown fields are
    refused. Validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    name: str = Field(min_length=1, max_length=120)
    primary_admin_email: str = Field(min_length=3, max_length=254)
    seats: Seats
    monthly_budget_chf: BudgetChf
    storage_quota: StorageQuotaBytes
    status: Literal["active", "deactivated"] = "active"

    @field_validator("name", "primary_admin_email", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        """Refuse control, format, surrogate and line/paragraph separator characters."""
        if any(unicodedata.category(char) in _ORG_NAME_BANNED_CATEGORIES for char in value):
            msg = "The name must not contain control or formatting characters."
            raise ValueError(msg)
        return value

    @field_validator("primary_admin_email")
    @classmethod
    def _check_email(cls, value: str) -> str:
        """The invitation email rules; the messages never include the address."""
        return _check_invite_email(value)


class OrgLimitsPatch(BaseModel):
    """PATCH /api/platform/orgs/{org_id}/limits request body.

    Any of the three plan limits, with the bounds of ``OrgCreateRequest``; a
    null counts as not given, and at least one must be given.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    seats: Seats | None = None
    monthly_budget_chf: BudgetChf | None = None
    storage_quota: StorageQuotaBytes | None = None

    @model_validator(mode="after")
    def _check_something_given(self) -> OrgLimitsPatch:
        """Refuse a patch that changes nothing."""
        if self.seats is None and self.monthly_budget_chf is None and self.storage_quota is None:
            msg = "Give at least one limit to change."
            raise ValueError(msg)
        return self


class OrgResidencyPatch(BaseModel):
    """PATCH /api/platform/orgs/{org_id}/residency request body: a strict bool."""

    # Validation errors never repeat the rejected input.
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    enabled: StrictBool


class OrgSummary(BaseModel):
    """One organization's metadata, as the Super Admin sees it (no content).

    ``storage_quota`` is in bytes; ``monthly_budget_chf`` is serialized as a
    decimal string. The deletion dates are set only while a deletion is
    pending.
    """

    id: PlainUUID
    name: str = Field(max_length=120)
    status: OrgStatus
    seats: int
    monthly_budget_chf: Decimal
    storage_quota: int
    data_residency: bool
    deletion_requested_at: datetime | None
    purge_after: datetime | None
    created_at: datetime
    updated_at: datetime


class OrgListResponse(BaseModel):
    """GET /api/platform/orgs response: every organization, oldest first."""

    organizations: list[OrgSummary]


class OrgCreateResponse(BaseModel):
    """POST /api/platform/orgs response: the new org and its first Org Admin's invitation.

    The invitation part carries no token and no link.
    """

    organization: OrgSummary
    invitation: InvitationSummary


# ---------------------------------------------------------------------------
# Org user management API models (GH-164): account metadata only, no credential
# ---------------------------------------------------------------------------

# A user's name is stored and shown in the org's user list: the display-name
# rule plus surrogates (Cs), which can't be stored as UTF-8.
_USER_NAME_BANNED_CATEGORIES: Final = _NAME_BANNED_CATEGORIES | {"Cs"}


class OrgUserSummary(BaseModel):
    """One user of the caller's org (list, change and status responses).

    No password hash, token, org id or account kind: a user is identified by
    its id only. An invited or deleted account is never a user here, so the
    status is ``active`` or ``deactivated``. ``name`` is None for an account
    created without one; ``last_login_at`` is None until the first login.
    """

    id: PlainUUID
    name: str | None = Field(max_length=120)
    email: str = Field(max_length=254)
    role: MemberRole
    status: Literal["active", "deactivated"]
    created_at: datetime
    last_login_at: datetime | None


class OrgSeats(BaseModel):
    """The read-only seat usage of the caller's org (GH-165).

    ``used`` counts the org's active and invited users (expired invitations
    included), the rule a new invitation is checked against; ``limit`` is the
    org's seats. ``used`` may exceed ``limit`` when the seats were lowered
    below the org's users, so there is no cross-field check.
    """

    used: int = Field(ge=0)
    limit: int = Field(ge=0)


class OrgUserListResponse(BaseModel):
    """GET /api/org/users response: the org's active and deactivated users, oldest first.

    ``seats`` is the org's seat usage (GH-165), shown next to the list.
    """

    users: list[OrgUserSummary]
    seats: OrgSeats


class OrgUserPatch(BaseModel):
    """PATCH /api/org/users/{user_id} request body: a new role, name or email.

    Any of the three; a null counts as not given, and at least one must be
    given. The name follows ``InvitationAcceptRequest.name``'s rules and also
    refuses surrogates; the email follows ``InvitationCreateRequest.email``'s
    rules exactly (capitalization kept). The org, the target user, the status
    and the account kind are never chosen by the body: unknown fields are
    refused. Validation errors never repeat the input.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    role: MemberRole | None = None
    name: str | None = Field(default=None, min_length=1, max_length=120)
    email: str | None = Field(default=None, min_length=3, max_length=254)

    @field_validator("name", "email", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        """Strip surrounding whitespace before the length checks."""
        return _strip_if_str(value)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str | None) -> str | None:
        """Refuse control, format, surrogate and line/paragraph separator characters."""
        if value is not None and any(
            unicodedata.category(char) in _USER_NAME_BANNED_CATEGORIES for char in value
        ):
            msg = "The name must not contain control or formatting characters."
            raise ValueError(msg)
        return value

    @field_validator("email")
    @classmethod
    def _check_email(cls, value: str | None) -> str | None:
        """The invitation email rules; the messages never include the address."""
        return None if value is None else _check_invite_email(value)

    @model_validator(mode="after")
    def _check_something_given(self) -> OrgUserPatch:
        """Refuse a patch that changes nothing."""
        if self.role is None and self.name is None and self.email is None:
            msg = "Give a role, a name or an email to change."
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# Platform diagnostics API model (GH-158): config metadata and statuses only
# ---------------------------------------------------------------------------


class PlatformDiagnosticsResponse(BaseModel):
    """GET /api/platform/diagnostics response (Super Admin): what public /health hides.

    ``status`` is the database check (``"ok"`` or ``"degraded"``), ``provider``
    and ``model`` the active LLM configuration (``model`` is None when no model
    is chosen), ``llm_reachable`` the provider probe. No content.
    """

    status: Literal["ok", "degraded"]
    provider: Literal["infomaniak", "anthropic", "openai", "vllm"]
    model: str | None = Field(max_length=200)
    llm_reachable: bool
