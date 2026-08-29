"""Shared Pydantic models for tool args, API types, and audit log entries.

This module defines all structured data types shared across admino modules:
- Audit log entry models (used by audit.py)
- API request/response models (used by server.py)
- Agent and LLM message models (used by agent.py and llm.py)

Security notes:
- No secrets, tokens, passwords, or credentials are stored in any model field.
- Audit entries strip credential patterns (OAuth tokens, JWTs, Bearer headers) via field validators.
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
from types import MappingProxyType
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

# Control characters to strip from free-text audit fields.
# Keeps tab (0x09), newline (0x0A), carriage return (0x0D) because they are
# legitimate in content. Newlines in audit entries are safe: Pydantic's
# model_dump_json() JSON-escapes them (\n -> \\n) before writing to NDJSON,
# so they never produce raw newline bytes in the log file.
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

# Patterns that must never appear in audit log entries
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
# Audit log models (audit.py imports these)
# ---------------------------------------------------------------------------


class ConversationAuditEntry(BaseModel):
    """Records a single conversation turn in the audit log.

    Logged once per user or assistant message. Used for security observability
    and fine-tuning dataset extraction.
    """

    entry_type: Literal["conversation"] = Field(
        default="conversation",
        description="Discriminator for the audit log entry type.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of when the entry was created.",
    )
    session_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Session identifier linking related conversation entries.",
    )

    @field_validator("session_id")
    @classmethod
    def redact_credentials_in_session_id(cls, v: str) -> str:
        """Defence-in-depth: strip credentials from session_id.

        The pattern constraint already restricts to alphanumeric/hyphen/underscore,
        but some credential formats (AKIA, gh[ps]_) fit within that character set.
        """
        return _strip_credentials(v)

    role: Literal["user", "assistant", "tool"] = Field(
        description=(
            "Role of this turn: 'user' (human input), 'assistant' (LLM output),"
            " or 'tool' (tool-execution result fed back to the LLM)."
        ),
    )
    content: str = Field(
        min_length=1,
        max_length=32768,
        description="The message content for this conversation turn.",
    )

    # NOTE: Pydantic v2 runs max_length before field_validator, so a value at
    # the length limit that contains a credential will be truncated first, then
    # redacted. Truncated credential fragments won't match the regex (minimum
    # match lengths prevent partial matches), so this ordering is safe.
    @field_validator("content")
    @classmethod
    def redact_credentials_in_content(cls, v: str) -> str:
        """Strip credentials and dangerous Unicode from content before storage."""
        v = v.translate(_CONTROL_CHAR_TABLE)
        v = _strip_credentials(v)
        return v if v else _SANITIZED_PLACEHOLDER

    model: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:/-]*$",
        description="The LLM model name used for this interaction.",
    )

    @field_validator("model")
    @classmethod
    def redact_credentials_in_model(cls, v: str) -> str:
        """Strip credentials and dangerous Unicode from model name."""
        v = v.translate(_CONTROL_CHAR_TABLE)
        v = _strip_credentials(v)
        return v if v else _SANITIZED_PLACEHOLDER

    tool_calls_count: int = Field(
        ge=0,
        le=50,
        description="Number of tool calls made during this turn.",
    )


class ToolCallAuditEntry(BaseModel):
    """Records a single tool invocation in the audit log.

    Logged once per tool call. Captures permission decision, execution result,
    and a sanitized summary of arguments (never raw credentials).
    """

    entry_type: Literal["tool_call"] = Field(
        default="tool_call",
        description="Discriminator for the audit log entry type.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of when the tool call was logged.",
    )
    session_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Session identifier linking this entry to a conversation.",
    )

    @field_validator("session_id")
    @classmethod
    def redact_credentials_in_session_id(cls, v: str) -> str:
        """Defence-in-depth: strip credentials from session_id."""
        return _strip_credentials(v)

    tool: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The tool name (e.g. 'gmail', 'calendar').",
    )
    action: str = Field(
        max_length=63,
        pattern=r"^[a-z][a-z0-9_]{0,62}$",
        description="The action name (e.g. 'read', 'search', 'create').",
    )
    permission: Literal["allow", "confirm", "deny", "disabled"] = Field(
        description="The permission engine's decision for this tool call.",
    )
    args_summary: str = Field(
        min_length=1,
        max_length=512,
        description="Sanitized summary of arguments. No raw credentials.",
    )
    success: bool = Field(
        description="Whether the tool call executed successfully.",
    )
    error: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description=(
            "Error message if the tool call failed, None otherwise. "
            "Credential patterns (OAuth tokens, JWTs, Fernet keys, Bearer headers) "
            "are automatically stripped by the model validator before storage."
        ),
    )

    # NOTE: Pydantic v2 runs max_length before field_validator, so credential
    # redaction happens after length enforcement. See content validator note above.
    @field_validator("args_summary")
    @classmethod
    def redact_credentials_in_args_summary(cls, v: str) -> str:
        """Strip credentials and dangerous Unicode from args_summary.

        In addition to credential redaction, strips Unicode direction-override
        and zero-width characters that could spoof displayed text in UIs.

        Callers should summarise only non-sensitive metadata (tool name,
        action, IDs); never include file contents, email bodies, or token values.
        """
        v = v.translate(_CONTROL_CHAR_TABLE)
        v = _strip_credentials(v)
        return v if v else _SANITIZED_PLACEHOLDER

    @field_validator("error")
    @classmethod
    def redact_credentials_in_error(cls, v: str | None) -> str | None:
        """Strip credentials and dangerous Unicode from error messages."""
        if v is None:
            return v
        v = v.translate(_CONTROL_CHAR_TABLE)
        v = _strip_credentials(v)
        return v if v else _SANITIZED_PLACEHOLDER


AuditEntry = ConversationAuditEntry | ToolCallAuditEntry
"""Union type for all audit log entry types. Used by audit.py for serialization."""


# ---------------------------------------------------------------------------
# API request/response models (server.py imports these)
# ---------------------------------------------------------------------------


class ChatMessage(BaseModel):
    """A single message in a conversation history.

    Note: content is NOT sanitised for control characters here. Sanitisation
    occurs at the audit boundary (ConversationAuditEntry) and at the display
    boundary (server.py SSE rendering). This model is used in conversation
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

    Validated on receipt by the ASGI server before any processing.
    """

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

    Used when the user approves or denies a pending confirmation.
    """

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
    _strip_control_chars) and at the audit boundary (ConversationAuditEntry).
    Raw content is preserved here for context-window fidelity.
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
            "and input. Ignored by the OpenAI serializer."
        ),
    )


class AgentConfig(BaseModel):
    """Runtime configuration for the agent loop.

    Separate from AppConfig (which covers the full application). AgentConfig
    controls agent-specific behavior limits.
    """

    max_tool_calls: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum tool calls the agent may make per user message.",
    )
    max_context_messages: int = Field(
        default=40,
        ge=1,
        le=200,
        description="Maximum conversation messages sent as LLM context.",
    )
    confirmation_timeout_s: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
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
    the caller can persist it. ``tool_calls`` is a summary for the HTTP
    response layer; authoritative records live in the audit log.
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
        description="Updated conversation history including this turn's additions.",
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


class FileReadArgs(BaseModel):
    """Arguments for the files.read action."""

    path: str = Field(
        max_length=500,
        description="Path to the file to read. Validated against allowed_paths at runtime.",
    )


class FileListArgs(BaseModel):
    """Arguments for the files.list action."""

    path: str = Field(
        max_length=500,
        description="Directory path to list. Validated against allowed_paths at runtime.",
    )
    max_depth: int = Field(
        default=1,
        ge=1,
        le=3,
        description="Maximum directory depth to recurse.",
    )


class FileSearchArgs(BaseModel):
    """Arguments for the files.search action."""

    path: str = Field(
        max_length=500,
        description="Root directory to search within. Validated against allowed_paths at runtime.",
    )
    pattern: str = Field(
        min_length=1,
        max_length=200,
        description="Filename glob pattern or text query.",
    )
    content_search: bool = Field(
        default=False,
        description="If True, search file contents instead of filenames.",
    )
    max_results: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of results to return.",
    )


class FileWriteArgs(BaseModel):
    """Arguments for the files.write action."""

    path: str = Field(
        max_length=500,
        description="Path to the file to write. Must be in a readwrite-allowed path.",
    )
    content: str = Field(
        max_length=50000,
        description="Content to write to the file.",
    )


class FileMoveArgs(BaseModel):
    """Arguments for the files.move action."""

    source: str = Field(
        max_length=500,
        description="Source file path. Must be in a readwrite-allowed path.",
    )
    destination: str = Field(
        max_length=500,
        description="Destination file path. Must be in a readwrite-allowed path.",
    )


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


class GoogleDriveDownloadArgs(BaseModel):
    """Arguments for the google_drive.download action (requires confirm)."""

    file_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Google Drive file ID to download.",
    )
    destination: str = Field(
        min_length=1,
        max_length=500,
        description="Destination path. Validated against allowed_paths.",
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


class OutlookReadArgs(BaseModel):
    """Arguments for the outlook.read action."""

    message_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9_\-]+$",
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
        max_length=200,
        pattern=r"^[A-Za-z0-9_\-]+$",
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


class OneDriveDownloadArgs(BaseModel):
    """Arguments for the onedrive.download action (requires confirm)."""

    item_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9_\-]+$",
        description="OneDrive item ID to download.",
    )
    destination: str = Field(
        min_length=1,
        max_length=500,
        description="Destination path. Validated against allowed_paths.",
    )


# ---------------------------------------------------------------------------
# Settings API models (server.py Settings endpoints)
# ---------------------------------------------------------------------------

# Shell metacharacter pattern for model name validation (mirrors LLMConfig).
_MODEL_NAME_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:\-/]*$")


class SettingsLLM(BaseModel):
    """LLM settings exposed via the Settings API."""

    provider: Literal["anthropic", "openai", "vllm"]
    anthropic_model: str = Field(max_length=200)
    openai_model: str = Field(max_length=200)
    # Boolean flags — never expose actual API key values.
    anthropic_key_configured: bool = False
    openai_key_configured: bool = False

    @field_validator("anthropic_model", "openai_model")
    @classmethod
    def validate_model_name(cls, v: str) -> str:
        """Reject model names containing shell metacharacters or control chars.

        An empty string is allowed: inactive-provider model fields have no
        hardcoded default and are rendered blank when unset in config.
        """
        if v and not _MODEL_NAME_RE.match(v):
            msg = "Model name contains invalid characters."
            raise ValueError(msg)
        return v


class SettingsAppearance(BaseModel):
    """Appearance settings."""

    theme: Literal["light", "dark", "system"] = "light"


class SettingsNotifications(BaseModel):
    """Notification preferences."""

    enabled: bool = True


class SettingsLimits(BaseModel):
    """Rate and size limits (read-only subset exposed to frontend)."""

    max_tool_calls_per_message: int = Field(ge=1, le=100)
    confirmation_timeout_s: int = Field(ge=10, le=3600)
    max_message_length: int = Field(ge=1, le=100_000)


class SettingsImmutable(BaseModel):
    """Immutable server settings — read-only in API response."""

    host: str
    port: int


class OAuthAuthorizeResponse(BaseModel):
    """GET /api/oauth/google/authorize response — consent URL for the frontend."""

    url: str = Field(max_length=2048, pattern=r"^https://")


class OAuthConnectionStatus(BaseModel):
    """OAuth connection status for a provider.

    ``connected`` means a token file exists on disk. ``healthy`` means the
    stored refresh token is still believed valid (not flagged dead after a
    terminal refresh failure). The frontend treats ``connected and not
    healthy`` the same as "Not connected" — prompting a fresh Connect.
    """

    connected: bool = False
    healthy: bool = False
    email: str | None = Field(
        default=None,
        max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    )
    services: list[str] = Field(default_factory=list)


class ToolsSettings(BaseModel):
    """Per-tool enabled/disabled state.

    Each field corresponds to a registered tool name. Default is True
    (enabled) for all tools, matching the implicit behavior before this
    feature was added.

    strict=True (mirrors :class:`SettingsPatchTools`): a non-boolean value
    loaded from the DB JSONB ``tools`` column — e.g. a manually corrupted or
    externally migrated ``"false"`` string — must raise ``ValidationError``
    and trip the explicit all-enabled fallback, NOT be silently coerced to
    ``True`` and re-enable a service the user disabled (GH-80 security gate).
    """

    model_config = ConfigDict(strict=True)

    gmail: bool = True
    google_calendar: bool = True
    google_drive: bool = True
    outlook: bool = True
    outlook_calendar: bool = True
    onedrive: bool = True
    files: bool = True
    memory: bool = True


class SettingsConnectedAccounts(BaseModel):
    """Connected OAuth account statuses."""

    google: OAuthConnectionStatus = Field(default_factory=OAuthConnectionStatus)
    microsoft: OAuthConnectionStatus = Field(default_factory=OAuthConnectionStatus)


class SettingsResponse(BaseModel):
    """GET /api/settings response — full settings with masked sensitive fields."""

    llm: SettingsLLM
    appearance: SettingsAppearance
    notifications: SettingsNotifications
    limits: SettingsLimits
    server: SettingsImmutable
    connected_accounts: SettingsConnectedAccounts = Field(
        default_factory=SettingsConnectedAccounts,
    )
    tools: ToolsSettings = Field(default_factory=ToolsSettings)


class SettingsPatchLLM(BaseModel):
    """Partial LLM settings for PATCH."""

    provider: Literal["anthropic", "openai", "vllm"] | None = None
    anthropic_model: str | None = Field(default=None, max_length=200)
    openai_model: str | None = Field(default=None, max_length=200)

    @field_validator("anthropic_model", "openai_model", mode="before")
    @classmethod
    def validate_model_name(cls, v: str | None) -> str | None:
        """Reject model names containing shell metacharacters or control chars."""
        if v is None:
            return v
        if not _MODEL_NAME_RE.match(v):
            msg = "Model name contains invalid characters."
            raise ValueError(msg)
        return v


class SettingsPatchAppearance(BaseModel):
    """Partial appearance settings for PATCH."""

    theme: Literal["light", "dark", "system"] | None = None


class SettingsPatchNotifications(BaseModel):
    """Partial notification settings for PATCH."""

    enabled: bool | None = None


class SettingsPatchTools(BaseModel):
    """Partial tool enable/disable updates for PATCH.

    Only provided fields are updated; omitted tools keep their current state.
    Unknown tool names are rejected at the API layer via registry validation.
    strict=True rejects string coercion (e.g. "yes") — only JSON booleans accepted.
    """

    model_config = ConfigDict(strict=True)

    gmail: bool | None = None
    google_calendar: bool | None = None
    google_drive: bool | None = None
    outlook: bool | None = None
    outlook_calendar: bool | None = None
    onedrive: bool | None = None
    files: bool | None = None
    memory: bool | None = None


class SettingsPatch(BaseModel):
    """PATCH /api/settings request body — all fields optional for partial update."""

    llm: SettingsPatchLLM | None = None
    appearance: SettingsPatchAppearance | None = None
    notifications: SettingsPatchNotifications | None = None
    tools: SettingsPatchTools | None = None


# ---------------------------------------------------------------------------
# Permissions API models
# ---------------------------------------------------------------------------


class PermissionEntry(BaseModel):
    """A single permission row: (tool, action) → permission state."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    permission: Literal["allow", "confirm", "deny"]


class PermissionsResponse(BaseModel):
    """GET /api/permissions response — full permission matrix."""

    permissions: list[PermissionEntry]


class PermissionPatch(BaseModel):
    """PATCH /api/permissions request body — update a single permission."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    permission: Literal["allow", "confirm", "deny"]


# ---------------------------------------------------------------------------
# Critical permissions (tier-2 promotable denials)
# ---------------------------------------------------------------------------


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
    """GET /api/critical-permissions response."""

    permissions: list[CriticalPermissionEntry]


class CriticalPermissionPromote(BaseModel):
    """PATCH body for promoting a critical permission (deny -> confirm)."""

    bearer_token: SecretStr = Field(
        min_length=1,
        max_length=2048,
        description="Re-auth token that must match the active session token.",
    )


class CriticalPermissionState(BaseModel):
    """Response after PATCH or DELETE on a critical permission."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,62}$", max_length=63)
    state: Literal["deny", "confirm"]
    pending_at: datetime | None = None
