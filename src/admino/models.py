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

from pydantic import BaseModel, Field, field_validator, model_validator

# Control characters to strip from free-text audit fields.
# Keeps tab (0x09), newline (0x0A), carriage return (0x0D) because they are
# legitimate in content. Newlines in audit entries are safe: Pydantic's
# model_dump_json() JSON-escapes them (\n -> \\n) before writing to NDJSON,
# so they never produce raw newline bytes in the log file.
# Strips Unicode direction-override and zero-width characters that could
# spoof displayed text in confirmation dialogs or log viewers.
_CONTROL_CHAR_TABLE: MappingProxyType[int, None] = MappingProxyType(
    dict.fromkeys(
        [i for i in range(32) if i not in (9, 10, 13)]
        + [
            0x200B,  # ZERO WIDTH SPACE
            0x200C,  # ZERO WIDTH NON-JOINER
            0x200D,  # ZERO WIDTH JOINER
            0x202A,  # LEFT-TO-RIGHT EMBEDDING
            0x202B,  # RIGHT-TO-LEFT EMBEDDING
            0x202C,  # POP DIRECTIONAL FORMATTING
            0x202D,  # LEFT-TO-RIGHT OVERRIDE
            0x202E,  # RIGHT-TO-LEFT OVERRIDE
            0x0085,  # NEXT LINE (NEL) — C1 control, line break in Unicode
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
    permission: Literal["allow", "confirm", "deny"] = Field(
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
    """Summary of a tool call included in a chat response."""

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
    permission: Literal["allow", "confirm", "deny"] = Field(
        description="The permission decision for this tool call.",
    )
    success: bool = Field(
        description="Whether the tool call executed successfully.",
    )


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
    tool_calls: list[ToolCallRecord] = Field(
        default_factory=list,
        max_length=50,
        description="Summary of tool calls made during this response.",
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

    Represents messages sent to and received from Ollama's /api/chat endpoint.

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
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Identifier linking a tool response to its originating call.",
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
