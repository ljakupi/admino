"""Shared Pydantic models for tool args, API types, and audit log entries.

This module defines all structured data types shared across admino modules:
- Audit log entry models (used by audit.py)
- API request/response models (used by server.py)
- Agent and LLM message models (used by agent.py and llm.py)

Security notes:
- No secrets, tokens, passwords, or credentials are stored in any model field.
- Audit entries use args_summary (sanitized) rather than raw arguments.
- All user-facing string fields have max_length constraints to prevent abuse.
- ToolCall.args uses dict[str, Any] because LLM output is untyped JSON;
  individual tools validate args via their own Pydantic models before execution.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

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
        max_length=64,
        description="Session identifier linking related conversation entries.",
    )
    role: Literal["user", "assistant"] = Field(
        description="Whether this turn is from the user or the assistant.",
    )
    content: str = Field(
        max_length=32768,
        description="The message content for this conversation turn.",
    )
    model: str = Field(
        max_length=128,
        description="The LLM model name used for this interaction.",
    )
    tool_calls_count: int = Field(
        ge=0,
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
        max_length=64,
        description="Session identifier linking this entry to a conversation.",
    )
    tool: str = Field(
        max_length=64,
        description="The tool name (e.g. 'gmail', 'calendar').",
    )
    action: str = Field(
        max_length=64,
        description="The action name (e.g. 'read', 'search', 'create').",
    )
    permission: Literal["allow", "confirm", "deny"] = Field(
        description="The permission engine's decision for this tool call.",
    )
    args_summary: str = Field(
        max_length=512,
        description="Sanitized summary of arguments. No raw credentials.",
    )
    success: bool = Field(
        description="Whether the tool call executed successfully.",
    )
    error: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "Error message if the tool call failed, None otherwise. "
            "Callers MUST sanitize before assignment — strip bearer tokens "
            "(e.g. 'ya29.*', 'ey[A-Za-z0-9].*') and other credentials from "
            "exception messages before populating this field."
        ),
    )


AuditEntry = ConversationAuditEntry | ToolCallAuditEntry
"""Union type for all audit log entry types. Used by audit.py for serialization."""


# ---------------------------------------------------------------------------
# API request/response models (server.py imports these)
# ---------------------------------------------------------------------------


class ChatMessage(BaseModel):
    """A single message in a conversation history."""

    role: Literal["user", "assistant", "system"] = Field(
        description="The role of the message sender.",
    )
    content: str = Field(
        max_length=32768,
        description="The message content.",
    )


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
        max_length=64,
        description="The tool name.",
    )
    action: str = Field(
        max_length=64,
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
        max_length=64,
        description="The session identifier for this conversation.",
    )
    response: str = Field(
        max_length=65536,
        description="The assistant's text response.",
    )
    tool_calls: list[ToolCallRecord] = Field(
        default_factory=list,
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
        description="The unique identifier of the pending confirmation.",
    )
    approved: bool = Field(
        description="Whether the user approved (True) or denied (False) the action.",
    )


class SSEEvent(BaseModel):
    """Server-sent event envelope for streaming responses."""

    event: str = Field(
        max_length=64,
        description="The SSE event type (e.g. 'message', 'thinking', 'done').",
    )
    data: str = Field(
        max_length=65536,
        description="The JSON-encoded event payload.",
    )


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
        max_length=64,
        description="The tool name (e.g. 'gmail', 'calendar').",
    )
    action: str = Field(
        max_length=64,
        description="The action name (e.g. 'read', 'search').",
    )
    # Any is justified here: LLM tool-call arguments are arbitrary JSON objects.
    # Each tool validates its own args via a dedicated Pydantic model before execution.
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw arguments from the LLM. Validated by individual tool schemas.",
    )


class LLMMessage(BaseModel):
    """A message in the LLM context window.

    Represents messages sent to and received from Ollama's /api/chat endpoint.
    """

    role: Literal["user", "assistant", "system", "tool"] = Field(
        description="The role of the message in the LLM context.",
    )
    content: str = Field(
        max_length=65536,
        description="The message content.",
    )
    tool_call_id: str | None = Field(
        default=None,
        max_length=64,
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
        max_length=64,
        description="Unique identifier for this pending confirmation.",
    )
    session_id: str = Field(
        max_length=64,
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
