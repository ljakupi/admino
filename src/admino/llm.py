"""LLM client protocol, shared utilities, and provider factory.

Defines the ``LLMClient`` protocol that all provider backends implement,
shared sanitization/parsing utilities, and the ``create_llm_client()``
factory that instantiates the correct backend based on config.

Provider modules:
- ``llm_anthropic.py`` — Anthropic Claude backend (default)
- ``llm_openai.py`` — OpenAI backend (opt-in)

Security notes:
- No credentials are stored or logged by this module.
- LLM output is sanitized: control characters stripped, length bounded.
- Tool call arguments are validated for size and nesting depth.
- Callers must log only str(LLMError), never __cause__ or repr(),
  to prevent leaking HTTP response bodies containing conversation context.
- Only the configured provider's SDK is imported (lazy import in factory).
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field, ValidationError

from admino.models import LLMMessage, ToolCall

if TYPE_CHECKING:
    from admino.config import LLMConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Maximum response content length to prevent unbounded memory usage
# ---------------------------------------------------------------------------
_MAX_CONTENT_LENGTH: int = 65536
_MAX_TOOLS_COUNT: int = 64
_MAX_TOOLS_PAYLOAD: int = 65536


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class LLMError(Exception):
    """Base error for all LLM provider failures.

    Callers must log only the .message attribute, never __cause__,
    to prevent leaking HTTP response bodies.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code if available, None for connection errors.
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


class LLMResponse(BaseModel):
    """Parsed response from an LLM provider.

    Attributes:
        content: The assistant's text response.
        tool_calls: Parsed tool calls from the LLM (empty list if none).
        model: Model name echoed back from the provider.
        done: Whether generation is complete.
    """

    content: str = Field(
        default="",
        max_length=_MAX_CONTENT_LENGTH,
        description="The assistant's text response.",
    )
    tool_calls: list[ToolCall] = Field(
        default_factory=list,
        description="Parsed tool calls requested by the LLM.",
    )
    model: str = Field(
        default="",
        max_length=200,
        description="Model name echoed back from the provider.",
    )
    done: bool = Field(
        default=False,
        description="Whether generation is complete.",
    )


# ---------------------------------------------------------------------------
# Shared sanitization utilities
# ---------------------------------------------------------------------------

# Control characters to strip from LLM output (keep tab, newline, carriage return).
# Also strips Unicode direction-override and zero-width characters that could be
# used to spoof displayed text in confirmation dialogs (display-spoofing attack).
# Includes C1 controls (0x80-0x9F) — notably U+009B (CSI) which can trigger
# terminal escape sequences, and U+0085 (NEL) which is a Unicode line break.
_CONTROL_CHAR_TABLE = dict.fromkeys(
    [i for i in range(32) if i not in (9, 10, 13)]  # ASCII controls except \t \n \r
    + list(range(0x80, 0xA0))  # C1 controls (includes CSI U+009B, NEL U+0085)
    + [
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
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


def strip_control_chars(content: str) -> str:
    """Strip dangerous control and Unicode characters without truncating.

    Removes:
    - ASCII control characters (0x00-0x1F) except tab, newline, carriage return
    - C1 control characters (0x80-0x9F) including CSI (U+009B) and NEL (U+0085)
    - Unicode direction-override characters (U+202A-U+202E)
    - BiDi isolate characters (U+2066-U+2069)
    - Zero-width characters (U+200B-U+200D, U+FEFF)
    - Line/paragraph separators (U+2028, U+2029)

    Args:
        content: Raw string from LLM response.

    Returns:
        String with control characters removed (not truncated).
    """
    return content.translate(_CONTROL_CHAR_TABLE)


def sanitize_content(content: str) -> str:
    """Truncate and strip dangerous control/Unicode characters from LLM content.

    Args:
        content: Raw string from LLM response.

    Returns:
        Sanitized, length-limited string.
    """
    return strip_control_chars(content)[:_MAX_CONTENT_LENGTH]


def check_args_depth(obj: object, limit: int = 4) -> bool:
    """Return True if the object's nesting depth is within the limit."""
    if limit <= 0:
        return False
    if isinstance(obj, dict):
        return all(check_args_depth(v, limit - 1) for v in obj.values())
    if isinstance(obj, list):
        return all(check_args_depth(v, limit - 1) for v in obj)
    return True


def parse_tool_calls(raw_tool_calls: list[dict[str, Any]]) -> list[ToolCall]:
    """Parse raw tool call objects into ToolCall models.

    Each raw tool call has the shape:
        {"function": {"name": "tool.action", "arguments": {...}}}

    The function name uses dot notation (e.g. "gmail.read") which is split
    into separate tool and action fields.

    Args:
        raw_tool_calls: List of raw tool call dicts from the LLM response.

    Returns:
        List of validated ToolCall models.
    """
    if len(raw_tool_calls) > 128:
        logger.warning(
            "Rejecting tool call batch: %d calls exceeds upper limit of 128",
            len(raw_tool_calls),
        )
        return []
    parsed: list[ToolCall] = []
    for raw in raw_tool_calls:
        func = raw.get("function", {})
        if not isinstance(func, dict):
            logger.warning("Skipping malformed tool call: 'function' is not a dict")
            continue

        name = func.get("name", "")
        if not isinstance(name, str) or not name:
            logger.warning("Skipping tool call with missing or non-string name")
            continue

        # Sanitize the name before logging to strip control/ANSI characters
        name_safe = name.translate(_CONTROL_CHAR_TABLE)[:64]

        arguments = func.get("arguments", {})
        if not isinstance(arguments, dict):
            logger.warning("Skipping tool call '%s': arguments is not a dict", name_safe)
            continue

        # Guard against deeply nested or pathologically large argument payloads
        if not check_args_depth(arguments):
            logger.warning(
                "Skipping tool call '%s': arguments exceed nesting depth limit", name_safe
            )
            continue
        # Quick pre-screen on top-level values only; nested strings are covered
        # by the 16 KiB total-size check below and Pydantic's 64 KiB backstop.
        if len(arguments) > 32 or any(
            isinstance(v, str) and len(v) > 2048 for v in arguments.values()
        ):
            logger.warning("Skipping tool call '%s': arguments exceed size limits", name_safe)
            continue
        if len(json.dumps(arguments)) > 16384:
            logger.warning("Skipping tool call '%s': arguments exceed size limits", name_safe)
            continue

        # Require "tool.action" dot-notation; reject names without a dot
        if "." not in name_safe:
            logger.warning(
                "Skipping tool call '%s': name must use 'tool.action' dot notation",
                name_safe,
            )
            continue

        tool, action = name_safe.split(".", maxsplit=1)
        if not tool or not action:
            logger.warning("Skipping tool call '%s': empty tool or action component", name_safe)
            continue
        try:
            parsed.append(ToolCall(tool=tool, action=action, args=arguments))
        except ValidationError:
            logger.warning(
                "Skipping tool call '%s': tool/action failed schema validation",
                name_safe,
            )

    return parsed


def validate_tools_payload(tools: list[dict[str, Any]]) -> None:
    """Validate tool definitions against size limits.

    Args:
        tools: List of tool definitions.

    Raises:
        ValueError: If tools exceed count or byte size limits.
    """
    if len(tools) > _MAX_TOOLS_COUNT or len(json.dumps(tools)) > _MAX_TOOLS_PAYLOAD:
        msg = (
            f"tools list exceeds size limits"
            f" (max {_MAX_TOOLS_COUNT} tools, {_MAX_TOOLS_PAYLOAD} bytes)"
        )
        raise ValueError(msg)


# ---------------------------------------------------------------------------
# LLMClient Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class LLMClient(Protocol):
    """Protocol defining the interface all LLM provider backends must implement.

    Each provider (Anthropic, OpenAI) implements this protocol.
    The agent loop uses this interface exclusively — it is provider-agnostic.
    """

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        """Send a chat request and return the parsed response.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (JSON Schema format).
            stream: Must be False (streaming not yet unified across providers).

        Returns:
            Parsed LLMResponse with content, tool_calls, model, and done flag.
        """
        ...

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        ...


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_llm_client(config: LLMConfig) -> LLMClient:
    """Create the appropriate LLM client based on the provider config.

    Only imports the provider-specific module when needed, so unused
    provider SDKs are never loaded.

    Args:
        config: Validated LLMConfig with provider selection.

    Returns:
        An LLMClient implementation for the configured provider.

    Raises:
        ValueError: If the provider is unknown.
        ImportError: If the provider's SDK is not installed.
    """
    if config.provider == "anthropic":
        from admino.llm_anthropic import AnthropicClient

        return AnthropicClient(config)

    if config.provider == "openai":
        from admino.llm_openai import OpenAIClient

        return OpenAIClient(config)

    msg = f"Unknown LLM provider: {config.provider!r}"
    raise ValueError(msg)
