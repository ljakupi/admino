"""LLM client protocol, shared utilities, and provider factory.

Defines the ``LLMClient`` protocol that all provider backends implement,
shared sanitization/parsing utilities, and the ``create_llm_client()``
factory that instantiates the correct backend based on config.

Provider modules:
- ``llm_infomaniak.py`` — Infomaniak AI Services backend (default; Swiss-hosted,
  OpenAI-compatible)
- ``llm_vllm.py`` — local vLLM backend (opt-in; OpenAI-compatible client)
- ``llm_anthropic.py`` — Anthropic Claude backend (opt-in)
- ``llm_openai.py`` — OpenAI backend (opt-in)

User-facing errors: setup and availability problems (missing key or model,
rejected key, unknown model, rate limit, provider unavailable) are raised as
``LLMError(user_facing=True)`` with a fixed, actionable message that the agent
shows in the chat verbatim. Every other failure stays ``user_facing=False`` and
the chat shows a generic reply. The helpers below build the shared catalogue.

Security notes:
- No credentials are stored or logged by this module.
- LLM output is sanitized: control characters stripped, length bounded.
- Tool call arguments are validated for size and nesting depth.
- Callers log an LLMError by its type and status_code only (GH-158), never
  its message, __cause__ or repr(), so no provider text or HTTP response body
  (conversation context) reaches the log.
- Only the configured provider's SDK is imported (lazy import in factory).
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field, ValidationError

from admino.logs import safe_log
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

    Callers log only the type and ``status_code``, never ``message`` or
    ``__cause__``, to keep provider text and HTTP response bodies out of logs.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code if available, None for connection errors.
        user_facing: True when ``message`` is a fixed, actionable text meant for
            the chat (it never embeds a response body or SDK cause). False means
            the agent replaces it with a generic reply.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        *,
        user_facing: bool = False,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.user_facing = user_facing
        super().__init__(message)


# ---------------------------------------------------------------------------
# User-facing error catalogue (shared by every provider client)
# ---------------------------------------------------------------------------


def not_configured_error(label: str, env_var: str) -> LLMError:
    """Return the user-facing error for a missing API key or token.

    Args:
        label: Provider name shown to the user (e.g. "Infomaniak", "Claude").
        env_var: Name of the environment variable to set (never its value).
    """
    return LLMError(
        message=f"{label} isn't configured; set {env_var} on the server.",
        user_facing=True,
    )


def missing_model_error(label: str) -> LLMError:
    """Return the user-facing error for a provider without a model."""
    return LLMError(
        message=f"No {label} model is set; choose one in Settings → Agent.",
        user_facing=True,
    )


def provider_status_error(
    label: str,
    status_code: int | None,
    *,
    key_env: str | None = None,
    key_noun: str = "API key",
    internal_message: str | None = None,
) -> LLMError:
    """Map a provider HTTP status (or a transport failure) to an LLMError.

    401/403 (only when the provider uses a key), 404, 429, 5xx and transport
    failures (``status_code=None``) become fixed user-facing messages. Any other
    status is internal: ``internal_message`` (or a bare status line) with
    ``user_facing=False``. Response bodies are never part of the message.

    Args:
        label: Provider name shown to the user.
        status_code: HTTP status, or None for timeouts and connection errors.
        key_env: Env var holding the credential; None for keyless providers.
        key_noun: What the credential is called ("API key" or "API token").
        internal_message: Log-only message for statuses outside the catalogue.
    """
    if status_code in (401, 403) and key_env:
        return LLMError(
            message=f"{label} rejected the {key_noun}; check {key_env} on the server.",
            status_code=status_code,
            user_facing=True,
        )
    if status_code == 404:
        return LLMError(
            message=(
                f"{label} doesn't offer the configured model; "
                "choose another one in Settings → Agent."
            ),
            status_code=status_code,
            user_facing=True,
        )
    if status_code == 429:
        return LLMError(
            message=f"{label} rate limit reached; wait a moment and try again.",
            status_code=status_code,
            user_facing=True,
        )
    if status_code is None or status_code >= 500:
        return LLMError(
            message=f"{label} is temporarily unavailable. Please try again in a moment.",
            status_code=status_code,
            user_facing=True,
        )
    return LLMError(
        message=internal_message or f"{label} API returned HTTP {status_code}",
        status_code=status_code,
    )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class LLMUsage(BaseModel):
    """Token usage reported by the provider for one request."""

    prompt_tokens: int = Field(ge=0, description="Input tokens billed for the request.")
    completion_tokens: int = Field(ge=0, description="Output tokens billed for the request.")


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
    usage: LLMUsage | None = Field(
        default=None,
        description="Token usage, when the provider reports it.",
    )


class LLMStreamDelta(BaseModel):
    """One streamed piece of answer text (sanitized, reasoning excluded)."""

    content: str = Field(description="Text to append to the answer.")


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

        # Control/ANSI characters are stripped before parsing; log lines carry
        # the name through safe_log (escaped and truncated).
        name_safe = name.translate(_CONTROL_CHAR_TABLE)[:64]
        log_name = safe_log(name)

        arguments = func.get("arguments", {})
        if not isinstance(arguments, dict):
            logger.warning("Skipping tool call '%s': arguments is not a dict", log_name)
            continue

        # Guard against deeply nested or pathologically large argument payloads
        if not check_args_depth(arguments):
            logger.warning(
                "Skipping tool call '%s': arguments exceed nesting depth limit", log_name
            )
            continue
        # Quick pre-screen on top-level values only; nested strings are covered
        # by the 16 KiB total-size check below and Pydantic's 64 KiB backstop.
        if len(arguments) > 32 or any(
            isinstance(v, str) and len(v) > 2048 for v in arguments.values()
        ):
            logger.warning("Skipping tool call '%s': arguments exceed size limits", log_name)
            continue
        if len(json.dumps(arguments)) > 16384:
            logger.warning("Skipping tool call '%s': arguments exceed size limits", log_name)
            continue

        # Require "tool.action" dot-notation; reject names without a dot
        if "." not in name_safe:
            logger.warning(
                "Skipping tool call '%s': name must use 'tool.action' dot notation",
                log_name,
            )
            continue

        tool, action = name_safe.split(".", maxsplit=1)
        if not tool or not action:
            logger.warning("Skipping tool call '%s': empty tool or action component", log_name)
            continue
        try:
            parsed.append(ToolCall(tool=tool, action=action, args=arguments))
        except ValidationError:
            logger.warning(
                "Skipping tool call '%s': tool/action failed schema validation",
                log_name,
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
        An LLMClient implementation for the configured provider. For the default
        'infomaniak' provider this is an ``InfomaniakClient``. No client does
        network I/O here or raises for a missing key or model: those surface as
        user-facing errors on the first chat request.

    Raises:
        ValueError: If the provider is unknown.
        ImportError: If the provider's SDK is not installed.
    """
    if config.provider == "infomaniak":
        from admino.llm_infomaniak import InfomaniakClient

        return InfomaniakClient(config)
    if config.provider == "anthropic":
        from admino.llm_anthropic import AnthropicClient

        return AnthropicClient(config)

    if config.provider == "openai":
        from admino.llm_openai import OpenAIClient

        return OpenAIClient(config)

    if config.provider == "vllm":
        from admino.llm_vllm import VLLMClient

        return VLLMClient(config)

    msg = f"Unknown LLM provider: {config.provider!r}"
    raise ValueError(msg)
