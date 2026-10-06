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

User-facing errors (GH-242): setup and availability problems carry a stable
``code`` (``admino.models.LLMErrorCode``: not_configured, missing_model,
provider_unavailable, rate_limited, timeout, residency_blocked,
context_too_long) and a fixed English message; a coded ``LLMError`` is always
user-facing, the PWA shows the code's translation and the agent's ``response``
keeps the English text. ``retryable`` is True for provider_unavailable,
rate_limited and timeout only (``admino.llm_policy`` retries those). Every
other failure is uncoded and ``user_facing=False``: the chat shows a generic
reply. The helpers below build the shared catalogue:
- ``provider_status_error`` maps an HTTP status (or a timeout / transport
  failure) to its code; 429/5xx carry ``retry_after_s``.
- ``sdk_status_error`` maps an SDK HTTP status error: Retry-After read with
  ``parse_retry_after``, a 400/413 classified with ``is_context_too_long``.

Per-call output cap (GH-179): ``LLMClient.chat`` takes a keyword-only
``max_tokens`` (default None = the configured ``max_response_tokens``). Every
client resolves it with ``output_token_cap``: the cap is
``min(max_tokens, configured)``, so a caller can lower it but never raise it;
a value below 1, a bool or a non-int is a ``ValueError`` before any request.

Streaming (GH-8): ``LLMClient.chat_stream`` yields sanitized, non-empty
``LLMStreamDelta`` pieces and then exactly one final ``LLMResponse`` whose
content is the joined deltas. ``CappedAnswer`` keeps a streamed answer within
the 65536-character content cap (counted after sanitizing); streamed tool-call
fragments are bounded by ``_MAX_STREAM_TOOL_CALLS`` calls and
``_MAX_TOOL_ARGUMENT_CHARS`` argument characters per call (plus
``_MAX_TOOL_NAME_CHARS`` name characters in the OpenAI-compatible reader, which
drops a call whose fragments would cross either bound), and are parsed only
once the stream ended, never streamed as deltas.

Inputs: provider statuses, response headers, and (for classification only)
the provider's error code and message, a per-call output cap, streamed answer
text. Outputs: ``LLMError`` instances, the cap a request sends, the capped
answer text.

Security notes:
- No credentials are stored or logged by this module.
- No provider text ever reaches an ``LLMError``: its message (and so ``str()``
  and ``repr()``) is a fixed catalogue text or "<label> API returned HTTP
  <status>". The provider's error code and message are only matched against
  fixed phrases by ``is_context_too_long``; they are never stored or logged.
- LLM output is sanitized: control characters (and lone surrogates, which no
  UTF-8 encoder accepts) stripped, length bounded.
- Tool call arguments are validated for size and nesting depth.
- Callers log an LLMError by its type, status_code and code only (GH-158),
  never its message, __cause__ or repr(), so no provider text or HTTP response
  body (conversation context) reaches the log.
- Only the configured provider's SDK is imported (lazy import in factory).
"""

from __future__ import annotations

import email.utils
import json
import logging
import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

from pydantic import BaseModel, Field, ValidationError

from admino.logs import safe_log
from admino.models import LLMMessage, ToolCall

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from admino.config import LLMConfig
    from admino.models import LLMErrorCode

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Maximum response content length to prevent unbounded memory usage
# ---------------------------------------------------------------------------
_MAX_CONTENT_LENGTH: int = 65536
_MAX_TOOLS_COUNT: int = 64
_MAX_TOOLS_PAYLOAD: int = 65536

# Bounds on streamed tool-call fragments (untrusted provider data): calls past
# the first 128 are ignored. The OpenAI-compatible reader bounds a call's name at
# 256 chars and its arguments at 65536: a fragment that would cross a bound is
# never appended, it marks the call overflowed (no further growth, dropped at
# parse time), so a hostile stream can't grow either string. Anthropic's argument
# fragments stop growing at 65536 chars (and then fail JSON parsing); its name
# arrives in one event.
_MAX_STREAM_TOOL_CALLS: Final = 128
_MAX_TOOL_NAME_CHARS: Final = 256
_MAX_TOOL_ARGUMENT_CHARS: Final = 65536


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


# Codes of transient failures: the model policy may retry them.
_RETRYABLE_CODES: Final[frozenset[str]] = frozenset(
    {"provider_unavailable", "rate_limited", "timeout"}
)


class LLMError(Exception):
    """Base error for all LLM provider failures.

    Callers log only the type, ``status_code`` and ``code``, never ``message``
    or ``__cause__``, to keep provider text and HTTP response bodies out of logs.

    Attributes:
        message: Human-readable error description (fixed text, never provider text).
        status_code: HTTP status code if available, None for connection errors.
        user_facing: True when ``message`` is a fixed, actionable text meant for
            the chat (it never embeds a response body or SDK cause). False means
            the agent replaces it with a generic reply. Always True for a coded
            error.
        code: The stable error code (GH-242) the UI translates, or None for an
            uncoded error.
        retry_after_s: The provider's Retry-After in seconds (429/5xx), or None.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        *,
        user_facing: bool = False,
        code: LLMErrorCode | None = None,
        retry_after_s: float | None = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.code: LLMErrorCode | None = code
        # A coded error is always shown: the UI translates its code.
        self.user_facing = user_facing or code is not None
        self.retry_after_s = retry_after_s
        super().__init__(message)

    @property
    def retryable(self) -> bool:
        """True for a transient failure (provider_unavailable, rate_limited, timeout)."""
        return self.code in _RETRYABLE_CODES


# ---------------------------------------------------------------------------
# User-facing error catalogue (shared by every provider client)
# ---------------------------------------------------------------------------


def not_configured_error(label: str, env_var: str) -> LLMError:
    """Return the ``not_configured`` error for a missing API key or token.

    Args:
        label: Provider name shown to the user (e.g. "Infomaniak", "Claude").
        env_var: Name of the environment variable to set (never its value).
    """
    return LLMError(
        message=f"{label} isn't configured; set {env_var} on the server.",
        code="not_configured",
    )


def missing_model_error(label: str) -> LLMError:
    """Return the ``missing_model`` error for a provider without a model."""
    return LLMError(
        message=f"No {label} model is set; ask your administrator to choose one.",
        code="missing_model",
    )


def provider_status_error(
    label: str,
    status_code: int | None,
    *,
    key_env: str | None = None,
    key_noun: str = "API key",
    internal_message: str | None = None,
    timed_out: bool = False,
    retry_after_s: float | None = None,
    context_too_long: bool = False,
) -> LLMError:
    """Map a provider HTTP status (or a timeout / transport failure) to an LLMError.

    - no status: ``timeout`` when ``timed_out``, else ``provider_unavailable``;
    - 401/403: ``not_configured`` (only when the provider uses a key);
    - 404: ``missing_model``;
    - 429: ``rate_limited``, 5xx: ``provider_unavailable`` (both carry
      ``retry_after_s``);
    - 400/413 with ``context_too_long``: ``context_too_long``.

    Any other status is internal: ``internal_message`` (or a bare status line),
    code None, ``user_facing=False``. Response bodies are never part of the
    message.

    Args:
        label: Provider name shown to the user.
        status_code: HTTP status, or None for timeouts and connection errors.
        key_env: Env var holding the credential; None for keyless providers.
        key_noun: What the credential is called ("API key" or "API token").
        internal_message: Log-only fixed message for statuses outside the catalogue.
        timed_out: The request timed out (meaningful without a status only).
        retry_after_s: The provider's Retry-After in seconds (kept for 429/5xx).
        context_too_long: ``is_context_too_long`` classified the failure.
    """
    if status_code is None:
        if timed_out:
            return LLMError(
                message=(
                    f"{label} is temporarily unavailable (the request timed out). "
                    "Please try again in a moment."
                ),
                code="timeout",
            )
        return LLMError(
            message=f"{label} is temporarily unavailable. Please try again in a moment.",
            code="provider_unavailable",
        )
    if status_code in (401, 403) and key_env:
        return LLMError(
            message=f"{label} rejected the {key_noun}; check {key_env} on the server.",
            status_code=status_code,
            code="not_configured",
        )
    if status_code == 404:
        return LLMError(
            message=(
                f"{label} doesn't offer the configured model; "
                "ask your administrator to choose another one."
            ),
            status_code=status_code,
            code="missing_model",
        )
    if status_code == 429:
        return LLMError(
            message=f"{label} rate limit reached; wait a moment and try again.",
            status_code=status_code,
            code="rate_limited",
            retry_after_s=retry_after_s,
        )
    if status_code >= 500:
        return LLMError(
            message=f"{label} is temporarily unavailable. Please try again in a moment.",
            status_code=status_code,
            code="provider_unavailable",
            retry_after_s=retry_after_s,
        )
    if context_too_long and status_code in (400, 413):
        return LLMError(
            message=(
                f"The conversation is too long for the {label} model; "
                "start a new chat or shorten your message."
            ),
            status_code=status_code,
            code="context_too_long",
        )
    return LLMError(
        message=internal_message or f"{label} API returned HTTP {status_code}",
        status_code=status_code,
    )


def sdk_status_error(
    label: str,
    status_code: int,
    *,
    headers: Mapping[str, str] | None,
    error_code: object,
    sdk_message: object,
    key_env: str | None = None,
    key_noun: str = "API key",
) -> LLMError:
    """Map an SDK HTTP status error through the catalogue.

    The Retry-After comes from ``headers``; a 400/413 is classified by
    ``is_context_too_long`` from the provider's error code and message, which
    are then dropped: neither is stored, logged or part of the returned error.

    Args:
        label: Provider name shown to the user.
        status_code: The HTTP status of the error response.
        headers: The error response's headers (a non-mapping counts as none).
        error_code: The body's error code (e.g. ``context_length_exceeded``);
            anything but a str is ignored.
        sdk_message: The SDK's error message; anything but a str is ignored.
        key_env: Env var holding the credential; None for keyless providers.
        key_noun: What the credential is called ("API key" or "API token").
    """
    return provider_status_error(
        label,
        status_code,
        key_env=key_env,
        key_noun=key_noun,
        retry_after_s=parse_retry_after(headers),
        context_too_long=is_context_too_long(
            status_code,
            error_code if isinstance(error_code, str) else None,
            sdk_message if isinstance(sdk_message, str) else None,
        ),
    )


# ---------------------------------------------------------------------------
# Retry-After and context-length classification
# ---------------------------------------------------------------------------

# A non-negative decimal number: no sign, exponent, NaN or infinity spelling.
_DECIMAL_RE: Final = re.compile(r"[0-9]+(?:\.[0-9]+)?")

# Phrases (lower-case) of a provider's "the input is too long" 400 message.
_CONTEXT_PHRASES: Final[tuple[str, ...]] = (
    "context length",
    "context_length",
    "maximum context",
    "context window",
    "prompt is too long",
    "input is too long",
    "too many tokens",
)


def _non_negative_number(value: str | None) -> float | None:
    """Parse a non-negative finite decimal number; anything else is None."""
    if value is None or not _DECIMAL_RE.fullmatch(value.strip()):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def parse_retry_after(
    headers: Mapping[str, str] | None, *, now: datetime | None = None
) -> float | None:
    """Return the provider's requested retry delay in seconds, or None.

    Header names match case-insensitively. ``retry-after-ms`` (milliseconds)
    wins when it is a non-negative finite number; else ``retry-after`` as
    seconds, or as an HTTP-date (seconds from ``now``, at least 0.0). Missing,
    negative, NaN, infinite or unparsable values give None. The value is not
    capped here (the model policy decides what is too long).

    Args:
        headers: Response headers (a dict or ``httpx.Headers``); a non-mapping
            counts as none.
        now: The current time for an HTTP-date (default: now, UTC).
    """
    if not isinstance(headers, Mapping):
        return None
    lowered = {str(name).lower(): value for name, value in headers.items()}
    millis = _non_negative_number(lowered.get("retry-after-ms"))
    if millis is not None:
        return millis / 1000.0
    raw = lowered.get("retry-after")
    seconds = _non_negative_number(raw)
    if seconds is not None or raw is None:
        return seconds
    try:
        when = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    current = now or datetime.now(UTC)
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return max(0.0, (when - current).total_seconds())


def is_context_too_long(
    status_code: int | None, error_code: str | None, message: str | None
) -> bool:
    """Return True when a provider failure means the input exceeds the model's context.

    413 always; a 400 whose error code is ``context_length_exceeded`` or whose
    message contains a known phrase (case-insensitive). Classification only:
    ``error_code`` and ``message`` are never stored or logged.
    """
    if status_code == 413:
        return True
    if status_code != 400:
        return False
    if error_code == "context_length_exceeded":
        return True
    if not message:
        return False
    lowered = message.lower()
    return any(phrase in lowered for phrase in _CONTEXT_PHRASES)


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
# Surrogate code points (U+D800-U+DFFF) only exist in a str as lone surrogates (a
# JSON escape without its partner, or a pair split across stream chunks): they
# can't be encoded as UTF-8, so a Pydantic str field, asyncpg and the SSE writer
# would reject them. A valid astral character is one code point and stays.
_CONTROL_CHAR_TABLE = dict.fromkeys(
    [i for i in range(32) if i not in (9, 10, 13)]  # ASCII controls except \t \n \r
    + list(range(0x80, 0xA0))  # C1 controls (includes CSI U+009B, NEL U+0085)
    + list(range(0xD800, 0xE000))  # lone surrogates
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
    - Lone surrogates (U+D800-U+DFFF), which no UTF-8 encoder accepts

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


class CappedAnswer:
    """Collect streamed answer text up to the ``LLMResponse`` content cap.

    Callers feed text that is already sanitized, so the cap counts sanitized
    characters. Text past the cap is dropped; the caller keeps reading its
    stream so tool calls and the stop reason still arrive.
    """

    def __init__(self) -> None:
        self._parts: list[str] = []
        self._length = 0

    @property
    def answer(self) -> str:
        """The answer collected so far (at most ``_MAX_CONTENT_LENGTH`` characters)."""
        return "".join(self._parts)

    def feed(self, text: str) -> str:
        """Keep what fits under the cap of ``text``; return the kept text (maybe "")."""
        kept = text[: _MAX_CONTENT_LENGTH - self._length]
        if kept:
            self._parts.append(kept)
            self._length += len(kept)
        return kept

    def finish(self) -> str:
        """Return the held-back text at the end of the stream: none is ever held."""
        return ""


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


def output_token_cap(configured: int, max_tokens: int | None) -> int:
    """Return a request's output cap: ``configured``, or the lower per-call cap (GH-179).

    A per-call cap only ever lowers the configured ``max_response_tokens``, so
    a caller (the chat-title call) can't make a reply longer than the operator
    allows. Clients call this before any setup check or request.

    Args:
        configured: The client's configured cap (``LLMConfig.max_response_tokens``).
        max_tokens: The per-call cap, or None for the configured cap.

    Returns:
        ``configured`` when ``max_tokens`` is None, else ``min(max_tokens, configured)``.

    Raises:
        ValueError: ``max_tokens`` is not an int (a bool counts as not one) or is below 1.
    """
    if max_tokens is None:
        return configured
    # type() rather than isinstance(): a bool is an int subclass but never a cap.
    if type(max_tokens) is not int or max_tokens < 1:
        msg = "max_tokens must be an int of at least 1"
        raise ValueError(msg)
    return min(max_tokens, configured)


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

    Each provider (Infomaniak, vLLM, Anthropic, OpenAI) implements this
    protocol. The agent loop uses this interface exclusively — it is
    provider-agnostic. ``provider`` names the backend ("infomaniak", "vllm",
    "anthropic", "openai"): the model policy's residency guard (GH-242) reads it.
    """

    @property
    def provider(self) -> str:
        """The backend's provider name."""
        ...

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a chat request and return the parsed response.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (JSON Schema format).
            stream: Must be False; streaming goes through ``chat_stream()``.
            max_tokens: Per-call output cap (GH-179). None sends the configured
                ``max_response_tokens``; an int sends ``output_token_cap()``'s
                ``min(max_tokens, configured)``. Nothing else in the request changes.

        Returns:
            Parsed LLMResponse with content, tool_calls, model, and done flag.

        Raises:
            ValueError: ``max_tokens`` below 1, a bool or not an int (before any request).
        """
        ...

    def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncGenerator[LLMStreamDelta | LLMResponse, None]:
        """Stream a chat reply (GH-8): answer deltas, then exactly one final LLMResponse.

        The request is ``chat()``'s (configured output cap) plus ``stream:
        true``. Deltas are sanitized and non-empty; the final response's
        content is their concatenation (capped at 65536 characters, the stream
        is still read to its end). Tool calls are only in the final response.
        An async generator, so a caller can close it early (``aclose()``) and
        the provider's HTTP stream closes with it.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (JSON Schema format).

        Yields:
            ``LLMStreamDelta`` pieces, then the final ``LLMResponse``.

        Raises:
            LLMError: The same catalogue as ``chat()``: setup errors on the
                first iteration (before any request), HTTP statuses before any
                delta, a timeout / transport failure possibly after deltas.
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
