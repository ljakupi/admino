"""Async Ollama API client for LLM inference.

Provides the OllamaClient class that communicates with Ollama's /api/chat
endpoint via httpx. Supports both synchronous (non-streaming) and streaming
chat completions with tool calling.

Security notes:
- No credentials are stored or logged by this module.
- Timeouts are enforced on all HTTP requests to prevent indefinite hangs.
- Does not import from agent.py, server.py, or tools/.
- LLM output length is bounded; callers should additionally sanitize
  control characters before processing (see SEC-16 in requirements).
- Callers must log only str(OllamaError), never __cause__ or repr(),
  to prevent leaking HTTP response bodies that may contain conversation context.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import httpx
from pydantic import BaseModel, Field, ValidationError

from admino.models import LLMMessage, ToolCall

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from admino.config import OllamaConfig

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


class OllamaError(Exception):
    """Error raised when communication with the Ollama API fails.

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
    """Parsed response from an Ollama /api/chat call.

    Attributes:
        content: The assistant's text response.
        tool_calls: Parsed tool calls from the LLM (empty list if none).
        model: Model name echoed back from Ollama.
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
        description="Model name echoed back from the Ollama response.",
    )
    done: bool = Field(
        default=False,
        description="Whether generation is complete.",
    )


# Control characters to strip from LLM output (keep tab, newline, carriage return).
# Also strips Unicode direction-override and zero-width characters that could be
# used to spoof displayed text in confirmation dialogs (display-spoofing attack).
_CONTROL_CHAR_TABLE = dict.fromkeys(
    [i for i in range(32) if i not in (9, 10, 13)]  # ASCII controls except \t \n \r
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


def _strip_control_chars(content: str) -> str:
    """Strip dangerous control and Unicode characters without truncating.

    Removes:
    - ASCII control characters (0x00-0x1F) except tab, newline, carriage return
    - Unicode direction-override characters (U+202A-U+202E) that can spoof
      displayed text in confirmation dialogs
    - BiDi isolate characters (U+2066-U+2069)
    - Zero-width characters (U+200B-U+200D, U+FEFF) used for invisible injection
    - Line/paragraph separators (U+2028, U+2029)

    Use _sanitize_content() when truncation is also needed (non-streaming path).

    Args:
        content: Raw string from LLM response.

    Returns:
        String with control characters removed (not truncated).
    """
    return content.translate(_CONTROL_CHAR_TABLE)


def _sanitize_content(content: str) -> str:
    """Truncate and strip dangerous control/Unicode characters from LLM content.

    Args:
        content: Raw string from LLM response.

    Returns:
        Sanitized, length-limited string.
    """
    return _strip_control_chars(content)[:_MAX_CONTENT_LENGTH]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _check_args_depth(obj: object, limit: int = 4) -> bool:
    """Return True if the object's nesting depth is within the limit."""
    if limit <= 0:
        return False
    if isinstance(obj, dict):
        return all(_check_args_depth(v, limit - 1) for v in obj.values())
    if isinstance(obj, list):
        return all(_check_args_depth(v, limit - 1) for v in obj)
    return True


def _parse_tool_calls(raw_tool_calls: list[dict[str, Any]]) -> list[ToolCall]:
    """Parse raw Ollama tool call objects into ToolCall models.

    Each raw tool call has the shape:
        {"function": {"name": "tool.action", "arguments": {...}}}

    The function name uses dot notation (e.g. "gmail.read") which is split
    into separate tool and action fields.

    Args:
        raw_tool_calls: List of raw tool call dicts from Ollama's response.

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
        if not _check_args_depth(arguments):
            logger.warning(
                "Skipping tool call '%s': arguments exceed nesting depth limit", name_safe
            )
            continue
        # Quick pre-screen: reject any single string value > 2048 chars before full serialisation
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


def _serialize_messages(messages: list[LLMMessage]) -> list[dict[str, str]]:
    """Serialize LLMMessage models to the format expected by Ollama's /api/chat.

    Args:
        messages: List of LLMMessage models.

    Returns:
        List of dicts with 'role' and 'content' keys.
    """
    serialized: list[dict[str, str]] = []
    for msg in messages:
        entry: dict[str, str] = {"role": msg.role, "content": msg.content}
        serialized.append(entry)
    return serialized


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class OllamaClient:
    """Async client for Ollama's /api/chat endpoint.

    Creates a single httpx.AsyncClient in __init__ and reuses it across
    all requests. Use as an async context manager or call close() explicitly.

    Example::

        async with OllamaClient(config) as client:
            response = await client.chat(messages)
            print(response.content)
    """

    def __init__(self, config: OllamaConfig) -> None:
        """Initialize the Ollama client.

        Args:
            config: Ollama configuration with url, model, and timeout_s.
        """
        self._config = config
        self._client = httpx.AsyncClient(
            base_url=config.url,
            timeout=httpx.Timeout(
                connect=10.0,
                read=float(config.timeout_s),
                write=10.0,
                pool=5.0,
            ),
            follow_redirects=False,
            verify=True,
        )

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        """Send a non-streaming chat request to Ollama.

        Posts to /api/chat with the given messages and optional tool definitions.
        Parses the response into an LLMResponse with text content and any
        tool calls requested by the model.

        The ``tools`` parameter accepts ``list[dict[str, Any]]`` because LLM
        tool definitions are untyped JSON Schema objects whose structure is
        defined by Ollama's API, not by admino's type system.

        Args:
            messages: Conversation messages to send as context.
            tools: Optional list of tool definitions (JSON Schema format).
            stream: Must be False for this method; use chat_stream() for streaming.

        Returns:
            Parsed LLMResponse with content, tool_calls, model, and done flag.

        Raises:
            OllamaError: On HTTP errors, connection failures, or timeouts.
            ValueError: If stream=True is passed (use chat_stream instead).
        """
        if stream:
            msg = "Use chat_stream() for streaming responses, not chat(stream=True)"
            raise ValueError(msg)

        body: dict[str, Any] = {
            "model": self._config.model,
            "messages": _serialize_messages(messages),
            "stream": False,
        }
        if tools:
            if len(tools) > _MAX_TOOLS_COUNT or len(json.dumps(tools)) > _MAX_TOOLS_PAYLOAD:
                msg = (
                    f"tools list exceeds size limits"
                    f" (max {_MAX_TOOLS_COUNT} tools, {_MAX_TOOLS_PAYLOAD} bytes)"
                )
                raise ValueError(msg)
            body["tools"] = tools

        try:
            response = await self._client.post("/api/chat", json=body)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise OllamaError(
                message=f"Ollama returned HTTP {exc.response.status_code}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.ConnectError as exc:
            raise OllamaError(
                message="Failed to connect to Ollama — check OLLAMA_BASE_URL and service status",
                status_code=None,
            ) from exc
        except httpx.TimeoutException as exc:
            raise OllamaError(
                message=f"Ollama request timed out after {self._config.timeout_s}s",
                status_code=None,
            ) from exc

        try:
            data: dict[str, Any] = response.json()
        except json.JSONDecodeError as exc:
            raise OllamaError(
                message="Ollama returned a non-JSON response body",
                status_code=None,
            ) from exc

        message_data = data.get("message", {})
        if not isinstance(message_data, dict):
            raise OllamaError(
                message="Ollama response missing or malformed 'message' field",
                status_code=None,
            )

        content = message_data.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        # Enforce length limit and strip dangerous control characters
        content = _sanitize_content(content)

        raw_tool_calls = message_data.get("tool_calls", [])
        if not isinstance(raw_tool_calls, list):
            raw_tool_calls = []

        tool_calls = _parse_tool_calls(raw_tool_calls)

        raw_model = data.get("model", self._config.model)
        if not isinstance(raw_model, str):
            raw_model = str(raw_model)
        model_name = _strip_control_chars(raw_model)[:200]

        done_flag = data.get("done")
        if done_flag is None:
            logger.warning("Ollama response missing 'done' field; defaulting to True")
            done_flag = True

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            model=model_name,
            done=bool(done_flag),
        )

    @asynccontextmanager
    async def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[AsyncIterator[str]]:
        """Send a streaming chat request to Ollama.

        Yields an async iterator of content chunks as they arrive from
        the LLM. Empty chunks are skipped. Stops on the final chunk
        (``"done": true``).

        The ``tools`` parameter accepts ``list[dict[str, Any]]`` because LLM
        tool definitions are untyped JSON Schema objects whose structure is
        defined by Ollama's API, not by admino's type system.

        Usage::

            async with client.chat_stream(messages) as chunks:
                async for chunk in chunks:
                    print(chunk, end="", flush=True)

        Args:
            messages: Conversation messages to send as context.
            tools: Optional list of tool definitions (JSON Schema format).

        Yields:
            An async iterator of string content chunks.

        Raises:
            OllamaError: On HTTP errors, connection failures, or timeouts.
        """
        body: dict[str, Any] = {
            "model": self._config.model,
            "messages": _serialize_messages(messages),
            "stream": True,
        }
        if tools:
            if len(tools) > _MAX_TOOLS_COUNT or len(json.dumps(tools)) > _MAX_TOOLS_PAYLOAD:
                msg = (
                    f"tools list exceeds size limits"
                    f" (max {_MAX_TOOLS_COUNT} tools, {_MAX_TOOLS_PAYLOAD} bytes)"
                )
                raise ValueError(msg)
            body["tools"] = tools

        try:
            async with self._client.stream("POST", "/api/chat", json=body) as response:
                if response.status_code >= 400:
                    raise OllamaError(
                        message=f"Ollama returned HTTP {response.status_code}",
                        status_code=response.status_code,
                    )
                # The inner async generator (_iter_stream) is cleaned up by Python's
                # async generator protocol when the outer context manager exits.
                # httpx's stream() context manager handles HTTP response cleanup.
                yield self._iter_stream(response)
        # NOTE: httpx.stream() does not call raise_for_status() automatically,
        # so HTTPStatusError cannot be raised here. HTTP errors are handled by
        # the manual status_code >= 400 check above.
        except httpx.ConnectError as exc:
            raise OllamaError(
                message="Failed to connect to Ollama — check OLLAMA_BASE_URL and service status",
                status_code=None,
            ) from exc
        except httpx.TimeoutException as exc:
            raise OllamaError(
                message=f"Ollama request timed out after {self._config.timeout_s}s",
                status_code=None,
            ) from exc

    @staticmethod
    async def _iter_stream(response: httpx.Response) -> AsyncIterator[str]:
        """Iterate over a streaming Ollama response, yielding content chunks.

        Each line from Ollama is a JSON object. We extract the content delta
        from each and yield non-empty strings. Stops when "done" is true.

        Note: sanitization is applied per-chunk via _sanitize_content(). This
        is safe for the current translate-table approach. If regex-based
        sanitization is ever added (e.g., ANSI escape stripping), it must
        operate on the fully reassembled content, not individual chunks,
        as sequences may split across chunk boundaries.

        Args:
            response: The httpx streaming response to iterate over.

        Yields:
            Non-empty content strings from the streaming response.
        """
        # NOTE: total_yielded counts code points, consistent with Pydantic's
        # max_length. Worst-case UTF-8 byte usage is 4x (e.g. all emoji),
        # capping at ~256 KB — acceptable for a 65 KB code-point limit.
        total_yielded = 0
        async for line in response.aiter_lines():
            line = line.rstrip("\r")
            if not line.strip():
                continue

            try:
                chunk_data: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON line in Ollama stream")
                continue

            # Extract content from message delta
            message_data = chunk_data.get("message", {})
            if isinstance(message_data, dict):
                content = message_data.get("content", "")
                if isinstance(content, str) and content:
                    content = _strip_control_chars(content)
                    # Enforce cumulative size cap across all chunks
                    remaining = _MAX_CONTENT_LENGTH - total_yielded
                    if remaining <= 0:
                        return
                    chunk = content[:remaining]
                    if chunk:
                        total_yielded += len(chunk)
                        # SECURITY: translate-table sanitization (applied above
                        # via _sanitize_content) is chunk-safe because it
                        # operates on individual code points. Do NOT add
                        # regex-based sanitization here — multi-byte sequences
                        # (e.g. ANSI escapes) may split across chunk boundaries.
                        yield chunk

            # Stop on final chunk
            if chunk_data.get("done", False):
                return

    async def close(self) -> None:
        """Close the underlying httpx client.

        Should be called when the client is no longer needed. Automatically
        called when used as an async context manager.
        """
        await self._client.aclose()

    async def __aenter__(self) -> OllamaClient:
        """Enter the async context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        """Exit the async context manager, closing the HTTP client."""
        await self.close()
