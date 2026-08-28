"""OpenAI LLM backend — opt-in proprietary provider.

Implements the ``LLMClient`` protocol defined in ``llm.py`` using the
official ``openai`` SDK. Messages and tool results are sent to OpenAI's
servers — users must explicitly opt in via config.

Tool calling: OpenAI's Chat Completions API uses a ``tools`` array.
GPT responds with ``tool_calls`` in the assistant message. This module
translates between admino's tool format and OpenAI's native format.

Security notes:
- API key is read from OPENAI_API_KEY env var, never from config files.
- No credentials are logged. LLM output is sanitized by the shared llm.py utilities.
- Does not import from agent.py, server.py, or tools/.
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from admino.llm import (
    LLMError,
    LLMResponse,
    check_args_depth,
    sanitize_content,
    strip_control_chars,
    validate_tools_payload,
)
from admino.models import LLMMessage, ToolCall

if TYPE_CHECKING:
    from admino.config import LLMConfig

logger = logging.getLogger(__name__)


def _convert_messages_to_openai(messages: list[LLMMessage]) -> list[dict[str, Any]]:
    """Convert LLMMessage list to OpenAI's Chat Completions format.

    OpenAI uses "system", "user", "assistant", and "tool" roles natively.
    Tool-role messages require a ``tool_call_id`` linking them to the
    originating tool call.

    Args:
        messages: Conversation messages.

    Returns:
        Messages in OpenAI format.
    """
    api_messages: list[dict[str, Any]] = []
    for msg in messages:
        entry: dict[str, Any] = {"role": msg.role, "content": msg.content}
        # OpenAI requires tool_call_id on tool-role messages
        if msg.role == "tool" and msg.tool_call_id:
            entry["tool_call_id"] = msg.tool_call_id
        api_messages.append(entry)
    return api_messages


def _convert_tools_to_openai(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert admino tool definitions to OpenAI's format.

    The admino tool format is already compatible with OpenAI::

        {"type": "function", "function": {"name": "...", "description": "...",
         "parameters": {...}}}

    This function passes through directly but validates structure.

    Args:
        tools: Tool definitions in admino format.

    Returns:
        Tool definitions in OpenAI format.
    """
    converted: list[dict[str, Any]] = []
    for tool in tools:
        func = tool.get("function", {})
        if not isinstance(func, dict):
            continue
        converted.append(
            {
                "type": "function",
                "function": {
                    "name": func.get("name", ""),
                    "description": func.get("description", ""),
                    "parameters": func.get("parameters", {"type": "object", "properties": {}}),
                },
            }
        )
    return converted


def _parse_openai_tool_calls(tool_calls: Any) -> list[ToolCall]:
    """Parse OpenAI tool_calls from assistant message into ToolCall models.

    OpenAI tool calls have the shape::

        {"id": "...", "type": "function",
         "function": {"name": "tool.action", "arguments": "{...}"}}

    Note: OpenAI returns arguments as a JSON string, not a dict.

    Args:
        tool_calls: Tool calls from OpenAI's response.

    Returns:
        List of validated ToolCall models.
    """
    if not tool_calls:
        return []

    parsed: list[ToolCall] = []
    for tc in tool_calls:
        func = getattr(tc, "function", None)
        if func is None:
            continue

        name = getattr(func, "name", "")
        if not isinstance(name, str) or not name:
            logger.warning("Skipping OpenAI tool call with missing name")
            continue

        # Capture the provider-assigned call id for multi-turn linking
        raw_id = getattr(tc, "id", None)
        call_id = strip_control_chars(raw_id)[:128] if isinstance(raw_id, str) else None

        name_safe = strip_control_chars(name)[:64]

        # OpenAI returns arguments as a JSON string
        raw_args = getattr(func, "arguments", "{}")
        if isinstance(raw_args, str):
            try:
                arguments = json.loads(raw_args)
            except json.JSONDecodeError:
                logger.warning("Skipping tool call '%s': malformed JSON arguments", name_safe)
                continue
        elif isinstance(raw_args, dict):
            arguments = raw_args
        else:
            logger.warning("Skipping tool call '%s': arguments is not a string or dict", name_safe)
            continue

        if not isinstance(arguments, dict):
            logger.warning("Skipping tool call '%s': parsed arguments is not a dict", name_safe)
            continue

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
            parsed.append(ToolCall(tool=tool, action=action, args=arguments, tool_call_id=call_id))
        except ValidationError:
            logger.warning(
                "Skipping tool call '%s': tool/action failed schema validation",
                name_safe,
            )

    return parsed


class OpenAIClient:
    """Async client for OpenAI's Chat Completions API.

    Uses the official ``openai`` SDK. Implements the ``LLMClient``
    protocol so it is interchangeable with the other LLMClient backends.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize the OpenAI client.

        Args:
            config: LLM configuration with openai_model and timeout_s.

        Raises:
            ImportError: If the ``openai`` package is not installed.
        """
        try:
            import openai
        except ImportError as exc:
            msg = (
                "The 'openai' package is required for the OpenAI provider. "
                "Install it with: pip install openai"
            )
            raise ImportError(msg) from exc

        if not config.openai_model:
            msg = "OpenAIClient requires llm.openai_model to be set in config."
            raise ValueError(msg)
        self._model = config.openai_model
        self._timeout_s = config.timeout_s
        self._max_tokens = config.max_response_tokens
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise LLMError(
                message="OPENAI_API_KEY env var is not set or is empty.",
                status_code=None,
            )
        self._client = openai.AsyncOpenAI(
            api_key=api_key,
            timeout=float(config.timeout_s),
        )

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        """Send a chat request to OpenAI's Chat Completions API.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).
            stream: Must be False for this method.

        Returns:
            Parsed LLMResponse.

        Raises:
            LLMError: On API errors, connection failures, or timeouts.
            ValueError: If stream=True is passed.
        """
        if stream:
            msg = "Streaming not yet supported for OpenAI provider"
            raise ValueError(msg)

        import openai

        api_messages = _convert_messages_to_openai(messages)

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "max_tokens": self._max_tokens,
        }
        if tools:
            try:
                validate_tools_payload(tools)
            except ValueError as exc:
                raise LLMError(message=str(exc), status_code=None) from exc
            kwargs["tools"] = _convert_tools_to_openai(tools)

        try:
            response = await self._client.chat.completions.create(**kwargs)
        except openai.APITimeoutError as exc:
            raise LLMError(
                message=f"OpenAI API request timed out after {self._timeout_s}s",
                status_code=None,
            ) from exc
        except openai.APIConnectionError as exc:
            raise LLMError(
                message="Failed to connect to OpenAI API",
                status_code=None,
            ) from exc
        except openai.RateLimitError as exc:
            raise LLMError(
                message="OpenAI API rate limit exceeded",
                status_code=429,
            ) from exc
        except openai.APIStatusError as exc:
            # exc.message is OpenAI's own error description — not the request
            # body, does not contain conversation content — safe to include.
            api_error = strip_control_chars(str(exc.message))[:500]
            raise LLMError(
                message=f"OpenAI API returned HTTP {exc.status_code}: {api_error}",
                status_code=exc.status_code,
            ) from exc

        # Extract the first choice
        if not response.choices:
            return LLMResponse(content="", tool_calls=[], model=self._model, done=True)

        choice = response.choices[0]
        message = choice.message

        content = sanitize_content(message.content or "")

        # Parse tool calls
        tool_calls = _parse_openai_tool_calls(message.tool_calls)

        model_name = strip_control_chars(response.model or self._model)[:200]

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            model=model_name,
            done=choice.finish_reason != "tool_calls",
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.close()

    async def __aenter__(self) -> OpenAIClient:
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
