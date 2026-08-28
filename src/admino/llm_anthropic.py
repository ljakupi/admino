"""Anthropic Claude LLM backend — opt-in proprietary provider.

Implements the ``LLMClient`` protocol defined in ``llm.py`` using the
official ``anthropic`` SDK. Messages and tool results are sent to
Anthropic's servers — users must explicitly opt in via config.

Tool calling: Anthropic's Messages API uses a ``tools`` array. Claude
responds with ``tool_use`` content blocks containing the tool name and
JSON input. This module translates between admino's tool format
(``{"type": "function", "function": {...}}``) and
Anthropic's native format.

Security notes:
- API key is read from ANTHROPIC_API_KEY env var, never from config files.
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


def _dot_to_anthropic_name(name: str) -> str:
    """Convert 'tool.action' dot notation to 'tool__action' for Anthropic.

    Anthropic tool names must match ``^[a-zA-Z0-9_-]+$`` — dots are not
    allowed. We encode the dot as a double-underscore so the name is
    reversible via :func:`_anthropic_name_to_dot`.
    """
    return name.replace(".", "__")


def _anthropic_name_to_dot(name: str) -> str:
    """Convert 'tool__action' back to 'tool.action' dot notation.

    Reverses the encoding applied by :func:`_dot_to_anthropic_name` so the
    admino parser can split on '.' as usual.
    """
    return name.replace("__", ".", 1)


def _convert_tools_to_anthropic(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert admino tool definitions to Anthropic's format.

    admino tool format::

        {"type": "function", "function": {"name": "...", "description": "...",
         "parameters": {...}}}

    Anthropic format::

        {"name": "...", "description": "...", "input_schema": {...}}

    Note: Anthropic requires tool names matching ``^[a-zA-Z0-9_-]+$``. The
    admino dot-notation (e.g. ``memory.store``) is converted to double-
    underscore notation (``memory__store``) so it is reversible when parsing
    the tool_use response.

    Args:
        tools: Tool definitions in admino tool format.

    Returns:
        Tool definitions in Anthropic Messages API format.
    """
    converted: list[dict[str, Any]] = []
    for tool in tools:
        func = tool.get("function", {})
        if not isinstance(func, dict):
            continue
        name = _dot_to_anthropic_name(func.get("name", ""))
        description = func.get("description", "")
        parameters = func.get("parameters", {"type": "object", "properties": {}})
        converted.append(
            {
                "name": name,
                "description": description,
                "input_schema": parameters,
            }
        )
    return converted


def _convert_messages_to_anthropic(
    messages: list[LLMMessage],
) -> tuple[str, list[dict[str, Any]]]:
    """Convert LLMMessage list to Anthropic's format.

    Anthropic requires the system prompt as a separate parameter, not
    in the messages array. Also, Anthropic requires alternating
    user/assistant turns — consecutive same-role messages are merged.

    Args:
        messages: Conversation messages.

    Returns:
        Tuple of (system_prompt, messages_list).
    """
    system_parts: list[str] = []
    api_messages: list[dict[str, Any]] = []

    for msg in messages:
        if msg.role == "system":
            system_parts.append(msg.content)
            continue

        # Anthropic uses "user" for both user messages and tool results
        role = "user" if msg.role in ("user", "tool") else "assistant"

        # For tool results, wrap in tool_result content block.
        # tool_call_id links this result to the originating tool_use block.
        if msg.role == "tool":
            if not msg.tool_call_id:
                logger.warning(
                    "Tool message missing tool_call_id — Anthropic requires this "
                    "for multi-turn tool calling. Skipping tool result message."
                )
                continue
            tool_result: dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": msg.tool_call_id,
                "content": msg.content,
            }
            content: str | list[dict[str, Any]] = [tool_result]
        elif msg.role == "assistant" and msg.tool_use_blocks:
            # Anthropic requires tool_use blocks in the assistant message so
            # that subsequent tool_result messages can reference them by ID.
            # The agent stores these in tool_use_blocks using dot notation;
            # we encode them here to Anthropic's double-underscore format.
            blocks: list[dict[str, Any]] = []
            if msg.content:
                blocks.append({"type": "text", "text": msg.content})
            for tb in msg.tool_use_blocks:
                if not tb.get("id"):
                    continue  # skip blocks without an ID — Anthropic requires it
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": tb["id"],
                        "name": _dot_to_anthropic_name(tb.get("name", "")),
                        "input": tb.get("input", {}),
                    }
                )
            content = blocks
        else:
            content = msg.content

        # Merge consecutive messages with the same role
        if api_messages and api_messages[-1]["role"] == role:
            prev_content = api_messages[-1]["content"]
            if isinstance(prev_content, str) and isinstance(content, str):
                api_messages[-1]["content"] = prev_content + "\n" + content
            elif isinstance(prev_content, list) and isinstance(content, list):
                api_messages[-1]["content"] = prev_content + content
            elif isinstance(prev_content, str) and isinstance(content, list):
                api_messages[-1]["content"] = [
                    {"type": "text", "text": prev_content},
                    *content,
                ]
            elif isinstance(prev_content, list) and isinstance(content, str):
                api_messages[-1]["content"] = [
                    *prev_content,
                    {"type": "text", "text": content},
                ]
        else:
            api_messages.append({"role": role, "content": content})

    system_prompt = "\n".join(system_parts) if system_parts else ""
    return system_prompt, api_messages


def _parse_anthropic_tool_calls(content_blocks: list[Any]) -> list[ToolCall]:
    """Parse Anthropic tool_use content blocks into ToolCall models.

    Args:
        content_blocks: Content blocks from Anthropic's response.

    Returns:
        List of validated ToolCall models.
    """
    parsed: list[ToolCall] = []
    for block in content_blocks:
        if not hasattr(block, "type") or block.type != "tool_use":
            continue

        name = getattr(block, "name", "")
        if not isinstance(name, str) or not name:
            logger.warning("Skipping Anthropic tool_use with missing name")
            continue

        # Capture the provider-assigned tool_use id for multi-turn linking
        raw_id = getattr(block, "id", None)
        block_id = strip_control_chars(raw_id)[:128] if isinstance(raw_id, str) else None

        # Reverse the dot→double-underscore encoding applied in _convert_tools_to_anthropic
        # so the rest of the parse logic can use standard 'tool.action' dot notation.
        name_safe = strip_control_chars(_anthropic_name_to_dot(name))[:64]
        arguments = getattr(block, "input", {})
        if not isinstance(arguments, dict):
            logger.warning("Skipping tool call '%s': input is not a dict", name_safe)
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
            parsed.append(ToolCall(tool=tool, action=action, args=arguments, tool_call_id=block_id))
        except ValidationError:
            logger.warning(
                "Skipping tool call '%s': tool/action failed schema validation",
                name_safe,
            )

    return parsed


class AnthropicClient:
    """Async client for Anthropic's Messages API.

    Uses the official ``anthropic`` SDK. Implements the ``LLMClient``
    protocol so it is interchangeable with the other LLMClient backends.
    """

    def __init__(self, config: LLMConfig) -> None:
        """Initialize the Anthropic client.

        Args:
            config: LLM configuration with anthropic_model and timeout_s.

        Raises:
            ImportError: If the ``anthropic`` package is not installed.
        """
        try:
            import anthropic
        except ImportError as exc:
            msg = (
                "The 'anthropic' package is required for the Anthropic provider. "
                "Install it with: pip install anthropic"
            )
            raise ImportError(msg) from exc

        if not config.anthropic_model:
            msg = "AnthropicClient requires llm.anthropic_model to be set in config."
            raise ValueError(msg)
        self._model = config.anthropic_model
        self._timeout_s = config.timeout_s
        self._max_tokens = config.max_response_tokens
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise LLMError(
                message="ANTHROPIC_API_KEY env var is not set or is empty.",
                status_code=None,
            )
        self._client = anthropic.AsyncAnthropic(
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
        """Send a chat request to Anthropic's Messages API.

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
            msg = "Streaming not yet supported for Anthropic provider"
            raise ValueError(msg)

        import anthropic

        system_prompt, api_messages = _convert_messages_to_anthropic(messages)

        # Ensure we have at least one message
        if not api_messages:
            api_messages = [{"role": "user", "content": "Hello"}]

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "max_tokens": self._max_tokens,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if tools:
            try:
                validate_tools_payload(tools)
            except ValueError as exc:
                raise LLMError(message=str(exc), status_code=None) from exc
            kwargs["tools"] = _convert_tools_to_anthropic(tools)

        try:
            response = await self._client.messages.create(**kwargs)
        except anthropic.APITimeoutError as exc:
            raise LLMError(
                message=f"Anthropic API request timed out after {self._timeout_s}s",
                status_code=None,
            ) from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError(
                message="Failed to connect to Anthropic API",
                status_code=None,
            ) from exc
        except anthropic.RateLimitError as exc:
            raise LLMError(
                message="Anthropic API rate limit exceeded",
                status_code=429,
            ) from exc
        except anthropic.APIStatusError as exc:
            # exc.message is Anthropic's own error description (e.g. validation
            # errors for invalid tool names). It is NOT the request body and
            # does not contain conversation content — safe to include in logs.
            api_error = strip_control_chars(str(exc.message))[:500]
            raise LLMError(
                message=f"Anthropic API returned HTTP {exc.status_code}: {api_error}",
                status_code=exc.status_code,
            ) from exc

        # Extract text content
        text_parts: list[str] = []
        for block in response.content:
            if hasattr(block, "type") and block.type == "text":
                text_parts.append(getattr(block, "text", ""))

        content = sanitize_content("\n".join(text_parts) if text_parts else "")

        # Parse tool calls
        tool_calls = _parse_anthropic_tool_calls(response.content)

        model_name = strip_control_chars(response.model)[:200]

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            model=model_name,
            done=response.stop_reason != "tool_use",
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.close()

    async def __aenter__(self) -> AnthropicClient:
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
