"""Ollama LLM backend — local inference via Ollama's /api/chat endpoint.

This is the default (and recommended) LLM provider. All inference happens
locally; no data leaves the machine.

Implements the ``LLMClient`` protocol defined in ``llm.py``.

Security notes:
- No credentials are stored or logged.
- Timeouts enforced on all HTTP requests.
- LLM output sanitized (control chars stripped, length bounded).
- Does not import from agent.py, server.py, or tools/.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import httpx

from admino.llm import (
    _MAX_CONTENT_LENGTH,
    _MAX_TOOLS_COUNT,
    _MAX_TOOLS_PAYLOAD,
    LLMError,
    LLMResponse,
    parse_tool_calls,
    sanitize_content,
    serialize_messages,
    strip_control_chars,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from admino.config import OllamaConfig
    from admino.models import LLMMessage

logger = logging.getLogger(__name__)

# Backward-compatible alias
OllamaError = LLMError


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

        Args:
            messages: Conversation messages to send as context.
            tools: Optional list of tool definitions (JSON Schema format).
            stream: Must be False; use chat_stream() for streaming.

        Returns:
            Parsed LLMResponse with content, tool_calls, model, and done flag.

        Raises:
            LLMError: On HTTP errors, connection failures, or timeouts.
            ValueError: If stream=True is passed.
        """
        if stream:
            msg = "Use chat_stream() for streaming responses, not chat(stream=True)"
            raise ValueError(msg)

        body: dict[str, Any] = {
            "model": self._config.model,
            "messages": serialize_messages(messages),
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
            raise LLMError(
                message=f"Ollama returned HTTP {exc.response.status_code}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.ConnectError as exc:
            raise LLMError(
                message="Failed to connect to Ollama — check OLLAMA_BASE_URL and service status",
                status_code=None,
            ) from exc
        except httpx.TimeoutException as exc:
            raise LLMError(
                message=f"Ollama request timed out after {self._config.timeout_s}s",
                status_code=None,
            ) from exc

        try:
            data: dict[str, Any] = response.json()
        except json.JSONDecodeError as exc:
            raise LLMError(
                message="Ollama returned a non-JSON response body",
                status_code=None,
            ) from exc

        message_data = data.get("message", {})
        if not isinstance(message_data, dict):
            raise LLMError(
                message="Ollama response missing or malformed 'message' field",
                status_code=None,
            )

        content = message_data.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        content = sanitize_content(content)

        raw_tool_calls = message_data.get("tool_calls", [])
        if not isinstance(raw_tool_calls, list):
            raw_tool_calls = []

        tool_calls = parse_tool_calls(raw_tool_calls)

        raw_model = data.get("model", self._config.model)
        if not isinstance(raw_model, str):
            raw_model = str(raw_model)
        model_name = strip_control_chars(raw_model)[:200]

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

        Yields an async iterator of content chunks as they arrive.

        Args:
            messages: Conversation messages to send as context.
            tools: Optional list of tool definitions (JSON Schema format).

        Yields:
            An async iterator of string content chunks.

        Raises:
            LLMError: On HTTP errors, connection failures, or timeouts.
        """
        body: dict[str, Any] = {
            "model": self._config.model,
            "messages": serialize_messages(messages),
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
                    raise LLMError(
                        message=f"Ollama returned HTTP {response.status_code}",
                        status_code=response.status_code,
                    )
                yield self._iter_stream(response)
        except httpx.ConnectError as exc:
            raise LLMError(
                message="Failed to connect to Ollama — check OLLAMA_BASE_URL and service status",
                status_code=None,
            ) from exc
        except httpx.TimeoutException as exc:
            raise LLMError(
                message=f"Ollama request timed out after {self._config.timeout_s}s",
                status_code=None,
            ) from exc

    @staticmethod
    async def _iter_stream(response: httpx.Response) -> AsyncIterator[str]:
        """Iterate over a streaming Ollama response, yielding content chunks.

        Args:
            response: The httpx streaming response to iterate over.

        Yields:
            Non-empty content strings from the streaming response.
        """
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

            message_data = chunk_data.get("message", {})
            if isinstance(message_data, dict):
                content = message_data.get("content", "")
                if isinstance(content, str) and content:
                    content = strip_control_chars(content)
                    remaining = _MAX_CONTENT_LENGTH - total_yielded
                    if remaining <= 0:
                        return
                    chunk = content[:remaining]
                    if chunk:
                        total_yielded += len(chunk)
                        yield chunk

            if chunk_data.get("done", False):
                return

    async def close(self) -> None:
        """Close the underlying httpx client."""
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
