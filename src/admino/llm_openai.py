"""OpenAI LLM backend — opt-in proprietary provider.

Implements the ``LLMClient`` protocol defined in ``llm.py`` using the
official ``openai`` SDK. Messages and tool results are sent to OpenAI's
servers — users must explicitly opt in via config.

Tool calling: OpenAI's Chat Completions API uses a ``tools`` array.
GPT responds with ``tool_calls`` in the assistant message. This module
translates between admino's tool format and OpenAI's native format.

Errors: a missing OPENAI_API_KEY or model does not fail construction; ``chat()``
raises a coded ``LLMError`` ("OpenAI isn't configured; set OPENAI_API_KEY" =
``not_configured``, "No OpenAI model is set …" = ``missing_model``) instead.
SDK failures map to the shared catalogue in ``llm.py`` (GH-242): a timeout is
``timeout``, a connection error ``provider_unavailable``, 401/403
``not_configured``, 404 ``missing_model``, 429 ``rate_limited`` and 5xx
``provider_unavailable`` (both with the response's Retry-After), a 400/413
whose input exceeds the context ``context_too_long``; other statuses stay
internal (code None, ``user_facing=False``, "OpenAI API returned HTTP <n>").
The SDK never retries (``max_retries=0``): one ``chat()`` or ``chat_stream()``
is exactly one HTTP request; retries belong to ``admino.llm_policy``.

Output cap: ``chat()``'s keyword-only ``max_tokens`` (GH-179) lowers the
request's ``max_tokens`` to ``min(max_tokens, config.max_response_tokens)``;
None keeps the configured cap, an invalid value is a ``ValueError`` before any
request.

Streaming (GH-8): ``chat_stream()`` sends ``chat()``'s request body plus
``stream: true`` (configured cap) and yields sanitized ``LLMStreamDelta`` pieces,
then exactly one final ``LLMResponse`` (content = the joined deltas, capped at
65536 characters while the stream is still read to its end). Setup errors come
on the first iteration, before any request; HTTP statuses when opening map like
``chat()``; a mid-stream timeout is ``timeout``, a transport failure or a
mid-stream error event ``provider_unavailable``. This module also holds the
stream reader shared by the OpenAI-compatible clients (OpenAI, vLLM,
Infomaniak): ``_stream_reply`` accumulates tool-call fragments per index
(``_accumulate_tool_calls``, at most 128 calls and 65536 argument characters
each) and parses them with ``_parse_openai_tool_calls`` once the stream ended;
tool calls are never streamed as deltas.

Inputs: conversation messages, tool definitions, OPENAI_API_KEY and the
configured model and caps. Outputs: ``LLMResponse`` / ``LLMStreamDelta`` items
or a catalogue ``LLMError``.

Security notes:
- API key is read from OPENAI_API_KEY env var, never from config files.
- No credentials are logged. LLM output is sanitized by the shared llm.py utilities.
- Error messages are fixed strings: never the SDK message, a response body or
  the body's error code (those only classify a context-length failure); SDK
  errors are raised ``from None``. Stream text and tool arguments are never
  logged (a dropped tool call is logged by its name through ``safe_log``).
- No end-user or account identifier is sent: no ``user``, ``metadata``,
  ``safety_identifier``, ``prompt_cache_key`` or ``store`` key, and the SDK's
  env-derived ``OpenAI-Organization`` / ``OpenAI-Project`` headers
  (OPENAI_ORG_ID / OPENAI_PROJECT_ID) are cleared.
- Does not import from agent.py, server.py, or tools/.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import aclosing
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Protocol

import httpx
from pydantic import ValidationError

from admino.llm import (
    _MAX_STREAM_TOOL_CALLS,
    _MAX_TOOL_ARGUMENT_CHARS,
    CappedAnswer,
    LLMError,
    LLMResponse,
    LLMStreamDelta,
    LLMUsage,
    check_args_depth,
    missing_model_error,
    not_configured_error,
    output_token_cap,
    provider_status_error,
    sanitize_content,
    sdk_status_error,
    strip_control_chars,
    validate_tools_payload,
)
from admino.logs import safe_log
from admino.models import LLMMessage, ToolCall

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable

    from openai import AsyncStream
    from openai.types import CompletionUsage
    from openai.types.chat import ChatCompletionChunk
    from openai.types.chat.chat_completion_chunk import ChoiceDeltaToolCall

    from admino.config import LLMConfig

logger = logging.getLogger(__name__)

# Provider label shown in user-facing errors and the env var holding the key.
_LABEL = "OpenAI"
_API_KEY_ENV = "OPENAI_API_KEY"


def _convert_messages_to_openai(messages: list[LLMMessage]) -> list[dict[str, Any]]:
    """Convert LLMMessage list to OpenAI's Chat Completions format.

    OpenAI uses "system", "user", "assistant", and "tool" roles natively.
    Tool-role messages require a ``tool_call_id`` linking them to the
    originating tool call, and that call must appear in the preceding assistant
    message's ``tool_calls``: the agent stores it in ``tool_use_blocks``, which
    is replayed here as OpenAI ``tool_calls`` (JSON-string arguments).

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
        if msg.role == "assistant" and msg.tool_use_blocks:
            tool_calls = _tool_use_blocks_to_openai(msg.tool_use_blocks)
            if tool_calls:
                entry["tool_calls"] = tool_calls
        api_messages.append(entry)
    return api_messages


def _tool_use_blocks_to_openai(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert the agent's stored tool_use blocks to OpenAI ``tool_calls`` entries.

    Blocks without a string id, a non-empty string name, or a dict input are
    skipped (a call that can't be linked to its result would be rejected).

    Args:
        blocks: ``{"type": "tool_use", "id", "name", "input"}`` dicts.

    Returns:
        OpenAI function tool calls with JSON-string arguments.
    """
    tool_calls: list[dict[str, Any]] = []
    for block in blocks:
        call_id = block.get("id")
        name = block.get("name")
        arguments = block.get("input")
        if not (isinstance(call_id, str) and call_id and isinstance(name, str) and name):
            continue
        if not isinstance(arguments, dict):
            continue
        tool_calls.append(
            {
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
        )
    return tool_calls


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
        log_name = safe_log(name)

        # OpenAI returns arguments as a JSON string
        raw_args = getattr(func, "arguments", "{}")
        if isinstance(raw_args, str):
            try:
                arguments = json.loads(raw_args)
            except json.JSONDecodeError:
                logger.warning("Skipping tool call '%s': malformed JSON arguments", log_name)
                continue
        elif isinstance(raw_args, dict):
            arguments = raw_args
        else:
            logger.warning("Skipping tool call '%s': arguments is not a string or dict", log_name)
            continue

        if not isinstance(arguments, dict):
            logger.warning("Skipping tool call '%s': parsed arguments is not a dict", log_name)
            continue

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
            parsed.append(ToolCall(tool=tool, action=action, args=arguments, tool_call_id=call_id))
        except ValidationError:
            logger.warning(
                "Skipping tool call '%s': tool/action failed schema validation",
                log_name,
            )

    return parsed


def _usage(usage: CompletionUsage | None) -> LLMUsage | None:
    """Convert provider token usage; a missing or malformed block yields None."""
    if usage is None:
        return None
    try:
        return LLMUsage(
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
        )
    except ValidationError:
        logger.warning("Ignoring malformed usage block")
        return None


@dataclass
class _StreamedFunction:
    """Function name / JSON-argument fragments of one streamed tool call."""

    name: str = ""
    arguments: str = ""


@dataclass
class _StreamedToolCall:
    """One tool call rebuilt from stream deltas (shape read by the OpenAI parser)."""

    id: str | None = None
    function: _StreamedFunction = field(default_factory=_StreamedFunction)


def _accumulate_tool_calls(
    calls: dict[int, _StreamedToolCall], fragments: list[ChoiceDeltaToolCall]
) -> None:
    """Merge streamed tool-call fragments into ``calls``, keyed by their index."""
    for fragment in fragments:
        call = calls.get(fragment.index)
        if call is None:
            if len(calls) >= _MAX_STREAM_TOOL_CALLS:
                continue
            call = calls[fragment.index] = _StreamedToolCall()
        call.id = call.id or fragment.id
        function = fragment.function
        if function is None:
            continue
        if function.name:
            call.function.name += function.name
        if function.arguments and len(call.function.arguments) < _MAX_TOOL_ARGUMENT_CHARS:
            call.function.arguments += function.arguments


class _AnswerText(Protocol):
    """Turns sanitized stream text into answer text (``CappedAnswer`` or a reasoning filter)."""

    @property
    def answer(self) -> str:
        """The answer collected so far."""
        ...

    def feed(self, text: str) -> str:
        """Consume a sanitized piece; return the newly visible answer text."""
        ...

    def finish(self) -> str:
        """Return the held-back answer text at the end of the stream."""
        ...


async def _stream_reply(
    stream: AsyncStream[ChatCompletionChunk],
    text: _AnswerText,
    *,
    configured_model: str,
    stream_error: Callable[[Exception], LLMError],
) -> AsyncGenerator[LLMStreamDelta | LLMResponse, None]:
    """Read an opened chat-completions stream: deltas, then one final LLMResponse.

    Shared by the OpenAI-compatible clients. Each chunk's text is sanitized and
    passed through ``text``; tool-call fragments are accumulated per index and
    parsed with ``_parse_openai_tool_calls`` once the stream ended, so they never
    become deltas. The stream is read to its end (also past the content cap) and
    closed when this generator ends or is closed.

    Args:
        stream: The SDK stream returned by ``chat.completions.create(stream=True)``.
        text: Answer filter (``CappedAnswer``, or Infomaniak's reasoning filter).
        configured_model: The model reported when the stream names none.
        stream_error: Maps an SDK error or transport failure to the client's
            catalogue ``LLMError``.

    Yields:
        ``LLMStreamDelta`` pieces, then the final ``LLMResponse``.

    Raises:
        LLMError: ``stream_error(exc)`` for a mid-stream failure, raised ``from
            None`` so no SDK exception (or provider text) travels with it.
    """
    import openai

    calls: dict[int, _StreamedToolCall] = {}
    model = ""
    usage: LLMUsage | None = None
    finish_reason: str | None = None
    async with stream:
        try:
            async for chunk in stream:
                model = chunk.model or model
                if chunk.usage is not None:
                    usage = _usage(chunk.usage)
                if not chunk.choices:
                    continue
                choice = chunk.choices[0]
                finish_reason = choice.finish_reason or finish_reason
                if choice.delta.tool_calls:
                    _accumulate_tool_calls(calls, choice.delta.tool_calls)
                piece = text.feed(strip_control_chars(choice.delta.content or ""))
                if piece:
                    yield LLMStreamDelta(content=piece)
        except (openai.APIError, httpx.TransportError) as exc:
            raise stream_error(exc) from None

    tail = text.finish()
    if tail:
        yield LLMStreamDelta(content=tail)
    yield LLMResponse(
        content=text.answer,
        tool_calls=_parse_openai_tool_calls([calls[index] for index in sorted(calls)]),
        model=strip_control_chars(model or configured_model)[:200],
        done=finish_reason != "tool_calls",
        usage=usage,
    )


def _api_error(exc: Exception) -> LLMError:
    """Map an SDK or transport failure (opening or mid-stream) to the catalogue.

    A status maps through ``sdk_status_error`` (the body's code and message only
    classify a context-length 400). Without a status: ``timeout`` for a timeout,
    else ``provider_unavailable`` (a connection or transport failure, or an
    error event inside an opened stream).
    """
    import openai

    if isinstance(exc, openai.APIStatusError):
        return sdk_status_error(
            _LABEL,
            exc.status_code,
            headers=exc.response.headers,
            error_code=exc.code,
            sdk_message=exc.message,
            key_env=_API_KEY_ENV,
        )
    # APITimeoutError is the SDK's wrapper; a raw httpx timeout arrives mid-stream.
    timed_out = isinstance(exc, openai.APITimeoutError | httpx.TimeoutException)
    return provider_status_error(_LABEL, None, key_env=_API_KEY_ENV, timed_out=timed_out)


class OpenAIClient:
    """Async client for OpenAI's Chat Completions API.

    Uses the official ``openai`` SDK. Implements the ``LLMClient``
    protocol so it is interchangeable with the other LLMClient backends.
    """

    provider: Final = "openai"

    def __init__(self, config: LLMConfig) -> None:
        """Initialize the OpenAI client.

        A missing OPENAI_API_KEY or model does not raise here: the state is
        stored and ``chat()`` answers with a user-facing error instead.

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

        self._model = config.openai_model or ""
        self._max_tokens = config.max_response_tokens
        api_key = os.environ.get(_API_KEY_ENV, "")
        self._api_key_configured = bool(api_key)
        # Built even without a key so close() stays uniform; chat() refuses to
        # send a request until the key is configured. No SDK retries: one chat()
        # is one request (the model policy decides about retries).
        self._client = openai.AsyncOpenAI(
            api_key=api_key,
            timeout=float(config.timeout_s),
            max_retries=0,
        )
        # The SDK fills these from OPENAI_ORG_ID / OPENAI_PROJECT_ID: account
        # identifiers that are never sent.
        self._client.organization = None
        self._client.project = None

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a chat request to OpenAI's Chat Completions API.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).
            stream: Must be False for this method.
            max_tokens: Per-call output cap (GH-179), sent as ``max_tokens``:
                ``min(max_tokens, configured cap)``; None sends the configured cap.

        Returns:
            Parsed LLMResponse.

        Raises:
            LLMError: Coded (user-facing) when the key or model is missing, the
                key is rejected, the model is unknown, the rate limit is hit,
                OpenAI is unavailable (5xx, connection), the request timed out or
                the input is too long; internal otherwise.
            ValueError: If stream=True is passed, or ``max_tokens`` is below 1,
                a bool or not an int (before any request).
        """
        if stream:
            msg = "Streaming not yet supported for OpenAI provider"
            raise ValueError(msg)
        cap = output_token_cap(self._max_tokens, max_tokens)
        kwargs = self._request(messages, tools, cap)

        import openai

        try:
            response = await self._client.chat.completions.create(**kwargs)
        except (openai.APIConnectionError, openai.APIStatusError) as exc:
            # Raised ``from None`` so the SDK exception (and any response body)
            # never travels with the LLMError.
            raise _api_error(exc) from None

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

    async def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncGenerator[LLMStreamDelta | LLMResponse, None]:
        """Stream a reply from OpenAI: answer deltas, then exactly one final LLMResponse.

        The request is ``chat()``'s body (configured output cap) plus ``stream:
        true``. Deltas are sanitized and stop at the content cap; tool calls
        come only in the final response.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).

        Yields:
            ``LLMStreamDelta`` pieces, then the final ``LLMResponse``.

        Raises:
            LLMError: ``chat()``'s setup errors on the first iteration (no
                request), its status mapping when opening the stream (before any
                delta); ``timeout`` / ``provider_unavailable`` mid-stream.
        """
        kwargs = self._request(messages, tools, self._max_tokens)

        import openai

        try:
            stream = await self._client.chat.completions.create(**kwargs, stream=True)
        except (openai.APIConnectionError, openai.APIStatusError) as exc:
            raise _api_error(exc) from None
        reply = _stream_reply(
            stream, CappedAnswer(), configured_model=self._model, stream_error=_api_error
        )
        # aclosing: closing this generator early closes the HTTP stream at once.
        async with aclosing(reply) as items:
            async for item in items:
                yield item

    def _request(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None, cap: int
    ) -> dict[str, Any]:
        """Check the setup and return the request body shared by chat() and chat_stream().

        Raises:
            LLMError: ``not_configured`` / ``missing_model`` for a missing key or
                model; an internal error for a tools payload over its limits.
        """
        if not self._api_key_configured:
            raise not_configured_error(_LABEL, _API_KEY_ENV)
        if not self._model:
            raise missing_model_error(_LABEL)
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": _convert_messages_to_openai(messages),
            "max_tokens": cap,
        }
        if tools:
            try:
                validate_tools_payload(tools)
            except ValueError as exc:
                raise LLMError(message=str(exc), status_code=None) from None
            kwargs["tools"] = _convert_tools_to_openai(tools)
        return kwargs

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
