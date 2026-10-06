"""Anthropic Claude LLM backend — opt-in proprietary provider.

Implements the ``LLMClient`` protocol defined in ``llm.py`` using the
official ``anthropic`` SDK. Messages and tool results are sent to
Anthropic's servers — users must explicitly opt in via config.

Tool calling: Anthropic's Messages API uses a ``tools`` array. Claude
responds with ``tool_use`` content blocks containing the tool name and
JSON input. This module translates between admino's tool format
(``{"type": "function", "function": {...}}``) and
Anthropic's native format.

Errors (provider label "Claude", GH-242 codes): a missing ANTHROPIC_API_KEY or
model does not fail construction; ``chat()`` raises a coded ``LLMError``
("Claude isn't configured; set ANTHROPIC_API_KEY" = ``not_configured``, "No
Claude model is set …" = ``missing_model``) instead. SDK failures map to the
shared catalogue in ``llm.py``: a timeout is ``timeout``, a connection error
``provider_unavailable``, 401/403 ``not_configured``, 404 ``missing_model``,
429 ``rate_limited`` and any status >= 500 (including 529 "overloaded")
``provider_unavailable`` (both with the response's Retry-After), a 413 or a
400 "prompt is too long" ``context_too_long``; other statuses stay internal
(code None, ``user_facing=False``, "Claude API returned HTTP <n>"). A reply
the client can't use is ``malformed_response`` (GH-25, not retried): a body or
event the SDK can't decode, ``httpx.DecodingError`` mid-stream, a field read
with the wrong type (a non-str model, text, ``partial_json``, tool_use id or
name, a block index that isn't an int), or any tool_use block that doesn't
parse (the whole reply is rejected). The SDK never retries
(``max_retries=0``): one ``chat()`` or ``chat_stream()`` is one request;
retries belong to ``admino.llm_policy``.

Output (GH-25): text sanitized with ``strip_control_chars`` and capped at 65536
characters (never cut at a word); tool arguments bounded, then cleaned with
``sanitize_tool_args``; ``LLMResponse.truncated`` for ``stop_reason ==
"max_tokens"`` or text past the cap.

Output cap: ``chat()``'s keyword-only ``max_tokens`` (GH-179) lowers the
request's ``max_tokens`` to ``min(max_tokens, config.max_response_tokens)``;
None keeps the configured cap, an invalid value is a ``ValueError`` before any
request.

Streaming (GH-8): ``chat_stream()`` sends ``chat()``'s request body plus
``stream: true`` (configured cap) and yields the sanitized text of each
``text_delta`` (every other delta or event type is ignored) as an
``LLMStreamDelta``, then exactly one final ``LLMResponse``: content = the joined
deltas (capped at 65536 characters, the stream is still read to its end),
model from ``message_start`` (else the configured one), ``done`` unless the stop
reason is ``tool_use``. A ``tool_use`` block's ``input_json_delta`` fragments
are accumulated per block index (at most 128 blocks, 65536 characters each:
crossing either bound rejects the reply; no fragment means ``{}``) and
validated by ``_parse_anthropic_tool_calls`` once the stream ended; tool calls
are never streamed as deltas. The call must end within ``stream_deadline_s`` of
its first iteration: opening and every event read are bounded (never a
``yield``). Errors: setup errors on the first iteration (no request),
``chat()``'s status mapping when opening the stream, a mid-stream ``event:
error`` (which the SDK raises as a status error carrying the stream's 200),
transport or ``httpx.StreamError`` failure ``provider_unavailable``, a
mid-stream timeout or the deadline ``timeout`` (the stream is closed first).

Inputs: conversation messages, tool definitions, ANTHROPIC_API_KEY and the
configured model and caps. Outputs: ``LLMResponse`` / ``LLMStreamDelta`` items
or a catalogue ``LLMError``.

Security notes:
- API key is read from ANTHROPIC_API_KEY env var, never from config files.
- No credentials are logged. LLM output is sanitized by the shared llm.py utilities
  (control characters and lone surrogates stripped).
- Error messages are fixed strings: never the SDK message, a response body or
  an error event's text (the message only classifies a context-length
  failure); SDK errors are raised ``from None``. Stream text, events and tool
  arguments are never logged (a dropped tool call is logged by its name
  through ``safe_log``, a rejected reply by its label and error type only).
- No end-user identifier is sent: the request body holds model, messages,
  max_tokens, system, tools and (streaming) ``stream`` only (never ``metadata``).
- Does not import from agent.py, server.py, or tools/.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import httpx
from pydantic import ValidationError

from admino.llm import (
    _MAX_STREAM_TOOL_CALLS,
    _MAX_TOOL_ARGUMENT_CHARS,
    CappedAnswer,
    LLMError,
    LLMResponse,
    LLMStreamDelta,
    MalformedReplyError,
    check_args_depth,
    malformed_response_error,
    missing_model_error,
    next_before,
    not_configured_error,
    output_token_cap,
    provider_status_error,
    sanitize_tool_args,
    sdk_status_error,
    strip_control_chars,
    validate_tools_payload,
)
from admino.logs import safe_log
from admino.models import LLMMessage, ToolCall

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from admino.config import LLMConfig

logger = logging.getLogger(__name__)

# Provider label shown in user-facing errors and the env var holding the key.
_LABEL = "Claude"
_API_KEY_ENV = "ANTHROPIC_API_KEY"


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

    The bounds are checked on the decoded ``input``; a kept call's arguments
    are then cleaned with ``sanitize_tool_args``. An invalid call is dropped
    and logged by its name only.

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
        log_name = safe_log(_anthropic_name_to_dot(name))
        arguments = getattr(block, "input", {})
        if not isinstance(arguments, dict):
            logger.warning("Skipping tool call '%s': input is not a dict", log_name)
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
            parsed.append(
                ToolCall(
                    tool=tool,
                    action=action,
                    args=sanitize_tool_args(arguments),
                    tool_call_id=block_id,
                )
            )
        except ValidationError:
            logger.warning(
                "Skipping tool call '%s': tool/action failed schema validation",
                log_name,
            )

    return parsed


def _all_tool_calls(blocks: list[Any], sent: int) -> list[ToolCall]:
    """Parse the reply's tool_use blocks; one that doesn't parse rejects the reply.

    Raises:
        MalformedReplyError: Fewer than ``sent`` calls parsed (the parser logged
            each dropped call by its name only).
    """
    parsed = _parse_anthropic_tool_calls(blocks)
    if len(parsed) != sent:
        raise MalformedReplyError
    return parsed


def _message_response(response: object) -> LLMResponse:
    """Build ``chat()``'s LLMResponse from a Messages API ``message``.

    The SDK builds the message without validation, so every field read is
    type-checked. The text blocks are joined, sanitized and capped (never cut
    at a word); every tool_use block must parse.

    Raises:
        LLMError: ``malformed_response``, raised ``from None``, for a non-str
            model, text, tool_use id or name, a content that is not a list, or
            a tool_use block that doesn't parse.
    """
    model = getattr(response, "model", None)
    blocks = getattr(response, "content", None)
    try:
        if not isinstance(model, str) or not isinstance(blocks, list):
            raise MalformedReplyError
        text_parts: list[str] = []
        sent = 0
        for block in blocks:
            kind = getattr(block, "type", None)
            if kind == "text":
                text = getattr(block, "text", None)
                if not isinstance(text, str):
                    raise MalformedReplyError
                text_parts.append(text)
            elif kind == "tool_use":
                call_id = getattr(block, "id", None)
                name = getattr(block, "name", None)
                if not (isinstance(call_id, str) and isinstance(name, str)):
                    raise MalformedReplyError
                sent += 1
        tool_calls = _all_tool_calls(blocks, sent)
    except MalformedReplyError:
        logger.warning("Rejecting malformed %s reply", _LABEL)
        raise malformed_response_error(_LABEL) from None
    answer = CappedAnswer()
    answer.feed(strip_control_chars("\n".join(text_parts)))
    stop_reason = getattr(response, "stop_reason", None)
    return LLMResponse(
        content=answer.answer,
        tool_calls=tool_calls,
        model=strip_control_chars(model)[:200],
        done=stop_reason != "tool_use",
        truncated=stop_reason == "max_tokens" or answer.truncated,
    )


@dataclass
class _StreamedToolUse:
    """One tool_use block rebuilt from stream events (shape read by the Anthropic parser)."""

    id: str
    name: str
    partial_json: str = ""
    input: object = None
    type: str = "tool_use"


class _StreamedMessage:
    """One Anthropic message rebuilt from its stream events.

    Keeps the capped answer text, the tool_use blocks keyed by block index (at
    most ``_MAX_STREAM_TOOL_CALLS``, each one's JSON fragments up to
    ``_MAX_TOOL_ARGUMENT_CHARS``), the model and the stop reason. Events are
    read by their ``type`` and every field read is type-checked: the SDK builds
    them without validation, so an unknown delta type may arrive as a
    ``TextDelta``-shaped object and any field may hold any JSON value.
    """

    def __init__(self) -> None:
        self._text = CappedAnswer()
        self._calls: dict[int, _StreamedToolUse] = {}
        self._model = ""
        self._stop_reason: object = None

    def apply(self, event: object) -> str:
        """Apply one stream event; return the newly visible answer text (maybe "").

        Raises:
            MalformedReplyError: A non-str model, text, partial_json, tool_use id
                or name; a block index that is not an int; a 129th or repeated
                tool_use block; JSON fragments that would cross 65536 characters.
        """
        kind = getattr(event, "type", None)
        if kind == "message_start":
            model = getattr(getattr(event, "message", None), "model", None)
            if not isinstance(model, str):
                raise MalformedReplyError
            self._model = model or self._model
        elif kind == "message_delta":
            stop_reason = getattr(getattr(event, "delta", None), "stop_reason", None)
            self._stop_reason = stop_reason or self._stop_reason
        elif kind in ("content_block_start", "content_block_delta"):
            index = getattr(event, "index", None)
            # type() rather than isinstance(): a bool is not an index.
            if type(index) is not int:
                raise MalformedReplyError
            if kind == "content_block_start":
                self._start_block(index, getattr(event, "content_block", None))
            else:
                return self._apply_delta(index, getattr(event, "delta", None))
        return ""

    def _start_block(self, index: int, block: object) -> None:
        """Track a tool_use block (every other block type is ignored)."""
        if getattr(block, "type", None) != "tool_use":
            return
        call_id = getattr(block, "id", None)
        name = getattr(block, "name", None)
        if (
            not (isinstance(call_id, str) and isinstance(name, str))
            or index in self._calls
            or len(self._calls) >= _MAX_STREAM_TOOL_CALLS
        ):
            raise MalformedReplyError
        self._calls[index] = _StreamedToolUse(id=call_id, name=name)

    def _apply_delta(self, index: int, delta: object) -> str:
        """Apply a text or input_json delta; return the newly visible text (maybe "")."""
        kind = getattr(delta, "type", None)
        if kind == "text_delta":
            text = getattr(delta, "text", None)
            if not isinstance(text, str):
                raise MalformedReplyError
            return self._text.feed(strip_control_chars(text))
        if kind == "input_json_delta":
            fragment = getattr(delta, "partial_json", None)
            if not isinstance(fragment, str):
                raise MalformedReplyError
            call = self._calls.get(index)
            if call is not None:
                # Never appended past the bound, so a cut prefix is never parsed.
                if len(call.partial_json) + len(fragment) > _MAX_TOOL_ARGUMENT_CHARS:
                    raise MalformedReplyError
                call.partial_json += fragment
        return ""

    def response(self, configured_model: str) -> LLMResponse:
        """Return the final response (the model falls back to ``configured_model``).

        Raises:
            MalformedReplyError: A tool_use block that doesn't parse.
        """
        return LLMResponse(
            content=self._text.answer,
            tool_calls=self._tool_calls(),
            model=strip_control_chars(self._model or configured_model)[:200],
            done=self._stop_reason != "tool_use",
            truncated=self._stop_reason == "max_tokens" or self._text.truncated,
        )

    def _tool_calls(self) -> list[ToolCall]:
        """Decode each block's JSON and validate it like ``chat()``, in index order.

        A block without fragments has ``{}`` arguments; malformed JSON skips the
        block (logged by its name only, never its arguments), which rejects the
        reply.
        """
        blocks: list[_StreamedToolUse] = []
        for index in sorted(self._calls):
            call = self._calls[index]
            try:
                call.input = json.loads(call.partial_json) if call.partial_json else {}
            except (ValueError, RecursionError):
                # Invalid JSON, an int over the digit limit, or nesting too deep.
                logger.warning(
                    "Skipping tool call '%s': malformed JSON arguments", safe_log(call.name)
                )
                continue
            blocks.append(call)
        return _all_tool_calls(blocks, len(self._calls))


def _api_error(exc: Exception) -> LLMError:
    """Map an SDK failure when sending a request, or a transport failure, to the catalogue.

    A status maps through ``sdk_status_error`` (Anthropic's error bodies carry a
    type but no code: the message alone classifies a context-length 400 and
    never reaches the LLMError; 529 "overloaded" is a plain 5xx). Without a
    status: ``timeout`` for a timeout (the stream deadline included), else
    ``provider_unavailable`` (a connection, transport or stream failure).
    """
    import anthropic

    if isinstance(exc, anthropic.APIStatusError):
        return sdk_status_error(
            _LABEL,
            exc.status_code,
            headers=exc.response.headers,
            error_code=None,
            sdk_message=exc.message,
            key_env=_API_KEY_ENV,
        )
    # APITimeoutError is the SDK's wrapper; a raw httpx timeout arrives mid-stream;
    # TimeoutError is the stream deadline (GH-25).
    timed_out = isinstance(exc, anthropic.APITimeoutError | httpx.TimeoutException | TimeoutError)
    return provider_status_error(_LABEL, None, key_env=_API_KEY_ENV, timed_out=timed_out)


class AnthropicClient:
    """Async client for Anthropic's Messages API.

    Uses the official ``anthropic`` SDK. Implements the ``LLMClient``
    protocol so it is interchangeable with the other LLMClient backends.
    """

    provider: Final = "anthropic"

    def __init__(self, config: LLMConfig) -> None:
        """Initialize the Anthropic client.

        A missing ANTHROPIC_API_KEY or model does not raise here: the state is
        stored and ``chat()`` answers with a user-facing error instead.

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

        self._model = config.anthropic_model or ""
        self._max_tokens = config.max_response_tokens
        self._stream_deadline_s = config.stream_deadline_s
        api_key = os.environ.get(_API_KEY_ENV, "")
        self._api_key_configured = bool(api_key)
        # Built even without a key so close() stays uniform; chat() refuses to
        # send a request until the key is configured. No SDK retries: one chat()
        # is one request (the model policy decides about retries).
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key,
            timeout=float(config.timeout_s),
            max_retries=0,
        )

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a chat request to Anthropic's Messages API.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).
            stream: Must be False for this method.
            max_tokens: Per-call output cap (GH-179), sent as ``max_tokens``:
                ``min(max_tokens, configured cap)``; None sends the configured cap.

        Returns:
            Parsed LLMResponse (``truncated`` for ``stop_reason == "max_tokens"``
            or text past the 65536-character cap).

        Raises:
            LLMError: Coded (user-facing) when the key or model is missing, the
                key is rejected, the model is unknown, the rate limit is hit,
                Claude is unavailable (5xx, connection), the request timed out,
                the prompt is too long or the reply is malformed (undecodable,
                wrong-typed, or a tool_use block that doesn't parse); internal
                otherwise.
            ValueError: If stream=True is passed, or ``max_tokens`` is below 1,
                a bool or not an int (before any request).
        """
        if stream:
            msg = "Streaming not yet supported for Anthropic provider"
            raise ValueError(msg)
        cap = output_token_cap(self._max_tokens, max_tokens)
        kwargs = self._request(messages, tools, cap)

        import anthropic

        try:
            response = await self._client.messages.create(**kwargs)
        except (anthropic.APIConnectionError, anthropic.APIStatusError) as exc:
            # Raised ``from None`` so the SDK exception (and any response body)
            # never travels with the LLMError.
            raise _api_error(exc) from None
        except (ValueError, RecursionError):
            # The SDK decodes the 200 body itself and raises these raw.
            raise malformed_response_error(_LABEL) from None
        return _message_response(response)

    async def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncGenerator[LLMStreamDelta | LLMResponse, None]:
        """Stream a reply from Claude: answer deltas, then exactly one final LLMResponse.

        The request is ``chat()``'s body (configured output cap) plus ``stream:
        true``. Only ``text_delta`` text is streamed (sanitized, stops at the
        content cap); tool_use blocks come only in the final response. The call
        must end within ``stream_deadline_s`` of its first iteration (opening
        included); each provider read is bounded, a yield never is.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).

        Yields:
            ``LLMStreamDelta`` pieces, then the final ``LLMResponse``.

        Raises:
            LLMError: ``chat()``'s setup errors on the first iteration (no
                request), its status mapping when opening the stream (before any
                delta); ``provider_unavailable`` for a mid-stream error event,
                transport or stream failure, ``timeout`` for a mid-stream timeout
                or the deadline, ``malformed_response`` for a reply it can't use.
        """
        deadline = asyncio.get_running_loop().time() + self._stream_deadline_s
        kwargs = self._request(messages, tools, self._max_tokens)

        import anthropic

        try:
            async with asyncio.timeout_at(deadline):
                stream = await self._client.messages.create(**kwargs, stream=True)
        except (anthropic.APIConnectionError, anthropic.APIStatusError, TimeoutError) as exc:
            raise _api_error(exc) from None

        message = _StreamedMessage()
        async with stream:
            events = aiter(stream)
            try:
                while (event := await next_before(events, deadline)) is not None:
                    piece = message.apply(event)
                    if piece:
                        yield LLMStreamDelta(content=piece)
                final = message.response(self._model)
            except anthropic.APIStatusError:
                # A mid-stream ``event: error``: the SDK raises it as a status error
                # carrying the opened stream's 200, so it is not a status to map.
                raise provider_status_error(_LABEL, None, key_env=_API_KEY_ENV) from None
            except (httpx.TransportError, httpx.StreamError, TimeoutError) as exc:
                raise _api_error(exc) from None
            except (MalformedReplyError, ValueError, RecursionError, httpx.DecodingError) as exc:
                # The SDK raises ValueError / RecursionError raw for an event it can't decode.
                logger.warning("Rejecting malformed %s reply (%s)", _LABEL, type(exc).__name__)
                raise malformed_response_error(_LABEL) from None
        yield final

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
        system_prompt, api_messages = _convert_messages_to_anthropic(messages)
        # Ensure we have at least one message
        if not api_messages:
            api_messages = [{"role": "user", "content": "Hello"}]
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "max_tokens": cap,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if tools:
            try:
                validate_tools_payload(tools)
            except ValueError as exc:
                raise LLMError(message=str(exc), status_code=None) from None
            kwargs["tools"] = _convert_tools_to_anthropic(tools)
        return kwargs

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
