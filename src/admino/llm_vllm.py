"""Local vLLM backend — opt-in local provider (first-class, OpenAI-compatible).

vLLM is admino's optional local LLM provider (started with ``make start-local``;
Infomaniak is the default). This module implements ``VLLMClient``, which wraps
the official ``openai`` SDK pointed at a *local* OpenAI-compatible endpoint
(``config.vllm_base_url``) serving ``config.vllm_model``. It reuses the OpenAI
conversion/parse helpers and the shared ``admino.llm`` sanitizers so the
request/response shape is identical to the OpenAI backend.

Inputs/outputs:
- ``VLLMClient.chat()`` sends messages/tools to the local endpoint and returns a
  sanitized ``LLMResponse`` (content, tool_calls, model, done). Its keyword-only
  ``max_tokens`` (GH-179) lowers the request's ``max_tokens`` to
  ``min(max_tokens, config.max_response_tokens)``; None keeps the configured cap,
  an invalid value is a ``ValueError`` before any request.
- ``VLLMClient.chat_stream()`` (GH-8) sends ``chat()``'s request body plus
  ``stream: true`` (configured cap) and yields sanitized ``LLMStreamDelta``
  pieces, then exactly one final ``LLMResponse`` (content = the joined deltas,
  capped at 65536 characters; tool calls only in the final response). It reads
  the stream with the shared OpenAI-compatible reader in ``llm_openai.py``.
  ``<think>`` blocks are not filtered (as in ``chat()``).
- ``VLLMClient.close()`` releases the underlying HTTP client.

Errors (provider label "vLLM", GH-242 codes): a missing/empty ``vllm_model``
does not fail construction; ``chat()`` raises the "No vLLM model is set …"
error (``missing_model``) instead (``chat_stream()`` on its first iteration,
before any request). Connection failures (``provider_unavailable``) and
timeouts (``timeout``), also mid-stream, carry a "starting or unavailable"
message pointing to ``make start-local``; 404, 429, 5xx and a 400/413 whose
input exceeds the context map to the shared catalogue in ``llm.py`` (429/5xx
with the response's Retry-After). vLLM has no key, so every other status
(including 401/403) stays internal (code None, ``user_facing=False``, "vLLM API
returned HTTP <n>"). The SDK never retries (``max_retries=0``): one ``chat()``
or ``chat_stream()`` is one request; retries belong to ``admino.llm_policy``.

Security notes:
- Local-only: requests go to ``config.vllm_base_url`` (a local endpoint). No
  message content ever leaves the machine when the endpoint is local.
- No API key is read from the environment — the local server needs none, so a
  fixed non-empty dummy key is sent to satisfy the SDK.
- Error messages are fixed strings: never the SDK message, a response body or
  the body's error code (those only classify a context-length failure).
- No end-user or account identifier is sent: no ``user``/``metadata``-style
  body key, and the SDK's env-derived OpenAI organization and project headers
  (OPENAI_ORG_ID / OPENAI_PROJECT_ID) are cleared.
- LLM output is sanitized by the shared llm.py utilities.
- Does not import from agent.py, server.py, or tools/.
"""

from __future__ import annotations

from contextlib import aclosing
from typing import TYPE_CHECKING, Any, Final

import httpx

from admino.llm import (
    CappedAnswer,
    LLMError,
    LLMResponse,
    missing_model_error,
    output_token_cap,
    sanitize_content,
    sdk_status_error,
    strip_control_chars,
    validate_tools_payload,
)

# Reuse the OpenAI conversion/parse helpers and stream reader verbatim — the
# served endpoint is OpenAI-compatible, so the request/response translation is
# identical.
from admino.llm_openai import (
    _convert_messages_to_openai,
    _convert_tools_to_openai,
    _parse_openai_tool_calls,
    _stream_reply,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from admino.config import LLMConfig
    from admino.llm import LLMStreamDelta
    from admino.models import LLMMessage

# Provider label shown in user-facing errors.
_LABEL = "vLLM"

# Placeholder API key sent to the SDK. The local vLLM server ignores it, but the
# openai SDK requires a non-empty key. Never read a real key from the env here.
_DUMMY_API_KEY = "sk-vllm-local"

# Friendly, leak-free message for an unreachable/starting local endpoint. Must
# contain both "starting" and "unavailable" so the user understands the 12B
# model may still be loading — never embed the raw SDK cause or response body.
# vLLM is opt-in, so point to the target that provisions and starts it.
_VLLM_UNAVAILABLE_MESSAGE = (
    "The local vLLM model is starting or unavailable. "
    "Check that the vLLM server is running (make start-local)."
)


def _api_error(exc: Exception) -> LLMError:
    """Map an SDK or transport failure (opening or mid-stream) to the catalogue.

    A status maps through ``sdk_status_error`` without a key (401/403 stay
    internal); the endpoint's code and message only classify a context-length
    400. Anything without a status (connection or transport failure, timeout,
    an error event inside an opened stream) is the "starting or unavailable"
    message: ``timeout`` for a timeout, else ``provider_unavailable``.
    """
    import openai

    if isinstance(exc, openai.APIStatusError):
        return sdk_status_error(
            _LABEL,
            exc.status_code,
            headers=exc.response.headers,
            error_code=exc.code,
            sdk_message=exc.message,
        )
    # APITimeoutError is the SDK's wrapper; a raw httpx timeout arrives mid-stream.
    timed_out = isinstance(exc, openai.APITimeoutError | httpx.TimeoutException)
    return LLMError(
        message=_VLLM_UNAVAILABLE_MESSAGE,
        code="timeout" if timed_out else "provider_unavailable",
    )


class VLLMClient:
    """Async client for a local OpenAI-compatible vLLM endpoint.

    Uses the official ``openai`` SDK pointed at ``config.vllm_base_url``.
    Implements the ``LLMClient`` protocol so it is interchangeable with the
    other backends. Needs no API key (a dummy placeholder is sent).
    """

    provider: Final = "vllm"

    def __init__(self, config: LLMConfig) -> None:
        """Initialize the vLLM client.

        A missing/empty ``vllm_model`` does not raise here: ``chat()`` answers
        with a user-facing error instead.

        Args:
            config: LLM configuration with vllm_model, vllm_base_url, timeout_s.

        Raises:
            ImportError: If the ``openai`` package is not installed.
        """
        try:
            import openai
        except ImportError as exc:
            msg = (
                "The 'openai' package is required for the vLLM provider. "
                "Install it with: pip install openai"
            )
            raise ImportError(msg) from exc

        self._model = config.vllm_model or ""
        self._timeout_s = config.timeout_s
        self._max_tokens = config.max_response_tokens
        self._base_url = config.vllm_base_url
        # No API key is read from the environment — the local server needs none.
        # No SDK retries: one chat() is one request (the model policy retries).
        self._client = openai.AsyncOpenAI(
            base_url=config.vllm_base_url,
            api_key=_DUMMY_API_KEY,
            timeout=float(config.timeout_s),
            max_retries=0,
        )
        # The SDK fills these from OPENAI_ORG_ID / OPENAI_PROJECT_ID: OpenAI
        # account identifiers that are never sent.
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
        """Send a chat request to the local vLLM (OpenAI-compatible) endpoint.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).
            stream: Must be False for this method.
            max_tokens: Per-call output cap (GH-179), sent as ``max_tokens``:
                ``min(max_tokens, configured cap)``; None sends the configured cap.

        Returns:
            Parsed LLMResponse.

        Raises:
            LLMError: Coded (user-facing) when the model is missing, the endpoint
                is starting/unreachable or timed out, the model is unknown (404),
                the rate limit is hit, the endpoint fails (5xx) or the input is
                too long; internal otherwise.
            ValueError: If stream=True is passed, or ``max_tokens`` is below 1,
                a bool or not an int (before any request).
        """
        if stream:
            msg = "Streaming not yet supported for vLLM provider"
            raise ValueError(msg)
        cap = output_token_cap(self._max_tokens, max_tokens)
        kwargs = self._request(messages, tools, cap)

        import openai

        try:
            response = await self._client.chat.completions.create(**kwargs)
        except (openai.APIConnectionError, openai.APIStatusError) as exc:
            # The local server may still be loading the model, or be down: raised
            # ``from None`` so the SDK cause/body never travels with the error.
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
        """Stream a reply from vLLM: answer deltas, then exactly one final LLMResponse.

        The request is ``chat()``'s body (configured output cap) plus ``stream:
        true``. Deltas are sanitized and stop at the content cap; tool calls
        come only in the final response.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).

        Yields:
            ``LLMStreamDelta`` pieces, then the final ``LLMResponse``.

        Raises:
            LLMError: ``missing_model`` on the first iteration (no request), the
                ``chat()`` status mapping when opening the stream (before any
                delta), the "starting or unavailable" ``timeout`` /
                ``provider_unavailable`` error also mid-stream.
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
            LLMError: ``missing_model`` without a model; an internal error for a
                tools payload over its limits.
        """
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

    async def __aenter__(self) -> VLLMClient:
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
