"""Local vLLM backend — opt-in local provider (first-class, OpenAI-compatible).

vLLM is admino's optional local LLM provider (started with ``make start-local``;
Infomaniak is the default). This module implements ``VLLMClient``, which wraps
the official ``openai`` SDK pointed at a *local* OpenAI-compatible endpoint
(``config.vllm_base_url``) serving ``config.vllm_model``. It reuses the OpenAI
conversion/parse helpers and the shared ``admino.llm`` sanitizers so the
request/response shape is identical to the OpenAI backend.

Inputs/outputs:
- ``VLLMClient.chat()`` sends messages/tools to the local endpoint and returns a
  sanitized ``LLMResponse`` (content, tool_calls, model, done).
- ``VLLMClient.close()`` releases the underlying HTTP client.

Errors (provider label "vLLM"): a missing/empty ``vllm_model`` does not fail
construction; ``chat()`` raises the user-facing "No vLLM model is set …" error
instead. Connection/timeout failures raise a user-facing "starting or
unavailable" message pointing to ``make start-local``; 404, 429 and 5xx map to
the shared catalogue in ``llm.py``. vLLM has no key, so every other status
(including 401/403) stays internal (``user_facing=False``).

Security notes:
- Local-only: requests go to ``config.vllm_base_url`` (a local endpoint). No
  message content ever leaves the machine when the endpoint is local.
- No API key is read from the environment — the local server needs none, so a
  fixed non-empty dummy key is sent to satisfy the SDK.
- Connection/timeout failures map to a FRIENDLY ``LLMError`` that never embeds
  the raw SDK cause/response body (the served model may still be loading).
  User-facing messages are fixed strings.
- LLM output is sanitized by the shared llm.py utilities.
- Does not import from agent.py, server.py, or tools/.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from admino.llm import (
    LLMError,
    LLMResponse,
    missing_model_error,
    provider_status_error,
    sanitize_content,
    strip_control_chars,
    validate_tools_payload,
)

# Reuse the OpenAI conversion/parse helpers verbatim — the served endpoint is
# OpenAI-compatible, so the request/response translation is identical.
from admino.llm_openai import (
    _convert_messages_to_openai,
    _convert_tools_to_openai,
    _parse_openai_tool_calls,
)

if TYPE_CHECKING:
    from admino.config import LLMConfig
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


class VLLMClient:
    """Async client for a local OpenAI-compatible vLLM endpoint.

    Uses the official ``openai`` SDK pointed at ``config.vllm_base_url``.
    Implements the ``LLMClient`` protocol so it is interchangeable with the
    other backends. Needs no API key (a dummy placeholder is sent).
    """

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
        self._client = openai.AsyncOpenAI(
            base_url=config.vllm_base_url,
            api_key=_DUMMY_API_KEY,
            timeout=float(config.timeout_s),
        )

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        """Send a chat request to the local vLLM (OpenAI-compatible) endpoint.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).
            stream: Must be False for this method.

        Returns:
            Parsed LLMResponse.

        Raises:
            LLMError: User-facing when the model is missing, the endpoint is
                starting/unreachable, the model is unknown (404), the rate limit
                is hit or the endpoint fails (5xx); internal otherwise.
            ValueError: If stream=True is passed.
        """
        if stream:
            msg = "Streaming not yet supported for vLLM provider"
            raise ValueError(msg)
        if not self._model:
            raise missing_model_error(_LABEL)

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
        except openai.APIConnectionError:
            # Also covers APITimeoutError (a subclass). The local server may still
            # be loading the model, or be down. Surface a friendly message; raised
            # ``from None`` so the SDK cause/body never travels with the error.
            raise LLMError(
                message=_VLLM_UNAVAILABLE_MESSAGE,
                status_code=None,
                user_facing=True,
            ) from None
        except openai.APIStatusError as exc:
            # exc.message is the endpoint's own error description — not the request
            # body and does not contain conversation content. It only reaches the
            # internal (log-only) message; user-facing messages are fixed. No
            # key_env: vLLM has no key, so 401/403 stay internal.
            api_error = strip_control_chars(str(exc.message))[:500]
            raise provider_status_error(
                _LABEL,
                exc.status_code,
                internal_message=f"vLLM endpoint returned HTTP {exc.status_code}: {api_error}",
            ) from None

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
