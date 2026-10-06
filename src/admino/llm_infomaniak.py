"""Infomaniak AI Services backend — the default provider (Swiss-hosted, OpenAI-compatible).

``InfomaniakClient`` wraps the official ``openai`` SDK pointed at
``https://api.infomaniak.com/2/ai/{product_id}/openai/v1`` and serves
``config.infomaniak_model``. It reuses the OpenAI conversion/parse helpers, the
OpenAI-compatible stream reader (``llm_openai._stream_reply``: tool-call
fragments accumulated per index, at most 128 calls, 256 name and 65536 argument
characters each, parsed once the stream ended) and the shared ``admino.llm``
sanitizers, so requests and responses have the same shape as the other
OpenAI-compatible backends.

Inputs:
- ``INFOMANIAK_API_TOKEN`` (env, required at chat time): bearer token with the
  ``ai-tools`` scope. ``INFOMANIAK_PRODUCT_ID`` (env, optional): ASCII digits
  only; when unset, the product is discovered with ``GET /1/ai``.
Outputs:
- ``chat()`` returns one sanitized ``LLMResponse`` (content, tool_calls, model,
  done, usage). ``chat_stream()`` yields ``LLMStreamDelta`` pieces and then
  exactly one final ``LLMResponse``. ``list_models()`` returns the served model
  ids (``[]`` on any failure). ``discover_product_id()`` / ``resolve_product_id()``
  return the product id used in every product-scoped URL.

Construction never raises for a missing token, product id or model and performs
no I/O: those problems surface as coded ``LLMError`` chat replies (GH-242). The
SDK client is built lazily on first use (``max_retries=0``: one ``chat()`` is
one request; retries belong to ``admino.llm_policy``, the V1 bridge of #174's
gateway). ``_new_http_client`` is the only place an ``httpx.AsyncClient`` is
constructed (discovery, model listing and the SDK all go through it).

Error codes: a missing token, a non-digit INFOMANIAK_PRODUCT_ID, no AI product
or several of them are ``not_configured``; a missing model ``missing_model``.
Chat, stream (also mid-stream) and discovery failures map through the shared
catalogue: a timeout is ``timeout``, a transport error ``provider_unavailable``,
401/403 ``not_configured``, 404 ``missing_model`` (chat only; a discovery 404 is
internal), 429 ``rate_limited`` and 5xx ``provider_unavailable`` (both with the
response's Retry-After), a chat 400/413 whose input exceeds the context
``context_too_long``; other statuses stay internal.

Request shape follows Infomaniak's documented schema for
``POST /2/ai/{product_id}/openai/v1/chat/completions``: the output cap is sent as
``max_completion_tokens`` and ``chat()`` sends an explicit ``stream: false``
(``stream`` defaults to true there). ``chat()``'s keyword-only ``max_tokens``
(GH-179, the chat-title call) lowers that cap to
``min(max_tokens, config.max_response_tokens)`` and changes nothing else; None
keeps the configured cap, an invalid value is a ``ValueError`` before any
request or product discovery. ``chat_stream()`` always sends the configured cap.
Tool-call turns are replayed with ``tool_calls`` so every ``tool`` result
answers its call.

Reasoning: requests send ``reasoning_effort: "none"`` (thinking is on by
default for most models). Reasoning never reaches the answer: the
``reasoning_content`` / ``reasoning`` fields that vLLM-style servers may add are
never read; ``<think>…</think>`` blocks are removed from the content (also when a
tag is split across stream chunks); an unclosed ``<think>`` drops the rest of the
reply; an orphan ``</think>`` (its opening tag was in the prompt template) drops
everything before it. A stream's deltas already sent can't be taken back: after an
orphan ``</think>`` the final content (``chat()``'s rule) is shorter than the
joined deltas, which total at most 65536 characters whatever the orphan tags (a
budget that never resets). Without an orphan tag, the final content is the
joined deltas.

Security notes:
- The token is read from the environment only; it is sent solely as the
  ``Authorization`` header and is never logged or put in an error message.
- Errors carry fixed catalogue messages (see ``admino.llm``): never an SDK
  ``exc.message``, a response body, its error code (those only classify a
  context-length failure), or the ``account_name`` / ``product_name`` returned
  by discovery. SDK errors are raised ``from None`` so the response body does
  not travel with the ``LLMError``. Logs contain only safe metadata (exception
  type, HTTP status).
- No end-user or account identifier is sent (no ``user``, ``safety_identifier``,
  ``prompt_cache_key``, ``metadata``; the SDK's env-derived OpenAI organization
  and project headers are cleared).
- The product id must be ASCII digits before it is placed in a URL.
- LLM output is sanitized (control/bidi characters and lone surrogates
  stripped, 65536-char cap). A stream's deltas total at most 65536 characters
  too; orphan ``</think>`` tags never reset that budget.
- Streamed tool calls share the OpenAI reader's bounds (128 calls, 256-char
  names, 65536-char arguments; a call crossing a bound is dropped).
- Does not import from agent.py, server.py, or tools/.
"""

from __future__ import annotations

import logging
import os
import re
from contextlib import aclosing
from typing import TYPE_CHECKING, Any, Final

import httpx

from admino.llm import (
    _MAX_CONTENT_LENGTH,
    LLMError,
    LLMResponse,
    missing_model_error,
    not_configured_error,
    output_token_cap,
    parse_retry_after,
    provider_status_error,
    sdk_status_error,
    strip_control_chars,
    validate_tools_payload,
)

# The endpoint is OpenAI-compatible: reuse the OpenAI translation helpers and
# stream reader verbatim.
from admino.llm_openai import (
    _convert_messages_to_openai,
    _convert_tools_to_openai,
    _parse_openai_tool_calls,
    _stream_reply,
    _usage,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from openai import AsyncOpenAI

    from admino.config import LLMConfig
    from admino.llm import LLMStreamDelta
    from admino.models import LLMMessage

logger = logging.getLogger(__name__)

INFOMANIAK_API_BASE: Final = "https://api.infomaniak.com"
_AUTH_ENV_VAR: Final = "INFOMANIAK_API_TOKEN"
_PRODUCT_ID_ENV_VAR: Final = "INFOMANIAK_PRODUCT_ID"

_LABEL: Final = "Infomaniak"
_KEY_NOUN: Final = "API token"
# Timeout for the small metadata calls (discovery, model listing).
_METADATA_TIMEOUT_S: Final = 10.0
# ASCII digits only — str.isdigit() would also accept e.g. fullwidth digits.
_PRODUCT_ID_RE: Final = re.compile(r"[0-9]+")

_INVALID_PRODUCT_ID_MESSAGE: Final = (
    "INFOMANIAK_PRODUCT_ID must be the numeric Infomaniak product ID; fix it on the server."
)
_NO_PRODUCT_MESSAGE: Final = (
    "No Infomaniak AI product was found for this token; create one in the "
    "Infomaniak Manager or set INFOMANIAK_PRODUCT_ID on the server."
)
_SEVERAL_PRODUCTS_MESSAGE: Final = (
    "Several Infomaniak AI products were found; set INFOMANIAK_PRODUCT_ID on the server."
)
_DISCOVERY_FAILED_MESSAGE: Final = "Infomaniak product discovery failed"
_DISCOVERY_MALFORMED_MESSAGE: Final = "Infomaniak product discovery returned unexpected data"
_UNEXPECTED_ERROR_MESSAGE: Final = "Infomaniak returned an unexpected error"

_THINK_OPEN: Final = "<think>"
_THINK_CLOSE: Final = "</think>"
_THINK_TAG_RE: Final = re.compile(r"</?think>")


def _new_http_client(timeout_s: float) -> httpx.AsyncClient:
    """Return a new HTTP client for Infomaniak requests (the single client seam).

    Redirects are not followed (httpx default), so the bearer token only ever
    goes to ``api.infomaniak.com``.
    """
    return httpx.AsyncClient(timeout=timeout_s)


def _product_base_url(product_id: str) -> str:
    """Return the product-scoped OpenAI-compatible base URL."""
    return f"{INFOMANIAK_API_BASE}/2/ai/{product_id}/openai/v1"


async def _authorized_get(url: str, token: str, timeout_s: float) -> httpx.Response:
    """GET ``url`` with bearer auth through a short-lived client (body fully read)."""
    async with _new_http_client(timeout_s) as http:
        return await http.get(url, headers={"Authorization": f"Bearer {token}"})


async def discover_product_id(token: str, *, timeout_s: float = _METADATA_TIMEOUT_S) -> str:
    """Discover the account's single AI product id via ``GET /1/ai``.

    Args:
        token: Infomaniak API token (sent as a bearer header, never logged).
        timeout_s: Request timeout in seconds.

    Returns:
        The product id as a string of ASCII digits.

    Raises:
        LLMError: coded (user-facing) for no product or several products
            (``not_configured``, asks for INFOMANIAK_PRODUCT_ID), a rejected
            token (``not_configured``), rate limiting (``rate_limited``), 5xx
            and transport failures (``provider_unavailable``) and timeouts
            (``timeout``); internal (code None) for any other status or a
            malformed payload. Messages never contain the response body, the
            account/product names, or the token.
    """
    try:
        response = await _authorized_get(f"{INFOMANIAK_API_BASE}/1/ai", token, timeout_s)
    except httpx.RequestError as exc:
        logger.warning("Infomaniak product discovery failed: %s", type(exc).__name__)
        timed_out = isinstance(exc, httpx.TimeoutException)
        raise provider_status_error(_LABEL, None, timed_out=timed_out) from None
    if not response.is_success:
        status = response.status_code
        logger.warning("Infomaniak product discovery failed: HTTP %d", status)
        if status == 404:  # the catalogue's 404 text is about models, not products
            raise LLMError(_DISCOVERY_FAILED_MESSAGE, status_code=status)
        raise provider_status_error(
            _LABEL,
            status,
            key_env=_AUTH_ENV_VAR,
            key_noun=_KEY_NOUN,
            internal_message=_DISCOVERY_FAILED_MESSAGE,
            retry_after_s=parse_retry_after(response.headers),
        )

    try:
        payload = response.json()
    except ValueError:
        payload = None
    products = (
        payload.get("data")
        if isinstance(payload, dict) and payload.get("result") == "success"
        else None
    )
    if not isinstance(products, list):
        logger.warning("Infomaniak product discovery returned an unexpected payload")
        raise LLMError(_DISCOVERY_MALFORMED_MESSAGE)
    if not products:
        raise LLMError(_NO_PRODUCT_MESSAGE, code="not_configured")
    if len(products) > 1:
        raise LLMError(_SEVERAL_PRODUCTS_MESSAGE, code="not_configured")
    product_id = products[0].get("product_id") if isinstance(products[0], dict) else None
    if type(product_id) is not int or not _PRODUCT_ID_RE.fullmatch(str(product_id)):
        logger.warning("Infomaniak product discovery returned an invalid product id")
        raise LLMError(_DISCOVERY_MALFORMED_MESSAGE)
    return str(product_id)


def _api_error(exc: Exception) -> LLMError:
    """Map an SDK / transport failure to the fixed catalogue (no message or body).

    The SDK's error code and message only classify a context-length 400; they
    are never logged or kept.
    """
    import openai

    if isinstance(exc, openai.APIStatusError):
        logger.warning(
            "Infomaniak request failed: %s (HTTP %s)", type(exc).__name__, exc.status_code
        )
        return sdk_status_error(
            _LABEL,
            exc.status_code,
            headers=exc.response.headers,
            error_code=exc.code,
            sdk_message=exc.message,
            key_env=_AUTH_ENV_VAR,
            key_noun=_KEY_NOUN,
        )
    if not isinstance(exc, openai.APIConnectionError | httpx.TransportError):
        logger.warning("Infomaniak request failed: %s", type(exc).__name__)
        return LLMError(_UNEXPECTED_ERROR_MESSAGE)
    logger.warning("Infomaniak request failed: %s (no response)", type(exc).__name__)
    # APITimeoutError is the SDK's wrapper; a raw httpx timeout arrives mid-stream.
    timed_out = isinstance(exc, openai.APITimeoutError | httpx.TimeoutException)
    return provider_status_error(
        _LABEL, None, key_env=_AUTH_ENV_VAR, key_noun=_KEY_NOUN, timed_out=timed_out
    )


def _held_tag_len(text: str, start: int, *tags: str) -> int:
    """Length of the longest suffix of ``text[start:]`` that may begin one of ``tags``."""
    for size in range(min(len(text) - start, len(_THINK_CLOSE) - 1), 0, -1):
        suffix = text[len(text) - size :]
        if any(tag.startswith(suffix) for tag in tags):
            return size
    return 0


class _ThinkFilter:
    """Remove ``<think>…</think>`` reasoning from text that arrives in pieces.

    Linear-time and stateful: a possible tag split across pieces (``"<thi"`` +
    ``"nk>"``) is held back until it can be classified; text inside a block is
    discarded; an unclosed block drops everything after its opening tag; an
    orphan ``</think>`` discards the answer collected so far. Leading whitespace
    left behind by removed reasoning is trimmed, and the answer is capped at the
    ``LLMResponse`` content limit.

    What ``feed()`` / ``finish()`` return (a stream's deltas) can't be taken back
    by a later orphan ``</think>``: that text is capped at the content limit in
    total, a budget no orphan tag resets, so a hostile stream can't send more
    than 65536 delta characters by repeating orphan tags. Without an orphan tag
    the returned text is exactly ``answer``.
    """

    def __init__(self) -> None:
        self._inside = False
        self._held = ""
        self._trim = False
        self._parts: list[str] = []
        self._length = 0
        self._emitted = 0

    @property
    def answer(self) -> str:
        """The visible answer collected so far."""
        return "".join(self._parts)

    def feed(self, text: str) -> str:
        """Consume a sanitized piece of text; return the newly visible answer text."""
        buf = self._held + text
        self._held = ""
        visible: list[str] = []
        pos = 0
        while pos < len(buf):
            if self._inside:
                end = buf.find(_THINK_CLOSE, pos)
                if end == -1:
                    self._held = buf[len(buf) - _held_tag_len(buf, pos, _THINK_CLOSE) :]
                    break
                self._inside = False
                pos = end + len(_THINK_CLOSE)
                continue
            tag = _THINK_TAG_RE.search(buf, pos)
            if tag is None:
                held = _held_tag_len(buf, pos, _THINK_OPEN, _THINK_CLOSE)
                visible.append(self._keep(buf[pos : len(buf) - held]))
                self._held = buf[len(buf) - held :]
                break
            visible.append(self._keep(buf[pos : tag.start()]))
            pos = tag.end()
            if tag.group() == _THINK_OPEN:
                self._inside = True
                if not self._parts:
                    self._trim = True
            else:
                # Orphan close tag: everything before it was reasoning.
                visible.clear()
                self._parts.clear()
                self._length = 0
                self._trim = True
        return self._emit("".join(visible))

    def finish(self) -> str:
        """Flush held-back text at the end; an unclosed block's text is dropped."""
        held, self._held = self._held, ""
        return "" if self._inside else self._emit(self._keep(held))

    def _emit(self, text: str) -> str:
        """Return what of ``text`` fits the stream's delta budget (never reset)."""
        text = text[: _MAX_CONTENT_LENGTH - self._emitted]
        self._emitted += len(text)
        return text

    def _keep(self, text: str) -> str:
        """Append visible text to the answer (trim + cap); return what was kept."""
        if self._trim:
            text = text.lstrip()
            self._trim = not text
        text = text[: _MAX_CONTENT_LENGTH - self._length]
        if text:
            self._parts.append(text)
            self._length += len(text)
        return text


def _answer_text(raw: str) -> str:
    """Sanitize a complete reply and remove its reasoning."""
    think = _ThinkFilter()
    think.feed(strip_control_chars(raw))
    think.finish()
    return think.answer


class InfomaniakClient:
    """Async client for Infomaniak AI Services (OpenAI-compatible chat completions).

    Implements the ``LLMClient`` protocol. Setup problems (missing token, model or
    product id) are reported by ``chat()`` / ``chat_stream()`` as user-facing
    errors, never by the constructor.
    """

    provider: Final = "infomaniak"

    def __init__(self, config: LLMConfig) -> None:
        """Read the token, product id and model; no I/O, no setup validation errors.

        Args:
            config: LLM configuration (infomaniak_model, timeout_s, max_response_tokens).

        Raises:
            ImportError: If the ``openai`` package is not installed.
        """
        try:
            import openai  # noqa: F401 — availability check; the SDK is used lazily
        except ImportError as exc:
            msg = (
                "The 'openai' package is required for the Infomaniak provider. "
                "Install it with: pip install openai"
            )
            raise ImportError(msg) from exc

        self._token: str = os.environ.get(_AUTH_ENV_VAR, "").strip()
        raw_product_id = os.environ.get(_PRODUCT_ID_ENV_VAR, "").strip()
        self._product_id: str | None = (
            raw_product_id if _PRODUCT_ID_RE.fullmatch(raw_product_id) else None
        )
        self._product_id_invalid: bool = bool(raw_product_id) and self._product_id is None
        self._model: str = config.infomaniak_model or ""
        self._timeout_s: float = float(config.timeout_s)
        self._max_tokens: int = config.max_response_tokens
        self._client: AsyncOpenAI | None = None

    def _require_token(self) -> str:
        """Return the API token or raise the user-facing "isn't configured" error."""
        if not self._token:
            raise not_configured_error(_LABEL, _AUTH_ENV_VAR)
        return self._token

    async def resolve_product_id(self) -> str:
        """Return INFOMANIAK_PRODUCT_ID, or discover it (cached after success only).

        Raises:
            LLMError: ``not_configured`` for a missing token or a non-digit
                INFOMANIAK_PRODUCT_ID; otherwise as ``discover_product_id``.
        """
        token = self._require_token()
        if self._product_id_invalid:
            raise LLMError(_INVALID_PRODUCT_ID_MESSAGE, code="not_configured")
        if self._product_id is None:
            self._product_id = await discover_product_id(token)
        return self._product_id

    async def _sdk_client(self) -> AsyncOpenAI:
        """Return the product-scoped SDK client, creating it on first use."""
        product_id = await self.resolve_product_id()
        if self._client is None:
            import openai

            client = openai.AsyncOpenAI(
                base_url=_product_base_url(product_id),
                api_key=self._token,
                timeout=self._timeout_s,
                max_retries=0,
                http_client=_new_http_client(self._timeout_s),
            )
            # The SDK fills these from OPENAI_ORG_ID / OPENAI_PROJECT_ID: OpenAI
            # account identifiers that must never be sent to Infomaniak.
            client.organization = None
            client.project = None
            self._client = client
        return self._client

    async def _prepare(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None,
        max_completion_tokens: int,
    ) -> tuple[AsyncOpenAI, dict[str, Any]]:
        """Check the setup, build the request kwargs and return them with the SDK client."""
        self._require_token()
        if not self._model:
            raise missing_model_error(_LABEL)
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": _convert_messages_to_openai(messages),
            # Infomaniak documents max_completion_tokens (not the legacy max_tokens).
            "max_completion_tokens": max_completion_tokens,
            "reasoning_effort": "none",
        }
        if tools:
            try:
                validate_tools_payload(tools)
            except ValueError as exc:
                raise LLMError(message=str(exc)) from None
            kwargs["tools"] = _convert_tools_to_openai(tools)
        return await self._sdk_client(), kwargs

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a non-streaming chat request to Infomaniak.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).
            stream: Must be False; use ``chat_stream()`` to stream.
            max_tokens: Per-call output cap (GH-179), sent as
                ``max_completion_tokens``: ``min(max_tokens, configured cap)``;
                None sends the configured cap.

        Returns:
            Parsed LLMResponse with reasoning removed.

        Raises:
            LLMError: Catalogue errors (user-facing or internal, never a body).
            ValueError: If stream=True is passed, or ``max_tokens`` is below 1,
                a bool or not an int (before any request or discovery).
        """
        if stream:
            msg = "InfomaniakClient.chat() does not stream; use chat_stream()"
            raise ValueError(msg)
        cap = output_token_cap(self._max_tokens, max_tokens)

        import openai

        client, kwargs = await self._prepare(messages, tools, cap)
        try:
            # Infomaniak documents ``stream`` as defaulting to true and the SDK omits
            # the key unless it is passed, so ask for a single JSON reply explicitly.
            response = await client.chat.completions.create(**kwargs, stream=False)
        except openai.APIError as exc:
            raise _api_error(exc) from None

        model = strip_control_chars(response.model or self._model)[:200]
        usage = _usage(response.usage)
        if not response.choices:
            return LLMResponse(model=model, done=True, usage=usage)
        choice = response.choices[0]
        return LLMResponse(
            content=_answer_text(choice.message.content or ""),
            tool_calls=_parse_openai_tool_calls(choice.message.tool_calls),
            model=model,
            done=choice.finish_reason != "tool_calls",
            usage=usage,
        )

    async def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncGenerator[LLMStreamDelta | LLMResponse, None]:
        """Stream a chat reply: answer deltas, then exactly one final LLMResponse.

        Deltas are sanitized with reasoning removed and stop at the content cap.
        Tool-call fragments are accumulated per index and parsed at the end.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions (admino tool format).

        Yields:
            ``LLMStreamDelta`` pieces, then the final ``LLMResponse`` (content,
            tool_calls, model, usage, done).

        Raises:
            LLMError: Catalogue errors; HTTP errors are raised before any delta,
                a transport failure or timeout may also come after one.
        """
        import openai

        client, kwargs = await self._prepare(messages, tools, self._max_tokens)
        try:
            stream = await client.chat.completions.create(
                **kwargs, stream=True, stream_options={"include_usage": True}
            )
        except openai.APIError as exc:
            raise _api_error(exc) from None
        reply = _stream_reply(
            stream, _ThinkFilter(), configured_model=self._model, stream_error=_api_error
        )
        # aclosing: closing this generator early closes the HTTP stream at once.
        async with aclosing(reply) as items:
            async for item in items:
                yield item

    async def list_models(self) -> list[str]:
        """Return the sanitized ids of the served models; ``[]`` on any failure."""
        try:
            product_id = await self.resolve_product_id()
        except LLMError:
            return []
        try:
            response = await _authorized_get(
                f"{_product_base_url(product_id)}/models", self._token, _METADATA_TIMEOUT_S
            )
        except httpx.HTTPError as exc:
            logger.warning("Listing Infomaniak models failed: %s", type(exc).__name__)
            return []
        if not response.is_success:
            logger.warning("Listing Infomaniak models failed: HTTP %d", response.status_code)
            return []
        try:
            payload = response.json()
        except ValueError:
            payload = None
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            logger.warning("Infomaniak returned an unexpected models payload")
            return []
        ids = (item.get("id") for item in data if isinstance(item, dict))
        return [
            strip_control_chars(model_id)[:200] for model_id in ids if isinstance(model_id, str)
        ]

    async def close(self) -> None:
        """Close the SDK client (and its HTTP client) if it was created."""
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def __aenter__(self) -> InfomaniakClient:
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
