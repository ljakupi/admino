"""Streaming for the OpenAI-compatible clients: ``chat_stream`` (GH-8, contract C1).

``OpenAIClient.chat_stream`` and ``VLLMClient.chat_stream`` are new;
``InfomaniakClient.chat_stream`` exists and is held to the same tool-call rules
here (parity). Every client is built from a real ``LLMConfig`` and drives the
REAL ``openai`` SDK against a fake wire: ``httpx.AsyncClient.send`` is replaced
by a recorder that keeps every outgoing request (method, URL, headers, body) and
answers with a scripted response (an SSE stream of ``data: <chunk>`` lines and
``data: [DONE]``, an error status, a stream that breaks mid-way, or a raised
transport error). Nothing reaches a real host.

What these tests pin (each for OpenAI and vLLM unless noted):

- Protocol: ``admino.llm.LLMClient`` requires ``chat_stream``. All four real
  clients (Infomaniak, vLLM, OpenAI, Anthropic, built by ``create_llm_client``)
  are ``LLMClient`` instances with a ``chat_stream``; an object with
  ``provider``, ``chat`` and ``close`` but no ``chat_stream`` is not.
- Shape: non-empty text deltas in order, then exactly one ``LLMResponse``, last;
  ``final.content`` is the concatenation of the deltas; empty-content chunks
  (role-only, ``null``, controls only, no choices) yield no delta.
- Sanitizing across chunk boundaries: C0 controls (NUL, ESC: an ANSI sequence
  loses its ESC), C1 (NEL, CSI), bidi overrides and isolates, zero-width
  characters, U+2028/U+2029 and the BOM are removed; tab, LF and CR are kept.
- Content cap: 65536 characters counted after sanitizing; no delta carries text
  past it, and a tool call, ``finish_reason`` and model that arrive after the
  cap still reach the final response (the stream is read to its end).
- Tool calls (OpenAI, vLLM and Infomaniak): fragments accumulated by index (id
  only in the first fragment, the name split, arguments split inside a JSON
  string, inside an escape sequence and between the halves of a surrogate pair;
  two calls interleaved), returned in index order, never as deltas; invalid
  calls dropped and valid ones kept (bad JSON, non-object JSON, depth 5, 33
  keys, a 2049-character top-level string, more than 16384 characters of JSON,
  a name without a dot, a schema-invalid name), the dropped call's arguments
  never logged; at most 128 calls (the first 128 indexes); a call whose
  arguments grow past 65536 characters is dropped, the others kept.
- ``done`` is False on ``finish_reason == "tool_calls"`` and True otherwise;
  the model is the stream's (sanitized, at most 200 characters) or the
  configured one when the stream names none.
- Setup errors before any request: OpenAI without ``OPENAI_API_KEY``
  (``not_configured``) or without a model, vLLM without a model
  (``missing_model``); the same error as ``chat()``.
- HTTP errors when opening the stream map like ``chat()`` (401/403
  ``not_configured`` for OpenAI, uncoded for keyless vLLM; 404
  ``missing_model``; 429 ``rate_limited`` and 503 ``provider_unavailable`` with
  their Retry-After; a context-length 400 ``context_too_long``; 418 uncoded),
  raised before any delta, ``from None``, after exactly one request, and the
  response body's marker never reaches the error or any log record (DEBUG).
- A transport failure mid-stream: ``timeout`` for a read timeout,
  ``provider_unavailable`` otherwise (vLLM keeps its "starting or unavailable"
  message), raised after the consumer already got the deltas, the same error
  ``chat()`` raises for that failure.
- Request: exactly ``chat()``'s body plus ``"stream": true`` (no
  ``stream_options``, no identifier keys), the configured
  ``max_response_tokens``; no ``OpenAI-Organization`` / ``OpenAI-Project``
  header and no trace of the ``OPENAI_ORG_ID`` / ``OPENAI_PROJECT_ID`` canaries.
- ``llm_policy.chat_stream`` through the real clients: a 503 when opening, then
  a good stream: two requests and the deltas once; a transport failure after
  the first delta: one request, no retry, the ``LLMError`` propagates.

Security notes:
- Keys are built at runtime (``tests.credential_keys``); every marker lives
  only in a fake response, never in a request.
- The openai SDK's retry sleep is a no-op, so a client whose SDK still retries
  fails fast (and visibly, by its request count) instead of sleeping.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import unquote

import httpx
import openai._base_client as openai_base_client
import pytest

import admino.llm_policy as policy
from admino.config import LLMConfig
from admino.llm import LLMClient, LLMError, LLMResponse, LLMStreamDelta, create_llm_client
from admino.llm_infomaniak import InfomaniakClient
from admino.llm_openai import OpenAIClient
from admino.llm_vllm import VLLMClient
from admino.models import LLMMessage
from tests.credential_keys import api_key

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The clients that gain chat_stream, and the OpenAI-compatible ones held to the
# same tool-call rules (Infomaniak's chat_stream exists already).
NEW_STREAMING: Final[tuple[str, ...]] = ("openai", "vllm")
OPENAI_COMPATIBLE: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak")

_OPENAI_MODEL: Final = "gpt-4o"
_VLLM_MODEL: Final = "Qwen/Qwen3-4B-Instruct-2507"
_IK_MODEL: Final = "Qwen/Qwen3.5-397B-A17B-FP8"
_ANTHROPIC_MODEL: Final = "claude-sonnet-4-6"
_CONFIGURED_MODELS: Final[dict[str, str]] = {
    "openai": _OPENAI_MODEL,
    "vllm": _VLLM_MODEL,
    "infomaniak": _IK_MODEL,
}
_STREAM_MODEL: Final = "wire-stream-model"
_MAX_TOKENS: Final = 777
_MAX_CONTENT: Final = 65536
_IK_PRODUCT_ID: Final = "7539"

# Runtime-built fake credentials (never a key literal in the repo).
_OPENAI_KEY: Final = api_key("sk-", 48, seed=8101).text
_ANTHROPIC_KEY: Final = api_key("sk-" + "ant-", 48, seed=8102).text
_IK_TOKEN: Final = api_key("ik-", 40, seed=8103).text

# OpenAI account identifiers the SDK would read from the environment.
_ORG_CANARY: Final = "org-CANARY-W1-STREAM"
_PROJECT_CANARY: Final = "proj-CANARY-W1-STREAM"

# A marker planted in tool-call arguments: never in a delta, content or log line.
_ARG_MARKER: Final = "ARGS-MARKER-w1-5e1f"

# Characters built with chr() so no invisible character lives in the source.
_BS: Final = chr(0x5C)  # backslash (JSON escapes inside streamed arguments)
_NUL: Final = chr(0x00)
_ESC: Final = chr(0x1B)
_NEL: Final = chr(0x85)
_CSI: Final = chr(0x9B)
_LRE: Final = chr(0x202A)
_PDF: Final = chr(0x202C)
_RLO: Final = chr(0x202E)
_LRI: Final = chr(0x2066)
_PDI: Final = chr(0x2069)
_ZWSP: Final = chr(0x200B)
_ZWJ: Final = chr(0x200D)
_LSEP: Final = chr(0x2028)
_PSEP: Final = chr(0x2029)
_BOM: Final = chr(0xFEFF)
_E_ACUTE: Final = chr(0xE9)
_GRIN: Final = chr(0x1F600)

# What strip_control_chars removes (contract C1.2): no delta may carry any of it.
_BANNED: Final[frozenset[str]] = frozenset(
    [chr(c) for c in range(32) if c not in (9, 10, 13)]
    + [chr(c) for c in range(0x80, 0xA0)]
    + [chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2028, 0x2029, 0xFEFF)]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
)

_OPENAI_STREAM_KEYS: Final = frozenset({"model", "messages", "max_tokens", "stream"})
_ACCOUNT_HEADERS: Final = frozenset({"openai-organization", "openai-project"})

_MEMORY_TOOL: Final[dict[str, Any]] = {
    "type": "function",
    "function": {
        "name": "memory.store",
        "description": "Store a note",
        "parameters": {
            "type": "object",
            "properties": {"key": {"type": "string"}, "value": {"type": "string"}},
        },
    },
}

# ---------------------------------------------------------------------------
# Stream chunks
# ---------------------------------------------------------------------------


def _chunk(
    delta: dict[str, Any] | None = None,
    *,
    finish_reason: str | None = None,
    model: str = _STREAM_MODEL,
    no_choices: bool = False,
) -> dict[str, Any]:
    """One OpenAI ``chat.completion.chunk``."""
    return {
        "id": "chatcmpl-w1-stream",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": model,
        "choices": []
        if no_choices
        else [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}],
    }


def _text_chunks(
    *pieces: str, finish_reason: str = "stop", model: str = _STREAM_MODEL
) -> list[dict[str, Any]]:
    """Content-only chunks followed by a finishing chunk."""
    chunks = [_chunk({"content": piece}, model=model) for piece in pieces]
    chunks.append(_chunk({}, finish_reason=finish_reason, model=model))
    return chunks


def _frag(
    index: int,
    *,
    call_id: str | None = None,
    name: str | None = None,
    arguments: str | None = None,
) -> dict[str, Any]:
    """One streamed tool-call fragment (``choices[0].delta.tool_calls[i]``)."""
    fragment: dict[str, Any] = {"index": index}
    if call_id is not None:
        fragment["id"] = call_id
        fragment["type"] = "function"
    function: dict[str, Any] = {}
    if name is not None:
        function["name"] = name
    if arguments is not None:
        function["arguments"] = arguments
    if function:
        fragment["function"] = function
    return fragment


def _tools_chunk(*fragments: dict[str, Any], model: str = _STREAM_MODEL) -> dict[str, Any]:
    """A chunk carrying tool-call fragments only."""
    return _chunk({"tool_calls": list(fragments)}, model=model)


def _split_call(index: int, call_id: str, name: str, arguments: str) -> list[dict[str, Any]]:
    """One tool call as two chunks: id + name + first half, then the second half."""
    half = len(arguments) // 2
    return [
        _tools_chunk(_frag(index, call_id=call_id, name=name, arguments=arguments[:half])),
        _tools_chunk(_frag(index, arguments=arguments[half:])),
    ]


def _sse_bytes(chunks: list[dict[str, Any]], *, done: bool = True) -> bytes:
    """``data: <chunk>`` lines, then ``data: [DONE]`` when ``done``."""
    text = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks)
    return (text + ("data: [DONE]\n\n" if done else "")).encode("utf-8")


# ---------------------------------------------------------------------------
# Wire routes
# ---------------------------------------------------------------------------


class _BreakingStream(httpx.AsyncByteStream):
    """An SSE body that sends ``first``, then breaks with ``error``."""

    def __init__(self, first: bytes, error: Exception) -> None:
        self._first = first
        self._error = error

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._first
        raise self._error


def _sse(chunks: list[dict[str, Any]]) -> Callable[[httpx.Request], httpx.Response]:
    """A route answering with a complete SSE stream."""
    body = _sse_bytes(chunks)

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=body, request=request
        )

    return route


def _breaking_sse(
    chunks: list[dict[str, Any]], exc_type: type[httpx.TransportError], marker: str
) -> Callable[[httpx.Request], httpx.Response]:
    """A route streaming ``chunks``, then failing with ``exc_type`` (no ``[DONE]``)."""
    first = _sse_bytes(chunks, done=False)

    def route(request: httpx.Request) -> httpx.Response:
        error = exc_type(f"stream broke {marker}", request=request)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_BreakingStream(first, error),
            request=request,
        )

    return route


def _status(
    status: int, marker: str, *, headers: dict[str, str] | None = None, context: bool = False
) -> Callable[[httpx.Request], httpx.Response]:
    """A route answering an error status whose body carries ``marker``."""
    message = (
        f"This model's maximum context length is 8192 tokens. {marker}"
        if context
        else f"upstream detail {marker}"
    )
    body = {"error": {"message": message, "type": "invalid_request_error", "code": marker}}

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers or {}, json=body, request=request)

    return route


def _raise(
    exc_type: type[httpx.TransportError], marker: str
) -> Callable[[httpx.Request], httpx.Response]:
    """A route failing at send time with a transport error."""

    def route(request: httpx.Request) -> httpx.Response:
        raise exc_type(f"transport failure {marker}", request=request)

    return route


def _completion() -> Callable[[httpx.Request], httpx.Response]:
    """A route answering a plain (non-streamed) ``chat.completion``."""
    body = {
        "id": "chatcmpl-w1-json",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": _STREAM_MODEL,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}
        ],
    }

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body, request=request)

    return route


# ---------------------------------------------------------------------------
# The fake wire
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Sent:
    """One recorded outgoing request."""

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    @property
    def is_chat(self) -> bool:
        """True for a chat-completions request."""
        return self.method == "POST" and httpx.URL(self.url).path.endswith("/chat/completions")

    def json_body(self) -> dict[str, Any]:
        """The JSON request body."""
        payload = json.loads(self.body)
        assert isinstance(payload, dict)
        return payload

    def header_names(self) -> set[str]:
        """The lower-cased header names."""
        return {name.lower() for name, _ in self.headers}

    def everything(self) -> str:
        """URL (raw and decoded), every header and the body, lower-cased."""
        parts = [
            self.method,
            self.url,
            unquote(self.url),
            *(f"{name}: {value}" for name, value in self.headers),
            self.body.decode("utf-8", errors="replace"),
        ]
        return "\n".join(parts).lower()


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    ``answer_with(*routes)`` scripts the next chat requests: the first one gets
    ``routes[0]``, the next ``routes[1]`` and so on; the last route repeats.
    """

    def __init__(self) -> None:
        self.sent: list[_Sent] = []
        self._routes: list[Callable[[httpx.Request], httpx.Response]] = [_sse(_text_chunks("Hi"))]
        self._offset = 0

    @property
    def chat_requests(self) -> list[_Sent]:
        """The recorded chat requests, in order."""
        return [sent for sent in self.sent if sent.is_chat]

    def answer_with(self, *routes: Callable[[httpx.Request], httpx.Response]) -> None:
        """Script the answers to the chat requests that follow."""
        self._routes = list(routes)
        self._offset = len(self.chat_requests)

    def leaked(self, *needles: str) -> list[str]:
        """The needles (case-insensitive) found anywhere in any recorded request."""
        haystacks = [sent.everything() for sent in self.sent]
        return [needle for needle in needles if any(needle.lower() in h for h in haystacks)]

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it."""
        body = await request.aread()
        sent = _Sent(
            method=request.method,
            url=str(request.url),
            headers=tuple(request.headers.multi_items()),
            body=body,
        )
        self.sent.append(sent)
        if not sent.is_chat:
            return httpx.Response(404, json={"error": "unexpected path"}, request=request)
        index = min(len(self.chat_requests) - self._offset, len(self._routes)) - 1
        return self._routes[index](request)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every provider configured; the OpenAI account identifiers set to canaries."""
    monkeypatch.setenv("OPENAI_API_KEY", _OPENAI_KEY)
    monkeypatch.setenv("ANTHROPIC_API_KEY", _ANTHROPIC_KEY)
    monkeypatch.setenv("INFOMANIAK_API_TOKEN", _IK_TOKEN)
    monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", _IK_PRODUCT_ID)
    monkeypatch.setenv("OPENAI_ORG_ID", _ORG_CANARY)
    monkeypatch.setenv("OPENAI_PROJECT_ID", _PROJECT_CANARY)
    for name in ("OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "OPENAI_LOG"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_sdk_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client whose SDK still retries fails fast instead of sleeping between tries."""

    async def no_sleep(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(openai_base_client.AsyncAPIClient, "_sleep_for_retry", no_sleep)


@pytest.fixture()
def wire(monkeypatch: pytest.MonkeyPatch) -> _Wire:
    """Route every ``httpx.AsyncClient.send`` through the recording fake wire."""
    fake = _Wire()

    async def send(_client: httpx.AsyncClient, request: httpx.Request, **_: Any) -> httpx.Response:
        return await fake.send(request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    return fake


def _config(provider: str, **overrides: Any) -> LLMConfig:
    """A real LLMConfig selecting ``provider``, every model set unless overridden."""
    values: dict[str, Any] = {
        "provider": provider,
        "timeout_s": 5,
        "max_response_tokens": _MAX_TOKENS,
        "infomaniak_model": _IK_MODEL,
        "vllm_model": _VLLM_MODEL,
        "vllm_base_url": "http://vllm:8000/v1",
        "openai_model": _OPENAI_MODEL,
        "anthropic_model": _ANTHROPIC_MODEL,
    }
    values.update(overrides)
    return LLMConfig(**values)


_CLIENT_CLASSES: Final[dict[str, Callable[[LLMConfig], Any]]] = {
    "infomaniak": InfomaniakClient,
    "vllm": VLLMClient,
    "openai": OpenAIClient,
}


@pytest.fixture()
async def build(wire: _Wire) -> AsyncIterator[Callable[..., Any]]:
    """Build provider clients on the fake wire; every built client is closed after."""
    built: list[Any] = []

    def factory(provider: str, **overrides: Any) -> Any:
        client = _CLIENT_CLASSES[provider](_config(provider, **overrides))
        built.append(client)
        return client

    yield factory
    for client in built:
        await client.close()


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the model policy's retry delays instead of sleeping."""
    recorded: list[float] = []

    async def fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(policy, "_sleep", fake_sleep)
    return recorded


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _messages() -> list[LLMMessage]:
    """A system prompt and one user message."""
    return [
        LLMMessage(role="system", content="You are admino."),
        LLMMessage(role="user", content="Please answer"),
    ]


async def _drain(client: Any, tools: list[dict[str, Any]] | None = None) -> list[Any]:
    """Drain ``client.chat_stream`` into a list."""
    return [item async for item in client.chat_stream(_messages(), tools)]


async def _drain_error(client: Any) -> tuple[list[Any], LLMError]:
    """Iterate ``chat_stream`` until it raises; return what arrived first and the error."""
    received: list[Any] = []
    with pytest.raises(LLMError) as exc_info:
        async for item in client.chat_stream(_messages()):
            received.append(item)
    return received, exc_info.value


async def _chat_error(client: Any) -> LLMError:
    """The LLMError ``client.chat`` raises for the wire's next answer."""
    with pytest.raises(LLMError) as exc_info:
        await client.chat(_messages())
    return exc_info.value


def _deltas(items: list[Any]) -> list[str]:
    """The text of every streamed delta, in order."""
    return [item.content for item in items if isinstance(item, LLMStreamDelta)]


def _final(items: list[Any]) -> LLMResponse:
    """The stream's final response, after checking the stream's shape.

    Every item but the last is a non-empty delta, the last is the only
    LLMResponse, and its content is the concatenation of the deltas.
    """
    assert items, "the stream yielded nothing"
    final = items[-1]
    assert isinstance(final, LLMResponse)
    assert all(isinstance(item, LLMStreamDelta) and item.content for item in items[:-1])
    assert final.content == "".join(_deltas(items))
    return final


def _calls(final: LLMResponse) -> list[tuple[str, str, dict[str, Any], str | None]]:
    """The final response's tool calls as (tool, action, args, id) tuples."""
    return [(c.tool, c.action, c.args, c.tool_call_id) for c in final.tool_calls]


def _shape(err: LLMError) -> tuple[Any, ...]:
    """What a caller sees of an LLMError (compared between chat and chat_stream)."""
    return (
        type(err),
        getattr(err, "code", "<missing>"),
        err.message,
        err.status_code,
        getattr(err, "retry_after_s", "<missing>"),
        err.user_facing,
    )


def _first_difference(actual: str, expected: str) -> tuple[int, int, str, str] | None:
    """None when equal, else (len diff, first index, 20-char windows) for a short report."""
    if actual == expected:
        return None
    index = next(
        (i for i, (a, b) in enumerate(zip(actual, expected, strict=False)) if a != b),
        min(len(actual), len(expected)),
    )
    return (
        len(actual) - len(expected),
        index,
        actual[index : index + 20],
        expected[index : index + 20],
    )


# ===========================================================================
# Protocol
# ===========================================================================


@pytest.mark.parametrize("provider", ["infomaniak", "vllm", "openai", "anthropic"])
async def test_llm_stream_every_real_client_is_an_llm_client_with_chat_stream(
    provider: str,
) -> None:
    """The factory's client for every provider is an LLMClient that can stream."""
    client = create_llm_client(_config(provider))
    try:
        assert isinstance(client, LLMClient)
        assert callable(getattr(client, "chat_stream", None))
    finally:
        await client.close()


def test_llm_stream_protocol_requires_chat_stream() -> None:
    """``provider`` + ``chat`` + ``close`` is not enough: ``chat_stream`` is required."""

    class ChatOnly:
        provider = "openai"

        async def chat(
            self,
            messages: list[LLMMessage],
            tools: list[dict[str, Any]] | None = None,
            *,
            stream: bool = False,
            max_tokens: int | None = None,
        ) -> LLMResponse:
            return LLMResponse(done=True)

        async def close(self) -> None:
            return None

    class Streaming(ChatOnly):
        async def chat_stream(
            self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
        ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
            yield LLMResponse(done=True)

    assert (isinstance(ChatOnly(), LLMClient), isinstance(Streaming(), LLMClient)) == (
        False,
        True,
    )


# ===========================================================================
# Text deltas
# ===========================================================================


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_text_deltas_in_order_then_one_final(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """Each content chunk becomes one delta, in order; one final response, last."""
    wire.answer_with(_sse(_text_chunks("Hel", "lo ", "world")))
    items = await _drain(build(provider))
    assert _deltas(items) == ["Hel", "lo ", "world"]
    final = _final(items)
    assert (final.content, final.tool_calls, final.done) == ("Hello world", [], True)
    assert len(wire.chat_requests) == 1


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_empty_chunks_yield_no_delta(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """Role-only, null, controls-only and choice-less chunks produce no delta."""
    chunks = [
        _chunk({"role": "assistant", "content": ""}),
        _chunk({"content": None}),
        _chunk({"content": _NUL + _ESC + _ZWSP + _BOM}),
        _chunk(no_choices=True),
        *_text_chunks("Hi"),
    ]
    wire.answer_with(_sse(chunks))
    items = await _drain(build(provider))
    assert _deltas(items) == ["Hi"]
    assert _final(items).content == "Hi"


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_deltas_sanitized_across_chunk_boundaries(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """C0/C1 controls, bidi, zero-width, separators and BOM go; tab, LF, CR stay."""
    pieces = (
        "Hel" + _NUL + "lo " + _ESC + "[31m",
        "red" + _ESC,
        "[0m\t" + _NEL + "a" + _CSI + "b",
        _RLO + "c" + _LRE + _LRI + "d" + _PDI + _PDF,
        _ZWSP + "e" + _ZWJ + _BOM + "f",
        _LSEP + "g" + _PSEP + "\r\n",
        "\x07\x08",
        "end",
    )
    wire.answer_with(_sse(_text_chunks(*pieces)))
    items = await _drain(build(provider))
    deltas = _deltas(items)
    assert "".join(deltas) == "Hello [31mred[0m\tabcdefg\r\nend"
    assert [d for d in deltas if set(d) & _BANNED] == []
    assert _final(items).content == "Hello [31mred[0m\tabcdefg\r\nend"


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_content_cap_counted_after_sanitizing(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """The concatenated deltas are exactly the first 65536 sanitized characters."""
    pieces = (
        _NUL * 2000 + "a" * 30000,
        _ZWSP * 2000 + "b" * 30000,
        "c" * 30000,
        "LATE-TEXT",
    )
    wire.answer_with(_sse(_text_chunks(*pieces)))
    items = await _drain(build(provider))
    expected = "a" * 30000 + "b" * 30000 + "c" * (_MAX_CONTENT - 60000)
    deltas = _deltas(items)
    assert _first_difference("".join(deltas), expected) is None
    assert [d for d in deltas if "LATE" in d] == []
    assert _first_difference(_final(items).content, expected) is None


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_after_cap_stream_still_read_to_its_end(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """A tool call, finish_reason and model arriving after the cap reach the final response."""
    chunks = [
        _chunk({"content": "a" * 40000}, model=""),
        _chunk({"content": "b" * 40000}, model=""),
        _tools_chunk(_frag(0, call_id="call_late", name="memory.store", arguments='{"key"')),
        _tools_chunk(_frag(0, arguments=': "k"}'), model="late-stream-model"),
        _chunk({}, finish_reason="tool_calls", model="late-stream-model"),
    ]
    wire.answer_with(_sse(chunks))
    items = await _drain(build(provider), [_MEMORY_TOOL])
    final = _final(items)
    assert len(final.content) == _MAX_CONTENT
    assert _calls(final) == [("memory", "store", {"key": "k"}, "call_late")]
    assert (final.done, final.model) == (False, "late-stream-model")


# ===========================================================================
# Tool calls (OpenAI, vLLM and, for parity, Infomaniak)
# ===========================================================================


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_stream_split_tool_call_fragments_parse(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """Id once, name split, arguments split in a string, an escape and a surrogate pair."""
    chunks = [
        _tools_chunk(_frag(0, call_id="call_split", name="mem", arguments="")),
        _tools_chunk(_frag(0, name="ory.st")),
        _tools_chunk(_frag(0, name="ore", arguments='{"key": "ca')),
        _tools_chunk(_frag(0, arguments="f" + _BS + "u00")),
        _tools_chunk(_frag(0, arguments='e9", "value": "' + _BS + "ud83d")),
        _tools_chunk(_frag(0, arguments=_BS + 'ude00 v"}')),
        _chunk({}, finish_reason="tool_calls"),
    ]
    wire.answer_with(_sse(chunks))
    items = await _drain(build(provider), [_MEMORY_TOOL])
    final = _final(items)
    expected_args = {"key": "caf" + _E_ACUTE, "value": _GRIN + " v"}
    assert _calls(final) == [("memory", "store", expected_args, "call_split")]
    assert (_deltas(items), final.done) == ([], False)


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_stream_interleaved_tool_calls_returned_in_index_order(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """Fragments of two indexes interleave (index 1 first); the result follows the index."""
    chunks = [
        _tools_chunk(_frag(1, call_id="call_b", name="memory.recall", arguments='{"key":')),
        _tools_chunk(_frag(0, call_id="call_a", name="memory.store", arguments='{"key"')),
        _tools_chunk(_frag(1, arguments=' "b"}'), _frag(0, arguments=': "a"}')),
        _chunk({}, finish_reason="tool_calls"),
    ]
    wire.answer_with(_sse(chunks))
    final = _final(await _drain(build(provider), [_MEMORY_TOOL]))
    assert _calls(final) == [
        ("memory", "store", {"key": "a"}, "call_a"),
        ("memory", "recall", {"key": "b"}, "call_b"),
    ]


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_stream_tool_calls_never_streamed_as_deltas(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """Text and tool-call fragments mixed: only the text is streamed."""
    chunks = [
        _chunk({"content": "Saving "}),
        _tools_chunk(
            _frag(0, call_id="call_m", name="memory.store", arguments='{"key": "' + _ARG_MARKER)
        ),
        _chunk(
            {"content": "it now", "tool_calls": [_frag(0, arguments='", "value": "v"}')]},
        ),
        _chunk({}, finish_reason="tool_calls"),
    ]
    wire.answer_with(_sse(chunks))
    items = await _drain(build(provider), [_MEMORY_TOOL])
    final = _final(items)
    assert [d for d in _deltas(items) if _ARG_MARKER in d or "memory" in d] == []
    assert final.content == "Saving it now"
    assert _calls(final) == [("memory", "store", {"key": _ARG_MARKER, "value": "v"}, "call_m")]


def _nested(levels: int) -> dict[str, Any]:
    """``levels`` nested dicts around a marker leaf."""
    value: dict[str, Any] = {"leaf": _ARG_MARKER}
    for _ in range(levels - 1):
        value = {"nested": value}
    return value


# (name, JSON arguments) of one invalid call each: every one is dropped.
_INVALID_CALLS: Final[dict[str, tuple[str, str]]] = {
    "bad-json": ("memory.store", '{"key": "' + _ARG_MARKER),
    "non-object-json": ("memory.store", json.dumps([_ARG_MARKER])),
    "depth-5": ("memory.store", json.dumps(_nested(5))),
    "33-keys": ("memory.store", json.dumps({f"k{i}": _ARG_MARKER for i in range(33)})),
    "2049-char-string": ("memory.store", json.dumps({"big": _ARG_MARKER.ljust(2049, "x")})),
    "json-over-16384": (
        "memory.store",
        json.dumps({f"k{i}": _ARG_MARKER.ljust(1000, "x") for i in range(20)}),
    ),
    "name-without-dot": ("memorystore", json.dumps({"key": _ARG_MARKER})),
    "schema-invalid-name": ("Memory.store", json.dumps({"key": _ARG_MARKER})),
}


@pytest.mark.parametrize("kind", list(_INVALID_CALLS))
@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_stream_invalid_tool_call_dropped_valid_kept(
    provider: str,
    kind: str,
    wire: _Wire,
    build: Callable[..., Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The invalid call between two valid ones is dropped; its arguments are never logged."""
    caplog.set_level(logging.DEBUG)
    name, arguments = _INVALID_CALLS[kind]
    chunks = [
        *_split_call(0, "call_0", "memory.store", '{"key": "first"}'),
        *_split_call(1, "call_1", name, arguments),
        *_split_call(2, "call_2", "memory.recall", '{"key": "third"}'),
        _chunk({}, finish_reason="tool_calls"),
    ]
    wire.answer_with(_sse(chunks))
    items = await _drain(build(provider), [_MEMORY_TOOL])
    assert _calls(_final(items)) == [
        ("memory", "store", {"key": "first"}, "call_0"),
        ("memory", "recall", {"key": "third"}, "call_2"),
    ]
    assert _ARG_MARKER not in caplog.text


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_stream_at_most_128_tool_calls_first_indexes_kept(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """130 tool-call indexes: the calls of indexes 0..127 only, in order."""
    fragments = [
        _frag(i, call_id=f"call_{i}", name="memory.store", arguments=json.dumps({"n": i}))
        for i in range(130)
    ]
    chunks = [_tools_chunk(*fragments[start : start + 10]) for start in range(0, 130, 10)]
    chunks.append(_chunk({}, finish_reason="tool_calls"))
    wire.answer_with(_sse(chunks))
    final = _final(await _drain(build(provider), [_MEMORY_TOOL]))
    assert [call.args["n"] for call in final.tool_calls] == list(range(128))


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_stream_tool_arguments_past_65536_chars_dropped(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """Whitespace-padded JSON: 59010 chars is kept, 72010 chars stops growing and is dropped."""
    pad = " " * 8000
    chunks = [
        _tools_chunk(_frag(0, call_id="call_0", name="memory.store", arguments='{"key": "a"')),
        _tools_chunk(_frag(1, call_id="call_1", name="memory.store", arguments='{"key": "b"')),
        _tools_chunk(_frag(2, call_id="call_2", name="memory.store", arguments='{"key": "c"}')),
    ]
    for _ in range(7):
        chunks.append(_tools_chunk(_frag(0, arguments=pad), _frag(1, arguments=pad)))
    chunks.append(_tools_chunk(_frag(0, arguments=" " * 3000 + "}"), _frag(1, arguments=pad)))
    chunks.append(_tools_chunk(_frag(1, arguments=pad)))
    chunks.append(_tools_chunk(_frag(1, arguments="}")))
    chunks.append(_chunk({}, finish_reason="tool_calls"))
    wire.answer_with(_sse(chunks))
    final = _final(await _drain(build(provider), [_MEMORY_TOOL]))
    assert _calls(final) == [
        ("memory", "store", {"key": "a"}, "call_0"),
        ("memory", "store", {"key": "c"}, "call_2"),
    ]


# ===========================================================================
# done and model
# ===========================================================================


@pytest.mark.parametrize(
    ("finish_reason", "done"),
    [("tool_calls", False), ("stop", True), ("length", True), (None, True)],
    ids=["tool_calls", "stop", "length", "no-finish-reason"],
)
@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_done_follows_finish_reason(
    provider: str,
    finish_reason: str | None,
    done: bool,
    wire: _Wire,
    build: Callable[..., Any],
) -> None:
    """``done`` is False only when the stream finished for tool calls."""
    chunks = [_chunk({"content": "Hi"})]
    if finish_reason is not None:
        chunks.append(_chunk({}, finish_reason=finish_reason))
    wire.answer_with(_sse(chunks))
    final = _final(await _drain(build(provider)))
    assert final.done is done


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_model_from_stream_sanitized_and_capped(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """The stream's model name loses its controls and is cut to 200 characters."""
    raw_model = "gpt" + _NUL + _RLO + "-stream-" + "m" * 300
    wire.answer_with(_sse(_text_chunks("Hi", model=raw_model)))
    final = _final(await _drain(build(provider)))
    assert final.model == ("gpt-stream-" + "m" * 300)[:200]


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_configured_model_when_stream_names_none(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """A stream without a model name reports the configured model."""
    wire.answer_with(_sse(_text_chunks("Hi", model="")))
    final = _final(await _drain(build(provider)))
    assert final.model == _CONFIGURED_MODELS[provider]


# ===========================================================================
# Setup errors
# ===========================================================================


@pytest.mark.parametrize(
    ("provider", "missing", "code"),
    [
        ("openai", "key", "not_configured"),
        ("openai", "model", "missing_model"),
        ("vllm", "model", "missing_model"),
    ],
    ids=["openai-no-key", "openai-no-model", "vllm-no-model"],
)
async def test_llm_stream_setup_error_before_any_request(
    provider: str,
    missing: str,
    code: str,
    wire: _Wire,
    build: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing key or model raises chat()'s coded error; nothing reaches the wire."""
    if missing == "key":
        monkeypatch.delenv("OPENAI_API_KEY")
        client = build(provider)
    else:
        client = build(provider, **{f"{provider}_model": None})
    received, err = await _drain_error(client)
    assert (received, wire.sent) == ([], [])
    assert (getattr(err, "code", "<missing>"), err.user_facing) == (code, True)
    assert _shape(err) == _shape(await _chat_error(client))


# ===========================================================================
# HTTP errors when opening the stream
# ===========================================================================

# id -> (provider, status, response headers, context-length body, code, retry_after_s)
_OPEN_ERRORS: Final[dict[str, tuple[str, int, dict[str, str], bool, str | None, float | None]]] = {
    "openai-401": ("openai", 401, {}, False, "not_configured", None),
    "openai-403": ("openai", 403, {}, False, "not_configured", None),
    "openai-404": ("openai", 404, {}, False, "missing_model", None),
    "openai-429": ("openai", 429, {"retry-after": "3"}, False, "rate_limited", 3.0),
    "openai-503": ("openai", 503, {"retry-after": "2"}, False, "provider_unavailable", 2.0),
    "openai-400-context": ("openai", 400, {}, True, "context_too_long", None),
    "openai-418": ("openai", 418, {}, False, None, None),
    "vllm-401": ("vllm", 401, {}, False, None, None),
    "vllm-403": ("vllm", 403, {}, False, None, None),
    "vllm-404": ("vllm", 404, {}, False, "missing_model", None),
    "vllm-429": ("vllm", 429, {"retry-after": "3"}, False, "rate_limited", 3.0),
    "vllm-503": ("vllm", 503, {"retry-after": "2"}, False, "provider_unavailable", 2.0),
    "vllm-400-context": ("vllm", 400, {}, True, "context_too_long", None),
    "vllm-418": ("vllm", 418, {}, False, None, None),
}


@pytest.mark.parametrize("case", list(_OPEN_ERRORS))
async def test_llm_stream_open_http_error_maps_like_chat(
    case: str,
    wire: _Wire,
    build: Callable[..., Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catalogue error before any delta, one request, from None, no body text anywhere."""
    caplog.set_level(logging.DEBUG)
    provider, status, headers, context, code, retry_after_s = _OPEN_ERRORS[case]
    marker = f"OPEN-BODY-MARKER-{case}"
    wire.answer_with(_status(status, marker, headers=headers, context=context))
    client = build(provider)
    received, err = await _drain_error(client)
    stream_log = caplog.text
    stream_records = [record.getMessage() for record in caplog.records]

    assert (received, len(wire.chat_requests)) == ([], 1)
    expected_facing = code is not None
    assert (getattr(err, "code", "<missing>"), err.status_code) == (code, status)
    assert (getattr(err, "retry_after_s", "<missing>"), err.user_facing) == (
        retry_after_s,
        expected_facing,
    )
    assert (err.__cause__, err.__suppress_context__) == (None, True)
    assert [text for text in (str(err), err.message, stream_log) if marker in text] == []
    assert [text for text in stream_records if marker in text] == []
    assert _shape(err) == _shape(await _chat_error(client))


# ===========================================================================
# Transport failures mid-stream
# ===========================================================================


@pytest.mark.parametrize(
    ("exc_type", "code"),
    [
        (httpx.ReadTimeout, "timeout"),
        (httpx.ReadError, "provider_unavailable"),
        (httpx.RemoteProtocolError, "provider_unavailable"),
    ],
    ids=["read-timeout", "read-error", "peer-closed"],
)
@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_transport_failure_after_deltas_maps_to_code(
    provider: str,
    exc_type: type[httpx.TransportError],
    code: str,
    wire: _Wire,
    build: Callable[..., Any],
) -> None:
    """The consumer already got the deltas; the error is chat()'s for that failure."""
    marker = f"MID-STREAM-MARKER-{provider}-{code}"
    chunks = [_chunk({"content": "Hel"}), _chunk({"content": "lo"})]
    wire.answer_with(_breaking_sse(chunks, exc_type, marker))
    client = build(provider)
    received, err = await _drain_error(client)

    assert received and all(isinstance(item, LLMStreamDelta) for item in received)
    assert _deltas(received) == ["Hel", "lo"]
    assert (getattr(err, "code", "<missing>"), err.user_facing, err.status_code) == (
        code,
        True,
        None,
    )
    assert (err.__cause__, err.__suppress_context__) == (None, True)
    assert [text for text in (str(err), err.message) if marker in text] == []
    if provider == "vllm":
        assert "starting" in err.message.lower()
        assert "unavailable" in err.message.lower()
    wire.answer_with(_raise(exc_type, marker))
    assert _shape(err) == _shape(await _chat_error(client))


# ===========================================================================
# Request
# ===========================================================================


@pytest.mark.parametrize("with_tools", [True, False], ids=["tools", "no-tools"])
@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_request_body_is_chat_body_plus_stream(
    provider: str, with_tools: bool, wire: _Wire, build: Callable[..., Any]
) -> None:
    """Keys: model, messages, max_tokens, [tools], stream; otherwise chat()'s body."""
    tools = [_MEMORY_TOOL] if with_tools else None
    client = build(provider)
    wire.answer_with(_sse(_text_chunks("Hi")))
    await _drain(client, tools)
    wire.answer_with(_completion())
    await client.chat(_messages(), tools=tools)

    assert len(wire.chat_requests) == 2
    stream_body, chat_body = (sent.json_body() for sent in wire.chat_requests)
    expected_keys = _OPENAI_STREAM_KEYS | ({"tools"} if with_tools else set())
    assert set(stream_body) == expected_keys
    assert (stream_body["stream"] is True, stream_body["max_tokens"]) == (True, _MAX_TOKENS)
    assert {key: value for key, value in stream_body.items() if key != "stream"} == chat_body


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_request_carries_no_account_identifiers(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """No OpenAI-Organization/Project header; the env canaries appear nowhere."""
    items = await _drain(build(provider), [_MEMORY_TOOL])
    _final(items)
    assert len(wire.chat_requests) == 1
    assert wire.chat_requests[0].header_names() & _ACCOUNT_HEADERS == set()
    assert wire.leaked(_ORG_CANARY, _PROJECT_CANARY) == []


# ===========================================================================
# llm_policy.chat_stream through the real clients
# ===========================================================================


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_policy_retries_open_failure_then_streams_once(
    provider: str, wire: _Wire, build: Callable[..., Any], sleeps: list[float]
) -> None:
    """A 503 when opening is retried: two requests, the deltas exactly once."""
    wire.answer_with(_status(503, "POLICY-503-MARKER"), _sse(_text_chunks("Hel", "lo")))
    client = build(provider)
    items = [
        item
        async for item in policy.chat_stream(
            client, _messages(), None, data_residency=False, max_retries=2
        )
    ]
    assert len(wire.chat_requests) == 2
    assert _deltas(items) == ["Hel", "lo"]
    assert _final(items).content == "Hello"
    assert len(sleeps) == 1


@pytest.mark.parametrize("provider", NEW_STREAMING)
async def test_llm_stream_policy_no_retry_after_first_delta(
    provider: str, wire: _Wire, build: Callable[..., Any], sleeps: list[float]
) -> None:
    """A transport failure after a delta propagates: one request, no retry sleep."""
    wire.answer_with(
        _breaking_sse([_chunk({"content": "Hel"})], httpx.ReadError, "POLICY-MID-MARKER"),
        _sse(_text_chunks("never sent")),
    )
    client = build(provider)
    received: list[Any] = []
    with pytest.raises(LLMError) as exc_info:
        async for item in policy.chat_stream(
            client, _messages(), None, data_residency=False, max_retries=3
        ):
            received.append(item)
    assert (len(wire.chat_requests), sleeps) == (1, [])
    assert _deltas(received) == ["Hel"]
    assert getattr(exc_info.value, "code", "<missing>") == "provider_unavailable"
