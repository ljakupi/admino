"""Tests for the Infomaniak AI Services LLM client (issue #142).

``admino.llm_infomaniak.InfomaniakClient`` is the default provider: an
OpenAI-compatible client pointed at
``https://api.infomaniak.com/2/ai/{product_id}/openai/v1``. These tests drive it
against a *mocked* Infomaniak server built on ``httpx.MockTransport`` and
injected through the module's single ``_new_http_client`` seam, so no real
network request is ever made.

The fake server routes by path:
- ``GET /1/ai`` — product discovery (``{"result": "success", "data": [...]}``).
- ``POST /2/ai/{id}/openai/v1/chat/completions`` — JSON or ``text/event-stream``.
- ``GET /2/ai/{id}/openai/v1/models`` — OpenAI list format.

Covered: text replies, tool calls with the admino tool payload, request shape
(product-scoped URL, bearer auth, ``reasoning_effort: "none"``, no account
identifiers), usage parsing, reasoning separation (``reasoning_content`` /
``reasoning`` fields and ``<think>`` tags, also across stream chunks), streaming,
product-ID resolution (env, discovery, caching, failures), missing-token and
missing-model replies, the user-facing error catalogue, ``list_models``, and
client lifecycle.

Security notes:
- Every error case plants a unique marker in the response body and asserts it
  never reaches the exception message or any log record (at DEBUG).
- The API token and the account/product names returned by discovery must never
  be logged or surfaced.
- ``admino.llm_infomaniak`` is imported inside a fixture so that, before the
  module exists, each test fails on its own (RED) instead of breaking collection
  of the whole suite.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import httpx
import pytest

import admino.llm as llm_mod
from admino.config import LLMConfig
from admino.llm import LLMClient, LLMError, LLMResponse
from admino.models import LLMMessage

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from types import ModuleType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TOKEN = "ik-test-token-SECRET-4d1c9e77"
_PRODUCT_ID = "7539"
_MODEL = "Qwen/Qwen3.5-397B-A17B-FP8"
_ACCOUNT_MARKER = "ACCOUNT-NAME-MARKER-c0ffee"
_PRODUCT_MARKER = "PRODUCT-NAME-MARKER-beef42"
_API_BASE = "https://api.infomaniak.com"
_CHAT_URL = f"{_API_BASE}/2/ai/{_PRODUCT_ID}/openai/v1/chat/completions"
_MODELS_URL = f"{_API_BASE}/2/ai/{_PRODUCT_ID}/openai/v1/models"
_DISCOVERY_URL = f"{_API_BASE}/1/ai"
_MAX_CONTENT = 65536
# Built with chr() so no invisible bidi / confusable characters live in the source.
_RLO = chr(0x202E)  # RIGHT-TO-LEFT OVERRIDE
_FULLWIDTH_7539 = "".join(chr(0xFF10 + int(d)) for d in "7539")

_CHAT_PATH_RE = re.compile(r"/2/ai/[^/]+/openai/v1/chat/completions")
_MODELS_PATH_RE = re.compile(r"/2/ai/[^/]+/openai/v1/models")

_MEMORY_TOOL: dict[str, Any] = {
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
# Response builders
# ---------------------------------------------------------------------------


def _json(payload: Any, status: int = 200) -> httpx.Response:
    """Build a JSON httpx response."""
    return httpx.Response(status, json=payload)


def _product(product_id: Any = 7539) -> dict[str, Any]:
    """One discovery entry, carrying account identifiers that must never leak."""
    return {
        "product_id": product_id,
        "product_name": _PRODUCT_MARKER,
        "account_name": _ACCOUNT_MARKER,
        "status": "ok",
    }


def _discovery(*products: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """Route returning a successful discovery payload with the given products."""

    def route(_request: httpx.Request) -> httpx.Response:
        return _json({"result": "success", "data": list(products)})

    return route


def _completion(
    content: str | None = "Hello!",
    *,
    tool_calls: list[dict[str, Any]] | None = None,
    finish_reason: str = "stop",
    model: str = _MODEL,
    usage: dict[str, Any] | None = None,
    message_extra: dict[str, Any] | None = None,
    no_choices: bool = False,
) -> dict[str, Any]:
    """Build an OpenAI ``chat.completion`` JSON body."""
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    if message_extra:
        message.update(message_extra)
    body: dict[str, Any] = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": model,
        "choices": []
        if no_choices
        else [{"index": 0, "message": message, "finish_reason": finish_reason}],
    }
    if usage is not None:
        body["usage"] = usage
    return body


def _reply(body: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """Route returning a fixed JSON chat completion."""

    def route(_request: httpx.Request) -> httpx.Response:
        return _json(body)

    return route


def _tool_call(
    name: str = "memory.store",
    arguments: str = '{"key": "k", "value": "v"}',
    call_id: str = "call_01",
) -> dict[str, Any]:
    """An OpenAI-format tool call as returned in ``message.tool_calls``."""
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


def _chunk(
    delta: dict[str, Any] | None = None,
    *,
    finish_reason: str | None = None,
    usage: dict[str, Any] | None = None,
    no_choices: bool = False,
    model: str = _MODEL,
) -> dict[str, Any]:
    """Build one OpenAI ``chat.completion.chunk``."""
    body: dict[str, Any] = {
        "id": "chatcmpl-stream",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": model,
        "choices": []
        if no_choices
        else [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}],
    }
    if usage is not None:
        body["usage"] = usage
    return body


def _text_chunks(*pieces: str, finish_reason: str = "stop") -> list[dict[str, Any]]:
    """Content-only chunks followed by a finishing chunk."""
    chunks = [_chunk({"content": piece}) for piece in pieces]
    chunks.append(_chunk({}, finish_reason=finish_reason))
    return chunks


def _sse(chunks: list[dict[str, Any]]) -> Callable[[httpx.Request], httpx.Response]:
    """Route returning an OpenAI SSE stream built from ``data:`` lines."""
    body = "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"

    def route(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=body.encode("utf-8"),
        )

    return route


def _status(status: int, marker: str) -> Callable[[httpx.Request], httpx.Response]:
    """Route returning an error status whose body carries a secret marker."""

    def route(_request: httpx.Request) -> httpx.Response:
        return _json(
            {"error": {"message": f"upstream detail {marker}", "code": marker}},
            status=status,
        )

    return route


def _raise(exc_type: type[httpx.TransportError], marker: str) -> Callable[..., httpx.Response]:
    """Route raising a transport-level error (timeout / connection failure)."""

    def route(request: httpx.Request) -> httpx.Response:
        raise exc_type(f"transport failure {marker}", request=request)

    return route


# ---------------------------------------------------------------------------
# Mocked Infomaniak server
# ---------------------------------------------------------------------------


class FakeInfomaniak:
    """A mocked OpenAI-compatible Infomaniak server behind ``httpx.MockTransport``.

    ``factory`` replaces ``admino.llm_infomaniak._new_http_client`` so every
    ``httpx.AsyncClient`` the module builds (discovery and the SDK client)
    talks to ``handler``. All requests are recorded for assertions.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.unexpected: list[str] = []
        self.clients: list[httpx.AsyncClient] = []
        self.discovery: Callable[[httpx.Request], httpx.Response] = _discovery(_product())
        self.chat: Callable[[httpx.Request], httpx.Response] = _reply(_completion())
        self.models: Callable[[httpx.Request], httpx.Response] = _reply(
            {
                "object": "list",
                "data": [
                    {"id": _MODEL, "object": "model", "created": 0, "owned_by": "infomaniak"},
                    {
                        "id": "mistralai/Mistral-Small-3.2",
                        "object": "model",
                        "created": 0,
                        "owned_by": "infomaniak",
                    },
                ],
            }
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Route a request by path and record it."""
        request.read()
        self.requests.append(request)
        path = request.url.path
        if path == "/1/ai":
            return self.discovery(request)
        if _CHAT_PATH_RE.fullmatch(path):
            return self.chat(request)
        if _MODELS_PATH_RE.fullmatch(path):
            return self.models(request)
        self.unexpected.append(path)
        return httpx.Response(418, json={"error": "unexpected path"})

    def factory(self, *_args: Any, **_kwargs: Any) -> httpx.AsyncClient:
        """Drop-in replacement for ``_new_http_client`` (no real network)."""
        client = httpx.AsyncClient(transport=httpx.MockTransport(self.handler))
        self.clients.append(client)
        return client

    @property
    def chat_requests(self) -> list[httpx.Request]:
        """Requests sent to the chat completions endpoint."""
        return [r for r in self.requests if _CHAT_PATH_RE.fullmatch(r.url.path)]

    @property
    def discovery_requests(self) -> list[httpx.Request]:
        """Requests sent to the product discovery endpoint."""
        return [r for r in self.requests if r.url.path == "/1/ai"]

    @property
    def models_requests(self) -> list[httpx.Request]:
        """Requests sent to the models endpoint."""
        return [r for r in self.requests if _MODELS_PATH_RE.fullmatch(r.url.path)]

    @property
    def product_scoped_requests(self) -> list[httpx.Request]:
        """Every request whose URL embeds a product id (``/2/ai/...``)."""
        return [r for r in self.requests if r.url.path.startswith("/2/")]

    def last_chat_body(self) -> dict[str, Any]:
        """The JSON body of the most recent chat request."""
        assert self.chat_requests, "no chat request was made"
        body: dict[str, Any] = json.loads(self.chat_requests[-1].content)
        return body


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ik() -> ModuleType:
    """Import ``admino.llm_infomaniak`` lazily (fails per-test until it exists)."""
    from admino import llm_infomaniak

    return llm_infomaniak


@pytest.fixture(autouse=True)
def _infomaniak_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured token and an explicit product id by default (no discovery)."""
    monkeypatch.setenv("INFOMANIAK_API_TOKEN", _TOKEN)
    monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", _PRODUCT_ID)


@pytest.fixture()
def fake(ik: ModuleType, monkeypatch: pytest.MonkeyPatch) -> FakeInfomaniak:
    """Install the mocked Infomaniak server through the ``_new_http_client`` seam."""
    server = FakeInfomaniak()
    monkeypatch.setattr(ik, "_new_http_client", server.factory)
    return server


def _config(**overrides: Any) -> LLMConfig:
    """A real LLMConfig selecting the infomaniak provider."""
    values: dict[str, Any] = {
        "provider": "infomaniak",
        "infomaniak_model": _MODEL,
        "timeout_s": 5,
        "max_response_tokens": 1024,
    }
    values.update(overrides)
    return LLMConfig(**values)


@pytest.fixture()
async def client(ik: ModuleType, fake: FakeInfomaniak) -> AsyncIterator[Any]:
    """An InfomaniakClient wired to the fake server; closed after the test."""
    instance = ik.InfomaniakClient(_config())
    yield instance
    await instance.close()


def _msgs(content: str = "Hi") -> list[LLMMessage]:
    """A minimal conversation."""
    return [LLMMessage(role="user", content=content)]


async def _collect(
    instance: Any, messages: list[LLMMessage] | None = None, **kwargs: Any
) -> list[Any]:
    """Drain ``chat_stream`` into a list."""
    return [item async for item in instance.chat_stream(messages or _msgs(), **kwargs)]


def _deltas(items: list[Any]) -> list[str]:
    """The text of every streamed delta, in order."""
    return [item.content for item in items if isinstance(item, llm_mod.LLMStreamDelta)]


def _final(items: list[Any]) -> LLMResponse:
    """The single final LLMResponse of a stream."""
    finals = [item for item in items if isinstance(item, LLMResponse)]
    assert len(finals) == 1
    return finals[0]


def _assert_not_leaked(exc: BaseException, caplog: pytest.LogCaptureFixture, *secrets: str) -> None:
    """Assert no secret appears in the exception text or in any log output."""
    message = getattr(exc, "message", "")
    for secret in secrets:
        assert secret not in str(exc)
        assert secret not in message
        assert secret not in caplog.text
        assert all(secret not in record.getMessage() for record in caplog.records)


# ===========================================================================
# Construction
# ===========================================================================


class TestInfomaniakConstruction:
    """The constructor never raises for missing setup and never performs I/O."""

    def test_infomaniak_module_api_base_constant(self, ik: ModuleType) -> None:
        """The API base is the Infomaniak API host over HTTPS."""
        assert ik.INFOMANIAK_API_BASE == "https://api.infomaniak.com"

    def test_infomaniak_client_implements_llm_client_protocol(
        self, ik: ModuleType, fake: FakeInfomaniak
    ) -> None:
        """InfomaniakClient satisfies the runtime-checkable LLMClient protocol."""
        assert isinstance(ik.InfomaniakClient(_config()), LLMClient)

    def test_infomaniak_constructor_makes_no_request(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Construction performs no I/O — not even product discovery."""
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        ik.InfomaniakClient(_config())
        assert fake.requests == []

    @pytest.mark.parametrize("token", [None, "", "   "], ids=["unset", "empty", "whitespace"])
    def test_infomaniak_constructor_missing_token_does_not_raise(
        self,
        ik: ModuleType,
        fake: FakeInfomaniak,
        monkeypatch: pytest.MonkeyPatch,
        token: str | None,
    ) -> None:
        """A missing/blank INFOMANIAK_API_TOKEN does not stop construction."""
        if token is None:
            monkeypatch.delenv("INFOMANIAK_API_TOKEN")
        else:
            monkeypatch.setenv("INFOMANIAK_API_TOKEN", token)
        instance = ik.InfomaniakClient(_config())
        assert instance is not None
        assert fake.requests == []

    @pytest.mark.parametrize("model", [None, ""], ids=["none", "empty"])
    def test_infomaniak_constructor_missing_model_does_not_raise(
        self, ik: ModuleType, fake: FakeInfomaniak, model: str | None
    ) -> None:
        """An unset infomaniak_model does not stop construction."""
        instance = ik.InfomaniakClient(_config(infomaniak_model=model))
        assert instance is not None

    def test_infomaniak_constructor_invalid_product_id_does_not_raise(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A malformed INFOMANIAK_PRODUCT_ID is surfaced at chat time, not at construction."""
        monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", "12/../x")
        instance = ik.InfomaniakClient(_config())
        assert instance is not None
        assert fake.requests == []

    def test_infomaniak_constructor_missing_openai_sdk_raises_import_error(
        self, ik: ModuleType, fake: FakeInfomaniak
    ) -> None:
        """Without the openai package the constructor raises ImportError (like other clients)."""
        with (
            patch.dict("sys.modules", {"openai": None}),
            pytest.raises(ImportError, match="openai"),
        ):
            ik.InfomaniakClient(_config())


# ===========================================================================
# chat() — response parsing
# ===========================================================================


class TestInfomaniakChatResponse:
    """Parsing of non-streaming chat completions."""

    async def test_infomaniak_chat_text_reply_parsed(self, client: Any) -> None:
        """A plain text completion becomes a done LLMResponse without tool calls."""
        result = await client.chat(_msgs())
        assert isinstance(result, LLMResponse)
        assert result.content == "Hello!"
        assert result.tool_calls == []
        assert result.done is True

    async def test_infomaniak_chat_model_echoed(self, client: Any, fake: FakeInfomaniak) -> None:
        """The model name reported by the server is echoed back."""
        fake.chat = _reply(_completion(model="Qwen/Qwen3.5-served"))
        result = await client.chat(_msgs())
        assert result.model == "Qwen/Qwen3.5-served"

    async def test_infomaniak_chat_model_sanitized(self, client: Any, fake: FakeInfomaniak) -> None:
        """Control / bidi characters in the echoed model name are stripped."""
        fake.chat = _reply(_completion(model=f"Qwen\x00/evil{_RLO}model"))
        result = await client.chat(_msgs())
        assert "\x00" not in result.model
        assert _RLO not in result.model

    async def test_infomaniak_chat_tool_call_parsed(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """An admino tool call (memory.store) is parsed into tool/action/args/id."""
        fake.chat = _reply(_completion("", tool_calls=[_tool_call()], finish_reason="tool_calls"))
        result = await client.chat(_msgs(), tools=[_MEMORY_TOOL])
        assert len(result.tool_calls) == 1
        call = result.tool_calls[0]
        assert call.tool == "memory"
        assert call.action == "store"
        assert call.args == {"key": "k", "value": "v"}
        assert call.tool_call_id == "call_01"
        assert result.done is False

    async def test_infomaniak_chat_multiple_tool_calls_parsed(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Several tool calls in one message are all parsed, in order."""
        calls = [
            _tool_call("memory.store", '{"key": "a"}', "call_a"),
            _tool_call("memory.recall", '{"key": "b"}', "call_b"),
        ]
        fake.chat = _reply(_completion(None, tool_calls=calls, finish_reason="tool_calls"))
        result = await client.chat(_msgs(), tools=[_MEMORY_TOOL])
        assert [(c.action, c.tool_call_id) for c in result.tool_calls] == [
            ("store", "call_a"),
            ("recall", "call_b"),
        ]

    async def test_infomaniak_chat_hallucinated_tool_name_rejected(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """A tool name that fails the admino tool/action schema rejects the reply.

        GH-25 (D2): the client raises ``malformed_response`` (fixed text naming
        Infomaniak, raised ``from None``) instead of dropping the call.
        """
        fake.chat = _reply(
            _completion(
                "", tool_calls=[_tool_call("FAKE-Tool.hack", "{}")], finish_reason="tool_calls"
            )
        )
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_msgs())
        error = exc_info.value
        assert (error.code, error.message, error.__cause__, error.__suppress_context__) == (
            "malformed_response",
            "Infomaniak returned a malformed response. Please try again.",
            None,
            True,
        )

    async def test_infomaniak_chat_malformed_tool_arguments_rejected(
        self, client: Any, fake: FakeInfomaniak, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Malformed JSON tool arguments reject the reply as an error, not a crash.

        GH-25 (D2): ``malformed_response`` instead of a dropped call; the arguments
        never reach the error or any log record.
        """
        caplog.set_level(logging.DEBUG)
        fake.chat = _reply(
            _completion(
                "", tool_calls=[_tool_call(arguments="not-json{")], finish_reason="tool_calls"
            )
        )
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_msgs())
        assert exc_info.value.code == "malformed_response"
        _assert_not_leaked(exc_info.value, caplog, "not-json{")

    @pytest.mark.parametrize(
        ("finish_reason", "done"),
        [("stop", True), ("length", True), ("tool_calls", False)],
    )
    async def test_infomaniak_chat_done_follows_finish_reason(
        self, client: Any, fake: FakeInfomaniak, finish_reason: str, done: bool
    ) -> None:
        """done is False only when the model stopped to call tools."""
        fake.chat = _reply(_completion("x", finish_reason=finish_reason))
        result = await client.chat(_msgs())
        assert result.done is done

    async def test_infomaniak_chat_no_choices_returns_empty_done_response(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """A completion without choices yields an empty, done response."""
        fake.chat = _reply(_completion(no_choices=True))
        result = await client.chat(_msgs())
        assert result.content == ""
        assert result.tool_calls == []
        assert result.done is True

    async def test_infomaniak_chat_null_content_is_empty_string(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """A null message content becomes an empty string."""
        fake.chat = _reply(_completion(None))
        result = await client.chat(_msgs())
        assert result.content == ""

    async def test_infomaniak_chat_content_control_chars_stripped(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Control, C1 and bidi characters are stripped from the reply."""
        fake.chat = _reply(_completion(f"Hello\x00\x85{_RLO}World"))
        result = await client.chat(_msgs())
        assert result.content == "HelloWorld"

    async def test_infomaniak_chat_stream_true_raises_value_error(self, client: Any) -> None:
        """chat(stream=True) is rejected — streaming goes through chat_stream()."""
        with pytest.raises(ValueError, match=r"(?i)stream"):
            await client.chat(_msgs(), stream=True)


# ===========================================================================
# chat() — request shape
# ===========================================================================


class TestInfomaniakRequestShape:
    """What the client sends to Infomaniak."""

    async def test_infomaniak_chat_url_uses_product_id(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """The chat endpoint is scoped to the product id over HTTPS."""
        await client.chat(_msgs())
        assert str(fake.chat_requests[0].url) == _CHAT_URL
        assert fake.chat_requests[0].method == "POST"

    async def test_infomaniak_chat_sends_bearer_token(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """The API token is sent as a Bearer Authorization header."""
        await client.chat(_msgs())
        assert fake.chat_requests[0].headers["authorization"] == f"Bearer {_TOKEN}"

    async def test_infomaniak_chat_sends_configured_model(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """The request model is config.infomaniak_model."""
        await client.chat(_msgs())
        assert fake.last_chat_body()["model"] == _MODEL

    async def test_infomaniak_chat_disables_reasoning(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Thinking is switched off with a top-level reasoning_effort: "none"."""
        await client.chat(_msgs())
        assert fake.last_chat_body()["reasoning_effort"] == "none"

    async def test_infomaniak_chat_sends_max_completion_tokens(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """The output cap is sent as max_completion_tokens (config.max_response_tokens).

        Infomaniak documents ``max_completion_tokens`` for this endpoint; the legacy
        ``max_tokens`` is not part of its schema, so it must not be sent.
        """
        await client.chat(_msgs())
        body = fake.last_chat_body()
        assert body["max_completion_tokens"] == 1024
        assert "max_tokens" not in body

    async def test_infomaniak_chat_messages_sent_verbatim(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Messages are converted 1:1 — nothing (names, emails, extra prompts) is injected."""
        messages = [
            LLMMessage(role="system", content="Be brief."),
            LLMMessage(role="user", content="Hi"),
            LLMMessage(role="assistant", content="Hello"),
            LLMMessage(role="tool", content="stored", tool_call_id="call_01"),
        ]
        await client.chat(messages)
        assert fake.last_chat_body()["messages"] == [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "Hi"},
            {"role": "assistant", "content": "Hello"},
            {"role": "tool", "content": "stored", "tool_call_id": "call_01"},
        ]

    async def test_infomaniak_chat_tools_converted(self, client: Any, fake: FakeInfomaniak) -> None:
        """The admino tool payload is sent in OpenAI function format."""
        await client.chat(_msgs(), tools=[_MEMORY_TOOL])
        sent = fake.last_chat_body()["tools"]
        assert sent == [
            {
                "type": "function",
                "function": {
                    "name": "memory.store",
                    "description": "Store a note",
                    "parameters": _MEMORY_TOOL["function"]["parameters"],
                },
            }
        ]

    async def test_infomaniak_chat_no_tools_key_without_tools(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """No tools key is sent when no tools are given."""
        await client.chat(_msgs())
        assert "tools" not in fake.last_chat_body()

    @pytest.mark.parametrize("key", ["user", "safety_identifier", "prompt_cache_key", "metadata"])
    async def test_infomaniak_chat_sends_no_account_identifiers(
        self, client: Any, fake: FakeInfomaniak, key: str
    ) -> None:
        """No end-user / account identifier fields are ever sent."""
        await client.chat(_msgs())
        assert key not in fake.last_chat_body()

    async def test_infomaniak_chat_is_not_streamed(self, client: Any, fake: FakeInfomaniak) -> None:
        """chat() sends an explicit ``stream: false``.

        Infomaniak documents ``stream`` as defaulting to true, and the SDK omits
        the key when it isn't passed, so it must be sent explicitly.
        """
        await client.chat(_msgs())
        assert fake.last_chat_body()["stream"] is False

    async def test_infomaniak_chat_tool_round_trip_links_call_and_result(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """A tool-call turn is replayed with ``tool_calls`` before its ``tool`` result."""
        messages = [
            LLMMessage(role="user", content="Remember that I like tea"),
            LLMMessage(
                role="assistant",
                content="",
                tool_use_blocks=[
                    {
                        "type": "tool_use",
                        "id": "call_01",
                        "name": "memory.store",
                        "input": {"key": "drink", "value": "tea"},
                    }
                ],
            ),
            LLMMessage(role="tool", content="stored", tool_call_id="call_01"),
        ]
        await client.chat(messages, tools=[_MEMORY_TOOL])
        sent = fake.last_chat_body()["messages"]
        assert sent[1]["role"] == "assistant"
        assert sent[1]["tool_calls"] == [
            {
                "id": "call_01",
                "type": "function",
                "function": {
                    "name": "memory.store",
                    "arguments": json.dumps({"key": "drink", "value": "tea"}),
                },
            }
        ]
        assert sent[2] == {"role": "tool", "content": "stored", "tool_call_id": "call_01"}

    async def test_infomaniak_chat_oversized_tools_is_internal_error(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """An oversized tools payload is an internal (non user-facing) error; nothing is sent."""
        tools = [
            {"type": "function", "function": {"name": f"tool.action{i}", "parameters": {}}}
            for i in range(65)
        ]
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_msgs(), tools=tools)
        assert exc_info.value.user_facing is False
        assert fake.chat_requests == []


# ===========================================================================
# Usage
# ===========================================================================


class TestInfomaniakUsage:
    """usage.prompt_tokens / usage.completion_tokens are parsed (ready for #178)."""

    async def test_infomaniak_chat_usage_parsed(self, client: Any, fake: FakeInfomaniak) -> None:
        """Token usage is surfaced on LLMResponse.usage."""
        fake.chat = _reply(
            _completion(usage={"prompt_tokens": 12, "completion_tokens": 34, "total_tokens": 46})
        )
        result = await client.chat(_msgs())
        assert result.usage is not None
        assert result.usage.prompt_tokens == 12
        assert result.usage.completion_tokens == 34

    async def test_infomaniak_chat_usage_with_reasoning_details_parsed(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """completion_tokens_details (reasoning_tokens) does not break usage parsing."""
        fake.chat = _reply(
            _completion(
                usage={
                    "prompt_tokens": 5,
                    "completion_tokens": 50,
                    "total_tokens": 55,
                    "completion_tokens_details": {"reasoning_tokens": 40},
                }
            )
        )
        result = await client.chat(_msgs())
        assert result.usage is not None
        assert (result.usage.prompt_tokens, result.usage.completion_tokens) == (5, 50)

    async def test_infomaniak_chat_usage_absent_is_none(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Without a usage block, LLMResponse.usage is None."""
        fake.chat = _reply(_completion())
        result = await client.chat(_msgs())
        assert result.usage is None


# ===========================================================================
# Reasoning separation (non-streaming)
# ===========================================================================


class TestInfomaniakReasoning:
    """Reasoning text must never leak into the answer content."""

    @pytest.mark.parametrize("field", ["reasoning_content", "reasoning"])
    async def test_infomaniak_chat_reasoning_field_never_in_content(
        self, client: Any, fake: FakeInfomaniak, field: str
    ) -> None:
        """A vLLM-style reasoning field on the message is ignored."""
        fake.chat = _reply(
            _completion("The answer.", message_extra={field: "SECRET-REASONING-trace"})
        )
        result = await client.chat(_msgs())
        assert result.content == "The answer."

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("<think>plan the steps</think>The answer.", "The answer."),
            ("<think>\nstep 1\nstep 2\n</think>\n\nThe answer.", "The answer."),
            ("<think>a</think>Part one. <think>b</think>Part two.", "Part one. Part two."),
            ("hidden reasoning</think>answer", "answer"),
            ("hidden\nreasoning\n</think>\n\nanswer", "answer"),
        ],
        ids=[
            "single-block",
            "multiline-block",
            "several-blocks",
            "orphan-close",
            "orphan-newlines",
        ],
    )
    async def test_infomaniak_chat_think_tags_stripped(
        self, client: Any, fake: FakeInfomaniak, raw: str, expected: str
    ) -> None:
        """<think> blocks (and an orphan </think> prefix) are removed from content."""
        fake.chat = _reply(_completion(raw))
        result = await client.chat(_msgs())
        assert result.content == expected

    async def test_infomaniak_chat_unclosed_think_block_not_leaked(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """A <think> block cut off before its closing tag never reaches content."""
        fake.chat = _reply(
            _completion("<think>SECRET-REASONING never closed", finish_reason="length")
        )
        result = await client.chat(_msgs())
        assert "SECRET-REASONING" not in result.content
        assert "<think>" not in result.content

    async def test_infomaniak_chat_plain_content_untouched(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Content without think tags (even with < and >) is left as-is."""
        text = "Use <b>bold</b> when 1 < 2 and 3 > 2.\nDone."
        fake.chat = _reply(_completion(text))
        result = await client.chat(_msgs())
        assert result.content == text

    async def test_infomaniak_chat_control_chars_sanitized_after_think_strip(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Sanitization still applies after reasoning removal."""
        fake.chat = _reply(_completion(f"<think>x</think>Hello\x00{_RLO}World"))
        result = await client.chat(_msgs())
        assert result.content == "HelloWorld"


# ===========================================================================
# Streaming
# ===========================================================================


class TestInfomaniakStreaming:
    """chat_stream(): OpenAI SSE → LLMStreamDelta* followed by one LLMResponse."""

    async def test_infomaniak_stream_yields_deltas_in_order(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Each content chunk becomes one delta, in order (true incremental streaming)."""
        fake.chat = _sse(_text_chunks("Hel", "lo ", "world"))
        items = await _collect(client)
        assert _deltas(items) == ["Hel", "lo ", "world"]

    async def test_infomaniak_stream_final_response_once_and_last(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Exactly one LLMResponse is yielded, as the last item; the rest are deltas."""
        fake.chat = _sse(_text_chunks("a", "b"))
        items = await _collect(client)
        assert isinstance(items[-1], LLMResponse)
        assert sum(isinstance(i, LLMResponse) for i in items) == 1
        assert all(isinstance(i, llm_mod.LLMStreamDelta) for i in items[:-1])

    async def test_infomaniak_stream_final_content_is_concatenated_deltas(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """The final response content equals the concatenated deltas."""
        fake.chat = _sse(_text_chunks("The ", "quick ", "fox."))
        items = await _collect(client)
        assert _final(items).content == "".join(_deltas(items)) == "The quick fox."

    async def test_infomaniak_stream_no_empty_deltas(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Role-only / empty chunks produce no delta."""
        chunks = [_chunk({"role": "assistant", "content": ""}), *_text_chunks("Hi")]
        fake.chat = _sse(chunks)
        items = await _collect(client)
        assert _deltas(items) == ["Hi"]

    @pytest.mark.parametrize(
        "pieces",
        [
            ("<thi", "nk>SECRET plan</th", "ink>The ", "answer"),
            ("<", "think", ">", "SECRET", "</", "think", ">", "The answer"),
            ("<think>SECRET", " more SECRET</think>The answer"),
            ("The ", "<think>SECRET</think>", "answer"),
        ],
        ids=["split-tags", "char-level-split", "open-then-close", "mid-stream-block"],
    )
    async def test_infomaniak_stream_split_think_tags_never_leak(
        self, client: Any, fake: FakeInfomaniak, pieces: tuple[str, ...]
    ) -> None:
        """Think tags split across chunk boundaries never leak into deltas or content."""
        fake.chat = _sse(_text_chunks(*pieces))
        items = await _collect(client)
        deltas = _deltas(items)
        for text in [*deltas, _final(items).content]:
            assert "SECRET" not in text
            assert "think" not in text
            assert "<" not in text
            assert ">" not in text
        assert "".join(deltas) == "The answer"
        assert _final(items).content == "The answer"

    async def test_infomaniak_stream_unclosed_think_never_leaks(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """A think block that never closes (cut off) yields no reasoning text."""
        fake.chat = _sse(_text_chunks("<think>SECRET ", "still thinking", finish_reason="length"))
        items = await _collect(client)
        assert all("SECRET" not in d for d in _deltas(items))
        assert "SECRET" not in _final(items).content

    async def test_infomaniak_stream_orphan_close_tag_removed_from_final_content(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """An orphan </think> drops everything before it from the final content."""
        fake.chat = _sse(_text_chunks("hidden ", "plan</think>", "Answer"))
        items = await _collect(client)
        assert _final(items).content == "Answer"

    @pytest.mark.parametrize("field", ["reasoning_content", "reasoning"])
    async def test_infomaniak_stream_delta_reasoning_ignored(
        self, client: Any, fake: FakeInfomaniak, field: str
    ) -> None:
        """Reasoning deltas are never yielded nor added to the final content."""
        chunks = [
            _chunk({field: "SECRET-REASONING step one"}),
            _chunk({field: "SECRET-REASONING step two"}),
            *_text_chunks("Answer"),
        ]
        fake.chat = _sse(chunks)
        items = await _collect(client)
        assert _deltas(items) == ["Answer"]
        assert _final(items).content == "Answer"

    async def test_infomaniak_stream_control_chars_stripped_from_deltas(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Deltas are sanitized like non-streaming content."""
        fake.chat = _sse(_text_chunks("Hel\x00lo", f"{_RLO}World"))
        items = await _collect(client)
        assert "".join(_deltas(items)) == "HelloWorld"
        assert _final(items).content == "HelloWorld"

    async def test_infomaniak_stream_tool_call_fragments_accumulated(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Split tool-call argument fragments become one valid ToolCall in the final response."""
        chunks = [
            _chunk(
                {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "memory.store", "arguments": ""},
                        }
                    ]
                }
            ),
            _chunk({"tool_calls": [{"index": 0, "function": {"arguments": '{"key": '}}]}),
            _chunk({"tool_calls": [{"index": 0, "function": {"arguments": '"k", "value"'}}]}),
            _chunk({"tool_calls": [{"index": 0, "function": {"arguments": ': "v"}'}}]}),
            _chunk({}, finish_reason="tool_calls"),
        ]
        fake.chat = _sse(chunks)
        items = await _collect(client, tools=[_MEMORY_TOOL])
        final = _final(items)
        assert len(final.tool_calls) == 1
        call = final.tool_calls[0]
        assert (call.tool, call.action, call.args, call.tool_call_id) == (
            "memory",
            "store",
            {"key": "k", "value": "v"},
            "call_1",
        )
        assert final.done is False
        assert _deltas(items) == []

    async def test_infomaniak_stream_interleaved_tool_calls_by_index(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Fragments for different tool-call indexes are kept apart."""
        chunks = [
            _chunk(
                {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_a",
                            "type": "function",
                            "function": {"name": "memory.store", "arguments": '{"key":'},
                        },
                        {
                            "index": 1,
                            "id": "call_b",
                            "type": "function",
                            "function": {"name": "memory.recall", "arguments": '{"key":'},
                        },
                    ]
                }
            ),
            _chunk({"tool_calls": [{"index": 1, "function": {"arguments": ' "b"}'}}]}),
            _chunk({"tool_calls": [{"index": 0, "function": {"arguments": ' "a"}'}}]}),
            _chunk({}, finish_reason="tool_calls"),
        ]
        fake.chat = _sse(chunks)
        items = await _collect(client, tools=[_MEMORY_TOOL])
        calls = _final(items).tool_calls
        assert [(c.action, c.args, c.tool_call_id) for c in calls] == [
            ("store", {"key": "a"}, "call_a"),
            ("recall", {"key": "b"}, "call_b"),
        ]

    async def test_infomaniak_stream_usage_from_final_chunk(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """The final usage chunk (choices: []) fills LLMResponse.usage."""
        chunks = [
            *_text_chunks("Hi"),
            _chunk(
                no_choices=True,
                usage={"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
            ),
        ]
        fake.chat = _sse(chunks)
        final = _final(await _collect(client))
        assert final.usage is not None
        assert (final.usage.prompt_tokens, final.usage.completion_tokens) == (7, 3)

    async def test_infomaniak_stream_usage_absent_is_none(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Without a usage chunk, usage stays None."""
        fake.chat = _sse(_text_chunks("Hi"))
        final = _final(await _collect(client))
        assert final.usage is None

    async def test_infomaniak_stream_final_model_and_done(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """The final response carries the model and done=True on a normal stop."""
        fake.chat = _sse(_text_chunks("Hi"))
        final = _final(await _collect(client))
        assert final.model == _MODEL
        assert final.done is True

    async def test_infomaniak_stream_request_shape(self, client: Any, fake: FakeInfomaniak) -> None:
        """The stream request asks for SSE with usage, and disables reasoning."""
        fake.chat = _sse(_text_chunks("Hi"))
        await _collect(client)
        body = fake.last_chat_body()
        assert str(fake.chat_requests[0].url) == _CHAT_URL
        assert fake.chat_requests[0].headers["authorization"] == f"Bearer {_TOKEN}"
        assert body["stream"] is True
        assert body["stream_options"] == {"include_usage": True}
        assert body["reasoning_effort"] == "none"
        assert body["model"] == _MODEL
        assert body["max_completion_tokens"] == 1024
        assert "max_tokens" not in body
        assert "user" not in body

    async def test_infomaniak_stream_content_capped(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Deltas stop at the 65536-char cap and the final content respects it."""
        fake.chat = _sse(_text_chunks("a" * 30000, "b" * 30000, "c" * 30000))
        items = await _collect(client)
        assert sum(len(d) for d in _deltas(items)) <= _MAX_CONTENT
        assert len(_final(items).content) <= _MAX_CONTENT

    @pytest.mark.parametrize(
        ("status", "phrase"),
        [(401, "Infomaniak rejected the API token"), (500, "temporarily unavailable")],
    )
    async def test_infomaniak_stream_http_error_raised_before_any_delta(
        self,
        client: Any,
        fake: FakeInfomaniak,
        caplog: pytest.LogCaptureFixture,
        status: int,
        phrase: str,
    ) -> None:
        """An HTTP error raises the catalogue LLMError before anything is yielded."""
        caplog.set_level(logging.DEBUG)
        marker = f"STREAM-BODY-SECRET-{status}"
        fake.chat = _status(status, marker)
        received: list[Any] = []
        with pytest.raises(LLMError) as exc_info:
            async for item in client.chat_stream(_msgs()):
                received.append(item)
        assert received == []
        assert exc_info.value.user_facing is True
        assert phrase in exc_info.value.message
        _assert_not_leaked(exc_info.value, caplog, marker, _TOKEN)

    async def test_infomaniak_stream_missing_token_user_facing(
        self, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch, ik: ModuleType
    ) -> None:
        """chat_stream() also answers a missing token with the friendly message."""
        monkeypatch.delenv("INFOMANIAK_API_TOKEN")
        instance = ik.InfomaniakClient(_config())
        with pytest.raises(LLMError) as exc_info:
            await _collect(instance)
        assert exc_info.value.user_facing is True
        assert "Infomaniak isn't configured; set INFOMANIAK_API_TOKEN" in exc_info.value.message
        assert fake.requests == []


# ===========================================================================
# Product id resolution
# ===========================================================================


class TestInfomaniakProductId:
    """INFOMANIAK_PRODUCT_ID from env, or discovered via GET /1/ai."""

    async def test_infomaniak_env_product_id_used_without_discovery(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """An explicit INFOMANIAK_PRODUCT_ID is used directly — no discovery request."""
        await client.chat(_msgs())
        assert fake.discovery_requests == []
        assert str(fake.chat_requests[0].url) == _CHAT_URL

    async def test_infomaniak_env_product_id_is_stripped(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Surrounding whitespace in INFOMANIAK_PRODUCT_ID is ignored."""
        monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", f"  {_PRODUCT_ID}\n")
        instance = ik.InfomaniakClient(_config())
        await instance.chat(_msgs())
        await instance.close()
        assert str(fake.chat_requests[0].url) == _CHAT_URL

    async def test_infomaniak_resolve_product_id_from_env(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """resolve_product_id() returns the env id without I/O."""
        assert await client.resolve_product_id() == _PRODUCT_ID
        assert fake.requests == []

    async def test_infomaniak_discovery_single_product_used_for_chat(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without an env id, the single discovered product scopes the chat URL."""
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        fake.discovery = _discovery(_product(4242))
        instance = ik.InfomaniakClient(_config())
        await instance.chat(_msgs())
        await instance.close()
        assert len(fake.discovery_requests) == 1
        assert fake.chat_requests[0].url.path == "/2/ai/4242/openai/v1/chat/completions"

    async def test_infomaniak_discovery_result_cached(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A successful discovery is cached: a second chat does not re-hit /1/ai."""
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        instance = ik.InfomaniakClient(_config())
        await instance.chat(_msgs())
        await instance.chat(_msgs())
        await instance.close()
        assert len(fake.discovery_requests) == 1
        assert len(fake.chat_requests) == 2

    async def test_infomaniak_discover_product_id_single_product(
        self, ik: ModuleType, fake: FakeInfomaniak
    ) -> None:
        """discover_product_id() returns the product id as a string."""
        product_id = await ik.discover_product_id(_TOKEN)
        assert product_id == "7539"
        assert isinstance(product_id, str)

    async def test_infomaniak_discover_product_id_request_shape(
        self, ik: ModuleType, fake: FakeInfomaniak
    ) -> None:
        """Discovery is GET https://api.infomaniak.com/1/ai with the bearer token."""
        await ik.discover_product_id(_TOKEN)
        request = fake.discovery_requests[0]
        assert request.method == "GET"
        assert str(request.url) == _DISCOVERY_URL
        assert request.headers["authorization"] == f"Bearer {_TOKEN}"

    async def test_infomaniak_discover_multiple_products_user_facing(
        self, ik: ModuleType, fake: FakeInfomaniak
    ) -> None:
        """Several products → a friendly error asking for INFOMANIAK_PRODUCT_ID."""
        fake.discovery = _discovery(_product(1), _product(2))
        with pytest.raises(LLMError) as exc_info:
            await ik.discover_product_id(_TOKEN)
        assert exc_info.value.user_facing is True
        assert "INFOMANIAK_PRODUCT_ID" in exc_info.value.message

    async def test_infomaniak_chat_multiple_products_user_facing(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """chat() with several products replies with the INFOMANIAK_PRODUCT_ID message."""
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        fake.discovery = _discovery(_product(1), _product(2))
        instance = ik.InfomaniakClient(_config())
        with pytest.raises(LLMError) as exc_info:
            await instance.chat(_msgs())
        await instance.close()
        assert exc_info.value.user_facing is True
        assert "INFOMANIAK_PRODUCT_ID" in exc_info.value.message
        assert fake.chat_requests == []

    async def test_infomaniak_discover_zero_products_user_facing(
        self, ik: ModuleType, fake: FakeInfomaniak
    ) -> None:
        """No product → a friendly error pointing at the Manager / INFOMANIAK_PRODUCT_ID."""
        fake.discovery = _discovery()
        with pytest.raises(LLMError) as exc_info:
            await ik.discover_product_id(_TOKEN)
        message = exc_info.value.message
        assert exc_info.value.user_facing is True
        assert "Infomaniak" in message
        assert "INFOMANIAK_PRODUCT_ID" in message or "Manager" in message

    @pytest.mark.parametrize("status", [401, 403])
    async def test_infomaniak_discover_rejected_token(
        self,
        ik: ModuleType,
        fake: FakeInfomaniak,
        caplog: pytest.LogCaptureFixture,
        status: int,
    ) -> None:
        """401/403 on discovery → "Infomaniak rejected the API token", body not leaked."""
        caplog.set_level(logging.DEBUG)
        marker = f"DISCOVERY-BODY-SECRET-{status}"
        fake.discovery = _status(status, marker)
        with pytest.raises(LLMError) as exc_info:
            await ik.discover_product_id(_TOKEN)
        assert exc_info.value.user_facing is True
        assert "Infomaniak rejected the API token" in exc_info.value.message
        _assert_not_leaked(exc_info.value, caplog, marker, _TOKEN)

    @pytest.mark.parametrize("status", [500, 502, 503])
    async def test_infomaniak_discover_server_error_temporarily_unavailable(
        self,
        ik: ModuleType,
        fake: FakeInfomaniak,
        caplog: pytest.LogCaptureFixture,
        status: int,
    ) -> None:
        """5xx on discovery → user-facing "temporarily unavailable", body not leaked."""
        caplog.set_level(logging.DEBUG)
        marker = f"DISCOVERY-5XX-SECRET-{status}"
        fake.discovery = _status(status, marker)
        with pytest.raises(LLMError) as exc_info:
            await ik.discover_product_id(_TOKEN)
        assert exc_info.value.user_facing is True
        assert "temporarily unavailable" in exc_info.value.message
        _assert_not_leaked(exc_info.value, caplog, marker)

    @pytest.mark.parametrize("exc_type", [httpx.ReadTimeout, httpx.ConnectError])
    async def test_infomaniak_discover_transport_error_temporarily_unavailable(
        self,
        ik: ModuleType,
        fake: FakeInfomaniak,
        caplog: pytest.LogCaptureFixture,
        exc_type: type[httpx.TransportError],
    ) -> None:
        """Timeouts / connection failures on discovery → user-facing temporary error."""
        caplog.set_level(logging.DEBUG)
        marker = "DISCOVERY-TRANSPORT-SECRET"
        fake.discovery = _raise(exc_type, marker)
        with pytest.raises(LLMError) as exc_info:
            await ik.discover_product_id(_TOKEN)
        assert exc_info.value.user_facing is True
        assert "temporarily unavailable" in exc_info.value.message
        _assert_not_leaked(exc_info.value, caplog, marker)

    @pytest.mark.parametrize(
        "route",
        [
            lambda _r: httpx.Response(200, content=b"<html>not json</html>"),
            lambda _r: _json({"result": "success", "data": "nope"}),
            lambda _r: _json({"result": "error"}),
            lambda _r: _json([1, 2, 3]),
            lambda _r: _json({"result": "success", "data": [_product("../../evil")]}),
            lambda _r: _json({"result": "success", "data": [{"product_name": "no id"}]}),
        ],
        ids=[
            "not-json",
            "data-not-list",
            "missing-data",
            "top-level-list",
            "non-int-product-id",
            "missing-product-id",
        ],
    )
    async def test_infomaniak_discover_malformed_payload_is_internal_error(
        self,
        ik: ModuleType,
        fake: FakeInfomaniak,
        route: Callable[[httpx.Request], httpx.Response],
    ) -> None:
        """Malformed / unexpected discovery payloads are internal (non user-facing) errors."""
        fake.discovery = route
        with pytest.raises(LLMError) as exc_info:
            await ik.discover_product_id(_TOKEN)
        assert exc_info.value.user_facing is False

    async def test_infomaniak_non_int_discovered_id_never_used_in_url(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-integer product_id from discovery never reaches a request URL."""
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        fake.discovery = _discovery(_product("../../evil"))
        instance = ik.InfomaniakClient(_config())
        with pytest.raises(LLMError):
            await instance.chat(_msgs())
        await instance.close()
        assert fake.product_scoped_requests == []

    async def test_infomaniak_discovery_failure_not_cached(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed discovery is retried on the next chat once the account is fixed."""
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        fake.discovery = _discovery(_product(1), _product(2))
        instance = ik.InfomaniakClient(_config())
        with pytest.raises(LLMError):
            await instance.chat(_msgs())
        fake.discovery = _discovery(_product(7539))
        result = await instance.chat(_msgs())
        await instance.close()
        assert result.content == "Hello!"
        assert len(fake.discovery_requests) == 2

    @pytest.mark.parametrize(
        "bad_id",
        ["12/../x", "abc", "12a", "-5", "75 39", _FULLWIDTH_7539],
        ids=["traversal", "letters", "mixed", "negative", "inner-space", "fullwidth-digits"],
    )
    async def test_infomaniak_invalid_env_product_id_user_facing(
        self,
        ik: ModuleType,
        fake: FakeInfomaniak,
        monkeypatch: pytest.MonkeyPatch,
        bad_id: str,
    ) -> None:
        """A non-digit INFOMANIAK_PRODUCT_ID → friendly error naming the variable, no request."""
        monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", bad_id)
        instance = ik.InfomaniakClient(_config())
        with pytest.raises(LLMError) as exc_info:
            await instance.chat(_msgs())
        await instance.close()
        assert exc_info.value.user_facing is True
        assert "INFOMANIAK_PRODUCT_ID" in exc_info.value.message
        assert fake.product_scoped_requests == []

    async def test_infomaniak_discovery_account_identifiers_never_logged(
        self,
        ik: ModuleType,
        fake: FakeInfomaniak,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """account_name / product_name / token never appear in logs on success."""
        caplog.set_level(logging.DEBUG)
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        instance = ik.InfomaniakClient(_config())
        await instance.chat(_msgs())
        await instance.close()
        for secret in (_ACCOUNT_MARKER, _PRODUCT_MARKER, _TOKEN):
            assert secret not in caplog.text

    async def test_infomaniak_discovery_account_identifiers_not_in_errors(
        self,
        ik: ModuleType,
        fake: FakeInfomaniak,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The multi-product error names neither accounts nor products, and logs none."""
        caplog.set_level(logging.DEBUG)
        fake.discovery = _discovery(_product(1), _product(2))
        with pytest.raises(LLMError) as exc_info:
            await ik.discover_product_id(_TOKEN)
        _assert_not_leaked(exc_info.value, caplog, _ACCOUNT_MARKER, _PRODUCT_MARKER, _TOKEN)

    async def test_infomaniak_resolve_product_id_missing_token_user_facing(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """resolve_product_id() without a token → "isn't configured", no discovery."""
        monkeypatch.delenv("INFOMANIAK_API_TOKEN")
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        instance = ik.InfomaniakClient(_config())
        with pytest.raises(LLMError) as exc_info:
            await instance.resolve_product_id()
        assert exc_info.value.user_facing is True
        assert "isn't configured" in exc_info.value.message
        assert fake.requests == []


# ===========================================================================
# Missing token / model
# ===========================================================================


class TestInfomaniakMissingSetup:
    """Setup problems become friendly, actionable chat replies."""

    @pytest.mark.parametrize("token", [None, "", "   "], ids=["unset", "empty", "whitespace"])
    async def test_infomaniak_chat_missing_token_mandated_message(
        self,
        ik: ModuleType,
        fake: FakeInfomaniak,
        monkeypatch: pytest.MonkeyPatch,
        token: str | None,
    ) -> None:
        """No token → "Infomaniak isn't configured; set INFOMANIAK_API_TOKEN", no request."""
        if token is None:
            monkeypatch.delenv("INFOMANIAK_API_TOKEN")
        else:
            monkeypatch.setenv("INFOMANIAK_API_TOKEN", token)
        instance = ik.InfomaniakClient(_config())
        with pytest.raises(LLMError) as exc_info:
            await instance.chat(_msgs())
        await instance.close()
        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "Infomaniak isn't configured; set INFOMANIAK_API_TOKEN" in exc_info.value.message
        assert fake.requests == []

    @pytest.mark.parametrize("model", [None, ""], ids=["none", "empty"])
    async def test_infomaniak_chat_missing_model_user_facing(
        self, ik: ModuleType, fake: FakeInfomaniak, model: str | None
    ) -> None:
        """No model → "No Infomaniak model is set … ask your administrator", no request."""
        instance = ik.InfomaniakClient(_config(infomaniak_model=model))
        with pytest.raises(LLMError) as exc_info:
            await instance.chat(_msgs())
        await instance.close()
        message = exc_info.value.message
        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "No Infomaniak model is set" in message
        assert "ask your administrator" in message
        assert "Settings → Agent" not in message  # GH-159: that section is gone
        assert fake.chat_requests == []


# ===========================================================================
# Error mapping
# ===========================================================================


_USER_FACING_STATUS_CASES: list[tuple[int, tuple[str, ...]]] = [
    (401, ("Infomaniak rejected the API token",)),
    (403, ("Infomaniak rejected the API token",)),
    (404, ("Infomaniak", "ask your administrator")),
    (429, ("Infomaniak", "rate limit")),
    (500, ("Infomaniak", "temporarily unavailable")),
    (502, ("Infomaniak", "temporarily unavailable")),
    (503, ("Infomaniak", "temporarily unavailable")),
]


class TestInfomaniakErrorMapping:
    """HTTP / transport failures map to the fixed user-facing catalogue."""

    @pytest.mark.parametrize(("status", "phrases"), _USER_FACING_STATUS_CASES)
    async def test_infomaniak_chat_status_maps_to_user_facing_error(
        self,
        client: Any,
        fake: FakeInfomaniak,
        caplog: pytest.LogCaptureFixture,
        status: int,
        phrases: tuple[str, ...],
    ) -> None:
        """401/403/404/429/5xx → user-facing, fixed message, status kept, body never leaked."""
        caplog.set_level(logging.DEBUG)
        marker = f"CHAT-BODY-SECRET-{status}"
        fake.chat = _status(status, marker)
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_msgs())
        exc = exc_info.value
        assert exc.user_facing is True
        assert exc.status_code == status
        for phrase in phrases:
            # "rate limit" may be capitalised; every other phrase is exact.
            if phrase == "rate limit":
                assert phrase in exc.message.lower()
            else:
                assert phrase in exc.message
        _assert_not_leaked(exc, caplog, marker, _TOKEN)

    # GH-242: 413 is context_too_long (user-facing), tested in test_llm_error_codes.
    @pytest.mark.parametrize("status", [400, 422])
    async def test_infomaniak_chat_other_4xx_is_internal_error(
        self,
        client: Any,
        fake: FakeInfomaniak,
        caplog: pytest.LogCaptureFixture,
        status: int,
    ) -> None:
        """Other 4xx → user_facing False (generic reply), still no body in message or logs."""
        caplog.set_level(logging.DEBUG)
        marker = f"CHAT-4XX-SECRET-{status}"
        fake.chat = _status(status, marker)
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_msgs())
        assert exc_info.value.user_facing is False
        assert exc_info.value.status_code == status
        _assert_not_leaked(exc_info.value, caplog, marker, _TOKEN)

    @pytest.mark.parametrize("exc_type", [httpx.ReadTimeout, httpx.ConnectError])
    async def test_infomaniak_chat_transport_error_temporarily_unavailable(
        self,
        client: Any,
        fake: FakeInfomaniak,
        caplog: pytest.LogCaptureFixture,
        exc_type: type[httpx.TransportError],
    ) -> None:
        """Timeout / connection failure → user-facing "temporarily unavailable", no status."""
        caplog.set_level(logging.DEBUG)
        marker = "CHAT-TRANSPORT-SECRET"
        fake.chat = _raise(exc_type, marker)
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_msgs())
        assert exc_info.value.user_facing is True
        assert exc_info.value.status_code is None
        assert "temporarily unavailable" in exc_info.value.message
        assert "Infomaniak" in exc_info.value.message
        # The transport error text itself is logged by the SDK at DEBUG (it carries
        # no response body in real life), so only the exception must omit it.
        assert marker not in exc_info.value.message
        assert marker not in str(exc_info.value)
        _assert_not_leaked(exc_info.value, caplog, _TOKEN)

    @pytest.mark.parametrize("status", [429, 500, 503])
    async def test_infomaniak_chat_errors_not_retried_by_client(
        self, client: Any, fake: FakeInfomaniak, status: int
    ) -> None:
        """The SDK client does not retry (max_retries=0); retries belong to the gateway."""
        fake.chat = _status(status, "retry-marker")
        with pytest.raises(LLMError):
            await client.chat(_msgs())
        assert len(fake.chat_requests) == 1


# ===========================================================================
# list_models()
# ===========================================================================


class TestInfomaniakListModels:
    """Model listing for the Settings dropdown — never raises."""

    async def test_infomaniak_list_models_returns_ids(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """The ids from GET …/openai/v1/models are returned in order."""
        assert await client.list_models() == [_MODEL, "mistralai/Mistral-Small-3.2"]

    async def test_infomaniak_list_models_request_shape(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """The models endpoint is product-scoped and authenticated."""
        await client.list_models()
        request = fake.models_requests[0]
        assert request.method == "GET"
        assert str(request.url) == _MODELS_URL
        assert request.headers["authorization"] == f"Bearer {_TOKEN}"

    async def test_infomaniak_list_models_missing_token_returns_empty(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No token → [] and no request."""
        monkeypatch.delenv("INFOMANIAK_API_TOKEN")
        instance = ik.InfomaniakClient(_config())
        assert await instance.list_models() == []
        await instance.close()
        assert fake.requests == []

    @pytest.mark.parametrize("status", [401, 404, 500])
    async def test_infomaniak_list_models_http_error_returns_empty(
        self, client: Any, fake: FakeInfomaniak, status: int
    ) -> None:
        """HTTP errors degrade to []."""
        fake.models = _status(status, "models-marker")
        assert await client.list_models() == []

    async def test_infomaniak_list_models_transport_error_returns_empty(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Timeouts degrade to []."""
        fake.models = _raise(httpx.ReadTimeout, "models-timeout")
        assert await client.list_models() == []

    @pytest.mark.parametrize(
        "route",
        [
            lambda _r: httpx.Response(200, content=b"not json at all"),
            lambda _r: _json({"object": "list", "data": "nope"}),
            lambda _r: _json({"object": "list", "data": 42}),
        ],
        ids=["not-json", "data-string", "data-int"],
    )
    async def test_infomaniak_list_models_bad_payload_returns_empty(
        self,
        client: Any,
        fake: FakeInfomaniak,
        route: Callable[[httpx.Request], httpx.Response],
    ) -> None:
        """A malformed models payload degrades to []."""
        fake.models = route
        assert await client.list_models() == []

    async def test_infomaniak_list_models_discovery_failure_returns_empty(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed product discovery degrades to []."""
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        fake.discovery = _discovery(_product(1), _product(2))
        instance = ik.InfomaniakClient(_config())
        assert await instance.list_models() == []
        await instance.close()
        assert fake.models_requests == []

    async def test_infomaniak_list_models_ids_sanitized(
        self, client: Any, fake: FakeInfomaniak
    ) -> None:
        """Control / bidi characters are stripped from returned ids."""
        fake.models = _reply({"object": "list", "data": [{"id": f"Qwen\x00/evil{_RLO}model"}]})
        models = await client.list_models()
        assert all("\x00" not in m and _RLO not in m for m in models)


# ===========================================================================
# Lifecycle
# ===========================================================================


class TestInfomaniakLifecycle:
    """close() and the async context manager."""

    async def test_infomaniak_close_before_use_is_safe(
        self, ik: ModuleType, fake: FakeInfomaniak
    ) -> None:
        """close() on a never-used client neither raises nor makes a request."""
        instance = ik.InfomaniakClient(_config())
        await instance.close()
        assert fake.requests == []

    async def test_infomaniak_close_after_use_closes_http_clients(
        self, ik: ModuleType, fake: FakeInfomaniak, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After close(), every HTTP client the module built is closed."""
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        instance = ik.InfomaniakClient(_config())
        await instance.chat(_msgs())
        await instance.close()
        assert fake.clients
        assert all(c.is_closed for c in fake.clients)

    async def test_infomaniak_async_context_manager(
        self, ik: ModuleType, fake: FakeInfomaniak
    ) -> None:
        """`async with` yields the client and closes it on exit."""
        async with ik.InfomaniakClient(_config()) as instance:
            assert isinstance(instance, ik.InfomaniakClient)
            await instance.chat(_msgs())
        assert all(c.is_closed for c in fake.clients)


# ===========================================================================
# Logging hygiene
# ===========================================================================


class TestInfomaniakLogging:
    """No credentials, account identifiers or content in logs."""

    async def test_infomaniak_chat_token_never_logged(
        self, client: Any, fake: FakeInfomaniak, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The API token never appears in any log record, even at DEBUG."""
        caplog.set_level(logging.DEBUG)
        await client.chat(_msgs())
        fake.chat = _sse(_text_chunks("Hi"))
        await _collect(client)
        await client.list_models()
        assert _TOKEN not in caplog.text

    async def test_infomaniak_chat_content_not_logged(
        self, client: Any, fake: FakeInfomaniak, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Neither the user message nor the reply is logged at INFO or above."""
        caplog.set_level(logging.INFO)
        fake.chat = _reply(_completion("REPLY-CONTENT-MARKER"))
        await client.chat(_msgs("USER-CONTENT-MARKER"))
        assert "USER-CONTENT-MARKER" not in caplog.text
        assert "REPLY-CONTENT-MARKER" not in caplog.text
