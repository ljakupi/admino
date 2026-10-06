"""Security-audit fixes of the streaming LLM layer (GH-8, contract C10: M-1, M-2, L-2).

Every client is built from a real ``LLMConfig`` and drives its REAL SDK
(``openai`` for Infomaniak, vLLM and OpenAI; ``anthropic`` for Claude) against a
fake wire: ``httpx.AsyncClient.send`` is replaced by a scripted route that
answers with an SSE body built frame by frame while it is read (so a huge
stream is never held whole by the test), or with a plain JSON reply for
``chat()``. Nothing reaches a real host.

What these tests pin:

- M-1 (Infomaniak ``</think>`` filter): the deltas of one stream never carry
  more than 65536 characters in total, whatever the orphan ``</think>`` tags
  (the budget never resets, and text retracted inside one chunk before it was
  streamed does not use it). The final content keeps today's orphan rule (an
  orphan ``</think>`` drops everything before it), equal to ``chat()`` on the
  same text, also after the delta budget is spent. A stream without an orphan
  close is unchanged: joined deltas == final content, capped at 65536 (paired
  ``<think>`` blocks never count).
- M-2 (OpenAI, vLLM, Infomaniak; shared stream reader): a streamed tool call
  whose name fragments add up to more than 256 characters is dropped and its
  neighbours kept (exactly 256 is kept; a crossing fragment is neither skipped
  nor sliced into a kept name); 50 name fragments of 100000 characters
  complete, drop the call, and are never accumulated (the traced memory peak
  while reading stays far below the joined name). Arguments: a single fragment
  over the 65536 budget drops its call; arguments that reach exactly 65536
  (single fragment or across fragments) still parse; a fragment that would cross
  the budget drops the call, even when its in-budget part or a later small
  fragment would complete valid JSON.
- L-2: ``strip_control_chars`` removes lone surrogates (U+D800..U+DFFF; the
  neighbours U+D7FF / U+E000 and an astral emoji stay). A stream carrying
  JSON-escaped lone surrogates (in the text, a pair split across two chunks,
  and the model name) yields deltas without any surrogate and a final
  ``LLMResponse`` that builds, its content the joined deltas; ``chat()`` on the
  same text returns it without them (OpenAI, vLLM, Infomaniak, Anthropic).

Security notes:
- Keys are built at runtime (``tests.credential_keys``); no key literal here.
- The SDKs' retry sleep is a no-op so a retrying client fails fast.
"""

from __future__ import annotations

import json
import tracemalloc
from typing import TYPE_CHECKING, Any, Final

import anthropic._base_client as anthropic_base_client
import httpx
import openai._base_client as openai_base_client
import pytest

from admino.config import LLMConfig
from admino.llm import LLMResponse, LLMStreamDelta, strip_control_chars
from admino.llm_anthropic import AnthropicClient
from admino.llm_infomaniak import InfomaniakClient
from admino.llm_openai import OpenAIClient
from admino.llm_vllm import VLLMClient
from admino.models import LLMMessage
from tests.credential_keys import api_key

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterable, Iterator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENAI_COMPATIBLE: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak")
ALL_PROVIDERS: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak", "anthropic")

_MAX_CONTENT: Final = 65536
_ARG_BUDGET: Final = 65536
_NAME_BUDGET: Final = 256
_MAX_TOKENS: Final = 777
_IK_PRODUCT_ID: Final = "7539"
_STREAM_MODEL: Final = "wire-stream-model"

_OPENAI_KEY: Final = api_key("sk-", 48, seed=8801).text
_ANTHROPIC_KEY: Final = api_key("sk-" + "ant-", 48, seed=8802).text
_IK_TOKEN: Final = api_key("ik-", 40, seed=8803).text

_THINK_OPEN: Final = "<think>"
_THINK_CLOSE: Final = "</think>"

# Surrogates and their neighbours, built with chr() (no escape lives in the source).
_HIGH_FIRST: Final = chr(0xD800)
_HIGH_LAST: Final = chr(0xDBFF)
_LOW_FIRST: Final = chr(0xDC00)
_LOW_LAST: Final = chr(0xDFFF)
_PAIR_HIGH: Final = chr(0xD83D)
_PAIR_LOW: Final = chr(0xDE00)
_BEFORE_SURROGATES: Final = chr(0xD7FF)
_AFTER_SURROGATES: Final = chr(0xE000)
_GRIN: Final = chr(0x1F600)

# Stream pieces with lone surrogates (each piece's JSON escapes them; a high one never
# directly precedes a low one inside a piece, or JSON would decode a valid pair). The
# pair D83D/DE00 is split across two chunks; the emoji stays whole in one chunk.
_SURROGATE_PIECES: Final[tuple[str, ...]] = (
    "Hi " + _HIGH_FIRST,
    _LOW_LAST + "there " + _HIGH_LAST,
    "x" + _LOW_FIRST + "pair" + _PAIR_HIGH,
    _PAIR_LOW + "end " + _GRIN,
)
# The same lone surrogates in one text for chat() (no high one directly before a low one).
_SURROGATE_TEXT: Final = (
    "Hi " + _HIGH_FIRST + "there " + _LOW_LAST + _HIGH_LAST + "xpair" + _LOW_FIRST + "end " + _GRIN
)
_SURROGATE_CLEAN: Final = "Hi there xpairend " + _GRIN
_SURROGATE_MODEL: Final = "model-" + _HIGH_LAST + "-x" + _LOW_FIRST
_SURROGATE_MODEL_CLEAN: Final = "model--x"

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
# OpenAI-compatible chunks
# ---------------------------------------------------------------------------


def _chunk(
    delta: dict[str, Any] | None = None,
    *,
    finish_reason: str | None = None,
    model: str = _STREAM_MODEL,
) -> dict[str, Any]:
    """One ``chat.completion.chunk``."""
    return {
        "id": "chatcmpl-w8-stream",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": model,
        "choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}],
    }


def _text_chunks(*pieces: str, model: str = _STREAM_MODEL) -> list[dict[str, Any]]:
    """Content-only chunks, then a ``stop`` chunk."""
    chunks = [_chunk({"content": piece}, model=model) for piece in pieces]
    chunks.append(_chunk({}, finish_reason="stop", model=model))
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


def _tools_chunk(*fragments: dict[str, Any]) -> dict[str, Any]:
    """A chunk carrying tool-call fragments only."""
    return _chunk({"tool_calls": list(fragments)})


def _finish_tools() -> dict[str, Any]:
    """The chunk ending a tool-call turn."""
    return _chunk({}, finish_reason="tool_calls")


def _completion(content: str, *, model: str = _STREAM_MODEL) -> dict[str, Any]:
    """A non-streamed ``chat.completion`` body (for ``chat()``)."""
    return {
        "id": "chatcmpl-w8-json",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Anthropic frames
# ---------------------------------------------------------------------------


def _frame(event: str, data: dict[str, Any]) -> bytes:
    """One Anthropic Messages SSE frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _anthropic_frames(*pieces: str, model: str) -> list[bytes]:
    """A whole stream: message_start, one text block with a delta per piece, the end."""
    frames = [
        _frame(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_w8_01",
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 10, "output_tokens": 1},
                },
            },
        ),
        _frame(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
    ]
    frames.extend(
        _frame(
            "content_block_delta",
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}},
        )
        for p in pieces
    )
    frames.extend(
        [
            _frame("content_block_stop", {"type": "content_block_stop", "index": 0}),
            _frame(
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 15},
                },
            ),
            _frame("message_stop", {"type": "message_stop"}),
        ]
    )
    return frames


def _anthropic_message(text: str, *, model: str) -> dict[str, Any]:
    """A non-streamed Anthropic ``message`` body (for ``chat()``)."""
    return {
        "id": "msg_w8_json",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


# ---------------------------------------------------------------------------
# The fake wire
# ---------------------------------------------------------------------------


class _LazyBody(httpx.AsyncByteStream):
    """A response body produced frame by frame while it is read (never held whole)."""

    def __init__(self, frames: Iterable[bytes]) -> None:
        self._frames = frames

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield each frame as the reader asks for it."""
        for frame in self._frames:
            yield frame

    async def aclose(self) -> None:
        """Nothing to release."""


def _openai_frames(chunks: Iterable[dict[str, Any]]) -> Iterator[bytes]:
    """``data: <chunk>`` lines, encoded one at a time, then ``data: [DONE]``."""
    for chunk in chunks:
        yield f"data: {json.dumps(chunk)}\n\n".encode()
    yield b"data: [DONE]\n\n"


def _sse_route(frames: Iterable[bytes]) -> Callable[[httpx.Request], httpx.Response]:
    """A route answering with a streamed SSE body."""

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_LazyBody(frames),
            request=request,
        )

    return route


def _json_route(body: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """A route answering with a JSON body (ASCII-escaped, so a lone surrogate stays an escape)."""
    content = json.dumps(body).encode()

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "application/json"}, content=content, request=request
        )

    return route


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    Each POST gets ``self.route``; anything else (or a POST without a route)
    gets a 404, so an unexpected request is visible.
    """

    def __init__(self) -> None:
        self.route: Callable[[httpx.Request], httpx.Response] | None = None
        self.requests: list[str] = []

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it."""
        await request.aread()
        self.requests.append(f"{request.method}:{request.url.path}")
        if request.method != "POST" or self.route is None:
            return httpx.Response(404, json={"error": "unexpected"}, request=request)
        return self.route(request)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every provider configured; no base-URL or account override from the environment."""
    monkeypatch.setenv("OPENAI_API_KEY", _OPENAI_KEY)
    monkeypatch.setenv("ANTHROPIC_API_KEY", _ANTHROPIC_KEY)
    monkeypatch.setenv("INFOMANIAK_API_TOKEN", _IK_TOKEN)
    monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", _IK_PRODUCT_ID)
    for name in (
        "OPENAI_BASE_URL",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
        "OPENAI_LOG",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_sdk_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client whose SDK still retries fails fast instead of sleeping."""

    async def no_sleep(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(openai_base_client.AsyncAPIClient, "_sleep_for_retry", no_sleep)
    monkeypatch.setattr(anthropic_base_client.AsyncAPIClient, "_sleep_for_retry", no_sleep)


@pytest.fixture()
def wire(monkeypatch: pytest.MonkeyPatch) -> _Wire:
    """Route every ``httpx.AsyncClient.send`` through the fake wire."""
    fake = _Wire()

    async def send(_client: httpx.AsyncClient, request: httpx.Request, **_: Any) -> httpx.Response:
        return await fake.send(request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    return fake


_CLIENT_CLASSES: Final[dict[str, Callable[[LLMConfig], Any]]] = {
    "infomaniak": InfomaniakClient,
    "vllm": VLLMClient,
    "openai": OpenAIClient,
    "anthropic": AnthropicClient,
}


@pytest.fixture()
async def build(wire: _Wire) -> AsyncIterator[Callable[[str], Any]]:
    """Build provider clients on the fake wire; every built client is closed after."""
    built: list[Any] = []

    def factory(provider: str) -> Any:
        config = LLMConfig(
            provider=provider,
            timeout_s=5,
            max_response_tokens=_MAX_TOKENS,
            infomaniak_model="Qwen/Qwen3.5-397B-A17B-FP8",
            vllm_model="Qwen/Qwen3-4B-Instruct-2507",
            vllm_base_url="http://vllm:8000/v1",
            openai_model="gpt-4o",
            anthropic_model="claude-sonnet-4-6",
        )
        client = _CLIENT_CLASSES[provider](config)
        built.append(client)
        return client

    yield factory
    for client in built:
        await client.close()


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


def _deltas(items: list[Any]) -> list[str]:
    """The text of every streamed delta, in order."""
    return [item.content for item in items if isinstance(item, LLMStreamDelta)]


def _last(items: list[Any]) -> LLMResponse:
    """The final response after checking the shape: non-empty deltas, one final, last."""
    assert items, "the stream yielded nothing"
    *deltas, final = items
    assert type(final) is LLMResponse
    assert all(type(d) is LLMStreamDelta and d.content for d in deltas)
    return final


def _final(items: list[Any]) -> LLMResponse:
    """``_last`` plus the C1.1 invariant: the final content is the joined deltas."""
    final = _last(items)
    assert final.content == "".join(_deltas(items))
    return final


def _runs(text: str) -> list[tuple[str, int]]:
    """Run-length summary of ``text`` (keeps failure reports of 64 KiB texts short)."""
    runs: list[tuple[str, int]] = []
    for char in text:
        if runs and runs[-1][0] == char:
            runs[-1] = (char, runs[-1][1] + 1)
        else:
            runs.append((char, 1))
    return runs


def _calls(final: LLMResponse) -> list[tuple[str, str, dict[str, Any], str | None]]:
    """The final response's tool calls as (tool, action, args, id) tuples."""
    return [(c.tool, c.action, c.args, c.tool_call_id) for c in final.tool_calls]


def _surrogates(text: str) -> list[str]:
    """The surrogate code points in ``text`` (hex), in order."""
    return [f"{ord(c):04X}" for c in text if 0xD800 <= ord(c) <= 0xDFFF]


def _padded(head: str, total: int, tail: str = "}") -> str:
    """``head`` + JSON whitespace + ``tail``: exactly ``total`` characters."""
    return head + " " * (total - len(head) - len(tail)) + tail


def _pieces(text: str, size: int) -> list[str]:
    """``text`` cut into consecutive pieces of ``size`` characters."""
    return [text[start : start + size] for start in range(0, len(text), size)]


async def _infomaniak_stream_and_chat(
    wire: _Wire, build: Callable[[str], Any], pieces: list[str]
) -> tuple[list[Any], str]:
    """Stream ``pieces`` through Infomaniak, then ``chat()`` on their joined text."""
    client = build("infomaniak")
    wire.route = _sse_route(_openai_frames(_text_chunks(*pieces)))
    items = await _drain(client)
    wire.route = _json_route(_completion("".join(pieces)))
    chat_content = (await client.chat(_messages())).content
    return items, chat_content


# ===========================================================================
# M-1: Infomaniak orphan </think> never resets the delta budget
# ===========================================================================


async def test_llm_audit_infomaniak_orphan_close_rounds_stream_one_budget(
    wire: _Wire, build: Callable[[str], Any]
) -> None:
    """Four rounds of 65536 letters + an orphan </think>: only the first round is streamed.

    A leading chunk retracted by its own orphan close (never streamed) does not use
    the budget; the final content is chat()'s (everything before the last orphan
    dropped: empty).
    """
    pieces = ["z" * 60000 + _THINK_CLOSE]
    for letter in "abcd":
        pieces += [letter * _MAX_CONTENT, _THINK_CLOSE]
    items, chat_content = await _infomaniak_stream_and_chat(wire, build, pieces)
    final = _last(items)
    assert (_runs("".join(_deltas(items))), final.content, chat_content) == (
        [("a", _MAX_CONTENT)],
        "",
        "",
    )


async def test_llm_audit_infomaniak_orphan_close_after_smaller_texts_budget_and_final_rule(
    wire: _Wire, build: Callable[[str], Any]
) -> None:
    """Five 20000-letter texts each closed by an orphan </think>, then "tail".

    The deltas stop after 65536 characters in total; the final content is still
    today's rule (the text after the last orphan), equal to chat() on the same text.
    """
    pieces: list[str] = []
    for letter in "abcde":
        pieces += [letter * 20000, _THINK_CLOSE]
    pieces.append("tail")
    items, chat_content = await _infomaniak_stream_and_chat(wire, build, pieces)
    final = _last(items)
    assert (_runs("".join(_deltas(items))), final.content, chat_content) == (
        [("a", 20000), ("b", 20000), ("c", 20000), ("d", _MAX_CONTENT - 60000)],
        "tail",
        "tail",
    )


async def test_llm_audit_infomaniak_stream_without_orphan_close_unchanged(
    wire: _Wire, build: Callable[[str], Any]
) -> None:
    """Regression guard: a paired <think> block and 80000 letters stream as before.

    Joined deltas == final content == chat() == the first 65536 visible characters;
    the reasoning never counts toward the cap.
    """
    pieces = [_THINK_OPEN + "r" * 70000 + _THINK_CLOSE, "a" * 40000, "b" * 40000]
    items, chat_content = await _infomaniak_stream_and_chat(wire, build, pieces)
    expected = [("a", 40000), ("b", _MAX_CONTENT - 40000)]
    final = _final(items)
    assert (_runs(final.content), _runs(chat_content)) == (expected, expected)


# ===========================================================================
# M-2: streamed tool-call names and arguments are bounded
# ===========================================================================


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_audit_stream_tool_name_over_256_chars_dropped_neighbours_kept(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """Name fragments of 256 characters are kept, 257 dropped; the calls around them stay.

    The 257th character arrives in a fragment that crosses the bound: it is neither
    skipped nor sliced into a kept 256-character name. The kept 256-character name
    is cut to 64 by the chat() parser, as before.
    """
    pad = "e" * ((_NAME_BUDGET - len("memory.store")) // 2)
    chunks = [
        _tools_chunk(_frag(0, call_id="call_0", name="memory.store", arguments='{"key": "first"}')),
        _tools_chunk(_frag(1, call_id="call_1", name="memory.store", arguments='{"key": ')),
        _tools_chunk(_frag(1, name=pad)),
        _tools_chunk(_frag(2, call_id="call_2", name="memory.store", arguments='{"key": "x"}')),
        _tools_chunk(_frag(2, name=pad), _frag(1, name=pad, arguments='"second"}')),
        _tools_chunk(_frag(2, name=pad + "e")),
        _tools_chunk(_frag(3, call_id="call_3", name="memory.recall", arguments='{"key": "last"}')),
        _finish_tools(),
    ]
    wire.route = _sse_route(_openai_frames(chunks))
    final = _final(await _drain(build(provider), [_MEMORY_TOOL]))
    assert _calls(final) == [
        ("memory", "store", {"key": "first"}, "call_0"),
        ("memory", "store" + "e" * 52, {"key": "second"}, "call_1"),
        ("memory", "recall", {"key": "last"}, "call_3"),
    ]


_HUGE_FRAGMENT: Final = "e" * 100_000
_HUGE_FRAGMENTS: Final = 50


def _huge_name_chunks() -> Iterator[dict[str, Any]]:
    """A valid call, a call whose name gets 50 fragments of 100000 characters, a valid call."""
    yield _tools_chunk(_frag(0, call_id="call_0", name="memory.store", arguments='{"key": "a"}'))
    yield _tools_chunk(_frag(1, call_id="call_1", name="memory.store", arguments='{"key": "b"}'))
    for _ in range(_HUGE_FRAGMENTS):
        yield _tools_chunk(_frag(1, name=_HUGE_FRAGMENT))
    yield _tools_chunk(_frag(2, call_id="call_2", name="memory.recall", arguments='{"key": "c"}'))
    yield _finish_tools()


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_audit_stream_huge_name_fragments_complete_and_drop_call(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """5,000,000 characters of name fragments: the stream completes and only that call goes."""
    wire.route = _sse_route(_openai_frames(_huge_name_chunks()))
    final = _final(await _drain(build(provider), [_MEMORY_TOOL]))
    assert _calls(final) == [
        ("memory", "store", {"key": "a"}, "call_0"),
        ("memory", "recall", {"key": "c"}, "call_2"),
    ]


# The joined name alone would be 5,000,000 bytes (twice that while it grows); reading
# one ~100 KB wire event peaks near 1 MB. Measured after a warm-up stream, so the
# SDK's lazy imports and client setup are not counted.
_NAME_PEAK_LIMIT: Final = 3_000_000


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_audit_stream_huge_name_fragments_never_accumulated(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """Reading 50 name fragments of 100000 characters never holds their joined name.

    The traced memory peak while the stream is read stays below 3 MB (one wire event
    is about 100 KB; an unbounded name would be 5 MB, twice that while it grows).
    """
    client = build(provider)
    warm_up = [
        _tools_chunk(_frag(0, call_id="call_w", name="memory.store", arguments='{"key": "w"}')),
        _finish_tools(),
    ]
    wire.route = _sse_route(_openai_frames(warm_up))
    await _drain(client, [_MEMORY_TOOL])
    wire.route = _sse_route(_openai_frames(_huge_name_chunks()))
    started = not tracemalloc.is_tracing()
    if started:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before, _ = tracemalloc.get_traced_memory()
        items = await _drain(client, [_MEMORY_TOOL])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if started:
            tracemalloc.stop()
    assert (type(items[-1]) is LLMResponse, peak - before < _NAME_PEAK_LIMIT) == (True, True), (
        peak - before
    )


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_audit_stream_single_argument_fragment_over_budget_dropped(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """One fragment of exactly 65536 characters parses; one of 65537 drops its call.

    Both are whitespace-padded valid JSON (small once parsed, so the 16384 check
    passes); the 65537-character fragment is not sliced into a kept call either.
    """
    chunks = [
        _tools_chunk(
            _frag(
                0,
                call_id="call_0",
                name="memory.store",
                arguments=_padded('{"key": "a"', _ARG_BUDGET),
            )
        ),
        _tools_chunk(
            _frag(
                1,
                call_id="call_1",
                name="memory.store",
                arguments=_padded('{"key": "b"}', _ARG_BUDGET + 1, tail=""),
            )
        ),
        _tools_chunk(_frag(2, call_id="call_2", name="memory.recall", arguments='{"key": "c"}')),
        _finish_tools(),
    ]
    wire.route = _sse_route(_openai_frames(chunks))
    final = _final(await _drain(build(provider), [_MEMORY_TOOL]))
    assert _calls(final) == [
        ("memory", "store", {"key": "a"}, "call_0"),
        ("memory", "recall", {"key": "c"}, "call_2"),
    ]


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_audit_stream_argument_fragment_crossing_budget_drops_call(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """Across fragments: exactly 65536 parses; a fragment crossing 65536 drops the call.

    call_1's crossing fragment closes the JSON inside the budget ("}" then spaces);
    call_2's crossing fragment is whitespace and a later "}" would still fit. Both
    are dropped; the calls at exactly the budget and after them stay.
    """
    exact = _pieces(_padded('{"key": "a"', _ARG_BUDGET), 16384)
    head_b = _pieces(_padded('{"key": "b"', _ARG_BUDGET - 6, tail=""), 16384)
    head_c = _pieces(_padded('{"key": "c"', _ARG_BUDGET - 6, tail=""), 16384)
    chunks = [
        _tools_chunk(_frag(0, call_id="call_0", name="memory.store", arguments=exact[0])),
        _tools_chunk(_frag(1, call_id="call_1", name="memory.store", arguments=head_b[0])),
        _tools_chunk(_frag(2, call_id="call_2", name="memory.store", arguments=head_c[0])),
    ]
    for a, b, c in zip(exact[1:], head_b[1:], head_c[1:], strict=True):
        chunks.append(
            _tools_chunk(_frag(0, arguments=a), _frag(1, arguments=b), _frag(2, arguments=c))
        )
    chunks += [
        _tools_chunk(_frag(1, arguments="}" + " " * 10), _frag(2, arguments=" " * 10)),
        _tools_chunk(_frag(2, arguments="}")),
        _tools_chunk(_frag(3, call_id="call_3", name="memory.recall", arguments='{"key": "d"}')),
        _finish_tools(),
    ]
    wire.route = _sse_route(_openai_frames(chunks))
    final = _final(await _drain(build(provider), [_MEMORY_TOOL]))
    assert _calls(final) == [
        ("memory", "store", {"key": "a"}, "call_0"),
        ("memory", "recall", {"key": "d"}, "call_3"),
    ]


# ===========================================================================
# L-2: lone surrogates are stripped
# ===========================================================================


@pytest.mark.parametrize(
    "lone",
    [_HIGH_FIRST, _HIGH_LAST, _LOW_FIRST, _LOW_LAST, _PAIR_HIGH + _PAIR_LOW],
    ids=["U+D800", "U+DBFF", "U+DC00", "U+DFFF", "split-pair-D83D-DE00"],
)
def test_llm_audit_strip_control_chars_removes_lone_surrogates(lone: str) -> None:
    """Every surrogate code point goes; U+D7FF, U+E000 and an astral emoji stay."""
    text = "a" + _BEFORE_SURROGATES + lone + _AFTER_SURROGATES + lone + _GRIN + "b"
    assert strip_control_chars(text) == "a" + _BEFORE_SURROGATES + _AFTER_SURROGATES + _GRIN + "b"


def _surrogate_stream(provider: str) -> Iterable[bytes]:
    """The provider's stream of ``_SURROGATE_PIECES`` with the surrogate model name."""
    if provider == "anthropic":
        return _anthropic_frames(*_SURROGATE_PIECES, model=_SURROGATE_MODEL)
    return _openai_frames(_text_chunks(*_SURROGATE_PIECES, model=_SURROGATE_MODEL))


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_audit_stream_lone_surrogates_never_in_deltas_final_builds(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """JSON-escaped lone surrogates (text, a pair split across chunks, the model).

    No delta carries one, the final LLMResponse builds with the joined deltas as its
    content, and the model is the sanitized stream model.
    """
    wire.route = _sse_route(_surrogate_stream(provider))
    items = await _drain(build(provider))
    deltas = _deltas(items)
    final = _final(items)
    assert (
        [s for d in deltas for s in _surrogates(d)],
        final.content,
        final.model,
    ) == ([], _SURROGATE_CLEAN, _SURROGATE_MODEL_CLEAN)


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_audit_chat_lone_surrogates_removed_from_content(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat() on the same text (lone surrogates, model too) returns them removed."""
    text = _SURROGATE_TEXT
    if provider == "anthropic":
        body = _anthropic_message(text, model=_SURROGATE_MODEL)
    else:
        body = _completion(text, model=_SURROGATE_MODEL)
    wire.route = _json_route(body)
    result = await build(provider).chat(_messages())
    assert (result.content, result.model) == (_SURROGATE_CLEAN, _SURROGATE_MODEL_CLEAN)
