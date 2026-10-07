"""Pins of existing LLM-client guards (GH-278 Decision 8, the GH-25 review's test gaps).

These guards already exist; the tests pin them with no behaviour change. Each test
is written so that the review's mutant of its guard fails it. Every client is
built from a real ``LLMConfig`` and drives its REAL SDK (``openai`` for
Infomaniak, vLLM and OpenAI; ``anthropic`` for Claude) against a fake wire:
``httpx.AsyncClient.send`` is replaced by scripted routes (a JSON body for
``chat()``, an SSE body for ``chat_stream()``, a product-discovery GET that waits).
Nothing reaches a real host.

What these tests pin:

- P38 (Anthropic stream): a second ``content_block_start`` for a tool_use at a
  block index the reply already holds rejects the reply with
  ``malformed_response`` (the text streamed before it reached the consumer); the
  same blocks at two distinct indexes are both returned.
- P40 (OpenAI-compatible stream: OpenAI, vLLM and Infomaniak share the reader): a
  JSON ``true`` as a tool-call fragment's ``index`` rejects the reply; the same
  fragment with index ``0`` is accepted. The SDK validates a well-formed fragment
  and turns ``true`` into ``1`` (pydantic's lax mode), so the fragment carries a
  ``type`` the SDK can't validate (the client never reads it): the SDK then
  builds the fragment as sent and the client sees ``True``. The Anthropic stream's
  own index check gets the same pin (a tool_use start whose ``input`` the SDK
  can't validate; the client reads the arguments from ``input_json_delta`` only).
- A ``tool_calls`` or ``choices`` that is present but not a list, in every
  OpenAI-compatible client, stream and ``chat()``: ``malformed_response``, as
  their siblings, never a raw exception and never a silently accepted reply. The
  stream skips a falsy ``tool_calls`` / ``choices`` before its list check, so only
  truthy values are pinned there.
- P35 (Infomaniak think filter): orphan ``</think>`` tags reset the answer, but
  not the stream's 65536-character delta budget. When the budget cuts the deltas
  while the final answer itself fits, the final ``LLMResponse.truncated`` is
  True; the same stream within the budget is not truncated.
- P27 (Infomaniak): product-ID discovery counts against ``llm.stream_deadline_s``.
  With no ``INFOMANIAK_PRODUCT_ID`` and a discovery request that never answers
  (or answers only after the deadline), ``chat_stream()`` fails with the
  ``timeout`` error at the deadline (far below discovery's own 10 s timeout),
  the discovery request is cancelled and no chat request is sent.

Every malformed case is the catalogue's ``malformed_response_error(label)``.

Security notes:
- Keys are built at runtime (``tests.credential_keys``); no key literal here.
- The SDKs' retry sleep is a no-op, so a retrying client fails fast.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

import anthropic._base_client as anthropic_base_client
import httpx
import openai._base_client as openai_base_client
import pytest

from admino.config import LLMConfig
from admino.llm import LLMError, LLMResponse, LLMStreamDelta
from admino.llm_anthropic import AnthropicClient
from admino.llm_infomaniak import InfomaniakClient
from admino.llm_openai import OpenAIClient
from admino.llm_vllm import VLLMClient
from admino.models import LLMMessage
from tests.credential_keys import api_key

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENAI_COMPATIBLE: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak")

_LABELS: Final[dict[str, str]] = {
    "openai": "OpenAI",
    "vllm": "vLLM",
    "infomaniak": "Infomaniak",
    "anthropic": "Claude",
}

_MAX_TOKENS: Final = 777
_IK_PRODUCT_ID: Final = "7539"
_MODEL: Final = "wire-w1-model"
_MAX_CONTENT: Final = 65536

_OPENAI_KEY: Final = api_key("sk-", 48, seed=27811).text
_ANTHROPIC_KEY: Final = api_key("sk-" + "ant-", 48, seed=27812).text
_IK_TOKEN: Final = api_key("ik-", 40, seed=27813).text

# The answer text every stream sends first (ends with a space: no filter holds it back).
_TEXT: Final = "Checking the notes "
_FIRST_ARGS: Final = json.dumps({"key": "first"})
_SECOND_ARGS: Final = json.dumps({"key": "second"})

# A tool-call ``type`` the openai SDK can't validate (it expects "function"); the
# client never reads it. With it, the SDK keeps the fragment's fields as sent.
_UNVALIDATED_TYPE: Final = "future_call_type"

_THINK_CLOSE: Final = "</think>"

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

# P27: the stream deadline, the floor below which no timeout may come, the bound by
# which it must have come ("at the deadline", far below discovery's 10 s timeout),
# and the bound after which a call counts as hung.
_DEADLINE: Final = 0.3
_FLOOR: Final = 0.25
_AT_DEADLINE: Final = 1.2
_LATE_DISCOVERY: Final = 1.5
_HUNG: Final = 3.0

# ---------------------------------------------------------------------------
# OpenAI-compatible bodies and chunks
# ---------------------------------------------------------------------------


def _chunk(
    delta: dict[str, Any] | None = None, *, finish_reason: str | None = None
) -> dict[str, Any]:
    """One ``chat.completion.chunk``."""
    return {
        "id": "chatcmpl-w1-stream",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": _MODEL,
        "choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}],
    }


def _oa_frames(chunks: list[dict[str, Any]]) -> list[bytes]:
    """``data: <chunk>`` lines, then ``data: [DONE]``."""
    return [*(f"data: {json.dumps(chunk)}\n\n".encode() for chunk in chunks), b"data: [DONE]\n\n"]


def _completion(message: dict[str, Any], *, choices: Any = None) -> dict[str, Any]:
    """A ``chat.completion`` body (``choices`` replaces the one-choice list when given)."""
    return {
        "id": "chatcmpl-w1-json",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": _MODEL,
        "choices": (
            choices
            if choices is not None
            else [{"index": 0, "message": message, "finish_reason": "tool_calls"}]
        ),
    }


def _oa_tool_call() -> dict[str, Any]:
    """One valid ``message.tool_calls`` entry."""
    return {
        "id": "call_0",
        "type": "function",
        "function": {"name": "memory.store", "arguments": _FIRST_ARGS},
    }


# ---------------------------------------------------------------------------
# Anthropic frames
# ---------------------------------------------------------------------------


def _frame(event: str, data: dict[str, Any]) -> bytes:
    """One Anthropic Messages SSE frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _a_start() -> bytes:
    """A valid ``message_start`` frame."""
    message = {
        "id": "msg_w1_01",
        "type": "message",
        "role": "assistant",
        "model": _MODEL,
        "content": [],
        "stop_reason": None,
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 1},
    }
    return _frame("message_start", {"type": "message_start", "message": message})


def _a_block_start(index: Any, block: dict[str, Any]) -> bytes:
    """A ``content_block_start`` frame."""
    return _frame(
        "content_block_start",
        {"type": "content_block_start", "index": index, "content_block": block},
    )


def _a_delta(index: Any, delta: dict[str, Any]) -> bytes:
    """A ``content_block_delta`` frame."""
    return _frame(
        "content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}
    )


def _a_block_stop(index: Any) -> bytes:
    """A ``content_block_stop`` frame."""
    return _frame("content_block_stop", {"type": "content_block_stop", "index": index})


def _a_text_block() -> list[bytes]:
    """The text block at index 0 carrying ``_TEXT``."""
    return [
        _a_block_start(0, {"type": "text", "text": ""}),
        _a_delta(0, {"type": "text_delta", "text": _TEXT}),
        _a_block_stop(0),
    ]


def _a_tool_block(index: Any, call_id: str, name: str, arguments: str) -> list[bytes]:
    """A whole tool_use block: its start, one ``input_json_delta``, its stop."""
    block = {"type": "tool_use", "id": call_id, "name": name, "input": {}}
    return [
        _a_block_start(index, block),
        _a_delta(index, {"type": "input_json_delta", "partial_json": arguments}),
        _a_block_stop(index),
    ]


def _a_end() -> list[bytes]:
    """``message_delta`` (stop reason tool_use), then ``message_stop``."""
    return [
        _frame(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                "usage": {"output_tokens": 15},
            },
        ),
        _frame("message_stop", {"type": "message_stop"}),
    ]


# ---------------------------------------------------------------------------
# The fake wire
# ---------------------------------------------------------------------------

type _Route = Callable[[httpx.Request], Awaitable[httpx.Response]]


class _Body(httpx.AsyncByteStream):
    """A response body yielding ``frames`` one by one."""

    def __init__(self, frames: list[bytes]) -> None:
        self._frames = frames

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield each frame."""
        for frame in self._frames:
            yield frame

    async def aclose(self) -> None:
        """Nothing to release."""


def _sse_route(frames: list[bytes]) -> _Route:
    """A route answering at once with a streamed SSE body."""

    async def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_Body(frames),
            request=request,
        )

    return route


def _json_route(body: dict[str, Any]) -> _Route:
    """A route answering at once with ``body`` as a 200 JSON body."""
    content = json.dumps(body).encode()

    async def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "application/json"}, content=content, request=request
        )

    return route


class _DelayedRoute:
    """Waits before answering (forever when ``delay`` is None); records a cancelled wait."""

    def __init__(self, delay: float | None, then: _Route) -> None:
        self._delay = delay
        self._then = then
        self.cancelled = False
        self.answered = False

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        """Wait, then answer with ``then`` (unless cancelled first)."""
        try:
            if self._delay is None:
                await asyncio.Event().wait()
            else:
                await asyncio.sleep(self._delay)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        self.answered = True
        return await self._then(request)


@dataclass
class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    A POST gets ``post``, a GET gets ``get``; anything else (or a method without
    a route) gets a 404, so an unexpected request is visible.
    """

    post: _Route | None = None
    get: _Route | None = None
    requests: list[str] = field(default_factory=list)

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it."""
        await request.aread()
        self.requests.append(f"{request.method}:{request.url.path}")
        route = {"POST": self.post, "GET": self.get}.get(request.method)
        if route is None:
            return httpx.Response(404, json={"error": "unexpected"}, request=request)
        return await route(request)


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
async def build(wire: _Wire) -> AsyncIterator[Callable[..., Any]]:
    """Build provider clients on the fake wire; every built client is closed after."""
    built: list[Any] = []

    def factory(provider: str, deadline: float = 300.0) -> Any:
        config = LLMConfig.model_validate(
            {
                "provider": provider,
                "timeout_s": 120,
                "max_response_tokens": _MAX_TOKENS,
                "infomaniak_model": "Qwen/Qwen3.5-397B-A17B-FP8",
                "vllm_model": "Qwen/Qwen3-4B-Instruct-2507",
                "vllm_base_url": "http://vllm:8000/v1",
                "openai_model": "gpt-4o",
                "anthropic_model": "claude-sonnet-4-6",
                "stream_deadline_s": deadline,
            }
        )
        client = _CLIENT_CLASSES[provider](config)
        built.append(client)
        return client

    yield factory
    for client in built:
        await client.close()


# ---------------------------------------------------------------------------
# Running a call and judging what reached the caller
# ---------------------------------------------------------------------------


def _messages() -> list[LLMMessage]:
    """A system prompt and one user message."""
    return [
        LLMMessage(role="system", content="You are admino."),
        LLMMessage(role="user", content="Please answer"),
    ]


@dataclass
class _Run:
    """What one call handed to its caller, and how long it took."""

    texts: list[str] = field(default_factory=list)
    finals: list[LLMResponse] = field(default_factory=list)
    error: LLMError | None = None
    crash: str | None = None
    elapsed: float = 0.0


async def _run(client: Any, path: str, *, bound: float = 10.0) -> _Run:
    """Call ``chat()`` or drain ``chat_stream()`` within ``bound`` seconds.

    A non-LLMError is kept by its type name only; a call still running at
    ``bound`` is cancelled and reported as hung.
    """
    run = _Run()
    loop = asyncio.get_running_loop()
    start = loop.time()

    async def drive() -> None:
        try:
            if path == "chat":
                run.finals.append(await client.chat(_messages(), [_MEMORY_TOOL]))
            else:
                async for item in client.chat_stream(_messages(), [_MEMORY_TOOL]):
                    if isinstance(item, LLMStreamDelta):
                        run.texts.append(item.content)
                    else:
                        run.finals.append(item)
        except LLMError as exc:
            run.error = exc
        except Exception as exc:  # a raw exception reached the caller: kept by type only
            run.crash = type(exc).__name__

    try:
        await asyncio.wait_for(drive(), bound)
    except TimeoutError:
        run.crash = f"hung for {bound} s"
    run.elapsed = loop.time() - start
    return run


def _shape(error: LLMError) -> tuple[Any, ...]:
    """The comparable parts of an LLMError."""
    return (
        type(error).__name__,
        error.code,
        error.message,
        error.status_code,
        error.retry_after_s,
        error.user_facing,
        error.retryable,
    )


def _verdict(run: _Run, path: str) -> dict[str, Any]:
    """Streamed text, the finals' tool calls, and the error (or the raw exception's type)."""
    return {
        "streamed": "".join(run.texts) if path == "stream" else None,
        "finals": [[f"{c.tool}.{c.action}" for c in final.tool_calls] for final in run.finals],
        "error": _shape(run.error) if run.error is not None else run.crash,
    }


def _accepted(path: str, *calls: str) -> dict[str, Any]:
    """The verdict of a reply accepted with ``calls``."""
    return {"streamed": _TEXT if path == "stream" else None, "finals": [list(calls)], "error": None}


def _rejected(provider: str, path: str) -> dict[str, Any]:
    """The verdict of a reply rejected with ``malformed_response``."""
    return {
        "streamed": _TEXT if path == "stream" else None,
        "finals": [],
        "error": (
            "LLMError",
            "malformed_response",
            f"{_LABELS[provider]} returned a malformed response. Please try again.",
            None,
            None,
            True,
            False,
        ),
    }


async def _judge(client: Any, wire: _Wire, path: str, route: _Route) -> dict[str, Any]:
    """Answer one call on ``path`` with ``route`` and return its verdict."""
    wire.post = route
    return _verdict(await _run(client, path), path)


# ===========================================================================
# P38: a repeated Anthropic tool_use index in a stream
# ===========================================================================


async def test_llm_guard_anthropic_stream_repeated_tool_use_index_rejected(
    wire: _Wire, build: Callable[..., Any]
) -> None:
    """A second tool_use ``content_block_start`` at index 1 rejects the reply (P38).

    The same two blocks at indexes 1 and 2 are both returned, in index order.
    """
    client = build("anthropic")
    verdicts = {}
    for case, second_index in (("distinct-indexes", 2), ("repeated-index", 1)):
        frames = [
            _a_start(),
            *_a_text_block(),
            *_a_tool_block(1, "toolu_1", "memory__store", _FIRST_ARGS),
            *_a_tool_block(second_index, "toolu_2", "memory__recall", _SECOND_ARGS),
            *_a_end(),
        ]
        verdicts[case] = await _judge(client, wire, "stream", _sse_route(frames))
    assert verdicts == {
        "distinct-indexes": _accepted("stream", "memory.store", "memory.recall"),
        "repeated-index": _rejected("anthropic", "stream"),
    }


# ===========================================================================
# P40: a bool tool-call index
# ===========================================================================


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_guard_stream_bool_tool_call_index_rejected(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """A JSON ``true`` as a fragment's ``index`` rejects the reply; index 0 is accepted (P40).

    The fragment's ``type`` is one the SDK can't validate, so the SDK hands the
    client the fragment as sent (``True``, not the ``1`` its validation makes).
    """
    client = build(provider)
    verdicts = {}
    for case, index in (("int-index", 0), ("bool-index", True)):
        fragment = {
            "index": index,
            "id": "call_0",
            "type": _UNVALIDATED_TYPE,
            "function": {"name": "memory.store", "arguments": _FIRST_ARGS},
        }
        chunks = [
            _chunk({"content": _TEXT}),
            _chunk({"tool_calls": [fragment]}),
            _chunk({}, finish_reason="tool_calls"),
        ]
        verdicts[case] = await _judge(client, wire, "stream", _sse_route(_oa_frames(chunks)))
    assert verdicts == {
        "int-index": _accepted("stream", "memory.store"),
        "bool-index": _rejected(provider, "stream"),
    }


async def test_llm_guard_anthropic_stream_bool_tool_use_index_rejected(
    wire: _Wire, build: Callable[..., Any]
) -> None:
    """A JSON ``true`` as a tool_use block's start index rejects the reply; 1 is accepted.

    The start block's ``input`` (never read: the arguments come from
    ``input_json_delta``) is one the SDK can't validate, so the SDK keeps ``true``.
    """
    client = build("anthropic")
    verdicts = {}
    for case, index in (("int-index", 1), ("bool-index", True)):
        block = {"type": "tool_use", "id": "toolu_1", "name": "memory__store", "input": "later"}
        frames = [
            _a_start(),
            *_a_text_block(),
            _a_block_start(index, block),
            _a_delta(1, {"type": "input_json_delta", "partial_json": _FIRST_ARGS}),
            _a_block_stop(1),
            *_a_end(),
        ]
        verdicts[case] = await _judge(client, wire, "stream", _sse_route(frames))
    assert verdicts == {
        "int-index": _accepted("stream", "memory.store"),
        "bool-index": _rejected("anthropic", "stream"),
    }


# ===========================================================================
# tool_calls / choices present but not a list
# ===========================================================================

# A truthy non-list ``tool_calls``: one call object instead of a list, a number.
_TOOL_CALLS_NOT_LISTS: Final[dict[str, Any]] = {
    "object": {
        "index": 0,
        "id": "call_0",
        "type": "function",
        "function": {"name": "memory.store", "arguments": _FIRST_ARGS},
    },
    "number": 7,
}
# A truthy non-list ``choices``: one choice object instead of a list, a string.
_STREAM_CHOICES_NOT_LISTS: Final[dict[str, Any]] = {
    "object": {"index": 0, "delta": {"content": "more "}, "finish_reason": None},
    "text": "abc",
}
_CHAT_CHOICES_NOT_LISTS: Final[dict[str, Any]] = {
    "object": {
        "index": 0,
        "message": {"role": "assistant", "content": _TEXT},
        "finish_reason": "stop",
    },
    "text": "abc",
}


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_guard_stream_tool_calls_not_a_list_rejected(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """A chunk whose ``delta.tool_calls`` is an object or a number rejects the reply."""
    client = build(provider)
    verdicts = {}
    for shape, tool_calls in _TOOL_CALLS_NOT_LISTS.items():
        chunks = [
            _chunk({"content": _TEXT}),
            _chunk({"tool_calls": tool_calls}),
            _chunk({}, finish_reason="tool_calls"),
        ]
        verdicts[shape] = await _judge(client, wire, "stream", _sse_route(_oa_frames(chunks)))
    assert verdicts == dict.fromkeys(_TOOL_CALLS_NOT_LISTS, _rejected(provider, "stream"))


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_guard_stream_choices_not_a_list_rejected(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """A chunk whose ``choices`` is an object or a string rejects the reply."""
    client = build(provider)
    verdicts = {}
    for shape, choices in _STREAM_CHOICES_NOT_LISTS.items():
        bad = _chunk()
        bad["choices"] = choices
        chunks = [_chunk({"content": _TEXT}), bad, _chunk({}, finish_reason="stop")]
        verdicts[shape] = await _judge(client, wire, "stream", _sse_route(_oa_frames(chunks)))
    assert verdicts == dict.fromkeys(_STREAM_CHOICES_NOT_LISTS, _rejected(provider, "stream"))


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_guard_chat_tool_calls_not_a_list_rejected(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """chat(): a ``message.tool_calls`` that is an object or a number rejects the reply.

    A valid list with the same call is accepted.
    """
    client = build(provider)
    shapes: dict[str, Any] = {"list": [_oa_tool_call()], **_TOOL_CALLS_NOT_LISTS}
    verdicts = {}
    for shape, tool_calls in shapes.items():
        message = {"role": "assistant", "content": _TEXT, "tool_calls": tool_calls}
        verdicts[shape] = await _judge(client, wire, "chat", _json_route(_completion(message)))
    assert verdicts == {
        "list": _accepted("chat", "memory.store"),
        **dict.fromkeys(_TOOL_CALLS_NOT_LISTS, _rejected(provider, "chat")),
    }


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_guard_chat_choices_not_a_list_rejected(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """chat(): a ``choices`` that is an object or a string rejects the reply."""
    client = build(provider)
    verdicts = {}
    for shape, choices in _CHAT_CHOICES_NOT_LISTS.items():
        body = _completion({}, choices=choices)
        verdicts[shape] = await _judge(client, wire, "chat", _json_route(body))
    assert verdicts == dict.fromkeys(_CHAT_CHOICES_NOT_LISTS, _rejected(provider, "chat"))


# ===========================================================================
# P35: the Infomaniak think filter's truncation flag
# ===========================================================================


def _runs(text: str) -> list[tuple[str, int]]:
    """``text`` as (character, run length) pairs (readable for 90k-character texts)."""
    runs: list[tuple[str, int]] = []
    for char in text:
        if runs and runs[-1][0] == char:
            runs[-1] = (char, runs[-1][1] + 1)
        else:
            runs.append((char, 1))
    return runs


async def test_llm_guard_infomaniak_orphan_close_past_delta_budget_flags_truncated(
    wire: _Wire, build: Callable[..., Any]
) -> None:
    """Orphan ``</think>`` tags reset the answer, not the delta budget: truncated (P35).

    Three 30000-letter texts, the second and third each after an orphan
    ``</think>``: the deltas stop at 65536 characters, the final answer is the
    last text (30000, within the answer cap), and the final response is
    truncated. Three 20000-letter texts (within the budget) are not.
    """
    client = build("infomaniak")
    verdicts = {}
    for case, size in (("past-budget", 30000), ("within-budget", 20000)):
        pieces = ["a" * size, _THINK_CLOSE + "b" * size, _THINK_CLOSE + "c" * size]
        chunks = [*(_chunk({"content": p}) for p in pieces), _chunk({}, finish_reason="stop")]
        wire.post = _sse_route(_oa_frames(chunks))
        run = await _run(client, "stream")
        final = run.finals[-1] if run.finals else None
        verdicts[case] = (
            _runs("".join(run.texts)),
            _runs(final.content) if final is not None else None,
            final.truncated if final is not None else None,
            run.error,
            run.crash,
        )
    assert verdicts == {
        "past-budget": (
            [("a", 30000), ("b", 30000), ("c", _MAX_CONTENT - 60000)],
            [("c", 30000)],
            True,
            None,
            None,
        ),
        "within-budget": (
            [("a", 20000), ("b", 20000), ("c", 20000)],
            [("c", 20000)],
            False,
            None,
            None,
        ),
    }


# ===========================================================================
# P27: product-ID discovery counts against llm.stream_deadline_s
# ===========================================================================

_TIMEOUT_SHAPE: Final[tuple[Any, ...]] = (
    "LLMError",
    "timeout",
    "Infomaniak is temporarily unavailable (the request timed out). Please try again in a moment.",
    None,
    None,
    True,
    True,
)


@pytest.mark.parametrize("discovery", ["never-answers", "answers-after-deadline"])
async def test_llm_guard_infomaniak_discovery_counts_against_stream_deadline(
    discovery: str,
    wire: _Wire,
    build: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No INFOMANIAK_PRODUCT_ID and a discovery that waits: ``timeout`` at the deadline (P27).

    The discovery GET never answers, or would answer (one product) only after
    1.5 s. The stream fails with the ``timeout`` error no earlier than its 0.3 s
    deadline and well before 1.2 s (discovery's own timeout is 10 s); the
    discovery request was cancelled, never answered, and no chat request was sent.
    """
    monkeypatch.delenv("INFOMANIAK_PRODUCT_ID", raising=False)
    client = build("infomaniak", deadline=_DEADLINE)
    delay = None if discovery == "never-answers" else _LATE_DISCOVERY
    products = {"result": "success", "data": [{"product_id": int(_IK_PRODUCT_ID)}]}
    wire.get = discovery_route = _DelayedRoute(delay, then=_json_route(products))
    reply = [_chunk({"content": "late "}), _chunk({}, finish_reason="stop")]
    wire.post = _sse_route(_oa_frames(reply))
    run = await _run(client, "stream", bound=_HUNG)
    assert (
        run.texts,
        run.finals,
        _shape(run.error) if run.error is not None else run.crash,
        (run.error.__cause__, run.error.__suppress_context__) if run.error else None,
        (discovery_route.cancelled, discovery_route.answered),
        wire.requests,
        _FLOOR <= run.elapsed < _AT_DEADLINE,
    ) == ([], [], _TIMEOUT_SHAPE, (None, True), (True, False), ["GET:/1/ai"], True), run.elapsed
