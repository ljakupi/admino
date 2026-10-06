"""Malformed LLM replies are rejected loudly with ``malformed_response`` (GH-25: D1, D2, D3).

Every client (Infomaniak, vLLM, OpenAI, Anthropic) is built from a real
``LLMConfig`` and drives its REAL SDK (``openai`` for the OpenAI-compatible
three, ``anthropic`` for Claude) against a fake wire: ``httpx.AsyncClient.send``
is replaced by a scripted route answering a JSON body for ``chat()`` or an SSE
body for ``chat_stream()`` (optionally breaking with an httpx error after its
frames). Nothing reaches a real host.

What these tests pin (contract C1, C2, C3.3, C3.4, C3.5, C4):

- The code (D1, C1/C2): ``LLMErrorCode`` / ``LLM_ERROR_CODES`` hold eight codes,
  ``malformed_response`` last; ``StreamErrorCode`` (the stream's ``error``
  event), ``ChatResponse.error_code`` and ``AgentResult.error_code`` accept it.
  ``admino.llm.malformed_response_error(label)`` is exactly C2's error: message
  ``"<label> returned a malformed response. Please try again."``, code
  ``malformed_response``, no status, no Retry-After, user-facing, not
  retryable; the retryable set stays provider_unavailable / rate_limited /
  timeout.
- Malformed tool calls (D2, C3.3), for every provider in ``chat()`` AND
  ``chat_stream()``: one invalid call between two valid ones rejects the whole
  reply. Invalid means arguments that are invalid JSON, nested deep enough for
  ``json.loads`` to raise ``RecursionError``, hold an integer over 4300 digits
  (``ValueError``), are a JSON array / string / number, nest 5 deep, have 33
  keys, a 2049-character top-level string or more than 16384 characters of
  JSON; a missing or empty name, one without a dot, ``Gmail.Read`` and
  ``gmail.``; the OpenAI-compatible ``chat()`` entry without ``function``.
  Streams only: name fragments crossing 256 characters, argument fragments
  crossing 65536 (Anthropic too: never parsed from a cut prefix), a 129th
  tool-call index / tool_use block; each next to its exact-bound reply, which is
  still kept.
- Undecodable or wrong-typed data (D3, C3.4): a ``chat()`` 200 body that is
  nested too deep, holds an int over 4300 digits or isn't JSON (the SDKs raise
  ``RecursionError`` / ``ValueError`` raw today); a stream line that isn't JSON,
  is too deep or holds such an int; a tool-call ``index`` of ``"a"`` or ``[1]``
  (Anthropic: on the tool_use start or on its JSON delta); a
  non-str content / text / name / arguments / partial_json / model / id;
  ``httpx.DecodingError`` raised mid-stream from the body.
- Other failures (C3.5): ``httpx.StreamError`` mid-stream is each client's
  ``provider_unavailable`` (the error ``chat()`` gives for a connection
  failure); an Infomaniak mid-stream ``event: error`` is ``provider_unavailable``,
  no longer the uncoded "unexpected error".
- Every error above: an ``LLMError`` (never a raw exception, never a returned or
  yielded ``LLMResponse``), raised ``from None`` (``__cause__`` None,
  ``__suppress_context__`` True), after exactly one request; no marker planted
  in the arguments, the answer text, the body or the stream line reaches
  ``str``, ``repr``, ``message`` or ``args`` of the error, or any log record at
  any level (DEBUG captured for admino, the SDKs and httpx). In a stream, the
  text sent before the bad part reached the consumer.
- Policy (C4): ``llm_policy.chat`` / ``llm_policy.chat_stream`` with
  ``max_retries=2`` over the real clients never retry ``malformed_response``:
  one request, no sleep.

Not covered here: the parsers' own drop-and-log behaviour (unchanged, pinned in
the per-provider test files), argument cleaning (``sanitize_tool_args``), cut
answers and the stream deadline (other GH-25 files).

Contract gaps (resolved, flagged in the hand-back): both SDKs coerce a JSON
``true`` tool-call / event index to ``1`` before the client sees it, so a
boolean index can't be sent over the wire and isn't pinned here; a non-str
tool-call id in ``chat()`` and an Anthropic name over 256 characters are left
open.

Security notes:
- Keys are built at runtime (``tests.credential_keys``); no key literal here.
- The SDKs' retry sleep and the policy's ``_sleep`` are no-ops, so a client or
  policy that still retries fails fast (and visibly, by its request count).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, get_args

import anthropic._base_client as anthropic_base_client
import httpx
import openai._base_client as openai_base_client
import pytest
from pydantic import TypeAdapter, ValidationError

import admino.llm as llm_mod
from admino import llm_policy, models
from admino.config import LLMConfig
from admino.llm import LLMError, LLMResponse, LLMStreamDelta
from admino.llm_anthropic import AnthropicClient
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

OPENAI_COMPATIBLE: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak")
ALL_PROVIDERS: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak", "anthropic")
PATHS: Final[tuple[str, ...]] = ("chat", "stream")

# Provider labels of the user-facing messages (contract C3).
_LABELS: Final[dict[str, str]] = {
    "openai": "OpenAI",
    "vllm": "vLLM",
    "infomaniak": "Infomaniak",
    "anthropic": "Claude",
}

_MAX_TOKENS: Final = 777
_IK_PRODUCT_ID: Final = "7539"
_STREAM_MODEL: Final = "wire-w2-model"
_NAME_BUDGET: Final = 256
_ARG_BUDGET: Final = 65536
_MAX_CALLS: Final = 128
# Deep enough for json.loads to raise RecursionError, short enough (2 x 30000 brackets)
# to stay inside the 65536-character argument bound of a stream.
_DEEP: Final = 30000
_DEEP_BODY: Final = 100_000

_OPENAI_KEY: Final = api_key("sk-", 48, seed=2501).text
_ANTHROPIC_KEY: Final = api_key("sk-" + "ant-", 48, seed=2502).text
_IK_TOKEN: Final = api_key("ik-", 40, seed=2503).text

# Markers: none may reach an LLMError or a log record.
_ARG_MARK: Final = "ARGMARK-w2-6c1d"  # the malformed call's arguments
_NEIGHBOUR_MARK: Final = "NBRMARK-w2-0f9e"  # the valid calls' arguments
_TEXT_MARK: Final = "TXTMARK-w2-a7b3"  # the answer text sent before the tool calls
_BODY_MARK: Final = "BODYMARK-w2-3e58"  # an undecodable body or stream line
_WIRE_MARK: Final = "WIREMARK-w2-91d2"  # a mid-stream httpx error's message
_MARKERS: Final[tuple[str, ...]] = (_ARG_MARK, _NEIGHBOUR_MARK, _TEXT_MARK, _BODY_MARK, _WIRE_MARK)

# The answer text every reply sends before its tool calls (ends with a space, so no
# filter holds part of it back).
_TEXT: Final = f"Checking {_TEXT_MARK} "

_RETRYABLE: Final = frozenset({"provider_unavailable", "rate_limited", "timeout"})

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
# Tool calls as a provider sends them
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Call:
    """One tool call: its dotted name (None: no name field at all) and its JSON text."""

    name: str | None
    arguments: str


_FIRST: Final = _Call("memory.store", json.dumps({"key": _NEIGHBOUR_MARK}))
_LAST: Final = _Call("memory.recall", json.dumps({"key": _NEIGHBOUR_MARK, "value": "v"}))


def _nested(levels: int) -> dict[str, Any]:
    """``levels`` nested dicts around a marker leaf."""
    value: dict[str, Any] = {"leaf": _ARG_MARK}
    for _ in range(levels - 1):
        value = {"nested": value}
    return value


# Arguments that can't become a valid tool call (the name is valid).
_BAD_ARGUMENTS: Final[dict[str, str]] = {
    "invalid-json": '{"key": "' + _ARG_MARK,
    "recursion-error": "[" * _DEEP + json.dumps(_ARG_MARK) + "]" * _DEEP,
    "int-over-4300-digits": '{"key": "' + _ARG_MARK + '", "n": ' + "7" * 5000 + "}",
    "json-array": json.dumps([_ARG_MARK, 2]),
    "json-string": json.dumps(_ARG_MARK),
    "json-number": "4" * 18,
    "depth-5": json.dumps(_nested(5)),
    "33-keys": json.dumps({f"k{i}": _ARG_MARK for i in range(33)}),
    "2049-char-string": json.dumps({"key": _ARG_MARK.ljust(2049, "x")}),
    "json-over-16384": json.dumps({f"k{i}": _ARG_MARK.ljust(1000, "x") for i in range(20)}),
}

# Names that aren't ``tool.action`` with two valid identifiers (the arguments are valid).
_BAD_NAMES: Final[dict[str, str | None]] = {
    "missing-name": None,
    "empty-name": "",
    "no-dot": "memorystore",
    "Gmail.Read": "Gmail.Read",
    "empty-action": "gmail.",
}

_BAD_CALLS: Final[dict[str, _Call]] = {
    **{kind: _Call("memory.store", text) for kind, text in _BAD_ARGUMENTS.items()},
    **{kind: _Call(name, json.dumps({"key": _ARG_MARK})) for kind, name in _BAD_NAMES.items()},
}

# ---------------------------------------------------------------------------
# OpenAI-compatible bodies and chunks
# ---------------------------------------------------------------------------


def _oa_tool_call(index: int, call: _Call) -> dict[str, Any]:
    """One ``message.tool_calls`` entry of a ``chat.completion``."""
    function: dict[str, Any] = {"arguments": call.arguments}
    if call.name is not None:
        function["name"] = call.name
    return {"id": f"call_{index}", "type": "function", "function": function}


def _oa_completion(
    *,
    content: Any = _TEXT,
    tool_calls: list[Any] | None = None,
    model: Any = _STREAM_MODEL,
    finish_reason: str = "tool_calls",
) -> dict[str, Any]:
    """A ``chat.completion`` body (for ``chat()``)."""
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-w2-json",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
    }


def _chunk(
    delta: dict[str, Any] | None = None,
    *,
    finish_reason: str | None = None,
    model: Any = _STREAM_MODEL,
) -> dict[str, Any]:
    """One ``chat.completion.chunk``."""
    return {
        "id": "chatcmpl-w2-stream",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": model,
        "choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}],
    }


def _frag(
    index: Any,
    *,
    call_id: Any = None,
    name: Any = None,
    arguments: Any = None,
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


def _oa_call_chunks(index: int, call: _Call) -> list[dict[str, Any]]:
    """One call as two chunks: id + name + first half of the arguments, then the rest."""
    half = len(call.arguments) // 2
    return [
        _tools_chunk(
            _frag(index, call_id=f"call_{index}", name=call.name, arguments=call.arguments[:half])
        ),
        _tools_chunk(_frag(index, arguments=call.arguments[half:])),
    ]


def _oa_frames(chunks: list[dict[str, Any]], *, done: bool = True) -> list[bytes]:
    """``data: <chunk>`` lines, then ``data: [DONE]`` when ``done``."""
    frames = [f"data: {json.dumps(chunk)}\n\n".encode() for chunk in chunks]
    if done:
        frames.append(b"data: [DONE]\n\n")
    return frames


def _oa_stream(calls: list[_Call], *, text: str | None = _TEXT) -> list[bytes]:
    """A stream: the answer text, then each call split in two chunks, then ``tool_calls``."""
    chunks = [_chunk({"content": text})] if text else []
    for index, call in enumerate(calls):
        chunks += _oa_call_chunks(index, call)
    chunks.append(_chunk({}, finish_reason="tool_calls"))
    return _oa_frames(chunks)


# ---------------------------------------------------------------------------
# Anthropic bodies and frames
# ---------------------------------------------------------------------------


def _a_name(name: str | None) -> str | None:
    """The admino dotted name in Anthropic's ``tool__action`` encoding."""
    return None if name is None else name.replace(".", "__")


def _a_message(
    content: list[Any], *, model: Any = _STREAM_MODEL, stop_reason: str = "tool_use"
) -> dict[str, Any]:
    """A non-streamed Anthropic ``message`` body."""
    return {
        "id": "msg_w2_json",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


def _a_message_bytes(calls: list[_Call], *, text: str | None = _TEXT) -> bytes:
    """A ``message`` body whose tool_use inputs are each call's JSON text, spliced verbatim."""
    content: list[Any] = [{"type": "text", "text": text}] if text else []
    for index, call in enumerate(calls, start=1):
        block: dict[str, Any] = {"type": "tool_use", "id": f"toolu_{index}"}
        if call.name is not None:
            block["name"] = _a_name(call.name)
        block["input"] = f"@@INPUT-{index}@@"
        content.append(block)
    raw = json.dumps(_a_message(content))
    for index, call in enumerate(calls, start=1):
        raw = raw.replace(json.dumps(f"@@INPUT-{index}@@"), call.arguments)
    return raw.encode()


def _frame(event: str, data: Any) -> bytes:
    """One Anthropic Messages SSE frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _a_start(model: Any = _STREAM_MODEL) -> bytes:
    """The ``message_start`` frame."""
    return _frame(
        "message_start",
        {
            "type": "message_start",
            "message": {
                "id": "msg_w2_01",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 10, "output_tokens": 1},
            },
        },
    )


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


def _a_text_block(index: int, text: Any) -> list[bytes]:
    """A whole text block with one ``text_delta``."""
    return [
        _a_block_start(index, {"type": "text", "text": ""}),
        _a_delta(index, {"type": "text_delta", "text": text}),
        _a_block_stop(index),
    ]


def _a_tool_use(tool_id: Any, name: Any) -> dict[str, Any]:
    """A ``tool_use`` content block as ``content_block_start`` carries it."""
    block: dict[str, Any] = {"type": "tool_use", "id": tool_id, "input": {}}
    if name is not None:
        block["name"] = name
    return block


def _a_tool_block(index: Any, name: Any, tool_id: Any, *fragments: Any) -> list[bytes]:
    """A whole tool_use block: start, one ``input_json_delta`` per fragment, stop."""
    return [
        _a_block_start(index, _a_tool_use(tool_id, name)),
        *(_a_delta(index, {"type": "input_json_delta", "partial_json": f}) for f in fragments),
        _a_block_stop(index),
    ]


def _a_end(stop_reason: str = "tool_use") -> list[bytes]:
    """``message_delta`` with the stop reason, then ``message_stop``."""
    return [
        _frame(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": stop_reason, "stop_sequence": None},
                "usage": {"output_tokens": 15},
            },
        ),
        _frame("message_stop", {"type": "message_stop"}),
    ]


def _a_stream(calls: list[_Call], *, text: str | None = _TEXT) -> list[bytes]:
    """A stream: the answer text block, then one tool_use block per call (JSON split in two)."""
    frames = [_a_start()]
    if text:
        frames += _a_text_block(0, text)
    for index, call in enumerate(calls, start=1):
        half = len(call.arguments) // 2
        frames += _a_tool_block(
            index,
            _a_name(call.name),
            f"toolu_{index}",
            call.arguments[:half],
            call.arguments[half:],
        )
    return frames + _a_end()


# ---------------------------------------------------------------------------
# The fake wire
# ---------------------------------------------------------------------------


class _Body(httpx.AsyncByteStream):
    """A response body yielding ``frames`` one by one, then raising ``failure(request)``."""

    def __init__(
        self,
        frames: list[bytes],
        request: httpx.Request,
        failure: Callable[[httpx.Request], Exception] | None,
    ) -> None:
        self._frames = frames
        self._request = request
        self._failure = failure

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield each frame, then raise the scripted failure (if any)."""
        for frame in self._frames:
            yield frame
        if self._failure is not None:
            raise self._failure(self._request)

    async def aclose(self) -> None:
        """Nothing to release."""


def _sse_route(
    frames: list[bytes], failure: Callable[[httpx.Request], Exception] | None = None
) -> Callable[[httpx.Request], httpx.Response]:
    """A route answering a streamed SSE body (the same frames on every request)."""

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_Body(frames, request, failure),
            request=request,
        )

    return route


def _raw_route(content: bytes) -> Callable[[httpx.Request], httpx.Response]:
    """A route answering ``content`` as a 200 JSON body (sent verbatim)."""

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "application/json"}, content=content, request=request
        )

    return route


def _json_route(body: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """A route answering ``body`` as JSON."""
    return _raw_route(json.dumps(body).encode())


def _connect_error_route() -> Callable[[httpx.Request], httpx.Response]:
    """A route failing at send time with a connection error (no marker)."""

    def route(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    return route


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    Each POST gets ``self.route``; anything else (or a POST without a route) gets
    a 404, so an unexpected request is visible.
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


@pytest.fixture()
def debug_logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """Capture every log record at DEBUG (root, admino, both SDKs, httpx)."""
    caplog.set_level(logging.DEBUG)
    for name in ("admino", "openai", "anthropic", "httpx", "httpcore"):
        caplog.set_level(logging.DEBUG, logger=name)
    return caplog


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


@pytest.fixture()
def policy_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the policy's retry sleeps instead of sleeping."""
    sleeps: list[float] = []

    async def record(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(llm_policy, "_sleep", record)
    return sleeps


# ---------------------------------------------------------------------------
# Running a call and judging what reached the caller
# ---------------------------------------------------------------------------


def _messages() -> list[LLMMessage]:
    """A system prompt and one user message (no marker)."""
    return [
        LLMMessage(role="system", content="You are admino."),
        LLMMessage(role="user", content="Please answer"),
    ]


@dataclass
class _Run:
    """What one call handed to its caller."""

    texts: list[str]
    finals: list[LLMResponse]
    error: LLMError | None
    crash: str | None


async def _run(client: Any, path: str) -> _Run:
    """Call ``chat()`` or drain ``chat_stream()``; a non-LLMError is kept by type name only."""
    run = _Run(texts=[], finals=[], error=None, crash=None)
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
    except Exception as exc:  # a pre-implementation crash, reported by type only
        run.crash = type(exc).__name__
    return run


def _shape(error: LLMError) -> tuple[Any, ...]:
    """The comparable parts of an LLMError (type, code, message, status, retry, flags)."""
    return (
        type(error).__name__,
        getattr(error, "code", "<no code>"),
        error.message,
        error.status_code,
        getattr(error, "retry_after_s", "<no retry_after_s>"),
        error.user_facing,
        getattr(error, "retryable", "<no retryable>"),
    )


def _malformed_shape(provider: str) -> tuple[Any, ...]:
    """The literal C2 ``malformed_response_error(label)`` shape for ``provider``."""
    return (
        "LLMError",
        "malformed_response",
        f"{_LABELS[provider]} returned a malformed response. Please try again.",
        None,
        None,
        True,
        False,
    )


def _leak_sites(error: LLMError | None, logs: pytest.LogCaptureFixture) -> list[str]:
    """Every ``marker@site`` where a planted marker shows up in the error or the logs."""
    sites: dict[str, str] = {
        "logs": logs.text + "\n".join(record.getMessage() for record in logs.records)
    }
    if error is not None:
        sites |= {
            "str": str(error),
            "repr": repr(error),
            "message": error.message,
            "args": repr(error.args),
        }
    return sorted(
        f"{marker}@{site}" for marker in _MARKERS for site, text in sites.items() if marker in text
    )


def _verdict(run: _Run, path: str, logs: pytest.LogCaptureFixture, wire: _Wire) -> dict[str, Any]:
    """What the caller got: streamed text, finals, error shape and chaining, leaks, requests."""
    error = run.error
    return {
        "streamed": "".join(run.texts) if path == "stream" else None,
        "finals": [f"LLMResponse with {len(f.tool_calls)} tool calls" for f in run.finals],
        "error": _shape(error) if error is not None else run.crash,
        "chained": None if error is None else (error.__cause__, error.__suppress_context__),
        "leaks": _leak_sites(error, logs),
        "requests": len(wire.requests),
    }


def _rejected(provider: str, path: str, *, streamed: str = _TEXT) -> dict[str, Any]:
    """The verdict of a reply rejected with ``malformed_response``."""
    return {
        "streamed": streamed if path == "stream" else None,
        "finals": [],
        "error": _malformed_shape(provider),
        "chained": (None, True),
        "leaks": [],
        "requests": 1,
    }


async def _judge(
    provider: str,
    path: str,
    route: Callable[[httpx.Request], httpx.Response],
    wire: _Wire,
    build: Callable[[str], Any],
    logs: pytest.LogCaptureFixture,
) -> dict[str, Any]:
    """Answer one call of ``provider`` on ``path`` with ``route`` and return its verdict."""
    wire.route = route
    run = await _run(build(provider), path)
    return _verdict(run, path, logs, wire)


def _tool_reply(
    provider: str, path: str, calls: list[_Call], *, text: str | None = _TEXT
) -> Callable[[httpx.Request], httpx.Response]:
    """The route answering ``calls`` (after ``text``) in ``provider``'s format for ``path``."""
    if provider == "anthropic":
        if path == "chat":
            return _raw_route(_a_message_bytes(calls, text=text))
        return _sse_route(_a_stream(calls, text=text))
    if path == "chat":
        tool_calls = [_oa_tool_call(index, call) for index, call in enumerate(calls)]
        return _json_route(_oa_completion(content=text, tool_calls=tool_calls))
    return _sse_route(_oa_stream(calls, text=text))


def _calls(final: LLMResponse) -> list[tuple[str, str, dict[str, Any], str | None]]:
    """The final response's tool calls as (tool, action, args, id) tuples."""
    return [(c.tool, c.action, c.args, c.tool_call_id) for c in final.tool_calls]


def _kept(run: _Run) -> Any:
    """The tool calls of a run's single final response, or what went wrong."""
    if run.error is not None:
        return ("error", getattr(run.error, "code", None))
    if run.crash is not None or len(run.finals) != 1:
        return ("no single final", run.crash, len(run.finals))
    return _calls(run.finals[0])


def _ids(provider_path: list[tuple[str, str]]) -> list[str]:
    """Space-free ids for (provider, path) pairs."""
    return [f"{provider}-{path}" for provider, path in provider_path]


_PROVIDER_PATHS: Final[list[tuple[str, str]]] = [(p, path) for p in ALL_PROVIDERS for path in PATHS]

# ===========================================================================
# 1. The code (D1; C1, C2)
# ===========================================================================


def test_llm_malformed_code_is_the_eighth_and_last_llm_error_code() -> None:
    """LLMErrorCode gains malformed_response as its last member; LLM_ERROR_CODES follows."""
    alias = models.LLMErrorCode
    codes = get_args(getattr(alias, "__value__", alias))
    assert (len(codes), codes[-1], frozenset(codes) == models.LLM_ERROR_CODES) == (
        8,
        "malformed_response",
        True,
    )


def _accepts(site: str) -> object:
    """Validate ``malformed_response`` at ``site``; return the stored value or "refused"."""
    try:
        if site == "StreamErrorCode":
            return models.ErrorPayload(code="malformed_response", message="x").code
        if site == "ChatResponse.error_code":
            annotation = models.ChatResponse.model_fields["error_code"].annotation
            return TypeAdapter(annotation).validate_python("malformed_response")
        return models.AgentResult(
            status="error", response="x", error_code="malformed_response"
        ).error_code
    except ValidationError:
        return "refused"


def test_llm_malformed_code_accepted_by_stream_chat_response_and_agent_result() -> None:
    """The stream's error event, the JSON route's error_code and the run's result carry it."""
    sites = ("StreamErrorCode", "ChatResponse.error_code", "AgentResult.error_code")
    assert {site: _accepts(site) for site in sites} == dict.fromkeys(sites, "malformed_response")


@pytest.mark.parametrize("label", [*_LABELS.values(), "Acme"])
def test_llm_malformed_response_error_matches_contract(label: str) -> None:
    """Fixed message naming the provider, the code, no status, user-facing, not retryable."""
    factory = getattr(llm_mod, "malformed_response_error", None)
    assert factory is not None, "admino.llm.malformed_response_error is missing"
    error = factory(label)
    assert (_shape(error), llm_mod._RETRYABLE_CODES) == (
        (
            "LLMError",
            "malformed_response",
            f"{label} returned a malformed response. Please try again.",
            None,
            None,
            True,
            False,
        ),
        _RETRYABLE,
    )


# ===========================================================================
# 2. Malformed tool calls reject the whole reply (D2; C3.3)
# ===========================================================================


@pytest.mark.parametrize("kind", list(_BAD_CALLS))
@pytest.mark.parametrize(("provider", "path"), _PROVIDER_PATHS, ids=_ids(_PROVIDER_PATHS))
async def test_llm_malformed_tool_call_between_valid_ones_rejects_reply(
    provider: str,
    path: str,
    kind: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """One invalid call between two valid ones: malformed_response, nothing returned."""
    route = _tool_reply(provider, path, [_FIRST, _BAD_CALLS[kind], _LAST])
    assert await _judge(provider, path, route, wire, build, debug_logs) == _rejected(provider, path)


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_malformed_chat_tool_call_without_function_rejects_reply(
    provider: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """A ``message.tool_calls`` entry without ``function`` counts as a sent, invalid call."""
    tool_calls = [
        _oa_tool_call(0, _FIRST),
        {"id": "call_1", "type": "function"},
        _oa_tool_call(2, _LAST),
    ]
    route = _json_route(_oa_completion(tool_calls=tool_calls))
    assert await _judge(provider, "chat", route, wire, build, debug_logs) == _rejected(
        provider, "chat"
    )


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_malformed_stream_name_fragments_crossing_256_reject_reply(
    provider: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """Name fragments of exactly 256 characters still parse; one more character rejects."""
    pad = "e" * (_NAME_BUDGET - len("memory.store"))
    head = [
        _chunk({"content": _TEXT}),
        _tools_chunk(_frag(0, call_id="call_0", name="memory.store", arguments=_FIRST.arguments)),
        _tools_chunk(_frag(0, name=pad)),
    ]
    client = build(provider)
    wire.route = _sse_route(_oa_frames([*head, _chunk({}, finish_reason="tool_calls")]))
    exact = _kept(await _run(client, "stream"))
    wire.requests.clear()
    debug_logs.clear()
    crossing = [*head, _tools_chunk(_frag(0, name="e")), _chunk({}, finish_reason="tool_calls")]
    wire.route = _sse_route(_oa_frames(crossing))
    verdict = _verdict(await _run(client, "stream"), "stream", debug_logs, wire)
    assert (exact, verdict) == (
        [("memory", "store" + "e" * 52, {"key": _NEIGHBOUR_MARK}, "call_0")],
        _rejected(provider, "stream"),
    )


def _budget_frames(provider: str, fragments: list[str]) -> list[bytes]:
    """A stream: the text, then ONE call (index 0 / block 1) with these argument fragments."""
    if provider == "anthropic":
        return [
            _a_start(),
            *_a_text_block(0, _TEXT),
            *_a_tool_block(1, "memory__store", "toolu_1", *fragments),
            *_a_end(),
        ]
    chunks = [
        _chunk({"content": _TEXT}),
        _tools_chunk(_frag(0, call_id="call_0", name="memory.store", arguments=fragments[0])),
        *(_tools_chunk(_frag(0, arguments=fragment)) for fragment in fragments[1:]),
        _chunk({}, finish_reason="tool_calls"),
    ]
    return _oa_frames(chunks)


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_malformed_stream_argument_fragments_crossing_65536_reject_reply(
    provider: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """Arguments of exactly 65536 characters parse; a fragment crossing the bound rejects.

    The crossing fragment is JSON whitespace after a complete object: the reply is
    rejected whether the client would append it (valid JSON) or parse the cut prefix.
    """
    head = '{"key": "' + _ARG_MARK + '"'
    exact = [head + " " * (_ARG_BUDGET - len(head) - 1 - 20000), " " * 20000, "}"]
    client = build(provider)
    wire.route = _sse_route(_budget_frames(provider, exact))
    kept = _kept(await _run(client, "stream"))
    wire.requests.clear()
    debug_logs.clear()
    wire.route = _sse_route(_budget_frames(provider, [*exact, "  "]))
    verdict = _verdict(await _run(client, "stream"), "stream", debug_logs, wire)
    call_id = "toolu_1" if provider == "anthropic" else "call_0"
    # The kept call's arguments carry _ARG_MARK by design: the logs were cleared before
    # the rejected reply, so only its own log records are scanned.
    assert (kept, verdict) == (
        [("memory", "store", {"key": _ARG_MARK}, call_id)],
        _rejected(provider, "stream"),
    )


def _many_calls_frames(provider: str, count: int) -> list[bytes]:
    """A stream: the text, then ``count`` valid calls numbered 0..count-1."""
    args = [json.dumps({"key": _NEIGHBOUR_MARK, "n": n}) for n in range(count)]
    if provider == "anthropic":
        frames = [_a_start(), *_a_text_block(0, _TEXT)]
        for n in range(count):
            frames += _a_tool_block(n + 1, "memory__store", f"toolu_{n:03d}", args[n])
        return frames + _a_end()
    fragments = [
        _frag(n, call_id=f"call_{n:03d}", name="memory.store", arguments=args[n])
        for n in range(count)
    ]
    chunks = [_chunk({"content": _TEXT})]
    chunks += [_tools_chunk(*fragments[start : start + 10]) for start in range(0, count, 10)]
    chunks.append(_chunk({}, finish_reason="tool_calls"))
    return _oa_frames(chunks)


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_malformed_stream_129th_tool_call_rejects_reply(
    provider: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """128 streamed calls are all kept in order; a 129th index / tool_use block rejects."""
    client = build(provider)
    wire.route = _sse_route(_many_calls_frames(provider, _MAX_CALLS))
    run = await _run(client, "stream")
    kept: Any = (
        [call.args.get("n") for call in run.finals[0].tool_calls]
        if len(run.finals) == 1
        else (run.crash, getattr(run.error, "code", None))
    )
    wire.requests.clear()
    debug_logs.clear()
    wire.route = _sse_route(_many_calls_frames(provider, _MAX_CALLS + 1))
    verdict = _verdict(await _run(client, "stream"), "stream", debug_logs, wire)
    assert (kept, verdict) == (list(range(_MAX_CALLS)), _rejected(provider, "stream"))


# ===========================================================================
# 3. Undecodable or wrong-typed data (D3; C3.4)
# ===========================================================================

_UNDECODABLE: Final[dict[str, bytes]] = {
    "not-json": b"<html>upstream " + _BODY_MARK.encode() + b"</html>",
    "recursion-error": b"[" * _DEEP_BODY + json.dumps(_BODY_MARK).encode() + b"]" * _DEEP_BODY,
    "int-over-4300-digits": b'{"note": "' + _BODY_MARK.encode() + b'", "n": ' + b"9" * 5000 + b"}",
}


@pytest.mark.parametrize("kind", list(_UNDECODABLE))
@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_malformed_chat_undecodable_body_rejected(
    provider: str,
    kind: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """A 200 body the SDK can't decode (raised raw by the SDK today) is malformed_response."""
    route = _raw_route(_UNDECODABLE[kind])
    assert await _judge(provider, "chat", route, wire, build, debug_logs) == _rejected(
        provider, "chat"
    )


def _bad_line_frames(provider: str, data: bytes) -> list[bytes]:
    """A stream: the text, then one event whose ``data:`` line is ``data``."""
    if provider == "anthropic":
        return [
            _a_start(),
            _a_block_start(0, {"type": "text", "text": ""}),
            _a_delta(0, {"type": "text_delta", "text": _TEXT}),
            b"event: content_block_delta\ndata: " + data + b"\n\n",
            _a_block_stop(0),
            *_a_end("end_turn"),
        ]
    return [
        *_oa_frames([_chunk({"content": _TEXT})], done=False),
        b"data: " + data + b"\n\n",
        *_oa_frames([_chunk({}, finish_reason="stop")]),
    ]


@pytest.mark.parametrize("kind", list(_UNDECODABLE))
@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_malformed_stream_undecodable_line_rejected(
    provider: str,
    kind: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """A stream line the SDK can't decode, after a delta: the delta arrived, then the error."""
    route = _sse_route(_bad_line_frames(provider, _UNDECODABLE[kind]))
    assert await _judge(provider, "stream", route, wire, build, debug_logs) == _rejected(
        provider, "stream"
    )


@pytest.mark.parametrize("index", ["a", [1]], ids=["str-a", "list-1"])
@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_malformed_stream_tool_call_index_not_int_rejected(
    provider: str,
    index: Any,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """A fragment whose ``index`` is not an int (after a valid call at index 0)."""
    chunks = [
        _chunk({"content": _TEXT}),
        _tools_chunk(_frag(0, call_id="call_0", name="memory.store", arguments=_FIRST.arguments)),
        _tools_chunk(
            _frag(index, call_id="call_x", name="memory.recall", arguments=_LAST.arguments)
        ),
        _chunk({}, finish_reason="tool_calls"),
    ]
    route = _sse_route(_oa_frames(chunks))
    assert await _judge(provider, "stream", route, wire, build, debug_logs) == _rejected(
        provider, "stream"
    )


@pytest.mark.parametrize("index", ["a", [1]], ids=["str-a", "list-1"])
@pytest.mark.parametrize("site", ["tool-use-start", "json-delta"])
async def test_llm_malformed_anthropic_stream_event_index_not_int_rejected(
    site: str,
    index: Any,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """A tool_use start or its input_json_delta whose ``index`` is not an int."""
    start_index = index if site == "tool-use-start" else 1
    frames = [
        _a_start(),
        *_a_text_block(0, _TEXT),
        _a_block_start(start_index, _a_tool_use("toolu_1", "memory__recall")),
        _a_delta(index, {"type": "input_json_delta", "partial_json": _LAST.arguments}),
        _a_block_stop(start_index),
        *_a_end(),
    ]
    route = _sse_route(frames)
    assert await _judge("anthropic", "stream", route, wire, build, debug_logs) == _rejected(
        "anthropic", "stream"
    )


def _oa_valid_call_chunk() -> dict[str, Any]:
    """The valid call at index 0 (its arguments carry the neighbour marker)."""
    return _tools_chunk(_frag(0, call_id="call_0", name="memory.store", arguments=_FIRST.arguments))


# One chunk with a wrong-typed field each, sent after the text and a valid call.
_OA_STREAM_WRONG_TYPES: Final[dict[str, dict[str, Any]]] = {
    "content-int": _chunk({"content": 5}),
    "model-int": _chunk({}, model=5),
    "id-int": _tools_chunk(_frag(1, call_id=5, name="memory.recall", arguments=_LAST.arguments)),
    "name-int": _tools_chunk(_frag(1, call_id="call_1", name=5, arguments=_LAST.arguments)),
    "arguments-int": _tools_chunk(_frag(1, call_id="call_1", name="memory.recall", arguments=5)),
    "arguments-object": _tools_chunk(
        _frag(1, call_id="call_1", name="memory.recall", arguments={"key": _ARG_MARK})
    ),
}


@pytest.mark.parametrize("kind", list(_OA_STREAM_WRONG_TYPES))
@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_malformed_stream_wrong_typed_field_rejected(
    provider: str,
    kind: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """A non-str content / model / id / name / arguments in a chunk (also a JSON-object one)."""
    chunks = [
        _chunk({"content": _TEXT}),
        _oa_valid_call_chunk(),
        _OA_STREAM_WRONG_TYPES[kind],
        _chunk({}, finish_reason="tool_calls"),
    ]
    route = _sse_route(_oa_frames(chunks))
    assert await _judge(provider, "stream", route, wire, build, debug_logs) == _rejected(
        provider, "stream"
    )


def _oa_wrong_typed_body(kind: str) -> dict[str, Any]:
    """A ``chat.completion`` with one wrong-typed field and a valid call."""
    valid = _oa_tool_call(0, _FIRST)
    if kind == "content-int":
        return _oa_completion(content=5, tool_calls=[valid])
    if kind == "model-int":
        return _oa_completion(model=5, tool_calls=[valid])
    bad = _oa_tool_call(1, _LAST)
    bad["function"]["name"] = 5
    return _oa_completion(tool_calls=[valid, bad])


@pytest.mark.parametrize("kind", ["content-int", "model-int", "name-int"])
@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_malformed_chat_wrong_typed_field_rejected(
    provider: str,
    kind: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """chat(): a non-str ``message.content``, ``model`` or tool-call ``function.name``."""
    route = _json_route(_oa_wrong_typed_body(kind))
    assert await _judge(provider, "chat", route, wire, build, debug_logs) == _rejected(
        provider, "chat"
    )


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_malformed_chat_object_arguments_kept_int_arguments_rejected(
    provider: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """chat() keeps accepting JSON-object arguments (as today); int arguments reject the reply."""
    client = build(provider)
    as_object = _oa_tool_call(0, _FIRST)
    as_object["function"]["arguments"] = {"key": _NEIGHBOUR_MARK}
    wire.route = _json_route(_oa_completion(tool_calls=[as_object]))
    kept = _kept(await _run(client, "chat"))
    wire.requests.clear()
    debug_logs.clear()
    as_int = _oa_tool_call(1, _LAST)
    as_int["function"]["arguments"] = 5
    wire.route = _json_route(_oa_completion(tool_calls=[_oa_tool_call(0, _FIRST), as_int]))
    verdict = _verdict(await _run(client, "chat"), "chat", debug_logs, wire)
    assert (kept, verdict) == (
        [("memory", "store", {"key": _NEIGHBOUR_MARK}, "call_0")],
        _rejected(provider, "chat"),
    )


def _a_wrong_typed_body(kind: str) -> dict[str, Any]:
    """An Anthropic ``message`` with one wrong-typed field and a valid tool_use block."""
    text: Any = 5 if kind == "text-int" else _TEXT
    tool_id: Any = 5 if kind == "id-int" else "toolu_1"
    name: Any = 5 if kind == "name-int" else "memory__store"
    model: Any = 5 if kind == "model-int" else _STREAM_MODEL
    content = [
        {"type": "text", "text": text},
        {"type": "tool_use", "id": tool_id, "name": name, "input": {"key": _NEIGHBOUR_MARK}},
    ]
    return _a_message(content, model=model)


@pytest.mark.parametrize("kind", ["text-int", "id-int", "name-int", "model-int"])
async def test_llm_malformed_anthropic_chat_wrong_typed_field_rejected(
    kind: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """chat(): a non-str text block ``text``, tool_use ``id`` / ``name``, or ``model``."""
    route = _json_route(_a_wrong_typed_body(kind))
    assert await _judge("anthropic", "chat", route, wire, build, debug_logs) == _rejected(
        "anthropic", "chat"
    )


def _a_wrong_typed_frames(kind: str) -> list[bytes]:
    """An Anthropic stream with one wrong-typed field, after the text.

    The model comes in the first event: that stream sends no text, so it doesn't
    matter whether the client checks the model at once or at the end.
    """
    tool_id: Any = 5 if kind == "id-int" else "toolu_1"
    name: Any = 5 if kind == "name-int" else "memory__store"
    fragment: Any = 5 if kind == "partial-json-int" else _FIRST.arguments
    if kind == "model-int":
        return [_a_start(5), *_a_tool_block(1, name, tool_id, fragment), *_a_end()]
    frames = [
        _a_start(),
        _a_block_start(0, {"type": "text", "text": ""}),
        _a_delta(0, {"type": "text_delta", "text": _TEXT}),
    ]
    if kind == "text-int":
        frames.append(_a_delta(0, {"type": "text_delta", "text": 5}))
    frames += [
        _a_block_stop(0),
        *_a_tool_block(1, name, tool_id, fragment),
        *_a_end(),
    ]
    return frames


@pytest.mark.parametrize(
    "kind", ["text-int", "partial-json-int", "id-int", "name-int", "model-int"]
)
async def test_llm_malformed_anthropic_stream_wrong_typed_field_rejected(
    kind: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """A non-str text_delta ``text``, ``partial_json``, tool_use ``id`` / ``name``, or model."""
    route = _sse_route(_a_wrong_typed_frames(kind))
    streamed = "" if kind == "model-int" else _TEXT
    assert await _judge("anthropic", "stream", route, wire, build, debug_logs) == _rejected(
        "anthropic", "stream", streamed=streamed
    )


def _text_then_failure_route(
    provider: str, failure: Callable[[httpx.Request], Exception]
) -> Callable[[httpx.Request], httpx.Response]:
    """A stream that sends the text, then breaks with ``failure`` (no end of stream)."""
    if provider == "anthropic":
        frames = [
            _a_start(),
            _a_block_start(0, {"type": "text", "text": ""}),
            _a_delta(0, {"type": "text_delta", "text": _TEXT}),
        ]
    else:
        frames = _oa_frames([_chunk({"content": _TEXT})], done=False)
    return _sse_route(frames, failure)


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_malformed_stream_decoding_error_mid_stream_rejected(
    provider: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """``httpx.DecodingError`` raised by the body after a delta is malformed_response."""

    def failure(request: httpx.Request) -> Exception:
        return httpx.DecodingError(f"bad gzip stream {_WIRE_MARK}", request=request)

    route = _text_then_failure_route(provider, failure)
    assert await _judge(provider, "stream", route, wire, build, debug_logs) == _rejected(
        provider, "stream"
    )


# ===========================================================================
# 4. Other mid-stream failures (C3.5)
# ===========================================================================


async def _connection_error_shape(client: Any, wire: _Wire) -> tuple[Any, ...]:
    """The shape of the error ``chat()`` raises for a connection failure (the oracle)."""
    wire.route = _connect_error_route()
    with pytest.raises(LLMError) as excinfo:
        await client.chat(_messages(), [_MEMORY_TOOL])
    return _shape(excinfo.value)


def _unavailable(provider: str, oracle: tuple[Any, ...]) -> dict[str, Any]:
    """The verdict of a stream failing with ``provider_unavailable`` after the text."""
    return {
        "streamed": _TEXT,
        "finals": [],
        "error": oracle,
        "chained": (None, True),
        "leaks": [],
        "requests": 1,
    }


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_malformed_stream_stream_error_mid_stream_is_provider_unavailable(
    provider: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """``httpx.StreamError`` after a delta: the client's provider_unavailable (as chat()'s)."""
    client = build(provider)

    def failure(_request: httpx.Request) -> Exception:
        return httpx.StreamError(f"stream closed {_WIRE_MARK}")

    wire.route = _text_then_failure_route(provider, failure)
    verdict = _verdict(await _run(client, "stream"), "stream", debug_logs, wire)
    oracle = await _connection_error_shape(client, wire)
    assert (oracle[1], verdict) == ("provider_unavailable", _unavailable(provider, oracle))


async def test_llm_malformed_infomaniak_error_event_mid_stream_is_provider_unavailable(
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """Infomaniak's mid-stream ``error`` event: provider_unavailable, not the uncoded text."""
    client = build("infomaniak")
    error_line = {"error": {"message": f"overloaded {_BODY_MARK}", "type": "server_error"}}
    frames = [
        *_oa_frames([_chunk({"content": _TEXT})], done=False),
        f"data: {json.dumps(error_line)}\n\n".encode(),
    ]
    wire.route = _sse_route(frames)
    verdict = _verdict(await _run(client, "stream"), "stream", debug_logs, wire)
    oracle = await _connection_error_shape(client, wire)
    assert (oracle[1], verdict) == ("provider_unavailable", _unavailable("infomaniak", oracle))


# ===========================================================================
# 5. The model policy never retries malformed_response (C4)
# ===========================================================================


@pytest.mark.parametrize(("provider", "path"), _PROVIDER_PATHS, ids=_ids(_PROVIDER_PATHS))
async def test_llm_malformed_policy_never_retries_malformed_response(
    provider: str,
    path: str,
    wire: _Wire,
    build: Callable[[str], Any],
    policy_sleeps: list[float],
) -> None:
    """max_retries=2: a malformed reply (nothing yielded before it) is one request, no sleep."""
    client = build(provider)
    wire.route = _tool_reply(provider, path, [_FIRST, _BAD_CALLS["invalid-json"]], text=None)
    yielded: list[Any] = []
    error: object = None
    try:
        if path == "chat":
            yielded.append(
                await llm_policy.chat(
                    client, _messages(), [_MEMORY_TOOL], data_residency=False, max_retries=2
                )
            )
        else:
            async for item in llm_policy.chat_stream(
                client, _messages(), [_MEMORY_TOOL], data_residency=False, max_retries=2
            ):
                yielded.append(item)
    except LLMError as exc:
        error = getattr(exc, "code", None)
    except Exception as exc:  # a pre-implementation crash, reported by type only
        error = type(exc).__name__
    assert (error, len(wire.requests), policy_sleeps, [type(i).__name__ for i in yielded]) == (
        "malformed_response",
        1,
        [],
        [],
    )
