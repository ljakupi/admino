"""Security-audit round 1 fixes of the GH-25 LLM layer (contract C10, decision 11).

Every client (Infomaniak, vLLM, OpenAI, Anthropic) is built from a real
``LLMConfig`` and drives its REAL SDK (``openai`` 1.109 for the
OpenAI-compatible three, ``anthropic`` 0.93 for Claude) against a fake wire:
``httpx.AsyncClient.send`` is replaced by a scripted route answering a JSON body
for ``chat()`` or an SSE body for ``chat_stream()``. Nothing reaches a real host.

What these tests pin:

- LLM M-1 (D3, D11): both SDKs build replies with ``construct(**provider_json)``.
  A provider object holding the key ``_fields_set`` (non-null) makes the SDK
  raise ``AttributeError``, ``_BaseModel__cls`` a ``TypeError``, and an
  Anthropic union member that also has a non-str ``type`` a ``RuntimeError``
  ("Could not convert data"). In ``chat()`` and ``chat_stream()`` of every
  provider, each such reply is ``malformed_response_error(label)``:
  - OpenAI-compatible ``chat()``: the completion, ``choices[0]``, ``message``;
    stream: the chunk, ``choices[0]``, ``delta`` (the nested tool-call objects are
    ``Optional`` unions the SDK validates, so they never reach ``construct``);
  - Anthropic ``chat()``: the message, its ``usage``, a text block / tool_use
    block with a wrong-typed field (the SDK validates the block union first), a
    block whose ``type`` is not a str; stream: the ``message_start`` event and its
    message (with a non-str ``model``), a tool_use ``content_block_start``, a
    ``text_delta``, a ``content_block_delta`` event (``index`` ``"a"``), the
    ``message_delta`` delta (non-int ``output_tokens``), a delta whose ``type`` is
    not a str.
  Each one is an ``LLMError`` raised ``from None`` (``__cause__`` None,
  ``__suppress_context__`` True) after exactly one request; no ``LLMResponse`` is
  returned or yielded; the text streamed before the bad item reached the
  consumer; no marker (the reserved key's value, the bad object's text, the
  arguments) shows up in ``str`` / ``repr`` / ``message`` / ``args`` of the error
  or in any log record (DEBUG captured for admino, both SDKs, httpx).
  ``llm_policy`` with ``max_retries=2`` never retries it (one request, no sleep).
- LLM L-1 (D11): a stream item that decodes to JSON ``null`` is
  ``malformed_response`` in every provider's stream, never a normal end: no final
  ``LLMResponse``, so the tool calls sent before it are never returned.
  OpenAI-compatible: ``data: null`` after a delta and before the finish reason,
  before the tool-call fragments, or after a complete call. Anthropic (the SDK
  hands ``None`` to the client for a ``data: null`` on every known event name,
  and drops it on ``ping`` / no event name): a ``content_block_delta`` inside the
  text block, a ``message_delta`` after a complete tool_use block, and the SDK's
  separate ``completion`` branch.
- Core L-1 (D11): ``llm_anthropic._convert_messages_to_anthropic`` leaves out an
  ``assistant`` message whose content is ``""``, ``" "``, ``"\\n\\t "`` or only
  non-ASCII spaces and that has no ``tool_use_blocks``; the user messages around
  it merge as the converter merges same-role messages (``"a" + "\\n" + "b"``; a
  tool_result list plus a str gains a text block). The input messages are not
  changed. An assistant with ``tool_use_blocks`` and empty text is kept as today
  (tool_use blocks only), a non-blank assistant is sent verbatim. On the wire,
  ``AnthropicClient.chat()`` / ``chat_stream()`` never send a blank assistant
  entry; the OpenAI-compatible clients still send it unchanged (regression
  guard).
- Dead code (C10, LLM I-4): ``admino.llm.sanitize_content`` is gone;
  ``parse_tool_calls`` stays.

Security notes:
- Keys are built at runtime (``tests.credential_keys``); no key literal here.
- The SDKs' retry sleep and the policy's ``_sleep`` are no-ops, so a client or
  policy that still retries fails fast (and visibly, by its request count).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import anthropic._base_client as anthropic_base_client
import httpx
import openai._base_client as openai_base_client
import pytest

import admino.llm as llm_mod
from admino import llm_policy
from admino.config import LLMConfig
from admino.llm import LLMError, LLMResponse, LLMStreamDelta
from admino.llm_anthropic import AnthropicClient, _convert_messages_to_anthropic
from admino.llm_infomaniak import InfomaniakClient
from admino.llm_openai import OpenAIClient, _convert_messages_to_openai
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
_MODEL: Final = "wire-w6-model"

_OPENAI_KEY: Final = api_key("sk-", 48, seed=2561).text
_ANTHROPIC_KEY: Final = api_key("sk-" + "ant-", 48, seed=2562).text
_IK_TOKEN: Final = api_key("ik-", 40, seed=2563).text

# Markers: none may reach an LLMError or a log record.
_KEY_MARK: Final = "KEYMARK-w6-c41a"  # the reserved key's value
_BODY_MARK: Final = "BODYMARK-w6-8d07"  # text inside the bad object
_ARG_MARK: Final = "ARGMARK-w6-17f3"  # tool-call arguments
_TEXT_MARK: Final = "TXTMARK-w6-5b2e"  # the answer text streamed before the bad item
_MARKERS: Final[tuple[str, ...]] = (_KEY_MARK, _BODY_MARK, _ARG_MARK, _TEXT_MARK)

# The text every stream sends before its bad item (ends with a space, so no filter
# holds part of it back).
_TEXT: Final = f"Checking {_TEXT_MARK} "
_BODY_TEXT: Final = f"More {_BODY_MARK} "

# The SDKs' reserved construct() parameters (contract C10, LLM M-1).
_RESERVED_KEYS: Final[dict[str, str]] = {
    "fields-set": "_fields_set",
    "basemodel-cls": "_BaseModel__cls",
}

_NULL_LINE: Final = b"data: null\n\n"

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

# A valid tool call (its arguments carry a marker).
_CALL_NAME: Final = "memory.store"
_CALL_ARGUMENTS: Final = json.dumps({"key": _ARG_MARK})

# ---------------------------------------------------------------------------
# OpenAI-compatible bodies and chunks
# ---------------------------------------------------------------------------


def _oa_completion(*, content: Any, tool_calls: list[Any] | None = None) -> dict[str, Any]:
    """A ``chat.completion`` body (for ``chat()``)."""
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-w6-json",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": _MODEL,
        "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls"}],
    }


def _oa_tool_call(index: int) -> dict[str, Any]:
    """One valid ``message.tool_calls`` entry."""
    return {
        "id": f"call_{index}",
        "type": "function",
        "function": {"name": _CALL_NAME, "arguments": _CALL_ARGUMENTS},
    }


def _chunk(
    delta: dict[str, Any] | None = None, *, finish_reason: str | None = None
) -> dict[str, Any]:
    """One ``chat.completion.chunk``."""
    return {
        "id": "chatcmpl-w6-stream",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": _MODEL,
        "choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}],
    }


def _oa_call_chunks() -> list[dict[str, Any]]:
    """The valid call at index 0 as two chunks: id + name + half the arguments, the rest."""
    half = len(_CALL_ARGUMENTS) // 2
    first = {
        "index": 0,
        "id": "call_0",
        "type": "function",
        "function": {"name": _CALL_NAME, "arguments": _CALL_ARGUMENTS[:half]},
    }
    rest = {"index": 0, "function": {"arguments": _CALL_ARGUMENTS[half:]}}
    return [_chunk({"tool_calls": [first]}), _chunk({"tool_calls": [rest]})]


def _oa_frames(chunks: list[dict[str, Any]], *, done: bool = True) -> list[bytes]:
    """``data: <chunk>`` lines, then ``data: [DONE]`` when ``done``."""
    frames = [f"data: {json.dumps(chunk)}\n\n".encode() for chunk in chunks]
    if done:
        frames.append(b"data: [DONE]\n\n")
    return frames


# ---------------------------------------------------------------------------
# Anthropic bodies and frames
# ---------------------------------------------------------------------------


def _a_message(
    content: list[Any], *, model: Any = _MODEL, stop_reason: str | None = "tool_use"
) -> dict[str, Any]:
    """An Anthropic ``message`` (a ``chat()`` body, or the one in ``message_start``)."""
    return {
        "id": "msg_w6_01",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


def _frame(event: str, data: Any) -> bytes:
    """One Anthropic Messages SSE frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _a_start() -> bytes:
    """A valid ``message_start`` frame."""
    return _frame(
        "message_start",
        {"type": "message_start", "message": _a_message([], stop_reason=None)},
    )


def _a_block_start(index: int, block: dict[str, Any]) -> bytes:
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


def _a_block_stop(index: int) -> bytes:
    """A ``content_block_stop`` frame."""
    return _frame("content_block_stop", {"type": "content_block_stop", "index": index})


def _a_text_open() -> list[bytes]:
    """The text block's start and its one ``text_delta`` (``_TEXT``); still open."""
    return [
        _a_block_start(0, {"type": "text", "text": ""}),
        _a_delta(0, {"type": "text_delta", "text": _TEXT}),
    ]


def _a_tool_block(index: int) -> list[bytes]:
    """The valid call as a whole tool_use block (JSON in two ``input_json_delta`` parts)."""
    half = len(_CALL_ARGUMENTS) // 2
    block = {"type": "tool_use", "id": f"toolu_{index}", "name": "memory__store", "input": {}}
    return [
        _a_block_start(index, block),
        _a_delta(index, {"type": "input_json_delta", "partial_json": _CALL_ARGUMENTS[:half]}),
        _a_delta(index, {"type": "input_json_delta", "partial_json": _CALL_ARGUMENTS[half:]}),
        _a_block_stop(index),
    ]


def _a_end(stop_reason: str = "end_turn") -> list[bytes]:
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


# ---------------------------------------------------------------------------
# M-1: replies whose object holds a reserved key
# ---------------------------------------------------------------------------

# Where the reserved key sits. The OpenAI tool-call objects are Optional unions the
# SDK validates (an extra key passes, a wrong type falls back to plain dicts), so
# they never reach construct() and aren't listed.
_OA_CHAT_LOCATIONS: Final[tuple[str, ...]] = ("completion", "choice", "message")
_OA_STREAM_LOCATIONS: Final[tuple[str, ...]] = ("chunk", "choice", "delta")
_A_CHAT_LOCATIONS: Final[tuple[str, ...]] = (
    "message",
    "usage",
    "text-block-text-not-str",
    "tool-use-block-id-not-str",
    "block-type-not-str",
)
_A_STREAM_LOCATIONS: Final[tuple[str, ...]] = (
    "message-start-event",
    "message-start-message",
    "tool-use-block-start-id-not-str",
    "text-delta-text-not-str",
    "content-block-delta-event-index-not-int",
    "message-delta-delta",
    "delta-type-not-str",
)
# The Anthropic stream locations in the first event: no text is streamed before them.
_A_FIRST_EVENT: Final = frozenset({"message-start-event", "message-start-message"})


def _oa_reserved_body(location: str, key: str) -> dict[str, Any]:
    """A ``chat.completion`` whose ``location`` object holds the reserved ``key``."""
    body = _oa_completion(content=_BODY_TEXT, tool_calls=[_oa_tool_call(0)])
    choice = body["choices"][0]
    target = {"completion": body, "choice": choice, "message": choice["message"]}[location]
    target[key] = _KEY_MARK
    return body


def _oa_reserved_frames(location: str, key: str, *, text: bool = True) -> list[bytes]:
    """A stream: ``_TEXT`` (when ``text``), a chunk whose ``location`` holds ``key``, the end."""
    bad = _chunk({"content": _BODY_TEXT})
    choice = bad["choices"][0]
    target = {"chunk": bad, "choice": choice, "delta": choice["delta"]}[location]
    target[key] = _KEY_MARK
    chunks = [_chunk({"content": _TEXT})] if text else []
    return _oa_frames([*chunks, bad, _chunk({}, finish_reason="stop")])


def _a_reserved_body(location: str, key: str) -> dict[str, Any]:
    """An Anthropic ``message`` whose ``location`` object holds the reserved ``key``.

    The SDK validates the content-block union first, so a block needs a
    wrong-typed field too before the SDK constructs it (a non-str ``type`` makes
    every union member fail: ``RuntimeError``).
    """
    text_block: dict[str, Any] = {"type": "text", "text": _BODY_TEXT}
    tool_block: dict[str, Any] = {
        "type": "tool_use",
        "id": "toolu_1",
        "name": "memory__store",
        "input": {"key": _ARG_MARK},
    }
    body = _a_message([text_block, tool_block])
    if location == "message":
        body[key] = _KEY_MARK
    elif location == "usage":
        body["usage"][key] = _KEY_MARK
    elif location == "text-block-text-not-str":
        text_block.update({"text": [_BODY_MARK], key: _KEY_MARK})
    elif location == "tool-use-block-id-not-str":
        tool_block.update({"id": 5, key: _KEY_MARK})
    else:
        text_block.update({"type": 5, key: _KEY_MARK})
    return body


def _a_reserved_frames(location: str, key: str) -> list[bytes]:
    """An Anthropic stream with one event whose ``location`` object holds ``key``.

    The events are a union the SDK validates first, so each bad object comes with
    a wrong-typed field in the same event. The ``message_start`` cases come first
    (no text before them); every other bad event comes after ``_TEXT`` and no text
    follows it.
    """
    if location in _A_FIRST_EVENT:
        message = _a_message([], model=5, stop_reason=None)
        event = {"type": "message_start", "message": message}
        (event if location == "message-start-event" else message)[key] = _KEY_MARK
        return [
            _frame("message_start", event),
            *_a_text_open(),
            _a_block_stop(0),
            *_a_end(),
        ]
    if location == "tool-use-block-start-id-not-str":
        bad = _a_block_start(
            1,
            {"type": "tool_use", "id": 5, "name": "memory__store", "input": {}, key: _KEY_MARK},
        )
    elif location == "text-delta-text-not-str":
        bad = _a_delta(0, {"type": "text_delta", "text": [_BODY_MARK], key: _KEY_MARK})
    elif location == "content-block-delta-event-index-not-int":
        bad = _frame(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": "a",
                "delta": {"type": "text_delta", "text": _BODY_TEXT},
                key: _KEY_MARK,
            },
        )
    elif location == "message-delta-delta":
        bad = _frame(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None, key: _KEY_MARK},
                "usage": {"output_tokens": [_BODY_MARK]},
            },
        )
    else:
        bad = _a_delta(0, {"type": 5, "text": _BODY_TEXT, key: _KEY_MARK})
    return [_a_start(), *_a_text_open(), bad, _a_block_stop(0), *_a_end()]


# ---------------------------------------------------------------------------
# L-1: stream items that decode to JSON null
# ---------------------------------------------------------------------------

_OA_NULL_PLACEMENTS: Final[tuple[str, ...]] = (
    "before-finish-reason",
    "before-tool-call",
    "after-tool-call",
)
# Event names whose ``data: null`` the SDK hands to the client: one of the main
# branch inside the text block, one after a complete tool_use block, and the
# SDK's separate ``completion`` branch.
_A_NULL_EVENTS: Final[tuple[str, ...]] = ("content_block_delta", "message_delta", "completion")


def _oa_null_frames(placement: str) -> list[bytes]:
    """A stream with ``data: null`` after ``_TEXT`` at ``placement``; no text after it."""
    text = [_chunk({"content": _TEXT})]
    calls = _oa_call_chunks()
    if placement == "before-finish-reason":
        before, after = text, [_chunk({}, finish_reason="stop")]
    elif placement == "before-tool-call":
        before, after = text, [*calls, _chunk({}, finish_reason="tool_calls")]
    else:
        before, after = [*text, *calls], [_chunk({}, finish_reason="tool_calls")]
    return [*_oa_frames(before, done=False), _NULL_LINE, *_oa_frames(after)]


def _a_null_frames(event: str) -> list[bytes]:
    """An Anthropic stream with ``event: <event>`` + ``data: null`` after ``_TEXT``."""
    null = f"event: {event}\ndata: null\n\n".encode()
    if event == "content_block_delta":
        return [_a_start(), *_a_text_open(), null, _a_block_stop(0), *_a_end()]
    return [
        _a_start(),
        *_a_text_open(),
        _a_block_stop(0),
        *_a_tool_block(1),
        null,
        *_a_end("tool_use"),
    ]


# ---------------------------------------------------------------------------
# The fake wire
# ---------------------------------------------------------------------------


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


def _sse_route(frames: list[bytes]) -> Callable[[httpx.Request], httpx.Response]:
    """A route answering a streamed SSE body (the same frames on every request)."""

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_Body(frames),
            request=request,
        )

    return route


def _json_route(body: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """A route answering ``body`` as a 200 JSON body."""
    content = json.dumps(body).encode()

    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "application/json"}, content=content, request=request
        )

    return route


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    Each POST gets ``self.route`` and its JSON body is kept; anything else (or a
    POST without a route) gets a 404, so an unexpected request is visible.
    """

    def __init__(self) -> None:
        self.route: Callable[[httpx.Request], httpx.Response] | None = None
        self.requests: list[str] = []
        self.bodies: list[dict[str, Any]] = []

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it."""
        await request.aread()
        self.requests.append(f"{request.method}:{request.url.path}")
        if request.method != "POST" or self.route is None:
            return httpx.Response(404, json={"error": "unexpected"}, request=request)
        self.bodies.append(json.loads(request.content))
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
    except Exception as exc:  # a pre-fix crash (raw SDK exception), reported by type only
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


# ===========================================================================
# 1. LLM M-1: reserved keys in a provider object (D3, D11)
# ===========================================================================


@pytest.mark.parametrize("key", list(_RESERVED_KEYS))
@pytest.mark.parametrize("location", _OA_CHAT_LOCATIONS)
@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_output_audit_reserved_key_in_chat_reply_is_malformed(
    provider: str,
    location: str,
    key: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """chat(): the completion / choice / message holding a reserved key (raw SDK error today)."""
    route = _json_route(_oa_reserved_body(location, _RESERVED_KEYS[key]))
    assert await _judge(provider, "chat", route, wire, build, debug_logs) == _rejected(
        provider, "chat"
    )


@pytest.mark.parametrize("key", list(_RESERVED_KEYS))
@pytest.mark.parametrize("location", _OA_STREAM_LOCATIONS)
@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_output_audit_reserved_key_in_stream_chunk_is_malformed(
    provider: str,
    location: str,
    key: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """Stream: after a delta, a chunk / choice / delta holding a reserved key."""
    route = _sse_route(_oa_reserved_frames(location, _RESERVED_KEYS[key]))
    assert await _judge(provider, "stream", route, wire, build, debug_logs) == _rejected(
        provider, "stream"
    )


@pytest.mark.parametrize("key", list(_RESERVED_KEYS))
@pytest.mark.parametrize("location", _A_CHAT_LOCATIONS)
async def test_llm_output_audit_reserved_key_in_anthropic_chat_reply_is_malformed(
    location: str,
    key: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """Claude chat(): the message, its usage, or a content block holding a reserved key."""
    route = _json_route(_a_reserved_body(location, _RESERVED_KEYS[key]))
    assert await _judge("anthropic", "chat", route, wire, build, debug_logs) == _rejected(
        "anthropic", "chat"
    )


@pytest.mark.parametrize("key", list(_RESERVED_KEYS))
@pytest.mark.parametrize("location", _A_STREAM_LOCATIONS)
async def test_llm_output_audit_reserved_key_in_anthropic_stream_event_is_malformed(
    location: str,
    key: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """Claude stream: an event / message / block / delta holding a reserved key."""
    route = _sse_route(_a_reserved_frames(location, _RESERVED_KEYS[key]))
    streamed = "" if location in _A_FIRST_EVENT else _TEXT
    assert await _judge("anthropic", "stream", route, wire, build, debug_logs) == _rejected(
        "anthropic", "stream", streamed=streamed
    )


def _first_item_reserved_route(
    provider: str, path: str, key: str
) -> Callable[[httpx.Request], httpx.Response]:
    """A reply whose FIRST item holds ``key`` (nothing is yielded before the error)."""
    if provider == "anthropic":
        if path == "chat":
            return _json_route(_a_reserved_body("message", key))
        return _sse_route(_a_reserved_frames("message-start-event", key))
    if path == "chat":
        return _json_route(_oa_reserved_body("completion", key))
    return _sse_route(_oa_reserved_frames("chunk", key, text=False))


@pytest.mark.parametrize("key", list(_RESERVED_KEYS))
@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_output_audit_policy_never_retries_reserved_key_reply(
    provider: str,
    path: str,
    key: str,
    wire: _Wire,
    build: Callable[[str], Any],
    policy_sleeps: list[float],
) -> None:
    """max_retries=2: a reserved-key reply (nothing yielded) is malformed_response, one request."""
    client = build(provider)
    wire.route = _first_item_reserved_route(provider, path, _RESERVED_KEYS[key])
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
    except Exception as exc:  # a pre-fix crash (raw SDK exception), reported by type only
        error = type(exc).__name__
    assert (error, len(wire.requests), policy_sleeps, [type(i).__name__ for i in yielded]) == (
        "malformed_response",
        1,
        [],
        [],
    )


# ===========================================================================
# 2. LLM L-1: a stream item that decodes to JSON null (D11)
# ===========================================================================


@pytest.mark.parametrize("placement", _OA_NULL_PLACEMENTS)
@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_output_audit_null_stream_chunk_is_malformed_not_end(
    provider: str,
    placement: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """``data: null`` after a delta: malformed_response, no final, no tool call returned."""
    route = _sse_route(_oa_null_frames(placement))
    assert await _judge(provider, "stream", route, wire, build, debug_logs) == _rejected(
        provider, "stream"
    )


@pytest.mark.parametrize("event", _A_NULL_EVENTS)
async def test_llm_output_audit_null_anthropic_event_is_malformed_not_end(
    event: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """``event: <name>`` + ``data: null`` after the text: malformed_response, no final."""
    route = _sse_route(_a_null_frames(event))
    assert await _judge("anthropic", "stream", route, wire, build, debug_logs) == _rejected(
        "anthropic", "stream"
    )


# ===========================================================================
# 3. Core L-1: blank assistant messages and Anthropic (D11)
# ===========================================================================

_SYSTEM: Final = "You are admino."
_FIRST_QUESTION: Final = "First question"
_SECOND_QUESTION: Final = "Second question"

# Blank assistant contents: empty, ASCII whitespace only, non-ASCII spaces only
# (NBSP; IDEOGRAPHIC SPACE + EM SPACE), built with chr() so the file stays ASCII.
_BLANKS: Final[dict[str, str]] = {
    "empty": "",
    "space": " ",
    "newline-tab-space": "\n\t ",
    "nbsp": chr(0xA0),
    "ideographic-and-em-space": chr(0x3000) + chr(0x2003),
}


def _history(assistant: LLMMessage) -> list[LLMMessage]:
    """System prompt, a user turn, ``assistant``, the next user turn."""
    return [
        LLMMessage(role="system", content=_SYSTEM),
        LLMMessage(role="user", content=_FIRST_QUESTION),
        assistant,
        LLMMessage(role="user", content=_SECOND_QUESTION),
    ]


# What Anthropic gets for a history whose assistant message is left out: the two
# user turns merged as the converter merges same-role str contents.
_MERGED_USERS: Final[list[dict[str, Any]]] = [
    {"role": "user", "content": f"{_FIRST_QUESTION}\n{_SECOND_QUESTION}"}
]


@pytest.mark.parametrize("blank", list(_BLANKS))
def test_llm_output_audit_anthropic_converter_leaves_out_blank_assistant(blank: str) -> None:
    """A blank assistant without tool_use blocks is left out; the users merge; input unchanged."""
    messages = _history(LLMMessage(role="assistant", content=_BLANKS[blank]))
    before = [message.model_dump() for message in messages]
    converted = _convert_messages_to_anthropic(messages)
    assert (converted, [message.model_dump() for message in messages]) == (
        (_SYSTEM, _MERGED_USERS),
        before,
    )


def test_llm_output_audit_anthropic_converter_blank_final_after_tool_turn() -> None:
    """Tool turn, then an empty (cut) final answer, then a new user turn.

    The assistant with tool_use blocks and empty text is kept as today (tool_use
    blocks only); the empty final answer is left out, so the tool result and the
    new user message merge into one user turn (tool_result, then a text block).
    """
    tool_use = {
        "type": "tool_use",
        "id": "toolu_1",
        "name": "memory.store",
        "input": {"key": "k"},
    }
    messages = [
        LLMMessage(role="system", content=_SYSTEM),
        LLMMessage(role="user", content="Store it"),
        LLMMessage(role="assistant", content="", tool_use_blocks=[tool_use]),
        LLMMessage(role="tool", content="stored", tool_call_id="toolu_1"),
        LLMMessage(role="assistant", content=""),
        LLMMessage(role="user", content="Next"),
    ]
    assert _convert_messages_to_anthropic(messages) == (
        _SYSTEM,
        [
            {"role": "user", "content": "Store it"},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "memory__store",
                        "input": {"key": "k"},
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "stored"},
                    {"type": "text", "text": "Next"},
                ],
            },
        ],
    )


@pytest.mark.parametrize("content", ["Hello there", " padded answer\n"], ids=["plain", "padded"])
def test_llm_output_audit_anthropic_converter_keeps_non_blank_assistant(content: str) -> None:
    """Regression guard: a non-blank assistant message is sent verbatim (never stripped)."""
    converted = _convert_messages_to_anthropic(
        _history(LLMMessage(role="assistant", content=content))
    )
    assert converted == (
        _SYSTEM,
        [
            {"role": "user", "content": _FIRST_QUESTION},
            {"role": "assistant", "content": content},
            {"role": "user", "content": _SECOND_QUESTION},
        ],
    )


def test_llm_output_audit_openai_converter_keeps_empty_assistant() -> None:
    """Regression guard: the OpenAI-compatible converter sends an empty assistant unchanged."""
    converted = _convert_messages_to_openai(_history(LLMMessage(role="assistant", content="")))
    assert converted == [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": _FIRST_QUESTION},
        {"role": "assistant", "content": ""},
        {"role": "user", "content": _SECOND_QUESTION},
    ]


def _plain_reply_route(provider: str, path: str) -> Callable[[httpx.Request], httpx.Response]:
    """A plain valid answer ("Fine ") in ``provider``'s format for ``path``."""
    if provider == "anthropic":
        if path == "chat":
            return _json_route(
                _a_message([{"type": "text", "text": "Fine "}], stop_reason="end_turn")
            )
        return _sse_route(
            [
                _a_start(),
                _a_block_start(0, {"type": "text", "text": ""}),
                _a_delta(0, {"type": "text_delta", "text": "Fine "}),
                _a_block_stop(0),
                *_a_end(),
            ]
        )
    if path == "chat":
        body = _oa_completion(content="Fine ")
        body["choices"][0]["finish_reason"] = "stop"
        return _json_route(body)
    return _sse_route(_oa_frames([_chunk({"content": "Fine "}), _chunk({}, finish_reason="stop")]))


async def _sent_messages(client: Any, path: str, messages: list[LLMMessage]) -> None:
    """Send ``messages`` through ``chat()`` or a drained ``chat_stream()``."""
    if path == "chat":
        await client.chat(messages)
        return
    async for _item in client.chat_stream(messages):
        pass


@pytest.mark.parametrize("blank", list(_BLANKS))
@pytest.mark.parametrize("path", PATHS)
async def test_llm_output_audit_anthropic_request_never_carries_blank_assistant(
    path: str,
    blank: str,
    wire: _Wire,
    build: Callable[[str], Any],
) -> None:
    """On the wire: Claude's request body has the users merged and no blank assistant entry."""
    client = build("anthropic")
    wire.route = _plain_reply_route("anthropic", path)
    await _sent_messages(
        client, path, _history(LLMMessage(role="assistant", content=_BLANKS[blank]))
    )
    sent = wire.bodies[0]
    assert (len(wire.bodies), sent.get("system"), sent["messages"]) == (
        1,
        _SYSTEM,
        _MERGED_USERS,
    )


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_output_audit_openai_compatible_request_keeps_empty_assistant(
    provider: str,
    path: str,
    wire: _Wire,
    build: Callable[[str], Any],
) -> None:
    """Regression guard: Infomaniak, vLLM and OpenAI still send the empty assistant unchanged."""
    client = build(provider)
    wire.route = _plain_reply_route(provider, path)
    await _sent_messages(client, path, _history(LLMMessage(role="assistant", content="")))
    assert [wire.bodies[0]["messages"], len(wire.bodies)] == [
        [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _FIRST_QUESTION},
            {"role": "assistant", "content": ""},
            {"role": "user", "content": _SECOND_QUESTION},
        ],
        1,
    ]


# ===========================================================================
# 4. Dead code (C10, LLM I-4)
# ===========================================================================


def test_llm_output_audit_sanitize_content_removed_parse_tool_calls_kept() -> None:
    """``sanitize_content`` has no caller and is gone; ``parse_tool_calls`` stays (C10)."""
    assert (
        hasattr(llm_mod, "sanitize_content"),
        callable(getattr(llm_mod, "parse_tool_calls", None)),
    ) == (False, True)
