"""Wire-level spec: ``AnthropicClient.chat_stream`` (GH-8 contract C1, Anthropic parts).

The REAL ``anthropic`` SDK is driven against a fake wire: ``httpx.AsyncClient.send``
is replaced by a recorder that keeps every outgoing request and answers with a
scripted reply (an Anthropic Messages SSE stream, or a JSON error status). Each
SSE frame arrives as its own chunk; a mid-stream transport failure is a 200 whose
byte stream yields some frames and then raises ``httpx.ReadTimeout`` /
``httpx.RemoteProtocolError`` / ``httpx.ReadError``. No real request is made.

What these tests pin down:

- Shape (C1.1): zero or more ``LLMStreamDelta`` (each non-empty), then exactly one
  ``LLMResponse``, last; ``final.content == "".join(deltas)``. Deltas are yielded
  as the stream arrives (a delta comes out before the rest of the body exists).
- Only ``text_delta`` text is forwarded (C1.8): ping events, thinking / signature
  deltas, unknown event types and unknown delta types (even one carrying a
  ``text`` field) never become deltas.
- Sanitizing (C1.2) per delta, across event boundaries: C0 (NUL, ESC), C1 (NEL,
  CSI), bidi overrides/isolates, zero-width characters, U+2028/U+2029 and the BOM
  are removed; tab, LF and CR are kept; a delta that sanitizes to nothing is not
  yielded.
- Content cap (C1.3): 65536 characters counted after sanitizing; text past it is
  dropped, but tool calls and the stop reason after it still count.
- Tool calls (C1.4): ``content_block_start`` tool_use blocks plus their
  ``input_json_delta`` fragments, keyed by block index, split anywhere (inside a
  JSON string, inside an escape), interleaved with text blocks; no fragment (or
  only ``""``) means ``{}``; ``tool__action`` decodes to ``tool.action``; the
  provider id is kept as ``tool_call_id``; index order; never in any delta.
  Invalid calls are dropped (bad JSON, non-object, depth 5, 33 keys, a 2049-char
  string, ``json.dumps`` over 16384, a name that doesn't decode to
  ``tool.action``) and the valid ones kept; their arguments never reach a log.
  Bounds: only the first 128 tool_use blocks; a call whose fragments exceed
  65536 characters is dropped (even when its JSON would be valid).
- ``done`` (C1.5) is False for ``stop_reason == "tool_use"``, True otherwise;
  ``model`` is the message_start model (sanitized, at most 200 characters), else
  the configured one.
- Errors (C1.7): a missing key / model raise ``not_configured`` /
  ``missing_model`` on the first iteration with zero requests; an HTTP status when
  opening the stream maps exactly like ``chat()`` (code, status, message,
  Retry-After) before any delta, with one request (SDK retries off); a mid-stream
  ``event: error`` is ``provider_unavailable``, a mid-stream timeout ``timeout``,
  another transport failure ``provider_unavailable``, each after the deltas
  already yielded. Errors are raised ``from None``; no body / provider text marker
  reaches ``str(exc)``, ``exc.message`` or any log record (DEBUG included).
- Request (C1.6): exactly ``chat()``'s body plus ``"stream": true`` (model,
  messages, max_tokens = configured ``max_response_tokens``, system when given,
  tools when given, stream; never ``metadata``).
- Retries (C1.9) through ``llm_policy.chat_stream`` and the real client: a
  529/503 when opening, then a good stream, is two requests with the deltas
  yielded once; a failure after the first delta is one request and the error
  propagates.

Security notes:
- The API key is built at runtime; no key literal is in this file.
- The fake wire never forwards anything to a real host.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

import anthropic._base_client as anthropic_base_client
import httpx
import pytest

from admino import llm_policy
from admino.config import LLMConfig
from admino.llm import (
    _MAX_CONTENT_LENGTH,
    LLMClient,
    LLMError,
    LLMResponse,
    LLMStreamDelta,
    missing_model_error,
    not_configured_error,
    provider_status_error,
)
from admino.llm_anthropic import AnthropicClient
from admino.models import LLMMessage, ToolCall

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LABEL: Final = "Claude"
_KEY_ENV: Final = "ANTHROPIC_API_KEY"
_MODEL: Final = "claude-configured-w2"
_MAX_TOKENS: Final = 777
_STREAM_MODEL: Final = "claude-x"
_SYSTEM_PROMPT: Final = "You are admino."

# Unique markers: response-side text that must never leak where it doesn't belong.
_BODY_MARK: Final = "BODYMARK-w2-7f3a"
_EVENT_MARK: Final = "EVENTMARK-w2-91c4"
_WIRE_MARK: Final = "WIREMARK-w2-5d20"
_TOOL_MARK: Final = "TOOLMARK-w2-c0de"
_TEXT_MARK: Final = "TEXTMARK-w2-ab12"
_THINK_MARK: Final = "THINKMARK-w2-0b0e"

# Characters strip_control_chars removes (C1.2), built with chr() so the file stays ASCII.
_NUL: Final = chr(0x00)
_ESC: Final = chr(0x1B)
_NEL: Final = chr(0x85)
_CSI: Final = chr(0x9B)
_RLO: Final = chr(0x202E)
_LRI: Final = chr(0x2066)
_ZWSP: Final = chr(0x200B)
_LSEP: Final = chr(0x2028)
_PSEP: Final = chr(0x2029)
_BOM: Final = chr(0xFEFF)
_REMOVED: Final = frozenset({_NUL, _ESC, _NEL, _CSI, _RLO, _LRI, _ZWSP, _LSEP, _PSEP, _BOM})

_ECHO_TOOL: Final[dict[str, Any]] = {
    "type": "function",
    "function": {
        "name": "echo.say",
        "description": "Say a short text back",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
}


def _api_key() -> str:
    """A fake Anthropic key, concatenated at runtime."""
    return "sk-" + "ant-" + "stream-" + "w2-" + "0" * 24


# ---------------------------------------------------------------------------
# Anthropic Messages SSE wire
# ---------------------------------------------------------------------------


def _frame(event: str, data: dict[str, Any]) -> bytes:
    """One SSE frame as the Messages API sends it."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _message_start(model: str = _STREAM_MODEL) -> bytes:
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


def _block_start(index: int, block: dict[str, Any]) -> bytes:
    """A ``content_block_start`` frame."""
    return _frame(
        "content_block_start",
        {"type": "content_block_start", "index": index, "content_block": block},
    )


def _block_delta(index: int, delta: dict[str, Any]) -> bytes:
    """A ``content_block_delta`` frame."""
    return _frame(
        "content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}
    )


def _block_stop(index: int) -> bytes:
    """A ``content_block_stop`` frame."""
    return _frame("content_block_stop", {"type": "content_block_stop", "index": index})


def _text_delta(index: int, text: str) -> bytes:
    """A ``text_delta`` frame."""
    return _block_delta(index, {"type": "text_delta", "text": text})


def _json_delta(index: int, partial_json: str) -> bytes:
    """An ``input_json_delta`` frame."""
    return _block_delta(index, {"type": "input_json_delta", "partial_json": partial_json})


def _text_block(index: int, *pieces: str) -> list[bytes]:
    """A whole text block: start, one ``text_delta`` per piece, stop."""
    return [
        _block_start(index, {"type": "text", "text": ""}),
        *(_text_delta(index, piece) for piece in pieces),
        _block_stop(index),
    ]


def _tool_block(index: int, name: str, tool_id: str, *fragments: str) -> list[bytes]:
    """A whole tool_use block: start, one ``input_json_delta`` per fragment, stop."""
    return [
        _block_start(index, {"type": "tool_use", "id": tool_id, "name": name, "input": {}}),
        *(_json_delta(index, fragment) for fragment in fragments),
        _block_stop(index),
    ]


def _message_delta(stop_reason: str | None) -> bytes:
    """The ``message_delta`` frame carrying the stop reason."""
    return _frame(
        "message_delta",
        {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": None},
            "usage": {"output_tokens": 15},
        },
    )


def _message_stop() -> bytes:
    """The ``message_stop`` frame."""
    return _frame("message_stop", {"type": "message_stop"})


def _ping() -> bytes:
    """A ``ping`` frame."""
    return _frame("ping", {"type": "ping"})


def _error_event(marker: str) -> bytes:
    """A mid-stream ``event: error`` frame whose provider message carries ``marker``."""
    return _frame(
        "error",
        {"type": "error", "error": {"type": "overloaded_error", "message": f"Overloaded {marker}"}},
    )


def _stream(
    *blocks: Iterable[bytes],
    stop_reason: str | None = "end_turn",
    model: str = _STREAM_MODEL,
) -> list[bytes]:
    """A complete stream: message_start, the blocks' frames, message_delta, message_stop."""
    frames = [_message_start(model)]
    for block in blocks:
        frames.extend(block)
    frames.extend([_message_delta(stop_reason), _message_stop()])
    return frames


def _error_body(message: str, error_type: str = "api_error") -> dict[str, Any]:
    """An Anthropic JSON error body."""
    return {"type": "error", "error": {"type": error_type, "message": message}}


def _message_body(text: str = "Hello!") -> dict[str, Any]:
    """A non-streamed Anthropic ``message`` body (for ``chat()`` comparisons)."""
    return {
        "id": "msg_w2_json",
        "type": "message",
        "role": "assistant",
        "model": _STREAM_MODEL,
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


# ---------------------------------------------------------------------------
# The fake wire
# ---------------------------------------------------------------------------


@dataclass
class _Reply:
    """One scripted answer to a request.

    ``status != 200`` answers ``json_body`` with ``headers``. A 200 with
    ``json_body`` answers that JSON (``chat()``); otherwise it streams ``frames``,
    one chunk each, then raises ``failure`` ("read_timeout", "remote_protocol",
    "read_error") if set. With ``gate`` the stream waits for it after frame
    number ``gate_after``.
    """

    status: int = 200
    frames: list[bytes] = field(default_factory=list)
    json_body: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    failure: str | None = None
    gate: asyncio.Event | None = None
    gate_after: int = 0


class _FrameStream(httpx.AsyncByteStream):
    """A response body that yields SSE frames one by one, then maybe fails."""

    def __init__(self, reply: _Reply, request: httpx.Request) -> None:
        self._reply = reply
        self._request = request

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield each frame; wait at the gate; raise the scripted transport failure."""
        reply = self._reply
        for number, frame in enumerate(reply.frames):
            yield frame
            if reply.gate is not None and number == reply.gate_after:
                await reply.gate.wait()
        if reply.failure == "read_timeout":
            raise httpx.ReadTimeout(f"read timed out {_WIRE_MARK}", request=self._request)
        if reply.failure == "remote_protocol":
            raise httpx.RemoteProtocolError(f"peer closed {_WIRE_MARK}", request=self._request)
        if reply.failure == "read_error":
            raise httpx.ReadError(f"connection reset {_WIRE_MARK}", request=self._request)

    async def aclose(self) -> None:
        """Nothing to release."""


@dataclass(frozen=True)
class _Sent:
    """One recorded outgoing request."""

    method: str
    path: str
    body: dict[str, Any]


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    Scripted replies are used in order; a request beyond the script gets a 418
    (an uncoded error), so an unexpected extra request is visible.
    """

    def __init__(self) -> None:
        self.sent: list[_Sent] = []
        self.replies: list[_Reply] = []

    def queue(self, *replies: _Reply) -> None:
        """Append scripted replies."""
        self.replies.extend(replies)

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it."""
        raw = await request.aread()
        self.sent.append(
            _Sent(method=request.method, path=request.url.path, body=json.loads(raw or b"{}"))
        )
        if not self.replies:
            body = _error_body("unexpected extra request")
            return httpx.Response(418, json=body, request=request)
        reply = self.replies.pop(0)
        if reply.status != 200 or reply.json_body is not None:
            return httpx.Response(
                reply.status, headers=reply.headers, json=reply.json_body, request=request
            )
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream", **reply.headers},
            stream=_FrameStream(reply, request),
            request=request,
        )


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _anthropic_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured key; no base-URL or auth-token override from the environment."""
    monkeypatch.setenv(_KEY_ENV, _api_key())
    for name in ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_sdk_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """An implementation that let the SDK retry would fail fast instead of sleeping."""

    async def no_sleep(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(anthropic_base_client.AsyncAPIClient, "_sleep_for_retry", no_sleep)


@pytest.fixture()
def wire(monkeypatch: pytest.MonkeyPatch) -> _Wire:
    """Route every ``httpx.AsyncClient.send`` through the recording fake wire."""
    fake = _Wire()

    async def send(_client: httpx.AsyncClient, request: httpx.Request, **_: Any) -> httpx.Response:
        return await fake.send(request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    return fake


@pytest.fixture()
def debug_logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """Capture every log record at DEBUG (root, admino, the SDK and httpx)."""
    caplog.set_level(logging.DEBUG)
    for name in ("admino", "anthropic", "httpx", "httpcore"):
        caplog.set_level(logging.DEBUG, logger=name)
    return caplog


def _config(model: str | None = _MODEL) -> LLMConfig:
    """A real LLMConfig selecting Anthropic."""
    return LLMConfig(
        provider="anthropic",
        anthropic_model=model,
        timeout_s=5,
        max_response_tokens=_MAX_TOKENS,
    )


@pytest.fixture()
async def client(wire: _Wire) -> AsyncIterator[AnthropicClient]:
    """An AnthropicClient on the fake wire, closed after the test."""
    llm = AnthropicClient(_config())
    yield llm
    await llm.close()


def _messages(text: str = "Hi") -> list[LLMMessage]:
    """A one-message conversation."""
    return [LLMMessage(role="user", content=text)]


async def _run(
    llm: AnthropicClient,
    messages: list[LLMMessage] | None = None,
    tools: list[dict[str, Any]] | None = None,
) -> tuple[list[str], LLMResponse]:
    """Drain ``chat_stream``; check the C1.1 shape; return the delta texts and the final."""
    items = [item async for item in llm.chat_stream(messages or _messages(), tools)]
    assert items, "chat_stream yielded nothing"
    *deltas, final = items
    assert type(final) is LLMResponse
    assert all(type(delta) is LLMStreamDelta and delta.content for delta in deltas), deltas
    texts = [delta.content for delta in deltas if isinstance(delta, LLMStreamDelta)]
    assert final.content == "".join(texts)
    return texts, final


async def _until_error(stream: AsyncIterator[Any]) -> tuple[list[Any], LLMError]:
    """Collect items until the stream raises; return them and the LLMError."""
    seen: list[Any] = []
    with pytest.raises(LLMError) as excinfo:
        async for item in stream:
            seen.append(item)
    return seen, excinfo.value


def _leak_sites(marker: str, error: LLMError, logs: pytest.LogCaptureFixture) -> list[str]:
    """Where ``marker`` shows up: the exception text, its message, any log record."""
    sites: list[str] = []
    if marker in str(error) or any(marker in str(arg) for arg in error.args):
        sites.append("str(exc)")
    if marker in error.message:
        sites.append("exc.message")
    if marker in logs.text or any(marker in record.getMessage() for record in logs.records):
        sites.append("logs")
    return sites


def _view(error: LLMError) -> tuple[Any, ...]:
    """The comparable parts of an LLMError."""
    return (error.code, error.status_code, error.message, error.retry_after_s, error.user_facing)


def _first_difference(actual: str, expected: str) -> tuple[int, int, str, str] | None:
    """None when equal, else (len actual, first differing index, both 20-char windows)."""
    if actual == expected:
        return None
    index = next(
        (i for i, (a, b) in enumerate(zip(actual, expected, strict=False)) if a != b),
        min(len(actual), len(expected)),
    )
    return len(actual), index, actual[index : index + 20], expected[index : index + 20]


def _tool_json(args: object) -> str:
    """The JSON text a model would stream for ``args``."""
    return json.dumps(args)


# ===========================================================================
# 1. Protocol and stream shape
# ===========================================================================


def test_anthropic_stream_client_satisfies_llm_client_protocol() -> None:
    """LLMClient declares chat_stream and AnthropicClient still satisfies it (C1)."""
    llm = AnthropicClient(_config())
    assert "chat_stream" in dir(LLMClient)
    assert callable(getattr(llm, "chat_stream", None))
    assert isinstance(llm, LLMClient)


async def test_anthropic_stream_yields_text_deltas_then_one_final_response(
    client: AnthropicClient, wire: _Wire
) -> None:
    wire.queue(_Reply(frames=_stream(_text_block(0, "Hel", "lo", ", world"))))
    texts, final = await _run(client)
    assert "".join(texts) == "Hello, world"
    assert final.tool_calls == []
    assert final.done is True
    assert final.model == _STREAM_MODEL


async def test_anthropic_stream_yields_delta_before_rest_of_stream_arrives(
    client: AnthropicClient, wire: _Wire
) -> None:
    """The first delta comes out while the provider hasn't sent the rest yet."""
    gate = asyncio.Event()
    frames = _stream(_text_block(0, "Hel", "lo"))
    # frames[2] is the "Hel" text_delta: the body stalls after it until the gate opens.
    wire.queue(_Reply(frames=frames, gate=gate, gate_after=2))
    stream = client.chat_stream(_messages())
    try:
        first = await asyncio.wait_for(anext(stream), timeout=5)
    finally:
        gate.set()
    rest = [item async for item in stream]
    assert type(first) is LLMStreamDelta
    assert first.content
    assert "Hel".startswith(first.content)
    texts = [first.content, *(item.content for item in rest[:-1])]
    assert "".join(texts) == "Hello"
    assert type(rest[-1]) is LLMResponse
    assert rest[-1].content == "Hello"


async def test_anthropic_stream_forwards_text_delta_only(
    client: AnthropicClient, wire: _Wire
) -> None:
    """Ping, thinking/signature deltas, unknown events and unknown delta types never show."""
    frames = [
        _message_start(),
        _ping(),
        _frame("future_event", {"type": "future_event", "text": f"event {_THINK_MARK}"}),
        _block_start(0, {"type": "thinking", "thinking": "", "signature": ""}),
        _block_delta(0, {"type": "thinking_delta", "thinking": f"reasoning {_THINK_MARK}"}),
        _block_delta(0, {"type": "signature_delta", "signature": f"sig{_THINK_MARK}"}),
        _block_stop(0),
        _block_start(1, {"type": "text", "text": ""}),
        _text_delta(1, "Visible "),
        _ping(),
        # An unknown delta type with a text field: the SDK parses it as a TextDelta-shaped
        # object, but only type "text_delta" is answer text.
        _block_delta(1, {"type": "future_delta", "text": f"hidden {_THINK_MARK}"}),
        _block_delta(1, {"type": "citations_delta", "citation": {"cited_text": _THINK_MARK}}),
        _text_delta(1, "answer"),
        _block_stop(1),
        _message_delta("end_turn"),
        _message_stop(),
    ]
    wire.queue(_Reply(frames=frames))
    texts, final = await _run(client)
    assert "".join(texts) == "Visible answer"
    assert _THINK_MARK not in final.content


async def test_anthropic_stream_sanitizes_deltas_across_event_boundaries(
    client: AnthropicClient, wire: _Wire
) -> None:
    pieces = (
        "Hi" + _ESC,
        "[31mred" + _NUL,
        _CSI + "2J" + _NEL,
        _RLO + "evil" + _LRI,
        _ZWSP + _LSEP + _PSEP + _BOM,
        _NUL,
        "\tok\r\n",
    )
    wire.queue(_Reply(frames=_stream(_text_block(0, *pieces))))
    texts, final = await _run(client)
    assert final.content == "Hi[31mred2Jevil\tok\r\n"
    assert not any(set(text) & _REMOVED for text in texts)


# ===========================================================================
# 2. Content cap
# ===========================================================================


async def test_anthropic_stream_caps_content_after_sanitizing_and_reads_to_end(
    client: AnthropicClient, wire: _Wire
) -> None:
    """65536 sanitized characters; a tool call and the stop reason after the cap count."""
    frames = _stream(
        _text_block(0, _NUL * 1000 + "a" * 40_000, "b" * 30_000, "c" * 50 + _TEXT_MARK),
        _tool_block(1, "gmail__search", "toolu_after_cap", _tool_json({"query": "late"})),
        stop_reason="tool_use",
    )
    wire.queue(_Reply(frames=frames))
    texts, final = await _run(client)
    expected = "a" * 40_000 + "b" * (_MAX_CONTENT_LENGTH - 40_000)
    assert _first_difference("".join(texts), expected) is None
    assert not any("c" in text for text in texts)
    assert final.tool_calls == [
        ToolCall(
            tool="gmail", action="search", args={"query": "late"}, tool_call_id="toolu_after_cap"
        )
    ]
    assert final.done is False


# ===========================================================================
# 3. Tool calls
# ===========================================================================


async def test_anthropic_stream_tool_use_partial_json_split_anywhere_is_reassembled(
    client: AnthropicClient, wire: _Wire
) -> None:
    """One fragment per character: splits inside strings and inside escapes."""
    args = {"query": 'a"b' + chr(0xE9) + "\n c " + _TOOL_MARK, "limit": 5}
    raw = _tool_json(args)
    assert "\\u00e9" in raw and '\\"' in raw and "\\n" in raw
    frames = _stream(_tool_block(0, "gmail__search", "toolu_01split", *raw), stop_reason="tool_use")
    wire.queue(_Reply(frames=frames))
    texts, final = await _run(client)
    assert texts == []
    assert final.tool_calls == [
        ToolCall(tool="gmail", action="search", args=args, tool_call_id="toolu_01split")
    ]
    assert final.done is False


async def test_anthropic_stream_tool_use_blocks_interleaved_with_text_keep_index_order(
    client: AnthropicClient, wire: _Wire
) -> None:
    query = {"query": f"invoices {_TOOL_MARK}"}
    store = {"key": "note", "value": f"v {_TOOL_MARK}"}
    frames = _stream(
        _text_block(0, "Let me ", "check. "),
        _tool_block(1, "gmail__search", "toolu_a", '{"query": "inv', f'oices {_TOOL_MARK}"}}'),
        _text_block(2, "Also "),
        _tool_block(3, "google_calendar__list", "toolu_b"),
        _tool_block(4, "memory__store", "toolu_c", _tool_json(store)[:9], _tool_json(store)[9:]),
        stop_reason="tool_use",
    )
    wire.queue(_Reply(frames=frames))
    texts, final = await _run(client)
    assert final.tool_calls == [
        ToolCall(tool="gmail", action="search", args=query, tool_call_id="toolu_a"),
        ToolCall(tool="google_calendar", action="list", args={}, tool_call_id="toolu_b"),
        ToolCall(tool="memory", action="store", args=store, tool_call_id="toolu_c"),
    ]
    assert final.content.replace("\n", "") == "Let me check. Also "
    assert not any(_TOOL_MARK in text or "gmail" in text or "{" in text for text in texts)


async def test_anthropic_stream_tool_fragments_are_keyed_by_block_index(
    client: AnthropicClient, wire: _Wire
) -> None:
    """Fragments of two open tool_use blocks alternate; each lands on its own block."""
    frames = _stream(
        _text_block(0, "Checking."),
        [
            _block_start(
                1, {"type": "tool_use", "id": "toolu_x", "name": "gmail__search", "input": {}}
            ),
            _block_start(
                2, {"type": "tool_use", "id": "toolu_y", "name": "memory__store", "input": {}}
            ),
            _json_delta(1, '{"query"'),
            _json_delta(2, '{"key": "k"'),
            _json_delta(1, ': "q"}'),
            _json_delta(2, ', "value": "v"}'),
            _block_stop(1),
            _block_stop(2),
        ],
        stop_reason="tool_use",
    )
    wire.queue(_Reply(frames=frames))
    texts, final = await _run(client)
    assert "".join(texts) == "Checking."
    assert final.tool_calls == [
        ToolCall(tool="gmail", action="search", args={"query": "q"}, tool_call_id="toolu_x"),
        ToolCall(
            tool="memory", action="store", args={"key": "k", "value": "v"}, tool_call_id="toolu_y"
        ),
    ]


async def test_anthropic_stream_tool_use_without_fragments_has_empty_arguments(
    client: AnthropicClient, wire: _Wire
) -> None:
    """No input_json_delta, or only an empty one, means {} arguments."""
    frames = _stream(
        _tool_block(0, "google_calendar__list", "toolu_none"),
        _tool_block(1, "memory__list", "toolu_empty", ""),
        stop_reason="tool_use",
    )
    wire.queue(_Reply(frames=frames))
    _, final = await _run(client)
    assert final.tool_calls == [
        ToolCall(tool="google_calendar", action="list", args={}, tool_call_id="toolu_none"),
        ToolCall(tool="memory", action="list", args={}, tool_call_id="toolu_empty"),
    ]


_INVALID_TOOL_CALLS: Final[dict[str, tuple[str, str]]] = {
    "bad_json": ("gmail__search", '{"query": "' + _TOOL_MARK),
    "non_object": ("gmail__search", _tool_json([_TOOL_MARK, 2])),
    "depth_5": ("gmail__search", _tool_json({"q": {"a": {"b": {"c": _TOOL_MARK}}}})),
    "keys_33": (
        "gmail__search",
        _tool_json({f"k{i}": _TOOL_MARK for i in range(33)}),
    ),
    "string_2049": (
        "gmail__search",
        _tool_json({"q": _TOOL_MARK + "x" * (2049 - len(_TOOL_MARK))}),
    ),
    "dumps_over_16384": (
        "gmail__search",
        _tool_json({f"k{i}": _TOOL_MARK + "y" * (2000 - len(_TOOL_MARK)) for i in range(9)}),
    ),
    "name_not_tool_action": ("gmailsearch", _tool_json({"q": _TOOL_MARK})),
}


@pytest.mark.parametrize(
    ("name", "partial_json"), list(_INVALID_TOOL_CALLS.values()), ids=list(_INVALID_TOOL_CALLS)
)
async def test_anthropic_stream_invalid_tool_call_dropped_valid_ones_kept(
    client: AnthropicClient,
    wire: _Wire,
    debug_logs: pytest.LogCaptureFixture,
    name: str,
    partial_json: str,
) -> None:
    """The invalid call goes; the calls before and after it stay; its args never hit a log."""
    alpha = {"query": "alpha"}
    beta = {"key": "beta", "value": "v"}
    frames = _stream(
        _tool_block(0, "gmail__search", "toolu_a", _tool_json(alpha)),
        _tool_block(1, name, "toolu_bad", partial_json[:7], partial_json[7:]),
        _tool_block(2, "memory__store", "toolu_b", _tool_json(beta)),
        stop_reason="tool_use",
    )
    wire.queue(_Reply(frames=frames))
    _, final = await _run(client)
    assert final.tool_calls == [
        ToolCall(tool="gmail", action="search", args=alpha, tool_call_id="toolu_a"),
        ToolCall(tool="memory", action="store", args=beta, tool_call_id="toolu_b"),
    ]
    assert _TOOL_MARK not in debug_logs.text


async def test_anthropic_stream_keeps_only_first_128_tool_use_blocks(
    client: AnthropicClient, wire: _Wire
) -> None:
    blocks = [
        _tool_block(i, "memory__get", f"toolu_{i:03d}", _tool_json({"key": f"k{i}"}))
        for i in range(130)
    ]
    wire.queue(_Reply(frames=_stream(*blocks, stop_reason="tool_use")))
    _, final = await _run(client)
    assert final.tool_calls == [
        ToolCall(tool="memory", action="get", args={"key": f"k{i}"}, tool_call_id=f"toolu_{i:03d}")
        for i in range(128)
    ]


async def test_anthropic_stream_drops_tool_call_over_65536_argument_chars(
    client: AnthropicClient, wire: _Wire
) -> None:
    """Its JSON would parse to a small valid object, but accumulation stops at 65536."""
    padding = [" " * 4096] * 17  # 69632 characters of JSON whitespace
    frames = _stream(
        _tool_block(0, "gmail__search", "toolu_ok", _tool_json({"query": "ok"})),
        _tool_block(1, "gmail__search", "toolu_padded", '{"query": "padded"', *padding, "}"),
        stop_reason="tool_use",
    )
    wire.queue(_Reply(frames=frames))
    _, final = await _run(client)
    assert final.tool_calls == [
        ToolCall(tool="gmail", action="search", args={"query": "ok"}, tool_call_id="toolu_ok")
    ]


async def test_anthropic_stream_never_logs_text_or_tool_arguments(
    client: AnthropicClient, wire: _Wire, debug_logs: pytest.LogCaptureFixture
) -> None:
    frames = _stream(
        _text_block(0, f"Answer {_TEXT_MARK} "),
        _tool_block(1, "gmail__search", "toolu_v", _tool_json({"query": _TOOL_MARK})),
        _tool_block(2, "gmail__search", "toolu_i", '{"query": "' + _TOOL_MARK),
        stop_reason="tool_use",
    )
    wire.queue(_Reply(frames=frames))
    texts, final = await _run(client)
    assert _TEXT_MARK in "".join(texts)
    assert len(final.tool_calls) == 1
    assert _TEXT_MARK not in debug_logs.text
    assert _TOOL_MARK not in debug_logs.text


# ===========================================================================
# 4. done and model
# ===========================================================================


@pytest.mark.parametrize(
    ("stop_reason", "done"),
    [("tool_use", False), ("end_turn", True), ("max_tokens", True), ("stop_sequence", True)],
)
async def test_anthropic_stream_done_follows_stop_reason(
    client: AnthropicClient, wire: _Wire, stop_reason: str, done: bool
) -> None:
    frames = _stream(
        _text_block(0, "ok"),
        _tool_block(1, "memory__list", "toolu_d", "{}"),
        stop_reason=stop_reason,
    )
    wire.queue(_Reply(frames=frames))
    _, final = await _run(client)
    assert final.done is done


async def test_anthropic_stream_model_from_message_start_is_sanitized_and_capped(
    client: AnthropicClient, wire: _Wire
) -> None:
    raw_model = _RLO + "claude-" + _NUL + "m" * 300
    wire.queue(_Reply(frames=_stream(_text_block(0, "ok"), model=raw_model)))
    _, final = await _run(client)
    assert final.model == ("claude-" + "m" * 300)[:200]


async def test_anthropic_stream_model_falls_back_to_configured_model(
    client: AnthropicClient, wire: _Wire
) -> None:
    wire.queue(_Reply(frames=_stream(_text_block(0, "ok"), model="")))
    _, final = await _run(client)
    assert final.model == _MODEL


# ===========================================================================
# 5. Setup errors
# ===========================================================================


async def test_anthropic_stream_missing_key_is_not_configured_before_any_request(
    wire: _Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(_KEY_ENV, raising=False)
    llm = AnthropicClient(_config())
    try:
        stream = llm.chat_stream(_messages())
        with pytest.raises(LLMError) as excinfo:
            await anext(stream)
    finally:
        await llm.close()
    assert excinfo.value.code == "not_configured"
    assert excinfo.value.message == not_configured_error(_LABEL, _KEY_ENV).message
    assert wire.sent == []


async def test_anthropic_stream_missing_model_is_missing_model_before_any_request(
    wire: _Wire,
) -> None:
    llm = AnthropicClient(_config(model=None))
    try:
        stream = llm.chat_stream(_messages())
        with pytest.raises(LLMError) as excinfo:
            await anext(stream)
    finally:
        await llm.close()
    assert excinfo.value.code == "missing_model"
    assert excinfo.value.message == missing_model_error(_LABEL).message
    assert wire.sent == []


# ===========================================================================
# 6. HTTP errors when opening the stream
# ===========================================================================

# id -> (status, headers, error type, provider message, expected (code, retry_after_s))
_OPEN_ERRORS: Final[dict[str, tuple[int, dict[str, str], str, str, tuple[Any, Any]]]] = {
    "401": (401, {}, "authentication_error", "invalid x-api-key", ("not_configured", None)),
    "403": (403, {}, "permission_error", "forbidden", ("not_configured", None)),
    "404": (404, {}, "not_found_error", "model: nope", ("missing_model", None)),
    "429": (429, {"retry-after": "7"}, "rate_limit_error", "slow down", ("rate_limited", 7.0)),
    "500": (500, {}, "api_error", "internal", ("provider_unavailable", None)),
    "503": (503, {}, "api_error", "unavailable", ("provider_unavailable", None)),
    "529": (529, {"retry-after": "3"}, "overloaded_error", "busy", ("provider_unavailable", 3.0)),
    "413": (413, {}, "request_too_large", "request too large", ("context_too_long", None)),
    "400-prompt-too-long": (
        400,
        {},
        "invalid_request_error",
        "prompt is too long: 210000 tokens > 200000 maximum",
        ("context_too_long", None),
    ),
    "400-other": (400, {}, "invalid_request_error", "messages: bad role", (None, None)),
    "422": (422, {}, "invalid_request_error", "unprocessable", (None, None)),
}


@pytest.mark.parametrize(
    ("status", "headers", "error_type", "provider_message", "expected"),
    list(_OPEN_ERRORS.values()),
    ids=list(_OPEN_ERRORS),
)
async def test_anthropic_stream_open_http_error_maps_like_chat(
    client: AnthropicClient,
    wire: _Wire,
    debug_logs: pytest.LogCaptureFixture,
    status: int,
    headers: dict[str, str],
    error_type: str,
    provider_message: str,
    expected: tuple[Any, Any],
) -> None:
    """Same LLMError as chat(), before any delta, one request, no body text anywhere."""
    body = _error_body(f"{provider_message} {_BODY_MARK}", error_type)
    wire.queue(_Reply(status=status, headers=headers, json_body=body))
    seen, error = await _until_error(client.chat_stream(_messages()))
    stream_requests = len(wire.sent)

    wire.queue(_Reply(status=status, headers=headers, json_body=body))
    with pytest.raises(LLMError) as chat_error:
        await client.chat(_messages())

    assert seen == []
    assert stream_requests == 1
    assert (error.code, error.retry_after_s) == expected
    assert error.status_code == status
    assert _view(error) == _view(chat_error.value)
    assert error.user_facing is (expected[0] is not None)
    assert error.__cause__ is None
    assert error.__suppress_context__ is True
    assert _leak_sites(_BODY_MARK, error, debug_logs) == []


# ===========================================================================
# 7. Mid-stream failures
# ===========================================================================


async def test_anthropic_stream_error_event_mid_stream_is_provider_unavailable(
    client: AnthropicClient, wire: _Wire, debug_logs: pytest.LogCaptureFixture
) -> None:
    frames = [
        _message_start(),
        *_text_block(0, "Hel", "lo"),
        _error_event(_EVENT_MARK),
    ]
    wire.queue(_Reply(frames=frames))
    seen, error = await _until_error(client.chat_stream(_messages()))
    assert all(type(item) is LLMStreamDelta for item in seen)
    assert "".join(item.content for item in seen) == "Hello"
    assert error.code == "provider_unavailable"
    assert error.message == provider_status_error(_LABEL, None, key_env=_KEY_ENV).message
    assert error.__cause__ is None
    assert _leak_sites(_EVENT_MARK, error, debug_logs) == []
    assert len(wire.sent) == 1


@pytest.mark.parametrize(
    ("failure", "code", "timed_out"),
    [
        ("read_timeout", "timeout", True),
        ("remote_protocol", "provider_unavailable", False),
        ("read_error", "provider_unavailable", False),
    ],
)
async def test_anthropic_stream_transport_failure_mid_stream_maps_to_code(
    client: AnthropicClient,
    wire: _Wire,
    debug_logs: pytest.LogCaptureFixture,
    failure: str,
    code: str,
    timed_out: bool,
) -> None:
    frames = [_message_start(), _block_start(0, {"type": "text", "text": ""}), _text_delta(0, "Hi")]
    wire.queue(_Reply(frames=frames, failure=failure))
    seen, error = await _until_error(client.chat_stream(_messages()))
    assert [type(item) for item in seen] == [LLMStreamDelta]
    assert seen[0].content == "Hi"
    assert error.code == code
    expected = provider_status_error(_LABEL, None, key_env=_KEY_ENV, timed_out=timed_out)
    assert error.message == expected.message
    assert error.__cause__ is None
    assert _leak_sites(_WIRE_MARK, error, debug_logs) == []
    assert len(wire.sent) == 1


# ===========================================================================
# 8. Request
# ===========================================================================


async def test_anthropic_stream_request_body_is_chat_body_plus_stream(
    client: AnthropicClient, wire: _Wire
) -> None:
    """System moved to ``system``, tools converted, max_tokens = configured cap."""
    messages = [
        LLMMessage(role="system", content=_SYSTEM_PROMPT),
        LLMMessage(role="user", content="first"),
        LLMMessage(role="assistant", content="reply"),
        LLMMessage(role="user", content="second"),
    ]
    tools = [_ECHO_TOOL]
    wire.queue(_Reply(json_body=_message_body()))
    await client.chat(messages, tools)
    wire.queue(_Reply(frames=_stream(_text_block(0, "ok"))))
    await _run(client, messages, tools)

    assert len(wire.sent) == 2
    chat_sent, stream_sent = wire.sent
    assert (stream_sent.method, stream_sent.path) == ("POST", "/v1/messages")
    assert stream_sent.body == {**chat_sent.body, "stream": True}
    assert set(stream_sent.body) == {"model", "messages", "max_tokens", "system", "tools", "stream"}
    assert stream_sent.body["stream"] is True
    assert stream_sent.body["max_tokens"] == _MAX_TOKENS
    assert stream_sent.body["model"] == _MODEL
    assert stream_sent.body["system"] == _SYSTEM_PROMPT
    assert all(message["role"] != "system" for message in stream_sent.body["messages"])
    assert [tool["name"] for tool in stream_sent.body["tools"]] == ["echo__say"]


async def test_anthropic_stream_request_without_system_or_tools_sends_only_core_keys(
    client: AnthropicClient, wire: _Wire
) -> None:
    wire.queue(_Reply(frames=_stream(_text_block(0, "ok"))))
    await _run(client, _messages("hello"))
    assert len(wire.sent) == 1
    body = wire.sent[0].body
    assert set(body) == {"model", "messages", "max_tokens", "stream"}
    assert body["stream"] is True
    assert body["messages"] == [{"role": "user", "content": "hello"}]


# ===========================================================================
# 9. Retries through llm_policy.chat_stream with the real client
# ===========================================================================


@pytest.fixture()
def policy_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the policy's retry sleeps instead of sleeping."""
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(llm_policy, "_sleep", fake_sleep)
    monkeypatch.setattr(llm_policy, "_random", lambda: 0.5)
    return slept


@pytest.mark.parametrize("status", [529, 503])
async def test_anthropic_stream_policy_retries_open_failure_then_streams_once(
    client: AnthropicClient, wire: _Wire, policy_sleeps: list[float], status: int
) -> None:
    wire.queue(
        _Reply(status=status, json_body=_error_body(f"busy {_BODY_MARK}", "overloaded_error")),
        _Reply(frames=_stream(_text_block(0, "Hel", "lo"))),
    )
    items = [
        item
        async for item in llm_policy.chat_stream(
            client, _messages(), None, data_residency=False, max_retries=2
        )
    ]
    *deltas, final = items
    assert len(wire.sent) == 2
    assert wire.sent[0].body == wire.sent[1].body
    assert all(type(item) is LLMStreamDelta for item in deltas)
    assert "".join(item.content for item in deltas) == "Hello"
    assert type(final) is LLMResponse
    assert final.content == "Hello"
    assert len(policy_sleeps) == 1


@pytest.mark.parametrize(
    ("failure", "code"), [("error_event", "provider_unavailable"), ("read_timeout", "timeout")]
)
async def test_anthropic_stream_policy_failure_after_first_delta_propagates(
    client: AnthropicClient,
    wire: _Wire,
    policy_sleeps: list[float],
    failure: str,
    code: str,
) -> None:
    frames = [
        _message_start(),
        _block_start(0, {"type": "text", "text": ""}),
        _text_delta(0, "Hel"),
    ]
    if failure == "error_event":
        wire.queue(_Reply(frames=[*frames, _error_event(_EVENT_MARK)]))
    else:
        wire.queue(_Reply(frames=frames, failure=failure))
    wire.queue(_Reply(frames=_stream(_text_block(0, "never sent"))))
    seen, error = await _until_error(
        llm_policy.chat_stream(client, _messages(), None, data_residency=False, max_retries=3)
    )
    assert error.code == code
    assert [type(item) for item in seen] == [LLMStreamDelta]
    assert seen[0].content == "Hel"
    assert len(wire.sent) == 1
    assert policy_sleeps == []
