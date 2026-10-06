"""LLM output sanitization at the client layer (GH-25: contract C2, C3.1, C3.2; decisions D4-D7).

Every client is built from a real ``LLMConfig`` and drives its REAL SDK
(``openai`` for Infomaniak, vLLM and OpenAI; ``anthropic`` for Claude) against a
fake wire: ``httpx.AsyncClient.send`` is replaced by a scripted route that
answers with a JSON body (``chat()``) or an SSE body produced frame by frame
(``chat_stream()``). Nothing reaches a real host.

What these tests pin:

1. ``admino.llm.sanitize_tool_args`` (C2, D5), as a unit: every str at any depth
   (keys, values, list items) gets each lone surrogate replaced by exactly one
   U+FFFD, THEN ``strip_control_chars`` removes NUL, ESC (an ANSI sequence keeps
   its printable rest), the other C0 controls (tab / LF / CR kept), C1 (NEL,
   CSI), bidi overrides and isolates, zero-width characters, U+2028 / U+2029 and
   the BOM. Valid characters (an emoji, U+D7FF, U+E000, U+FFFD) stay. Non-str
   leaves keep their type and value. The input is never mutated and the result
   is a new structure. When two keys clean to the same key, the later one wins.
2. Tool-call arguments per provider and path: the OpenAI-compatible arguments
   JSON string (and chat()'s object form), Anthropic's ``input`` object and
   ``partial_json`` fragments carry ESC, NUL, RLO, ZWSP and JSON-escaped lone
   surrogates in a top-level value, a nested value, a list item and a key; the
   returned ``ToolCall.args`` are cleaned exactly as in 1. Stream fragments are
   cut inside every escape sequence. ``admino.llm.parse_tool_calls`` cleans the
   same way. The bounds are checked on the decoded arguments BEFORE cleaning (a
   2048-character top-level string holding control characters is accepted and
   cleaned; 2049 raw characters are dropped by the parser even though they
   clean to fewer).
3. Text per provider and path (D6, regression guards for every provider
   including Infomaniak): ANSI ESC / CSI, NUL, C0, C1, bidi, zero-width,
   U+2028 / U+2029, BOM and lone surrogates removed, tab / LF / CR and an emoji
   kept; the stream invariant ``final.content == "".join(deltas)``.
4. ``LLMResponse.truncated`` (C3.2, D7): True for ``finish_reason == "length"``
   and Anthropic ``stop_reason == "max_tokens"``, and when the 65536-character
   cap (counted after sanitizing) dropped text, in both paths; False for every
   other stop reason (None included), for exactly 65536 characters after
   sanitizing and when sanitizing brought the text back under the cap.
   Infomaniak's reasoning never counts. The client never cuts the content at a
   word: that is the agent's job.
5. A well-formed but unregistered ``foo.bar`` call comes back as
   ``ToolCall(tool="foo", action="bar")`` in every provider and path (D4: the
   registry rejects it, not the LLM layer).
6. Logs: no argument value, argument key or answer text in any log record
   (DEBUG capture) on these paths.

Security notes:
- Keys are built at runtime (``tests.credential_keys``); no key literal here.
- Control characters and surrogates are built with ``chr()``: no invisible or
  escaped character lives in this source.
- New code (``sanitize_tool_args``, ``LLMResponse.truncated``) is imported or
  read lazily so the module collects before the implementation exists.
"""

from __future__ import annotations

import copy
import itertools
import json
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import anthropic._base_client as anthropic_base_client
import httpx
import openai._base_client as openai_base_client
import pytest

from admino.config import LLMConfig
from admino.llm import LLMResponse, LLMStreamDelta, parse_tool_calls
from admino.llm_anthropic import AnthropicClient
from admino.llm_infomaniak import InfomaniakClient
from admino.llm_openai import OpenAIClient
from admino.llm_vllm import VLLMClient
from admino.models import LLMMessage
from tests.credential_keys import api_key

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Sequence

    from admino.models import ToolCall

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENAI_COMPATIBLE: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak")
ALL_PROVIDERS: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak", "anthropic")

_MAX_CONTENT: Final = 65536
_MAX_TOKENS: Final = 777
_IK_PRODUCT_ID: Final = "7539"
_STREAM_MODEL: Final = "wire-w1-model"

_OPENAI_KEY: Final = api_key("sk-", 48, seed=2501).text
_ANTHROPIC_KEY: Final = api_key("sk-" + "ant-", 48, seed=2502).text
_IK_TOKEN: Final = api_key("ik-", 40, seed=2503).text

_THINK_OPEN: Final = "<think>"
_THINK_CLOSE: Final = "</think>"

# Characters, built with chr() (no escape or invisible character lives in the source).
_NUL: Final = chr(0x00)
_SOH: Final = chr(0x01)
_BEL: Final = chr(0x07)
_BS: Final = chr(0x08)
_TAB: Final = chr(0x09)
_LF: Final = chr(0x0A)
_VT: Final = chr(0x0B)
_FF: Final = chr(0x0C)
_CR: Final = chr(0x0D)
_SO: Final = chr(0x0E)
_ESC: Final = chr(0x1B)
_US: Final = chr(0x1F)
_C1_FIRST: Final = chr(0x80)
_NEL: Final = chr(0x85)
_CSI: Final = chr(0x9B)
_C1_LAST: Final = chr(0x9F)
_ZWSP: Final = chr(0x200B)
_ZWNJ: Final = chr(0x200C)
_ZWJ: Final = chr(0x200D)
_LSEP: Final = chr(0x2028)
_PSEP: Final = chr(0x2029)
_LRE: Final = chr(0x202A)
_RLE: Final = chr(0x202B)
_PDF: Final = chr(0x202C)
_LRO: Final = chr(0x202D)
_RLO: Final = chr(0x202E)
_LRI: Final = chr(0x2066)
_RLI: Final = chr(0x2067)
_FSI: Final = chr(0x2068)
_PDI: Final = chr(0x2069)
_BOM: Final = chr(0xFEFF)
_HIGH_FIRST: Final = chr(0xD800)
_HIGH_LAST: Final = chr(0xDBFF)
_LOW_FIRST: Final = chr(0xDC00)
_LOW_LAST: Final = chr(0xDFFF)
_BEFORE_SURROGATES: Final = chr(0xD7FF)
_AFTER_SURROGATES: Final = chr(0xE000)
_FFFD: Final = chr(0xFFFD)
_GRIN: Final = chr(0x1F600)

# Every character class strip_control_chars removes (D5), one representative each
# plus the bounds of each range.
_REMOVED: Final[dict[str, str]] = {
    "NUL": _NUL,
    "SOH": _SOH,
    "BEL": _BEL,
    "BS": _BS,
    "VT": _VT,
    "FF": _FF,
    "SO": _SO,
    "ESC": _ESC,
    "US": _US,
    "U+0080": _C1_FIRST,
    "NEL": _NEL,
    "CSI": _CSI,
    "U+009F": _C1_LAST,
    "LRE": _LRE,
    "RLE": _RLE,
    "PDF": _PDF,
    "LRO": _LRO,
    "RLO": _RLO,
    "LRI": _LRI,
    "RLI": _RLI,
    "FSI": _FSI,
    "PDI": _PDI,
    "ZWSP": _ZWSP,
    "ZWNJ": _ZWNJ,
    "ZWJ": _ZWJ,
    "LSEP": _LSEP,
    "PSEP": _PSEP,
    "BOM": _BOM,
}
_SURROGATES: Final[dict[str, str]] = {
    "U+D800": _HIGH_FIRST,
    "U+DBFF": _HIGH_LAST,
    "U+DC00": _LOW_FIRST,
    "U+DFFF": _LOW_LAST,
}
_BANNED: Final = frozenset(_REMOVED.values()) | frozenset(_SURROGATES.values())

# Tool arguments with something to clean in a top-level value, a nested value, a
# list item and a key. No high surrogate directly precedes a low one inside one
# string, so JSON can never decode them as a pair (the emoji is a real pair).
# "long" is a top-level string of exactly 2048 decoded characters (the bound):
# accepted, because the bounds are checked before cleaning.
_DIRTY_ARGS: Final[dict[str, Any]] = {
    "query": (
        "find "
        + _ESC
        + "[31mred"
        + _ESC
        + "[0m"
        + _NUL
        + " mail"
        + _RLO
        + "txt"
        + _ZWSP
        + "."
        + _HIGH_FIRST
        + "x "
        + _GRIN
    ),
    "nested": {
        "inner": "in" + _BOM + "ner" + _LOW_LAST + _CSI + "2J" + _NEL + "end",
        "tags": ["t" + _LSEP + "1", 2, True, None, 1.5, _PSEP + _LRI + "t2" + _PDI],
    },
    "items": [
        "p" + _NUL + "q",
        _LOW_FIRST + "r" + _HIGH_LAST,
        {"deep" + _ESC: "d" + _ZWJ + "v"},
        7,
        False,
    ],
    "k" + _ESC + "ey" + _ZWSP + _HIGH_FIRST: "val" + _US + "ue",
    "kept": "a" + _TAB + "b" + _LF + "c" + _CR + "d",
    "long": "L" * 2000 + _NUL * 24 + _ESC * 24,
}
_CLEAN_ARGS: Final[dict[str, Any]] = {
    "query": "find [31mred[0m mailtxt." + _FFFD + "x " + _GRIN,
    "nested": {
        "inner": "inner" + _FFFD + "2Jend",
        "tags": ["t1", 2, True, None, 1.5, "t2"],
    },
    "items": ["pq", _FFFD + "r" + _FFFD, {"deep": "dv"}, 7, False],
    "key" + _FFFD: "value",
    "kept": "a" + _TAB + "b" + _LF + "c" + _CR + "d",
    "long": "L" * 2000,
}
# The JSON text a model sends for _DIRTY_ARGS (ASCII-escaped: every control
# character, surrogate and non-ASCII character is a \uXXXX escape).
_DIRTY_JSON: Final = json.dumps(_DIRTY_ARGS)

# Answer text: every removed class, an ANSI sequence split across pieces, lone
# surrogates (never at a piece boundary, never high directly before low), and
# what stays (tab, LF, CR, an emoji).
_TEXT_PIECES: Final[tuple[str, ...]] = (
    "Alpha " + _ESC + "[31",
    "mred" + _ESC + "[0m ",
    _NUL + "beta" + _SOH + _BEL + _BS + _VT + _FF + _SO + _US + " ",
    "gamma" + _C1_FIRST + _NEL + _CSI + "1m" + _C1_LAST + " ",
    "delta" + _LRE + _RLE + _PDF + _LRO + _RLO + _LRI + _RLI + _FSI + _PDI + " ",
    "eps" + _ZWSP + _ZWNJ + _ZWJ + _LSEP + _PSEP + _BOM + "ilon ",
    "zeta" + _HIGH_FIRST + "x" + _LOW_LAST + " " + _GRIN + _TAB + "eta",
    _LF + "theta" + _CR + _LF + "end",
)
_TEXT_CLEAN: Final = (
    "Alpha [31mred[0m beta gamma1m delta epsilon zetax "
    + _GRIN
    + _TAB
    + "eta"
    + _LF
    + "theta"
    + _CR
    + _LF
    + "end"
)

# A reply cut by the provider's output cap: the client keeps it as it is.
_CUT_TEXT: Final = "The answer is incompl"

# 66000 characters of words; character 65536 falls inside a word ("abcd a|bcd").
_WORDS: Final = "abcd " * 13200

_ARG_MARK: Final = "ARGMARK-w1-5e7a"
_KEY_MARK: Final = "KEYMARK-w1-c3d9"
_TEXT_MARK: Final = "TEXTMARK-w1-91b0"

# Placeholder for "the provider's usual stop reason for this reply".
_DEFAULT_STOP: Final = "<default-stop>"


# ---------------------------------------------------------------------------
# Tool calls on the wire
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Call:
    """One tool call a provider sends.

    ``arguments`` is the JSON text (or, for an OpenAI-compatible chat() body,
    an object); ``fragments`` is how a stream cuts that text (default: whole).
    """

    call_id: str
    name: str
    arguments: str | dict[str, Any]
    fragments: tuple[str, ...] | None = None

    def stream_fragments(self) -> tuple[str, ...]:
        """The argument fragments a stream sends."""
        if self.fragments is not None:
            return self.fragments
        assert isinstance(self.arguments, str)
        return (self.arguments,)

    def input_object(self) -> dict[str, Any]:
        """The arguments as a JSON object (Anthropic's ``input``)."""
        if isinstance(self.arguments, str):
            decoded = json.loads(self.arguments)
            assert isinstance(decoded, dict)
            return decoded
        return self.arguments


def _anthropic_name(name: str) -> str:
    """Anthropic's wire form of a dotted tool name (``tool__action``)."""
    return name.replace(".", "__")


# A JSON escape: \uXXXX or a two-character one (\t, \n, \", ...).
_JSON_ESCAPE_RE: Final = re.compile(r"\\(?:u[0-9a-fA-F]{4}|[\"\\/bfnrt])")


def _cut_inside_escapes(text: str) -> tuple[str, ...]:
    """Cut JSON text so that every escape sequence is split inside itself.

    The n-th escape is cut after 1 + n % (length - 1) of its characters, so a
    \\uXXXX escape is split after its backslash, ``\\u``, ``\\u0``, ``\\u00`` and
    ``\\u00X`` in turn.
    """
    cuts = [
        match.start() + 1 + n % (len(match.group()) - 1)
        for n, match in enumerate(_JSON_ESCAPE_RE.finditer(text))
    ]
    bounds = [0, *cuts, len(text)]
    return tuple(text[start:end] for start, end in itertools.pairwise(bounds) if end > start)


_DIRTY_FRAGMENTS: Final = _cut_inside_escapes(_DIRTY_JSON)


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
        "model": _STREAM_MODEL,
        "choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}],
    }


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


def _openai_chunks(
    pieces: Sequence[str], calls: Sequence[_Call], finish_reason: str | None
) -> Iterator[dict[str, Any]]:
    """Text chunks, then each call's fragments, then the chunk carrying the finish reason."""
    for piece in pieces:
        yield _chunk({"content": piece})
    for index, call in enumerate(calls):
        first, *rest = call.stream_fragments()
        yield _chunk(
            {"tool_calls": [_frag(index, call_id=call.call_id, name=call.name, arguments=first)]}
        )
        for fragment in rest:
            yield _chunk({"tool_calls": [_frag(index, arguments=fragment)]})
    yield _chunk({}, finish_reason=finish_reason)


def _openai_frames(chunks: Iterable[dict[str, Any]]) -> Iterator[bytes]:
    """``data: <chunk>`` lines, encoded one at a time, then ``data: [DONE]``."""
    for chunk in chunks:
        yield f"data: {json.dumps(chunk)}\n\n".encode()
    yield b"data: [DONE]\n\n"


def _completion(text: str, calls: Sequence[_Call], finish_reason: str | None) -> dict[str, Any]:
    """A non-streamed ``chat.completion`` body (for ``chat()``)."""
    message: dict[str, Any] = {"role": "assistant", "content": text or None}
    if calls:
        message["tool_calls"] = [
            {
                "id": call.call_id,
                "type": "function",
                "function": {"name": call.name, "arguments": call.arguments},
            }
            for call in calls
        ]
    return {
        "id": "chatcmpl-w1-json",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": _STREAM_MODEL,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19},
    }


# ---------------------------------------------------------------------------
# Anthropic bodies and frames
# ---------------------------------------------------------------------------


def _frame(event: str, data: dict[str, Any]) -> bytes:
    """One Anthropic Messages SSE frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _anthropic_frames(
    pieces: Sequence[str], calls: Sequence[_Call], stop_reason: str | None
) -> Iterator[bytes]:
    """A whole stream: message_start, a text block, one block per call, the stop reason."""
    yield _frame(
        "message_start",
        {
            "type": "message_start",
            "message": {
                "id": "msg_w1_01",
                "type": "message",
                "role": "assistant",
                "model": _STREAM_MODEL,
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 10, "output_tokens": 1},
            },
        },
    )
    index = 0
    if pieces:
        yield _frame(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        )
        for piece in pieces:
            yield _frame(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": piece},
                },
            )
        yield _frame("content_block_stop", {"type": "content_block_stop", "index": 0})
        index = 1
    for call in calls:
        yield _frame(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": index,
                "content_block": {
                    "type": "tool_use",
                    "id": call.call_id,
                    "name": _anthropic_name(call.name),
                    "input": {},
                },
            },
        )
        for fragment in call.stream_fragments():
            yield _frame(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": index,
                    "delta": {"type": "input_json_delta", "partial_json": fragment},
                },
            )
        yield _frame("content_block_stop", {"type": "content_block_stop", "index": index})
        index += 1
    yield _frame(
        "message_delta",
        {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": None},
            "usage": {"output_tokens": 15},
        },
    )
    yield _frame("message_stop", {"type": "message_stop"})


def _anthropic_message(
    text: str, calls: Sequence[_Call], stop_reason: str | None
) -> dict[str, Any]:
    """A non-streamed Anthropic ``message`` body (for ``chat()``)."""
    content: list[dict[str, Any]] = []
    if text:
        content.append({"type": "text", "text": text})
    content.extend(
        {
            "type": "tool_use",
            "id": call.call_id,
            "name": _anthropic_name(call.name),
            "input": call.input_object(),
        }
        for call in calls
    )
    return {
        "id": "msg_w1_json",
        "type": "message",
        "role": "assistant",
        "model": _STREAM_MODEL,
        "content": content,
        "stop_reason": stop_reason,
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


def _default_stop(provider: str, calls: Sequence[_Call]) -> str:
    """The provider's usual stop reason for a reply with (or without) tool calls."""
    if provider == "anthropic":
        return "tool_use" if calls else "end_turn"
    return "tool_calls" if calls else "stop"


def _chat_route(
    provider: str,
    text: str = "",
    calls: Sequence[_Call] = (),
    *,
    stop: str | None = _DEFAULT_STOP,
) -> Callable[[httpx.Request], httpx.Response]:
    """The provider's chat() reply: ``text``, then ``calls``, with ``stop`` as its stop reason."""
    reason = _default_stop(provider, calls) if stop == _DEFAULT_STOP else stop
    if provider == "anthropic":
        return _json_route(_anthropic_message(text, calls, reason))
    return _json_route(_completion(text, calls, reason))


def _stream_route(
    provider: str,
    pieces: Sequence[str] = (),
    calls: Sequence[_Call] = (),
    *,
    stop: str | None = _DEFAULT_STOP,
) -> Callable[[httpx.Request], httpx.Response]:
    """The provider's stream: a delta per piece, then ``calls``, then ``stop``."""
    reason = _default_stop(provider, calls) if stop == _DEFAULT_STOP else stop
    if provider == "anthropic":
        return _sse_route(_anthropic_frames(pieces, calls, reason))
    return _sse_route(_openai_frames(_openai_chunks(pieces, calls, reason)))


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    Each POST gets ``self.route``; anything else (or a POST without a route)
    gets a 404, so an unexpected request is visible.
    """

    def __init__(self) -> None:
        self.route: Callable[[httpx.Request], httpx.Response] | None = None

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Answer ``request``."""
        await request.aread()
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
    """Capture every log record at DEBUG (root, admino, the SDKs and httpx)."""
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitize(args: dict[str, Any]) -> Any:
    """Call ``admino.llm.sanitize_tool_args`` (imported lazily: new in GH-25)."""
    from admino.llm import sanitize_tool_args

    return sanitize_tool_args(args)


def _typed(value: object) -> object:
    """``value`` with every leaf tagged by its exact type (True != 1, 2.0 != 2); keys sorted."""
    if isinstance(value, dict):
        return ("dict", tuple(sorted((key, _typed(item)) for key, item in value.items())))
    if isinstance(value, list):
        return ("list", tuple(_typed(item) for item in value))
    return (type(value).__name__, value)


def _views(calls: Sequence[ToolCall]) -> list[tuple[str, str, object, str | None]]:
    """Tool calls as (tool, action, typed args, id) tuples."""
    return [(c.tool, c.action, _typed(c.args), c.tool_call_id) for c in calls]


def _truncated(response: LLMResponse) -> object:
    """``response.truncated``, or a marker when the field does not exist yet."""
    return getattr(response, "truncated", "<no truncated field>")


def _messages() -> list[LLMMessage]:
    """A system prompt and one user message."""
    return [
        LLMMessage(role="system", content="You are admino."),
        LLMMessage(role="user", content="Please answer"),
    ]


async def _drain(client: Any) -> list[Any]:
    """Drain ``client.chat_stream`` into a list."""
    return [item async for item in client.chat_stream(_messages())]


def _deltas(items: list[Any]) -> list[str]:
    """The text of every streamed delta, in order."""
    return [item.content for item in items if isinstance(item, LLMStreamDelta)]


def _final(items: list[Any]) -> LLMResponse:
    """The final response after checking the stream's shape and the C1.1 invariant.

    Non-empty deltas, then exactly one final ``LLMResponse`` whose content is the
    joined deltas.
    """
    assert items, "the stream yielded nothing"
    *deltas, final = items
    assert type(final) is LLMResponse
    assert all(type(d) is LLMStreamDelta and d.content for d in deltas)
    assert final.content == "".join(_deltas(items))
    return final


def _pieces(text: str, size: int) -> list[str]:
    """``text`` cut into consecutive pieces of ``size`` characters."""
    return [text[start : start + size] for start in range(0, len(text), size)]


def _cap_view(content: str, expected: str) -> tuple[int, str, bool]:
    """(length, last 6 characters, equal to ``expected``): short reports for 64 KiB texts."""
    return len(content), content[-6:], content == expected


def _log_leaks(logs: pytest.LogCaptureFixture, *markers: str) -> list[str]:
    """The markers found in any captured log record (message, args or formatted text)."""
    return [
        marker
        for marker in markers
        if marker in logs.text
        or any(
            marker in record.getMessage() or marker in str(record.args) for record in logs.records
        )
    ]


def _everywhere(char: str) -> dict[str, Any]:
    """``char`` in keys, values and list items at every depth (six levels)."""
    return {
        "top" + char: "a" + char + "b",
        "nested": {
            "in" + char + "ner": ["x" + char, {"deep": [char + "y", {"leaf" + char: char}]}]
        },
        "items": [char, "z" + char + char, 3],
    }


# ===========================================================================
# 1. sanitize_tool_args (C2, D5)
# ===========================================================================


@pytest.mark.parametrize("lone", list(_SURROGATES.values()), ids=list(_SURROGATES))
def test_llm_sanitize_tool_args_lone_surrogate_becomes_one_replacement_char_everywhere(
    lone: str,
) -> None:
    """Each lone surrogate becomes exactly one U+FFFD in keys, values and items at any depth."""
    assert _typed(_sanitize(_everywhere(lone))) == _typed(_everywhere(_FFFD))


@pytest.mark.parametrize("char", list(_REMOVED.values()), ids=list(_REMOVED))
def test_llm_sanitize_tool_args_removes_control_char_everywhere(char: str) -> None:
    """Each strip_control_chars class is removed from keys, values and items at any depth."""
    assert _typed(_sanitize(_everywhere(char))) == _typed(_everywhere(""))


def test_llm_sanitize_tool_args_ansi_sequence_keeps_printable_rest() -> None:
    """ESC and CSI go; the printable rest of the sequence stays as text (D6)."""
    args = {
        "esc": _ESC + "[31mred" + _ESC + "[0m",
        "csi": _CSI + "31mred" + _CSI + "0m",
        "osc": _ESC + "]0;title" + _BEL + "x",
    }
    assert _typed(_sanitize(args)) == _typed(
        {"esc": "[31mred[0m", "csi": "31mred0m", "osc": "]0;titlex"}
    )


def test_llm_sanitize_tool_args_every_c0_and_c1_removed_tab_lf_cr_kept() -> None:
    """All of U+0000-U+001F but tab / LF / CR, and all of U+0080-U+009F, are removed."""
    c0 = "".join(map(chr, range(0x20)))
    c1 = "".join(map(chr, range(0x80, 0xA0)))
    args = {"value": c0 + "|" + c1 + "|", "key" + c0 + c1: [c1 + "x" + c0]}
    expected = {
        "value": _TAB + _LF + _CR + "||",
        "key" + _TAB + _LF + _CR: ["x" + _TAB + _LF + _CR],
    }
    assert _typed(_sanitize(args)) == _typed(expected)


def test_llm_sanitize_tool_args_replaces_surrogates_before_stripping() -> None:
    """A lone surrogate next to removed characters still becomes U+FFFD (step order).

    Low-then-high neighbours are two lone surrogates: two U+FFFD.
    """
    args = {
        "v": _NUL + _HIGH_FIRST + _ESC + "x" + _ZWSP + _LOW_LAST + _BOM,
        "pair": "a" + _LOW_FIRST + _HIGH_LAST + "b",
    }
    expected = {"v": _FFFD + "x" + _FFFD, "pair": "a" + _FFFD + _FFFD + "b"}
    assert _typed(_sanitize(args)) == _typed(expected)


def test_llm_sanitize_tool_args_keeps_valid_characters() -> None:
    """An emoji, U+D7FF, U+E000, U+FFFD itself, non-ASCII letters, tab / LF / CR all stay."""
    value = "Zuerich " + chr(0xFC) + chr(0x65E5) + " " + _GRIN + _BEFORE_SURROGATES
    value += _AFTER_SURROGATES + _FFFD + _TAB + _LF + _CR + "end"
    args = {"text": value, "k" + _GRIN: [_GRIN, {"x": value}]}
    assert _typed(_sanitize(args)) == _typed(copy.deepcopy(args))


def test_llm_sanitize_tool_args_non_str_leaves_keep_type_and_value() -> None:
    """int, float, bool and None leaves come back with the same type and value."""
    args = {
        "zero": 0,
        "negative": -7,
        "big": 10**30,
        "float": 1.5,
        "float_whole": 2.0,
        "true": True,
        "false": False,
        "none": None,
        "list": [1, 2.0, True, False, None, "s"],
        "nested": {"n": 3, "b": False, "f": 0.0, "z": None},
        "empty_list": [],
        "empty_dict": {},
    }
    assert _typed(_sanitize(args)) == _typed(copy.deepcopy(args))


def test_llm_sanitize_tool_args_does_not_mutate_input_and_returns_new_structure() -> None:
    """The input is unchanged, even after the result's containers are modified."""
    args: dict[str, Any] = {
        "dirty": "a" + _NUL + _HIGH_FIRST,
        "nested": {"x" + _ESC: ["y" + _ZWSP, {"z": _LOW_LAST}]},
        "clean": {"inner": ["a", "b"], "n": 1},
    }
    snapshot = copy.deepcopy(args)
    result = _sanitize(args)
    after_call = _typed(args)
    result["added"] = 1
    result["nested"]["x"].append("more")
    result["nested"]["x"][1]["added"] = 2
    result["clean"]["inner"].append("c")
    result["clean"]["added"] = 3
    assert (result is not args, after_call, _typed(args)) == (
        True,
        _typed(snapshot),
        _typed(snapshot),
    )


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({"a" + _NUL: 1, "a": 2}, {"a": 2}),
        ({"a": 1, "a" + _ZWSP: 2}, {"a": 2}),
        ({"k" + _HIGH_FIRST: 1, "k" + _LOW_LAST: 2}, {"k" + _FFFD: 2}),
        ({"n": {"x" + _ESC: "first", "x": "second", "x" + _BOM: "third"}}, {"n": {"x": "third"}}),
    ],
    ids=["dirty-then-clean", "clean-then-dirty", "two-surrogates", "nested-three"],
)
def test_llm_sanitize_tool_args_colliding_keys_later_one_wins(
    args: dict[str, Any], expected: dict[str, Any]
) -> None:
    """Keys that clean to the same key keep the LATER value (as JSON objects do)."""
    assert _typed(_sanitize(args)) == _typed(expected)


def test_llm_sanitize_tool_args_whole_dirty_payload() -> None:
    """The payload the client tests send cleans to the expected arguments."""
    assert _typed(_sanitize(copy.deepcopy(_DIRTY_ARGS))) == _typed(_CLEAN_ARGS)


# ===========================================================================
# 2. Tool-call arguments: parse_tool_calls and every client, both paths
# ===========================================================================


def test_llm_parse_tool_calls_cleans_args_like_sanitize_tool_args() -> None:
    """The dict-based parser returns the call with its arguments cleaned (D5)."""
    raw = [{"function": {"name": "memory.store", "arguments": copy.deepcopy(_DIRTY_ARGS)}}]
    assert _views(parse_tool_calls(raw)) == [("memory", "store", _typed(_CLEAN_ARGS), None)]


def test_llm_parse_tool_calls_bounds_checked_before_cleaning() -> None:
    """2048 raw characters (24 NUL + 24 ESC) are accepted and cleaned; 2049 are dropped.

    The 2049-character value would clean to 2000 characters: it is still dropped,
    because the bounds apply to the decoded arguments before cleaning.
    """
    accepted = {"long": "L" * 2000 + _NUL * 24 + _ESC * 24}
    over = {"long": "L" * 2000 + _NUL * 49}
    result = (
        _views(parse_tool_calls([{"function": {"name": "memory.store", "arguments": accepted}}])),
        _views(parse_tool_calls([{"function": {"name": "memory.store", "arguments": over}}])),
    )
    assert result == ([("memory", "store", _typed({"long": "L" * 2000}), None)], [])


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_chat_tool_call_args_cleaned(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat(): JSON-escaped control characters and lone surrogates are cleaned everywhere.

    OpenAI-compatible: the arguments JSON string; Anthropic: the ``input`` object.
    """
    call = _Call("call_dirty", "memory.store", _DIRTY_JSON)
    wire.route = _chat_route(provider, "", [call])
    result = await build(provider).chat(_messages())
    assert _views(result.tool_calls) == [("memory", "store", _typed(_CLEAN_ARGS), "call_dirty")]


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_chat_openai_compatible_object_arguments_cleaned(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat() still accepts arguments sent as a JSON object, and cleans them too."""
    call = _Call("call_object", "memory.store", copy.deepcopy(_DIRTY_ARGS))
    wire.route = _chat_route(provider, "", [call])
    result = await build(provider).chat(_messages())
    assert _views(result.tool_calls) == [("memory", "store", _typed(_CLEAN_ARGS), "call_object")]


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_stream_tool_call_args_cleaned_fragments_split_inside_escapes(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat_stream(): argument fragments cut inside every escape still clean exactly.

    OpenAI-compatible: ``function.arguments`` fragments; Anthropic: ``partial_json``.
    """
    assert ("".join(_DIRTY_FRAGMENTS), len(_DIRTY_FRAGMENTS) > 60) == (_DIRTY_JSON, True)
    call = _Call("call_dirty", "memory.store", _DIRTY_JSON, fragments=_DIRTY_FRAGMENTS)
    wire.route = _stream_route(provider, ["Let me store that. "], [call])
    final = _final(await _drain(build(provider)))
    assert _views(final.tool_calls) == [("memory", "store", _typed(_CLEAN_ARGS), "call_dirty")]


# ===========================================================================
# 3. Answer text: every rule, every provider, both paths (regression guards)
# ===========================================================================


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_chat_text_sanitized(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat(): ANSI ESC / CSI, NUL, C0, C1, bidi, zero-width, separators, BOM, surrogates go."""
    wire.route = _chat_route(provider, "".join(_TEXT_PIECES))
    result = await build(provider).chat(_messages())
    assert result.content == _TEXT_CLEAN


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_stream_text_sanitized_deltas_and_final(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat_stream(): no delta carries a removed character; joined deltas == final content."""
    wire.route = _stream_route(provider, _TEXT_PIECES)
    items = await _drain(build(provider))
    final = _final(items)
    banned = sorted({f"U+{ord(c):04X}" for d in _deltas(items) for c in d if c in _BANNED})
    assert (banned, final.content) == ([], _TEXT_CLEAN)


# ===========================================================================
# 4. LLMResponse.truncated (C3.2, D7)
# ===========================================================================

_STOP_CASES: Final[list[tuple[str, str | None, bool]]] = [
    *(
        (provider, reason, reason == "length")
        for provider in OPENAI_COMPATIBLE
        for reason in ("length", "stop", "tool_calls", "content_filter", None)
    ),
    *(
        ("anthropic", reason, reason == "max_tokens")
        for reason in ("max_tokens", "end_turn", "tool_use", "stop_sequence", None)
    ),
]
_STOP_IDS: Final[list[str]] = [f"{provider}-{reason}" for provider, reason, _ in _STOP_CASES]


@pytest.mark.parametrize(("provider", "stop", "expected"), _STOP_CASES, ids=_STOP_IDS)
async def test_llm_chat_truncated_follows_stop_reason(
    provider: str, stop: str | None, expected: bool, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat(): truncated only for "length" / "max_tokens"; the content is never cut."""
    wire.route = _chat_route(provider, _CUT_TEXT, stop=stop)
    result = await build(provider).chat(_messages())
    assert (result.content, _truncated(result)) == (_CUT_TEXT, expected)


@pytest.mark.parametrize(("provider", "stop", "expected"), _STOP_CASES, ids=_STOP_IDS)
async def test_llm_stream_truncated_follows_stop_reason(
    provider: str, stop: str | None, expected: bool, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat_stream(): truncated only for "length" / "max_tokens"; deltas and content uncut."""
    wire.route = _stream_route(provider, [_CUT_TEXT[:9], _CUT_TEXT[9:]], stop=stop)
    final = _final(await _drain(build(provider)))
    assert (final.content, _truncated(final)) == (_CUT_TEXT, expected)


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_chat_truncated_when_cap_drops_text_content_not_cut_at_word(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat(): 66000 characters after 2000 NULs: the first 65536 sanitized ones, truncated.

    The cap counts after sanitizing (the NULs don't use it), and the client does
    not cut back to the last word: the content ends inside "abcd a".
    """
    wire.route = _chat_route(provider, _NUL * 2000 + _WORDS)
    result = await build(provider).chat(_messages())
    assert (_cap_view(result.content, _WORDS[:_MAX_CONTENT]), _truncated(result)) == (
        (_MAX_CONTENT, "abcd a", True),
        True,
    )


_UNDER_CAP_TEXTS: Final[dict[str, str]] = {
    "exact": "a" * _MAX_CONTENT,
    "sanitized-to-exact": _NUL * 1000 + "a" * _MAX_CONTENT + _BOM * 1000,
    "sanitized-under": _ZWSP * 3000 + "a" * 65000 + _ESC * 1000,
}


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
@pytest.mark.parametrize("text", list(_UNDER_CAP_TEXTS.values()), ids=list(_UNDER_CAP_TEXTS))
async def test_llm_chat_not_truncated_at_or_under_cap_after_sanitizing(
    provider: str, text: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat(): at most 65536 characters after sanitizing is not truncated (raw may be longer)."""
    wire.route = _chat_route(provider, text)
    result = await build(provider).chat(_messages())
    expected = text.replace(_NUL, "").replace(_BOM, "").replace(_ZWSP, "").replace(_ESC, "")
    assert (_cap_view(result.content, expected), _truncated(result)) == (
        (len(expected), "aaaaaa", True),
        False,
    )


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_stream_truncated_when_cap_drops_text_deltas_not_cut_at_word(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat_stream(): text past 65536 sanitized characters is dropped and the reply truncated.

    The pieces are 10000 characters (the first after 2000 NULs), so the cap falls
    inside a piece; the deltas end inside "abcd a", not at the last word.
    """
    pieces = _pieces(_WORDS, 10000)
    pieces[0] = _NUL * 2000 + pieces[0]
    wire.route = _stream_route(provider, pieces)
    items = await _drain(build(provider))
    final = _final(items)
    assert (_cap_view(final.content, _WORDS[:_MAX_CONTENT]), _truncated(final)) == (
        (_MAX_CONTENT, "abcd a", True),
        True,
    )


_UNDER_CAP_STREAMS: Final[dict[str, tuple[tuple[str, ...], int]]] = {
    "exact": (("a" * 40000, "a" * 25536), _MAX_CONTENT),
    "exact-then-removed-only": (("a" * 40000, "a" * 25536, _NUL * 300 + _ZWSP * 300), _MAX_CONTENT),
    "sanitized-to-exact": (
        (_NUL * 1000 + "a" * 40000, _ZWSP * 500 + "a" * 25536 + _BOM * 1000, _ESC * 500),
        _MAX_CONTENT,
    ),
    "sanitized-under": ((_BOM * 3000 + "a" * 40000, "a" * 25000 + _NUL * 1000), 65000),
}


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
@pytest.mark.parametrize(
    ("pieces", "length"), list(_UNDER_CAP_STREAMS.values()), ids=list(_UNDER_CAP_STREAMS)
)
async def test_llm_stream_not_truncated_at_or_under_cap_after_sanitizing(
    provider: str,
    pieces: tuple[str, ...],
    length: int,
    wire: _Wire,
    build: Callable[[str], Any],
) -> None:
    """chat_stream(): at most 65536 sanitized characters is not truncated.

    Also when the cap is reached exactly and a later chunk holds only removed
    characters.
    """
    wire.route = _stream_route(provider, pieces)
    final = _final(await _drain(build(provider)))
    assert (_cap_view(final.content, "a" * length), _truncated(final)) == (
        (length, "aaaaaa", True),
        False,
    )


_REASONING: Final = _THINK_OPEN + "r" * 70000 + _THINK_CLOSE


@pytest.mark.parametrize(("answer", "expected"), [(_MAX_CONTENT, False), (_MAX_CONTENT + 1, True)])
async def test_llm_infomaniak_chat_truncated_counts_answer_without_reasoning(
    answer: int, expected: bool, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """Infomaniak chat(): 70000 reasoning characters never count; only the answer does."""
    wire.route = _chat_route("infomaniak", _REASONING + "a" * answer)
    result = await build("infomaniak").chat(_messages())
    assert (_cap_view(result.content, "a" * _MAX_CONTENT), _truncated(result)) == (
        (_MAX_CONTENT, "aaaaaa", True),
        expected,
    )


@pytest.mark.parametrize(("answer", "expected"), [(_MAX_CONTENT, False), (_MAX_CONTENT + 1, True)])
async def test_llm_infomaniak_stream_truncated_counts_answer_without_reasoning(
    answer: int, expected: bool, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """Infomaniak chat_stream(): the think filter's reasoning never counts toward the cap."""
    wire.route = _stream_route("infomaniak", [_REASONING, "a" * 40000, "a" * (answer - 40000)])
    final = _final(await _drain(build("infomaniak")))
    assert (_cap_view(final.content, "a" * _MAX_CONTENT), _truncated(final)) == (
        (_MAX_CONTENT, "aaaaaa", True),
        expected,
    )


# ===========================================================================
# 5. Unregistered but well-formed names pass the LLM layer (D4)
# ===========================================================================

_UNKNOWN_CALLS: Final[tuple[_Call, ...]] = (
    _Call("call_known", "memory.store", '{"key": "a"}'),
    _Call("call_unknown", "foo.bar", '{"q": "x"}'),
)
_UNKNOWN_VIEWS: Final = [
    ("memory", "store", _typed({"key": "a"}), "call_known"),
    ("foo", "bar", _typed({"q": "x"}), "call_unknown"),
]


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_chat_unregistered_well_formed_name_returned(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat(): ``foo.bar`` comes back as ToolCall(tool="foo", action="bar") (D4)."""
    wire.route = _chat_route(provider, "", _UNKNOWN_CALLS)
    result = await build(provider).chat(_messages())
    assert _views(result.tool_calls) == _UNKNOWN_VIEWS


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_stream_unregistered_well_formed_name_returned(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """chat_stream(): ``foo.bar`` comes back as ToolCall(tool="foo", action="bar")."""
    wire.route = _stream_route(provider, (), _UNKNOWN_CALLS)
    final = _final(await _drain(build(provider)))
    assert _views(final.tool_calls) == _UNKNOWN_VIEWS


# ===========================================================================
# 6. No argument or answer text in any log record
# ===========================================================================

_LOGGED_ARGS: Final[dict[str, Any]] = {
    "note": _ARG_MARK + _ESC + "[0m",
    _KEY_MARK + _ZWSP: "v" + _NUL + _HIGH_FIRST,
    "list": [_ARG_MARK + _RLO],
}
_LOGGED_CLEAN: Final[dict[str, Any]] = {
    "note": _ARG_MARK + "[0m",
    _KEY_MARK: "v" + _FFFD,
    "list": [_ARG_MARK],
}
_LOGGED_TEXT: Final = "Answer " + _TEXT_MARK + _ESC + "[1m done"


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_chat_logs_no_argument_or_answer_text(
    provider: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """chat(): the arguments are cleaned and no value, key or answer text is logged (DEBUG)."""
    call = _Call("call_log", "memory.store", json.dumps(_LOGGED_ARGS))
    wire.route = _chat_route(provider, _LOGGED_TEXT, [call])
    result = await build(provider).chat(_messages())
    assert (
        _views(result.tool_calls),
        _TEXT_MARK in result.content,
        _log_leaks(debug_logs, _ARG_MARK, _KEY_MARK, _TEXT_MARK),
    ) == ([("memory", "store", _typed(_LOGGED_CLEAN), "call_log")], True, [])


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_stream_logs_no_argument_or_answer_text(
    provider: str,
    wire: _Wire,
    build: Callable[[str], Any],
    debug_logs: pytest.LogCaptureFixture,
) -> None:
    """chat_stream(): the arguments are cleaned and no value, key or answer text is logged."""
    arguments = json.dumps(_LOGGED_ARGS)
    call = _Call("call_log", "memory.store", arguments, fragments=_cut_inside_escapes(arguments))
    wire.route = _stream_route(provider, [_LOGGED_TEXT[:12], _LOGGED_TEXT[12:]], [call])
    final = _final(await _drain(build(provider)))
    assert (
        _views(final.tool_calls),
        _TEXT_MARK in final.content,
        _log_leaks(debug_logs, _ARG_MARK, _KEY_MARK, _TEXT_MARK),
    ) == ([("memory", "store", _typed(_LOGGED_CLEAN), "call_log")], True, [])
