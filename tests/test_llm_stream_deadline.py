"""Stream deadline and the once-per-stream usage warning (GH-25 D8, D10; contract C3.6, C3.7, C4).

Every client is built from a real ``LLMConfig`` and drives its REAL SDK
(``openai`` for Infomaniak, vLLM and OpenAI; ``anthropic`` for Claude) against a
fake wire: ``httpx.AsyncClient.send`` is replaced by a queue of scripted routes.
A route can answer at once with an SSE body played step by step while it is
read (frames, pauses, a raised transport error, or silence that never ends),
answer after a delay, never answer at all, or answer ``chat()`` with JSON.
Nothing reaches a real host, and no httpx timeout applies on this wire: without
a deadline a silent provider would hang until the test's own bound. Each
process first runs every provider's stream and ``chat()`` once on a client with
a long deadline, so the SDKs' lazy imports and deferred model builds never count
toward a timed call.

What these tests pin (``stream_deadline_s=0.2`` unless a test says otherwise):

- ``LLMConfig.stream_deadline_s``: 300.0 by default; 0, negative values,
  3600.0001, NaN, infinity and False are rejected; 0.2, 1 and 3600 are accepted.
  The field is the contract's ``float`` with ``gt=0, le=3600``, so lax float
  input applies: ``True`` validates as 1.0 and is not pinned either way.
  ``config/config.yaml`` ships ``stream_deadline_s: 300`` and still loads.
- Per provider (OpenAI, vLLM, Infomaniak, Anthropic), ``chat_stream()``:
  (a) one delta, then silence: the consumer gets the delta, then the client's
  ``timeout`` error, identical to the one a mid-stream read timeout gives today
  on a client of the same provider (vLLM: its "starting or unavailable" text),
  raised ``from None``, no earlier than the deadline and far below the 120 s
  read timeout;
  (b) empty chunks / keepalive comments (OpenAI-compatible) or pings / empty text
  deltas (Anthropic) every 20 ms, forever: ``timeout`` likewise;
  (c) opening waits (never answers, or answers only after the deadline):
  ``timeout`` with no item, the pending send cancelled;
  (d) in (a) and (b) the provider's response body is closed when the error
  reaches the consumer (in (c) the send is cancelled, never answered);
  (e) a stream that finishes in time is unchanged;
  (f) a consumer that sleeps past the deadline between two items is never
  cancelled, and its next ``anext`` raises ``timeout``;
  (g) the deadline is per call, counted from the call's first iteration: two
  calls each under the deadline but over it together both succeed, and a third
  silent one still gets its own full deadline;
  (h) ``chat()`` ignores ``stream_deadline_s``.
- Policy (C4) through the real clients: a deadline hit before any item is
  retried (two requests; the good retry's deltas reach the caller once; the
  retry has its own deadline); a deadline hit after a delta is not retried.
- Usage warning (C3.7): "Ignoring malformed usage block" is logged once per
  ``chat_stream()`` call of an OpenAI-compatible client however many chunks
  carry a malformed block, once again for a second call, never for a valid
  block; Anthropic never logs it; ``chat()`` stays at most one warning (exactly
  one for Infomaniak, the only ``chat()`` that reads usage).
- Logs: the delta text of a stream that hits the deadline is in no log record
  (DEBUG capture of admino and the SDK loggers) and not in the error.

Security notes:
- Keys are built at runtime (``tests.credential_keys``); no key literal here.
- The SDKs' and the model policy's retry sleeps are no-ops.
- New names (``stream_deadline_s``) are only read through the config at run time,
  so this module collects before the implementation exists.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import anthropic._base_client as anthropic_base_client
import httpx
import openai._base_client as openai_base_client
import pytest
import yaml
from pydantic import ValidationError

from admino import llm_policy
from admino.config import LLMConfig, load_app_config
from admino.llm import LLMError, LLMResponse, LLMStreamDelta, LLMUsage
from admino.llm_anthropic import AnthropicClient
from admino.llm_infomaniak import InfomaniakClient
from admino.llm_openai import OpenAIClient
from admino.llm_vllm import VLLMClient
from admino.models import LLMMessage
from tests.credential_keys import api_key

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Iterable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENAI_COMPATIBLE: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak")
ALL_PROVIDERS: Final[tuple[str, ...]] = ("openai", "vllm", "infomaniak", "anthropic")

# The deadline of most tests; the timeout never comes before _FLOOR (the deadline
# minus scheduling slack) and always before _BOUND (the test's own guard, far below
# the 120 s read timeout: a client without a deadline hangs until it).
_DEADLINE: Final = 0.2
_FLOOR: Final = 0.15
_BOUND: Final = 2.5
_TICK: Final = 0.02
# Warm-up and oracle clients: a deadline that never plays a part.
_LONG_DEADLINE: Final = 60.0

# (g): a longer deadline, two calls of ~0.25 s each (0.5 s together) and a 0.3 s
# wait before the first call's first iteration.
_PER_CALL_DEADLINE: Final = 0.4
_PER_CALL_FLOOR: Final = 0.3
_CALL_PAUSE: Final = 0.25
_PRE_ITERATION_WAIT: Final = 0.3

_MAX_TOKENS: Final = 777
_IK_PRODUCT_ID: Final = "7539"
_STREAM_MODEL: Final = "wire-deadline-model"

_OPENAI_KEY: Final = api_key("sk-", 48, seed=2581).text
_ANTHROPIC_KEY: Final = api_key("sk-" + "ant-", 48, seed=2582).text
_IK_TOKEN: Final = api_key("ik-", 40, seed=2583).text

_CANARY: Final = "q7zk-delta-canary-" + "2525"
_USAGE_WARNING: Final = "Ignoring malformed usage block"
_BAD_USAGE: Final[dict[str, int]] = {
    "prompt_tokens": -3,
    "completion_tokens": 2,
    "total_tokens": -1,
}
_GOOD_USAGE: Final[dict[str, int]] = {
    "prompt_tokens": 7,
    "completion_tokens": 3,
    "total_tokens": 10,
}

_REPO_ROOT: Final = Path(__file__).resolve().parent.parent
_SHIPPED_CONFIG_PATH: Final = _REPO_ROOT / "config" / "config.yaml"
# Env vars that load_app_config / LLMConfig validators read (the test_shipped_defaults list).
_ENV_VARS_TO_CLEAR: Final[tuple[str, ...]] = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "INFOMANIAK_API_TOKEN",
    "INFOMANIAK_PRODUCT_ID",
    "LLM_PROVIDER",
    "VLLM_MODEL",
    "VLLM_BASE_URL",
    "VLLM_MAX_MODEL_LEN",
    "COOKIE_SECURE",
    "ADMINO_PUBLIC_URL",
    "ADMINO_TRUSTED_PROXIES",
    "LOG_LEVEL",
    "AUDIT_LOG_PATH",
)

# ---------------------------------------------------------------------------
# Wire frames
# ---------------------------------------------------------------------------


def _sse(payload: dict[str, Any]) -> bytes:
    """One ``data:`` SSE frame."""
    return f"data: {json.dumps(payload)}\n\n".encode()


_DONE: Final = b"data: [DONE]\n\n"
_KEEPALIVE: Final = b": keepalive\n\n"


def _chunk(
    delta: dict[str, Any] | None = None,
    *,
    finish_reason: str | None = None,
    usage: dict[str, int] | None = None,
    with_choice: bool = True,
) -> dict[str, Any]:
    """One ``chat.completion.chunk`` (OpenAI-compatible)."""
    body: dict[str, Any] = {
        "id": "chatcmpl-w3-deadline",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": _STREAM_MODEL,
        "choices": (
            [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}]
            if with_choice
            else []
        ),
    }
    if usage is not None:
        body["usage"] = usage
    return body


def _completion(content: str, *, usage: dict[str, int] | None = None) -> dict[str, Any]:
    """A non-streamed ``chat.completion`` body (for ``chat()``)."""
    body: dict[str, Any] = {
        "id": "chatcmpl-w3-json",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": _STREAM_MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }
    if usage is not None:
        body["usage"] = usage
    return body


def _event(event: str, data: dict[str, Any]) -> bytes:
    """One Anthropic Messages SSE frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def _anthropic_open(usage: dict[str, int] | None = None) -> list[bytes]:
    """``message_start`` and the start of text block 0 (no text yet)."""
    return [
        _event(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_w3_01",
                    "type": "message",
                    "role": "assistant",
                    "model": _STREAM_MODEL,
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": usage or {"input_tokens": 10, "output_tokens": 1},
                },
            },
        ),
        _event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
    ]


def _anthropic_text(piece: str) -> bytes:
    """A ``text_delta`` of block 0."""
    return _event(
        "content_block_delta",
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": piece}},
    )


def _anthropic_close(output_tokens: int = 15) -> list[bytes]:
    """The end of block 0 and of the message (``end_turn``)."""
    return [
        _event("content_block_stop", {"type": "content_block_stop", "index": 0}),
        _event(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": output_tokens},
            },
        ),
        _event("message_stop", {"type": "message_stop"}),
    ]


def _anthropic_message(text: str) -> dict[str, Any]:
    """A non-streamed Anthropic ``message`` body (for ``chat()``)."""
    return {
        "id": "msg_w3_json",
        "type": "message",
        "role": "assistant",
        "model": _STREAM_MODEL,
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


_PING: Final = _event("ping", {"type": "ping"})


def _opening(provider: str) -> list[bytes]:
    """Frames that open a reply without any text (Anthropic's starts; nothing otherwise)."""
    return _anthropic_open() if provider == "anthropic" else []


def _piece(provider: str, text: str) -> bytes:
    """One frame carrying ``text`` as answer text."""
    if provider == "anthropic":
        return _anthropic_text(text)
    return _sse(_chunk({"content": text}))


def _ending(provider: str) -> list[bytes]:
    """Frames that end a text reply normally."""
    if provider == "anthropic":
        return _anthropic_close()
    return [_sse(_chunk({}, finish_reason="stop")), _DONE]


def _reply(provider: str, *pieces: str) -> list[bytes]:
    """A whole, normal text reply."""
    return [*_opening(provider), *(_piece(provider, p) for p in pieces), *_ending(provider)]


def _chat_body(provider: str, text: str) -> dict[str, Any]:
    """The provider's ``chat()`` JSON body answering ``text``."""
    return _anthropic_message(text) if provider == "anthropic" else _completion(text)


# Traffic that carries no answer text, sent every _TICK forever in (b): one kind
# the SDK swallows inside a single read (a comment, a ping) and one kind it hands
# to the client as an item the client ignores (an empty chunk, an empty text delta).
_IDLE_FRAMES: Final[dict[str, bytes]] = {
    "empty-chunk": _sse(_chunk({})),
    "keepalive-comment": _KEEPALIVE,
    "ping": _PING,
    "empty-text-delta": _anthropic_text(""),
}
_IDLE_CASES: Final = [
    *(
        pytest.param(provider, kind, id=f"{provider}-{kind}")
        for provider in OPENAI_COMPATIBLE
        for kind in ("empty-chunk", "keepalive-comment")
    ),
    pytest.param("anthropic", "ping", id="anthropic-ping"),
    pytest.param("anthropic", "empty-text-delta", id="anthropic-empty-text-delta"),
]

# ---------------------------------------------------------------------------
# The scripted wire
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Pause:
    """A body step: wait ``seconds`` before the next step."""

    seconds: float


class _Silence:
    """A body step: nothing more ever comes (the read waits forever)."""


_SILENT: Final = _Silence()

type _Step = bytes | _Pause | _Silence | Exception


class _ScriptedBody(httpx.AsyncByteStream):
    """A response body played step by step while it is read; records its close."""

    def __init__(self, steps: Iterable[_Step]) -> None:
        self._steps = steps
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield frames, pause, raise or fall silent, as scripted."""
        for step in self._steps:
            if isinstance(step, bytes):
                yield step
            elif isinstance(step, _Pause):
                await asyncio.sleep(step.seconds)
            elif isinstance(step, Exception):
                raise step
            else:
                await asyncio.Event().wait()

    async def aclose(self) -> None:
        """Record that the reader closed the response."""
        self.closed = True


type _Route = Callable[[httpx.Request], Awaitable[httpx.Response]]


class _StreamRoute:
    """Answers at once with a 200 SSE response whose body plays ``steps``."""

    def __init__(self, steps: Iterable[_Step]) -> None:
        self.body = _ScriptedBody(steps)

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        """Return the streamed response."""
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=self.body,
            request=request,
        )


class _JsonRoute:
    """Answers at once with a JSON body (for ``chat()``)."""

    def __init__(self, body: dict[str, Any]) -> None:
        self._content = json.dumps(body).encode()

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        """Return the JSON response."""
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=self._content,
            request=request,
        )


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


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    Each POST takes the next queued route; anything else (or a POST with no route
    left) gets a 404, so an unexpected request is visible.
    """

    def __init__(self) -> None:
        self.routes: list[_Route] = []
        self.requests: list[str] = []

    def queue(self, *routes: _Route) -> None:
        """Queue the routes answering the next POSTs, in order."""
        self.routes.extend(routes)

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it."""
        await request.aread()
        self.requests.append(f"{request.method}:{request.url.path}")
        if request.method != "POST" or not self.routes:
            return httpx.Response(404, json={"error": "unexpected"}, request=request)
        return await self.routes.pop(0)(request)


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
        "ANTHROPIC_LOG",
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
    """Route every ``httpx.AsyncClient.send`` through the scripted wire."""
    fake = _Wire()

    async def send(_client: httpx.AsyncClient, request: httpx.Request, **_: Any) -> httpx.Response:
        return await fake.send(request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    return fake


@pytest.fixture()
def policy_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record every model-policy retry delay instead of sleeping; ``_random`` returns 0.5."""
    delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(llm_policy, "_sleep", fake_sleep)
    monkeypatch.setattr(llm_policy, "_random", lambda: 0.5)
    return delays


_CLIENT_CLASSES: Final[dict[str, Callable[[LLMConfig], Any]]] = {
    "infomaniak": InfomaniakClient,
    "vllm": VLLMClient,
    "openai": OpenAIClient,
    "anthropic": AnthropicClient,
}


def _config(provider: str, deadline: float) -> LLMConfig:
    """The LLM config of a client under test, with ``stream_deadline_s=deadline``."""
    return LLMConfig.model_validate(
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


# Providers whose SDK paths already ran once in this process (see _warm_up).
_WARMED: Final[set[str]] = set()


async def _warm_up(wire: _Wire) -> None:
    """Run each provider's stream and chat() once, on a client with a long deadline.

    The SDKs import modules lazily and build their pydantic models on first use
    (openai defers them), which can take longer than a 0.2 s deadline on a cold
    process (with coverage). Paying that here keeps it out of every timed call.
    """
    for provider in ALL_PROVIDERS:
        if provider in _WARMED:
            continue
        client = _CLIENT_CLASSES[provider](_config(provider, _LONG_DEADLINE))
        try:
            wire.queue(
                _StreamRoute(_reply(provider, "warm ", "up")),
                _JsonRoute(_chat_body(provider, "warm")),
            )
            async for _item in client.chat_stream(_messages(), None):
                pass
            await client.chat(_messages())
        finally:
            await client.close()
        _WARMED.add(provider)
    wire.routes.clear()
    wire.requests.clear()


@pytest.fixture()
async def build(wire: _Wire) -> AsyncIterator[Callable[..., Any]]:
    """Build provider clients on the scripted wire; every built client is closed after.

    The SDKs are warmed up first (once per process), so no timed call pays their
    first-use cost.
    """
    await _warm_up(wire)
    built: list[Any] = []

    def factory(provider: str, deadline: float = _DEADLINE) -> Any:
        client = _CLIENT_CLASSES[provider](_config(provider, deadline))
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


def _kinds(items: list[Any]) -> list[tuple[str, str]]:
    """Each yielded item as ("delta", text) / ("final", content) / ("other", repr)."""
    kinds: list[tuple[str, str]] = []
    for item in items:
        if type(item) is LLMStreamDelta:
            kinds.append(("delta", item.content))
        elif type(item) is LLMResponse:
            kinds.append(("final", item.content))
        else:
            kinds.append(("other", repr(item)))
    return kinds


def _shape(err: object) -> tuple[object, ...]:
    """An error's comparable fields (a missing attribute shows as a marker)."""
    return (
        type(err).__name__,
        getattr(err, "code", "<no code>"),
        getattr(err, "message", "<no message>"),
        getattr(err, "status_code", "<no status>"),
        getattr(err, "retry_after_s", "<no retry_after_s>"),
        getattr(err, "user_facing", "<no user_facing>"),
    )


def _raised_from_none(err: object) -> tuple[object, object]:
    """``(__cause__, __suppress_context__)``: ``(None, True)`` for ``raise ... from None``."""
    return (
        getattr(err, "__cause__", "<no cause>"),
        getattr(err, "__suppress_context__", "<no suppress>"),
    )


@dataclass
class _Run:
    """What a consumer saw: items, the LLMError (or a hang marker) and timings."""

    items: list[Any]
    error: object = None
    elapsed: float = 0.0
    probe: object = None


async def _run(stream: AsyncIterator[Any], probe: Callable[[], object] | None = None) -> _Run:
    """Drain ``stream`` within ``_BOUND`` seconds.

    ``elapsed`` runs from the first iteration to the LLMError (or the end);
    ``probe()`` is evaluated when the LLMError reaches this consumer. A stream
    still running at ``_BOUND`` is cancelled and reported as hung.
    """
    loop = asyncio.get_running_loop()
    run = _Run(items=[])
    start = loop.time()

    async def drive() -> None:
        try:
            async for item in stream:
                run.items.append(item)
        except LLMError as exc:
            run.error = exc
            run.probe = probe() if probe is not None else None
        run.elapsed = loop.time() - start

    try:
        await asyncio.wait_for(drive(), _BOUND)
    except TimeoutError:
        run.error = f"no error within {_BOUND} s (hung)"
        run.elapsed = loop.time() - start
    return run


async def _read_timeout_oracle(wire: _Wire, build: Callable[..., Any], provider: str) -> LLMError:
    """The error a ``provider`` client gives today for a read timeout after one delta.

    Built on its own client with a long deadline, so the deadline never plays a
    part in the oracle (code timeout).
    """
    client = build(provider, deadline=_LONG_DEADLINE)
    wire.queue(
        _StreamRoute([*_opening(provider), _piece(provider, "Hi "), httpx.ReadTimeout("slow")])
    )
    run = await _run(client.chat_stream(_messages(), None))
    assert isinstance(run.error, LLMError), run.error
    assert run.error.code == "timeout"
    return run.error


def _usage_warnings(caplog: pytest.LogCaptureFixture) -> int:
    """How many "Ignoring malformed usage block" records were logged so far."""
    return sum(_USAGE_WARNING in record.getMessage() for record in caplog.records)


def _capture_all(caplog: pytest.LogCaptureFixture, level: int) -> None:
    """Capture admino's and the SDKs' records from ``level`` up."""
    for name in ("", "admino", "openai", "anthropic", "httpx", "httpcore"):
        caplog.set_level(level, logger=name)


# ===========================================================================
# LLMConfig.stream_deadline_s
# ===========================================================================


def test_config_stream_deadline_default_is_300_seconds() -> None:
    """Without a value the deadline is 300.0 seconds (a float)."""
    value = getattr(LLMConfig(), "stream_deadline_s", "<missing>")
    assert (value, type(value)) == (300.0, float)


@pytest.mark.parametrize(
    "value",
    [0, 0.0, -1, -0.5, 3600.0001, math.nan, math.inf, False],
    ids=["zero", "zero-float", "minus-one", "minus-half", "over-3600", "nan", "inf", "false"],
)
def test_config_stream_deadline_out_of_range_rejected(value: object) -> None:
    """0, negatives, anything above 3600, NaN, infinity and False (0) are refused."""
    with pytest.raises(ValidationError) as caught:
        LLMConfig.model_validate({"stream_deadline_s": value})
    assert [error["loc"] for error in caught.value.errors()] == [("stream_deadline_s",)]


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0.2, 0.2), (1, 1.0), (3600, 3600.0)],
    ids=["fifth", "one", "max-3600"],
)
def test_config_stream_deadline_in_range_accepted(value: object, expected: float) -> None:
    """Any number above 0 up to 3600 is kept as that float."""
    config = LLMConfig.model_validate({"stream_deadline_s": value})
    assert getattr(config, "stream_deadline_s", "<missing>") == expected


def test_config_stream_deadline_shipped_config_loads_300(monkeypatch: pytest.MonkeyPatch) -> None:
    """config/config.yaml sets llm.stream_deadline_s: 300 and still loads with it."""
    for name in _ENV_VARS_TO_CLEAR:
        monkeypatch.delenv(name, raising=False)
    raw = yaml.safe_load(_SHIPPED_CONFIG_PATH.read_text(encoding="utf-8"))
    config = load_app_config(_SHIPPED_CONFIG_PATH)
    assert (
        raw["llm"].get("stream_deadline_s"),
        getattr(config.llm, "stream_deadline_s", "<missing>"),
    ) == (300, 300.0)


# ===========================================================================
# (a)-(d): the deadline ends a stream that stalls, idles or never opens
# ===========================================================================


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_deadline_silence_after_delta_raises_read_timeout_error(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """(a)+(d) One delta, then nothing: the delta, then the read-timeout error at the deadline.

    The error equals the one a mid-stream read timeout gives today on a client of
    the same provider (vLLM: "starting or unavailable", code timeout), is raised
    from None, comes no earlier than the deadline and well before the bound, and
    the response body is already closed when it reaches the consumer.
    """
    client = build(provider)
    oracle = await _read_timeout_oracle(wire, build, provider)
    route = _StreamRoute([*_opening(provider), _piece(provider, "Hello "), _SILENT])
    wire.queue(route)
    run = await _run(client.chat_stream(_messages(), None), probe=lambda: route.body.closed)
    assert (
        _kinds(run.items),
        _shape(run.error),
        _raised_from_none(run.error),
        run.probe,
        _FLOOR <= run.elapsed < _BOUND,
    ) == ([("delta", "Hello ")], _shape(oracle), (None, True), True, True), run.elapsed


@pytest.mark.parametrize(("provider", "kind"), _IDLE_CASES)
async def test_llm_deadline_idle_traffic_forever_raises_timeout(
    provider: str, kind: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """(b)+(d) Text-free traffic every 20 ms, forever: the read-timeout error at the deadline.

    Neither a frame the SDK swallows (keepalive comment, ping) nor an item the
    client ignores (empty chunk, empty text delta) extends the deadline; the body
    is closed when the error reaches the consumer.
    """
    client = build(provider)
    oracle = await _read_timeout_oracle(wire, build, provider)
    idle = itertools.cycle([_IDLE_FRAMES[kind], _Pause(_TICK)])
    route = _StreamRoute(itertools.chain(_opening(provider), idle))
    wire.queue(route)
    run = await _run(client.chat_stream(_messages(), None), probe=lambda: route.body.closed)
    assert (
        _kinds(run.items),
        _shape(run.error),
        _raised_from_none(run.error),
        run.probe,
        _FLOOR <= run.elapsed < _BOUND,
    ) == ([], _shape(oracle), (None, True), True, True), run.elapsed


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
@pytest.mark.parametrize("opening", ["never-answers", "answers-after-deadline"])
async def test_llm_deadline_opening_counts_and_waiting_send_cancelled(
    provider: str, opening: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """(c)+(d) Opening the stream counts: a send still waiting at the deadline is cancelled.

    Whether the provider never answers or would answer (a complete reply) only
    after 0.5 s, the call raises the read-timeout error at the deadline with no
    item, and the pending send was cancelled, never answered.
    """
    client = build(provider)
    oracle = await _read_timeout_oracle(wire, build, provider)
    delay = None if opening == "never-answers" else 0.5
    route = _DelayedRoute(delay, then=_StreamRoute(_reply(provider, "late ", "reply")))
    wire.queue(route)
    run = await _run(
        client.chat_stream(_messages(), None), probe=lambda: (route.cancelled, route.answered)
    )
    assert (
        _kinds(run.items),
        _shape(run.error),
        _raised_from_none(run.error),
        run.probe,
        _FLOOR <= run.elapsed < _BOUND,
    ) == ([], _shape(oracle), (None, True), (True, False), True), run.elapsed


# ===========================================================================
# (e)-(h): what the deadline leaves alone
# ===========================================================================


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_deadline_stream_finishing_in_time_unchanged(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """(e) A reply with short pauses that ends before the deadline streams exactly as before.

    Also pins that the client config carries the 0.2 s deadline (so this guard
    runs with the deadline active).
    """
    client = build(provider)
    steps: list[_Step] = [
        *_opening(provider),
        _piece(provider, "Hel"),
        _Pause(0.03),
        _piece(provider, "lo "),
        _Pause(0.03),
        _piece(provider, "world"),
        *_ending(provider),
    ]
    wire.queue(_StreamRoute(steps))
    run = await _run(client.chat_stream(_messages(), None))
    final = run.items[-1] if run.items else None
    assert (
        getattr(_config(provider, _DEADLINE), "stream_deadline_s", "<missing>"),
        _kinds(run.items),
        run.error,
        (getattr(final, "model", None), getattr(final, "done", None)),
    ) == (
        _DEADLINE,
        [("delta", "Hel"), ("delta", "lo "), ("delta", "world"), ("final", "Hello world")],
        None,
        (_STREAM_MODEL, True),
    )


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_deadline_slow_consumer_never_cancelled_then_timeout(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """(f) A consumer sleeping 0.35 s past the deadline is not cancelled; its next anext times out.

    The deadline never spans a ``yield``: cancellation reaches only the provider
    await, never the consumer's own code.
    """
    client = build(provider)
    wire.queue(_StreamRoute([*_opening(provider), _piece(provider, "Hello "), _SILENT]))
    events: list[str] = []

    async def consume() -> None:
        stream = client.chat_stream(_messages(), None)
        try:
            first = await anext(stream)
            events.append(f"item:{getattr(first, 'content', first)}")
            try:
                await asyncio.sleep(_DEADLINE + 0.15)
            except asyncio.CancelledError:
                events.append("sleep-cancelled")
                raise
            events.append("slept")
            try:
                await anext(stream)
                events.append("item")
            except LLMError as exc:
                events.append(f"error:{exc.code}")
        finally:
            await stream.aclose()

    task = asyncio.create_task(consume())
    done, _ = await asyncio.wait({task}, timeout=_BOUND)
    if not done:
        events.append("hung")
        task.cancel()
        await asyncio.wait({task})
    elif not task.cancelled() and task.exception() is not None:
        events.append(f"raised:{type(task.exception()).__name__}")
    assert events == ["item:Hello ", "slept", "error:timeout"]


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_deadline_is_per_call_from_first_iteration(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """(g) Each call gets its own deadline, counted from its first iteration.

    Deadline 0.4 s: a call created 0.3 s before its first iteration and a second
    call each take ~0.25 s (0.5 s together) and both succeed; a third call that
    falls silent still gets its own full deadline.
    """
    client = build(provider, deadline=_PER_CALL_DEADLINE)

    def timed() -> _StreamRoute:
        return _StreamRoute(
            [
                *_opening(provider),
                _piece(provider, "one "),
                _Pause(_CALL_PAUSE),
                _piece(provider, "two"),
                *_ending(provider),
            ]
        )

    wire.queue(
        timed(),
        timed(),
        _StreamRoute([*_opening(provider), _piece(provider, "three "), _SILENT]),
    )
    first = client.chat_stream(_messages(), None)
    await asyncio.sleep(_PRE_ITERATION_WAIT)
    run_1 = await _run(first)
    run_2 = await _run(client.chat_stream(_messages(), None))
    run_3 = await _run(client.chat_stream(_messages(), None))
    whole = [("delta", "one "), ("delta", "two"), ("final", "one two")]
    assert (
        (_kinds(run_1.items), run_1.error),
        (_kinds(run_2.items), run_2.error),
        (
            _kinds(run_3.items),
            getattr(run_3.error, "code", run_3.error),
            _PER_CALL_FLOOR <= run_3.elapsed < _BOUND,
        ),
    ) == ((whole, None), (whole, None), ([("delta", "three ")], "timeout", True)), run_3.elapsed


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_deadline_chat_ignores_stream_deadline(
    provider: str, wire: _Wire, build: Callable[..., Any]
) -> None:
    """(h) chat() has no deadline: a body sent after 0.4 s (deadline 0.2 s) returns normally."""
    client = build(provider)
    wire.queue(_DelayedRoute(0.4, then=_JsonRoute(_chat_body(provider, "late answer"))))
    result = await asyncio.wait_for(client.chat(_messages()), _BOUND)
    assert (
        getattr(_config(provider, _DEADLINE), "stream_deadline_s", "<missing>"),
        result.content,
    ) == (_DEADLINE, "late answer")


# ===========================================================================
# C4: the model policy over a deadline timeout
# ===========================================================================


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_deadline_policy_retries_deadline_before_any_item(
    provider: str, wire: _Wire, build: Callable[..., Any], policy_sleeps: list[float]
) -> None:
    """A deadline hit before any item is retried once (max_retries=1), with a fresh deadline.

    Two requests; the retry's reply (which starts after a 0.05 s pause, so a
    deadline shared with the first attempt would already have passed) reaches the
    caller exactly once.
    """
    client = build(provider)
    wire.queue(
        _StreamRoute([*_opening(provider), _SILENT]),
        _StreamRoute([_Pause(0.05), *_reply(provider, "Hello ", "world")]),
    )
    run = await _run(
        llm_policy.chat_stream(client, _messages(), None, data_residency=False, max_retries=1)
    )
    assert (_kinds(run.items), run.error, len(wire.requests), len(policy_sleeps)) == (
        [("delta", "Hello "), ("delta", "world"), ("final", "Hello world")],
        None,
        2,
        1,
    )


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_deadline_policy_never_retries_after_a_delta(
    provider: str, wire: _Wire, build: Callable[..., Any], policy_sleeps: list[float]
) -> None:
    """A deadline hit after a delta is not retried: one request, the delta, then timeout."""
    client = build(provider)
    wire.queue(
        _StreamRoute([*_opening(provider), _piece(provider, "Hello "), _SILENT]),
        _StreamRoute(_reply(provider, "never ", "sent")),
    )
    run = await _run(
        llm_policy.chat_stream(client, _messages(), None, data_residency=False, max_retries=1)
    )
    assert (
        _kinds(run.items),
        getattr(run.error, "code", run.error),
        len(wire.requests),
        policy_sleeps,
    ) == ([("delta", "Hello ")], "timeout", 1, [])


# ===========================================================================
# C3.7: the malformed usage warning, once per stream
# ===========================================================================


def _usage_frames(usage: dict[str, int]) -> list[bytes]:
    """A text reply whose every chunk (the stop chunk too) carries ``usage``."""
    frames = [_sse(_chunk({"content": p}, usage=usage)) for p in ("Hello ", "big ", "world")]
    frames += [_sse(_chunk({}, finish_reason="stop", usage=usage)), _DONE]
    return frames


def _valid_usage_frames() -> list[bytes]:
    """A text reply and a trailing usage-only chunk with a valid block."""
    return [
        _sse(_chunk({"content": "Fine "})),
        _sse(_chunk({"content": "thanks"})),
        _sse(_chunk({}, finish_reason="stop")),
        _sse(_chunk(usage=_GOOD_USAGE, with_choice=False)),
        _DONE,
    ]


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_usage_malformed_block_warns_once_per_stream(
    provider: str,
    wire: _Wire,
    build: Callable[..., Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Every chunk's usage block is malformed: one warning per chat_stream call.

    Two such calls on one client log it once each (two in all); a third call with
    a valid block adds none and reports that usage.
    """
    _capture_all(caplog, logging.WARNING)
    client = build(provider)
    wire.queue(
        _StreamRoute(_usage_frames(_BAD_USAGE)),
        _StreamRoute(_usage_frames(_BAD_USAGE)),
        _StreamRoute(_valid_usage_frames()),
    )
    runs: list[_Run] = []
    counts: list[int] = []
    for _ in range(3):
        runs.append(await _run(client.chat_stream(_messages(), None)))
        counts.append(_usage_warnings(caplog))
    final = runs[2].items[-1] if runs[2].items else None
    assert (
        [(_kinds(run.items)[-1:], run.error) for run in runs],
        counts,
        getattr(final, "usage", None),
    ) == (
        [
            ([("final", "Hello big world")], None),
            ([("final", "Hello big world")], None),
            ([("final", "Fine thanks")], None),
        ],
        [1, 2, 2],
        LLMUsage(prompt_tokens=7, completion_tokens=3),
    )


async def test_llm_usage_anthropic_stream_never_warns(
    wire: _Wire, build: Callable[..., Any], caplog: pytest.LogCaptureFixture
) -> None:
    """Anthropic doesn't read usage: negative token counts in its events log no usage warning."""
    _capture_all(caplog, logging.WARNING)
    client = build("anthropic")
    frames = [
        *_anthropic_open(usage={"input_tokens": -4, "output_tokens": -1}),
        _anthropic_text("Hello "),
        _anthropic_text("world"),
        *_anthropic_close(output_tokens=-9),
    ]
    wire.queue(_StreamRoute(frames))
    run = await _run(client.chat_stream(_messages(), None))
    assert (_kinds(run.items)[-1:], run.error, _usage_warnings(caplog)) == (
        [("final", "Hello world")],
        None,
        0,
    )


@pytest.mark.parametrize("provider", OPENAI_COMPATIBLE)
async def test_llm_usage_chat_malformed_block_warns_at_most_once(
    provider: str,
    wire: _Wire,
    build: Callable[..., Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """chat() is unchanged: one malformed block, at most one warning (Infomaniak: exactly one)."""
    _capture_all(caplog, logging.WARNING)
    client = build(provider)
    wire.queue(_JsonRoute(_completion("All good", usage=_BAD_USAGE)))
    result = await client.chat(_messages())
    allowed = {1} if provider == "infomaniak" else {0, 1}
    assert (result.content, _usage_warnings(caplog) in allowed) == ("All good", True)


# ===========================================================================
# Logs: no delta text anywhere when the deadline ends a stream
# ===========================================================================


@pytest.mark.parametrize("provider", ALL_PROVIDERS)
async def test_llm_deadline_logs_and_error_never_carry_delta_text(
    provider: str,
    wire: _Wire,
    build: Callable[..., Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The streamed text is in no DEBUG-and-up record and not in the timeout error.

    Non-vacuous: the stream did deliver the marked delta, the call did end with
    the deadline's timeout, and records were captured (the SDKs log at DEBUG).
    """
    _capture_all(caplog, logging.DEBUG)
    client = build(provider)
    text = f"Hello {_CANARY} "
    wire.queue(_StreamRoute([*_opening(provider), _piece(provider, text), _SILENT]))
    run = await _run(client.chat_stream(_messages(), None))
    seen = [caplog.text]
    for record in caplog.records:
        seen += [record.getMessage(), repr(record.args), record.exc_text or ""]
    err = run.error
    error_text = f"{err} {err!r} {getattr(err, 'message', '')}"
    assert (
        _kinds(run.items),
        getattr(err, "code", err),
        [entry for entry in seen if _CANARY in entry],
        _CANARY in error_text,
        bool(caplog.records),
    ) == ([("delta", text)], "timeout", [], False, True)
