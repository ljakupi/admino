"""The agent's timing hooks (GH-244, contract C1.4, agent part).

The timing line's LLM and tool fields (``llm_start_ms``, ``llm_first_byte_ms``,
``llm_ms``, ``tool_ms``) are measured by the agent calling
``admino.request_timing``:
- every LLM call of a run (``llm_policy.chat`` on the JSON path,
  ``llm_policy.chat_stream`` through ``_stream_reply`` on a streamed run) runs
  inside ``request_timing.llm_call()``: entered before the client is called,
  exited after it returned or raised (an LLM error, a retry and its wait
  included);
- ``request_timing.llm_first_byte()`` right after ``llm_policy.chat`` returns
  (JSON), and when the first item of a streamed call arrives, before that
  item's ``on_delta`` (a delta or the final response; once per streamed call),
  never when nothing arrived;
- each tool dispatch (a resumed confirmation's included) runs inside
  ``request_timing.tool_call()``, and the tool-call recorder's write is NOT
  inside it (the dispatch only).

The REAL ``admino.agent.Agent`` runs with a scripted fake LLM (provider
"infomaniak"), a registered echo tool and a recorder; the three hooks are
replaced on the ``admino.request_timing`` module by spies that append to one
event list, as do the fake client, the tool handler, the recorder, the stream
sink and ``llm_policy._sleep``. ``llm_first_byte`` directly after a call's end
is accepted on either side of ``llm_call``'s exit (both are "right after the
call returns").

``admino.request_timing`` is new: it is imported lazily in the fixture, so the
file collects before it exists and each test fails on its own.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

import pytest
from pydantic import BaseModel, Field

from admino.access import Principal
from admino.agent import Agent
from admino.llm import LLMError, LLMResponse, LLMStreamDelta
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolPolicy,
)
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tools.registry import clear_registry, register_tool

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Generator
    from types import TracebackType

    from admino.models import ToolCallRecord


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SESSION: Final = "sess-timing"
_NOW: Final = datetime(2026, 10, 6, 9, 30, tzinfo=UTC)
_PRINCIPAL = Principal(
    user_id=UUID("21111111-2222-4333-8444-555555555555"),
    kind="member",
    org_id=UUID("1f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"),
    role="editor",
)
# The events of one LLM call that ended with a response (JSON path).
_JSON_CALL: Final = [
    "llm_call:enter",
    "client.chat",
    "client.return",
    "llm_call:exit",
    "first_byte",
]
# One allowed dispatch: the handler inside tool_call, the recorder after it.
_DISPATCH: Final = ["tool_call:enter", "handler", "tool_call:exit", "recorder"]


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _SpyContext:
    """Records ``<name>:enter`` / ``<name>:exit`` (also when the block raises).

    Usable with ``with`` and ``async with``; never swallows an exception.
    """

    def __init__(self, events: list[str], name: str) -> None:
        self._events = events
        self._name = name

    def __enter__(self) -> None:
        self._events.append(f"{self._name}:enter")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._events.append(f"{self._name}:exit")

    async def __aenter__(self) -> None:
        self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.__exit__(exc_type, exc, tb)


class _ScriptedLLM:
    """Fake LLM client: ``chat`` plays ``replies``, ``chat_stream`` plays ``streams``.

    A step that is an exception is raised. Events: ``client.chat`` when ``chat``
    is called, then ``client.return`` or ``client.raise``; ``client.chat_stream``
    when ``chat_stream`` is called, ``client.item`` right before each item is
    yielded, ``client.raise`` before a scripted error.
    """

    provider = "infomaniak"

    def __init__(
        self,
        events: list[str],
        *,
        replies: list[LLMResponse | BaseException] | None = None,
        streams: list[list[LLMStreamDelta | LLMResponse | BaseException]] | None = None,
    ) -> None:
        self._events = events
        self._replies = list(replies or [])
        self._streams = list(streams or [])

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        **_: Any,
    ) -> LLMResponse:
        self._events.append("client.chat")
        step = self._replies.pop(0)
        await asyncio.sleep(0)
        if isinstance(step, BaseException):
            self._events.append("client.raise")
            raise step
        self._events.append("client.return")
        return step

    def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        self._events.append("client.chat_stream")
        return self._play(self._streams.pop(0))

    async def _play(
        self, script: list[LLMStreamDelta | LLMResponse | BaseException]
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        for step in script:
            await asyncio.sleep(0)
            if isinstance(step, BaseException):
                self._events.append("client.raise")
                raise step
            self._events.append("client.item")
            yield step


class _Recorder:
    """Stand-in ``ToolCallRecorder``: one ``recorder`` event per call."""

    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def __call__(self, **_: Any) -> None:
        self._events.append("recorder")


class _Sink:
    """What a streamed run reports to: ``on_delta`` / ``on_tool_call`` events."""

    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def on_delta(self, _text: str) -> None:
        self._events.append("on_delta")

    async def on_tool_call(self, _record: ToolCallRecord) -> None:
        self._events.append("on_tool_call")


class EchoArgs(BaseModel):
    """Args of the echo test tool."""

    text: str = Field(min_length=1, max_length=100)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Clear the global tool registry before and after every test."""
    clear_registry()
    yield
    clear_registry()


@pytest.fixture()
def events(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The shared event list, with the three hooks replaced by spies.

    The hooks are patched on ``admino.request_timing`` (and on ``admino.agent``
    too, if the agent imported the names themselves); ``llm_policy._sleep``
    records a ``sleep`` event instead of sleeping.
    """
    from admino import agent as agent_module
    from admino import llm_policy, request_timing

    log: list[str] = []

    def first_byte() -> None:
        log.append("first_byte")

    async def no_sleep(_delay: float) -> None:
        log.append("sleep")

    spies: dict[str, Any] = {
        "llm_call": lambda: _SpyContext(log, "llm_call"),
        "tool_call": lambda: _SpyContext(log, "tool_call"),
        "llm_first_byte": first_byte,
    }
    for name, spy in spies.items():
        monkeypatch.setattr(request_timing, name, spy)
        if hasattr(agent_module, name):
            monkeypatch.setattr(agent_module, name, spy)
    monkeypatch.setattr(llm_policy, "_sleep", no_sleep)
    return log


@pytest.fixture()
def echo(events: list[str]) -> None:
    """echo.say (allow) and echo.write (confirm), registered; the handler logs ``handler``."""

    async def handle(args: EchoArgs, **_: object) -> str:
        events.append("handler")
        return f"echo:{args.text}"

    for action in ("say", "write"):
        register_tool("echo", action, f"echo {action}", EchoArgs)(handle)


def _policy() -> ToolPolicy:
    return ToolPolicy(
        permissions=PermissionsConfig(
            tools={"echo": ToolPermissions(actions={"say": "allow", "write": "confirm"})}
        ),
        data_residency=False,
    )


def _agent(llm: _ScriptedLLM, events: list[str], *, llm_max_retries: int = 0) -> Agent:
    return Agent(
        llm_client=llm,
        tool_call_recorder=_Recorder(events),
        agent_config=AgentConfig(
            max_tool_calls=5,
            max_context_messages=20,
            confirmation_timeout_s=60.0,
            llm_max_retries=llm_max_retries,
        ),
        clock=lambda: _NOW,
    )


async def _run(
    agent: Agent,
    message: str = "hello",
    *,
    stream: Any = None,
    history: list[LLMMessage] | None = None,
    pending: PendingConfirmation | None = None,
) -> AgentResult:
    return await asyncio.wait_for(
        agent.run(
            message,
            _SESSION,
            history=list(history or []),
            principal=_PRINCIPAL,
            tool_policy=_policy(),
            pending_confirmation=pending,
            stream=stream,
        ),
        5.0,
    )


def _run_stream(events: list[str]) -> Any:
    from admino.streaming import RunStream

    sink = _Sink(events)
    return RunStream(on_delta=sink.on_delta, on_tool_call=sink.on_tool_call)


def _canonical(events: list[str]) -> list[str]:
    """``first_byte`` right before ``llm_call:exit`` is put right after it.

    Both orders mean "right after the call returned"; nothing else moves.
    """
    out = list(events)
    for i in range(len(out) - 1):
        if out[i] == "first_byte" and out[i + 1] == "llm_call:exit":
            out[i], out[i + 1] = out[i + 1], out[i]
    return out


def _final(content: str = "", *calls: ToolCall) -> LLMResponse:
    return LLMResponse(content=content, tool_calls=list(calls), model="m", done=not calls)


def _say(call_id: str = "c-1") -> ToolCall:
    return ToolCall(tool="echo", action="say", args={"text": "hi"}, tool_call_id=call_id)


def _err(code: str) -> LLMError:
    return LLMError(f"Fixed {code} text.", code=code)


# ===========================================================================
# 1. JSON path
# ===========================================================================


async def test_agent_timing_json_run_wraps_each_llm_call_and_each_dispatch(
    events: list[str], echo: None
) -> None:
    """Call 1 asks for echo.say, call 2 answers: two timed LLM calls, each followed
    by its first-byte mark, and one timed dispatch with the recorder after it."""
    llm = _ScriptedLLM(events, replies=[_final("", _say()), _final("Done.")])

    result = await _run(_agent(llm, events))

    assert (result.status, result.response) == ("final", "Done.")
    assert _canonical(events) == [*_JSON_CALL, *_DISPATCH, *_JSON_CALL]


async def test_agent_timing_json_retry_and_its_wait_stay_inside_one_llm_call(
    events: list[str],
) -> None:
    llm = _ScriptedLLM(events, replies=[_err("provider_unavailable"), _final("Fine.")])

    result = await _run(_agent(llm, events, llm_max_retries=1))

    assert (result.status, result.response) == ("final", "Fine.")
    assert _canonical(events) == [
        "llm_call:enter",
        "client.chat",
        "client.raise",
        "sleep",
        "client.chat",
        "client.return",
        "llm_call:exit",
        "first_byte",
    ]


async def test_agent_timing_json_llm_error_exits_the_llm_call_without_a_first_byte(
    events: list[str],
) -> None:
    llm = _ScriptedLLM(events, replies=[_err("not_configured")])

    result = await _run(_agent(llm, events))

    assert (result.status, result.error_code) == ("error", "not_configured")
    assert events == ["llm_call:enter", "client.chat", "client.raise", "llm_call:exit"]


async def test_agent_timing_resumed_confirmation_dispatch_runs_inside_tool_call(
    events: list[str], echo: None
) -> None:
    write = ToolCall(tool="echo", action="write", args={"text": "note"}, tool_call_id="c-w")
    now = datetime.now(UTC)
    pending = PendingConfirmation(
        confirmation_id="conf-timing-1",
        session_id=_SESSION,
        tool_call=write,
        created_at=now,
        expires_at=now + timedelta(seconds=60),
    )
    prior = [
        LLMMessage(role="user", content="write a note"),
        LLMMessage(
            role="assistant",
            content="",
            tool_use_blocks=[
                {"type": "tool_use", "id": "c-w", "name": "echo.write", "input": {"text": "note"}}
            ],
        ),
    ]
    llm = _ScriptedLLM(events, replies=[_final("Written.")])

    result = await _run(_agent(llm, events), "", history=prior, pending=pending)

    assert (result.status, result.response) == ("final", "Written.")
    assert _canonical(events) == [*_DISPATCH, *_JSON_CALL]


# ===========================================================================
# 2. Streamed path
# ===========================================================================


async def test_agent_timing_stream_first_byte_marks_the_first_item_before_its_delta(
    events: list[str],
) -> None:
    """Two deltas and the final response: one timed call; the first byte is marked
    once, when the first delta arrives and before it is forwarded."""
    llm = _ScriptedLLM(
        events,
        streams=[[LLMStreamDelta(content="Hel"), LLMStreamDelta(content="lo"), _final("Hello")]],
    )

    result = await _run(_agent(llm, events), stream=_run_stream(events))

    assert (result.status, result.response) == ("final", "Hello")
    assert _canonical(events) == [
        "llm_call:enter",
        "client.chat_stream",
        "client.item",
        "first_byte",
        "on_delta",
        "client.item",
        "on_delta",
        "client.item",
        "llm_call:exit",
    ]


async def test_agent_timing_stream_run_wraps_each_llm_call_and_each_dispatch(
    events: list[str], echo: None
) -> None:
    """Call 1's only item is a final response asking for echo.say (its first byte),
    then the timed dispatch, the recorder and the record, then call 2."""
    llm = _ScriptedLLM(
        events,
        streams=[
            [_final("", _say())],
            [LLMStreamDelta(content="Done."), _final("Done.")],
        ],
    )

    result = await _run(_agent(llm, events), stream=_run_stream(events))

    assert (result.status, result.response) == ("final", "Done.")
    assert _canonical(events) == [
        "llm_call:enter",
        "client.chat_stream",
        "client.item",
        "llm_call:exit",
        "first_byte",
        *_DISPATCH,
        "on_tool_call",
        "llm_call:enter",
        "client.chat_stream",
        "client.item",
        "first_byte",
        "on_delta",
        "client.item",
        "llm_call:exit",
    ]


async def test_agent_timing_stream_retry_and_its_wait_stay_inside_one_llm_call(
    events: list[str],
) -> None:
    llm = _ScriptedLLM(
        events,
        streams=[
            [_err("provider_unavailable")],
            [LLMStreamDelta(content="Fine."), _final("Fine.")],
        ],
    )

    result = await _run(_agent(llm, events, llm_max_retries=1), stream=_run_stream(events))

    assert (result.status, result.response) == ("final", "Fine.")
    assert _canonical(events) == [
        "llm_call:enter",
        "client.chat_stream",
        "client.raise",
        "sleep",
        "client.chat_stream",
        "client.item",
        "first_byte",
        "on_delta",
        "client.item",
        "llm_call:exit",
    ]


async def test_agent_timing_stream_llm_error_exits_the_llm_call_without_a_first_byte(
    events: list[str],
) -> None:
    llm = _ScriptedLLM(events, streams=[[_err("not_configured")]])

    result = await _run(_agent(llm, events), stream=_run_stream(events))

    assert (result.status, result.error_code) == ("error", "not_configured")
    assert events == ["llm_call:enter", "client.chat_stream", "client.raise", "llm_call:exit"]
