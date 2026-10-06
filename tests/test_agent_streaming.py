"""Streamed agent runs and stop generation (GH-8, contract section C3).

Pinned here:
- ``Agent.run`` gains one keyword-only ``stream`` parameter, default None, and
  ``"stopped"`` is an ``AgentStatus``.
- ``stream=None``: today's path (``chat()`` is used, ``chat_stream`` never).
- ``stream`` given (an ``admino.streaming.RunStream``): every LLM call goes
  through ``llm_policy.chat_stream`` (never ``chat``) with the context and tools
  the JSON path sends; each delta's text reaches ``on_delta`` in order and
  unchanged, while the call is still open; the final response is used exactly
  like today's ``chat()`` response (same status, response and history as a JSON
  run of the same replies); each ``ToolCallRecord`` reaches ``on_tool_call``
  right after its recorder call, in the order of ``AgentResult.tool_calls`` (the
  resumed pre-dispatch's record first); the residency guard still ends the run
  before any call or event; a retryable error is retried only before the first
  item; an LLM error ends the run like today's (deltas already sent stay sent).
- Stop (``stream.stop``): (a) set before an LLM call, there is no call; (b) set
  during a call, the call's stream is closed at once, also while the provider
  sends nothing, and the text forwarded from THAT call becomes the response and
  the assistant message (no tool_use blocks); (c) set before a dispatch, that
  call and the rest of the batch are not dispatched; (d) a dispatch in progress
  is never cancelled: it finishes, is recorded once, its record is emitted and
  its result appended; (e) the approved call of a resume always runs; (f) a
  stopped result has no error_code and no pending_confirmation; a stop after
  the final response arrived changes nothing.
- C11 (audit core L-1/L-2): a stopped run's response, and its assistant message,
  is the interrupted call's forwarded text up to and including its last ASCII
  whitespace (space, tab, LF, CR; NBSP, U+3000 and U+2003 are no boundary), so a
  key cut by the stop is dropped with its unfinished word; no message when that
  leaves ""; capped at 65536 characters when a fake stream forwards more; a lone
  surrogate in the forwarded text never makes the run raise (no ValidationError
  carrying answer text). ``on_delta`` still gets every raw piece.
- No log record carries a delta's text, a tool argument or the user message.

The fake streaming LLM (``StreamLLM``, provider "infomaniak") plays one
scripted list per ``chat_stream`` call: ``LLMStreamDelta`` items and the final
``LLMResponse`` are yielded, an exception is raised, a ``_Park`` step sets its
``reached`` event and waits (bounded) for its ``release`` event, a ``_Do`` step
runs an action. It records every call (messages copied) and, in a ``finally``,
how each generator ended ("parked" = closed while waiting at a park). Its
``chat()`` fails the test on a streamed run. ``_SlowTool`` is a handler that
parks until released and records whether it finished or was cancelled.

The new names (``admino.streaming``, the ``stream`` keyword) are used lazily so
each test fails on its own before the implementation exists.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import typing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

import pytest
from pydantic import BaseModel, Field

from admino import models as models_module
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
from tests.credential_keys import openai_project_key

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Generator

    from admino.models import ToolCallRecord


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SESSION: Final = "sess-stream"
# Every wait of a test on the agent is bounded by this.
_BOUND_S: Final = 5.0
# A park that is never released gives up after this (longer than _BOUND_S, so a
# test that waits on the agent fails on its own bound first).
_PARK_LIMIT_S: Final = 30.0
_GENERIC_REPLY: Final = (
    "I hit an error while processing your request. Please try again in a moment."
)
_NOW: Final = datetime(2026, 10, 6, 9, 30, tzinfo=UTC)
_NBSP: Final = chr(0xA0)
_IDEOGRAPHIC_SPACE: Final = chr(0x3000)
_EM_SPACE: Final = chr(0x2003)
_LONE_SURROGATE: Final = chr(0xD83D)  # the high half of an emoji, without its low half
_U_UMLAUT: Final = chr(0xFC)
_LIGATURE_FI: Final = chr(0xFB01)
_FULLWIDTH_A: Final = chr(0xFF21)

_PRINCIPAL = Principal(
    user_id=UUID("11111111-2222-4333-8444-555555555555"),
    kind="member",
    org_id=UUID("0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"),
    role="editor",
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class _Park:
    """A script step: set ``reached``, then wait (bounded) until ``release`` is set."""

    reached: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass(frozen=True, eq=False)
class _Do:
    """A script step that runs ``action`` when the agent asks for the next item."""

    action: Callable[[], object]


StreamStep = LLMStreamDelta | LLMResponse | BaseException | _Park | _Do


class StreamLLM:
    """Scripted streaming LLM client: each ``chat_stream`` call plays the next script.

    ``calls`` holds every ``chat_stream`` call's (copied messages, tools);
    ``endings`` maps each call's index to how its generator ended: "exhausted"
    (played to the end), "raised" (a scripted exception), "parked" (closed while
    waiting at a ``_Park``) or "running" (closed at an item). ``chat()`` answers
    from ``replies`` (the JSON path) and fails when there is none, so it fails the
    test on a streamed run.
    """

    def __init__(
        self,
        scripts: list[list[StreamStep]],
        *,
        replies: list[LLMResponse] | None = None,
        provider: str = "infomaniak",
    ) -> None:
        self.provider = provider
        self._scripts = list(scripts)
        self._replies = list(replies or [])
        self.calls: list[tuple[list[LLMMessage], list[dict[str, Any]] | None]] = []
        self.chat_calls: list[tuple[list[LLMMessage], list[dict[str, Any]] | None]] = []
        self.endings: dict[int, str] = {}

    def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        index = len(self.calls)
        self.calls.append((list(messages), tools))
        if index >= len(self._scripts):
            msg = "chat_stream called more often than scripted"
            raise AssertionError(msg)
        return self._play(index, self._scripts[index])

    async def _play(
        self, index: int, script: list[StreamStep]
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        state = "running"
        try:
            for step in script:
                if isinstance(step, _Park):
                    state = "parked"
                    step.reached.set()
                    await asyncio.wait_for(step.release.wait(), _PARK_LIMIT_S)
                    state = "running"
                elif isinstance(step, _Do):
                    step.action()
                elif isinstance(step, BaseException):
                    state = "raised"
                    raise step
                else:
                    yield step
            state = "exhausted"
        finally:
            self.endings[index] = state

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.chat_calls.append((list(messages), tools))
        if not self._replies:
            msg = "chat() must not be called on a streamed run"
            raise AssertionError(msg)
        return self._replies.pop(0)


class _Recorder:
    """Stand-in ``ToolCallRecorder``: records each call's keywords."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, **kwargs: Any) -> None:
        self.calls.append(dict(kwargs))

    def outcomes(self) -> list[tuple[str, str, str, bool]]:
        """(tool, action, decision, success) of every recorded call, in order."""
        return [(c["tool"], c["action"], c["decision"], c["success"]) for c in self.calls]


class _Sink:
    """Collects what a streamed run reports, in order.

    ``events`` holds ("delta", text) and ("tool_call", record) items. With a
    recorder, each record also notes how many recorder calls had happened when
    it arrived. ``on_delta_hook`` / ``on_record_hook`` run inside the callbacks.
    """

    def __init__(self, recorder: _Recorder | None = None) -> None:
        self.events: list[tuple[str, Any]] = []
        self.recorder_calls_at_record: list[int] = []
        self.on_delta_hook: Callable[[str], object] | None = None
        self.on_record_hook: Callable[[ToolCallRecord], object] | None = None
        self._recorder = recorder

    async def on_delta(self, text: str) -> None:
        self.events.append(("delta", text))
        if self.on_delta_hook is not None:
            self.on_delta_hook(text)

    async def on_tool_call(self, record: ToolCallRecord) -> None:
        self.events.append(("tool_call", record))
        if self._recorder is not None:
            self.recorder_calls_at_record.append(len(self._recorder.calls))
        if self.on_record_hook is not None:
            self.on_record_hook(record)

    @property
    def deltas(self) -> list[str]:
        return [value for kind, value in self.events if kind == "delta"]

    @property
    def records(self) -> list[ToolCallRecord]:
        return [value for kind, value in self.events if kind == "tool_call"]


class EchoArgs(BaseModel):
    """Args of the echo and slow test tools."""

    text: str = Field(min_length=1, max_length=100)


class _Echo:
    """The echo.* handler: returns ``echo:<text>`` and records every text it ran with."""

    def __init__(self) -> None:
        self.ran: list[str] = []

    async def handle(self, args: EchoArgs, **_: object) -> str:
        self.ran.append(args.text)
        return f"echo:{args.text}"


class _SlowTool:
    """The slow.run handler: sets ``executing``, waits for ``release``, then finishes.

    ``finished`` is set only once it returns its result; ``cancelled`` when a
    cancellation reached it while it waited.
    """

    def __init__(self) -> None:
        self.executing = asyncio.Event()
        self.release = asyncio.Event()
        self.finished = False
        self.cancelled = False

    async def handle(self, args: EchoArgs, **_: object) -> str:
        self.executing.set()
        try:
            await asyncio.wait_for(self.release.wait(), _PARK_LIMIT_S)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        self.finished = True
        return f"slow:{args.text}"


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
def recorder() -> _Recorder:
    return _Recorder()


@pytest.fixture()
def echo() -> _Echo:
    """echo.say (allow), echo.write (confirm) and echo.shout (deny), registered."""
    tool = _Echo()
    for action in ("say", "write", "shout"):
        register_tool("echo", action, f"echo {action}", EchoArgs)(tool.handle)
    return tool


@pytest.fixture()
def slow() -> _SlowTool:
    """slow.run (allow), registered: parks until the test releases it."""
    tool = _SlowTool()
    register_tool("slow", "run", "slow run", EchoArgs)(tool.handle)
    return tool


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Patch ``llm_policy._sleep`` to record each retry delay instead of sleeping."""
    from admino import llm_policy

    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(llm_policy, "_sleep", fake_sleep)
    return slept


def _policy(*, data_residency: bool = False) -> ToolPolicy:
    return ToolPolicy(
        permissions=PermissionsConfig(
            tools={
                "echo": ToolPermissions(
                    actions={"say": "allow", "write": "confirm", "shout": "deny"}
                ),
                "slow": ToolPermissions(actions={"run": "allow"}),
            }
        ),
        data_residency=data_residency,
    )


def _config(*, llm_max_retries: int = 0) -> AgentConfig:
    return AgentConfig(
        max_tool_calls=5,
        max_context_messages=20,
        confirmation_timeout_s=60.0,
        llm_max_retries=llm_max_retries,
    )


def _fixed_clock() -> datetime:
    return _NOW


def _agent(fake: StreamLLM, recorder: _Recorder, *, config: AgentConfig | None = None) -> Agent:
    return Agent(
        llm_client=fake,
        tool_call_recorder=recorder,
        agent_config=config or _config(),
        clock=_fixed_clock,
    )


def _run_stream(sink: _Sink) -> Any:
    """A ``RunStream`` reporting to ``sink`` (imported lazily: the module is new)."""
    from admino.streaming import RunStream

    return RunStream(on_delta=sink.on_delta, on_tool_call=sink.on_tool_call)


async def _run(
    agent: Agent,
    message: str = "hello",
    *,
    stream: Any,
    history: list[LLMMessage] | None = None,
    pending: PendingConfirmation | None = None,
    data_residency: bool = False,
) -> AgentResult:
    return await agent.run(
        message,
        _SESSION,
        history=list(history or []),
        principal=_PRINCIPAL,
        tool_policy=_policy(data_residency=data_residency),
        pending_confirmation=pending,
        stream=stream,
    )


def _start(agent: Agent, message: str = "hello", **kwargs: Any) -> asyncio.Task[AgentResult]:
    return asyncio.ensure_future(_run(agent, message, **kwargs))


async def _finish(task: asyncio.Task[AgentResult]) -> AgentResult:
    return await asyncio.wait_for(task, _BOUND_S)


async def _until_set(event: asyncio.Event, task: asyncio.Task[AgentResult]) -> None:
    """Wait (bounded) for ``event``; fail at once with the run's error if it ended first."""
    waiter = asyncio.ensure_future(event.wait())
    done, _ = await asyncio.wait(
        {waiter, task}, timeout=_BOUND_S, return_when=asyncio.FIRST_COMPLETED
    )
    if waiter in done:
        return
    waiter.cancel()
    if task in done:
        task.result()
        msg = "the run ended before reaching the expected point"
        raise AssertionError(msg)
    msg = "timed out waiting for the expected point of the run"
    raise AssertionError(msg)


async def _until(predicate: Callable[[], bool], task: asyncio.Task[AgentResult]) -> None:
    """Poll (bounded) until ``predicate()`` holds; fail if the run ends first."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _BOUND_S
    while not predicate():
        if task.done():
            task.result()
            msg = "the run ended before the expected state"
            raise AssertionError(msg)
        if loop.time() > deadline:
            msg = "timed out waiting for the expected state"
            raise AssertionError(msg)
        await asyncio.sleep(0.001)


async def _settle() -> None:
    """Give the agent a few loop turns to react to a stop (no wall-clock delay)."""
    for _ in range(20):
        await asyncio.sleep(0)


def _delta(text: str) -> LLMStreamDelta:
    return LLMStreamDelta(content=text)


def _final(content: str = "", *calls: ToolCall) -> LLMResponse:
    return LLMResponse(content=content, tool_calls=list(calls), model="m", done=not calls)


def _call(tool: str, action: str, text: str, call_id: str) -> ToolCall:
    return ToolCall(tool=tool, action=action, args={"text": text}, tool_call_id=call_id)


def _err(code: str) -> LLMError:
    return LLMError(f"Fixed {code} text.", code=code)


def _user(text: str) -> LLMMessage:
    return LLMMessage(role="user", content=text)


def _assistant(text: str) -> LLMMessage:
    return LLMMessage(role="assistant", content=text)


def _tool_turn(content: str, *calls: ToolCall) -> LLMMessage:
    """The assistant turn the agent stores for a response that requested ``calls``."""
    return LLMMessage(
        role="assistant",
        content=content,
        tool_use_blocks=[
            {
                "type": "tool_use",
                "id": call.tool_call_id,
                "name": f"{call.tool}.{call.action}",
                "input": call.args,
            }
            for call in calls
        ],
    )


def _tool_result(content: str, call_id: str) -> LLMMessage:
    return LLMMessage(role="tool", content=content, tool_call_id=call_id)


def _outcome(record: ToolCallRecord) -> tuple[str, str, dict[str, Any], str, bool]:
    """A record without its timing: (tool, action, args, permission, success)."""
    return (record.tool, record.action, record.args, record.permission, record.success)


def _assert_stopped(result: AgentResult, *, response: str, records: list[ToolCallRecord]) -> None:
    """The shape of a stopped run's result (C3 f)."""
    assert (
        result.status,
        result.response,
        result.error_code,
        result.pending_confirmation,
        result.tool_calls,
    ) == ("stopped", response, None, None, records)


def _pending(call: ToolCall) -> PendingConfirmation:
    now = datetime.now(UTC)
    return PendingConfirmation(
        confirmation_id="conf-stream-1",
        session_id=_SESSION,
        tool_call=call,
        created_at=now,
        expires_at=now + timedelta(seconds=60),
    )


def _log_texts(records: list[logging.LogRecord]) -> str:
    """Everything a log record could show: message, raw args and exception text."""
    parts: list[str] = []
    for record in records:
        parts.append(record.getMessage())
        parts.append(repr(record.args))
        if record.exc_info:
            parts.append(logging.Formatter().formatException(record.exc_info))
        if record.exc_text:
            parts.append(record.exc_text)
    return "\n".join(parts)


# ===========================================================================
# 1. Surface
# ===========================================================================


class TestSurface:
    """The new keyword and status."""

    def test_agent_run_has_keyword_only_stream_defaulting_to_none(self) -> None:
        param = inspect.signature(Agent.run).parameters.get("stream")

        assert param is not None, "Agent.run must take a stream keyword"
        assert (param.kind, param.default) == (inspect.Parameter.KEYWORD_ONLY, None)

    def test_agent_status_includes_stopped(self) -> None:
        assert "stopped" in typing.get_args(models_module.AgentStatus)
        assert AgentResult(status="stopped").status == "stopped"

    async def test_agent_stream_none_uses_chat_and_never_chat_stream(
        self, recorder: _Recorder
    ) -> None:
        """stream=None is today's path: one chat() call, no chat_stream call."""
        fake = StreamLLM([], replies=[_final("Hi there")])

        result = await _run(_agent(fake, recorder), stream=None)

        assert (result.status, result.response) == ("final", "Hi there")
        assert (len(fake.chat_calls), len(fake.calls)) == (1, 0)


# ===========================================================================
# 2. Streamed runs
# ===========================================================================


def _two_step_replies() -> tuple[list[LLMResponse], list[list[StreamStep]]]:
    """One run's replies (echo.say, then text) as JSON replies and as stream scripts."""
    say = _call("echo", "say", "x", "c-1")
    first = _final("Let me check. ", say)
    second = _final("All done.")
    scripts: list[list[StreamStep]] = [
        [_delta("Let me "), _delta("check. "), first],
        [_delta("All "), _delta("done."), second],
    ]
    return [first, second], scripts


_PRIOR: Final = [_user("earlier question"), _assistant("earlier answer")]


class TestStreamedRun:
    """What a run with a RunStream sends, forwards and returns."""

    async def test_agent_stream_every_llm_call_uses_chat_stream_never_chat(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        _, scripts = _two_step_replies()
        fake = StreamLLM(scripts)

        result = await _run(_agent(fake, recorder), stream=_run_stream(_Sink()))

        assert (result.status, result.response) == ("final", "All done.")
        assert (len(fake.calls), len(fake.chat_calls)) == (2, 0)

    async def test_agent_stream_sends_the_json_paths_context_and_tools(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """Every streamed LLM call gets exactly the messages and tools of the JSON run."""
        replies, scripts = _two_step_replies()
        json_fake = StreamLLM([], replies=replies)
        stream_fake = StreamLLM(scripts)

        await _run(_agent(json_fake, recorder), stream=None, history=_PRIOR)
        await _run(_agent(stream_fake, recorder), stream=_run_stream(_Sink()), history=_PRIOR)

        assert len(stream_fake.calls) == 2
        assert stream_fake.calls == json_fake.chat_calls

    async def test_agent_stream_run_ends_like_the_json_run_of_the_same_replies(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """The final response is used like chat()'s: same status, response, history, records."""
        replies, scripts = _two_step_replies()

        json_result = await _run(
            _agent(StreamLLM([], replies=replies), recorder), stream=None, history=_PRIOR
        )
        stream_result = await _run(
            _agent(StreamLLM(scripts), recorder), stream=_run_stream(_Sink()), history=_PRIOR
        )

        say = _call("echo", "say", "x", "c-1")
        assert stream_result.history == [
            *_PRIOR,
            _user("hello"),
            _tool_turn("Let me check. ", say),
            _tool_result("echo:x", "c-1"),
            _assistant("All done."),
        ]
        assert (
            stream_result.status,
            stream_result.response,
            stream_result.history,
            [_outcome(r) for r in stream_result.tool_calls],
        ) == (
            json_result.status,
            json_result.response,
            json_result.history,
            [_outcome(r) for r in json_result.tool_calls],
        )

    async def test_agent_stream_passes_each_delta_text_unchanged_in_order(
        self, recorder: _Recorder
    ) -> None:
        """Raw text goes to on_delta as is: no NFKC, no trimming, no regrouping."""
        pieces = [
            "  Gr" + _U_UMLAUT + "ezi",
            "\t" + _LIGATURE_FI + "ne ",
            _FULLWIDTH_A + "B\n",
            "end",
        ]
        text = "".join(pieces)
        sink = _Sink()
        fake = StreamLLM([[*(_delta(piece) for piece in pieces), _final(text)]])

        result = await _run(_agent(fake, recorder), stream=_run_stream(sink))

        assert sink.events == [("delta", piece) for piece in pieces]
        assert (result.status, result.response) == ("final", text)
        assert result.history == [_user("hello"), _assistant(text)]

    async def test_agent_stream_forwards_deltas_while_the_call_is_still_open(
        self, recorder: _Recorder
    ) -> None:
        """Deltas reach on_delta as they arrive, not when the call ends."""
        park = _Park()
        sink = _Sink()
        fake = StreamLLM([[_delta("first "), _delta("second "), park, _final("first second ")]])

        task = _start(_agent(fake, recorder), stream=_run_stream(sink))
        await _until_set(park.reached, task)
        await _until(lambda: len(sink.deltas) == 2, task)
        forwarded_while_open = list(sink.deltas)
        park.release.set()
        result = await _finish(task)

        assert forwarded_while_open == ["first ", "second "]
        assert (result.status, result.response) == ("final", "first second ")

    async def test_agent_stream_emits_tool_records_in_order_equal_to_result_tool_calls(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """A batch of allow, deny and confirm: every record is emitted, the confirm one too."""
        sink = _Sink()
        batch = (
            _call("echo", "say", "hi", "c-1"),
            _call("echo", "shout", "loud", "c-2"),
            _call("echo", "write", "note", "c-3"),
        )
        fake = StreamLLM([[_delta("On it. "), _final("On it. ", *batch)]])

        result = await _run(_agent(fake, recorder), stream=_run_stream(sink))

        assert result.status == "awaiting_confirmation"
        assert result.pending_confirmation is not None
        assert result.pending_confirmation.tool_call.action == "write"
        assert sink.records == result.tool_calls
        assert [_outcome(r) for r in sink.records] == [
            ("echo", "say", {"text": "hi"}, "allow", True),
            ("echo", "shout", {"text": "loud"}, "deny", False),
            ("echo", "write", {"text": "note"}, "confirm", False),
        ]

    async def test_agent_stream_emits_each_tool_record_after_its_recorder_call(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """Record n is emitted once the recorder has been awaited n times (never before)."""
        sink = _Sink(recorder)
        batch = (
            _call("echo", "say", "hi", "c-1"),
            _call("echo", "shout", "loud", "c-2"),
            _call("echo", "write", "note", "c-3"),
        )
        fake = StreamLLM([[_final("", *batch)]])

        await _run(_agent(fake, recorder), stream=_run_stream(sink))

        assert sink.recorder_calls_at_record == [1, 2, 3]

    async def test_agent_stream_resume_emits_the_approved_calls_record_first(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        write = _call("echo", "write", "note", "c-w")
        prior = [_user("write a note"), _tool_turn("", write)]
        sink = _Sink()
        fake = StreamLLM([[_delta("Written."), _final("Written.")]])

        result = await _run(
            _agent(fake, recorder),
            "",
            stream=_run_stream(sink),
            history=prior,
            pending=_pending(write),
        )

        assert (result.status, result.response) == ("final", "Written.")
        assert [kind for kind, _ in sink.events] == ["tool_call", "delta"]
        assert sink.records == result.tool_calls
        assert [_outcome(r) for r in sink.records] == [
            ("echo", "write", {"text": "note"}, "confirm", True)
        ]

    async def test_agent_stream_interleaves_deltas_and_records_in_run_order(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """Call 1's deltas, then call 1's tool records, then call 2's deltas."""
        _, scripts = _two_step_replies()
        sink = _Sink()

        result = await _run(_agent(StreamLLM(scripts), recorder), stream=_run_stream(sink))

        assert [
            (kind, value if kind == "delta" else _outcome(value)) for kind, value in sink.events
        ] == [
            ("delta", "Let me "),
            ("delta", "check. "),
            ("tool_call", ("echo", "say", {"text": "x"}, "allow", True)),
            ("delta", "All "),
            ("delta", "done."),
        ]
        assert sink.records == result.tool_calls

    async def test_agent_stream_residency_blocks_before_any_call_or_event(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        from admino import llm_policy

        sink = _Sink()
        fake = StreamLLM([[_delta("never"), _final("never")]], provider="anthropic")

        result = await _run(_agent(fake, recorder), stream=_run_stream(sink), data_residency=True)

        blocked = llm_policy.residency_blocked_error().message
        assert (result.status, result.error_code, result.response) == (
            "error",
            "residency_blocked",
            blocked,
        )
        assert (fake.calls, fake.chat_calls, sink.events, recorder.calls) == ([], [], [], [])

    async def test_agent_stream_retries_a_retryable_error_before_the_first_item(
        self, recorder: _Recorder, sleeps: list[float]
    ) -> None:
        """Retried through llm_policy (one _sleep) with the same request; deltas sent once."""
        sink = _Sink()
        fake = StreamLLM([[_err("provider_unavailable")], [_delta("Fine."), _final("Fine.")]])

        result = await _run(
            _agent(fake, recorder, config=_config(llm_max_retries=1)), stream=_run_stream(sink)
        )

        assert (result.status, result.response) == ("final", "Fine.")
        assert sink.deltas == ["Fine."]
        assert len(sleeps) == 1
        assert len(fake.calls) == 2
        assert fake.calls[0] == fake.calls[1]

    @pytest.mark.parametrize(
        ("script", "forwarded", "code", "reply"),
        [
            pytest.param(
                [_err("not_configured")],
                [],
                "not_configured",
                "Fixed not_configured text.",
                id="coded-before-the-first-item",
            ),
            pytest.param(
                [_delta("Partial "), _err("provider_unavailable")],
                ["Partial "],
                "provider_unavailable",
                "Fixed provider_unavailable text.",
                id="retryable-after-a-delta",
            ),
            pytest.param(
                [_delta("Partial "), RuntimeError("boom-internal-detail")],
                ["Partial "],
                None,
                _GENERIC_REPLY,
                id="uncoded-after-a-delta",
            ),
        ],
    )
    async def test_agent_stream_llm_error_ends_the_run_like_a_json_run(
        self,
        recorder: _Recorder,
        sleeps: list[float],
        script: list[StreamStep],
        forwarded: list[str],
        code: str | None,
        reply: str,
    ) -> None:
        """No retry once a delta went out; the error reply ends the history; deltas stay sent."""
        sink = _Sink()
        fake = StreamLLM([script, [_final("never")]])

        result = await _run(
            _agent(fake, recorder, config=_config(llm_max_retries=1)), stream=_run_stream(sink)
        )

        assert (result.status, result.error_code, result.response) == ("error", code, reply)
        assert result.history == [_user("hello"), _assistant(reply)]
        assert sink.deltas == forwarded
        assert (len(fake.calls), sleeps) == (1, [])


# ===========================================================================
# 3. Stop
# ===========================================================================


class TestStop:
    """stream.stop: before, during and between LLM calls and dispatches (C3 a-f)."""

    async def test_agent_stream_stop_before_the_run_makes_no_llm_call(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """(a) Set before the run: no chat_stream call; history = prior + the user message."""
        sink = _Sink()
        stream = _run_stream(sink)
        stream.stop.set()
        fake = StreamLLM([[_delta("never"), _final("never")]])

        result = await _run(_agent(fake, recorder), "new question", stream=stream, history=_PRIOR)

        _assert_stopped(result, response="", records=[])
        assert result.history == [*_PRIOR, _user("new question")]
        assert (fake.calls, fake.chat_calls, sink.events) == ([], [], [])

    async def test_agent_stream_stop_while_the_provider_sends_nothing_closes_the_stream(
        self, recorder: _Recorder
    ) -> None:
        """(b) Parked before the first item: the stream is closed while still parked."""
        park = _Park()
        sink = _Sink()
        stream = _run_stream(sink)
        fake = StreamLLM([[park, _delta("late"), _final("late")]])

        task = _start(_agent(fake, recorder), stream=stream)
        await _until_set(park.reached, task)
        stream.stop.set()
        result = await _finish(task)

        assert fake.endings == {0: "parked"}
        _assert_stopped(result, response="", records=[])
        assert result.history == [_user("hello")]
        assert sink.events == []

    async def test_agent_stream_stop_after_two_deltas_keeps_exactly_the_forwarded_text(
        self, recorder: _Recorder
    ) -> None:
        """(b) The forwarded text is the response and a plain assistant message; no new call.
        The text ends with an ASCII whitespace, so the C11 cut keeps all of it (dropping an
        unfinished last word is pinned in ``TestStopCut``)."""
        park = _Park()
        sink = _Sink()
        stream = _run_stream(sink)
        fake = StreamLLM(
            [
                [_delta("Hello "), _delta("world "), park, _delta("never"), _final("x")],
                [_final("never")],
            ]
        )

        task = _start(_agent(fake, recorder), stream=stream)
        await _until_set(park.reached, task)
        await _until(lambda: len(sink.deltas) == 2, task)
        stream.stop.set()
        result = await _finish(task)

        _assert_stopped(result, response="Hello world ", records=[])
        assert result.history == [_user("hello"), _assistant("Hello world ")]
        assert result.history[-1].tool_use_blocks is None
        assert sink.deltas == ["Hello ", "world "]
        assert (len(fake.calls), fake.endings) == (1, {0: "parked"})

    async def test_agent_stream_stop_during_a_later_call_keeps_only_that_calls_text(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """(b) The response is the interrupted call's text, not the whole run's."""
        park = _Park()
        sink = _Sink()
        stream = _run_stream(sink)
        say = _call("echo", "say", "x", "c-1")
        fake = StreamLLM(
            [
                [_delta("Checking. "), _final("Checking. ", say)],
                [_delta("Found "), park, _final("Found it.")],
            ]
        )

        task = _start(_agent(fake, recorder), stream=stream)
        await _until_set(park.reached, task)
        await _until(lambda: len(sink.deltas) == 2, task)
        stream.stop.set()
        result = await _finish(task)

        _assert_stopped(result, response="Found ", records=sink.records)
        assert result.history == [
            _user("hello"),
            _tool_turn("Checking. ", say),
            _tool_result("echo:x", "c-1"),
            _assistant("Found "),
        ]
        assert [_outcome(r) for r in result.tool_calls] == [
            ("echo", "say", {"text": "x"}, "allow", True)
        ]
        assert fake.endings[1] == "parked"

    async def test_agent_stream_stop_from_on_delta_forwards_nothing_more(
        self, recorder: _Recorder
    ) -> None:
        """(b) A stop set between items: no further delta, the call ends stopped."""
        sink = _Sink()
        stream = _run_stream(sink)
        sink.on_delta_hook = lambda _text: stream.stop.set()
        fake = StreamLLM(
            [
                [_delta("One "), _delta("two "), _delta("three"), _final("One two three")],
                [_final("never")],
            ]
        )

        result = await _run(_agent(fake, recorder), stream=stream)

        _assert_stopped(result, response="One ", records=[])
        assert sink.deltas == ["One "]
        assert result.history == [_user("hello"), _assistant("One ")]
        assert len(fake.calls) == 1

    async def test_agent_stream_stop_during_a_dispatch_lets_it_finish_and_be_recorded(
        self, recorder: _Recorder, echo: _Echo, slow: _SlowTool
    ) -> None:
        """(d)+(c) The running dispatch completes and is recorded; the batch's rest is not run."""
        sink = _Sink()
        stream = _run_stream(sink)
        slow_call = _call("slow", "run", "job", "c-slow")
        say = _call("echo", "say", "after", "c-say")
        fake = StreamLLM(
            [[_delta("Working. "), _final("Working. ", slow_call, say)], [_final("never")]]
        )

        task = _start(_agent(fake, recorder), stream=stream)
        await _until_set(slow.executing, task)
        stream.stop.set()
        await _settle()
        slow.release.set()
        result = await _finish(task)

        assert (slow.finished, slow.cancelled) == (True, False)
        assert recorder.outcomes() == [("slow", "run", "allow", True)]
        assert [_outcome(r) for r in sink.records] == [
            ("slow", "run", {"text": "job"}, "allow", True)
        ]
        _assert_stopped(result, response="", records=sink.records)
        assert result.history == [
            _user("hello"),
            _tool_turn("Working. ", slow_call, say),
            _tool_result("slow:job", "c-slow"),
        ]
        assert (echo.ran, len(fake.calls)) == ([], 1)

    async def test_agent_stream_stop_from_on_tool_call_skips_the_rest_of_the_batch(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """(c) Stop set while the first record is emitted: the second call isn't dispatched."""
        sink = _Sink()
        stream = _run_stream(sink)
        sink.on_record_hook = lambda _record: stream.stop.set()
        one = _call("echo", "say", "one", "c-1")
        two = _call("echo", "say", "two", "c-2")
        fake = StreamLLM([[_final("", one, two)], [_final("never")]])

        result = await _run(_agent(fake, recorder), stream=stream)

        assert echo.ran == ["one"]
        assert recorder.outcomes() == [("echo", "say", "allow", True)]
        _assert_stopped(result, response="", records=sink.records)
        assert [_outcome(r) for r in sink.records] == [
            ("echo", "say", {"text": "one"}, "allow", True)
        ]
        assert result.history[-1] == _tool_result("echo:one", "c-1")
        assert len(fake.calls) == 1

    async def test_agent_stream_stop_after_the_last_dispatch_makes_no_further_llm_call(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """(a) after a batch: the tool result is kept and no follow-up LLM call is made."""
        sink = _Sink()
        stream = _run_stream(sink)
        sink.on_record_hook = lambda _record: stream.stop.set()
        say = _call("echo", "say", "only", "c-1")
        fake = StreamLLM([[_final("", say)], [_delta("never"), _final("never")]])

        result = await _run(_agent(fake, recorder), stream=stream)

        _assert_stopped(result, response="", records=sink.records)
        assert result.history == [
            _user("hello"),
            _tool_turn("", say),
            _tool_result("echo:only", "c-1"),
        ]
        assert (len(fake.calls), sink.deltas) == (1, [])

    async def test_agent_stream_stop_before_an_approval_resume_still_runs_the_approved_call(
        self, recorder: _Recorder, echo: _Echo
    ) -> None:
        """(e) The approved call is dispatched, recorded and emitted; then no LLM call."""
        write = _call("echo", "write", "note", "c-w")
        prior = [_user("write a note"), _tool_turn("", write)]
        sink = _Sink()
        stream = _run_stream(sink)
        stream.stop.set()
        fake = StreamLLM([[_delta("never"), _final("never")]])

        result = await _run(
            _agent(fake, recorder), "", stream=stream, history=prior, pending=_pending(write)
        )

        assert echo.ran == ["note"]
        assert recorder.outcomes() == [("echo", "write", "confirm", True)]
        _assert_stopped(result, response="", records=sink.records)
        assert [_outcome(r) for r in sink.records] == [
            ("echo", "write", {"text": "note"}, "confirm", True)
        ]
        assert result.history == [*prior, _tool_result("echo:note", "c-w")]
        assert (fake.calls, fake.chat_calls) == ([], [])

    async def test_agent_stream_stop_after_the_final_response_changes_nothing(
        self, recorder: _Recorder
    ) -> None:
        """(f) A stop that arrives once the final response was received leaves the run final."""
        sink = _Sink()
        stream = _run_stream(sink)
        fake = StreamLLM([[_delta("Done."), _final("Done."), _Do(stream.stop.set)]])

        result = await _run(_agent(fake, recorder), stream=stream)

        assert (result.status, result.response, result.error_code) == ("final", "Done.", None)
        assert result.history == [_user("hello"), _assistant("Done.")]
        assert sink.deltas == ["Done."]


# ===========================================================================
# 3b. A stopped reply drops its unfinished last word and stays bounded (C11)
# ===========================================================================


async def _stopped_after(
    recorder: _Recorder, deltas: list[str], sink: _Sink, stream: Any
) -> tuple[AgentResult | None, str | None]:
    """Stream ``deltas`` then park; stop once all were forwarded. (result, None) or
    (None, the exception's type name: never its text, which could hold the answer)."""
    park = _Park()
    fake = StreamLLM([[*map(_delta, deltas), park, _delta("never"), _final("never")]])
    task = _start(_agent(fake, recorder), stream=stream)
    await _until_set(park.reached, task)
    await _until(lambda: len(sink.deltas) == len(deltas), task)
    stream.stop.set()
    try:
        return await _finish(task), None
    except Exception as exc:
        return None, type(exc).__name__


class TestStopCut:
    """C11 (audit core L-1/L-2): a stopped run's response, and its assistant message, is the
    interrupted call's forwarded text up to and including its last ASCII whitespace
    (space, tab, LF, CR), then capped at 65536 characters; no message when that is "".
    ``on_delta`` still gets every raw piece (the server's display deltas cut them)."""

    async def test_agent_stream_stop_inside_a_key_drops_the_unfinished_word(
        self, recorder: _Recorder
    ) -> None:
        """Deltas "Here is the key " and a key's first characters, parked, then the stop:
        the response and the stored message end before the key."""
        partial = openai_project_key().text[:10]
        sink = _Sink()
        stream = _run_stream(sink)

        result, error = await _stopped_after(
            recorder, ["Here is the key ", partial[:6], partial[6:]], sink, stream
        )

        assert error is None
        assert result is not None
        _assert_stopped(result, response="Here is the key ", records=[])
        assert result.history == [_user("hello"), _assistant("Here is the key ")]
        assert sink.deltas == ["Here is the key ", partial[:6], partial[6:]]

    @pytest.mark.parametrize(
        ("separator", "kept"),
        [
            (" ", "Kept text alpha "),
            ("\t", "Kept text alpha\t"),
            ("\n", "Kept text alpha\n"),
            ("\r", "Kept text alpha\r"),
            (_NBSP, "Kept text "),
            (_IDEOGRAPHIC_SPACE, "Kept text "),
            (_EM_SPACE, "Kept text "),
        ],
        ids=["space", "tab", "lf", "cr", "nbsp", "u3000", "em-space"],
    )
    async def test_agent_stream_stop_cuts_after_the_last_ascii_whitespace_only(
        self, recorder: _Recorder, separator: str, kept: str
    ) -> None:
        """A stop set from ``on_delta`` after "alpha<sep>be" + "ta": an ASCII whitespace
        ends the kept text; a Unicode space (NBSP, U+3000, U+2003) is no boundary, so
        the whole last word goes."""
        sink = _Sink()
        stream = _run_stream(sink)
        sink.on_delta_hook = lambda text: stream.stop.set() if text == "ta" else None
        fake = StreamLLM(
            [
                [
                    _delta("Kept text "),
                    _delta(f"alpha{separator}be"),
                    _delta("ta"),
                    _delta("never"),
                    _final("never"),
                ],
                [_final("never")],
            ]
        )

        result = await _run(_agent(fake, recorder), stream=stream)

        _assert_stopped(result, response=kept, records=[])
        assert result.history == [_user("hello"), _assistant(kept)]
        assert len(fake.calls) == 1

    async def test_agent_stream_stop_with_no_ascii_whitespace_stores_no_reply(
        self, recorder: _Recorder
    ) -> None:
        """Only an unfinished word was forwarded: the response is "" and no assistant
        message is added."""
        partial = openai_project_key().text[:14]
        sink = _Sink()
        stream = _run_stream(sink)

        result, error = await _stopped_after(
            recorder, [partial[:5], partial[5:] + _NBSP + "x"], sink, stream
        )

        assert error is None
        assert result is not None
        _assert_stopped(result, response="", records=[])
        assert result.history == [_user("hello")]

    async def test_agent_stream_stop_after_more_than_65536_characters_caps_the_reply(
        self, recorder: _Recorder, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A fake stream that bypasses the client cap forwards 80000 characters of
        16-character words, then the stop: the run ends stopped with the first 65536 of
        them (no ValidationError), and no log record holds the answer's text."""
        caplog.set_level(logging.DEBUG)
        piece = ("CAPMARK-" + "abcdefg" + " ") * 1000
        sink = _Sink()
        stream = _run_stream(sink)

        result, error = await _stopped_after(recorder, [piece] * 5, sink, stream)

        assert error is None
        assert result is not None
        assert (result.status, result.error_code, len(result.response)) == ("stopped", None, 65536)
        assert result.response == (piece * 5)[:65536]
        assert result.history[-1] == _assistant(result.response)
        assert "CAPMARK" not in _log_texts(caplog.records)

    @pytest.mark.parametrize(
        ("deltas", "kept"),
        [
            (["Kept SURRMARK" + _LONE_SURROGATE + " text ", "tail"], None),
            (["Kept text ", "SURRMARK" + _LONE_SURROGATE], "Kept text "),
        ],
        ids=["in-the-kept-text", "in-the-dropped-word"],
    )
    async def test_agent_stream_stop_with_a_lone_surrogate_still_ends_stopped(
        self,
        recorder: _Recorder,
        caplog: pytest.LogCaptureFixture,
        deltas: list[str],
        kept: str | None,
    ) -> None:
        """A fake delta holding a lone surrogate (the client strips them; a fake can
        bypass it): the stopped run doesn't raise (no ValidationError carrying answer
        text), ends ``stopped`` with a reply free of surrogates, and nothing of the answer
        is logged. In the dropped last word, the cut alone removes it."""
        caplog.set_level(logging.DEBUG)
        sink = _Sink()
        stream = _run_stream(sink)

        result, error = await _stopped_after(recorder, deltas, sink, stream)

        assert error is None
        assert result is not None
        assert (result.status, result.error_code, result.pending_confirmation) == (
            "stopped",
            None,
            None,
        )
        assert not any(0xD800 <= ord(char) <= 0xDFFF for char in result.response)
        if kept is None:
            # The guard may strip or replace the surrogate, or keep no reply (C11/L-2).
            allowed = {"", "Kept SURRMARK text ", "Kept SURRMARK" + chr(0xFFFD) + " text "}
            assert result.response in allowed
        else:
            assert result.response == kept
        reply = [_assistant(result.response)] if result.response else []
        assert result.history == [_user("hello"), *reply]
        assert "SURRMARK" not in _log_texts(caplog.records)


# ===========================================================================
# 4. Logs
# ===========================================================================


class TestLogs:
    """A streamed, stopped run logs no content."""

    async def test_agent_stream_logs_no_delta_argument_or_user_text(
        self, recorder: _Recorder, echo: _Echo, caplog: pytest.LogCaptureFixture
    ) -> None:
        user_marker = "USER-MARK-7f3a"
        delta_marker = "DELTA-MARK-19c4"
        arg_marker = "ARG-MARK-5e8b"
        later_marker = "LATER-MARK-2d6e"
        park = _Park()
        sink = _Sink()
        stream = _run_stream(sink)
        say = _call("echo", "say", arg_marker, "c-1")
        fake = StreamLLM(
            [
                [_delta(delta_marker + " "), _final(delta_marker + " ", say)],
                [_delta(later_marker + " "), park, _final("x")],
            ]
        )
        caplog.set_level(logging.DEBUG)

        task = _start(_agent(fake, recorder), f"{user_marker} please", stream=stream)
        await _until_set(park.reached, task)
        stream.stop.set()
        result = await _finish(task)

        assert (result.status, echo.ran) == ("stopped", [arg_marker])
        logged = _log_texts(caplog.records)
        markers = (user_marker, delta_marker, arg_marker, later_marker)
        assert [marker for marker in markers if marker in logged] == []
