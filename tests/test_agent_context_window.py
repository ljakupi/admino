"""Spec for orphan ``tool`` results under the message cap (GH-294 Decision 4).

A chat turn loads only the latest messages of a chat, so its history can open with
``tool`` results whose assistant tool call lies before the load limit. Without a cap
(``max_context_messages`` 0) ``agent._context_window`` drops such leading results; with a
cap, a window that fits under it was sent unchanged, orphan included (#190 audit core
I-1 / server I-5): a provider then receives a ``tool`` message without its call.

What these tests pin down:

- With ``max_context_messages > 0`` the window never starts with a ``tool`` message,
  whether or not the cap cut anything: leading ``tool`` messages are dropped, as the
  no-cap path drops them. The current user message and every message after it stay, and
  the returned index points at the current user message (0 on a resume whose history
  holds no user message).
- A cut that lands between an assistant tool call and its results (before the first
  result, or between two) drops those results with the call; a cut that splits no pair
  keeps the window as the cap cut it (guards: the cap path already drops the leading
  results of a cut window).
- The invariant, checked on EVERY context a fake LLM receives: each ``tool`` message
  follows the assistant message whose tool calls name its id, directly or after that
  call's other results. ``Agent.run`` under a cap with a loaded history opening with an
  orphan, a resumed confirmation whose history holds no user message, and a seeded
  property run (random histories of tool rounds, a random load-limit start, runs with
  their own tool loops and resumes, caps 0, 3, 5, 10 and 40; the GH-190 audit found 190 of
  4000 such cuts broken on the cap path).

Every LLM call is faked; nothing touches the network or a database.

Security notes: every text is fixed fake data.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

import pytest
from pydantic import BaseModel, Field

from admino import agent as agent_module
from admino.access import Principal
from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import AgentConfig, LLMMessage, PendingConfirmation, ToolCall, ToolPolicy
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tools import registry

if TYPE_CHECKING:
    from collections.abc import Sequence

    from admino.models import AgentResult
    from admino.permissions import PermissionState
    from admino.tools.registry import ToolHandler

_ORG_ID: Final = UUID("7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
_USER_ID: Final = UUID("8b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e")
_MEMBER: Final = Principal(user_id=_USER_ID, kind="member", org_id=_ORG_ID, role="editor")
_SESSION: Final = "9c3d4e5f-6a7b-4c8d-8e9f-1a2b3c4d5e6f"
_NOW: Final = datetime(2026, 10, 9, 9, 30, tzinfo=UTC)
_ACTIONS: Final[dict[str, PermissionState]] = {"look": "allow", "ask": "confirm"}
_SEED: Final = 294
_CASES_PER_CAP: Final = 120
_CAPS: Final = (0, 3, 5, 10, 40)


# ---------------------------------------------------------------------------
# Fakes and fixtures
# ---------------------------------------------------------------------------


class _ScriptedLLM:
    """JSON-path client: plays its steps in order and keeps every call's context."""

    provider = "infomaniak"

    def __init__(self, *steps: LLMResponse) -> None:
        self._steps = list(steps)
        self.received: list[list[LLMMessage]] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.received.append(list(messages))
        assert self._steps, "the scripted LLM ran out of responses"
        return self._steps.pop(0)


class _Recorder:
    """The injected ``ToolCallRecorder``: accepts every call."""

    async def __call__(self, **kwargs: Any) -> None:
        return None


class _TextArgs(BaseModel):
    """The probe tool's arguments."""

    text: str = Field(min_length=1, max_length=100)


@dataclass
class _Probe:
    """The probe tool: every action returns ``"<action>:<text>"``."""

    ran: list[tuple[str, str]] = field(default_factory=list)

    def handler(self, action: str) -> ToolHandler:
        async def handle(args: _TextArgs, **_: object) -> str:
            self.ran.append((action, args.text))
            return f"{action}:{args.text}"

        return handle


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty, unfrozen registry for each test; the previous one is restored after."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)


@pytest.fixture()
def probe() -> _Probe:
    tool = _Probe()
    for action in _ACTIONS:
        registry.register_tool(
            "probe", action, f"probe.{action} (GH-294 suite)", _TextArgs, side_effect=False
        )(tool.handler(action))
    return tool


def _policy() -> ToolPolicy:
    tools = {"probe": ToolPermissions(actions=dict(_ACTIONS))}
    return ToolPolicy(permissions=PermissionsConfig(tools=tools))


def _limits(cap: int) -> AgentConfig:
    """A run config with room for every history here; ``cap`` is ``max_context_messages``."""
    return AgentConfig(
        max_tool_calls=10,
        max_context_messages=cap,
        confirmation_timeout_s=60.0,
        max_input_tokens=200_000,
    )


async def _run(
    llm: Any,
    message: str,
    *,
    cap: int,
    history: Sequence[LLMMessage],
    pending: PendingConfirmation | None = None,
) -> AgentResult:
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=_Recorder(),
        agent_config=AgentConfig(),
        clock=lambda: _NOW,
    )
    return await agent.run(
        message,
        _SESSION,
        history=list(history),
        principal=_MEMBER,
        tool_policy=_policy(),
        pending_confirmation=pending,
        agent_config=_limits(cap),
    )


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


def _user(label: str) -> LLMMessage:
    return LLMMessage(role="user", content=f"{label} please")


def _reply(label: str) -> LLMMessage:
    return LLMMessage(role="assistant", content=f"{label} done")


def _calls(*call_ids: str, action: str = "look") -> LLMMessage:
    """The assistant tool-call message the agent stores (GH-25 format)."""
    return LLMMessage(
        role="assistant",
        content="",
        tool_use_blocks=[
            {"type": "tool_use", "id": call_id, "name": f"probe.{action}", "input": {"text": "x"}}
            for call_id in call_ids
        ],
    )


def _result(call_id: str) -> LLMMessage:
    return LLMMessage(role="tool", content=f"result of {call_id}", tool_call_id=call_id)


def _call(call_id: str, action: str = "look") -> ToolCall:
    return ToolCall(tool="probe", action=action, args={"text": "x"}, tool_call_id=call_id)


def _pending(call_id: str) -> PendingConfirmation:
    """The approved confirmation of ``probe.ask`` with ``call_id``, valid for an hour."""
    created = datetime.now(UTC)
    return PendingConfirmation(
        confirmation_id=f"conf-{call_id}",
        session_id=_SESSION,
        tool_call=_call(call_id, action="ask"),
        created_at=created,
        expires_at=created + timedelta(hours=1),
    )


def _label(message: LLMMessage) -> str:
    """A short, unique name of a message: its role and first word, or its call ids."""
    if message.tool_use_blocks:
        return "calls:" + ",".join(str(block["id"]) for block in message.tool_use_blocks)
    if message.role == "tool":
        return f"result:{message.tool_call_id}"
    assert isinstance(message.content, str)
    return f"{message.role}:{message.content.split(' ', 1)[0]}"


def _labels(messages: Sequence[LLMMessage]) -> list[str]:
    return [_label(message) for message in messages]


def _orphan_results(context: Sequence[LLMMessage]) -> list[str]:
    """Decision 4: every ``tool`` message whose call isn't the assistant message before it.

    A result may follow its call directly or after that call's other results; any other
    message in between (or none before it) makes it an orphan.
    """
    orphans: list[str] = []
    for index, message in enumerate(context):
        if message.role != "tool":
            continue
        owner = index - 1
        while owner >= 0 and context[owner].role == "tool":
            owner -= 1
        call = context[owner] if owner >= 0 else None
        named = (
            {str(block["id"]) for block in call.tool_use_blocks or ()}
            if call is not None and call.role == "assistant"
            else set()
        )
        if message.tool_call_id not in named:
            orphans.append(f"{message.tool_call_id}@{index}")
    return orphans


def _window(history: list[LLMMessage], current_idx: int | None, cap: int) -> tuple[list[str], int]:
    window, current = agent_module._context_window(
        history, current_idx=current_idx, max_messages=cap
    )
    return _labels(window), current


# A loaded history opening with an orphan result (its call lies before the load limit),
# then a tool turn; the current user message is last.
_LOADED: Final = [
    _result("h-0"),
    _reply("a-0"),
    _user("u-1"),
    _calls("h-1", "h-2"),
    _result("h-1"),
    _result("h-2"),
    _reply("a-1"),
    _user("current"),
]


# ---------------------------------------------------------------------------
# 1. _context_window under a cap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("history", "current_idx", "cap", "expected"),
    [
        pytest.param(
            _LOADED,
            7,
            40,
            (
                [
                    "assistant:a-0",
                    "user:u-1",
                    "calls:h-1,h-2",
                    "result:h-1",
                    "result:h-2",
                    "assistant:a-1",
                    "user:current",
                ],
                6,
            ),
            id="room-to-spare",
        ),
        pytest.param(
            _LOADED,
            7,
            9,  # the system message, the current message and all 7 earlier ones
            (
                [
                    "assistant:a-0",
                    "user:u-1",
                    "calls:h-1,h-2",
                    "result:h-1",
                    "result:h-2",
                    "assistant:a-1",
                    "user:current",
                ],
                6,
            ),
            id="exactly-at-the-cap",
        ),
        pytest.param(
            [_result("h-8"), _result("h-9"), _reply("a-0"), _user("current")],
            3,
            40,
            (["assistant:a-0", "user:current"], 1),
            id="two-results-of-one-call",
        ),
        pytest.param(
            [_result("h-0"), _reply("a-0"), _user("current"), _calls("c-1"), _result("c-1")],
            2,
            40,
            (["assistant:a-0", "user:current", "calls:c-1", "result:c-1"], 1),
            id="before-the-runs-own-tool-calls",
        ),
        pytest.param(
            [_result("h-0"), _user("current"), _calls("c-1"), _result("c-1")],
            1,
            40,
            (["user:current", "calls:c-1", "result:c-1"], 0),
            id="only-the-orphan-before-the-current-message",
        ),
    ],
)
def test_agent_context_window_cap_drops_the_leading_orphans_of_a_window_that_fits(
    history: list[LLMMessage], current_idx: int, cap: int, expected: tuple[list[str], int]
) -> None:
    """Nothing is cut, yet the window starts after the leading ``tool`` messages."""
    assert _window(history, current_idx, cap) == expected


def test_agent_context_window_cap_resume_without_a_user_message_drops_the_leading_orphan() -> None:
    """``current_idx`` None (a resume whose request lies before the load limit): index 0."""
    history = [_result("h-0"), _reply("a-0"), _calls("c-5", action="ask"), _result("c-5")]

    assert _window(history, None, 40) == (["assistant:a-0", "calls:c-5", "result:c-5"], 0)


@pytest.mark.parametrize(
    ("history", "current_idx", "cap", "expected"),
    [
        pytest.param(
            _LOADED,
            7,
            5,  # the 3 newest earlier messages: the cut lands before h-1's result
            (["assistant:a-1", "user:current"], 1),
            id="cut-before-the-first-result",
        ),
        pytest.param(
            _LOADED,
            7,
            4,  # the 2 newest earlier messages: the cut lands between the two results
            (["assistant:a-1", "user:current"], 1),
            id="cut-between-the-results",
        ),
        pytest.param(
            [_calls("c-4"), _result("c-4"), _calls("c-5", action="ask"), _result("c-5")],
            None,
            4,  # the 3 newest messages: the cut lands between c-4's call and result
            (["calls:c-5", "result:c-5"], 0),
            id="resume-cut-between-a-call-and-its-result",
        ),
    ],
)
def test_agent_context_window_cap_cut_inside_a_tool_pair_drops_the_results_with_the_call(
    history: list[LLMMessage], current_idx: int | None, cap: int, expected: tuple[list[str], int]
) -> None:
    """Guard: a cut between a call and its results never leaves those results behind."""
    assert _window(history, current_idx, cap) == expected


@pytest.mark.parametrize(
    ("cap", "expected"),
    [
        pytest.param(
            6,
            (["calls:h-1,h-2", "result:h-1", "result:h-2", "assistant:a-1", "user:current"], 4),
            id="cut-at-the-call",
        ),
        pytest.param(
            7,
            (
                [
                    "user:u-1",
                    "calls:h-1,h-2",
                    "result:h-1",
                    "result:h-2",
                    "assistant:a-1",
                    "user:current",
                ],
                5,
            ),
            id="cut-at-a-user-message",
        ),
    ],
)
def test_agent_context_window_cap_cut_that_splits_no_tool_pair_keeps_what_the_cap_kept(
    cap: int, expected: tuple[list[str], int]
) -> None:
    """Guard: a cut on a message boundary outside any tool pair drops nothing more."""
    assert _window(_LOADED, 7, cap) == expected


# ---------------------------------------------------------------------------
# 2. Agent.run: no provider receives a tool message without its call
# ---------------------------------------------------------------------------


async def test_agent_context_window_run_under_a_cap_never_sends_a_leading_orphan(
    probe: _Probe,
) -> None:
    """A cap of 10 keeps the whole loaded history, yet its orphan result isn't sent."""
    llm = _ScriptedLLM(
        LLMResponse(content="", tool_calls=[_call("c-1")]), LLMResponse(content="Done.")
    )

    result = await _run(llm, "current please", cap=10, history=_LOADED[:-1])

    assert result.status == "final"
    assert [_labels(context[1:]) for context in llm.received] == [
        _labels([*_LOADED[1:-1], _user("current")]),
        _labels([*_LOADED[1:-1], _user("current"), _calls("c-1"), _result("c-1")]),
    ]
    assert [_orphan_results(context) for context in llm.received] == [[], []]


async def test_agent_context_window_resumed_run_without_a_user_message_sends_no_orphan(
    probe: _Probe,
) -> None:
    """A resume whose history holds no user message: the dispatched result follows its call."""
    pending = _pending("c-5")
    history = [_result("h-0"), _reply("a-0"), _calls("c-5", action="ask")]
    llm = _ScriptedLLM(LLMResponse(content="Done."))

    result = await _run(llm, "", cap=10, history=history, pending=pending)

    assert (result.status, probe.ran) == ("final", [("ask", "x")])
    assert _labels(llm.received[0][1:]) == ["assistant:a-0", "calls:c-5", "result:c-5"]


# ---------------------------------------------------------------------------
# 3. The invariant on every context of random runs (seeded, deterministic)
# ---------------------------------------------------------------------------


def _conversation(rng: random.Random, turns: int) -> list[LLMMessage]:
    """``turns`` well-formed turns: a user message, 0 to 3 tool rounds, the reply."""
    messages: list[LLMMessage] = []
    calls = 0
    for turn in range(turns):
        messages.append(_user(f"u-{turn}"))
        for _ in range(rng.randint(0, 3)):
            ids = [f"h-{calls + n}" for n in range(rng.randint(1, 3))]
            calls += len(ids)
            messages.append(_calls(*ids))
            messages.extend(_result(call_id) for call_id in ids)
        messages.append(_reply(f"a-{turn}"))
    return messages


@dataclass
class _Case:
    """One random run: its loaded history, its own tool rounds, and whether it resumes."""

    history: list[LLMMessage]
    rounds: list[list[str]]
    resume: bool


def _case(rng: random.Random, number: int) -> _Case:
    full = _conversation(rng, rng.randint(1, 8))
    # The server's load limit: the loaded history may start anywhere, inside a tool round too.
    history = full[rng.randrange(len(full)) :]
    rounds = [
        [f"c-{number}-{r}-{n}" for n in range(rng.randint(1, 2))] for r in range(rng.randint(0, 3))
    ]
    resume = rng.random() < 0.3
    if resume:
        if rng.random() < 0.5:
            # The request lies before the load limit: no user message at all.
            history = [message for message in history if message.role != "user"]
        history = [*history, _calls(f"c-{number}-ask", action="ask")]
    return _Case(history=history, rounds=rounds, resume=resume)


async def test_agent_context_window_every_llm_call_sends_each_result_after_its_call(
    probe: _Probe,
) -> None:
    """Random loaded histories and runs under every cap: no context holds an orphan result."""
    rng = random.Random(_SEED)  # noqa: S311 - deterministic test data, not a secret
    violations: list[tuple[int, int, int, list[str]]] = []
    exercised = dict.fromkeys(_CAPS, 0)
    calls_made = 0
    for cap in _CAPS:
        for number in range(_CASES_PER_CAP):
            case = _case(rng, number)
            steps = [
                LLMResponse(content="", tool_calls=[_call(call_id) for call_id in ids])
                for ids in case.rounds
            ]
            llm = _ScriptedLLM(*steps, LLMResponse(content="Done."))
            pending = _pending(f"c-{number}-ask") if case.resume else None

            result = await _run(
                llm,
                "" if case.resume else "current please",
                cap=cap,
                history=case.history,
                pending=pending,
            )

            assert result.status == "final", (cap, number, result.status, result.response)
            if case.history and case.history[0].role == "tool":
                exercised[cap] += 1
            calls_made += len(llm.received)
            for call, context in enumerate(llm.received):
                orphans = _orphan_results(context)
                if orphans:
                    violations.append((cap, number, call, orphans))

    # Non-vacuity: every cap ran histories that open with a result, over many LLM calls.
    assert min(exercised.values()) >= 10, exercised
    assert calls_made >= 2 * len(_CAPS) * _CASES_PER_CAP
    assert (len(violations), violations[:5]) == (0, [])
