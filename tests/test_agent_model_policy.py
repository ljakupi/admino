"""Tests for the agent's use of the V1 model policy (GH-242 contract section 3).

- ``ToolPolicy.data_residency`` (default False): when it is on and the agent's
  client is not Swiss (``provider`` not "infomaniak"/"vllm", or missing), the
  run ends at once, right after the H-2 session check: status "error",
  ``error_code == "residency_blocked"``, the blocked error's message as
  ``response``, no LLM call, no dispatch (a resumed confirmation's tool is NOT
  dispatched) and no recorder call.
- ``AgentConfig.llm_max_retries`` (default 0, 0..5): every LLM call goes
  through ``llm_policy.chat`` with the run's ``max_retries`` (the run's
  ``agent_config`` wins over the construction one), so transient failures are
  retried on the same client with the same context.
- ``AgentResult.error_code`` (an ``LLMErrorCode`` or None): an LLMError's
  ``code`` (None for uncoded errors and any other exception); the response
  text rule is unchanged (user-facing message, else the generic reply).
- Logs carry type, status and code only: a canary in an error's message never
  reaches a log record.

``llm_policy._sleep`` is patched to a recorder wherever a run retries.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

import pytest
from pydantic import BaseModel, Field, ValidationError

from admino import agent as agent_module
from admino.access import Principal
from admino.agent import Agent
from admino.llm import LLMError, LLMResponse
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolPolicy,
)
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tools.registry import ToolCallResult, clear_registry, register_tool

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

_CANARY = "CANARY-51c2-provider-text"
_GENERIC_REPLY = "I hit an error while processing your request. Please try again in a moment."
_LLM_ERROR_CODES = (
    "not_configured",
    "missing_model",
    "provider_unavailable",
    "rate_limited",
    "timeout",
    "residency_blocked",
    "context_too_long",
)
_MISSING = object()
_SESSION = "sess-policy"

_PRINCIPAL = Principal(
    user_id=UUID("11111111-2222-4333-8444-555555555555"),
    kind="member",
    org_id=UUID("0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"),
    role="editor",
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class FakeLLM:
    """Scripted LLM client: each ``chat`` call returns or raises the next item.

    Records every call's messages (copied) and tools. ``provider`` is set as an
    attribute unless it is ``_MISSING``.
    """

    def __init__(
        self, script: list[LLMResponse | BaseException], *, provider: object = "infomaniak"
    ) -> None:
        self._script = list(script)
        self.calls = 0
        self.received_messages: list[list[LLMMessage]] = []
        self.received_tools: list[list[dict[str, Any]] | None] = []
        if provider is not _MISSING:
            self.provider = provider

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls += 1
        self.received_messages.append(list(messages))
        self.received_tools.append(tools)
        if not self._script:
            msg = "FakeLLM exhausted"
            raise AssertionError(msg)
        item = self._script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class RecordingRecorder:
    """Stand-in ``ToolCallRecorder``: records each call's keywords."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, **kwargs: Any) -> None:
        self.calls.append(dict(kwargs))


class _DispatchSpy:
    """Stands in for ``agent.dispatch_tool_call``: records each call, then forwards it."""

    def __init__(self) -> None:
        self.calls: list[ToolCall] = []
        self._real = agent_module.dispatch_tool_call

    async def __call__(
        self, tool_call: ToolCall, permissions: PermissionsConfig, **kwargs: Any
    ) -> ToolCallResult:
        self.calls.append(tool_call)
        return await self._real(tool_call, permissions, **kwargs)


class EchoArgs(BaseModel):
    """Args of the echo test tool."""

    text: str = Field(min_length=1, max_length=100)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    clear_registry()
    yield
    clear_registry()


@pytest.fixture()
def recorder() -> RecordingRecorder:
    return RecordingRecorder()


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Patch ``llm_policy._sleep`` to record delays instead of sleeping."""
    from admino import llm_policy

    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(llm_policy, "_sleep", fake_sleep)
    return slept


@pytest.fixture()
def dispatch_spy(monkeypatch: pytest.MonkeyPatch) -> _DispatchSpy:
    spy = _DispatchSpy()
    monkeypatch.setattr(agent_module, "dispatch_tool_call", spy)
    return spy


def _permissions() -> PermissionsConfig:
    return PermissionsConfig(
        tools={"echo": ToolPermissions(actions={"say": "allow", "write": "confirm"})}
    )


def _tool_policy(*, data_residency: bool) -> ToolPolicy:
    """The run's policy (echo.say allow, echo.write confirm) with residency on or off."""
    return ToolPolicy(permissions=_permissions(), data_residency=data_residency)


def _config(llm_max_retries: int) -> AgentConfig:
    """Agent limits with the given ``llm_max_retries``."""
    return AgentConfig(
        max_tool_calls=5,
        max_context_messages=20,
        confirmation_timeout_s=60.0,
        llm_max_retries=llm_max_retries,
    )


def _agent(fake: FakeLLM, recorder: RecordingRecorder, config: AgentConfig) -> Agent:
    return Agent(llm_client=fake, tool_call_recorder=recorder, agent_config=config)


async def _run(
    agent: Agent,
    *,
    data_residency: bool = False,
    message: str = "hello",
    pending: PendingConfirmation | None = None,
    agent_config: AgentConfig | None = None,
) -> AgentResult:
    return await agent.run(
        message,
        session_id=_SESSION,
        history=[],
        principal=_PRINCIPAL,
        tool_policy=_tool_policy(data_residency=data_residency),
        pending_confirmation=pending,
        agent_config=agent_config,
    )


def _text(content: str) -> LLMResponse:
    return LLMResponse(content=content, tool_calls=[], model="m", done=True)


def _say_call() -> LLMResponse:
    return LLMResponse(
        content="",
        tool_calls=[ToolCall(tool="echo", action="say", args={"text": "x"}, tool_call_id="call-1")],
        model="m",
        done=True,
    )


def _err(code: str, *, status: int | None = None, message: str | None = None) -> LLMError:
    """A coded LLMError (built per test: the ``code`` keyword is new)."""
    return LLMError(message or f"Fixed {code} text.", status, code=code)


async def _echo(args: EchoArgs, **_: object) -> str:
    return f"echo:{args.text}"


def _residency_message() -> str:
    from admino import llm_policy

    message: str = llm_policy.residency_blocked_error().message
    return message


# ===========================================================================
# 1. Models
# ===========================================================================


class TestModels:
    """The new fields on AgentConfig, ToolPolicy and AgentResult."""

    def test_agent_config_llm_max_retries_defaults_to_zero(self) -> None:
        assert AgentConfig().llm_max_retries == 0

    @pytest.mark.parametrize("value", [0, 1, 2, 3, 4, 5])
    def test_agent_config_llm_max_retries_accepts_zero_to_five(self, value: int) -> None:
        assert AgentConfig(llm_max_retries=value).llm_max_retries == value

    @pytest.mark.parametrize("value", [-1, 6, 100])
    def test_agent_config_llm_max_retries_out_of_range_rejected(self, value: int) -> None:
        with pytest.raises(ValidationError):
            AgentConfig(llm_max_retries=value)

    def test_tool_policy_data_residency_defaults_to_false(self) -> None:
        assert ToolPolicy(permissions=_permissions()).data_residency is False

    def test_tool_policy_data_residency_true_is_kept(self) -> None:
        assert ToolPolicy(permissions=_permissions(), data_residency=True).data_residency is True

    def test_agent_result_error_code_defaults_to_none(self) -> None:
        assert AgentResult(status="final", response="ok").error_code is None

    @pytest.mark.parametrize("code", _LLM_ERROR_CODES)
    def test_agent_result_error_code_accepts_each_llm_error_code(self, code: str) -> None:
        assert AgentResult(status="error", response="x", error_code=code).error_code == code

    @pytest.mark.parametrize("code", ["bogus", "", "TIMEOUT", "internal"])
    def test_agent_result_error_code_rejects_unknown_codes(self, code: str) -> None:
        with pytest.raises(ValidationError):
            AgentResult(status="error", response="x", error_code=code)


# ===========================================================================
# 2. Residency guard
# ===========================================================================


class TestResidency:
    """A residency org never reaches a non-Swiss provider."""

    @pytest.mark.parametrize("provider", ["anthropic", "openai"])
    async def test_agent_residency_on_non_swiss_client_ends_run_residency_blocked(
        self, recorder: RecordingRecorder, provider: str
    ) -> None:
        register_tool("echo", "say", "Echo text", EchoArgs)(_echo)
        fake = FakeLLM([_say_call(), _text("done")], provider=provider)
        result = await _run(_agent(fake, recorder, _config(0)), data_residency=True)
        assert result.status == "error"
        assert result.error_code == "residency_blocked"
        assert result.response == _residency_message()

    @pytest.mark.parametrize("provider", ["anthropic", "openai"])
    async def test_agent_residency_blocked_run_never_calls_llm_or_recorder(
        self, recorder: RecordingRecorder, provider: str
    ) -> None:
        register_tool("echo", "say", "Echo text", EchoArgs)(_echo)
        fake = FakeLLM([_say_call(), _text("done")], provider=provider)
        result = await _run(_agent(fake, recorder, _config(0)), data_residency=True)
        assert result.status == "error"
        assert fake.calls == 0
        assert recorder.calls == []
        assert result.tool_calls == []

    async def test_agent_residency_on_client_without_provider_is_blocked(
        self, recorder: RecordingRecorder
    ) -> None:
        """Fail closed: a client that doesn't say what it is counts as non-Swiss."""
        fake = FakeLLM([_text("should not happen")], provider=_MISSING)
        result = await _run(_agent(fake, recorder, _config(0)), data_residency=True)
        assert result.status == "error"
        assert result.error_code == "residency_blocked"
        assert fake.calls == 0

    @pytest.mark.parametrize("provider", ["anthropic", "openai"])
    async def test_agent_residency_blocked_resume_does_not_dispatch_pending_tool(
        self,
        recorder: RecordingRecorder,
        dispatch_spy: _DispatchSpy,
        provider: str,
    ) -> None:
        handled: list[str] = []

        async def write_handler(args: EchoArgs, **_: object) -> str:
            handled.append(args.text)
            return "written"

        register_tool("echo", "write", "Write text", EchoArgs)(write_handler)
        tool_call = ToolCall(tool="echo", action="write", args={"text": "x"}, tool_call_id="c-1")
        now = datetime.now(UTC)
        pending = PendingConfirmation(
            confirmation_id="conf-residency",
            session_id=_SESSION,
            tool_call=tool_call,
            created_at=now,
            expires_at=now + timedelta(seconds=60),
        )
        fake = FakeLLM([_text("Done.")], provider=provider)
        result = await _run(
            _agent(fake, recorder, _config(0)), data_residency=True, message="", pending=pending
        )
        assert result.status == "error"
        assert result.error_code == "residency_blocked"
        assert dispatch_spy.calls == []
        assert handled == []
        assert recorder.calls == []
        assert fake.calls == 0

    @pytest.mark.parametrize("provider", ["infomaniak", "vllm"])
    async def test_agent_residency_on_swiss_client_answers_normally(
        self, recorder: RecordingRecorder, provider: str
    ) -> None:
        fake = FakeLLM([_text("Grüezi")], provider=provider)
        result = await _run(_agent(fake, recorder, _config(0)), data_residency=True)
        assert result.status == "final"
        assert result.response == "Grüezi"
        assert result.error_code is None
        assert fake.calls == 1

    @pytest.mark.parametrize("provider", ["infomaniak", "vllm"])
    async def test_agent_residency_on_swiss_client_dispatches_tools(
        self, recorder: RecordingRecorder, provider: str
    ) -> None:
        register_tool("echo", "say", "Echo text", EchoArgs)(_echo)
        fake = FakeLLM([_say_call(), _text("done")], provider=provider)
        result = await _run(_agent(fake, recorder, _config(0)), data_residency=True)
        assert result.status == "final"
        assert result.error_code is None
        assert len(recorder.calls) == 1
        assert fake.calls == 2

    @pytest.mark.parametrize("provider", ["anthropic", "openai"])
    async def test_agent_residency_off_non_swiss_client_answers_normally(
        self, recorder: RecordingRecorder, provider: str
    ) -> None:
        fake = FakeLLM([_text("Hello")], provider=provider)
        result = await _run(_agent(fake, recorder, _config(0)), data_residency=False)
        assert result.status == "final"
        assert result.response == "Hello"
        assert result.error_code is None
        assert fake.calls == 1


# ===========================================================================
# 3. Retries
# ===========================================================================


class TestRetries:
    """Every LLM call goes through the policy with the run's llm_max_retries."""

    async def test_agent_llm_max_retries_two_recovers_after_two_transient_failures(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        fake = FakeLLM(
            [_err("timeout"), _err("provider_unavailable", status=503), _text("recovered")]
        )
        result = await _run(_agent(fake, recorder, _config(2)))
        assert result.status == "final"
        assert result.response == "recovered"
        assert result.error_code is None
        assert fake.calls == 3
        assert len(sleeps) == 2

    async def test_agent_llm_max_retries_zero_fails_after_one_call(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        fake = FakeLLM([_err("timeout"), _text("never reached")])
        result = await _run(_agent(fake, recorder, _config(0)))
        assert result.status == "error"
        assert result.error_code == "timeout"
        assert fake.calls == 1
        assert sleeps == []

    async def test_agent_default_config_does_not_retry(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        config = AgentConfig()
        assert config.llm_max_retries == 0
        fake = FakeLLM([_err("rate_limited", status=429), _text("never reached")])
        result = await _run(_agent(fake, recorder, config))
        assert result.status == "error"
        assert result.error_code == "rate_limited"
        assert fake.calls == 1

    async def test_agent_run_config_retries_override_construction_config_upwards(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        fake = FakeLLM([_err("timeout"), _err("timeout"), _text("recovered")])
        agent = _agent(fake, recorder, _config(0))
        result = await _run(agent, agent_config=_config(2))
        assert result.status == "final"
        assert result.response == "recovered"
        assert fake.calls == 3

    async def test_agent_run_config_retries_override_construction_config_downwards(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        fake = FakeLLM([_err("timeout"), _text("never reached")])
        agent = _agent(fake, recorder, _config(2))
        result = await _run(agent, agent_config=_config(0))
        assert result.status == "error"
        assert result.error_code == "timeout"
        assert fake.calls == 1

    async def test_agent_construction_config_retries_apply_without_run_config(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        fake = FakeLLM([_err("rate_limited", status=429), _text("recovered")])
        result = await _run(_agent(fake, recorder, _config(2)))
        assert result.status == "final"
        assert fake.calls == 2

    async def test_agent_exhausted_retries_return_last_error_code_and_message(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        last = _err("rate_limited", status=429, message="Example rate limit reached.")
        fake = FakeLLM([_err("timeout"), _err("timeout"), last, _text("never reached")])
        result = await _run(_agent(fake, recorder, _config(2)))
        assert result.status == "error"
        assert result.error_code == "rate_limited"
        assert result.response == "Example rate limit reached."
        assert fake.calls == 3

    async def test_agent_non_retryable_error_is_not_retried(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        fake = FakeLLM([_err("not_configured", status=401), _text("never reached")])
        result = await _run(_agent(fake, recorder, _config(5)))
        assert result.error_code == "not_configured"
        assert fake.calls == 1
        assert sleeps == []

    async def test_agent_retry_resends_identical_context_and_tools(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        register_tool("echo", "say", "Echo text", EchoArgs)(_echo)
        fake = FakeLLM([_err("timeout"), _text("ok")])
        await _run(_agent(fake, recorder, _config(1)))
        assert fake.calls == 2
        assert fake.received_messages[1] == fake.received_messages[0]
        assert fake.received_tools[1] == fake.received_tools[0]
        assert fake.received_tools[0]

    async def test_agent_retry_after_a_tool_dispatch_does_not_redispatch(
        self, recorder: RecordingRecorder, sleeps: list[float]
    ) -> None:
        """The second LLM call of a run is retried too; the tool still ran once."""
        register_tool("echo", "say", "Echo text", EchoArgs)(_echo)
        fake = FakeLLM([_say_call(), _err("timeout"), _text("done")])
        result = await _run(_agent(fake, recorder, _config(1)))
        assert result.status == "final"
        assert result.response == "done"
        assert fake.calls == 3
        assert len(recorder.calls) == 1
        assert len(result.tool_calls) == 1


# ===========================================================================
# 4. error_code
# ===========================================================================


class TestErrorCode:
    """AgentResult.error_code carries the LLMError's code, else None."""

    @pytest.mark.parametrize("code", _LLM_ERROR_CODES)
    async def test_agent_coded_llm_error_sets_error_code_and_shows_its_message(
        self, recorder: RecordingRecorder, code: str
    ) -> None:
        error = _err(code, message=f"Fixed text for {code}.")
        fake = FakeLLM([error, _text("never reached")])
        result = await _run(_agent(fake, recorder, _config(0)))
        assert result.status == "error"
        assert result.error_code == code
        assert result.response == f"Fixed text for {code}."
        assert fake.calls == 1

    async def test_agent_uncoded_user_facing_llm_error_has_no_code_and_shows_message(
        self, recorder: RecordingRecorder
    ) -> None:
        fake = FakeLLM([LLMError("Shown verbatim.", user_facing=True)])
        result = await _run(_agent(fake, recorder, _config(0)))
        assert result.status == "error"
        assert result.error_code is None
        assert result.response == "Shown verbatim."

    async def test_agent_internal_llm_error_has_no_code_and_generic_reply(
        self, recorder: RecordingRecorder
    ) -> None:
        fake = FakeLLM([LLMError("Example API returned HTTP 400", 400)])
        result = await _run(_agent(fake, recorder, _config(0)))
        assert result.status == "error"
        assert result.error_code is None
        assert result.response == _GENERIC_REPLY

    async def test_agent_non_llm_exception_has_no_code_and_generic_reply(
        self, recorder: RecordingRecorder
    ) -> None:
        fake = FakeLLM([RuntimeError("boom")])
        result = await _run(_agent(fake, recorder, _config(0)))
        assert result.status == "error"
        assert result.error_code is None
        assert result.response == _GENERIC_REPLY

    async def test_agent_successful_run_has_no_error_code(
        self, recorder: RecordingRecorder
    ) -> None:
        fake = FakeLLM([_text("fine")])
        result = await _run(_agent(fake, recorder, _config(0)))
        assert result.status == "final"
        assert result.error_code is None

    async def test_agent_error_after_tool_dispatch_keeps_code_and_tool_record(
        self, recorder: RecordingRecorder
    ) -> None:
        register_tool("echo", "say", "Echo text", EchoArgs)(_echo)
        fake = FakeLLM([_say_call(), _err("context_too_long", status=400)])
        result = await _run(_agent(fake, recorder, _config(0)))
        assert result.status == "error"
        assert result.error_code == "context_too_long"
        assert len(result.tool_calls) == 1


# ===========================================================================
# 5. Logs
# ===========================================================================


_FAILURES: dict[str, tuple[Callable[[], BaseException], int, str | None]] = {
    # name: (error factory, llm_max_retries, expected error_code)
    "retryable_exhausted": (
        lambda: _err("provider_unavailable", status=503, message=_CANARY),
        2,
        "provider_unavailable",
    ),
    "coded_not_retryable": (
        lambda: _err("context_too_long", status=400, message=_CANARY),
        2,
        "context_too_long",
    ),
    "uncoded_user_facing": (lambda: LLMError(_CANARY, user_facing=True), 2, None),
    "internal": (lambda: LLMError(_CANARY, 500), 2, None),
    "runtime_error": (lambda: RuntimeError(_CANARY), 2, None),
}


class TestLogs:
    """Failures log type, status and code only, never message text."""

    @pytest.mark.parametrize("failure", list(_FAILURES.values()), ids=list(_FAILURES))
    async def test_agent_llm_failure_logs_never_carry_message_text(
        self,
        recorder: RecordingRecorder,
        sleeps: list[float],
        caplog: pytest.LogCaptureFixture,
        failure: tuple[Callable[[], BaseException], int, str | None],
    ) -> None:
        make_error, retries, expected_code = failure
        fake = FakeLLM([make_error() for _ in range(retries + 1)])
        caplog.set_level(logging.DEBUG)
        result = await _run(_agent(fake, recorder, _config(retries)))
        assert result.status == "error"
        assert result.error_code == expected_code
        errors = [
            r for r in caplog.records if r.name == "admino.agent" and r.levelno >= logging.ERROR
        ]
        assert errors, "expected the agent's content-free failure log line"
        assert _CANARY not in caplog.text
        for record in caplog.records:
            assert _CANARY not in record.getMessage()
            assert _CANARY not in repr(record.args)

    @pytest.mark.parametrize("code", ["rate_limited", "missing_model"])
    async def test_agent_llm_error_log_names_the_code(
        self, recorder: RecordingRecorder, caplog: pytest.LogCaptureFixture, code: str
    ) -> None:
        fake = FakeLLM([_err(code, message=_CANARY)])
        caplog.set_level(logging.DEBUG)
        result = await _run(_agent(fake, recorder, _config(0)))
        assert result.error_code == code
        agent_lines = [r.getMessage() for r in caplog.records if r.name == "admino.agent"]
        assert any(code in line for line in agent_lines)
        assert _CANARY not in caplog.text

    async def test_agent_residency_blocked_run_logs_no_principal_identifiers(
        self, recorder: RecordingRecorder, caplog: pytest.LogCaptureFixture
    ) -> None:
        fake = FakeLLM([_text("never reached")], provider="anthropic")
        caplog.set_level(logging.DEBUG)
        result = await _run(_agent(fake, recorder, _config(0)), data_residency=True)
        assert result.error_code == "residency_blocked"
        assert str(_PRINCIPAL.user_id) not in caplog.text
        assert str(_PRINCIPAL.org_id) not in caplog.text
