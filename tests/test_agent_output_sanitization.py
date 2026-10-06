"""Agent output sanitization (GH-25, contract C5 and C1's ``AgentResult.truncated``).

A real ``Agent`` runs against an LLM faked at the client boundary
(``_ScriptLLM``, provider "infomaniak"): ``chat()`` answers or raises its
scripted items in order (the JSON path), and each ``chat_stream`` call plays
its scripted list (``LLMStreamDelta`` items and the final ``LLMResponse`` are
yielded, an exception is raised). Every call's messages are copied, so the
context of the next call can be checked. Tools live in the real registry
(cleared around each test): ``echo.say`` (allow).

Pinned here:
- C1: ``AgentResult.truncated`` is a bool field, default False.
- C5.1 (D7), a cut final answer: when the response that ends the run ``final``
  (no tool calls) has ``truncated=True``, the reply and the ``assistant``
  history message are its content up to and including its last ASCII
  whitespace (space, tab, LF, CR; NBSP, U+3000 and U+2003 are no boundary),
  "" when there is none (the message still added); a fake key the cut falls
  inside is in neither; ``truncated=True``, status ``final``, in the JSON and
  the streamed run alike, and ``on_delta`` still got every raw piece. An
  untruncated final run is today's (``truncated`` False). A truncated
  response WITH tool calls is not cut (its text goes to history as today), and
  a run ending ``limit_reached`` after it is not ``truncated``.
- C5.2 (D9), a streamed ``timeout`` after forwarded text: the history ends
  ``[..., assistant(<that call's forwarded text, control-stripped, capped at
  65536, cut at its last ASCII whitespace>), assistant(<error message>)]``;
  status ``error``, ``error_code`` ``timeout``, the response is the error's
  message, ``truncated`` False. No partial message when the cut leaves "", none
  for a timeout before any delta, none for another code after deltas
  (``provider_unavailable``, ``malformed_response``, an uncoded failure); only
  the interrupted call's text counts.
- C5.3 (D1): ``LLMError(code="malformed_response")`` from ``chat()`` or a stream
  (before or after deltas) ends the run ``error`` with that code and the
  error's message as the response (never the generic reply); it is not retried.
- C5.4 (D4), an unknown tool end to end through the real registry: one
  recorder call (``deny``, not successful, the requested names), a deny
  ``ToolCallRecord`` in ``AgentResult.tool_calls`` and via ``on_tool_call``,
  the tool message ``Unknown tool: gmail.forward_all`` in the next call's
  context, and the run goes on to the model's final reply. Through the real
  recorder (``main._build_tool_call_recorder``) the ``tool.call`` row's
  metadata has ``decision`` "deny" and a name outside the audit vocabulary as
  None ("gmail" is vocabulary, "forward_all" and "crm" are not).
- Logs: no record carries answer text, a partial reply or a tool argument.

New names (``truncated``, the ``malformed_response`` code) are used lazily, so the
file collects before GH-25 is implemented.

Security notes:
- Keys are built at runtime (tests/credential_keys.py), never literal.
- No network, no real LLM, no real PostgreSQL (FakeDb behind the recorder).
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any, Final

import pytest
from pydantic import BaseModel, Field

from admino import main as main_module
from admino.access import Principal
from admino.agent import Agent
from admino.llm import LLMError, LLMResponse, LLMStreamDelta, provider_status_error
from admino.models import AgentConfig, AgentResult, LLMMessage, ToolCall, ToolPolicy
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tools.registry import clear_registry, register_tool
from tests.credential_keys import GITHUB_FINE_GRAINED, openai_project_key, surviving_chunks

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Generator

    from admino.models import ToolCallRecord
    from tests.credential_keys import ApiKey

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SESSION: Final = "sess-gh25-w4"
_GENERIC_REPLY: Final = (
    "I hit an error while processing your request. Please try again in a moment."
)
_MALFORMED_MESSAGE: Final = "Infomaniak returned a malformed response. Please try again."
_NUL: Final = chr(0)
_ESC: Final = chr(0x1B)
_CSI: Final = chr(0x9B)
_NBSP: Final = chr(0xA0)
_IDEOGRAPHIC_SPACE: Final = chr(0x3000)
_EM_SPACE: Final = chr(0x2003)
_LONE_SURROGATE: Final = chr(0xD83D)  # the high half of an emoji, without its low half
_MAX_CHARS: Final = 65536

_PRINCIPAL: Final = Principal(
    user_id=uuid.UUID("2a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c6d"),
    kind="member",
    org_id=uuid.UUID("3b4c5d6e-7f8a-4b9c-8d0e-2f3a4b5c6d7e"),
    role="editor",
)

# (separator, the reply a truncated "Kept text alpha<separator>beta" keeps)
_SEPARATORS: Final = [
    pytest.param(" ", "Kept text alpha ", id="space"),
    pytest.param("\t", "Kept text alpha\t", id="tab"),
    pytest.param("\n", "Kept text alpha\n", id="lf"),
    pytest.param("\r", "Kept text alpha\r", id="cr"),
    pytest.param(_NBSP, "Kept text ", id="nbsp"),
    pytest.param(_IDEOGRAPHIC_SPACE, "Kept text ", id="u3000"),
    pytest.param(_EM_SPACE, "Kept text ", id="em-space"),
]
_MODES: Final = ["json", "stream"]


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

Step = LLMStreamDelta | LLMResponse | BaseException


class _ScriptLLM:
    """Scripted LLM client faked at the client boundary.

    ``chat()`` answers (or raises) the next of ``replies``; each ``chat_stream``
    call plays the next of ``scripts``. Both record the call's messages (copied)
    in ``calls``, in call order; a call past the script fails the run.
    """

    provider = "infomaniak"

    def __init__(
        self,
        *,
        replies: list[LLMResponse | BaseException] | None = None,
        scripts: list[list[Step]] | None = None,
    ) -> None:
        self._replies = list(replies or [])
        self._scripts = list(scripts or [])
        self.calls: list[list[LLMMessage]] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls.append(list(messages))
        if not self._replies:
            msg = "chat() called more often than scripted"
            raise AssertionError(msg)
        reply = self._replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply

    def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        self.calls.append(list(messages))
        if not self._scripts:
            msg = "chat_stream called more often than scripted"
            raise AssertionError(msg)
        return self._play(self._scripts.pop(0))

    async def _play(self, script: list[Step]) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        for step in script:
            if isinstance(step, BaseException):
                raise step
            yield step


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
    """Collects what a streamed run reports: ("delta", text) and ("tool_call", record)."""

    def __init__(self) -> None:
        self.events: list[tuple[str, Any]] = []

    async def on_delta(self, text: str) -> None:
        self.events.append(("delta", text))

    async def on_tool_call(self, record: ToolCallRecord) -> None:
        self.events.append(("tool_call", record))

    @property
    def deltas(self) -> list[str]:
        return [value for kind, value in self.events if kind == "delta"]

    @property
    def records(self) -> list[ToolCallRecord]:
        return [value for kind, value in self.events if kind == "tool_call"]


class _EchoArgs(BaseModel):
    text: str = Field(min_length=1, max_length=100)


async def _echo(args: _EchoArgs, **_: object) -> str:
    return f"echo:{args.text}"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _registry() -> Generator[None, None, None]:
    """The real registry, cleared, holding echo.say only (cleared again afterwards)."""
    clear_registry()
    register_tool("echo", "say", "echo say", _EchoArgs)(_echo)
    yield
    clear_registry()


@pytest.fixture()
def recorder() -> _Recorder:
    return _Recorder()


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Patch ``llm_policy._sleep`` to record each retry delay instead of sleeping."""
    from admino import llm_policy

    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(llm_policy, "_sleep", fake_sleep)
    return slept


def _policy() -> ToolPolicy:
    return ToolPolicy(
        permissions=PermissionsConfig(
            tools={"echo": ToolPermissions(actions={"say": "allow"})},
        ),
    )


def _config(*, max_tool_calls: int = 5, llm_max_retries: int = 0) -> AgentConfig:
    return AgentConfig(
        max_tool_calls=max_tool_calls,
        max_context_messages=20,
        confirmation_timeout_s=60.0,
        llm_max_retries=llm_max_retries,
    )


def _agent(fake: _ScriptLLM, recorder: Any, *, config: AgentConfig | None = None) -> Agent:
    return Agent(llm_client=fake, tool_call_recorder=recorder, agent_config=config or _config())


def _response(content: str, *calls: ToolCall, truncated: bool = False) -> LLMResponse:
    """A final LLM response; ``truncated`` (GH-25) is passed only when set, so the
    helper builds before the field exists (an unknown field is ignored today)."""
    data: dict[str, Any] = {
        "content": content,
        "tool_calls": list(calls),
        "model": "m",
        "done": not calls,
    }
    if truncated:
        data["truncated"] = True
    return LLMResponse.model_validate(data)


def _delta(text: str) -> LLMStreamDelta:
    return LLMStreamDelta(content=text)


def _timeout() -> LLMError:
    """The ``timeout`` error a client raises (a read timeout or the stream deadline)."""
    return provider_status_error("Infomaniak", None, timed_out=True)


def _malformed() -> LLMError:
    """C2's ``malformed_response`` error, built directly (the Literal isn't enforced)."""
    return LLMError(_MALFORMED_MESSAGE, code="malformed_response")


def _coded(code: str) -> LLMError:
    return LLMError(f"Fixed {code} text.", code=code)


def _fake(
    mode: str, answers: list[tuple[tuple[str, ...], LLMResponse | BaseException]]
) -> _ScriptLLM:
    """One run's LLM answers for ``mode``: (stream pieces, final response or error) each.
    JSON: ``chat()`` answers the final item; stream: the pieces as deltas, then it."""
    if mode == "json":
        return _ScriptLLM(replies=[final for _, final in answers])
    return _ScriptLLM(scripts=[[*map(_delta, pieces), final] for pieces, final in answers])


def _answer(*pieces: str, truncated: bool = False) -> tuple[tuple[str, ...], LLMResponse]:
    """A text-only answer streamed as ``pieces`` (its content is their join)."""
    return pieces, _response("".join(pieces), truncated=truncated)


async def _run(
    agent: Agent,
    mode: str,
    *,
    sink: _Sink | None = None,
    message: str = "hello",
    history: list[LLMMessage] | None = None,
) -> AgentResult:
    stream: Any = None
    if mode == "stream":
        from admino.streaming import RunStream

        target = sink or _Sink()
        stream = RunStream(on_delta=target.on_delta, on_tool_call=target.on_tool_call)
    return await agent.run(
        message,
        _SESSION,
        history=list(history or []),
        principal=_PRINCIPAL,
        tool_policy=_policy(),
        stream=stream,
    )


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


def _tool_result(content: str, call_id: str | None) -> LLMMessage:
    return LLMMessage(role="tool", content=content, tool_call_id=call_id)


def _outcome(record: ToolCallRecord) -> tuple[str, str, dict[str, Any], str, bool]:
    """A record without its timing: (tool, action, args, permission, success)."""
    return (record.tool, record.action, record.args, record.permission, record.success)


def _ends(result: AgentResult) -> tuple[Any, ...]:
    """(status, response, error_code, truncated, pending_confirmation) of a run.
    ``truncated`` is read with a sentinel, so a run without the field differs."""
    return (
        result.status,
        result.response,
        result.error_code,
        getattr(result, "truncated", "<missing>"),
        result.pending_confirmation,
    )


def _cut_key() -> tuple[ApiKey, str]:
    """A GitHub fine-grained token one character short of its realistic length: the
    display redaction doesn't match that, so it shows if the cut word were kept."""
    from admino.models import sanitize_display_text

    key = GITHUB_FINE_GRAINED.key()
    cut = key.text[:-1]
    assert surviving_chunks(sanitize_display_text(cut), key), "fixture: shown when uncut"
    return key, cut


def _texts(result: AgentResult) -> str:
    """Everything the run returns as text: its response and every history message."""
    return "\n".join([result.response, *(str(message.content) for message in result.history)])


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
# 1. C1: AgentResult.truncated
# ===========================================================================


def test_agent_result_truncated_is_a_bool_field_defaulting_to_false() -> None:
    field = AgentResult.model_fields.get("truncated")

    assert field is not None, "AgentResult must have a truncated field"
    assert (field.annotation, field.default) == (bool, False)
    assert AgentResult(status="final").truncated is False
    assert AgentResult(status="final", truncated=True).truncated is True


# ===========================================================================
# 2. C5.1: a truncated final answer ends at its last complete word
# ===========================================================================


class TestTruncatedFinal:
    """D7: the final answer the provider (or the 64 KiB cap) cut is kept up to and
    including its last ASCII whitespace, in the JSON and the streamed run alike."""

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize(("separator", "kept"), _SEPARATORS)
    async def test_agent_truncated_final_cuts_after_the_last_ascii_whitespace(
        self, recorder: _Recorder, mode: str, separator: str, kept: str
    ) -> None:
        """ "Kept text alpha<sep>beta", truncated: an ASCII whitespace ends the reply;
        NBSP, U+3000 and U+2003 are no boundary, so the whole last word goes."""
        fake = _fake(mode, [_answer("Kept text ", f"alpha{separator}be", "ta", truncated=True)])

        result = await _run(_agent(fake, recorder), mode)

        assert _ends(result) == ("final", kept, None, True, None)
        assert result.history == [_user("hello"), _assistant(kept)]

    @pytest.mark.parametrize("mode", _MODES)
    async def test_agent_truncated_final_without_ascii_whitespace_keeps_an_empty_reply(
        self, recorder: _Recorder, mode: str
    ) -> None:
        """No ASCII whitespace at all (an NBSP only): the reply is "" and the assistant
        message is still added, with ""."""
        fake = _fake(mode, [_answer("Unfinished", _NBSP + "word", truncated=True)])

        result = await _run(_agent(fake, recorder), mode)

        assert _ends(result) == ("final", "", None, True, None)
        assert result.history == [_user("hello"), _assistant("")]

    @pytest.mark.parametrize("mode", _MODES)
    @pytest.mark.parametrize("cut_at", [20, 60, 163], ids=["head", "middle", "one-short"])
    async def test_agent_truncated_final_inside_a_key_keeps_no_part_of_it(
        self, recorder: _Recorder, mode: str, cut_at: int
    ) -> None:
        """An answer cut by the output cap inside a runtime-built key: no 8 characters
        of the key's body are in the response or any history message."""
        key = openai_project_key()
        partial = key.text[:cut_at]
        fake = _fake(
            mode, [_answer("Here is the key ", partial[:12], partial[12:], truncated=True)]
        )

        result = await _run(_agent(fake, recorder), mode)

        assert _ends(result) == ("final", "Here is the key ", None, True, None)
        assert surviving_chunks(_texts(result), key) == []

    async def test_agent_truncated_final_display_key_one_short_never_returned(
        self, recorder: _Recorder
    ) -> None:
        """The worst case of the display rules (a GitHub fine-grained token one character
        short, which no credential rule redacts): the cut reply holds none of it."""
        key, cut = _cut_key()
        fake = _fake("stream", [_answer("Here is the key ", cut[:30], cut[30:], truncated=True)])

        result = await _run(_agent(fake, recorder), "stream")

        assert _ends(result) == ("final", "Here is the key ", None, True, None)
        assert surviving_chunks(_texts(result), key) == []

    async def test_agent_stream_truncated_final_still_forwards_every_raw_piece(
        self, recorder: _Recorder
    ) -> None:
        """``on_delta`` gets every raw piece, the cut word too (the server's display deltas
        drop it); the returned reply is cut."""
        pieces = ("Kept text ", "alpha be", "ta")
        sink = _Sink()
        fake = _fake("stream", [_answer(*pieces, truncated=True)])

        result = await _run(_agent(fake, recorder), "stream", sink=sink)

        assert sink.events == [("delta", piece) for piece in pieces]
        assert _ends(result) == ("final", "Kept text alpha ", None, True, None)

    async def test_agent_truncated_final_json_and_stream_runs_end_alike(
        self, recorder: _Recorder
    ) -> None:
        """The same truncated answer: the JSON and the streamed run return the same
        status, reply, flag and history (the cut one)."""
        answer = _answer("One two thr", "ee four fi", truncated=True)

        json_result = await _run(_agent(_fake("json", [answer]), recorder), "json")
        stream_result = await _run(_agent(_fake("stream", [answer]), recorder), "stream")

        assert (_ends(json_result), json_result.history) == (
            _ends(stream_result),
            stream_result.history,
        )
        assert _ends(json_result) == ("final", "One two three four ", None, True, None)

    @pytest.mark.parametrize("mode", _MODES)
    async def test_agent_untruncated_final_is_todays_result_and_not_truncated(
        self, recorder: _Recorder, mode: str
    ) -> None:
        """No flag: the whole answer (its last word included) is the reply; truncated False."""
        fake = _fake(mode, [_answer("No trailing ", "space here")])

        result = await _run(_agent(fake, recorder), mode)

        assert _ends(result) == ("final", "No trailing space here", None, False, None)
        assert result.history == [_user("hello"), _assistant("No trailing space here")]

    @pytest.mark.parametrize("mode", _MODES)
    async def test_agent_truncated_response_with_tool_calls_is_not_cut(
        self, recorder: _Recorder, mode: str
    ) -> None:
        """D7: text before tool calls is never a final answer: a truncated response that
        asks for a tool keeps its whole text in the tool turn; the run's final answer (not
        truncated) ends it with ``truncated`` False."""
        say = ToolCall(tool="echo", action="say", args={"text": "x"}, tool_call_id="c-1")
        first = (("Let me check th",), _response("Let me check th", say, truncated=True))
        fake = _fake(mode, [first, _answer("All done.")])

        result = await _run(_agent(fake, recorder), mode)

        assert _ends(result) == ("final", "All done.", None, False, None)
        assert result.history == [
            _user("hello"),
            _tool_turn("Let me check th", say),
            _tool_result("echo:x", "c-1"),
            _assistant("All done."),
        ]

    @pytest.mark.parametrize("mode", _MODES)
    async def test_agent_truncated_final_after_a_tool_turn_cuts_only_the_final(
        self, recorder: _Recorder, mode: str
    ) -> None:
        """The tool turn's text stays whole; only the truncated final answer is cut."""
        say = ToolCall(tool="echo", action="say", args={"text": "x"}, tool_call_id="c-1")
        first = (("Checking now",), _response("Checking now", say))
        fake = _fake(mode, [first, _answer("Found it and mo", truncated=True)])

        result = await _run(_agent(fake, recorder), mode)

        assert _ends(result) == ("final", "Found it and ", None, True, None)
        assert result.history == [
            _user("hello"),
            _tool_turn("Checking now", say),
            _tool_result("echo:x", "c-1"),
            _assistant("Found it and "),
        ]

    @pytest.mark.parametrize("mode", _MODES)
    async def test_agent_truncated_tool_turn_ending_at_the_limit_is_not_truncated(
        self, recorder: _Recorder, mode: str
    ) -> None:
        """C1: ``truncated`` is True only for a ``final`` run: a truncated response with a
        tool call that reaches ``max_tool_calls`` ends ``limit_reached`` with it False."""
        say = ToolCall(tool="echo", action="say", args={"text": "x"}, tool_call_id="c-1")
        first = (("Working on th",), _response("Working on th", say, truncated=True))
        fake = _fake(mode, [first])

        result = await _run(_agent(fake, recorder, config=_config(max_tool_calls=1)), mode)

        assert (result.status, getattr(result, "truncated", "<missing>")) == (
            "limit_reached",
            False,
        )
        assert result.history[1] == _tool_turn("Working on th", say)


# ===========================================================================
# 3. C5.2: a streamed timeout after forwarded text keeps the cut partial reply
# ===========================================================================


async def _timed_out(
    recorder: _Recorder, scripts: list[list[Step]], sink: _Sink | None = None
) -> AgentResult:
    """A streamed run of ``scripts`` (no retry)."""
    return await _run(_agent(_ScriptLLM(scripts=scripts), recorder), "stream", sink=sink)


_TIMEOUT_END: Final = ("error", _timeout().message, "timeout", False, None)


class TestTimeoutPartial:
    """D9: the interrupted call's forwarded text, cut like a stop's, is stored before the
    error reply; every other failure is today's."""

    @pytest.mark.parametrize(("separator", "kept"), _SEPARATORS)
    async def test_agent_stream_timeout_after_deltas_keeps_the_cut_partial_before_the_error(
        self, recorder: _Recorder, separator: str, kept: str
    ) -> None:
        sink = _Sink()
        script: list[Step] = [
            _delta("Kept text "),
            _delta(f"alpha{separator}be"),
            _delta("ta"),
            _timeout(),
        ]

        result = await _timed_out(recorder, [script], sink)

        assert _ends(result) == _TIMEOUT_END
        assert result.history == [_user("hello"), _assistant(kept), _assistant(_timeout().message)]
        assert sink.deltas == ["Kept text ", f"alpha{separator}be", "ta"]

    async def test_agent_stream_timeout_inside_a_key_keeps_no_part_of_it(
        self, recorder: _Recorder
    ) -> None:
        """Deltas ending inside a key, then the timeout: the stored partial ends before the
        key and no 8 characters of its body are in the run's texts."""
        key, cut = _cut_key()
        script: list[Step] = [_delta("Here is the key "), _delta(cut[:20]), _delta(cut[20:])]

        result = await _timed_out(recorder, [[*script, _timeout()]])

        assert _ends(result) == _TIMEOUT_END
        assert result.history == [
            _user("hello"),
            _assistant("Here is the key "),
            _assistant(_timeout().message),
        ]
        assert surviving_chunks(_texts(result), key) == []

    async def test_agent_stream_timeout_after_an_unfinished_word_only_adds_no_partial(
        self, recorder: _Recorder
    ) -> None:
        """The forwarded text has no ASCII whitespace (the cut is ""): no partial message,
        only the error reply, as today."""
        key = openai_project_key()
        script: list[Step] = [_delta(key.text[:10]), _delta(key.text[10:30] + _NBSP + "x")]

        result = await _timed_out(recorder, [[*script, _timeout()]])

        assert _ends(result) == _TIMEOUT_END
        assert result.history == [_user("hello"), _assistant(_timeout().message)]

    async def test_agent_stream_timeout_before_any_delta_is_todays_error(
        self, recorder: _Recorder
    ) -> None:
        """Nothing forwarded (and no retry configured): only the error reply."""
        sink = _Sink()

        result = await _timed_out(recorder, [[_timeout()]], sink)

        assert _ends(result) == _TIMEOUT_END
        assert result.history == [_user("hello"), _assistant(_timeout().message)]
        assert sink.events == []

    @pytest.mark.parametrize(
        ("error", "code", "reply"),
        [
            pytest.param(
                _coded("provider_unavailable"),
                "provider_unavailable",
                "Fixed provider_unavailable text.",
                id="provider-unavailable",
            ),
            pytest.param(_malformed(), "malformed_response", _MALFORMED_MESSAGE, id="malformed"),
            pytest.param(RuntimeError("boom-internal-detail"), None, _GENERIC_REPLY, id="uncoded"),
        ],
    )
    async def test_agent_stream_other_failure_after_deltas_stores_no_partial(
        self, recorder: _Recorder, error: BaseException, code: str | None, reply: str
    ) -> None:
        """D9: only ``timeout`` keeps the forwarded text; another error after deltas ends the
        run as today (the deltas stay sent, the history holds only the error reply)."""
        sink = _Sink()
        script: list[Step] = [_delta("Partial answer "), _delta("and mo"), error]

        result = await _timed_out(recorder, [script], sink)

        assert _ends(result) == ("error", reply, code, False, None)
        assert result.history == [_user("hello"), _assistant(reply)]
        assert sink.deltas == ["Partial answer ", "and mo"]

    async def test_agent_stream_timeout_partial_is_control_stripped_before_the_cut(
        self, recorder: _Recorder, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A fake stream bypassing the client's sanitizing forwards NUL, ESC, CSI and a lone
        surrogate: the stored partial is ``strip_control_chars`` of the text, then cut (the
        run never raises a ValidationError carrying answer text)."""
        caplog.set_level(logging.DEBUG)
        pieces = [
            f"Kept{_NUL} te",
            f"xt{_ESC}[31m and {_CSI}SURRMARK{_LONE_SURROGATE} more ",
            "unfinish",
        ]

        result = await _timed_out(recorder, [[*map(_delta, pieces), _timeout()]])

        assert _ends(result) == _TIMEOUT_END
        assert result.history == [
            _user("hello"),
            _assistant("Kept text[31m and SURRMARK more "),
            _assistant(_timeout().message),
        ]
        assert "SURRMARK" not in _log_texts(caplog.records)

    async def test_agent_stream_timeout_partial_is_capped_at_65536_before_the_cut(
        self, recorder: _Recorder, caplog: pytest.LogCaptureFixture
    ) -> None:
        """70000 forwarded characters (10 NULs, then 10-character words): stripped first,
        then capped at 65536 (inside a word), then cut: 6553 whole words. Capping before
        stripping, or cutting before capping, keeps a different text."""
        caplog.set_level(logging.DEBUG)
        word = "CAPMARK-x "
        raw = _NUL * 10 + word * 7000
        pieces = [raw[i : i + 10000] for i in range(0, len(raw), 10000)]

        result = await _timed_out(recorder, [[*map(_delta, pieces), _timeout()]])

        assert _ends(result) == _TIMEOUT_END
        partial = result.history[1]
        assert (partial.role, len(partial.content), partial.content == word * 6553) == (
            "assistant",
            65530,
            True,
        )
        assert result.history[-1] == _assistant(_timeout().message)
        assert "CAPMARK" not in _log_texts(caplog.records)

    async def test_agent_stream_timeout_keeps_only_the_interrupted_calls_text(
        self, recorder: _Recorder
    ) -> None:
        """An earlier call's text (before its tool call) is not part of the partial."""
        say = ToolCall(tool="echo", action="say", args={"text": "x"}, tool_call_id="c-1")
        scripts: list[list[Step]] = [
            [_delta("Checking now. "), _response("Checking now. ", say)],
            [_delta("Found the ans"), _delta("wer for you"), _timeout()],
        ]

        result = await _timed_out(recorder, scripts)

        assert _ends(result) == _TIMEOUT_END
        assert result.history == [
            _user("hello"),
            _tool_turn("Checking now. ", say),
            _tool_result("echo:x", "c-1"),
            _assistant("Found the answer for "),
            _assistant(_timeout().message),
        ]


# ===========================================================================
# 4. C5.3: malformed_response is a coded, user-facing error
# ===========================================================================


class TestMalformedResponse:
    """D1: the new code ends the run like any coded LLM error, never as the generic reply."""

    @pytest.mark.parametrize(
        ("mode", "pieces"),
        [
            pytest.param("json", (), id="json"),
            pytest.param("stream", (), id="stream-before-any-delta"),
            pytest.param("stream", ("Partial ", "answ"), id="stream-after-deltas"),
        ],
    )
    async def test_agent_malformed_response_ends_the_run_with_its_code_and_message(
        self,
        recorder: _Recorder,
        sleeps: list[float],
        mode: str,
        pieces: tuple[str, ...],
    ) -> None:
        """Status error, error_code malformed_response, the error's own message as the
        response and the history's last message; not retried (one call, no retry sleep,
        although two retries are allowed); deltas already sent stay sent."""
        sink = _Sink()
        fake = _fake(mode, [(pieces, _malformed()), _answer("never")])

        result = await _run(
            _agent(fake, recorder, config=_config(llm_max_retries=2)), mode, sink=sink
        )

        assert _ends(result) == ("error", _MALFORMED_MESSAGE, "malformed_response", False, None)
        assert result.response != _GENERIC_REPLY
        assert result.history == [_user("hello"), _assistant(_MALFORMED_MESSAGE)]
        assert (len(fake.calls), sleeps) == (1, [])
        assert sink.deltas == list(pieces)


# ===========================================================================
# 5. C5.4 / D4: an unknown tool, end to end through the real registry
# ===========================================================================

_ARG_MARK: Final = "ARG-MARK-gh25-w4"
_FORWARD: Final = ToolCall(
    tool="gmail",
    action="forward_all",
    args={"to": "everyone", "note": _ARG_MARK},
    tool_call_id="c-unknown",
)
_UNKNOWN_RESULT: Final = "Unknown tool: gmail.forward_all"
_AFTER_UNKNOWN: Final = "I can't forward your mail."


class TestUnknownTool:
    """D4: a well-formed but unregistered ``tool.action`` keeps today's handling."""

    @pytest.mark.parametrize("mode", _MODES)
    async def test_agent_unknown_tool_is_denied_recorded_once_and_reported(
        self, recorder: _Recorder, mode: str
    ) -> None:
        """One recorder call (deny, not successful, the requested names); a deny record in
        ``tool_calls`` (and via ``on_tool_call`` when streamed); the model gets the
        ``Unknown tool`` result and the run ends with its reply."""
        sink = _Sink()
        first = (("Forwarding now. ",), _response("Forwarding now. ", _FORWARD))
        fake = _fake(mode, [first, _answer(_AFTER_UNKNOWN)])

        result = await _run(_agent(fake, recorder), mode, sink=sink)

        assert recorder.outcomes() == [("gmail", "forward_all", "deny", False)]
        assert (recorder.calls[0]["session_id"], recorder.calls[0]["escalated"]) == (
            _SESSION,
            False,
        )
        assert [_outcome(r) for r in result.tool_calls] == [
            ("gmail", "forward_all", dict(_FORWARD.args), "deny", False)
        ]
        if mode == "stream":
            assert sink.records == result.tool_calls
        assert len(fake.calls) == 2
        assert fake.calls[1][-1] == _tool_result(_UNKNOWN_RESULT, "c-unknown")
        assert (result.status, result.response) == ("final", _AFTER_UNKNOWN)
        assert result.history == [
            _user("hello"),
            _tool_turn("Forwarding now. ", _FORWARD),
            _tool_result(_UNKNOWN_RESULT, "c-unknown"),
            _assistant(_AFTER_UNKNOWN),
        ]

    @pytest.mark.parametrize(
        ("tool", "action", "stored"),
        [
            pytest.param("gmail", "forward_all", ("gmail", None), id="gmail-forward-all"),
            pytest.param("crm", "export_all", (None, None), id="crm-export-all"),
        ],
    )
    async def test_agent_unknown_tool_audit_row_is_a_deny_without_free_text_names(
        self, monkeypatch: pytest.MonkeyPatch, tool: str, action: str, stored: tuple[Any, Any]
    ) -> None:
        """Through the real recorder (``main._build_tool_call_recorder`` ->
        ``audit_events.record_tool_call``) one ``tool.call`` row: decision deny, not
        successful, the names stored only when they are audit vocabulary (else None)."""
        from tests.db_fakes import FakeDb
        from tests.tenancy_world import build_world, use_fake_database

        db = FakeDb()
        world = build_world(db)
        use_fake_database(monkeypatch, db)
        editor = world.a["editor"]
        principal = Principal(
            user_id=editor.user_id, kind="member", org_id=editor.org_id, role="editor"
        )
        chat_id = uuid.uuid4()
        call = ToolCall(tool=tool, action=action, args={"note": _ARG_MARK}, tool_call_id="c-u")
        fake = _ScriptLLM(
            scripts=[[_response("", call)], [_delta("Sorry. "), _response("Sorry. ")]]
        )
        agent = _agent(fake, main_module._build_tool_call_recorder())
        from admino.streaming import RunStream

        sink = _Sink()
        result = await agent.run(
            "forward everything",
            str(chat_id),
            history=[],
            principal=principal,
            tool_policy=_policy(),
            stream=RunStream(on_delta=sink.on_delta, on_tool_call=sink.on_tool_call),
        )

        assert (result.status, result.response) == ("final", "Sorry. ")
        (row,) = db.audit_rows("tool.call")
        metadata = row["metadata"]
        assert (metadata["tool"], metadata["action"]) == stored
        assert (metadata["decision"], metadata["success"], metadata["escalated"]) == (
            "deny",
            False,
            False,
        )
        assert _ARG_MARK not in repr(row)


# ===========================================================================
# 6. Logs
# ===========================================================================


async def test_agent_output_sanitization_logs_no_answer_partial_or_argument(
    recorder: _Recorder, caplog: pytest.LogCaptureFixture
) -> None:
    """At DEBUG: a truncated final answer, a timeout's partial reply, a malformed reply's
    deltas and an unknown tool's arguments reach no log record (each run's outcome is
    checked, so the scan is not vacuous)."""
    answer_mark = "ANSWER-MARK-gh25"
    partial_mark = "PARTIAL-MARK-gh25"
    malformed_mark = "MALFORMED-MARK-gh25"
    user_mark = "USER-MARK-gh25"
    caplog.set_level(logging.DEBUG)

    forward = (("On it. ",), _response("On it. ", _FORWARD))
    truncated = _answer(f"{answer_mark} is ", "the answ", truncated=True)
    first = await _run(
        _agent(_fake("stream", [forward, truncated]), recorder), "stream", message=user_mark
    )
    second = await _timed_out(recorder, [[_delta(f"{partial_mark} so "), _delta("fa"), _timeout()]])
    third = await _run(
        _agent(_fake("stream", [((f"{malformed_mark} ",), _malformed())]), recorder), "stream"
    )

    assert _ends(first) == ("final", f"{answer_mark} is the ", None, True, None)
    assert second.history[1] == _assistant(f"{partial_mark} so ")
    assert _ends(third) == ("error", _MALFORMED_MESSAGE, "malformed_response", False, None)
    logged = _log_texts(caplog.records)
    assert "Agent run terminated" in logged
    leaked = [
        m for m in (answer_mark, partial_mark, malformed_mark, user_mark, _ARG_MARK) if m in logged
    ]
    assert leaked == []
