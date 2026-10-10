"""HTTP spec of LLM output sanitization in chat turns (GH-25, contract C6 with C5).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin and an Editor each, real
session cookies) with the REAL ``admino.agent.Agent`` (the real
tool-call recorder of ``main._build_tool_call_recorder()``) around an LLM faked
at the client boundary (``_ScriptLLM``, provider "infomaniak"): per user message
it plays the planned answers in order, one per LLM call of the turn. A
streamed call plays its ``LLMStreamDelta`` items and then the final
``LLMResponse`` (or raises the planned error); a JSON call answers the final
item (or raises it). The registry is an empty, unfrozen one, so any tool call
is an unknown tool. Every chat is user-titled, so no title call runs.

``_parse_sse`` reads a body as an SSE client does (lines split at CRLF, CR or
LF; a blank line ends a frame; ``:`` comment lines ignored; one ``event:`` and
one ``data:`` line per frame; strict JSON data).

Pinned (C6):
- A truncated final turn (D7: the provider stopped at its output cap inside a
  key, or the 64 KiB cap cut a 65536-character answer inside one): over SSE the
  joined ``delta`` texts equal ``sanitize_display_text(<the cut reply>)``, which
  is GET /api/chats/{id}'s content of the stored reply; the stored raw reply is
  the cut one; no 8 characters of the key's body are in any frame or in GET; the
  stream ends ``context_usage`` (GH-190, Decision 4), ``message_saved{status:
  "complete"}``, ``done`` with no ``error``.
  The same turn over JSON returns and stores the cut reply (status ``final``).
- A streamed ``timeout`` after text (D9): the frames are ``run_started``, the
  deltas ending at the same word as the stored partial message, ``context_usage``,
  ``message_saved{status: "error", message_id: <the LAST stored message, the
  error reply>}``, ``error{code: "timeout", message: <the error reply>}``,
  ``done``; GET shows the user message, the cut partial reply, then the error
  reply with status ``error``; no part of a key cut by the timeout anywhere.
- ``malformed_response`` (D1): over SSE ``context_usage``, ``message_saved{error}``, then
  ``error{code: "malformed_response", message: <the error's message>}`` (never
  ``internal_error``), the deltas sent before it ending at a word, and nothing
  but the error reply stored after the user message; over JSON a 200 with
  ``status: "error"``, ``error_code: "malformed_response"`` and that message.
- Logs: at DEBUG no app record holds the user message, answer text, a partial
  reply, the deltas of a rejected reply or a tool argument.

New names (``truncated``, the ``malformed_response`` code) are used lazily, so the
file collects before GH-25 is implemented.

Security notes:
- Keys are built at runtime (tests/credential_keys.py), never literal.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import main as main_module
from admino.agent import Agent
from admino.llm import LLMError, LLMResponse, LLMStreamDelta, provider_status_error
from admino.models import AgentConfig, LLMMessage, ToolCall, sanitize_display_text
from admino.tools import registry
from tests.context_frames import fix_instructions, usage_frame
from tests.credential_keys import GITHUB_FINE_GRAINED, surviving_chunks
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    build_world,
    make_app,
    make_client,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import AsyncIterator

    import httpx
    from fastapi.testclient import TestClient

    from tests.credential_keys import ApiKey
    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SSE_ACCEPT: Final = {"Accept": "text/event-stream"}
_MAX_CHARS: Final = 65536
_MAX_DELTA_CHARS: Final = 4096
_KEPT: Final = "Here is the key "
_MALFORMED_MESSAGE: Final = "Infomaniak returned a malformed response. Please try again."
_TIMEOUT_MESSAGE: Final = (
    "Infomaniak is temporarily unavailable (the request timed out). Please try again in a moment."
)
_EVENT_NAME: Final = re.compile(r"[a-zA-Z0-9_.:-]+")
_LINE_BREAK: Final = re.compile(r"\r\n|\r|\n")

Frame = tuple[str, dict[str, Any]]
Step = LLMStreamDelta | LLMResponse | BaseException


# ---------------------------------------------------------------------------
# The scripted LLM
# ---------------------------------------------------------------------------


def _last_user(messages: list[LLMMessage]) -> str:
    """The content of the last user message (the turn being run)."""
    return next(str(m.content) for m in reversed(messages) if m.role == "user")


class _ScriptLLM:
    """Per user message, the planned answers in call order: each a list of steps (deltas,
    then the final ``LLMResponse`` or an exception). ``chat_stream`` plays the steps;
    ``chat()`` answers (or raises) the last one. An unplanned call fails the run."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self._plans: dict[str, list[list[Step]]] = {}
        self.calls: list[str] = []

    def plan(self, message: str, *answers: list[Step]) -> None:
        self._plans[message] = [list(answer) for answer in answers]

    def _next(self, messages: list[LLMMessage]) -> list[Step]:
        message = _last_user(messages)
        self.calls.append(message)
        queued = self._plans.get(message, [])
        if not queued:
            msg = "an LLM call that was not planned"
            raise AssertionError(msg)
        return queued.pop(0)

    def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        return self._play(self._next(messages))

    async def _play(self, steps: list[Step]) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        for step in steps:
            if isinstance(step, BaseException):
                raise step
            yield step

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        final = self._next(messages)[-1]
        if isinstance(final, BaseException):
            raise final
        return final

    async def close(self) -> None:
        """Nothing to close."""


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


def _streamed(*pieces: str, truncated: bool = False) -> list[Step]:
    """A text answer streamed as ``pieces`` (its content is their join)."""
    return [
        *(LLMStreamDelta(content=p) for p in pieces),
        _response("".join(pieces), truncated=truncated),
    ]


def _failing(error: BaseException, *pieces: str) -> list[Step]:
    """``pieces`` streamed, then ``error`` raised (a JSON call raises it at once)."""
    return [*(LLMStreamDelta(content=p) for p in pieces), error]


def _timeout() -> LLMError:
    """The ``timeout`` error a client raises (a read timeout or the stream deadline)."""
    return provider_status_error("Infomaniak", None, timed_out=True)


def _malformed() -> LLMError:
    """C2's ``malformed_response`` error, built directly (the Literal isn't enforced)."""
    return LLMError(_MALFORMED_MESSAGE, code="malformed_response")


def _cut(text: str) -> str:
    """D7/D9: ``text`` up to and including its last ASCII whitespace ("" when none)."""
    return text[: max(text.rfind(char) for char in " \t\n\r") + 1]


def _cut_key() -> tuple[ApiKey, str]:
    """A GitHub fine-grained token one character short of its realistic length: the
    display redaction doesn't match that, so it is shown if the cut word is kept."""
    key = GITHUB_FINE_GRAINED.key()
    cut = key.text[:-1]
    assert surviving_chunks(sanitize_display_text(cut), key), "fixture: shown when uncut"
    return key, cut


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED each) and a Super Admin, behind the fake database."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture(autouse=True)
def _fixed_instructions(monkeypatch: pytest.MonkeyPatch) -> None:
    """GH-190: the instructions count a constant (tests/context_frames.py), so every
    ``context_usage`` frame is deterministic."""
    fix_instructions(monkeypatch)


@pytest.fixture(autouse=True)
def _empty_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty, unfrozen registry (any tool call is unknown); the old one is restored."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)


@pytest.fixture()
def llm() -> _ScriptLLM:
    return _ScriptLLM()


@pytest.fixture()
def client(world: World, llm: _ScriptLLM) -> TestClient:
    """The app around a REAL Agent (real tool-call recorder) and the scripted LLM."""
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    return make_client(make_app(agent), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Requests and reading the result
# ---------------------------------------------------------------------------


def _chat(db: FakeDb, account: Account) -> uuid.UUID:
    """A live, user-titled chat of ``account`` (so no title step runs)."""
    return db.add_chat(account.user_id, title="Sanitizing 25", title_source="user")


def _send(
    client: TestClient, account: Account, chat_id: uuid.UUID, message: str, *, sse: bool = True
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account`` (streamed unless ``sse`` is false)."""
    return client.post(
        f"/api/chats/{chat_id}/messages",
        headers={**account.cookie, **(_SSE_ACCEPT if sse else {})},
        json={"message": message},
    )


def _detail(client: TestClient, account: Account, chat_id: uuid.UUID) -> httpx.Response:
    """GET /api/chats/{chat_id} as its owner (must succeed)."""
    response = client.get(f"/api/chats/{chat_id}", headers=account.cookie)
    assert response.status_code == 200, response.text
    return response


def _shown(response: httpx.Response) -> list[tuple[str, str, str]]:
    """GET's messages as (role, content, status)."""
    return [(m["role"], m["content"], m["status"]) for m in response.json()["messages"]]


def _stored(db: FakeDb, chat_id: uuid.UUID) -> list[tuple[str, str]]:
    """The chat's stored messages by seq, raw: (role, content)."""
    return [(m["role"], m["content"]) for m in db.messages_of(chat_id)]


def _refuse_constant(name: str) -> Any:
    msg = f"non-standard JSON constant {name} in an SSE payload"
    raise ValueError(msg)


def _parse_sse(text: str) -> list[Frame]:
    """The frames of an SSE body, read as a client reads them (see the module docstring)."""
    frames: list[Frame] = []
    event: str | None = None
    data: list[str] = []
    for line in _LINE_BREAK.split(text):
        if line == "":
            if event is not None or data:
                assert event is not None, f"a frame without an event line: {data!r}"
                assert len(data) == 1, f"frame {event!r} has {len(data)} data lines"
                payload = json.loads(data[0], parse_constant=_refuse_constant)
                assert isinstance(payload, dict), data[0]
                frames.append((event, payload))
            event, data = None, []
            continue
        if line.startswith(":"):
            continue
        name, colon, value = line.partition(":")
        assert colon, f"not an SSE field line: {line[:80]!r}"
        value = value.removeprefix(" ")
        if name == "event":
            assert event is None, f"two event lines in one frame: {line[:80]!r}"
            assert _EVENT_NAME.fullmatch(value), f"bad event name {value!r}"
            event = value
        elif name == "data":
            data.append(value)
        else:
            msg = f"unexpected SSE field {name!r}"
            raise AssertionError(msg)
    assert event is None, "the body ends inside a frame"
    assert not data, "the body ends inside a frame"
    return frames


def _stream(response: httpx.Response) -> list[Frame]:
    """A streamed answer's frames (a 200 ``text/event-stream``); every delta 1..4096 chars."""
    content_type = response.headers.get("content-type", "")
    assert (response.status_code, content_type.split(";")[0]) == (200, "text/event-stream"), (
        response.status_code,
        content_type,
        response.text[:400],
    )
    frames = _parse_sse(response.text)
    for name, payload in frames:
        if name == "delta":
            assert 0 < len(payload["text"]) <= _MAX_DELTA_CHARS, len(payload["text"])
    return frames


def _names(frames: list[Frame]) -> list[str]:
    return [name for name, _ in frames]


def _joined(frames: list[Frame]) -> str:
    """The concatenated ``delta`` texts."""
    return "".join(payload["text"] for name, payload in frames if name == "delta")


def _usage(db: FakeDb, chat_id: uuid.UUID) -> Frame:
    """GH-190 (Decision 4): the ``context_usage`` frame right before ``message_saved``: the
    chat as its next turn starts, read now (tests/context_frames.py)."""
    return usage_frame(db, chat_id)


def _saved(db: FakeDb, chat_id: uuid.UUID, status: str) -> Frame:
    """``message_saved`` naming the chat's last stored message (read now) with ``status``."""
    last = db.messages_of(chat_id)[-1]
    return ("message_saved", {"message_id": str(plain(last["id"])), "status": status})


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the httpx client lines, which name request URLs)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


def _capped_answer(key_part: str) -> str:
    """A 65536-character answer (the 64 KiB cap's length) of filler words, then ``_KEPT``
    and ``key_part`` at its very end: the cap cut it inside the key."""
    tail = _KEPT + key_part
    room = _MAX_CHARS - len(tail)
    words, spaces = divmod(room, len("filler "))
    answer = "filler " * words + " " * spaces + tail
    assert len(answer) == _MAX_CHARS, "fixture: exactly the cap"
    return answer


# ===========================================================================
# 1. A truncated final answer ends at its last complete word (D7)
# ===========================================================================


@pytest.mark.parametrize("cut_by", ["output-cap", "64k-cap"])
def test_chat_output_truncated_final_turn_streams_and_stores_only_the_cut_reply(
    world: World, client: TestClient, llm: _ScriptLLM, cut_by: str
) -> None:
    """The answer was cut inside a key (by the provider's output cap, or a 65536-character
    answer by the 64 KiB cap): the deltas are the display text of the cut reply, which is
    what is stored and what GET shows; no part of the key in any frame or in GET; the turn
    is complete (``message_saved{complete}``, no ``error`` frame)."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    key, cut = _cut_key()
    if cut_by == "output-cap":
        content = _KEPT + cut
        pieces = [_KEPT, cut[:20], cut[20:]]
    else:
        content = _capped_answer(cut)
        pieces = [content[i : i + 8000] for i in range(0, len(content), 8000)]
    reply = _cut(content)
    llm.plan("Show me the key", _streamed(*pieces, truncated=True))

    response = _send(client, editor, chat_id, "Show me the key")

    frames = _stream(response)
    names = _names(frames)
    assert (names[0], names[-3:], set(names[1:-3])) == (
        "run_started",
        ["context_usage", "message_saved", "done"],
        {"delta"},
    )
    assert frames[-3:-1] == [_usage(db, chat_id), _saved(db, chat_id, "complete")]
    assert _joined(frames) == sanitize_display_text(reply)
    assert _stored(db, chat_id) == [("user", "Show me the key"), ("assistant", reply)]
    shown = _detail(client, editor, chat_id)
    assert _shown(shown)[-1] == ("assistant", _joined(frames), "complete")
    assert surviving_chunks(response.text, key) == []
    assert surviving_chunks(shown.text, key) == []


def test_chat_output_truncated_final_turn_over_json_returns_and_stores_the_cut_reply(
    world: World, client: TestClient, llm: _ScriptLLM
) -> None:
    """The same cut answer over JSON: status ``final`` with the cut reply (no part of the
    key in the body), stored cut, shown cut by GET."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    key, cut = _cut_key()
    llm.plan("Show me the key", _streamed(_KEPT, cut[:20], cut[20:], truncated=True))

    response = _send(client, editor, chat_id, "Show me the key", sse=False)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["status"], body["response"], body["error_code"]) == ("final", _KEPT, None)
    assert _stored(db, chat_id) == [("user", "Show me the key"), ("assistant", _KEPT)]
    shown = _detail(client, editor, chat_id)
    assert _shown(shown)[-1] == ("assistant", _KEPT, "complete")
    assert surviving_chunks(response.text, key) == []
    assert surviving_chunks(shown.text, key) == []


# ===========================================================================
# 2. A streamed timeout after text stores the cut partial reply (D9)
# ===========================================================================


def test_chat_output_streamed_timeout_after_text_stores_the_partial_then_the_error(
    world: World, client: TestClient, llm: _ScriptLLM
) -> None:
    """Deltas ending inside a key, then the ``timeout``: the frames are the deltas up to the
    last whole word, ``message_saved{error}`` naming the stored error reply (the last
    message), ``error{timeout}``, ``done``; GET shows the cut partial reply before the
    error reply; no part of the key anywhere."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    key, cut = _cut_key()
    llm.plan("Show me the key", _failing(_timeout(), _KEPT, cut[:20], cut[20:]))

    response = _send(client, editor, chat_id, "Show me the key")

    frames = _stream(response)
    assert _stored(db, chat_id) == [
        ("user", "Show me the key"),
        ("assistant", _KEPT),
        ("assistant", _TIMEOUT_MESSAGE),
    ]
    assert frames == [
        ("run_started", {"chat_id": str(chat_id)}),
        ("delta", {"text": _KEPT}),
        _usage(db, chat_id),
        _saved(db, chat_id, "error"),
        ("error", {"code": "timeout", "message": _TIMEOUT_MESSAGE}),
        ("done", {}),
    ]
    shown = _detail(client, editor, chat_id)
    assert [(role, content) for role, content, _ in _shown(shown)[-3:]] == [
        ("user", "Show me the key"),
        ("assistant", _joined(frames)),
        ("assistant", _TIMEOUT_MESSAGE),
    ]
    assert _shown(shown)[-1][2] == "error"
    assert surviving_chunks(response.text, key) == []
    assert surviving_chunks(shown.text, key) == []


# ===========================================================================
# 3. malformed_response is a coded error in both modes (D1)
# ===========================================================================


@pytest.mark.parametrize(
    ("pieces", "sent"),
    [
        pytest.param((), [], id="before-any-delta"),
        pytest.param(("Partial ", "answ"), ["Partial "], id="after-deltas"),
    ],
)
def test_chat_output_malformed_response_streams_error_malformed_response(
    world: World,
    client: TestClient,
    llm: _ScriptLLM,
    pieces: tuple[str, ...],
    sent: list[str],
) -> None:
    """``message_saved{error}`` then ``error{malformed_response}`` (never
    ``internal_error``); deltas already sent end at a word; only the error reply is
    stored after the user message (no partial: D9 is for ``timeout`` only)."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    llm.plan("Summarise it", _failing(_malformed(), *pieces))

    frames = _stream(_send(client, editor, chat_id, "Summarise it"))

    assert _stored(db, chat_id) == [("user", "Summarise it"), ("assistant", _MALFORMED_MESSAGE)]
    assert frames == [
        ("run_started", {"chat_id": str(chat_id)}),
        *(("delta", {"text": text}) for text in sent),
        _usage(db, chat_id),
        _saved(db, chat_id, "error"),
        ("error", {"code": "malformed_response", "message": _MALFORMED_MESSAGE}),
        ("done", {}),
    ]
    assert _shown(_detail(client, editor, chat_id))[-1] == (
        "assistant",
        _MALFORMED_MESSAGE,
        "error",
    )


def test_chat_output_malformed_response_over_json_is_status_error_with_its_code(
    world: World, client: TestClient, llm: _ScriptLLM
) -> None:
    """A 200 with ``status: "error"``, ``error_code: "malformed_response"`` and the error's
    message (never the generic reply or a 500); the error reply is stored."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    llm.plan("Summarise it", _failing(_malformed()))

    response = _send(client, editor, chat_id, "Summarise it", sse=False)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["status"], body["error_code"], body["response"]) == (
        "error",
        "malformed_response",
        _MALFORMED_MESSAGE,
    )
    assert _stored(db, chat_id) == [("user", "Summarise it"), ("assistant", _MALFORMED_MESSAGE)]


# ===========================================================================
# 4. Logs
# ===========================================================================


def test_chat_output_sanitization_debug_logs_carry_no_answer_or_argument(
    world: World, client: TestClient, llm: _ScriptLLM, caplog: pytest.LogCaptureFixture
) -> None:
    """At DEBUG, over four turns (an unknown tool's call then a truncated answer, a timeout
    after text, a malformed reply after text, a malformed JSON reply): no app record holds
    a user message, answer or partial text, the deltas of the rejected reply or a tool
    argument. Each turn's outcome is checked, so the scan is not vacuous."""
    caplog.set_level(logging.DEBUG)
    editor = world.a["editor"]
    db = world.db
    marks = {
        "user": "USER-MARK-gh25",
        "argument": "ARG-MARK-gh25",
        "answer": "ANSWER-MARK-gh25",
        "partial": "PARTIAL-MARK-gh25",
        "rejected": "REJECTED-MARK-gh25",
    }
    export = ToolCall(
        tool="crm", action="export_all", args={"note": marks["argument"]}, tool_call_id="c-x"
    )
    first, second, third, fourth = (f"{marks['user']} turn {n}" for n in range(1, 5))
    llm.plan(
        first,
        [LLMStreamDelta(content="On it. "), _response("On it. ", export)],
        _streamed(f"{marks['answer']} is ", "the answ", truncated=True),
    )
    llm.plan(second, _failing(_timeout(), f"{marks['partial']} so ", "fa"))
    llm.plan(third, _failing(_malformed(), f"{marks['rejected']} and ", "mo"))
    llm.plan(fourth, _failing(_malformed()))
    chats = [_chat(db, editor) for _ in range(4)]

    frames = _stream(_send(client, editor, chats[0], first))
    _stream(_send(client, editor, chats[1], second))
    third_frames = _stream(_send(client, editor, chats[2], third))
    json_body = _send(client, editor, chats[3], fourth, sse=False).json()

    (record,) = (payload for name, payload in frames if name == "tool_call")
    assert (record["tool"], record["action"], record["permission"], record["success"]) == (
        "crm",
        "export_all",
        "deny",
        False,
    )
    assert _stored(db, chats[0])[-1] == ("assistant", f"{marks['answer']} is the ")
    assert _stored(db, chats[1])[1] == ("assistant", f"{marks['partial']} so ")
    assert ("error", {"code": "malformed_response", "message": _MALFORMED_MESSAGE}) in third_frames
    assert json_body["error_code"] == "malformed_response"
    (audit,) = db.audit_rows("tool.call")
    assert audit["metadata"]["decision"] == "deny"
    logged = _app_log_text(caplog)
    assert "Completed message for chat" in logged
    assert [name for name, mark in marks.items() if mark in logged] == []
