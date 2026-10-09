"""HTTP spec of the context frames of streamed chat runs (GH-190, Decisions 3 to 5, C11).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B, real session cookies; the attachments root
under ``tmp_path``). The agent is a stub (``_Script``): its ``run`` binds every call
to ``Agent.run``'s signature, plays the scripted reply (tests/test_chat_stream_api.py's
``_Reply``: text pieces into ``on_delta``, records into ``on_tool_call``) into the
run's stream, runs a one-shot ``during`` hook, and answers an ``AgentResult`` whose
history is the history it got, the turn's user message (none on a resume) and the
scripted messages, with the scripted ``context_notice`` (contract C2) when one is
given. ``admino.context_budget.instructions_tokens`` answers a constant
(tests/context_frames.py), so every ``context_usage`` is deterministic: the
instructions, the active attachments' row ``token_estimate``, the stored history
after the budget and the reserved output, over the budget 180 000 (the default
platform's 200 000 input tokens minus the 10 % margin).

What is pinned (the frames are read as an SSE client reads them,
tests/test_chat_stream_api.py's ``_stream``):
- A stored streamed run ends ``[limit text deltas]``, ``confirm``,
  ``context_notice``, ``context_usage``, ``message_saved``, ``error``, ``title``,
  ``done`` (Decision 4): checked frame by frame for a final answer, a kept
  confirmation, a ``limit_reached`` run, an LLM error, ``context_too_long``, a first
  exchange with its model title, a failed first exchange with its fallback title, a
  ``stopped`` run and a streamed approval, each reporting dropped turns.
- ``context_usage`` is exactly ``{"used", "max", "percent"}`` (a literal for a
  plain turn: the turn's own messages count) and ``context_notice`` exactly
  ``{"dropped_turns", "dropped_messages"}``; a run that dropped nothing sends no
  ``context_notice``. For the same scripted turn and the same scripted approval
  (with a sent file counted by its row estimate), both payloads equal the JSON
  answer's ``context_usage`` and ``context_notice``.
- A streamed denial is exactly ``run_started``, the denial ``delta``,
  ``context_usage``, ``message_saved``, ``done``, its usage counting the chat's
  active file from its row (the file's derived files are gone: nothing is read).
- No context frame when nothing is stored: an agent that raised is
  ``error{internal_error}`` and a chat trashed during the run (whose result carried a
  notice) ``error{chat_not_found}``; the send rule's refusals (Decision 5) are the
  JSON 422 ``context_overflow`` and ``attachment_bytes_exceeded`` with
  ``Accept: text/event-stream`` too, the same body as without it, nothing run or
  stored.
- OpenAPI: the 200 description of both streaming routes (``_EVENT_STREAM_RESPONSES``)
  names ``context_notice`` and ``context_usage``.

New names (``admino.context_budget``, ``ContextNotice``) are used lazily, so the file
collects before GH-190 is implemented.

Security notes:
- Every message, id and figure here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import inspect
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import attachments, scoped_settings
from admino.agent import Agent
from admino.models import AgentResult, LLMMessage, PendingConfirmation
from tests.attachment_derived import write_derived
from tests.conftest import default_test_platform_settings
from tests.context_frames import (
    BUDGET,
    INSTRUCTIONS,
    RESERVED_OUTPUT,
    fix_instructions,
    notice_frame,
    usage_frame,
    usage_payload,
)
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    build_world,
    make_app,
    make_client,
    seed_pending_confirmation,
    stub_agent,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)
from tests.test_chat_stream_api import (
    _CALL_A,
    _CONFIRMATION_ID,
    _DONE,
    _EXPIRES_AT,
    _EXPIRES_AT_JSON,
    _LIMIT_REPLY,
    _PENDING_CALL,
    _TITLE,
    _TITLE_MESSAGE,
    _chat,
    _confirm,
    _delta,
    _error,
    _of,
    _record,
    _Reply,
    _reply,
    _resumed,
    _saved,
    _started,
    _stream,
    _TitleLLM,
    _tool_call,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence
    from pathlib import Path
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SSE_ACCEPT: Final = {"Accept": "text/event-stream"}
_JSON: Final = "application/json"
_MESSAGE: Final = "Hello there"
_FAILURE: Final = "The model is not available right now."
_CONTEXT_TOO_LONG: Final = (
    "This message doesn't fit the model's context, even without the earlier messages. "
    "Shorten it or exclude some attachments."
)
_DENIAL: Final = "Action memory.store was denied."
# The notice every run of the order matrix reports.
_NOTICE: Final = (2, 5)
# A sent file's row token_estimate (its derived text estimates the same).
_FILE_TOKENS: Final = 1_000
# Decision 5: budget minus reserved output, and the default per-turn byte cap (64 MiB).
_AVAILABLE_TOKENS: Final = BUDGET - RESERVED_OUTPUT
_MAX_TURN_BYTES: Final = 64 * 1_048_576

_CONFIRM_FRAME: Final = (
    "confirm",
    {
        "confirmation_id": _CONFIRMATION_ID,
        "tool": "memory",
        "action": "store",
        "args": {"key": "plan", "value": "ship"},
        "expires_at": _EXPIRES_AT_JSON,
    },
)

_CONTEXT_EVENT: Final = re.compile(r"\bcontext_(?:usage|notice)\b")

# ---------------------------------------------------------------------------
# The stub agent
# ---------------------------------------------------------------------------

_AGENT_RUN: Final = inspect.signature(Agent.run)


@dataclass(frozen=True)
class _Planned:
    """One stub run: the scripted reply and the notice its result reports (None: none)."""

    reply: _Reply
    notice: tuple[int, int] | None = None


class _Script:
    """Scripted runs for the stub agent's ``run`` and the arguments of every call."""

    def __init__(self) -> None:
        self.planned: list[_Planned] = []
        self.runs: list[dict[str, Any]] = []
        # Awaited once, inside the next run, after its script and before it answers.
        self.during: Callable[[], Awaitable[None]] | None = None

    def queue(self, reply: _Reply, notice: tuple[int, int] | None = None) -> None:
        self.planned.append(_Planned(reply, notice))

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        bound = _AGENT_RUN.bind(None, *args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        self.runs.append(arguments)
        planned = self.planned.pop(0) if self.planned else _Planned(_Reply())
        reply = planned.reply
        stream = arguments["stream"]
        if stream is not None:
            for step in reply.steps:
                if isinstance(step, str):
                    await stream.on_delta(step)
                else:
                    await stream.on_tool_call(step)
        during, self.during = self.during, None
        if during is not None:
            await during()
        if reply.error is not None:
            raise reply.error
        base = list(arguments["history"])
        if arguments["pending_confirmation"] is None:
            base.append(LLMMessage(role="user", content=arguments["user_message"]))
        pending = None
        if reply.pending is not None:
            pending = PendingConfirmation(
                confirmation_id=_CONFIRMATION_ID,
                session_id=arguments["session_id"],
                tool_call=reply.pending,
                expires_at=_EXPIRES_AT,
            )
        extra: dict[str, Any] = {}
        if planned.notice is not None:
            from admino.models import ContextNotice

            turns, messages = planned.notice
            extra["context_notice"] = ContextNotice(dropped_turns=turns, dropped_messages=messages)
        return AgentResult(
            status=reply.status,  # type: ignore[arg-type]
            response=reply.response,
            history=[*base, *reply.new],
            tool_calls=reply.tool_calls,
            pending_confirmation=pending,
            error_code=reply.error_code,  # type: ignore[arg-type]
            **extra,
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin, behind the fake database; the
    attachments root is under ``tmp_path``."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    return built


@pytest.fixture(autouse=True)
def _fixed_instructions(monkeypatch: pytest.MonkeyPatch) -> None:
    """The instructions count ``INSTRUCTIONS`` tokens (tests/context_frames.py)."""
    fix_instructions(monkeypatch)


@pytest.fixture()
def script() -> _Script:
    return _Script()


@pytest.fixture()
def agent(script: _Script) -> MagicMock:
    """A stub agent whose ``run`` (an AsyncMock) plays ``script``."""
    stub = stub_agent()
    stub.run.side_effect = script.run
    return stub


@pytest.fixture()
def client(world: World, agent: MagicMock) -> TestClient:
    """The app around the stub agent; an escaping exception becomes the app's 500."""
    return make_client(make_app(agent), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _send(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    message: str = _MESSAGE,
    *,
    sse: bool = True,
    attachment_ids: Sequence[uuid.UUID] = (),
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account`` (streamed unless ``sse`` is false)."""
    body: dict[str, Any] = {"message": message}
    if attachment_ids:
        body["attachment_ids"] = [str(file_id) for file_id in attachment_ids]
    return client.post(
        f"/api/chats/{chat_id}/messages",
        headers={**account.cookie, **(_SSE_ACCEPT if sse else {})},
        json=body,
    )


def _earlier_exchange(db: FakeDb, chat_id: uuid.UUID) -> uuid.UUID:
    """Store an earlier exchange (user, assistant); return the user message's id."""
    question = db.add_chat_message(chat_id, "user", "Earlier question")
    db.add_chat_message(chat_id, "assistant", "Earlier answer.")
    return question


def _sent_file(db: FakeDb, chat_id: uuid.UUID, message_id: uuid.UUID) -> tuple[uuid.UUID, Path]:
    """A ready, active file sent with ``message_id``: row ``token_estimate`` ``_FILE_TOKENS``,
    its derived text (estimating the same) written; return its id and derived directory."""
    chat = db.chat_row(chat_id)
    assert chat is not None
    text = "x" * (_FILE_TOKENS * 4)
    file_id = db.add_attachment(
        chat_id,
        status="ready",
        page_count=1,
        token_estimate=_FILE_TOKENS,
        derived_bytes=len(text),
        message_id=message_id,
    )
    derived = write_derived(
        attachments.attachments_root(),
        plain(chat["org_id"]),
        file_id,
        kind="pdf",
        parts=[("text", text, 1)],
        page_count=1,
    )
    return file_id, derived


def _ask(client: TestClient, script: _Script, account: Account, chat_id: uuid.UUID) -> None:
    """A JSON turn that keeps a confirmation of memory.store (no notice)."""
    script.queue(_reply(ask=_PENDING_CALL))
    asked = _send(client, account, chat_id, sse=False)
    assert asked.json()["status"] == "awaiting_confirmation", asked.text


# ---------------------------------------------------------------------------
# 1. context_usage right before message_saved; its value
# ---------------------------------------------------------------------------


def test_chat_context_stream_final_turn_ends_with_context_usage_right_before_message_saved(
    world: World, client: TestClient, script: _Script
) -> None:
    """A final turn in a chat with one earlier exchange: the deltas, then
    ``context_usage`` exactly ``{"used", "max", "percent"}``, then ``message_saved``,
    ``done``; no ``context_notice`` (the run dropped nothing). ``used`` counts the
    instructions, the four stored messages (the earlier exchange and this turn's two)
    and the reserved output: 2345 + (4 + 4) + (4 + 4) + (4 + 3) + (4 + 3) + 4096."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    _earlier_exchange(db, chat_id)
    script.queue(_reply("Hello ", "world."))

    frames = _stream(_send(client, editor, chat_id))

    assert INSTRUCTIONS + RESERVED_OUTPUT == 6_441, "fixture: the patched constants"
    assert frames == [
        _started(chat_id),
        _delta("Hello "),
        _delta("world."),
        ("context_usage", {"used": 6_471, "max": 180_000, "percent": 3}),
        _saved(db, chat_id, "complete"),
        _DONE,
    ]


@pytest.mark.parametrize("route", ["turn", "approval"])
def test_chat_context_stream_usage_and_notice_frames_equal_the_json_answer(
    world: World, client: TestClient, script: _Script, route: str
) -> None:
    """The same scripted run reporting a notice {3, 7} (a turn, or an approved resume),
    once as JSON and once streamed, on two chats with the same stored history and one
    sent file each (row estimate 1000): the ``context_notice`` and ``context_usage``
    frames carry the JSON answer's ``context_notice`` and ``context_usage``, the usage
    counting the file."""
    editor = world.a["editor"]
    db = world.db
    chats: list[uuid.UUID] = []
    for _ in range(2):
        chat_id = _chat(db, editor)
        _sent_file(db, chat_id, _earlier_exchange(db, chat_id))
        chats.append(chat_id)
    json_chat, sse_chat = chats
    if route == "turn":
        run = _reply("Answer ", "given.")
        script.queue(run, notice=(3, 7))
        script.queue(run, notice=(3, 7))
        as_json = _send(client, editor, json_chat, sse=False)
        streamed = _send(client, editor, sse_chat)
    else:
        for chat_id in chats:
            _ask(client, script, editor, chat_id)
        resumed = _resumed(_PENDING_CALL, "Saved ", "it.")
        script.queue(resumed, notice=(3, 7))
        script.queue(resumed, notice=(3, 7))
        as_json = _confirm(client, editor, json_chat, sse=False)
        streamed = _confirm(client, editor, sse_chat)

    assert as_json.status_code == 200, as_json.text
    body = as_json.json()
    frames = _stream(streamed)
    assert (_of(frames, "context_notice"), _of(frames, "context_usage")) == (
        [body["context_notice"]],
        [body["context_usage"]],
    )
    assert (body["context_notice"], body["context_usage"]) == (
        {"dropped_turns": 3, "dropped_messages": 7},
        usage_payload(db, sse_chat, attachment_tokens=_FILE_TOKENS),
    )


# ---------------------------------------------------------------------------
# 2. The end order of every stored outcome (Decision 4)
# ---------------------------------------------------------------------------

Frame = tuple[str, dict[str, Any]]


@dataclass(frozen=True)
class _Outcome:
    """A stored run's script and the frames around its context frames."""

    reply: _Reply
    # The frames after run_started and before context_notice.
    head: tuple[Frame, ...]
    # The stored status message_saved names.
    status: str
    # The frames after message_saved and before done.
    tail: tuple[Frame, ...] = ()
    # An untitled chat's first exchange (its title is sent).
    first_exchange: bool = False
    # A streamed approval of a confirmation a JSON turn kept.
    approval: bool = False


_OUTCOMES: Final[dict[str, _Outcome]] = {
    "final": _Outcome(
        reply=_reply("Answer ", "given."),
        head=(_delta("Answer "), _delta("given.")),
        status="complete",
    ),
    "awaiting_confirmation": _Outcome(
        reply=_reply("Storing ", ask=_PENDING_CALL),
        head=(
            _delta("Storing "),
            _tool_call(_record(_PENDING_CALL, "confirm", success=False)),
            _CONFIRM_FRAME,
        ),
        status="awaiting_confirmation",
    ),
    "limit_reached": _Outcome(
        reply=_reply("Looking ", _CALL_A, status="limit_reached", closing=_LIMIT_REPLY),
        head=(_delta("Looking "), _tool_call(_record(_CALL_A)), _delta(_LIMIT_REPLY)),
        status="limit_reached",
    ),
    "llm_error": _Outcome(
        reply=_reply(
            "Partial answer ", status="error", closing=_FAILURE, error_code="rate_limited"
        ),
        head=(_delta("Partial answer "),),
        status="error",
        tail=(_error("rate_limited", _FAILURE),),
    ),
    "context_too_long": _Outcome(
        reply=_reply(status="error", closing=_CONTEXT_TOO_LONG, error_code="context_too_long"),
        head=(),
        status="error",
        tail=(_error("context_too_long", _CONTEXT_TOO_LONG),),
    ),
    "first_exchange_title": _Outcome(
        reply=_reply("Answer ", "given."),
        head=(_delta("Answer "), _delta("given.")),
        status="complete",
        tail=(("title", {"title": _TITLE}),),
        first_exchange=True,
    ),
    "first_exchange_error": _Outcome(
        reply=_reply(status="error", closing=_FAILURE, error_code="timeout"),
        head=(),
        status="error",
        tail=(_error("timeout", _FAILURE), ("title", {"title": _TITLE_MESSAGE})),
        first_exchange=True,
    ),
    "stopped": _Outcome(
        reply=_reply("Partial ", "answer ", status="stopped"),
        head=(_delta("Partial "), _delta("answer ")),
        status="stopped",
    ),
    "approval": _Outcome(
        reply=_resumed(_PENDING_CALL, "Saved ", "it."),
        head=(_tool_call(_record(_PENDING_CALL, "confirm")), _delta("Saved "), _delta("it.")),
        status="complete",
        approval=True,
    ),
}


@pytest.mark.parametrize("outcome", list(_OUTCOMES))
def test_chat_context_stream_end_order_puts_notice_then_usage_right_before_message_saved(
    world: World, client: TestClient, agent: MagicMock, script: _Script, outcome: str
) -> None:
    """Each stored outcome, its run reporting dropped turns {2, 5}: the stream is
    ``run_started``, its deltas and tool calls (a ``limit_reached`` run's limit reply
    last), ``confirm`` when one is kept, then ``context_notice``, ``context_usage``,
    ``message_saved``, then ``error`` for a failed run, ``title`` for a first exchange
    (the model's title, or the fallback after an error), then ``done``. A first
    exchange's chat holds two earlier user messages only (no reply yet)."""
    editor = world.a["editor"]
    db = world.db
    case = _OUTCOMES[outcome]
    chat_id = _chat(db, editor, titled=not case.first_exchange)
    if case.first_exchange:
        agent._llm = _TitleLLM()
        db.add_chat_message(chat_id, "user", "Earlier note one")
        db.add_chat_message(chat_id, "user", "Earlier note two")
    else:
        _earlier_exchange(db, chat_id)
    if case.approval:
        _ask(client, script, editor, chat_id)
    script.queue(case.reply, notice=_NOTICE)

    if case.approval:
        response = _confirm(client, editor, chat_id)
    else:
        message = _TITLE_MESSAGE if case.first_exchange else _MESSAGE
        response = _send(client, editor, chat_id, message)

    frames = _stream(response)
    assert frames == [
        _started(chat_id),
        *case.head,
        notice_frame(*_NOTICE),
        usage_frame(db, chat_id),
        _saved(db, chat_id, case.status),
        *case.tail,
        _DONE,
    ]


def test_chat_context_stream_pending_limit_refusal_sends_usage_before_message_saved(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GH-24's refused confirmation (the Editor already holds the stored
    ``max_pending_confirmations``, 1, elsewhere), the run reporting dropped turns: no
    ``confirm``; ``context_notice``, ``context_usage`` (counting the stored refusal
    messages), ``message_saved{error}``, ``error{rate_limit}``, ``done``."""
    stored = default_test_platform_settings()
    limits = stored.limits.model_copy(update={"max_pending_confirmations": 1})
    monkeypatch.setattr(
        scoped_settings, "_platform_cache", stored.model_copy(update={"limits": limits})
    )
    editor = world.a["editor"]
    db = world.db
    seed_pending_confirmation(editor, _chat(db, editor), "confirm-190-elsewhere")
    chat_id = _chat(db, editor)
    _earlier_exchange(db, chat_id)
    script.queue(_reply(ask=_PENDING_CALL), notice=_NOTICE)

    frames = _stream(_send(client, editor, chat_id))

    refusal = (
        "Action memory.store was not run: too many confirmations are pending."
        " Approve or deny one of them first."
    )
    assert frames == [
        _started(chat_id),
        _tool_call(_record(_PENDING_CALL, "confirm", success=False)),
        notice_frame(*_NOTICE),
        usage_frame(db, chat_id),
        _saved(db, chat_id, "error"),
        _error("rate_limit", refusal),
        _DONE,
    ]


# ---------------------------------------------------------------------------
# 3. The denial stream
# ---------------------------------------------------------------------------


def test_chat_context_stream_denial_streams_usage_right_before_message_saved(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """A streamed denial in a chat with a sent file whose derived files are gone by
    then: exactly ``run_started``, the denial ``delta``, ``context_usage`` (the stored
    history with the denial's messages, the file counted from its row: nothing is read),
    ``message_saved{complete}``, ``done``; no run."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    _, derived = _sent_file(db, chat_id, _earlier_exchange(db, chat_id))
    _ask(client, script, editor, chat_id)
    shutil.rmtree(derived)

    frames = _stream(_confirm(client, editor, chat_id, approved=False))

    assert frames == [
        _started(chat_id),
        _delta(_DENIAL),
        usage_frame(db, chat_id, attachment_tokens=_FILE_TOKENS),
        _saved(db, chat_id, "complete"),
        _DONE,
    ]
    assert agent.run.await_count == 1


# ---------------------------------------------------------------------------
# 4. No context frame when nothing is stored
# ---------------------------------------------------------------------------


def test_chat_context_stream_agent_failure_sends_no_context_frame(
    world: World, client: TestClient, script: _Script
) -> None:
    """The agent raises after a delta: ``run_started``, the delta,
    ``error{internal_error}``, ``done``, with no ``context_notice`` or
    ``context_usage`` (nothing is stored). The chat's next streamed turn is stored and
    ends ``context_usage``, ``message_saved``, ``done``."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    _earlier_exchange(db, chat_id)
    script.queue(_Reply(steps=("Partial ",), error=RuntimeError("agent failure 190")))
    script.queue(_reply("Answer ", "given."))

    failed = _stream(_send(client, editor, chat_id))
    retried = _stream(_send(client, editor, chat_id, "Try again"))

    assert failed == [
        _started(chat_id),
        _delta("Partial "),
        _error("internal_error", "Internal error"),
        _DONE,
    ]
    assert retried[-3:] == [usage_frame(db, chat_id), _saved(db, chat_id, "complete"), _DONE]


def test_chat_context_stream_chat_trashed_during_the_run_sends_no_context_frame(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """The chat is trashed while a run that reports dropped turns is in flight:
    ``run_started``, ``error{chat_not_found}``, ``done``; neither the run's notice nor a
    usage is sent, nothing is stored."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    _earlier_exchange(db, chat_id)

    async def trash() -> None:
        db.chats[uuid.UUID(int=chat_id.int)]["deleted_at"] = datetime.now(UTC)

    script.during = trash
    script.queue(_Reply(steps=()), notice=_NOTICE)

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [_started(chat_id), _error("chat_not_found", "Chat not found"), _DONE]
    assert agent.run.await_count == 1
    assert [row["content"] for row in db.messages_of(chat_id)] == [
        "Earlier question",
        "Earlier answer.",
    ]


@pytest.mark.parametrize(
    ("reason", "token_estimate", "derived_bytes"),
    [
        ("context_overflow", _AVAILABLE_TOKENS + 1, 64),
        ("attachment_bytes_exceeded", 10, _MAX_TURN_BYTES + 1),
    ],
    ids=["context_overflow", "attachment_bytes_exceeded"],
)
def test_chat_context_stream_send_rule_refusal_is_json_with_an_event_stream_accept(
    world: World,
    client: TestClient,
    agent: MagicMock,
    reason: str,
    token_estimate: int,
    derived_bytes: int,
) -> None:
    """Decision 5 on a streamed send: a message sending a ready file one token over the
    budget minus the reserved output (or one byte over the 64 MiB cap) is the JSON 422
    with that ``reason``, the same body as the request without the SSE header; no
    stream, no run, nothing stored, the file still unsent."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    file_id = db.add_attachment(
        chat_id,
        status="ready",
        page_count=1,
        token_estimate=token_estimate,
        derived_bytes=derived_bytes,
    )

    as_json = _send(client, editor, chat_id, sse=False, attachment_ids=[file_id])
    streamed = _send(client, editor, chat_id, attachment_ids=[file_id])

    assert (streamed.status_code, streamed.headers["content-type"]) == (422, _JSON), streamed.text[
        :300
    ]
    body = streamed.json()
    assert (body["reason"], set(body), body) == (
        reason,
        {"detail", "reason", "report"},
        as_json.json(),
    )
    assert agent.run.await_count == 0
    assert db.messages_of(chat_id) == []
    file_row = db.attachment_row(file_id)
    assert file_row is not None
    assert file_row["message_id"] is None


# ---------------------------------------------------------------------------
# 5. OpenAPI
# ---------------------------------------------------------------------------


def test_chat_context_stream_openapi_names_the_context_events_on_both_streaming_routes(
    agent: MagicMock,
) -> None:
    """The 200 description of POST /api/chats/{chat_id}/messages and
    POST /api/confirm/{confirmation_id} (the SSE events they stream) names
    ``context_notice`` and ``context_usage``."""
    schema = make_app(agent).openapi()
    paths = ("/api/chats/{chat_id}/messages", "/api/confirm/{confirmation_id}")

    named = {
        path: sorted(
            set(
                _CONTEXT_EVENT.findall(
                    schema["paths"][path]["post"]["responses"]["200"]["description"]
                )
            )
        )
        for path in paths
    }

    assert named == {path: ["context_notice", "context_usage"] for path in paths}
