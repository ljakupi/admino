"""HTTP spec of streamed chat turns (GH-8, contract C5.1 to C5.6, with C2, C3 and C6).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin, an Editor and a Viewer
each, plus a Super Admin, all with real session cookies). The agent is a stub
(``_Script``, the pattern of tests/test_chat_turns_api.py): its ``run`` binds
every call to ``Agent.run``'s contract signature (now with the keyword-only
``stream``), records the arguments and the exact keyword set, and answers a
scripted ``AgentResult`` whose ``history`` is the history it received plus
this turn's user message (none on a confirmation resume) plus the scripted new
messages. When the server passes a ``RunStream``, the stub first plays its
script into it: each text piece into ``on_delta``, each ``ToolCallRecord``
into ``on_tool_call``, in order. A one-shot ``during`` hook (park, trash,
rename) runs after the script and before the result.

``_parse_sse`` reads a body as an SSE client does (lines split at CRLF, CR or
LF; a blank line ends a frame; ``:`` comment lines ignored; exactly one
``event:`` and one ``data:`` line per frame; the data parsed as strict JSON,
so a ``NaN`` or ``Infinity`` literal fails) into ``[(event, payload)]``.
``TestClient`` and ``httpx.ASGITransport`` return a body once the stream has
ended, which is enough for order and payloads. Concurrency (a send while a run
is parked) drives two requests in the test's event loop through
``httpx.ASGITransport``.

What is pinned:
- Negotiation (C5.1): POST /api/chats/{id}/messages and POST /api/confirm/{id}
  stream for an ``Accept`` listing ``text/event-stream`` (any position, any
  case, parameters ignored, a ``q`` above 0) and answer today's JSON
  ChatResponse otherwise (no header, ``*/*``, ``application/json``,
  ``text/html``, ``q=0``). The legacy POST /api/message stays JSON. The stream
  is a 200 with ``text/event-stream; charset=utf-8``, ``cache-control:
  no-cache`` and ``x-accel-buffering: no``.
- The agent call (C3): a JSON request passes exactly today's keywords (no
  ``stream``); a streamed turn or approval passes an ``admino.streaming.RunStream``
  whose ``stop`` is not set.
- Refusals before the run with ``Accept: text/event-stream`` are the usual JSON
  error, the same status and body as without the header: 401, CSRF 403, Viewer
  and Super Admin 403 (no chat statement), 422 (extra field, over the stored
  ``max_message_length``, a non-UUID id; the input never echoed), the identical
  404 ``chat_not_found`` (unknown, other org, colleague, trashed), 429, and
  the confirm route's 404 with nothing pending; no run, nothing stored.
- Frames per outcome (C5.3): ``run_started {chat_id}`` first and ``done {}``
  last; deltas word by word (``DisplayDeltas``: flushed before every
  ``tool_call`` and at the end of the run); ``tool_call`` = the record's JSON;
  then ``confirm``, ``message_saved {message_id, status}``, ``error {code,
  message}``, in that order: final, tool turn, kept confirmation (no delta of
  the "requires user confirmation" text), GH-24's pending-limit refusal,
  coded and uncoded errors, ``residency_blocked``, ``limit_reached`` (one
  delta of the limit reply), ``stopped``, an agent that raised (``internal_error``,
  nothing stored) and a chat trashed during the run (``chat_not_found``,
  nothing stored).
- Payloads: ``tool_call`` and ``confirm`` equal the JSON response's
  ``tool_calls`` and ``pending_confirmation`` for the same scripted run;
  ``message_saved`` names the chat's last stored message and its stored
  status; non-finite tool arguments are null.
- Display deltas end to end: keys split across ``on_delta`` calls and a split
  ``Bearer`` token never reach a frame, in full or in part; the deltas equal the
  stored reply as GET /api/chats/{id} shows it.
- A cut answer (C11, audit core L-1): the end of a ``stopped`` or ``error`` run,
  an agent that raised and a chat trashed during the run drop the answer's
  unfinished last word (``flush(complete=False)``), so deltas ending inside a key
  (a GitHub fine-grained token one character short, which the display rules
  don't match) put no 8 characters of it in any frame, and a stopped turn's
  deltas equal its stored reply (the stub returns it cut, as the agent does); a
  ``final`` or ``limit_reached`` run sends its last word, and text before a
  ``tool_call`` is sent whole, also in a stopped run (``flush(complete=True)``).
- Frame injection: blank lines, ``event:`` lines, CRLF and U+2028 in deltas and
  tool arguments: exactly one ``done``, every payload round-trips.
- One active run per chat (C5.5): while a run of the chat (streamed or JSON)
  is parked, a send in either mode is ``409 run_active`` (JSON), with no run
  and nothing stored; the same on the legacy route; the chat's pending
  confirmation survives the refusal; the next send after the run runs; an
  approval sent meanwhile waits and then streams the resumed run.
- Confirm with SSE: an approval streams the resumed run (no ``title``); a
  denial is exactly ``run_started``, the denial ``delta``,
  ``message_saved{complete}``, ``done``, and is stored like the JSON denial.
- Titles (C5.6): an untitled chat's first streamed exchange sends ``title``
  (the stored title) between ``message_saved`` and ``done``; an ``error`` or
  ``stopped`` first exchange the fallback title with no title call; a chat
  renamed during the run and a second exchange send none; a JSON turn still
  titles in the background.
- OpenAPI: both operations list ``text/event-stream`` beside ``application/json``.
- Logs: at DEBUG no record holds the message, a delta, a title or a tool
  argument value.

New names (``admino.streaming``, the ``hold`` keyword) are used lazily, so the
file collects before GH-8 is implemented.

Security notes:
- Every message, id and argument here is a fixed fake value; the keys and the
  Bearer token are built at runtime (tests/credential_keys.py), never literal.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import re
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest

from admino import scoped_settings, server
from admino.llm import LLMResponse
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
    sanitize_display_text,
)
from tests.conftest import default_test_platform_settings
from tests.credential_keys import (
    GITHUB_FINE_GRAINED,
    anthropic_api03_key,
    api_key,
    openai_project_key,
    surviving_chunks,
)
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    CLIENT_IP,
    FORBIDDEN,
    UNAUTHORIZED,
    build_world,
    make_app,
    make_client,
    seed_pending_confirmation,
    stub_agent,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable
    from unittest.mock import MagicMock

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.credential_keys import ApiKey
    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SSE_ACCEPT: Final = {"Accept": "text/event-stream"}
_CHAT_NOT_FOUND: Final = {"detail": "Chat not found", "reason": "chat_not_found"}
_NO_PENDING: Final = {"detail": "No pending confirmation for this session"}
_RUN_ACTIVE: Final = {
    "detail": "A message is already running in this chat.",
    "reason": "run_active",
}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}
_JSON: Final = "application/json"

_CONFIRMATION_ID: Final = "confirm-8-kestrel"
# Far ahead and fixed, so two runs' confirmations compare equal.
_EXPIRES_AT: Final = datetime(2099, 1, 1, tzinfo=UTC)
_EXPIRES_AT_JSON: Final = "2099-01-01T00:00:00Z"
_MESSAGE: Final = "Hello there"
_LEGACY_SESSION: Final = "legacy-8-heron"
_ECHO: Final = "echo-marker-8-osprey"
_LIMIT_REPLY: Final = "I stopped: this message reached its tool call limit."
_DENIED_RESULT: Final = "Tool call denied by the user."
_PENDING_LIMIT_REPLY: Final = (
    "Action memory.store was not run: too many confirmations are pending."
    " Approve or deny one of them first."
)

# Titles (tests/test_chat_titles_api.py's values): the raw model title and its sanitized form.
_TITLE_MESSAGE: Final = "Summarise the quarterly VAT figures"
_RAW_TITLE: Final = '"Quarterly VAT report."'
_TITLE: Final = "Quarterly VAT report"
_TITLE_MAX_TOKENS: Final = 40

_WAIT_S: Final = 5.0
# A refusal answers at once; a send that waited for the parked run would hit this bound.
_QUICK_S: Final = 3.0

# A statement on either chat table (FakeDb's normalized SQL).
_CHAT_SQL: Final = re.compile(r"\bchat(?:s|_messages)\b")
_EVENT_NAME: Final = re.compile(r"[a-zA-Z0-9_.:-]+")
# SSE line terminators (WHATWG): CRLF, a lone CR or a lone LF.
_LINE_BREAK: Final = re.compile(r"\r\n|\r|\n")
_MAX_DELTA_CHARS: Final = 4096

# The keywords the server passes to Agent.run today (JSON requests keep exactly these).
_TURN_KEYWORDS: Final = frozenset(
    {
        "user_message",
        "session_id",
        "history",
        "principal",
        "tool_policy",
        "agent_config",
        "prompt_context",
        "earlier_external_content",
    }
)
_RESUME_KEYWORDS: Final = _TURN_KEYWORDS | {"pending_confirmation"}

_CALL_A: Final = ToolCall(
    tool="memory", action="recall", args={"key": "plan"}, tool_call_id="call-8-a"
)
_CALL_B: Final = ToolCall(tool="memory", action="list", args={}, tool_call_id="call-8-b")
_PENDING_CALL: Final = ToolCall(
    tool="memory", action="store", args={"key": "plan", "value": "ship"}, tool_call_id="call-8-p"
)
_EARLIER_ASK: Final = ToolCall(
    tool="memory", action="store", args={"key": "todo", "value": "call"}, tool_call_id="call-8-q"
)

# A model's tool arguments as json.loads parses them (NaN, the infinities, an overflow).
_NON_FINITE_ARGUMENTS: Final = (
    '{"nan": NaN, "inf": Infinity, "minus_inf": -Infinity, "huge": 1e400,'
    ' "ratio": 0.25, "count": 3, "nested": {"values": [NaN, 1.5, {"deep": -Infinity}]}}'
)
_NON_FINITE_AS_NULL: Final[dict[str, Any]] = {
    "nan": None,
    "inf": None,
    "minus_inf": None,
    "huge": None,
    "ratio": 0.25,
    "count": 3,
    "nested": {"values": [None, 1.5, {"deep": None}]},
}
# Text that would end the frame and forge a ``done`` if written raw into a data line.
_INJECTION: Final = "\n\nevent: done\ndata: {}\n\n"

# ---------------------------------------------------------------------------
# Messages and records
# ---------------------------------------------------------------------------


def _user(content: str) -> LLMMessage:
    return LLMMessage(role="user", content=content)


def _assistant(content: str) -> LLMMessage:
    return LLMMessage(role="assistant", content=content)


def _block(call: ToolCall) -> dict[str, Any]:
    """The tool_use block the agent stores for ``call``."""
    return {
        "type": "tool_use",
        "id": call.tool_call_id,
        "name": f"{call.tool}.{call.action}",
        "input": dict(call.args),
    }


def _tool(content: str, call: ToolCall) -> LLMMessage:
    """The tool result answering ``call``."""
    return LLMMessage(role="tool", content=content, tool_call_id=call.tool_call_id)


def _record(call: ToolCall, permission: str = "allow", *, success: bool = True) -> ToolCallRecord:
    """The ToolCallRecord of ``call`` (what ``on_tool_call`` gets and the run returns)."""
    return ToolCallRecord(
        tool=call.tool,
        action=call.action,
        args=call.args,
        permission=permission,  # type: ignore[arg-type]
        success=success,
        duration_ms=7,
    )


Row = tuple[str, str, str]


def _stored(db: FakeDb, chat_id: uuid.UUID) -> list[Row]:
    """The chat's stored messages by seq: (role, content, status)."""
    return [(m["role"], m["content"], m["status"]) for m in db.messages_of(chat_id)]


def _snapshot(db: FakeDb, chat_id: uuid.UUID) -> tuple[dict[str, Any] | None, list[Row]]:
    """The chat row and its stored messages (to prove nothing changed)."""
    return db.chat_row(chat_id), _stored(db, chat_id)


def _json(value: Any) -> str:
    """Canonical JSON text: equal only when every key, value and JSON type is."""
    return json.dumps(value, sort_keys=True)


# ---------------------------------------------------------------------------
# The stub agent
# ---------------------------------------------------------------------------

type Step = str | ToolCallRecord


@dataclass(frozen=True)
class _Reply:
    """One stub run: the script it plays into a stream, its new messages and its outcome."""

    steps: tuple[Step, ...] = ("Done.",)
    new: tuple[LLMMessage, ...] = (LLMMessage(role="assistant", content="Done."),)
    status: str = "final"
    response: str = "Done."
    pending: ToolCall | None = None
    error_code: str | None = None
    error: Exception | None = None

    @property
    def tool_calls(self) -> list[ToolCallRecord]:
        """The run's records: the ones the script emits, in order."""
        return [step for step in self.steps if isinstance(step, ToolCallRecord)]


def _reply(
    *steps: str | ToolCall,
    ask: ToolCall | None = None,
    status: str = "final",
    closing: str | None = None,
    error_code: str | None = None,
) -> _Reply:
    """A run as the real agent stores it.

    Text pieces go to ``on_delta``; a ``ToolCall`` is an allowed dispatch: its
    record goes to ``on_tool_call`` and the run stores an assistant turn (the
    text before it, its tool_use block) and the tool result. ``ask`` ends the
    run awaiting confirmation of that call (its ``confirm`` record emitted, the
    tool_use turn stored last). ``closing`` is a reply the agent adds without
    streaming it (an error or the limit reply): stored last, the run's
    response. Otherwise the text after the last call is the stored reply.
    """
    played: list[Step] = []
    new: list[LLMMessage] = []
    text = ""
    for step in steps:
        if isinstance(step, str):
            played.append(step)
            text += step
            continue
        played.append(_record(step))
        new += [
            LLMMessage(role="assistant", content=text, tool_use_blocks=[_block(step)]),
            _tool(f"Result {step.tool_call_id}", step),
        ]
        text = ""
    if ask is not None:
        played.append(_record(ask, "confirm", success=False))
        new.append(LLMMessage(role="assistant", content=text, tool_use_blocks=[_block(ask)]))
        response = f"Action {ask.tool}.{ask.action} requires user confirmation."
        status = "awaiting_confirmation"
    elif closing is not None:
        new.append(_assistant(closing))
        response = closing
    else:
        new.append(_assistant(text))
        response = text
    return _Reply(
        steps=tuple(played),
        new=tuple(new),
        status=status,
        response=response,
        pending=ask,
        error_code=error_code,
    )


def _resumed(call: ToolCall, *text: str) -> _Reply:
    """An approved resume: the approved call's record and result, then the reply ``text``."""
    reply = "".join(text)
    return _Reply(
        steps=(_record(call, "confirm"), *text),
        new=(_tool(f"Result {call.tool_call_id}", call), _assistant(reply)),
        response=reply,
    )


@dataclass(frozen=True)
class _Run:
    """One stub run: the bound arguments, the keywords passed and the stop flag at call time."""

    user_message: str
    arguments: dict[str, Any]
    keywords: frozenset[str]
    stop_set: bool | None

    @property
    def stream(self) -> Any:
        return self.arguments["stream"]


def _run_signature(
    user_message: str,
    session_id: str,
    *,
    history: list[LLMMessage],
    principal: Any,
    tool_policy: Any,
    pending_confirmation: PendingConfirmation | None = None,
    agent_config: AgentConfig | None = None,
    prompt_context: Any = None,
    earlier_external_content: bool = False,
    stream: Any = None,
) -> None:
    """``Agent.run``'s contract signature (C3); every stub call is bound to it."""


class _Script:
    """Scripted replies for the stub agent's ``run`` and the record of every call."""

    def __init__(self) -> None:
        self.replies: list[_Reply] = []
        self.runs: list[_Run] = []
        # Awaited once, inside the next run, after its script and before it answers.
        self.during: Callable[[], Awaitable[None]] | None = None

    def queue(self, *replies: _Reply) -> None:
        self.replies.extend(replies)

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        bound = inspect.signature(_run_signature).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        stream = arguments["stream"]
        self.runs.append(
            _Run(
                user_message=arguments["user_message"],
                arguments=arguments,
                keywords=frozenset(kwargs),
                stop_set=None if stream is None else stream.stop.is_set(),
            )
        )
        reply = self.replies.pop(0) if self.replies else _Reply()
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
            base.append(_user(arguments["user_message"]))
        pending = None
        if reply.pending is not None:
            pending = PendingConfirmation(
                confirmation_id=_CONFIRMATION_ID,
                session_id=arguments["session_id"],
                tool_call=reply.pending,
                expires_at=_EXPIRES_AT,
            )
        return AgentResult(
            status=reply.status,  # type: ignore[arg-type]
            response=reply.response,
            history=[*base, *reply.new],
            tool_calls=reply.tool_calls,
            pending_confirmation=pending,
            error_code=reply.error_code,  # type: ignore[arg-type]
        )


class _TitleLLM:
    """The running client for the title call (``_running_llm_client``): records the
    ``max_tokens`` of every call and answers ``title``."""

    provider = "infomaniak"

    def __init__(self, title: str = _RAW_TITLE) -> None:
        self.title = title
        self.calls: list[int | None] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        self.calls.append(max_tokens)
        return LLMResponse(content=self.title)

    async def close(self) -> None:
        """Nothing to close."""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin, behind the fake database."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


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
# Requests
# ---------------------------------------------------------------------------


def _chat(db: FakeDb, account: Account, *, titled: bool = True) -> uuid.UUID:
    """A live chat of ``account``: user-titled (so no title step runs) unless ``titled``
    is false (untitled, ``title_source`` "auto")."""
    if titled:
        return db.add_chat(account.user_id, title="Planning 8", title_source="user")
    return db.add_chat(account.user_id)


def _send(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID | str,
    message: str = _MESSAGE,
    *,
    sse: bool = True,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account`` (streamed unless ``sse`` is false)."""
    return client.post(
        f"/api/chats/{chat_id}/messages",
        headers={**account.cookie, **(_SSE_ACCEPT if sse else {}), **(headers or {})},
        json={"message": message},
    )


def _confirm(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    *,
    approved: bool = True,
    sse: bool = True,
) -> httpx.Response:
    """POST /api/confirm/{_CONFIRMATION_ID} for the chat (streamed unless ``sse`` is false)."""
    body = {"confirmation_id": _CONFIRMATION_ID, "approved": approved, "chat_id": str(chat_id)}
    return client.post(
        f"/api/confirm/{_CONFIRMATION_ID}",
        headers={**account.cookie, **(_SSE_ACCEPT if sse else {})},
        json=body,
    )


def _with_accept(
    client: TestClient, path: str, account: Account, body: dict[str, Any], accept: str | None
) -> httpx.Response:
    """POST ``body`` to ``path`` with exactly this ``Accept`` header (None: no header at all,
    not even the client's default ``*/*``)."""
    request = client.build_request("POST", path, headers=account.cookie, json=body)
    if accept is None:
        del request.headers["Accept"]
    else:
        request.headers["Accept"] = accept
    return client.send(request)


def _detail(client: TestClient, account: Account, chat_id: uuid.UUID) -> dict[str, Any]:
    """GET /api/chats/{chat_id} as its owner (must succeed)."""
    response = client.get(f"/api/chats/{chat_id}", headers=account.cookie)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _stored_limits(monkeypatch: pytest.MonkeyPatch, **limits: int) -> None:
    """Store platform limits in the settings cache (GH-160) for the next requests."""
    stored = default_test_platform_settings()
    updated = stored.limits.model_copy(update=limits)
    monkeypatch.setattr(
        scoped_settings, "_platform_cache", stored.model_copy(update={"limits": updated})
    )


def _chat_calls(db: FakeDb, since: int) -> list[str]:
    """The SQL of every chat-table statement run after the first ``since`` calls."""
    return [call.sql for call in db.calls[since:] if _CHAT_SQL.search(call.normalized)]


def _pending_id(chat_id: uuid.UUID) -> str | None:
    """The confirmation id the server's runtime keeps for the chat, or None."""
    pending = server._chat_runtime.get_pending(uuid.UUID(str(chat_id)))
    return None if pending is None else pending.confirmation_id


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the httpx client lines, which name request URLs)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


# ---------------------------------------------------------------------------
# Reading a stream
# ---------------------------------------------------------------------------

Frame = tuple[str, dict[str, Any]]


def _refuse_constant(name: str) -> Any:
    """``json.loads``'s hook for NaN / Infinity / -Infinity: not JSON, so refused."""
    msg = f"non-standard JSON constant {name} in an SSE payload"
    raise ValueError(msg)


def _payload(data: str) -> dict[str, Any]:
    """One frame's data: strict JSON (no NaN or Infinity literal), an object."""
    payload = json.loads(data, parse_constant=_refuse_constant)
    assert isinstance(payload, dict), data
    return payload


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
                frames.append((event, _payload(data[0])))
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
            assert set(payload) == {"text"}, payload
            assert 0 < len(payload["text"]) <= _MAX_DELTA_CHARS, payload
    return frames


def _names(frames: list[Frame]) -> list[str]:
    return [name for name, _ in frames]


def _deltas(frames: list[Frame]) -> list[str]:
    """The texts of the delta frames, in order."""
    return [payload["text"] for name, payload in frames if name == "delta"]


def _of(frames: list[Frame], event: str) -> list[dict[str, Any]]:
    """The payloads of every ``event`` frame, in order."""
    return [payload for name, payload in frames if name == event]


def _started(chat_id: uuid.UUID) -> Frame:
    return ("run_started", {"chat_id": str(chat_id)})


def _delta(text: str) -> Frame:
    return ("delta", {"text": text})


def _tool_call(record: ToolCallRecord) -> Frame:
    return ("tool_call", record.model_dump(mode="json"))


def _saved(db: FakeDb, chat_id: uuid.UUID, status: str) -> Frame:
    """``message_saved`` naming the chat's last stored message (read now) with ``status``."""
    last = db.messages_of(chat_id)[-1]
    return ("message_saved", {"message_id": str(plain(last["id"])), "status": status})


def _error(code: str, message: str) -> Frame:
    return ("error", {"code": code, "message": message})


_DONE: Final[Frame] = ("done", {})


def _mode(response: httpx.Response) -> str:
    """The answer's mode: sse (a streamed 200), json (today's ChatResponse) or its status."""
    content_type = response.headers.get("content-type", "")
    if response.status_code == 200 and content_type.startswith("text/event-stream"):
        return "sse"
    if response.status_code == 200 and content_type == _JSON and "chat_id" in response.json():
        return "json"
    return f"status-{response.status_code}"


# ---------------------------------------------------------------------------
# Concurrency helpers
# ---------------------------------------------------------------------------


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the caller's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50008))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _until(condition: Callable[[], bool]) -> None:
    """Yield to the event loop until ``condition()`` holds (at most ``_WAIT_S`` seconds)."""

    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(poll(), _WAIT_S)


@dataclass
class _Parked:
    """A first request whose run is parked: the client, its task and the release event."""

    http: httpx.AsyncClient
    first: asyncio.Task[httpx.Response]
    release: asyncio.Event


@contextlib.asynccontextmanager
async def _parked(
    app: FastAPI,
    script: _Script,
    first: Callable[[httpx.AsyncClient], Awaitable[httpx.Response]],
) -> AsyncIterator[_Parked]:
    """Send ``first``; yield once its run is parked (after its script, inside the chat's
    run slot). On exit the run is released and the first request awaited (bounded)."""
    parked, release = asyncio.Event(), asyncio.Event()

    async def park() -> None:
        parked.set()
        await asyncio.wait_for(release.wait(), _WAIT_S)

    script.during = park
    async with _async_client(app) as http:
        task = asyncio.create_task(first(http))
        try:
            await asyncio.wait_for(parked.wait(), _WAIT_S)
            yield _Parked(http=http, first=task, release=release)
        finally:
            release.set()
            await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), _WAIT_S)


def _watched_runtime(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Swap in a real ``ChatRuntime`` that records every ``hold()`` call when it is made,
    i.e. before the caller waits for the chat's lock (any keyword passed through)."""
    from admino.chat_runtime import ChatRuntime

    class _Watched(ChatRuntime):
        def __init__(self) -> None:
            super().__init__(max_entries=64, idle_s=900.0)
            self.holds: list[uuid.UUID] = []

        def hold(self, chat_id: uuid.UUID, owner_user_id: uuid.UUID, **kwargs: Any) -> Any:
            self.holds.append(chat_id)
            return super().hold(chat_id, owner_user_id, **kwargs)

    runtime = _Watched()
    monkeypatch.setattr(server, "_chat_runtime", runtime)
    return runtime


async def _post_turn(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID, message: str, *, sse: bool
) -> httpx.Response:
    return await http.post(
        f"/api/chats/{chat_id}/messages",
        headers={**account.cookie, **(_SSE_ACCEPT if sse else {})},
        json={"message": message},
    )


async def _post_legacy(http: httpx.AsyncClient, account: Account, message: str) -> httpx.Response:
    return await http.post(
        "/api/message",
        headers=account.cookie,
        json={"message": message, "session_id": _LEGACY_SESSION},
    )


async def _post_approval(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID
) -> httpx.Response:
    body = {"confirmation_id": _CONFIRMATION_ID, "approved": True, "chat_id": str(chat_id)}
    return await http.post(
        f"/api/confirm/{_CONFIRMATION_ID}",
        headers={**account.cookie, **_SSE_ACCEPT},
        json=body,
    )


# ---------------------------------------------------------------------------
# 1. Negotiation (C5.1)
# ---------------------------------------------------------------------------

_STREAM_ACCEPTS: Final = (
    "text/event-stream",
    "text/event-stream, application/json",
    "application/json, text/event-stream",
    "TEXT/Event-Stream",
    "text/event-stream; charset=utf-8",
    "text/event-stream;q=0.5",
)
_JSON_ACCEPTS: Final = (None, "*/*", "application/json", "text/html", "text/event-stream;q=0")
_EXPECTED_MODES: Final = {
    **dict.fromkeys(_STREAM_ACCEPTS, "sse"),
    **dict.fromkeys(_JSON_ACCEPTS, "json"),
}


def test_chat_stream_accept_header_picks_the_mode_of_the_turn_route(
    world: World, client: TestClient
) -> None:
    """Each Accept value on a fresh chat: a listed ``text/event-stream`` (any position,
    any case, parameters ignored, q above 0) streams; anything else is today's JSON."""
    editor = world.a["editor"]
    modes: dict[str | None, str] = {}

    for accept in _EXPECTED_MODES:
        path = f"/api/chats/{_chat(world.db, editor)}/messages"
        response = _with_accept(client, path, editor, {"message": _MESSAGE}, accept)
        modes[accept] = _mode(response)

    assert modes == _EXPECTED_MODES


def test_chat_stream_accept_header_picks_the_mode_of_the_confirm_route(
    world: World, client: TestClient, script: _Script
) -> None:
    """The same Accept values on POST /api/confirm/{id}, each approving a fresh chat's
    pending confirmation (kept by a JSON turn)."""
    editor = world.a["editor"]
    modes: dict[str | None, str] = {}

    for accept in _EXPECTED_MODES:
        chat_id = _chat(world.db, editor)
        script.queue(_reply(ask=_PENDING_CALL), _resumed(_PENDING_CALL, "Saved."))
        asked = _send(client, editor, chat_id, sse=False)
        assert asked.json()["status"] == "awaiting_confirmation", asked.text
        body = {"confirmation_id": _CONFIRMATION_ID, "approved": True, "chat_id": str(chat_id)}
        response = _with_accept(client, f"/api/confirm/{_CONFIRMATION_ID}", editor, body, accept)
        modes[accept] = _mode(response)

    assert modes == _EXPECTED_MODES


def test_chat_stream_legacy_message_route_answers_json_to_an_event_stream_accept(
    world: World, client: TestClient, script: _Script
) -> None:
    """POST /api/message stays JSON-only (until #177): ``Accept: text/event-stream`` gets
    the ChatResponse and the run no stream; the same header on the chat route streams."""
    editor = world.a["editor"]

    legacy = client.post(
        "/api/message",
        headers={**editor.cookie, **_SSE_ACCEPT},
        json={"message": _MESSAGE, "session_id": _LEGACY_SESSION},
    )

    assert (legacy.status_code, legacy.headers["content-type"]) == (200, _JSON), legacy.text
    assert legacy.json()["session_id"] == _LEGACY_SESSION
    assert script.runs[0].keywords == _TURN_KEYWORDS
    streamed = _stream(_send(client, editor, _chat(world.db, editor)))
    assert _names(streamed)[0] == "run_started"


def test_chat_stream_response_headers_on_both_routes(
    world: World, client: TestClient, script: _Script
) -> None:
    """A streamed turn and a streamed approval: 200, ``text/event-stream; charset=utf-8``,
    ``cache-control: no-cache``, ``x-accel-buffering: no``."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_reply(ask=_PENDING_CALL))

    turn = _send(client, editor, chat_id)
    approval = _confirm(client, editor, chat_id)

    for response in (turn, approval):
        assert response.status_code == 200, response.text
        headers = response.headers
        assert (
            headers.get("content-type"),
            headers.get("cache-control"),
            headers.get("x-accel-buffering"),
        ) == ("text/event-stream; charset=utf-8", "no-cache", "no")


# ---------------------------------------------------------------------------
# 2. What the agent gets (C3)
# ---------------------------------------------------------------------------


def test_chat_stream_only_a_streamed_turn_passes_a_run_stream(
    world: World, client: TestClient, script: _Script
) -> None:
    """A JSON turn passes exactly today's keywords (no ``stream``); a streamed turn adds
    ``stream``: a ``RunStream`` whose ``stop`` isn't set when the run starts."""
    from admino.streaming import RunStream

    editor = world.a["editor"]

    as_json = _send(client, editor, _chat(world.db, editor), sse=False)
    streamed = _send(client, editor, _chat(world.db, editor))

    assert as_json.status_code == 200, as_json.text
    assert _names(_stream(streamed))[-1] == "done"
    json_run, sse_run = script.runs
    assert (json_run.keywords, json_run.stream) == (_TURN_KEYWORDS, None)
    assert sse_run.keywords == _TURN_KEYWORDS | {"stream"}
    assert isinstance(sse_run.stream, RunStream)
    assert sse_run.stop_set is False


def test_chat_stream_only_a_streamed_approval_passes_a_run_stream(
    world: World, client: TestClient, script: _Script
) -> None:
    """The approve path: a JSON approval resumes with today's keywords, a streamed one adds
    a ``RunStream`` (stop not set)."""
    from admino.streaming import RunStream

    editor = world.a["editor"]
    json_chat, sse_chat = _chat(world.db, editor), _chat(world.db, editor)
    script.queue(_reply(ask=_PENDING_CALL), _reply(ask=_PENDING_CALL))
    for chat_id in (json_chat, sse_chat):
        assert _send(client, editor, chat_id, sse=False).json()["status"] == (
            "awaiting_confirmation"
        )

    as_json = _confirm(client, editor, json_chat, sse=False)
    streamed = _confirm(client, editor, sse_chat)

    assert as_json.status_code == 200, as_json.text
    assert _names(_stream(streamed))[-1] == "done"
    json_resume, sse_resume = script.runs[2:]
    assert (json_resume.keywords, json_resume.stream) == (_RESUME_KEYWORDS, None)
    assert sse_resume.keywords == _RESUME_KEYWORDS | {"stream"}
    assert isinstance(sse_resume.stream, RunStream)
    assert sse_resume.stop_set is False


# ---------------------------------------------------------------------------
# 3. Refusals before the run are the usual JSON errors (C5.1)
# ---------------------------------------------------------------------------

_REFUSALS: Final = (
    "no_session",
    "cross_site",
    "viewer",
    "super_admin",
    "extra_field",
    "over_stored_length",
    "non_uuid_id",
    "unknown_chat",
    "other_org_chat",
    "colleague_chat",
    "trashed_chat",
)


@pytest.mark.parametrize("case", _REFUSALS)
def test_chat_stream_refusal_before_the_run_is_the_usual_json_error(
    world: World,
    client: TestClient,
    agent: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    """With ``Accept: text/event-stream`` the refusal is the JSON error it is without the
    header (same status and body, ``application/json``, the input never echoed): no run,
    nothing stored, and for a Viewer or a Super Admin no chat statement. The Editor's
    valid streamed send to their own chat then streams (the refusal is the gate's)."""
    editor = world.a["editor"]
    db = world.db
    own = _chat(db, editor)
    headers: dict[str, str] = dict(editor.cookie)
    target: object = own
    body: dict[str, Any] = {"message": "Go on"}
    expected: tuple[int, Any]
    if case == "no_session":
        headers, expected = {}, (401, UNAUTHORIZED)
    elif case == "cross_site":
        headers["Sec-Fetch-Site"] = "cross-site"
        expected = (403, _CSRF_REFUSED)
    elif case == "viewer":
        viewer = world.a["viewer"]
        headers, target, expected = dict(viewer.cookie), _chat(db, viewer), (403, FORBIDDEN)
    elif case == "super_admin":
        headers, expected = dict(world.super_admin.cookie), (403, FORBIDDEN)
    elif case == "extra_field":
        body, expected = {"message": "Go on", "org_id": _ECHO}, (422, None)
    elif case == "over_stored_length":
        _stored_limits(monkeypatch, max_message_length=10)
        body = {"message": _ECHO}
        expected = (422, {"detail": "Message exceeds maximum length of 10 characters"})
    elif case == "non_uuid_id":
        target, expected = _ECHO, (422, None)
    else:
        if case == "unknown_chat":
            target = uuid.uuid4()
        elif case == "other_org_chat":
            target = _chat(db, world.b["editor"])
        elif case == "colleague_chat":
            target = _chat(db, world.a["org_admin"])
        else:
            target = db.add_chat(editor.user_id, deleted_at=datetime.now(UTC))
        expected = (404, _CHAT_NOT_FOUND)
    path = f"/api/chats/{target}/messages"
    message_count = len(db.chat_messages)
    before = len(db.calls)

    as_json = client.post(path, headers=headers, json=body)
    streamed = client.post(path, headers={**headers, **_SSE_ACCEPT}, json=body)

    assert (streamed.status_code, streamed.json()) == (as_json.status_code, as_json.json())
    assert streamed.status_code == expected[0], streamed.text
    if expected[1] is not None:
        assert streamed.json() == expected[1]
    assert streamed.headers["content-type"] == _JSON
    assert _ECHO not in streamed.text
    detail = streamed.json()["detail"]
    if isinstance(detail, list):
        assert all("input" not in error for error in detail)
    assert agent.run.await_count == 0
    assert len(db.chat_messages) == message_count
    if case in ("viewer", "super_admin"):
        assert _chat_calls(db, before) == []
    assert _names(_stream(_send(client, editor, own, "Go on")))[0] == "run_started"


def test_chat_stream_rate_limited_send_is_the_json_429(
    world: World, client: TestClient, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-user ``/api/message`` bucket (burst 1): the first streamed send streams,
    the next one is the JSON 429 with no run."""
    monkeypatch.setitem(server._RATE_LIMITS, "/api/message", (0.0001, 1))
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)

    first = _send(client, editor, chat_id)
    refused = _send(client, editor, chat_id)

    assert _names(_stream(first))[0] == "run_started"
    assert (refused.status_code, refused.json(), refused.headers["content-type"]) == (
        429,
        _RATE_LIMITED,
        _JSON,
    )
    assert agent.run.await_count == 1


def test_chat_stream_confirm_with_nothing_pending_is_the_json_404(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """A streamed confirm of a chat without a pending confirmation: today's JSON 404, no
    run; once the chat holds one, the streamed approval streams."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)

    as_json = _confirm(client, editor, chat_id, sse=False)
    streamed = _confirm(client, editor, chat_id)

    assert (streamed.status_code, streamed.json(), streamed.headers["content-type"]) == (
        404,
        _NO_PENDING,
        _JSON,
    )
    assert as_json.json() == streamed.json()
    assert agent.run.await_count == 0
    script.queue(_reply(ask=_PENDING_CALL), _resumed(_PENDING_CALL, "Saved."))
    assert _send(client, editor, chat_id, sse=False).json()["status"] == "awaiting_confirmation"
    assert _names(_stream(_confirm(client, editor, chat_id)))[0] == "run_started"


# ---------------------------------------------------------------------------
# 4. Frames per outcome (C5.3)
# ---------------------------------------------------------------------------


def test_chat_stream_final_turn_streams_its_text_word_by_word(
    world: World, client: TestClient, script: _Script
) -> None:
    """Pieces "Hello ", "wor", "ld. How ", "are you?": each delta ends after a whitespace
    (a word waits for the whitespace after it), the rest is flushed at the end;
    ``message_saved`` names the stored reply (complete). The deltas equal the reply as
    GET /api/chats/{id} shows it."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_reply("Hello ", "wor", "ld. How ", "are you?"))

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _delta("Hello "),
        _delta("world. How "),
        _delta("are "),
        _delta("you?"),
        _saved(world.db, chat_id, "complete"),
        _DONE,
    ]
    shown = _detail(client, editor, chat_id)["messages"][-1]
    assert (shown["role"], shown["content"]) == ("assistant", "".join(_deltas(frames)))


def test_chat_stream_tool_turn_interleaves_deltas_and_tool_calls(
    world: World, client: TestClient, script: _Script
) -> None:
    """Text, a tool call, text: the held word "now" is flushed before the ``tool_call``;
    the deltas after it equal the stored reply; the record sits on the last message."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_reply("Checking ", "now", _CALL_A, "Here ", "it is."))

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _delta("Checking "),
        _delta("now"),
        _tool_call(_record(_CALL_A)),
        _delta("Here "),
        _delta("it "),
        _delta("is."),
        _saved(world.db, chat_id, "complete"),
        _DONE,
    ]
    shown = _detail(client, editor, chat_id)["messages"][-1]
    assert shown["content"] == "Here it is."
    assert shown["tool_calls"] == [_record(_CALL_A).model_dump(mode="json")]


def test_chat_stream_kept_confirmation_sends_confirm_before_message_saved(
    world: World, client: TestClient, script: _Script
) -> None:
    """A run asking to confirm memory.store: its text, the ``confirm`` record's
    ``tool_call``, ``confirm`` (the pending confirmation's JSON), ``message_saved``
    (awaiting_confirmation), ``done``; the "requires user confirmation" response is never
    a delta. The chat then shows the confirmation pending."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_reply("I will store it. ", ask=_PENDING_CALL))

    response = _send(client, editor, chat_id)

    frames = _stream(response)
    assert frames == [
        _started(chat_id),
        _delta("I will store it. "),
        _tool_call(_record(_PENDING_CALL, "confirm", success=False)),
        (
            "confirm",
            {
                "confirmation_id": _CONFIRMATION_ID,
                "tool": "memory",
                "action": "store",
                "args": {"key": "plan", "value": "ship"},
                "expires_at": _EXPIRES_AT_JSON,
            },
        ),
        _saved(world.db, chat_id, "awaiting_confirmation"),
        _DONE,
    ]
    assert "requires user confirmation" not in response.text
    assert _detail(client, editor, chat_id)["confirmation_status"] == "pending"


def test_chat_stream_pending_limit_refusal_sends_error_rate_limit(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GH-24: the Editor already holds the stored ``max_pending_confirmations`` (1) in
    another chat. The run's confirmation is refused: no ``confirm``,
    ``message_saved{error}`` naming the stored refusal reply, then ``error{rate_limit}``
    with that reply; nothing is kept for the chat."""
    _stored_limits(monkeypatch, max_pending_confirmations=1)
    editor = world.a["editor"]
    elsewhere = _chat(world.db, editor)
    seed_pending_confirmation(editor, elsewhere, "confirm-8-elsewhere")
    chat_id = _chat(world.db, editor)
    script.queue(_reply(ask=_PENDING_CALL))

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _tool_call(_record(_PENDING_CALL, "confirm", success=False)),
        _saved(world.db, chat_id, "error"),
        _error("rate_limit", _PENDING_LIMIT_REPLY),
        _DONE,
    ]
    assert _stored(world.db, chat_id)[-1] == ("assistant", _PENDING_LIMIT_REPLY, "error")
    assert (_pending_id(chat_id), _pending_id(elsewhere)) == (None, "confirm-8-elsewhere")


@pytest.mark.parametrize(
    ("code", "steps"),
    [
        ("rate_limited", ("Partial answer ",)),
        ("residency_blocked", ()),
        (None, ("Partial answer ",)),
    ],
    ids=["rate_limited", "residency_blocked", "uncoded"],
)
def test_chat_stream_failed_run_sends_message_saved_then_error(
    world: World, client: TestClient, script: _Script, code: str | None, steps: tuple[str, ...]
) -> None:
    """A run ending ``error``: the deltas already sent stay; ``message_saved{error}``
    names the stored error reply; ``error`` carries the run's ``error_code`` (an uncoded
    failure: ``internal_error``) and the run's reply. ``residency_blocked`` ends before
    any delta."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    failure = "The model is not available right now."
    script.queue(_reply(*steps, status="error", closing=failure, error_code=code))

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        *(_delta(step) for step in steps),
        _saved(world.db, chat_id, "error"),
        _error(code or "internal_error", failure),
        _DONE,
    ]
    assert _stored(world.db, chat_id)[-1] == ("assistant", failure, "error")


def test_chat_stream_limit_reached_sends_the_limit_reply_as_one_delta(
    world: World, client: TestClient, script: _Script
) -> None:
    """A run that reached its tool call limit: its streamed text and tool call, then ONE
    delta with the limit reply (the agent adds it without streaming), then
    ``message_saved{limit_reached}``."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_reply("Looking ", _CALL_A, status="limit_reached", closing=_LIMIT_REPLY))

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _delta("Looking "),
        _tool_call(_record(_CALL_A)),
        _delta(_LIMIT_REPLY),
        _saved(world.db, chat_id, "limit_reached"),
        _DONE,
    ]


def test_chat_stream_stopped_run_is_saved_as_stopped(
    world: World, client: TestClient, script: _Script
) -> None:
    """A run that ended ``stopped`` with partial text: its deltas, then
    ``message_saved{stopped}`` naming the stored partial reply (status ``stopped``)."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_reply("Partial ", "answer ", status="stopped"))

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _delta("Partial "),
        _delta("answer "),
        _saved(world.db, chat_id, "stopped"),
        _DONE,
    ]
    assert _stored(world.db, chat_id)[-1] == ("assistant", "Partial answer ", "stopped")


def test_chat_stream_agent_failure_sends_internal_error_and_stores_nothing(
    world: World, client: TestClient, script: _Script
) -> None:
    """The agent raises after a delta (JSON: the 500): ``error{internal_error, "Internal
    error"}``, then ``done``; no ``message_saved``, nothing stored, the exception text
    nowhere in the stream."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    world.db.add_chat_message(chat_id, "user", "Earlier question")
    before = _snapshot(world.db, chat_id)
    script.queue(_Reply(steps=("Partial ",), error=RuntimeError("agent failure 8 heron")))

    response = _send(client, editor, chat_id)

    assert _stream(response) == [
        _started(chat_id),
        _delta("Partial "),
        _error("internal_error", "Internal error"),
        _DONE,
    ]
    assert "agent failure 8 heron" not in response.text
    assert _snapshot(world.db, chat_id) == before


def test_chat_stream_chat_trashed_during_the_run_sends_chat_not_found(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """The chat is trashed while the run is in flight (JSON: the 404):
    ``error{chat_not_found, "Chat not found"}``, then ``done``; nothing stored."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    db.add_chat_message(chat_id, "user", "Earlier question")

    async def trash() -> None:
        db.chats[uuid.UUID(int=chat_id.int)]["deleted_at"] = datetime.now(UTC)

    script.during = trash
    script.queue(_Reply(steps=()))

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [_started(chat_id), _error("chat_not_found", "Chat not found"), _DONE]
    assert agent.run.await_count == 1
    assert _stored(db, chat_id) == [("user", "Earlier question", "complete")]


# ---------------------------------------------------------------------------
# 5. Payloads equal the JSON response's (C5.3 invariants)
# ---------------------------------------------------------------------------


def test_chat_stream_tool_call_and_confirm_payloads_equal_the_json_response(
    world: World, client: TestClient, script: _Script
) -> None:
    """The same scripted run (two allowed calls, then one to confirm) once as JSON and
    once streamed, on two chats: the ``tool_call`` payloads are the JSON ``tool_calls``
    in order and ``confirm`` is the JSON ``pending_confirmation``."""
    editor = world.a["editor"]
    run = _reply(_CALL_A, "Listing ", _CALL_B, ask=_PENDING_CALL)
    script.queue(run, run)

    as_json = _send(client, editor, _chat(world.db, editor), sse=False)
    frames = _stream(_send(client, editor, _chat(world.db, editor)))

    assert as_json.status_code == 200, as_json.text
    body = as_json.json()
    assert len(body["tool_calls"]) == 3
    assert _of(frames, "tool_call") == body["tool_calls"]
    assert _of(frames, "confirm") == [body["pending_confirmation"]]


def test_chat_stream_non_finite_tool_arguments_are_null_in_tool_call(
    world: World, client: TestClient, script: _Script
) -> None:
    """A record whose arguments hold NaN, the infinities and 1e400, nested too: the
    ``tool_call`` data is strict JSON (no NaN/Infinity literal) with null in place of
    each, every finite value with its JSON type, equal to the JSON response's record."""
    editor = world.a["editor"]
    call = ToolCall(
        tool="memory",
        action="recall",
        args=json.loads(_NON_FINITE_ARGUMENTS),
        tool_call_id="call-8-nf",
    )
    run = _reply(call, "Not found.")
    script.queue(run, run)

    as_json = _send(client, editor, _chat(world.db, editor), sse=False)
    frames = _stream(_send(client, editor, _chat(world.db, editor)))

    assert as_json.status_code == 200, as_json.text
    (payload,) = _of(frames, "tool_call")
    assert _json(payload["args"]) == _json(_NON_FINITE_AS_NULL)
    assert _json(payload) == _json(as_json.json()["tool_calls"][0])


# ---------------------------------------------------------------------------
# 6. Display deltas end to end (C2, decision 4)
# ---------------------------------------------------------------------------


def test_chat_stream_split_credentials_never_stream_in_part(
    world: World, client: TestClient, script: _Script
) -> None:
    """An OpenAI project key split inside its body, an Anthropic key split inside its
    prefix and a ``Bearer`` token whose word ``Bearer`` ends one piece: no frame holds
    any of them, whole or in part (any 8 characters of a body); the deltas equal the
    redacted reply GET /api/chats/{id} shows."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    openai, anthropic = openai_project_key(), anthropic_api03_key()
    token = api_key("", 40, seed=8)
    script.queue(
        _reply(
            "My key is " + openai.text[:60],
            openai.text[60:] + " and " + anthropic.text[:5],
            anthropic.text[5:] + ", send it with Bearer ",
            token.text + " please.",
        )
    )

    response = _send(client, editor, chat_id)

    frames = _stream(response)
    redacted = (
        "My key is [CREDENTIAL_REDACTED] and [CREDENTIAL_REDACTED],"
        " send it with [CREDENTIAL_REDACTED] please."
    )
    assert "".join(_deltas(frames)) == redacted
    assert _detail(client, editor, chat_id)["messages"][-1]["content"] == redacted
    for key in (openai, anthropic, token):
        assert key.text not in response.text
        assert surviving_chunks(response.text, key) == []


def test_chat_stream_held_text_is_flushed_before_a_tool_call(
    world: World, client: TestClient, script: _Script
) -> None:
    """The word "up" (no whitespace after it yet) is sent before the ``tool_call``, not
    held past it; the text after the call starts a new answer."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_reply("Let me look that up", _CALL_A, "Found it."))

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _delta("Let me look that "),
        _delta("up"),
        _tool_call(_record(_CALL_A)),
        _delta("Found "),
        _delta("it."),
        _saved(world.db, chat_id, "complete"),
        _DONE,
    ]


# ---------------------------------------------------------------------------
# 6b. A cut answer drops its unfinished last word (C11, audit core L-1)
# ---------------------------------------------------------------------------

_KEPT: Final = "Here is the key "


def _cut(text: str) -> str:
    """C11: ``text`` up to and including its last ASCII whitespace ("" when none)."""
    return text[: max(text.rfind(char) for char in " \t\n\r") + 1]


def _cut_key() -> tuple[ApiKey, str]:
    """A GitHub fine-grained token (realistic length == the rule's minimum) and its text
    one character short: the display redaction doesn't match that, so an answer cut
    there would show 81 of its 82 body characters if the cut word were sent (L-1)."""
    key = GITHUB_FINE_GRAINED.key()
    cut = key.text[:-1]
    assert surviving_chunks(sanitize_display_text(cut), key), "fixture: shown when uncut"
    return key, cut


def _stopped_reply(*steps: str | ToolCall) -> _Reply:
    """A run stopped during its last LLM call, as the agent returns it (C11): the text
    after its last call is cut after its last ASCII whitespace, and stored as the
    assistant reply only when that leaves text."""
    played = _reply(*steps, status="stopped")
    reply = _cut(played.response)
    kept = (*played.new[:-1], *((_assistant(reply),) if reply else ()))
    return replace(played, new=kept, response=reply)


def _stop_during(script: _Script) -> None:
    """Set the run's stop signal once its script played (what POST /stop does)."""

    async def stop() -> None:
        script.runs[-1].stream.stop.set()

    script.during = stop


def _trash_during(script: _Script, db: FakeDb, chat_id: uuid.UUID) -> None:
    """Trash the chat once the run's script played (the chat is gone when it is stored)."""

    async def trash() -> None:
        db.chats[uuid.UUID(int=chat_id.int)]["deleted_at"] = datetime.now(UTC)

    script.during = trash


def test_chat_stream_stopped_run_inside_a_key_streams_and_stores_no_part_of_it(
    world: World, client: TestClient, script: _Script
) -> None:
    """Stopped while the answer's last word is a key one character short (split across
    deltas): no frame holds any 8 characters of its body; the deltas are the kept text,
    equal to the stored reply as GET /api/chats/{id} shows it (flush(complete=False))."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    key, cut = _cut_key()
    script.queue(_stopped_reply(_KEPT, cut[:20], cut[20:]))
    _stop_during(script)

    response = _send(client, editor, chat_id)

    frames = _stream(response)
    assert frames == [
        _started(chat_id),
        _delta(_KEPT),
        _saved(world.db, chat_id, "stopped"),
        _DONE,
    ]
    assert surviving_chunks(response.text, key) == []
    shown = _detail(client, editor, chat_id)["messages"][-1]
    assert (shown["role"], shown["content"]) == ("assistant", "".join(_deltas(frames)))


@pytest.mark.parametrize("outcome", ["error", "exception", "chat-trashed"])
def test_chat_stream_failed_run_after_a_cut_key_streams_no_part_of_it(
    world: World, client: TestClient, script: _Script, outcome: str
) -> None:
    """Deltas ending inside a key, then the run ends ``error``, the agent raises, or the
    chat is trashed during the run: the unfinished word is dropped
    (flush(complete=False)); no frame holds any 8 characters of the key's body."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    key, cut = _cut_key()
    steps = (_KEPT, cut[:20], cut[20:])
    failure = "The model is not available right now."
    if outcome == "error":
        script.queue(
            _reply(*steps, status="error", closing=failure, error_code="provider_unavailable")
        )
    elif outcome == "exception":
        script.queue(_Reply(steps=steps, error=RuntimeError("agent failure 8 heron")))
    else:
        script.queue(_reply(*steps))
        _trash_during(script, db, chat_id)

    response = _send(client, editor, chat_id)

    frames = _stream(response)
    if outcome == "error":
        ending = [_saved(db, chat_id, "error"), _error("provider_unavailable", failure)]
    elif outcome == "exception":
        ending = [_error("internal_error", "Internal error")]
    else:
        ending = [_error("chat_not_found", "Chat not found")]
    assert frames == [_started(chat_id), _delta(_KEPT), *ending, _DONE]
    assert surviving_chunks(response.text, key) == []


def test_chat_stream_end_of_run_sends_or_drops_the_unfinished_word_by_outcome(
    world: World, client: TestClient, script: _Script
) -> None:
    """The same answer "The answer is forty-two" (no whitespace after its last word)
    under every outcome, one chat each: a ``final`` and a ``limit_reached`` run are
    complete, their last word is sent (flush(complete=True)); a ``stopped`` or ``error``
    run, an agent that raised and a chat trashed during the run cut it."""
    editor = world.a["editor"]
    db = world.db
    answer = ("The answer is ", "forty-two")
    failure = "The model is not available right now."

    def prepare(outcome: str, chat_id: uuid.UUID) -> None:
        if outcome == "final":
            script.queue(_reply(*answer))
        elif outcome == "limit_reached":
            script.queue(
                _reply("Looking ", _CALL_A, *answer, status="limit_reached", closing=_LIMIT_REPLY)
            )
        elif outcome == "stopped":
            script.queue(_stopped_reply(*answer))
            _stop_during(script)
        elif outcome == "error":
            script.queue(_reply(*answer, status="error", closing=failure, error_code="timeout"))
        elif outcome == "exception":
            script.queue(_Reply(steps=answer, error=RuntimeError("agent failure 8 heron")))
        else:
            script.queue(_reply(*answer))
            _trash_during(script, db, chat_id)

    sent: dict[str, list[str]] = {}
    for outcome in ("final", "limit_reached", "stopped", "error", "exception", "chat-trashed"):
        chat_id = _chat(db, editor)
        prepare(outcome, chat_id)
        sent[outcome] = _deltas(_stream(_send(client, editor, chat_id)))

    complete = ["The answer is ", "forty-two"]
    assert sent == {
        "final": complete,
        "limit_reached": ["Looking ", *complete, _LIMIT_REPLY],
        "stopped": ["The answer is "],
        "error": ["The answer is "],
        "exception": ["The answer is "],
        "chat-trashed": ["The answer is "],
    }


def test_chat_stream_stopped_run_sends_the_word_before_a_tool_call_and_cuts_only_the_last(
    world: World, client: TestClient, script: _Script
) -> None:
    """A stopped run whose first call's text ends without whitespace before a tool call:
    that word is sent before the ``tool_call`` (flush(complete=True): the call's answer
    was complete), only the interrupted call's unfinished word is dropped, and the
    deltas after the ``tool_call`` equal the stored reply."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_stopped_reply("Let me look that up", _CALL_A, "Found it and mor"))
    _stop_during(script)

    frames = _stream(_send(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _delta("Let me look that "),
        _delta("up"),
        _tool_call(_record(_CALL_A)),
        _delta("Found it and "),
        _saved(world.db, chat_id, "stopped"),
        _DONE,
    ]
    shown = _detail(client, editor, chat_id)["messages"][-1]
    assert shown["content"] == "Found it and "


# ---------------------------------------------------------------------------
# 7. Frame injection (C5.2)
# ---------------------------------------------------------------------------


def test_chat_stream_frame_injection_in_deltas_and_tool_arguments_stays_in_its_frame(
    world: World, client: TestClient, script: _Script
) -> None:
    """Deltas and tool arguments holding a blank line plus forged ``event: done`` /
    ``data:`` lines, CRLF and U+2028: a client reads exactly the frames sent (one
    ``done``, last), the deltas are the display text of the pieces and the
    ``tool_call`` payload equals the JSON response's record, arguments intact."""
    editor = world.a["editor"]
    separator = chr(0x2028)
    args = {"note": _INJECTION, "crlf": "x\r\ny", "separator": f"u{separator}v"}
    call = ToolCall(tool="memory", action="recall", args=args, tool_call_id="call-8-inj")
    pieces = ("Look:" + _INJECTION, f"a\r\nb{separator}c ", "end.")
    run = _reply(*pieces, call, "Fine.")
    script.queue(run, run)

    as_json = _send(client, editor, _chat(world.db, editor), sse=False)
    frames = _stream(_send(client, editor, _chat(world.db, editor)))

    assert _names(frames) == [
        "run_started",
        "delta",
        "delta",
        "delta",
        "tool_call",
        "delta",
        "message_saved",
        "done",
    ]
    before_call = "".join(_deltas(frames)[:3])
    assert before_call == sanitize_display_text("".join(pieces))
    assert before_call == f"Look:{_INJECTION}a\r\nbc end."
    (payload,) = _of(frames, "tool_call")
    assert payload["args"] == args
    assert payload == as_json.json()["tool_calls"][0]


# ---------------------------------------------------------------------------
# 8. One active run per chat (C5.5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("first_mode", ["sse", "json"])
async def test_chat_stream_send_while_the_chats_run_is_parked_gets_409_run_active(
    world: World, agent: MagicMock, script: _Script, first_mode: str
) -> None:
    """While a turn of the chat (streamed or JSON) is parked in its run, a JSON and a
    streamed send both answer at once ``409 run_active`` (JSON), with no run; nothing of
    them is stored. Once the first turn ended, a send runs."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    app = make_app(agent)

    async with _parked(
        app,
        script,
        lambda http: _post_turn(http, editor, chat_id, "first", sse=first_mode == "sse"),
    ) as parked:
        as_json = await asyncio.wait_for(
            _post_turn(parked.http, editor, chat_id, "second", sse=False), _QUICK_S
        )
        streamed = await asyncio.wait_for(
            _post_turn(parked.http, editor, chat_id, "third", sse=True), _QUICK_S
        )
        while_parked = [run.user_message for run in script.runs]

    for refused in (as_json, streamed):
        assert (refused.status_code, refused.json(), refused.headers["content-type"]) == (
            409,
            _RUN_ACTIVE,
            _JSON,
        )
    assert while_parked == ["first"]
    assert parked.first.result().status_code == 200
    assert _stored(world.db, chat_id) == [
        ("user", "first", "complete"),
        ("assistant", "Done.", "complete"),
    ]
    async with _async_client(app) as http:
        after = await _post_turn(http, editor, chat_id, "fourth", sse=False)
    assert after.status_code == 200, after.text
    assert [run.user_message for run in script.runs] == ["first", "fourth"]


async def test_chat_stream_legacy_send_on_a_busy_legacy_chat_gets_409_run_active(
    world: World, agent: MagicMock, script: _Script
) -> None:
    """POST /api/message: a second message of the same legacy session id while the
    first one's run is parked is ``409 run_active`` with no run; the next one runs."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(
        editor.user_id, legacy_session_id=_LEGACY_SESSION, title="Legacy 8", title_source="user"
    )
    app = make_app(agent)

    async with _parked(app, script, lambda http: _post_legacy(http, editor, "first")) as parked:
        refused = await asyncio.wait_for(_post_legacy(parked.http, editor, "second"), _QUICK_S)
        while_parked = [run.user_message for run in script.runs]

    assert (refused.status_code, refused.json()) == (409, _RUN_ACTIVE)
    assert while_parked == ["first"]
    assert parked.first.result().status_code == 200
    assert [row[1] for row in _stored(world.db, chat_id)] == ["first", "Done."]
    async with _async_client(app) as http:
        after = await _post_legacy(http, editor, "third")
    assert after.status_code == 200, after.text


async def test_chat_stream_refused_send_keeps_the_chats_pending_confirmation(
    world: World, agent: MagicMock, script: _Script
) -> None:
    """The chat holds a pending confirmation while its streamed run is parked: a send
    refused with 409 leaves it untouched (it isn't cancelled like a message that runs)."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    app = make_app(agent)

    async with _parked(
        app, script, lambda http: _post_turn(http, editor, chat_id, "first", sse=True)
    ) as parked:
        seed_pending_confirmation(editor, chat_id, "confirm-8-seeded")
        refused = await asyncio.wait_for(
            _post_turn(parked.http, editor, chat_id, "second", sse=True), _QUICK_S
        )
        while_parked = _pending_id(chat_id)

    assert (refused.status_code, refused.json()) == (409, _RUN_ACTIVE)
    assert while_parked == "confirm-8-seeded"
    assert parked.first.result().status_code == 200
    assert _pending_id(chat_id) == "confirm-8-seeded"


async def test_chat_stream_approval_sent_during_a_turn_waits_then_streams(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A confirmation still waits for a running message (GH-24): the chat awaits a
    confirmation; a streamed turn (cancelling it) asks again under the same id and is
    parked; a streamed approval sent meanwhile waits on the chat (seen in ``hold()``),
    then resumes the confirmation that turn kept and streams the resumed run."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    app = make_app(agent)
    runtime = _watched_runtime(monkeypatch)
    script.queue(_reply(ask=_EARLIER_ASK))
    async with _async_client(app) as http:
        earlier = await _post_turn(http, editor, chat_id, "plan it", sse=False)
    assert earlier.json()["status"] == "awaiting_confirmation", earlier.text
    script.queue(_reply("Reading ", ask=_PENDING_CALL), _resumed(_PENDING_CALL, "Stored ", "it."))

    async with _parked(
        app, script, lambda http: _post_turn(http, editor, chat_id, "store it", sse=True)
    ) as parked:
        holds = len(runtime.holds)
        approval = asyncio.create_task(_post_approval(parked.http, editor, chat_id))
        await _until(lambda: len(runtime.holds) > holds)
        assert not approval.done()
        parked.release.set()
        approved = await asyncio.wait_for(approval, _WAIT_S)
        turn = await asyncio.wait_for(parked.first, _WAIT_S)

    assert _names(_stream(turn)) == [
        "run_started",
        "delta",
        "tool_call",
        "confirm",
        "message_saved",
        "done",
    ]
    assert _stream(approved) == [
        _started(chat_id),
        _tool_call(_record(_PENDING_CALL, "confirm")),
        _delta("Stored "),
        _delta("it."),
        _saved(world.db, chat_id, "complete"),
        _DONE,
    ]
    resumed = script.runs[2]
    assert resumed.arguments["pending_confirmation"].tool_call == _PENDING_CALL
    assert "stream" in resumed.keywords


# ---------------------------------------------------------------------------
# 9. POST /api/confirm with SSE (C5.3)
# ---------------------------------------------------------------------------


def test_chat_stream_approval_streams_the_resumed_run_without_a_title(
    world: World, client: TestClient, script: _Script
) -> None:
    """An approval streams like a turn: ``run_started``, the approved call's
    ``tool_call``, the reply's deltas, ``message_saved{complete}``, ``done``, and no
    ``title`` even for an untitled chat."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor)
    script.queue(_reply(ask=_PENDING_CALL), _resumed(_PENDING_CALL, "Saved ", "your plan."))
    assert _send(client, editor, chat_id, sse=False).json()["status"] == "awaiting_confirmation"
    row = db.chats[uuid.UUID(int=chat_id.int)]
    row["title"], row["title_source"] = "", "auto"

    frames = _stream(_confirm(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _tool_call(_record(_PENDING_CALL, "confirm")),
        _delta("Saved "),
        _delta("your "),
        _delta("plan."),
        _saved(db, chat_id, "complete"),
        _DONE,
    ]


def test_chat_stream_denial_streams_exactly_the_denial(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """A streamed denial: exactly ``run_started``, one ``delta`` "Action memory.store was
    denied.", ``message_saved{complete}`` naming the stored denial, ``done``; no run; the
    denial is stored like the JSON denial and the chat shows no confirmation."""
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor)
    script.queue(_reply(ask=_PENDING_CALL))
    assert _send(client, editor, chat_id, sse=False).json()["status"] == "awaiting_confirmation"

    frames = _stream(_confirm(client, editor, chat_id, approved=False))

    assert frames == [
        _started(chat_id),
        _delta("Action memory.store was denied."),
        _saved(world.db, chat_id, "complete"),
        _DONE,
    ]
    assert agent.run.await_count == 1
    assert _stored(world.db, chat_id) == [
        ("user", _MESSAGE, "complete"),
        ("assistant", "", "awaiting_confirmation"),
        ("tool", _DENIED_RESULT, "complete"),
        ("assistant", "Action memory.store was denied.", "complete"),
    ]
    assert world.db.messages_of(chat_id)[2]["tool_call_id"] == _PENDING_CALL.tool_call_id
    assert _detail(client, editor, chat_id)["confirmation_status"] == "none"


# ---------------------------------------------------------------------------
# 10. Titles (C5.6)
# ---------------------------------------------------------------------------


def test_chat_stream_first_exchange_sends_the_stored_title(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """An untitled chat's first streamed exchange: one title call (``max_tokens`` 40),
    then ``title`` with the stored title between ``message_saved`` and ``done``."""
    llm = _TitleLLM()
    agent._llm = llm
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor, titled=False)
    script.queue(_reply("Here is the VAT summary."))

    frames = _stream(_send(client, editor, chat_id, _TITLE_MESSAGE))

    assert frames[-3:] == [
        _saved(world.db, chat_id, "complete"),
        ("title", {"title": _TITLE}),
        _DONE,
    ]
    row = world.db.chat_row(chat_id)
    assert row is not None
    assert (row["title"], row["title_source"]) == (_TITLE, "auto")
    assert llm.calls == [_TITLE_MAX_TOKENS]


@pytest.mark.parametrize("outcome", ["error", "stopped"])
def test_chat_stream_failed_or_stopped_first_exchange_sends_the_fallback_title(
    world: World, client: TestClient, agent: MagicMock, script: _Script, outcome: str
) -> None:
    """A first exchange stored as ``error`` or ``stopped`` makes no title call: the
    fallback (the first message) is stored and sent as ``title``, right before ``done``."""
    llm = _TitleLLM()
    agent._llm = llm
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor, titled=False)
    if outcome == "error":
        script.queue(
            _reply(status="error", closing="The model is unavailable.", error_code="timeout")
        )
    else:
        script.queue(_reply("Partial ", status="stopped"))

    frames = _stream(_send(client, editor, chat_id, _TITLE_MESSAGE))

    assert frames[-2:] == [("title", {"title": _TITLE_MESSAGE}), _DONE]
    assert _saved(world.db, chat_id, outcome) in frames
    row = world.db.chat_row(chat_id)
    assert row is not None
    assert (row["title"], row["title_source"]) == (_TITLE_MESSAGE, "auto")
    assert llm.calls == []


def test_chat_stream_chat_renamed_during_the_run_sends_no_title(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """The user renames the untitled chat while its first run is in flight: the rename
    is kept and no ``title`` frame is sent."""
    agent._llm = _TitleLLM()
    editor = world.a["editor"]
    db = world.db
    chat_id = _chat(db, editor, titled=False)

    async def rename() -> None:
        row = db.chats[uuid.UUID(int=chat_id.int)]
        row["title"], row["title_source"] = "Renamed by me", "user"

    script.during = rename

    frames = _stream(_send(client, editor, chat_id, _TITLE_MESSAGE))

    assert _names(frames)[-2:] == ["message_saved", "done"]
    assert "title" not in _names(frames)
    row = db.chat_row(chat_id)
    assert row is not None
    assert (row["title"], row["title_source"]) == ("Renamed by me", "user")


def test_chat_stream_second_exchange_sends_no_title(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    """The first streamed exchange sends ``title``; the second sends none and makes no
    title call."""
    llm = _TitleLLM()
    agent._llm = llm
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor, titled=False)

    first = _stream(_send(client, editor, chat_id, _TITLE_MESSAGE))
    second = _stream(_send(client, editor, chat_id, "And the next quarter?"))

    assert ("title", {"title": _TITLE}) in first
    assert "title" not in _names(second)
    assert llm.calls == [_TITLE_MAX_TOKENS]


def test_chat_stream_json_first_exchange_still_titles_in_the_background(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    """Regression guard: a JSON first exchange keeps today's background title (the
    response has no title field; the chat is titled once the response is done)."""
    llm = _TitleLLM()
    agent._llm = llm
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor, titled=False)

    response = _send(client, editor, chat_id, _TITLE_MESSAGE, sse=False)

    assert response.status_code == 200, response.text
    assert "title" not in response.json()
    row = world.db.chat_row(chat_id)
    assert row is not None
    assert (row["title"], row["title_source"]) == (_TITLE, "auto")
    assert llm.calls == [_TITLE_MAX_TOKENS]


# ---------------------------------------------------------------------------
# 11. OpenAPI and logs
# ---------------------------------------------------------------------------


def test_chat_stream_openapi_lists_event_stream_beside_json(agent: MagicMock) -> None:
    """Both operations keep their JSON ChatResponse and list ``text/event-stream`` as a
    200 content type next to it."""
    schema = make_app(agent).openapi()

    for path in ("/api/chats/{chat_id}/messages", "/api/confirm/{confirmation_id}"):
        content = schema["paths"][path]["post"]["responses"]["200"]["content"]
        assert set(content) == {"application/json", "text/event-stream"}, path
        assert content["application/json"]["schema"] == {
            "$ref": "#/components/schemas/ChatResponse"
        }


def test_chat_stream_debug_logs_carry_no_content(
    world: World,
    client: TestClient,
    agent: MagicMock,
    script: _Script,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Every logger at DEBUG during a streamed first exchange with a tool call and a
    title: the frames carry the delta, argument, reply and title canaries, and no app
    record holds any of them or the message."""
    caplog.set_level(logging.DEBUG)
    agent._llm = _TitleLLM("Godwit canary eight")
    editor = world.a["editor"]
    chat_id = _chat(world.db, editor, titled=False)
    call = ToolCall(
        tool="memory",
        action="recall",
        args={"key": "arg-canary-8-avocet"},
        tool_call_id="call-8-log",
    )
    script.queue(_reply("delta-canary-8-curlew ", call, "reply-canary-8-dunlin"))

    frames = _stream(_send(client, editor, chat_id, "msg-canary-8-plover"))

    sent = json.dumps(frames)
    shown = ("delta-canary-8-curlew", "arg-canary-8-avocet", "reply-canary-8-dunlin")
    assert all(canary in sent for canary in shown)
    assert ("title", {"title": "Godwit canary eight"}) in frames
    logs = _app_log_text(caplog)
    assert logs
    for canary in (*shown, "Godwit canary eight", "msg-canary-8-plover"):
        assert canary not in logs
