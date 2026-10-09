"""HTTP spec of POST /api/chats/{chat_id}/retry beyond its JSON core (GH-245, writer W6).

Issue #245, criteria "Retry" and "Errors", Decisions 1 to 5; contract C2 and C4
(``RUN_DIR/contract.md``). Tracker #139 §5: a refusal answers before the run with
nothing run or stored, every error is a stable code in the existing envelope and
documented in the OpenAPI contract. The route's authorization, its 404/409 matrices,
the run's keywords on the JSON path, the JSON storage, the 500, the rate limit and the
logs are tests/test_chat_retry_api.py's; the real agent tests/test_chat_retry_agent_api.py's;
the tenancy rows and GET ``retryable`` W5's.

Harness: the app from ``create_app()`` on the FakeDb world of tests/tenancy_world.py
(orgs A and B with an Org Admin, an Editor and a Viewer each, real session cookies),
the attachments root under ``tmp_path`` and derived files written with
tests/attachment_derived.py. The agent is a stub (``_Script``, the pattern of
tests/test_chat_stream_api.py): its ``run`` binds every call to ``Agent.run``'s
signature (``stream`` and ``attachments`` included), records the keywords passed and
the slot's attachment ids, plays its script into a ``RunStream`` when it gets one (text
to ``on_delta``, a ``ToolCallRecord`` to ``on_tool_call``), awaits a one-shot
``during(stream)`` hook (park, wait for the stop, trash the chat) and answers the
history it got plus the user message plus the scripted new messages, as the real
agent does. A failed turn is seeded as the server stores it (the run's last message
carries ``error`` or ``stopped``), or made by a real send whose run ends ``error``.

What is pinned:
- Streaming (Decision 4 "Answer", C4 step 11): ``Accept: text/event-stream`` answers
  the run's event stream with a send's frames: ``run_started {chat_id}`` first, the
  deltas word by word, ``tool_call``, ``context_usage``, ``message_saved`` naming the
  re-stored turn's last message with its stored status, ``error`` for a retry that
  failed again, ``done`` last. The run gets a ``RunStream`` (stop not set) and a
  send's keywords. The replacement is stored exactly as a JSON retry stores it: the
  messages before the retried one, the user message again (same text, a new row), the
  new answer; nothing of the failed turn. A streamed retry whose agent raised
  (``internal_error``) or whose chat was trashed during the run (``chat_not_found``)
  stores nothing and leaves the failed turn as it was (Decision 2). While a streamed
  retry runs, a send to the chat is the 409 ``run_active``.
- Stop (Decision 4): POST /api/chats/{id}/stop reaches a streamed retry
  (``{"stopped": true}``, the run's stop event set): it ends ``message_saved{stopped}``,
  is stored ``stopped`` in place of the failed turn, GET shows ``retryable`` and the
  next retry runs and replaces it again.
- Files (Decision 2, Decision 3 "the slot a send builds"): after a send with files
  failed, the retry's re-stored user message carries the same attachment ids
  (excluded ones too, as GET /api/chats/{id} lists them), every attachment row and
  file is intact (nothing deleted, ``active`` unchanged), an earlier message's file
  stays on its message; the run gets the chat's active attachments as ``attachments``,
  in the order the failed send's run got them (the excluded file never), and the new
  answer records them as ``included_attachment_ids``. JSON and streamed.
- Title (Decision 4): an untitled ``auto`` chat whose only turn failed gets the
  first-exchange title after a successful retry (JSON: the background task; streamed:
  ``title`` between ``message_saved`` and ``done``), made from the retried message
  and the new reply; a chat with an earlier assistant reply or a user title gets no
  title call.
- Errors (criterion "Errors", Decision 5, C4): /api/openapi.json documents the route
  with no request body, the 200 ChatResponse beside ``text/event-stream``, and the
  named examples 404 ``chat_not_found``, 409 ``run_active`` / ``not_retryable``, 422
  ``context_overflow`` / ``attachment_bytes_exceeded`` / ``image_input_unsupported``
  (the 422 description naming the validation list and the three codes), 429
  ``rate_limit`` (named in the description) and 503 ``chats_busy`` /
  ``storage_unavailable``. Each documented example is the body the route answers in
  that case, for a JSON and a streamed request alike (always ``application/json``),
  with no run and nothing changed: no message, no attachment row, no file.

The route is reached over HTTP only (``admino.chat_runtime`` and ``admino.streaming``
exist since GH-8), so the file collects before GH-245 is implemented and every test
fails on the missing route or its missing OpenAPI entry.

Security notes:
- Every message, id, file name and file text here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest

from admino import organizations, scoped_settings, server
from admino.chat_runtime import ChatRuntime
from admino.llm import LLMResponse
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
)
from tests.attachment_derived import png_bytes, write_derived
from tests.conftest import default_test_platform_settings
from tests.context_frames import fix_instructions, usage_frame
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    CHAT_NOT_FOUND,
    CLIENT_IP,
    attachment_files,
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

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
    from unittest.mock import MagicMock

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ROUTE: Final = "/api/chats/{chat_id}/retry"
_SSE: Final = {"Accept": "text/event-stream"}
_JSON: Final = "application/json"

# The route's documented bodies (contract C4 and the existing chat bodies).
_NOT_RETRYABLE: Final = {"detail": "The last answer can't be retried.", "reason": "not_retryable"}
_RUN_ACTIVE: Final = {
    "detail": "A message is already running in this chat.",
    "reason": "run_active",
}
_CHATS_BUSY: Final = {
    "detail": "Too many active chats. Try again shortly.",
    "reason": "chats_busy",
}
_USER_CHATS_BUSY: Final = {
    "detail": "Too many of your chats are active. Try again shortly.",
    "reason": "rate_limit",
}
_IMAGE_UNSUPPORTED: Final = {
    "detail": "The current model does not accept image input",
    "reason": "image_input_unsupported",
}
_STORAGE_UNAVAILABLE: Final = {
    "detail": "Attachment storage is unavailable",
    "reason": "storage_unavailable",
}
_CONTEXT_DETAILS: Final = {
    "context_overflow": "The chat's attachments don't fit the model's context",
    "attachment_bytes_exceeded": "The chat's attachments are too large for one turn",
}
_LITERAL_BODIES: Final[dict[str, dict[str, str]]] = {
    "chat_not_found": CHAT_NOT_FOUND,
    "run_active": _RUN_ACTIVE,
    "not_retryable": _NOT_RETRYABLE,
    "image_input_unsupported": _IMAGE_UNSUPPORTED,
    "rate_limit": _USER_CHATS_BUSY,
    "chats_busy": _CHATS_BUSY,
    "storage_unavailable": _STORAGE_UNAVAILABLE,
}
_STOPPED: Final = {"stopped": True}

_USER_TITLE: Final = "Planning 245"
_EARLIER_QUESTION: Final = "Earlier question 245"
_EARLIER_ANSWER: Final = "Earlier answer 245"
_MESSAGE: Final = "Compare the ledgers 245"
_FILES_MESSAGE: Final = "Compare these files 245"
_FAILURE: Final = "The model is not available right now."
_REPLY: Final = "Done."
_EARLIER_ROWS: Final = [
    ("user", _EARLIER_QUESTION, "complete"),
    ("assistant", _EARLIER_ANSWER, "complete"),
]

# Titles (tests/test_chat_titles_api.py's values): the raw model title and its sanitized form.
_TITLE_MESSAGE: Final = "Summarise the quarterly VAT figures"
_TITLE_REPLY: Final = "Here is the VAT summary 245."
_RAW_TITLE: Final = '"Quarterly VAT report."'
_TITLE: Final = "Quarterly VAT report"
_TITLE_MAX_TOKENS: Final = 40

_WAIT_S: Final = 5.0
# A refusal answers at once; a send that waited for the parked run would hit this bound.
_QUICK_S: Final = 3.0
_T0: Final = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)

# SSE line terminators (WHATWG): CRLF, a lone CR or a lone LF.
_LINE_BREAK: Final = re.compile(r"\r\n|\r|\n")
_EVENT_NAME: Final = re.compile(r"[a-zA-Z0-9_.:-]+")

# The keywords a send passes to Agent.run (a streamed run adds ``stream``, a run with a
# slot ``attachments``).
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

_CALL_A: Final = ToolCall(
    tool="memory", action="recall", args={"key": "plan"}, tool_call_id="call-245-a"
)

# Every documented example of the route: (status, code).
_DOCUMENTED: Final = (
    ("404", "chat_not_found"),
    ("409", "run_active"),
    ("409", "not_retryable"),
    ("422", "context_overflow"),
    ("422", "attachment_bytes_exceeded"),
    ("422", "image_input_unsupported"),
    ("429", "rate_limit"),
    ("503", "chats_busy"),
    ("503", "storage_unavailable"),
)
_CODES_422: Final = ("context_overflow", "attachment_bytes_exceeded", "image_input_unsupported")


def _at(minutes: int) -> datetime:
    return _T0 + timedelta(minutes=minutes)


# ---------------------------------------------------------------------------
# The stub agent
# ---------------------------------------------------------------------------

type Step = str | ToolCallRecord


def _block(call: ToolCall) -> dict[str, Any]:
    """The tool_use block the agent stores for ``call``."""
    return {
        "type": "tool_use",
        "id": call.tool_call_id,
        "name": f"{call.tool}.{call.action}",
        "input": dict(call.args),
    }


def _record(call: ToolCall) -> ToolCallRecord:
    """The allowed ToolCallRecord of ``call`` (what ``on_tool_call`` gets and the run returns)."""
    return ToolCallRecord(
        tool=call.tool,
        action=call.action,
        args=call.args,
        permission="allow",
        success=True,
        duration_ms=7,
    )


@dataclass(frozen=True)
class _Reply:
    """One stub run: the script it plays into a stream, its new messages and its outcome."""

    steps: tuple[Step, ...] = (_REPLY,)
    new: tuple[LLMMessage, ...] = (LLMMessage(role="assistant", content=_REPLY),)
    status: str = "final"
    response: str = _REPLY
    error_code: str | None = None
    error: Exception | None = None

    @property
    def tool_calls(self) -> list[ToolCallRecord]:
        return [step for step in self.steps if isinstance(step, ToolCallRecord)]


def _reply(
    *steps: str | ToolCall,
    status: str = "final",
    closing: str | None = None,
    error_code: str | None = None,
) -> _Reply:
    """A run as the real agent stores it (tests/test_chat_stream_api.py's ``_reply``).

    Text pieces go to ``on_delta``; a ``ToolCall`` is an allowed dispatch: its record
    goes to ``on_tool_call`` and the run stores an assistant turn (the text before it,
    its tool_use block) and the tool result. ``closing`` is a reply the agent adds
    without streaming it (an error): stored last, the run's response. Otherwise the
    text after the last call is the stored reply.
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
            LLMMessage(
                role="tool", content=f"Result {step.tool_call_id}", tool_call_id=step.tool_call_id
            ),
        ]
        text = ""
    if closing is not None:
        new.append(LLMMessage(role="assistant", content=closing))
        response = closing
    else:
        new.append(LLMMessage(role="assistant", content=text))
        response = text
    return _Reply(
        steps=tuple(played), new=tuple(new), status=status, response=response, error_code=error_code
    )


@dataclass(frozen=True)
class _Run:
    """One stub run: the user message, the keywords passed, the stream and the slot's ids."""

    user_message: str
    keywords: frozenset[str]
    stream: Any
    stop_set: bool | None
    attachment_ids: tuple[uuid.UUID, ...]


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
    attachments: Sequence[Any] = (),
) -> None:
    """``Agent.run``'s signature (GH-8's ``stream``, GH-189's ``attachments``)."""


class _Script:
    """Scripted replies for the stub agent's ``run`` and the record of every call."""

    def __init__(self) -> None:
        self.replies: list[_Reply] = []
        self.runs: list[_Run] = []
        # Awaited once, inside the next run, with its stream (None for a JSON run), after
        # its script and before it answers.
        self.during: Callable[[Any], Awaitable[None]] | None = None

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
                keywords=frozenset(kwargs),
                stream=stream,
                stop_set=None if stream is None else stream.stop.is_set(),
                attachment_ids=tuple(
                    uuid.UUID(str(content.id)) for content in arguments["attachments"]
                ),
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
            await during(stream)
        if reply.error is not None:
            raise reply.error
        history = [
            *arguments["history"],
            LLMMessage(role="user", content=arguments["user_message"]),
        ]
        return AgentResult(
            status=reply.status,  # type: ignore[arg-type]
            response=reply.response,
            history=[*history, *reply.new],
            tool_calls=reply.tool_calls,
            pending_confirmation=None,
            error_code=reply.error_code,  # type: ignore[arg-type]
        )


class _TitleLLM:
    """The running client for the title call: records each call's ``max_tokens`` and its
    messages (as JSON text) and answers ``_RAW_TITLE``."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self.calls: list[int | None] = []
        self.prompts: list[str] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        self.calls.append(max_tokens)
        self.prompts.append(json.dumps([m.model_dump(mode="json") for m in messages]))
        return LLMResponse(content=_RAW_TITLE)

    async def close(self) -> None:
        """Nothing to close."""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin behind the fake database, with the
    attachments root under ``tmp_path``."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    return built


@pytest.fixture(autouse=True)
def _fixed_instructions(monkeypatch: pytest.MonkeyPatch) -> None:
    """GH-190: the instructions count a constant (tests/context_frames.py), so every
    ``context_usage`` frame is deterministic."""
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
# Chats, files and requests
# ---------------------------------------------------------------------------


def _url(chat_id: uuid.UUID | str) -> str:
    return _ROUTE.format(chat_id=chat_id)


def _failed_chat(
    db: FakeDb,
    account: Account,
    *,
    titled: bool = True,
    earlier: bool = True,
    message: str = _MESSAGE,
) -> uuid.UUID:
    """A live chat of ``account`` whose last turn failed: an earlier exchange (unless
    ``earlier`` is false), then ``message`` and the run's error reply (status ``error``).
    User-titled (no title step runs) unless ``titled`` is false (untitled, ``auto``)."""
    if titled:
        chat_id = db.add_chat(account.user_id, title=_USER_TITLE, title_source="user")
    else:
        chat_id = db.add_chat(account.user_id)
    if earlier:
        db.add_chat_message(chat_id, "user", _EARLIER_QUESTION)
        db.add_chat_message(chat_id, "assistant", _EARLIER_ANSWER)
    db.add_chat_message(chat_id, "user", message)
    db.add_chat_message(chat_id, "assistant", _FAILURE, status="error")
    return chat_id


Row = tuple[str, str, str]


def _stored(db: FakeDb, chat_id: uuid.UUID) -> list[Row]:
    """The chat's stored messages by seq: (role, content, status)."""
    return [(m["role"], m["content"], m["status"]) for m in db.messages_of(chat_id)]


def _ids(db: FakeDb, chat_id: uuid.UUID) -> list[uuid.UUID]:
    """The chat's stored message ids by seq."""
    return [plain(m["id"]) for m in db.messages_of(chat_id)]


def _turn_rows(db: FakeDb, chat_id: uuid.UUID) -> list[tuple[Any, ...]]:
    """Every stored column of the chat's messages that a turn decides (no id, seq or time)."""
    return [
        (
            m["role"],
            m["content"],
            m["status"],
            m["tool_call_id"],
            m["tool_use_blocks"],
            m["tool_calls"],
            m["included_attachment_ids"],
        )
        for m in db.messages_of(chat_id)
    ]


def _attachment_rows(db: FakeDb, chat_id: uuid.UUID) -> dict[uuid.UUID, dict[str, Any]]:
    """The chat's attachment rows by id, without the link columns a retry moves."""
    return {
        plain(row["id"]): {
            key: value for key, value in row.items() if key not in ("message_id", "updated_at")
        }
        for row in db.attachments_of(chat_id)
    }


def _links(db: FakeDb, chat_id: uuid.UUID) -> dict[uuid.UUID, uuid.UUID | None]:
    """Each attachment of the chat -> the message it is linked to (None: none)."""
    return {
        plain(row["id"]): None if row["message_id"] is None else plain(row["message_id"])
        for row in db.attachments_of(chat_id)
    }


def _state(db: FakeDb, chat_id: uuid.UUID) -> tuple[Any, ...]:
    """Everything a refused retry may not change: the chat row, its messages (with ids),
    its attachment rows, the message count of every chat and the files on disk."""
    return (
        db.chat_row(chat_id),
        db.messages_of(chat_id),
        db.attachments_of(chat_id),
        len(db.chat_messages),
        attachment_files(),
    )


def _org_of(db: FakeDb, chat_id: uuid.UUID) -> uuid.UUID:
    chat = db.chat_row(chat_id)
    assert chat is not None
    return plain(chat["org_id"])


def _file(
    db: FakeDb,
    chat_id: uuid.UUID,
    *,
    minute: int,
    message_id: uuid.UUID | None = None,
    active: bool = True,
    tokens: int = 12,
    size: int = 120,
    image: bool = False,
    derived: bool = True,
    attachment_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """A ``ready`` attachment of the chat (uploaded at ``minute``) with its stored
    ``token_estimate`` and ``derived_bytes``, and its derived files unless ``derived``
    is false: a text file, or a PNG (``image``)."""
    kind = "png" if image else "txt"
    file_id = db.add_attachment(
        chat_id,
        attachment_id=attachment_id,
        filename=f"retry-file-245-{minute}.{kind}",
        kind=kind,
        status="ready",
        token_estimate=tokens,
        derived_bytes=size,
        message_id=message_id,
        created_at=_at(minute),
        **({} if active else {"active": False}),
    )
    if derived:
        parts: list[tuple[Any, ...]] = (
            [("image", png_bytes(), "image/png", None, None)]
            if image
            else [("text", f"Ledger text 245 minute {minute}", None)]
        )
        write_derived(
            Path(organizations.ATTACHMENTS_ROOT),
            _org_of(db, chat_id),
            file_id,
            kind=kind,  # type: ignore[arg-type]
            parts=parts,
            page_count=None,
        )
    return file_id


def _image_input_off(monkeypatch: pytest.MonkeyPatch, db: FakeDb) -> None:
    """The stored platform ``llm.image_input`` is false (settings cache and row)."""
    stored = default_test_platform_settings()
    data = stored.model_dump()
    data["llm"]["image_input"] = False
    monkeypatch.setattr(scoped_settings, "_platform_cache", type(stored).model_validate(data))
    row = db.platform_row()
    assert row is not None
    row["image_input"] = False


def _retry(
    client: TestClient, account: Account, chat_id: uuid.UUID, *, sse: bool = True
) -> httpx.Response:
    """POST /api/chats/{chat_id}/retry as ``account`` (no body; streamed unless ``sse`` is
    false)."""
    return client.post(_url(chat_id), headers={**account.cookie, **(_SSE if sse else {})})


def _send(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    message: str,
    attachment_ids: Sequence[uuid.UUID] = (),
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account`` (JSON)."""
    body: dict[str, Any] = {"message": message}
    if attachment_ids:
        body["attachment_ids"] = [str(file_id) for file_id in attachment_ids]
    return client.post(f"/api/chats/{chat_id}/messages", headers=account.cookie, json=body)


def _detail(client: TestClient, account: Account, chat_id: uuid.UUID) -> dict[str, Any]:
    """GET /api/chats/{chat_id} as its owner (must succeed)."""
    response = client.get(f"/api/chats/{chat_id}", headers=account.cookie)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _chat_title(db: FakeDb, chat_id: uuid.UUID) -> tuple[str, str]:
    row = db.chat_row(chat_id)
    assert row is not None
    return row["title"], row["title_source"]


# ---------------------------------------------------------------------------
# Reading a stream
# ---------------------------------------------------------------------------

Frame = tuple[str, dict[str, Any]]


def _refuse_constant(name: str) -> Any:
    """``json.loads``'s hook for NaN / Infinity / -Infinity: not JSON, so refused."""
    msg = f"non-standard JSON constant {name} in an SSE payload"
    raise ValueError(msg)


def _parse_sse(text: str) -> list[Frame]:
    """The frames of an SSE body, read as a client reads them (lines split at CRLF, CR or
    LF; a blank line ends a frame; ``:`` comments ignored; one ``event:`` and one
    ``data:`` line per frame, the data strict JSON)."""
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
        else:
            assert name == "data", f"unexpected SSE field {name!r}"
            data.append(value)
    assert event is None, "the body ends inside a frame"
    assert not data, "the body ends inside a frame"
    return frames


def _stream(response: httpx.Response) -> list[Frame]:
    """A streamed answer's frames (a 200 ``text/event-stream``)."""
    content_type = response.headers.get("content-type", "")
    assert (response.status_code, content_type.split(";")[0]) == (200, "text/event-stream"), (
        response.status_code,
        content_type,
        response.text[:400],
    )
    return _parse_sse(response.text)


def _names(frames: list[Frame]) -> list[str]:
    return [name for name, _ in frames]


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


# ---------------------------------------------------------------------------
# Concurrency helpers
# ---------------------------------------------------------------------------


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the test's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50245))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _until_parked(event: asyncio.Event, request: asyncio.Task[Any]) -> None:
    """Wait until ``event`` is set; fail at once when ``request`` ends first (it never
    reached the run)."""
    waiter = asyncio.ensure_future(event.wait())
    done, _ = await asyncio.wait(
        {waiter, request}, timeout=_WAIT_S, return_when=asyncio.FIRST_COMPLETED
    )
    if waiter in done:
        return
    waiter.cancel()
    if request.done() and isinstance(request.result(), httpx.Response):
        answered: httpx.Response = request.result()
        pytest.fail(f"the retry never ran: {answered.status_code} {answered.text[:300]}")
    pytest.fail("the retry never ran")


# ---------------------------------------------------------------------------
# 1. A streamed retry (Decision 4 "Answer", C4 step 11)
# ---------------------------------------------------------------------------


def test_chat_retry_stream_answers_a_sends_frames_and_replaces_the_failed_turn(
    world: World, client: TestClient, script: _Script
) -> None:
    """Text, a tool call, text: ``run_started``, the deltas word by word (the held word
    flushed before the ``tool_call``), ``context_usage``, ``message_saved`` naming the
    re-stored turn's last message (complete), ``done``. The failed turn is gone: the
    retried message is stored again, then the new answer. The run got the retried
    message, a send's keywords plus ``stream``, and a stop event that isn't set."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _failed_chat(db, editor)
    failed = _ids(db, chat_id)[2:]
    script.queue(_reply("Checking ", "now", _CALL_A, "Here ", "it is."))

    frames = _stream(_retry(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _delta("Checking "),
        _delta("now"),
        _tool_call(_record(_CALL_A)),
        _delta("Here "),
        _delta("it "),
        _delta("is."),
        usage_frame(db, chat_id),
        _saved(db, chat_id, "complete"),
        _DONE,
    ]
    assert _stored(db, chat_id) == [
        *_EARLIER_ROWS,
        ("user", _MESSAGE, "complete"),
        ("assistant", "Checking now", "complete"),
        ("tool", "Result call-245-a", "complete"),
        ("assistant", "Here it is.", "complete"),
    ]
    assert set(failed).isdisjoint(_ids(db, chat_id))
    run = script.runs[0]
    assert (run.user_message, run.keywords, run.stop_set) == (
        _MESSAGE,
        _TURN_KEYWORDS | {"stream"},
        False,
    )


def test_chat_retry_stream_stores_the_turn_a_json_retry_stores(
    world: World, client: TestClient, script: _Script
) -> None:
    """Two chats with the same failed turn, the same scripted run: the streamed retry
    stores exactly what the JSON retry stores (every column a turn decides)."""
    editor = world.a["editor"]
    db = world.db
    as_json, streamed = _failed_chat(db, editor), _failed_chat(db, editor)
    script.queue(
        _reply("Checking ", _CALL_A, "Here it is."),
        _reply("Checking ", _CALL_A, "Here it is."),
    )

    answered = _retry(client, editor, as_json, sse=False)
    frames = _stream(_retry(client, editor, streamed))

    assert (answered.status_code, answered.json()["status"]) == (200, "final"), answered.text
    assert _names(frames)[-2:] == ["message_saved", "done"]
    assert _turn_rows(db, streamed) == _turn_rows(db, as_json)
    assert _stored(db, streamed)[2:] == [
        ("user", _MESSAGE, "complete"),
        ("assistant", "Checking ", "complete"),
        ("tool", "Result call-245-a", "complete"),
        ("assistant", "Here it is.", "complete"),
    ]


def test_chat_retry_stream_failed_again_reports_message_saved_error_then_error(
    world: World, client: TestClient, script: _Script
) -> None:
    """A retry whose run fails again: its delta, ``message_saved{error}`` naming the new
    error reply, ``error`` with the run's code and reply, ``done``. The new failed turn
    replaces the old one (so the chat holds one failed turn)."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _failed_chat(db, editor)
    failed = _ids(db, chat_id)[2:]
    again = "The provider timed out 245."
    script.queue(_reply("Partial ", status="error", closing=again, error_code="timeout"))

    frames = _stream(_retry(client, editor, chat_id))

    assert frames == [
        _started(chat_id),
        _delta("Partial "),
        usage_frame(db, chat_id),
        _saved(db, chat_id, "error"),
        _error("timeout", again),
        _DONE,
    ]
    assert _stored(db, chat_id) == [
        *_EARLIER_ROWS,
        ("user", _MESSAGE, "complete"),
        ("assistant", again, "error"),
    ]
    assert set(failed).isdisjoint(_ids(db, chat_id))


@pytest.mark.parametrize("outcome", ["agent_raised", "chat_trashed"])
def test_chat_retry_stream_run_that_stores_nothing_keeps_the_failed_turn(
    world: World, client: TestClient, script: _Script, outcome: str
) -> None:
    """Decision 2: the agent raised (``error{internal_error, "Internal error"}``, the
    exception text nowhere) or the chat was trashed during the run
    (``error{chat_not_found, "Chat not found"}``): nothing is stored and the failed turn
    stays as it was (same rows, same ids)."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _failed_chat(db, editor)
    before = db.messages_of(chat_id)
    if outcome == "agent_raised":
        script.queue(_Reply(steps=(), error=RuntimeError("retry failure 245 kestrel")))
        expected = _error("internal_error", "Internal error")
    else:

        async def trash(_stream: Any) -> None:
            db.chats[uuid.UUID(int=chat_id.int)]["deleted_at"] = datetime.now(UTC)

        script.during = trash
        script.queue(_Reply(steps=()))
        expected = _error("chat_not_found", "Chat not found")

    response = _retry(client, editor, chat_id)

    assert _stream(response) == [_started(chat_id), expected, _DONE]
    assert "retry failure 245 kestrel" not in response.text
    assert db.messages_of(chat_id) == before


async def test_chat_retry_stream_send_while_a_streamed_retry_runs_gets_409_run_active(
    world: World, agent: MagicMock, script: _Script
) -> None:
    """The streamed retry holds the chat until its turn is stored: a send to the chat
    while the retry's run is parked is the 409 ``run_active`` at once, with no run; the
    retry then ends and replaces the failed turn."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _failed_chat(db, editor)
    app = make_app(agent)
    parked, release = asyncio.Event(), asyncio.Event()

    async def park(_stream: Any) -> None:
        parked.set()
        await asyncio.wait_for(release.wait(), _WAIT_S)

    script.during = park

    async with _async_client(app) as http:
        task = asyncio.create_task(http.post(_url(chat_id), headers={**editor.cookie, **_SSE}))
        try:
            await _until_parked(parked, task)
            refused = await asyncio.wait_for(
                http.post(
                    f"/api/chats/{chat_id}/messages",
                    headers=editor.cookie,
                    json={"message": "Next 245"},
                ),
                _QUICK_S,
            )
        finally:
            release.set()
        response = await asyncio.wait_for(task, _WAIT_S)

    assert (refused.status_code, refused.json()) == (409, _RUN_ACTIVE)
    assert agent.run.await_count == 1
    assert _names(_stream(response))[-2:] == ["message_saved", "done"]
    assert _stored(db, chat_id) == [
        *_EARLIER_ROWS,
        ("user", _MESSAGE, "complete"),
        ("assistant", _REPLY, "complete"),
    ]


# ---------------------------------------------------------------------------
# 2. POST /api/chats/{id}/stop stops a streamed retry (Decision 4)
# ---------------------------------------------------------------------------


async def test_chat_retry_stream_stop_route_stops_a_streamed_retry_and_it_is_retryable_again(
    world: World, agent: MagicMock, script: _Script
) -> None:
    """While a streamed retry's run waits after two deltas, POST /stop answers
    ``{"stopped": true}`` and sets the run's stop event; the run ends ``stopped``:
    ``message_saved{stopped}``, stored ``stopped`` in place of the failed turn. GET then
    shows the chat ``retryable`` and the next retry runs and replaces that turn."""
    editor = world.a["editor"]
    db = world.db
    chat_id = _failed_chat(db, editor)
    app = make_app(agent)
    parked = asyncio.Event()
    stop_seen: list[bool] = []

    async def until_stopped(stream: Any) -> None:
        parked.set()
        try:
            await asyncio.wait_for(stream.stop.wait(), _QUICK_S)
        except TimeoutError:
            stop_seen.append(False)
        else:
            stop_seen.append(True)

    script.during = until_stopped
    script.queue(_reply("Partial ", "answer ", status="stopped"))

    async with _async_client(app) as http:
        task = asyncio.create_task(http.post(_url(chat_id), headers={**editor.cookie, **_SSE}))
        await _until_parked(parked, task)
        stopped = await http.post(f"/api/chats/{chat_id}/stop", headers=editor.cookie)
        response = await asyncio.wait_for(task, _WAIT_S)
        frames = _stream(response)
        # Read before the next retry replaces the stopped turn.
        expected_tail = [usage_frame(db, chat_id), _saved(db, chat_id, "stopped"), _DONE]
        stored_after_stop = _stored(db, chat_id)
        detail = await http.get(f"/api/chats/{chat_id}", headers=editor.cookie)
        again = await http.post(_url(chat_id), headers=editor.cookie)

    assert (stopped.status_code, stopped.json(), stop_seen) == (200, _STOPPED, [True])
    assert frames == [
        _started(chat_id),
        _delta("Partial "),
        _delta("answer "),
        *expected_tail,
    ]
    assert stored_after_stop == [
        *_EARLIER_ROWS,
        ("user", _MESSAGE, "complete"),
        ("assistant", "Partial answer ", "stopped"),
    ]
    assert (detail.status_code, detail.json().get("retryable")) == (200, True)
    assert (again.status_code, again.json().get("status")) == (200, "final"), again.text
    assert _stored(db, chat_id) == [
        *_EARLIER_ROWS,
        ("user", _MESSAGE, "complete"),
        ("assistant", _REPLY, "complete"),
    ]


# ---------------------------------------------------------------------------
# 3. Files (Decision 2: the same files move to the new row; Decision 3: the slot)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FailedFiles:
    """A chat whose last send carried files and failed (made through the send route)."""

    chat_id: uuid.UUID
    earlier_user: uuid.UUID
    failed_user: uuid.UUID
    earlier: uuid.UUID
    first: uuid.UUID
    second: uuid.UUID
    excluded: uuid.UUID


def _failed_send_with_files(
    client: TestClient, db: FakeDb, account: Account, script: _Script
) -> _FailedFiles:
    """An earlier exchange whose user message carries a file, then a JSON send of
    ``_FILES_MESSAGE`` listing three files out of upload order (one excluded) whose run
    ends ``error``. The send's run is ``script.runs[0]``."""
    chat_id = db.add_chat(account.user_id, title=_USER_TITLE, title_source="user")
    earlier_user = db.add_chat_message(chat_id, "user", _EARLIER_QUESTION)
    earlier = _file(db, chat_id, minute=0, message_id=earlier_user)
    db.add_chat_message(chat_id, "assistant", _EARLIER_ANSWER)
    first = _file(db, chat_id, minute=1)
    second = _file(db, chat_id, minute=2)
    excluded = _file(db, chat_id, minute=3, active=False)
    script.queue(_reply(status="error", closing=_FAILURE, error_code="timeout"))
    sent = _send(client, account, chat_id, _FILES_MESSAGE, [second, excluded, first])
    assert (sent.status_code, sent.json().get("status")) == (200, "error"), sent.text
    failed_user = _ids(db, chat_id)[2]
    assert _links(db, chat_id) == {
        earlier: earlier_user,
        first: failed_user,
        second: failed_user,
        excluded: failed_user,
    }
    return _FailedFiles(
        chat_id=chat_id,
        earlier_user=earlier_user,
        failed_user=failed_user,
        earlier=earlier,
        first=first,
        second=second,
        excluded=excluded,
    )


@pytest.mark.parametrize("mode", ["json", "sse"])
def test_chat_retry_files_restored_user_message_carries_the_same_attachments(
    world: World, client: TestClient, script: _Script, mode: str
) -> None:
    """After the retry the re-stored user message (a new row, the same text) carries the
    failed one's files, the excluded one too, as GET /api/chats/{id} lists them; the
    earlier message keeps its file; every attachment row (but its link) and every file
    on disk is unchanged: nothing deleted, ``active`` kept."""
    editor = world.a["editor"]
    db = world.db
    files = _failed_send_with_files(client, db, editor, script)
    chat_id = files.chat_id
    shown_before = _detail(client, editor, chat_id)["messages"][2]["attachment_ids"]
    rows_before = _attachment_rows(db, chat_id)
    files_before = attachment_files()

    response = _retry(client, editor, chat_id, sse=mode == "sse")

    if mode == "sse":
        assert _names(_stream(response))[-2:] == ["message_saved", "done"]
    else:
        assert (response.status_code, response.json()["status"]) == (200, "final"), response.text
    assert _stored(db, chat_id) == [
        *_EARLIER_ROWS,
        ("user", _FILES_MESSAGE, "complete"),
        ("assistant", _REPLY, "complete"),
    ]
    restored = _ids(db, chat_id)[2]
    assert restored != files.failed_user
    assert _links(db, chat_id) == {
        files.earlier: files.earlier_user,
        files.first: restored,
        files.second: restored,
        files.excluded: restored,
    }
    shown = _detail(client, editor, chat_id)["messages"][2]
    assert (shown["id"], shown["attachment_ids"]) == (str(restored), shown_before)
    assert shown_before == [str(files.first), str(files.second), str(files.excluded)]
    assert _attachment_rows(db, chat_id) == rows_before
    assert attachment_files() == files_before


def test_chat_retry_files_run_gets_the_chats_active_attachments_in_the_sends_order(
    world: World, client: TestClient, script: _Script
) -> None:
    """The retry's run gets ``attachments``: the chat's active files in the order the
    failed send's run got them (the earlier message's file, then the retried message's
    in upload order, the excluded file never); the new answer records them as
    ``included_attachment_ids``."""
    editor = world.a["editor"]
    db = world.db
    files = _failed_send_with_files(client, db, editor, script)
    expected = (files.earlier, files.first, files.second)

    response = _retry(client, editor, files.chat_id, sse=False)

    assert (response.status_code, response.json()["status"]) == (200, "final"), response.text
    send_run, retry_run = script.runs
    assert (send_run.attachment_ids, retry_run.attachment_ids) == (expected, expected)
    assert (retry_run.user_message, retry_run.keywords) == (
        _FILES_MESSAGE,
        _TURN_KEYWORDS | {"attachments"},
    )
    answer = db.messages_of(files.chat_id)[-1]
    assert (answer["role"], answer["included_attachment_ids"]) == ("assistant", list(expected))


# ---------------------------------------------------------------------------
# 4. The first-exchange title rule of a send (Decision 4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["json", "sse"])
def test_chat_retry_title_untitled_chat_whose_only_turn_failed_is_titled_after_the_retry(
    world: World, client: TestClient, agent: MagicMock, script: _Script, mode: str
) -> None:
    """An untitled ``auto`` chat whose only turn failed: a successful retry makes the one
    title call (``max_tokens`` 40) from the retried message and the new reply and stores
    the model's title (JSON: after the response; streamed: sent as ``title`` between
    ``message_saved`` and ``done``)."""
    llm = _TitleLLM()
    agent._llm = llm
    editor = world.a["editor"]
    db = world.db
    chat_id = _failed_chat(db, editor, titled=False, earlier=False, message=_TITLE_MESSAGE)
    script.queue(_reply(_TITLE_REPLY))

    response = _retry(client, editor, chat_id, sse=mode == "sse")

    if mode == "sse":
        assert _stream(response)[-3:] == [
            _saved(db, chat_id, "complete"),
            ("title", {"title": _TITLE}),
            _DONE,
        ]
    else:
        assert response.status_code == 200, response.text
        assert "title" not in response.json()
    assert _chat_title(db, chat_id) == (_TITLE, "auto")
    assert llm.calls == [_TITLE_MAX_TOKENS]
    assert (_TITLE_MESSAGE in llm.prompts[0], _TITLE_REPLY in llm.prompts[0]) == (True, True)


@pytest.mark.parametrize("case", ["earlier_reply", "user_title"])
def test_chat_retry_title_chat_with_an_earlier_reply_or_a_user_title_gets_none(
    world: World, client: TestClient, agent: MagicMock, case: str
) -> None:
    """An untitled ``auto`` chat with an earlier assistant reply, and a user-titled chat
    whose only turn failed: the retry runs and replaces the failed turn, with no title
    call and the title unchanged."""
    llm = _TitleLLM()
    agent._llm = llm
    editor = world.a["editor"]
    db = world.db
    if case == "earlier_reply":
        chat_id = _failed_chat(db, editor, titled=False, earlier=True)
        expected_rows = [*_EARLIER_ROWS, ("user", _MESSAGE, "complete")]
    else:
        chat_id = _failed_chat(db, editor, titled=True, earlier=False)
        expected_rows = [("user", _MESSAGE, "complete")]
    title_before = _chat_title(db, chat_id)

    response = _retry(client, editor, chat_id, sse=False)

    assert (response.status_code, response.json()["status"]) == (200, "final"), response.text
    assert _stored(db, chat_id) == [*expected_rows, ("assistant", _REPLY, "complete")]
    assert (llm.calls, _chat_title(db, chat_id)) == ([], title_before)


# ---------------------------------------------------------------------------
# 5. Errors: the OpenAPI entry and every documented body (criterion "Errors", Decision 5)
# ---------------------------------------------------------------------------


def _examples(responses: dict[str, Any], status: str) -> dict[str, Any]:
    """The named JSON examples of a documented response: name -> value."""
    media = responses.get(status, {}).get("content", {}).get(_JSON, {})
    return {name: item.get("value") for name, item in media.get("examples", {}).items()}


def _retry_operation(app: FastAPI) -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"].get(_ROUTE, {}).get("post", {})
    return operation


def test_chat_retry_openapi_documents_the_route_its_models_and_codes(client: TestClient) -> None:
    """POST /api/chats/{chat_id}/retry: no request body; the 200 is the ChatResponse
    beside ``text/event-stream``; the named examples are exactly the route's codes; the
    422 describes the validation list and its three codes, the 429 ``rate_limit``."""
    operation = _retry_operation(client.app)  # type: ignore[arg-type]
    responses: dict[str, Any] = operation.get("responses", {})
    content = responses.get("200", {}).get("content", {})
    described = {status: responses.get(status, {}).get("description", "") for status in responses}

    assert (
        bool(operation),
        "requestBody" in operation,
        set(content),
        content.get(_JSON, {}).get("schema"),
    ) == (
        True,
        False,
        {_JSON, "text/event-stream"},
        {"$ref": "#/components/schemas/ChatResponse"},
    )
    assert {status: sorted(_examples(responses, status)) for status in responses} == {
        "200": [],
        "404": ["chat_not_found"],
        "409": ["not_retryable", "run_active"],
        "422": sorted(_CODES_422),
        "429": ["rate_limit"],
        "503": ["chats_busy", "storage_unavailable"],
    }
    assert (
        [code for code in _CODES_422 if code in described.get("422", "")],
        "validation" in described.get("422", "").lower(),
        "rate_limit" in described.get("429", ""),
    ) == (list(_CODES_422), True, True)


@contextlib.asynccontextmanager
async def _reached(
    world: World, monkeypatch: pytest.MonkeyPatch, code: str, example: Any
) -> AsyncIterator[uuid.UUID]:
    """Set up the Editor's chat for which a retry answers ``code``; yield its id.

    The two context codes seed the documented example's own files (ids, estimates,
    sizes) on the failed message, so the answered report is comparable with it.
    """
    db = world.db
    editor = world.a["editor"]
    if code == "chat_not_found":
        yield uuid.uuid4()
        return
    if code == "not_retryable":
        chat_id = db.add_chat(editor.user_id, title=_USER_TITLE, title_source="user")
        db.add_chat_message(chat_id, "user", _MESSAGE)
        db.add_chat_message(chat_id, "assistant", _REPLY)
        yield chat_id
        return
    chat_id = db.add_chat(editor.user_id, title=_USER_TITLE, title_source="user")
    user = db.add_chat_message(chat_id, "user", _MESSAGE)
    if code in _CONTEXT_DETAILS:
        for minute, item in enumerate(example["report"]["attachments"], start=1):
            _file(
                db,
                chat_id,
                minute=minute,
                message_id=user,
                attachment_id=uuid.UUID(item["attachment_id"]),
                tokens=item["token_estimate"],
                size=item["derived_bytes"],
            )
    elif code == "image_input_unsupported":
        _file(db, chat_id, minute=1, message_id=user, image=True)
        _image_input_off(monkeypatch, db)
    elif code == "storage_unavailable":
        _file(db, chat_id, minute=1, message_id=user, derived=False)
    db.add_chat_message(chat_id, "assistant", _FAILURE, status="error")
    if code == "run_active":
        # A run of the chat is going: the test holds the chat as a run does.
        async with server._chat_runtime.hold(chat_id, editor.user_id, wait=False):
            yield chat_id
        return
    if code == "rate_limit":
        # The Editor's one runtime entry holds a pending confirmation of another chat.
        monkeypatch.setattr(
            server,
            "_chat_runtime",
            ChatRuntime(max_entries=64, idle_s=900.0, max_entries_per_user=1),
        )
        seed_pending_confirmation(editor, _failed_chat(db, editor), "confirm-245-bound")
    elif code == "chats_busy":
        # Both entries hold other users' pending confirmations: nothing to evict.
        monkeypatch.setattr(server, "_chat_runtime", ChatRuntime(max_entries=2, idle_s=900.0))
        for index, owner in enumerate((world.a["org_admin"], world.b["editor"])):
            seed_pending_confirmation(owner, _failed_chat(db, owner), f"confirm-245-full-{index}")
    yield chat_id


@pytest.mark.parametrize(
    ("status", "code"), _DOCUMENTED, ids=[f"{status}-{code}" for status, code in _DOCUMENTED]
)
async def test_chat_retry_refusal_is_the_documented_json_body_in_both_modes(
    world: World,
    agent: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    code: str,
) -> None:
    """Each documented example is the body the route answers in its case (the contract's
    body for the fixed codes), to a JSON and to a streamed request alike (the streamed
    one ``application/json`` too): no run, and nothing of the chat, its messages, its
    attachment rows or the files on disk changed (a refused retry keeps the failed
    turn)."""
    app = make_app(agent)
    example = _examples(_retry_operation(app).get("responses", {}), status).get(code)
    assert example is not None, f"no documented {status} example {code}"
    editor = world.a["editor"]

    async with _async_client(app) as http, _reached(world, monkeypatch, code, example) as chat_id:
        before = _state(world.db, chat_id)
        as_json = await http.post(_url(chat_id), headers=editor.cookie)
        streamed = await http.post(_url(chat_id), headers={**editor.cookie, **_SSE})
        after = _state(world.db, chat_id)

    assert (as_json.status_code, as_json.json()) == (int(status), example)
    assert (streamed.status_code, streamed.headers.get("content-type"), streamed.json()) == (
        int(status),
        _JSON,
        example,
    )
    if code in _CONTEXT_DETAILS:
        assert (example["detail"], example["reason"]) == (_CONTEXT_DETAILS[code], code)
    else:
        assert example == _LITERAL_BODIES[code]
    assert agent.run.await_count == 0
    assert after == before
