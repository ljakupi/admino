"""HTTP spec of GH-190's context budget on the JSON chat routes (writer W4a).

Issue #190, Decisions 1 to 6, 8 and 14, amendment A1; contract C1, C2, C4 to C6 and
C11. Tracker #139 §5: nothing stored, run or audited on a refusal, no file name or
content in any body or log record, content-free counts only.

Routes: ``POST /api/chats/{chat_id}/messages`` (the send), ``POST /api/message`` (the
legacy route) and ``POST /api/confirm/{confirmation_id}`` (an approval and a denial),
answered as JSON. The streamed answers are tests/test_chat_stream_api.py's (W4b); the
new routes and ``GET /api/chats/{chat_id}`` are W5's.

Harness: the app from ``create_app()`` on the FakeDb world of tests/tenancy_world.py
(orgs A and B, real session cookies), the attachments root under ``tmp_path`` and the
derived files written with tests/attachment_derived.py. The app's config is a real
``AppConfig`` with ``llm.max_response_tokens`` (the reserved output) and a
``context`` section (margin, byte cap, tool-result cap); the stored platform
``llm.max_input_tokens`` and ``limits.max_context_messages`` are set in the settings
cache and the platform row. By default the model takes 10_001 input tokens, the
margin is 10 % (the budget is 10_001 - ceil(1000.1) = 9000), the reserved output is
1000 (8000 tokens for the attachments) and the byte cap is 1 MiB. Two agents:
- a stub bound to ``Agent.run``'s signature (``attachments`` included): it records
  every call and answers the history it got plus the turn's messages (the request's
  tool result plus a reply for a resumed confirmation), optionally with a
  ``context_notice``;
- the REAL ``Agent`` with a fake LLM (Swiss provider, records each call's messages,
  tools and the statement count), ``main._build_tool_call_recorder()``, a fixed clock
  and an isolated tool registry.

What is pinned:
- Send rule (Decision 5): the slot's files (the chat's earlier active ones in the
  order they were sent, then the message's own active ones in upload order) whose
  ``token_estimate`` sum is above ``budget - reserved`` are the 422 ``{"detail":
  "The chat's attachments don't fit the model's context", "reason":
  "context_overflow", "report": ...}``; else, with a ``derived_bytes`` sum above
  ``context.max_attachment_mb_per_turn`` MiB (Decision 6), the 422 ``{"detail": "The
  chat's attachments are too large for one turn", "reason":
  "attachment_bytes_exceeded", "report": ...}``. The report: the slot's ids in slot
  order with their estimate and bytes (NULL as 0), both sums, ``available_tokens``
  (``budget - reserved``, at least 0) and ``max_bytes``. Exactly at the token limit
  and at the byte cap the turn runs (the run gets each file's estimate); tokens are
  checked before bytes. Both come before any derived file is read (the readers are
  never called), so a missing derived directory or an image while the model takes
  none is that 422, not GH-189's 503 or 422. Excluded files don't count and aren't
  listed; an excluded file the message lists is linked to it but not sent.
- Every refusal (send, legacy, approval; JSON and a streamed send or approval):
  exactly that body, no run, every table and the chat runtime unchanged (nothing
  stored, linked or audited), the pending confirmation kept (an approval's included:
  it isn't consumed), no file name or text in the body or any log record. A denial
  reads no attachment and is never refused.
- ``context_usage`` (Decision 4) on every JSON answer (turn, legacy, approval,
  denial): ``used`` = instructions + the chat's active attachment estimates (a
  denial's from the rows) + the history after the budget (the loaded messages plus
  the ones the turn stored, newest turns kept, whole turns) + the reserved output,
  ``max`` = the budget, ``percent`` = ``used * 100 // max`` (above 100 only when the
  attachments alone don't fit). The instructions are
  ``context_budget.instructions_tokens(prompt_context, policy, now=server._utc_now())``:
  the real value grows when the org adds instructions.
- ``context_notice`` (Decision 3): None without drops; the run's
  ``result.context_notice`` is echoed; the real agent with a small budget drops the
  oldest turns and reports their counts.
- Load limit (Decision 8): a stored ``max_context_messages`` of 0 makes every turn
  read the latest 200 messages (``context_budget.HISTORY_LOAD_LIMIT``, the turn read's
  ``$4``), a positive cap that many: on a send, the legacy route, an approval and a
  denial.
- Run config (C11): the run's ``agent_config`` carries the stored platform
  ``max_input_tokens``, the config's reserved output, margin and tool-result cap, and
  the stored cap (0 included).
- A1 (Decision 9): a turn whose only wrapped tool result is cut past its begin marker
  sets the chat's sticky ``external_content`` flag, the next turn's side effect is
  escalated to a confirmation, and the first exchange's title is the fallback.
- Decision 2: a run the real agent ends with ``context_too_long`` (no LLM call) is
  stored and answered like any coded LLM error.
- OpenAPI: the 422 of the message, legacy and confirm routes names both codes.
- Decision 14 (GH-244): a send in a chat with attachments still makes 3 statements
  before its LLM call (the session, the turn setup, the turn read T2''); with a file
  listed one more (A8''), before the hold.

New names (``admino.context_budget``, ``AgentResult.context_notice``, ``active``) are
looked up at test time, so the file collects before GH-190 is implemented.

Security notes:
- Every id, name, text and number here is a fixed fake value under ``tmp_path``. No
  network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest
from pydantic import BaseModel, Field

from admino import (
    attachment_context,
    chat_titles,
    org_permissions,
    scoped_settings,
    server,
    untrusted,
)
from admino import main as main_module
from admino.agent import Agent
from admino.config import AppConfig
from admino.llm import LLMResponse, LLMStreamDelta
from admino.models import AgentConfig, AgentResult, LLMMessage, PendingConfirmation, ToolCall
from admino.server import create_app
from admino.tenancy import TenantContext
from admino.tokens import estimate_text_tokens
from admino.tools import registry
from tests.attachment_derived import png_bytes, write_derived
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, PUBLIC_URL, FakeDb, norm, plain
from tests.tenancy_world import (
    build_world,
    chat_runtime_state,
    make_client,
    stub_agent,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import AsyncIterator, Callable, Sequence
    from pathlib import Path
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.db_fakes import Call
    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_INPUT: Final = 10_001
_MARGIN: Final = 10
_BUDGET: Final = 9000  # 10_001 - ceil(10_001 * 10 / 100)
_RESERVED: Final = 1000
_AVAILABLE: Final = 8000  # _BUDGET - _RESERVED
_MIB: Final = 1_048_576
_MAX_BYTES: Final = _MIB  # context.max_attachment_mb_per_turn = 1
_INSTRUCTIONS: Final = 500  # the patched instructions_tokens

_OVERFLOW_DETAIL: Final = "The chat's attachments don't fit the model's context"
_BYTES_DETAIL: Final = "The chat's attachments are too large for one turn"
_TOO_LONG_REPLY: Final = (
    "This message doesn't fit the model's context, even without the earlier messages. "
    "Shorten it or exclude some attachments."
)
_TOOL_RESULT_MARKER: Final = "\n[tool result truncated to fit the context]"
_STORAGE_UNAVAILABLE: Final = {
    "detail": "Attachment storage is unavailable",
    "reason": "storage_unavailable",
}
_HISTORY_LOAD_LIMIT: Final = 200

_SSE: Final = {"Accept": "text/event-stream"}
_MESSAGE: Final = "Compare the attached ledgers"
_REPLY: Final = "Here is the comparison of the ledgers."
_RESUMED: Final = "Created the offsite event."
_DENIED_RESULT: Final = "Tool call denied by the user."
_DENIAL: Final = "Action google_calendar.create was denied."
_EARLIER: Final = "Earlier question about the ledgers"
_EARLIER_REPLY: Final = "Earlier answer about the ledgers"
_REQUEST: Final = "Book the ledger review offsite"
_LEGACY: Final = "legacy-session-190-plover"
_CONFIRMATION_ID: Final = "confirm-190-plover"
_T0: Final = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
_NOW: Final = datetime(2026, 10, 9, 9, 30, tzinfo=UTC)
_BLOCK_ID: Final = "call-190-book"
_BOOK_CALL: Final = ToolCall(
    tool="google_calendar", action="create", args={"title": "Review"}, tool_call_id=_BLOCK_ID
)
_BOOK_BLOCK: Final = {
    "type": "tool_use",
    "id": _BLOCK_ID,
    "name": "google_calendar.create",
    "input": {"title": "Review"},
}

# Log and body needles: every seeded file name holds _NAME_MARK, every derived text
# _TEXT_MARK.
_NAME_MARK: Final = "heron-ledger-budget"
_TEXT_MARK: Final = "kestrel-total-budget"

_TURN_RE: Final = re.compile(r"\bfrom chats c left join lateral\b")
_TABLE_RE: Final = re.compile(
    r"\b(sessions|permissions|org_settings|users|chats|chat_messages|attachments)\b"
)
_T1_TABLES: Final = frozenset({"permissions", "org_settings", "users", "chats"})
_T2_TABLES: Final = frozenset({"chats", "chat_messages"})
# Contract C5 (T2'') and C6 (A8''), verbatim.
_T2_SQL: Final = """
    SELECT c.id, c.org_id, c.owner_user_id, c.title, c.title_source, c.external_content,
           c.created_at, c.last_activity_at,
           ARRAY(
               SELECT ARRAY[a.id::text, a.filename, a.kind, a.page_count::text,
                            a.token_estimate::text, a.derived_bytes::text]
               FROM attachments a
               JOIN chat_messages am ON am.id = a.message_id AND am.org_id = a.org_id
               WHERE a.chat_id = c.id AND a.org_id = c.org_id
                 AND a.owner_user_id = c.owner_user_id
                 AND a.status = 'ready' AND a.active AND a.deleted_at IS NULL
               ORDER BY am.seq, a.created_at, a.id
           ) AS attachment_rows,
           m.role, m.content, m.tool_use_blocks, m.tool_call_id
    FROM chats c
    LEFT JOIN LATERAL (
        SELECT seq, role, content, tool_use_blocks, tool_call_id
        FROM chat_messages
        WHERE chat_id = c.id AND org_id = c.org_id
        ORDER BY seq DESC
        LIMIT $4
    ) m ON true
    WHERE c.id = $1 AND c.org_id = $2 AND c.owner_user_id = $3 AND c.deleted_at IS NULL
    ORDER BY m.seq DESC
"""
_A8_SQL: Final = """
    SELECT id, message_id, status, filename, kind, page_count, token_estimate, derived_bytes, active
    FROM attachments
    WHERE id = ANY($1::uuid[]) AND chat_id = $2 AND org_id = $3 AND owner_user_id = $4
      AND deleted_at IS NULL
    ORDER BY created_at, id
"""

# The attributes every LogRecord has; anything else came in through ``extra=``.
_STANDARD_RECORD_ATTRS: Final = frozenset(
    vars(logging.LogRecord("n", logging.INFO, "p", 1, "m", None, None))
) | {"message", "asctime"}


def _at(minutes: int) -> datetime:
    return _T0 + timedelta(minutes=minutes)


def _text(tokens: int, tag: str) -> str:
    """ASCII text without digits of exactly ``tokens`` estimated tokens (4 bytes each)."""
    assert not any(char.isdigit() for char in tag)
    text = (tag + " " + "q" * (4 * tokens))[: 4 * tokens]
    assert estimate_text_tokens(text) == tokens
    return text


# ---------------------------------------------------------------------------
# The expected usage (contract C1's formulas, computed independently)
# ---------------------------------------------------------------------------


def _message_tokens(message: LLMMessage) -> int:
    """4 + the text's estimate + the tool-call blocks as compact JSON."""
    content = message.content
    assert isinstance(content, str)
    total = 4 + estimate_text_tokens(content)
    if message.tool_use_blocks:
        blocks = json.dumps(message.tool_use_blocks, ensure_ascii=False, separators=(",", ":"))
        total += estimate_text_tokens(blocks)
    return total


def _turns(messages: Sequence[LLMMessage]) -> list[list[LLMMessage]]:
    """A turn starts at every user message; the messages before the first form one."""
    groups: list[list[LLMMessage]] = []
    for message in messages:
        if message.role == "user" or not groups:
            groups.append([message])
        else:
            groups[-1].append(message)
    return groups


def _usage(
    history: Sequence[LLMMessage],
    *,
    attachments: int,
    instructions: int = _INSTRUCTIONS,
    reserved: int = _RESERVED,
    budget: int = _BUDGET,
) -> dict[str, int]:
    """The fixed part plus the longest run of the newest whole turns that fits."""
    used = instructions + attachments + reserved
    if used <= budget:
        for group in reversed(_turns(history)):
            cost = sum(_message_tokens(message) for message in group)
            if used + cost > budget:
                break
            used += cost
    return {"used": used, "max": budget, "percent": used * 100 // budget}


def _user(content: str) -> LLMMessage:
    return LLMMessage(role="user", content=content)


def _assistant(content: str, **fields: Any) -> LLMMessage:
    return LLMMessage(role="assistant", content=content, **fields)


def _tool(content: str, call_id: str = _BLOCK_ID) -> LLMMessage:
    return LLMMessage(role="tool", content=content, tool_call_id=call_id)


# ---------------------------------------------------------------------------
# The stub agent
# ---------------------------------------------------------------------------


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
    """``Agent.run``'s signature (no GH-190 keyword); every stub call binds to it."""


class _Script:
    """The stub agent's ``run``: records each call and answers one final reply.

    A turn answers the user message plus ``_REPLY``; a resumed confirmation the
    approved call's tool result plus ``_REPLY``. ``notice`` (when set) is the result's
    ``context_notice``.
    """

    def __init__(self) -> None:
        self.runs: list[dict[str, Any]] = []
        self.notice: dict[str, int] | None = None

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        bound = inspect.signature(_run_signature).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        received = list(arguments["history"])
        arguments["history"] = [message.model_copy(deep=True) for message in received]
        self.runs.append(arguments)
        pending = arguments["pending_confirmation"]
        new = (
            [_tool(_RESUMED, pending.tool_call.tool_call_id), _assistant(_REPLY)]
            if pending is not None
            else [_user(arguments["user_message"]), _assistant(_REPLY)]
        )
        payload: dict[str, Any] = {
            "status": "final",
            "response": _REPLY,
            "history": [*received, *new],
            "tool_calls": [],
            "pending_confirmation": None,
        }
        if self.notice is not None:
            payload["context_notice"] = self.notice
        return AgentResult.model_validate(payload)


# ---------------------------------------------------------------------------
# The real agent's fake LLM
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _LLMCall:
    """One LLM call: its kind, messages and tools (copied), the statements so far."""

    kind: str  # "chat" or "title"
    messages: tuple[LLMMessage, ...]
    tools: tuple[dict[str, Any], ...]
    statements: int


class _FakeLLM:
    """A Swiss client: each agent call answers the next queued response, then ``_REPLY``;
    a call with ``max_tokens`` is a title call."""

    provider = "infomaniak"

    def __init__(self, db: FakeDb) -> None:
        self._db = db
        self.calls: list[_LLMCall] = []
        self.queue: list[LLMResponse] = []

    def ask(self, call: ToolCall) -> None:
        self.queue.append(LLMResponse(content="", tool_calls=[call]))

    def kinds(self) -> list[str]:
        return [call.kind for call in self.calls]

    def _record(self, kind: str, messages: list[LLMMessage], tools: Any) -> None:
        copied = tuple(message.model_copy(deep=True) for message in messages)
        self.calls.append(_LLMCall(kind, copied, tuple(tools or ()), len(self._db.calls)))

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if max_tokens is not None:
            self._record("title", messages, tools)
            return LLMResponse(content="Model title")
        self._record("chat", messages, tools)
        return self.queue.pop(0) if self.queue else LLMResponse(content=_REPLY)

    def chat_stream(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        self._record("stream", messages, tools)
        return self._play(self.queue.pop(0) if self.queue else LLMResponse(content=_REPLY))

    async def _play(self, response: LLMResponse) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        if response.content:
            yield LLMStreamDelta(content=response.content)
        yield response

    async def close(self) -> None:
        """Nothing to close."""


class _KeyArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)


class _StoreArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    value: str = Field(min_length=1, max_length=200)


@dataclass
class _Real:
    """The app around the real agent: its client, the fake LLM, the handlers that ran."""

    client: TestClient
    llm: _FakeLLM
    ran: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Fixtures and the app
# ---------------------------------------------------------------------------


def _app_config(
    *, reserved: int = _RESERVED, margin: int = _MARGIN, mb: int = 1, tool_cap: int = 8000
) -> AppConfig:
    """A real config: localhost, the reserved output and the ``context`` section."""
    return AppConfig.model_validate(
        {
            "server": {"host": "127.0.0.1", "port": 8000, "public_url": PUBLIC_URL},
            "llm": {
                "provider": "anthropic",
                "anthropic_model": "claude-sonnet-4-6",
                "max_response_tokens": reserved,
            },
            "context": {
                "safety_margin_percent": margin,
                "max_attachment_mb_per_turn": mb,
                "max_tool_result_tokens": tool_cap,
            },
        }
    )


def _platform(
    monkeypatch: pytest.MonkeyPatch,
    db: FakeDb,
    *,
    max_input_tokens: int = _MAX_INPUT,
    max_context_messages: int = 20,
    image_input: bool = True,
) -> None:
    """The stored platform settings (validated): in the settings cache and the row."""
    stored = default_test_platform_settings()
    data = stored.model_dump()
    data["llm"].update(max_input_tokens=max_input_tokens, image_input=image_input)
    data["limits"]["max_context_messages"] = max_context_messages
    monkeypatch.setattr(scoped_settings, "_platform_cache", type(stored).model_validate(data))
    row = db.platform_row()
    assert row is not None
    row.update(
        max_input_tokens=max_input_tokens,
        image_input=image_input,
        max_context_messages=max_context_messages,
    )


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    return tmp_path / "attachments"


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, root: Path) -> World:
    """Orgs A and B (OA/ED each) behind the fake database, the attachments root at
    ``root`` and the default platform of this file (budget 9000)."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, root)
    _platform(monkeypatch, db)
    return built


@pytest.fixture()
def script() -> _Script:
    return _Script()


@pytest.fixture()
def agent(script: _Script) -> MagicMock:
    stub = stub_agent()
    stub.run.side_effect = script.run
    return stub


def _stub_client(agent: MagicMock, **config: int) -> TestClient:
    """The app around the stub agent; an escaping exception is the app's 500."""
    app = create_app(agent=agent, config=_app_config(**config))
    return make_client(app, raise_server_exceptions=False)


@pytest.fixture()
def client(world: World, agent: MagicMock) -> TestClient:
    return _stub_client(agent)


@pytest.fixture()
def instructions(monkeypatch: pytest.MonkeyPatch) -> int:
    """``admino.context_budget.instructions_tokens`` answers ``_INSTRUCTIONS`` (the server
    calls it through the module attribute)."""
    from admino import context_budget

    monkeypatch.setattr(context_budget, "instructions_tokens", lambda *_a, **_k: _INSTRUCTIONS)
    return _INSTRUCTIONS


def _real(
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    *,
    wrapped_recall: bool = False,
    **config: int,
) -> _Real:
    """The app around a REAL Agent (main's recorder, fixed clock) and the fake LLM, in an
    unfrozen registry restored afterwards: empty, or (``wrapped_recall``) memory.recall
    answering 4000 filler characters then a wrapped email and memory.store (a side
    effect, allowed by default)."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    ran: list[str] = []
    if wrapped_recall:

        async def recall(args: _KeyArgs, **_: Any) -> str:
            ran.append("memory.recall")
            mail = untrusted.wrap("email", "probe message", "Mail body of the probe")
            return "y" * 4000 + " " + mail

        async def store(args: _StoreArgs, **_: Any) -> str:
            ran.append("memory.store")
            return "Stored the note."

        register: Any = registry.register_tool
        register("memory", "recall", "Recall a note (GH-190)", _KeyArgs, side_effect=False)(recall)
        register("memory", "store", "Store a note (GH-190)", _StoreArgs, side_effect=True)(store)
    llm = _FakeLLM(world.db)
    agent = Agent(
        llm_client=llm,  # type: ignore[arg-type]
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
        clock=lambda: _NOW,
    )
    app = create_app(agent=agent, config=_app_config(**config))
    return _Real(client=make_client(app, raise_server_exceptions=False), llm=llm, ran=ran)


# ---------------------------------------------------------------------------
# Helpers: chats, files, requests
# ---------------------------------------------------------------------------


def _chat(db: FakeDb, account: Account, **fields: Any) -> uuid.UUID:
    """A user-titled chat of ``account`` (no title step runs after a turn)."""
    fields.setdefault("title", "Ledgers 190")
    fields.setdefault("title_source", "user")
    return db.add_chat(account.user_id, **fields)


def _org_of(db: FakeDb, chat_id: uuid.UUID) -> uuid.UUID:
    chat = db.chat_row(chat_id)
    assert chat is not None
    return plain(chat["org_id"])


def _file(
    db: FakeDb,
    root: Path,
    chat_id: uuid.UUID,
    *,
    tokens: int | None,
    size: int | None,
    minute: int,
    message_id: uuid.UUID | None = None,
    active: bool = True,
    image: bool = False,
    derived: bool = True,
) -> uuid.UUID:
    """A ready attachment of the chat (its stored ``token_estimate`` and
    ``derived_bytes``), named after ``_NAME_MARK``, with its derived files unless
    ``derived`` is False: a text file, or a PNG (``image``)."""
    kind = "png" if image else "txt"
    fields: dict[str, Any] = {} if active else {"active": False}
    file_id = db.add_attachment(
        chat_id,
        filename=f"{_NAME_MARK}-{minute}.{kind}",
        kind=kind,
        status="ready",
        token_estimate=tokens,
        derived_bytes=size,
        message_id=message_id,
        created_at=_at(minute),
        **fields,
    )
    if derived:
        parts: list[tuple[Any, ...]] = (
            [("image", png_bytes(), "image/png", None, None)]
            if image
            else [("text", f"Ledger {_TEXT_MARK}", None)]
        )
        write_derived(root, _org_of(db, chat_id), file_id, kind=kind, parts=parts, page_count=None)
    return file_id


def _item(file_id: uuid.UUID, tokens: int, size: int) -> dict[str, Any]:
    return {"attachment_id": str(file_id), "token_estimate": tokens, "derived_bytes": size}


def _refusal(reason: str, items: list[dict[str, Any]], *, available: int = _AVAILABLE) -> Any:
    """The 422 body of a slot whose files don't fit (``reason``), over ``items``."""
    return {
        "detail": _OVERFLOW_DETAIL if reason == "context_overflow" else _BYTES_DETAIL,
        "reason": reason,
        "report": {
            "attachments": items,
            "attachment_tokens": sum(item["token_estimate"] for item in items),
            "available_tokens": available,
            "attachment_bytes": sum(item["derived_bytes"] for item in items),
            "max_bytes": _MAX_BYTES,
        },
    }


def _awaiting(db: FakeDb, chat_id: uuid.UUID) -> uuid.UUID:
    """The chat's request (returned) and the assistant's unanswered tool_use."""
    request = db.add_chat_message(chat_id, "user", _REQUEST)
    db.add_chat_message(
        chat_id, "assistant", "", tool_use_blocks=[_BOOK_BLOCK], status="awaiting_confirmation"
    )
    return request


def _pending(account: Account, chat_id: uuid.UUID, confirmation_id: str) -> PendingConfirmation:
    """A live confirmation of ``_BOOK_CALL`` in ``server._chat_runtime`` (after the app)."""
    now = datetime.now(UTC)
    pending = PendingConfirmation(
        confirmation_id=confirmation_id,
        session_id=str(chat_id),
        tool_call=_BOOK_CALL,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    server._chat_runtime.set_pending(chat_id, account.user_id, pending)
    return pending


def _send(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    ids: Sequence[uuid.UUID] = (),
    *,
    message: str = _MESSAGE,
    sse: bool = False,
) -> httpx.Response:
    body: dict[str, Any] = {"message": message}
    if ids:
        body["attachment_ids"] = [str(file_id) for file_id in ids]
    headers = {**account.cookie, **(_SSE if sse else {})}
    return client.post(f"/api/chats/{chat_id}/messages", headers=headers, json=body)


def _legacy(client: TestClient, account: Account, message: str = _MESSAGE) -> httpx.Response:
    return client.post(
        "/api/message", headers=account.cookie, json={"message": message, "session_id": _LEGACY}
    )


def _confirm(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    confirmation_id: str = _CONFIRMATION_ID,
    *,
    approved: bool,
    sse: bool = False,
) -> httpx.Response:
    headers = {**account.cookie, **(_SSE if sse else {})}
    return client.post(
        f"/api/confirm/{confirmation_id}",
        headers=headers,
        json={"confirmation_id": confirmation_id, "approved": approved, "chat_id": str(chat_id)},
    )


def _answer(response: httpx.Response) -> tuple[int, Any]:
    content_type = response.headers.get("content-type", "").split(";")[0]
    body = response.json() if content_type == "application/json" else response.text
    return response.status_code, body


def _state(world: World) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Every table and what the chat runtime holds."""
    return world.db.snapshot(), chat_runtime_state(world.db)


def _changed(world: World, before: tuple[dict[str, Any], dict[str, Any] | None]) -> list[str]:
    """The tables (and ``runtime``) that differ from ``before``."""
    tables, runtime = _state(world)
    changed = [name for name, rows in tables.items() if rows != before[0].get(name)]
    return [*changed, "runtime"] if runtime != before[1] else changed


def _record_text(record: logging.LogRecord) -> str:
    """Everything a record carries: message, arguments, exception, ``extra=`` fields."""
    parts = [str(record.msg), record.getMessage(), repr(record.args)]
    if record.exc_info:
        parts.append(logging.Formatter().formatException(record.exc_info))
    parts.extend(str(value) for value in (record.exc_text, record.stack_info) if value)
    parts.extend(
        repr(value) for key, value in vars(record).items() if key not in _STANDARD_RECORD_ATTRS
    )
    return "\n".join(parts)


def _leaks(caplog: pytest.LogCaptureFixture, needles: Sequence[str]) -> list[str]:
    """The app's records (not the client's) holding any needle."""
    return [
        record.getMessage()
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore", "asyncio", "PIL"))
        and any(needle in _record_text(record) for needle in needles)
    ]


def _refuse_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Make both derived-file readers fail if called; the calls made (in order)."""
    calls: list[str] = []

    def read_content(*_args: Any, **_kwargs: Any) -> Any:
        calls.append("read_content")
        raise AssertionError("a derived file was read")

    async def load_contents(*_args: Any, **_kwargs: Any) -> Any:
        calls.append("load_contents")
        raise AssertionError("the derived files were loaded")

    monkeypatch.setattr(attachment_context, "read_content", read_content)
    monkeypatch.setattr(attachment_context, "load_contents", load_contents)
    return calls


def _passed(script: _Script) -> list[tuple[uuid.UUID, Any]]:
    """The one run's attachments: (id, token_estimate) in slot order."""
    (run,) = script.runs
    return [
        (plain(item.id), getattr(item, "token_estimate", "missing")) for item in run["attachments"]
    ]


def _linked_to(db: FakeDb, file_id: uuid.UUID) -> uuid.UUID | None:
    row = db.attachment_row(file_id)
    assert row is not None
    return None if row["message_id"] is None else plain(row["message_id"])


def _turn_limits(db: FakeDb, since: int) -> list[Any]:
    """The ``$4`` (load limit) of every turn read (T2) after the first ``since`` calls."""
    return [call.args[3] for call in db.calls[since:] if _TURN_RE.search(call.normalized)]


def _tenant(account: Account) -> TenantContext:
    assert account.org_id is not None
    return TenantContext(org_id=account.org_id, user_id=account.user_id, role=account.role)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1. The refusals: exact body, nothing changed, on every JSON route (Decisions 5, 6)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Scene:
    """A refused request: how to send it, the chat, the pending confirmation, the body."""

    send: Callable[[], httpx.Response]
    chat_id: uuid.UUID
    pending: PendingConfirmation
    expected: Any


# reason -> the two files' (tokens, bytes): one over the token limit, or over the cap.
_OVER: Final[dict[str, tuple[tuple[int, int], tuple[int, int]]]] = {
    "context_overflow": ((5000, 100), (3001, 200)),
    "attachment_bytes_exceeded": ((10, 600_000), (20, 448_577)),
}

_REFUSALS: Final = (
    ("send", "context_overflow"),
    ("send", "attachment_bytes_exceeded"),
    ("send-sse", "context_overflow"),
    ("legacy", "context_overflow"),
    ("legacy", "attachment_bytes_exceeded"),
    ("approve", "context_overflow"),
    ("approve", "attachment_bytes_exceeded"),
    ("approve-sse", "attachment_bytes_exceeded"),
)


def _scene(world: World, client: TestClient, root: Path, route: str, reason: str) -> _Scene:
    """The Editor of org A's chat awaiting a confirmation, whose request sent the first
    file (and, but for a send, the second); a send lists the second (unsent)."""
    db = world.db
    editor = world.a["editor"]
    legacy = route == "legacy"
    chat_id = _chat(db, editor, legacy_session_id=_LEGACY if legacy else None)
    request = _awaiting(db, chat_id)
    (tokens_1, bytes_1), (tokens_2, bytes_2) = _OVER[reason]
    first = _file(db, root, chat_id, tokens=tokens_1, size=bytes_1, minute=0, message_id=request)
    listed = route.startswith("send")
    second = _file(
        db,
        root,
        chat_id,
        tokens=tokens_2,
        size=bytes_2,
        minute=1,
        message_id=None if listed else request,
    )
    pending = _pending(editor, chat_id, _CONFIRMATION_ID)
    sse = route.endswith("-sse")
    send: Callable[[], httpx.Response]
    if listed:
        send = lambda: _send(client, editor, chat_id, [second], sse=sse)  # noqa: E731
    elif legacy:
        send = lambda: _legacy(client, editor)  # noqa: E731
    else:
        send = lambda: _confirm(client, editor, chat_id, approved=True, sse=sse)  # noqa: E731
    items = [_item(first, tokens_1, bytes_1), _item(second, tokens_2, bytes_2)]
    return _Scene(send, chat_id, pending, (422, _refusal(reason, items)))


@pytest.mark.parametrize(("route", "reason"), _REFUSALS, ids=[f"{r}-{c}" for r, c in _REFUSALS])
def test_chat_context_budget_refusal_is_the_exact_body_and_changes_nothing(
    world: World,
    client: TestClient,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    route: str,
    reason: str,
) -> None:
    """The fixed body with the report (slot order, sums, available tokens, cap) as JSON
    (also for a streamed request); no derived file read, no run; every table and the
    runtime unchanged (no message, link or audit row; the pending confirmation kept,
    an approval's not consumed); no file name or text in the body or any log record."""
    scene = _scene(world, client, root, route, reason)
    reads = _refuse_reads(monkeypatch)
    before = _state(world)
    caplog.set_level(logging.DEBUG)
    caplog.clear()

    response = scene.send()

    assert _answer(response) == scene.expected
    assert (reads, script.runs, _changed(world, before)) == ([], [], [])
    assert server._chat_runtime.get_pending(scene.chat_id) == scene.pending
    needles = (_NAME_MARK, _TEXT_MARK)
    assert ([n for n in needles if n in response.text], _leaks(caplog, needles)) == ([], [])


# ---------------------------------------------------------------------------
# 2. The boundaries and the order of the checks (Decisions 5, 6)
# ---------------------------------------------------------------------------

# case -> ((tokens, bytes) of the earlier file, of the listed file), the outcome.
_BOUNDARIES: Final[dict[str, tuple[tuple[int, int], tuple[int, int], str | None]]] = {
    "tokens-at-the-limit": ((5000, 100), (3000, 100), None),
    "tokens-one-over": ((5000, 100), (3001, 100), "context_overflow"),
    "bytes-one-under": ((10, 600_000), (10, 448_575), None),
    "bytes-at-the-cap": ((10, 600_000), (10, 448_576), None),
    "bytes-one-over": ((10, 600_000), (10, 448_577), "attachment_bytes_exceeded"),
    "tokens-before-bytes": ((5000, 600_000), (3001, 448_577), "context_overflow"),
}


@pytest.mark.parametrize("case", list(_BOUNDARIES))
def test_chat_context_budget_send_runs_up_to_the_limit_and_the_cap(
    world: World, client: TestClient, script: _Script, root: Path, case: str
) -> None:
    """An earlier sent file and a listed one: exactly at ``budget - reserved`` tokens and
    up to exactly 1 MiB the turn runs and the run gets both files with their stored
    estimates; one token or byte more is the 422 with the report; over both, the token
    refusal wins."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    earlier = db.add_chat_message(chat_id, "user", _EARLIER)
    db.add_chat_message(chat_id, "assistant", _EARLIER_REPLY)
    (tokens_1, bytes_1), (tokens_2, bytes_2), reason = _BOUNDARIES[case]
    first = _file(db, root, chat_id, tokens=tokens_1, size=bytes_1, minute=0, message_id=earlier)
    second = _file(db, root, chat_id, tokens=tokens_2, size=bytes_2, minute=1)

    response = _send(client, editor, chat_id, [second])

    if reason is None:
        assert response.status_code == 200, response.text
        assert _passed(script) == [(first, tokens_1), (second, tokens_2)]
    else:
        items = [_item(first, tokens_1, bytes_1), _item(second, tokens_2, bytes_2)]
        assert (_answer(response), script.runs) == ((422, _refusal(reason, items)), [])


def test_chat_context_budget_report_lists_the_active_files_in_slot_order_null_as_zero(
    world: World, client: TestClient, script: _Script, root: Path
) -> None:
    """Earlier messages sent E1 (second message) and E0 (first), plus an excluded X; the
    message lists N2, N1 (uploaded first, NULL estimate and bytes) and an excluded N3:
    the report names E0, E1, N1, N2 in that order (send order, then upload order), the
    NULLs as 0, and neither excluded file."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    first_message = db.add_chat_message(chat_id, "user", _EARLIER)
    db.add_chat_message(chat_id, "assistant", _EARLIER_REPLY)
    second_message = db.add_chat_message(chat_id, "user", "Second question about the ledgers")
    db.add_chat_message(chat_id, "assistant", "Second answer")
    e1 = _file(db, root, chat_id, tokens=2000, size=300, minute=0, message_id=second_message)
    e0 = _file(db, root, chat_id, tokens=1000, size=200, minute=1, message_id=first_message)
    _file(
        db, root, chat_id, tokens=9999, size=9999, minute=2, message_id=first_message, active=False
    )
    n1 = _file(db, root, chat_id, tokens=None, size=None, minute=3)
    n2 = _file(db, root, chat_id, tokens=5001, size=400, minute=4)
    n3 = _file(db, root, chat_id, tokens=9999, size=9999, minute=5, active=False)

    response = _send(client, editor, chat_id, [n3, n2, n1])

    items = [_item(e0, 1000, 200), _item(e1, 2000, 300), _item(n1, 0, 0), _item(n2, 5001, 400)]
    assert (_answer(response), script.runs) == ((422, _refusal("context_overflow", items)), [])


def test_chat_context_budget_available_tokens_are_never_negative(
    world: World,
    agent: MagicMock,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Max input 1000 (budget 900) under a reserved output of 1000: ``available_tokens``
    is 0, so a file of one token is refused while a file without an estimate runs."""
    db = world.db
    _platform(monkeypatch, db, max_input_tokens=1000)
    client = _stub_client(agent)
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    one = _file(db, root, chat_id, tokens=1, size=10, minute=0)
    unknown = _file(db, root, chat_id, tokens=None, size=10, minute=1)

    refused = _send(client, editor, chat_id, [one])
    accepted = _send(client, editor, chat_id, [unknown])

    expected = _refusal("context_overflow", [_item(one, 1, 10)], available=0)
    assert _answer(refused) == (422, expected)
    assert accepted.status_code == 200, accepted.text
    assert _passed(script) == [(unknown, 0)]


@pytest.mark.parametrize("reason", list(_OVER))
@pytest.mark.parametrize("gate", ["missing-derived", "image-input-off"])
def test_chat_context_budget_checks_come_before_storage_and_image_input(
    world: World,
    client: TestClient,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    gate: str,
    reason: str,
) -> None:
    """The listed file has no derived directory (GH-189's 503) or is an image while the
    model takes none (GH-189's 422): over the budget or the cap it is this 422 all the
    same, with no run; under both (``tokens`` and ``bytes`` small) GH-189's refusal."""
    db = world.db
    editor = world.a["editor"]
    if gate == "image-input-off":
        _platform(monkeypatch, db, image_input=False)
    chat_id = _chat(db, editor)
    earlier = db.add_chat_message(chat_id, "user", _EARLIER)
    db.add_chat_message(chat_id, "assistant", _EARLIER_REPLY)
    (tokens_1, bytes_1), (tokens_2, bytes_2) = _OVER[reason]
    first = _file(db, root, chat_id, tokens=tokens_1, size=bytes_1, minute=0, message_id=earlier)
    image = gate == "image-input-off"
    second = _file(
        db, root, chat_id, tokens=tokens_2, size=bytes_2, minute=1, image=image, derived=image
    )
    small = _file(db, root, chat_id, tokens=1, size=1, minute=2, image=image, derived=image)
    items = [_item(first, tokens_1, bytes_1), _item(second, tokens_2, bytes_2)]

    over = _send(client, editor, chat_id, [second])

    assert (_answer(over), script.runs) == ((422, _refusal(reason, items)), [])
    under = _send(client, editor, chat_id, [small])
    expected_under = (
        (503, _STORAGE_UNAVAILABLE)
        if gate == "missing-derived"
        else (
            422,
            {
                "detail": "The current model does not accept image input",
                "reason": "image_input_unsupported",
            },
        )
    )
    assert (_answer(under), script.runs) == (expected_under, [])


def test_chat_context_budget_excluded_files_dont_count_and_a_listed_one_is_linked_unsent(
    world: World, client: TestClient, script: _Script, root: Path
) -> None:
    """An excluded earlier file and an excluded listed file, each far over the budget and
    without derived files: the turn runs with the active files only (the earlier one,
    then the listed one), and the excluded listed file is linked to the user message."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    earlier = db.add_chat_message(chat_id, "user", _EARLIER)
    db.add_chat_message(chat_id, "assistant", _EARLIER_REPLY)
    sent = _file(db, root, chat_id, tokens=300, size=10, minute=0, message_id=earlier)
    big = 10 * _AVAILABLE
    _file(
        db,
        root,
        chat_id,
        tokens=big,
        size=2 * _MIB,
        minute=1,
        message_id=earlier,
        active=False,
        derived=False,
    )
    listed = _file(db, root, chat_id, tokens=400, size=10, minute=2)
    excluded = _file(
        db, root, chat_id, tokens=big, size=2 * _MIB, minute=3, active=False, derived=False
    )

    response = _send(client, editor, chat_id, [excluded, listed])

    assert response.status_code == 200, response.text
    assert _passed(script) == [(sent, 300), (listed, 400)]
    (user_id,) = [
        plain(row["id"])
        for row in db.messages_of(chat_id)
        if (row["role"], row["content"]) == ("user", _MESSAGE)
    ]
    assert (_linked_to(db, listed), _linked_to(db, excluded)) == (user_id, user_id)


def test_chat_context_budget_denial_reads_nothing_is_never_refused_and_counts_the_rows(
    world: World,
    client: TestClient,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    instructions: int,
) -> None:
    """The request sent files whose estimates (8500) alone don't fit, one of them without
    derived files: a denial reads no derived file, is stored and answered, consumes the
    confirmation, and its usage counts the files from their rows (above 100 %)."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    request = _awaiting(db, chat_id)
    _file(db, root, chat_id, tokens=5000, size=10, minute=0, message_id=request)
    _file(db, root, chat_id, tokens=3500, size=10, minute=1, message_id=request, derived=False)
    _pending(editor, chat_id, _CONFIRMATION_ID)
    reads = _refuse_reads(monkeypatch)

    response = _confirm(client, editor, chat_id, approved=False)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["status"], body["response"], reads, script.runs) == ("final", _DENIAL, [], [])
    assert server._chat_runtime.get_pending(chat_id) is None
    # 500 + 8500 + 1000 > 9000: no history fits, the percent is above 100.
    assert body.get("context_usage") == {"used": 10_000, "max": _BUDGET, "percent": 111}


# ---------------------------------------------------------------------------
# 3. context_usage and context_notice on every JSON answer (Decisions 3, 4)
# ---------------------------------------------------------------------------

_ROUTES: Final = ("send", "legacy", "approve", "deny")


def _usage_chat(world: World, root: Path, route: str) -> tuple[uuid.UUID, list[LLMMessage]]:
    """A chat of the Editor of org A whose first message sent an active file (1200
    tokens) and an excluded one (3000); for an approval or a denial the message is the
    request and the assistant's tool_use awaits a confirmation. Returns the chat and its
    history as a turn loads it."""
    db = world.db
    editor = world.a["editor"]
    legacy = route == "legacy"
    chat_id = _chat(db, editor, legacy_session_id=_LEGACY if legacy else None)
    awaiting = route in ("approve", "deny")
    if awaiting:
        first = _awaiting(db, chat_id)
        history = [_user(_REQUEST), _assistant("", tool_use_blocks=[_BOOK_BLOCK])]
    else:
        first = db.add_chat_message(chat_id, "user", _EARLIER)
        db.add_chat_message(chat_id, "assistant", _EARLIER_REPLY)
        history = [_user(_EARLIER), _assistant(_EARLIER_REPLY)]
    _file(db, root, chat_id, tokens=1200, size=50, minute=0, message_id=first)
    _file(db, root, chat_id, tokens=3000, size=50, minute=1, message_id=first, active=False)
    if awaiting:
        _pending(editor, chat_id, _CONFIRMATION_ID)
    return chat_id, history


def _post(client: TestClient, account: Account, route: str, chat_id: uuid.UUID) -> Any:
    if route == "send":
        return _send(client, account, chat_id)
    if route == "legacy":
        return _legacy(client, account)
    return _confirm(client, account, chat_id, approved=route == "approve")


_STORED: Final[dict[str, list[LLMMessage]]] = {
    "send": [_user(_MESSAGE), _assistant(_REPLY)],
    "legacy": [_user(_MESSAGE), _assistant(_REPLY)],
    "approve": [_tool(_RESUMED), _assistant(_REPLY)],
    "deny": [_tool(_DENIED_RESULT), _assistant(_DENIAL)],
}


@pytest.mark.parametrize("route", _ROUTES)
def test_chat_context_budget_every_json_answer_carries_the_chats_usage(
    world: World, client: TestClient, root: Path, instructions: int, route: str
) -> None:
    """Instructions 500 + the active file's 1200 (the excluded one's 3000 not) + the
    loaded history and the messages the turn stored + the reserved 1000, of the budget
    9000; ``context_notice`` None (nothing dropped)."""
    chat_id, loaded = _usage_chat(world, root, route)

    response = _post(client, world.a["editor"], route, chat_id)

    assert response.status_code == 200, response.text
    body = response.json()
    expected = _usage([*loaded, *_STORED[route]], attachments=1200)
    assert (body.get("context_usage"), body.get("context_notice", "missing")) == (expected, None)


def test_chat_context_budget_usage_counts_the_newest_whole_turns_that_fit(
    world: World, client: TestClient, instructions: int
) -> None:
    """Three earlier turns (3500, 2000 and 2000 tokens of user text) and the new one:
    500 + 1000 fixed leave 7500, so the newest three turns fit and the oldest is left
    out of ``used`` (5557 of 9000, 61 %)."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    history: list[LLMMessage] = []
    for tokens, tag in ((3500, "oldest"), (2000, "middle"), (2000, "newest")):
        question, answer = _text(tokens, tag), f"Answer to the {tag} question"
        db.add_chat_message(chat_id, "user", question)
        db.add_chat_message(chat_id, "assistant", answer)
        history += [_user(question), _assistant(answer)]

    response = _send(client, editor, chat_id)

    assert response.status_code == 200, response.text
    expected = _usage([*history, _user(_MESSAGE), _assistant(_REPLY)], attachments=0)
    assert response.json().get("context_usage") == expected
    # 2016 + 2016 (the two newest earlier turns) + 25 (the new one); the oldest's 3516
    # more would make 9073.
    assert expected == {"used": 1500 + 4057, "max": _BUDGET, "percent": 61}


def test_chat_context_budget_usage_takes_the_real_instructions_of_the_request(
    world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unpatched: ``used`` is ``instructions_tokens(prompt_context, policy, now)`` of the
    request (``server._utc_now``) plus the history and the reserved output, and it grows
    once the org adds instructions."""
    from admino import context_budget

    monkeypatch.setattr(server, "_utc_now", lambda: _NOW)
    db = world.db
    editor = world.a["editor"]
    tenant = _tenant(editor)
    stored = [_user(_MESSAGE), _assistant(_REPLY)]
    seen: list[tuple[int, Any]] = []
    for instructions_text in ("", "Answer in short sentences. " * 40):
        db.org_settings[ORG_ID]["instructions"] = instructions_text
        context = asyncio.run(scoped_settings.load_prompt_context(db.pool, tenant))
        policy = asyncio.run(org_permissions.load_tool_policy(db.pool, tenant))
        tokens = context_budget.instructions_tokens(context, policy, now=_NOW)
        response = _send(client, editor, _chat(db, editor))
        assert response.status_code == 200, response.text
        seen.append((tokens, response.json().get("context_usage")))

    (without, usage_without), (with_text, usage_with) = seen
    assert (usage_without, usage_with) == (
        _usage(stored, attachments=0, instructions=without),
        _usage(stored, attachments=0, instructions=with_text),
    )
    assert with_text > without


@pytest.mark.parametrize("route", ["send", "legacy", "approve"])
def test_chat_context_budget_runs_context_notice_is_echoed(
    world: World, client: TestClient, script: _Script, root: Path, route: str
) -> None:
    """The run reports two dropped turns (five messages): the JSON answer carries
    exactly that ``context_notice``."""
    chat_id, _ = _usage_chat(world, root, route)
    script.notice = {"dropped_turns": 2, "dropped_messages": 5}

    response = _post(client, world.a["editor"], route, chat_id)

    assert response.status_code == 200, response.text
    assert response.json().get("context_notice") == {"dropped_turns": 2, "dropped_messages": 5}


def test_chat_context_budget_real_agent_drops_the_oldest_turns_and_reports_them(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Margin 0, reserved 100, max input = the instructions + reserved + the current
    message + the newest earlier turn: the call gets the system message, the newest turn
    and the current message only, and the answer reports 2 turns, 4 messages."""
    db = world.db
    editor = world.a["editor"]
    real = _real(world, monkeypatch, reserved=100, margin=0)
    calibrated = _send(real.client, editor, _chat(db, editor), message="Calibrate")
    assert calibrated.status_code == 200, calibrated.text
    (calibration,) = real.llm.calls
    system = calibration.messages[0]
    assert (system.role, isinstance(system.content, str)) == ("system", True)
    tools = json.dumps(list(calibration.tools), ensure_ascii=False, separators=(",", ":"))
    prompt = estimate_text_tokens(str(system.content)) + 4
    prompt += estimate_text_tokens(tools) if calibration.tools else 0
    chat_id = _chat(db, editor)
    turns = [(_text(800, tag), f"Reply to the {tag} turn") for tag in ("first", "second", "third")]
    for question, answer in turns:
        db.add_chat_message(chat_id, "user", question)
        db.add_chat_message(chat_id, "assistant", answer)
    current = "Next question please"
    newest = _message_tokens(_user(turns[2][0])) + _message_tokens(_assistant(turns[2][1]))
    limit = prompt + 100 + _message_tokens(_user(current)) + newest
    assert limit >= 1000
    _platform(monkeypatch, db, max_input_tokens=limit)

    response = _send(real.client, editor, chat_id, message=current)

    assert response.status_code == 200, response.text
    call = real.llm.calls[-1]
    assert [(m.role, m.content) for m in call.messages] == [
        ("system", system.content),
        ("user", turns[2][0]),
        ("assistant", turns[2][1]),
        ("user", current),
    ]
    assert response.json().get("context_notice") == {"dropped_turns": 2, "dropped_messages": 4}


# ---------------------------------------------------------------------------
# 4. The load limit and the run config (Decision 8, C11)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", _ROUTES)
def test_chat_context_budget_turn_reads_the_capped_or_the_latest_200_messages(
    world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """A stored ``max_context_messages`` of 7, then 0: the turn read's limit (``$4``) is
    7, then 200 (``HISTORY_LOAD_LIMIT``), on every JSON route."""
    db = world.db
    editor = world.a["editor"]
    limits: list[list[Any]] = []
    for cap in (7, 0):
        _platform(monkeypatch, db, max_context_messages=cap)
        legacy = route == "legacy"
        chat_id = _chat(db, editor, legacy_session_id=_LEGACY if legacy and cap else None)
        if route in ("approve", "deny"):
            _awaiting(db, chat_id)
            _pending(editor, chat_id, f"{_CONFIRMATION_ID}-{cap}")
        else:
            db.add_chat_message(chat_id, "user", _EARLIER)
            db.add_chat_message(chat_id, "assistant", _EARLIER_REPLY)
        since = len(db.calls)
        if route in ("approve", "deny"):
            response = _confirm(
                client, editor, chat_id, f"{_CONFIRMATION_ID}-{cap}", approved=route == "approve"
            )
        else:
            response = _post(client, editor, route, chat_id)
        assert response.status_code == 200, response.text
        limits.append(_turn_limits(db, since))

    assert limits == [[7], [_HISTORY_LOAD_LIMIT]]


@pytest.mark.parametrize("route", ["send", "legacy", "approve"])
def test_chat_context_budget_run_config_carries_the_budget_inputs(
    world: World,
    agent: MagicMock,
    script: _Script,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
) -> None:
    """The run's ``agent_config``: the stored max input tokens (10_001), the config's
    reserved output (1000), margin (10) and tool-result cap (300), the stored cap (0)."""
    _platform(monkeypatch, world.db, max_context_messages=0)
    client = _stub_client(agent, tool_cap=300)
    chat_id, _ = _usage_chat(world, root, route)

    response = _post(client, world.a["editor"], route, chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    fields = (
        "max_input_tokens",
        "reserved_output_tokens",
        "context_margin_percent",
        "max_tool_result_tokens",
        "max_context_messages",
    )
    assert {name: getattr(run["agent_config"], name, "missing") for name in fields} == {
        "max_input_tokens": _MAX_INPUT,
        "reserved_output_tokens": _RESERVED,
        "context_margin_percent": _MARGIN,
        "max_tool_result_tokens": 300,
        "max_context_messages": 0,
    }


# ---------------------------------------------------------------------------
# 5. The real agent: a cut wrapped result (A1) and context_too_long (Decision 2)
# ---------------------------------------------------------------------------


def test_chat_context_budget_cut_wrapped_result_still_sets_the_sticky_flag(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tool cap 256: memory.recall's result (4000 filler characters, then a wrapped email)
    is stored cut, without the begin marker. Still the chat's ``external_content`` is
    set, the untitled chat gets the fallback title without a title call, and the next
    turn's memory.store (allowed) awaits a confirmation instead of running."""
    db = world.db
    editor = world.a["editor"]
    real = _real(world, monkeypatch, wrapped_recall=True, tool_cap=256)
    chat_id = db.add_chat(editor.user_id)
    message = "Please recall the probe note for the ledger review"
    real.llm.ask(
        ToolCall(tool="memory", action="recall", args={"key": "probe"}, tool_call_id="call-r")
    )

    first = _send(real.client, editor, chat_id, message=message)

    assert (first.status_code, first.json()["status"]) == (200, "final"), first.text
    (stored,) = [row["content"] for row in db.messages_of(chat_id) if row["role"] == "tool"]
    assert (untrusted.contains_wrapped(stored), stored.endswith(_TOOL_RESULT_MARKER)) == (
        False,
        True,
    )
    chat = db.chat_row(chat_id)
    assert chat is not None
    assert (chat["external_content"], chat["title"], real.llm.kinds()) == (
        True,
        chat_titles.fallback_title(message),
        ["chat", "chat"],
    )

    real.llm.ask(
        ToolCall(
            tool="memory",
            action="store",
            args={"key": "probe", "value": "noted"},
            tool_call_id="call-s",
        )
    )
    second = _send(real.client, editor, chat_id, message="Store a note about it")

    assert (second.status_code, second.json()["status"]) == (200, "awaiting_confirmation")
    assert real.ran == ["memory.recall"]


def test_chat_context_budget_context_too_long_is_stored_like_a_coded_llm_error(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Max input 1000, margin 0, reserved 100, a 975-token message: the real agent makes
    no LLM call and the turn is stored and answered like a coded LLM error: status
    ``error``, ``error_code`` ``context_too_long``, the fixed reply."""
    db = world.db
    editor = world.a["editor"]
    real = _real(world, monkeypatch, reserved=100, margin=0)
    _platform(monkeypatch, db, max_input_tokens=1000)
    chat_id = _chat(db, editor)
    message = _text(975, "long")

    response = _send(real.client, editor, chat_id, message=message)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["status"], body.get("error_code"), body["response"], real.llm.calls) == (
        "error",
        "context_too_long",
        _TOO_LONG_REPLY,
        [],
    )
    assert [(r["role"], r["content"], r["status"]) for r in db.messages_of(chat_id)] == [
        ("user", message, "complete"),
        ("assistant", _TOO_LONG_REPLY, "error"),
    ]
    assert body.get("context_notice", "missing") is None


# ---------------------------------------------------------------------------
# 6. The statements before the LLM call (Decision 14, GH-244)
# ---------------------------------------------------------------------------


def _kind(call: Call) -> str:
    """``session``, ``turn_setup`` (T1), ``turn_load`` (T2), ``attachment_check`` (A8)."""
    tables = frozenset(_TABLE_RE.findall(call.normalized))
    if "sessions" in tables:
        return "session"
    if tables >= _T1_TABLES:
        return "turn_setup"
    if tables >= _T2_TABLES:
        return "turn_load"
    if tables == {"attachments"}:
        return "attachment_check"
    return "other:" + ",".join(sorted(tables))


@pytest.mark.parametrize("with_file", [False, True], ids=["no-file", "file"])
def test_chat_context_budget_send_keeps_three_statements_before_the_llm_call(
    world: World, root: Path, monkeypatch: pytest.MonkeyPatch, with_file: bool
) -> None:
    """A chat whose earlier message sent a file with its estimate and bytes, beside an
    excluded one: the session lookup, the turn setup and the turn read (T2'') before the
    LLM call; a listed file adds the A8'' lookup. The budget check adds none."""
    db = world.db
    editor = world.a["editor"]
    real = _real(world, monkeypatch)
    chat_id = _chat(db, editor)
    earlier = db.add_chat_message(chat_id, "user", _EARLIER)
    db.add_chat_message(chat_id, "assistant", _EARLIER_REPLY)
    _file(db, root, chat_id, tokens=120, size=64, minute=0, message_id=earlier)
    _file(db, root, chat_id, tokens=99, size=64, minute=1, message_id=earlier, active=False)
    ids = [_file(db, root, chat_id, tokens=80, size=64, minute=2)] if with_file else []
    since = len(db.calls)

    response = _send(real.client, editor, chat_id, ids)

    assert response.status_code == 200, response.text
    (call,) = real.llm.calls
    before = db.calls[since : call.statements]
    expected = ["session", "turn_setup", *(["attachment_check"] if with_file else []), "turn_load"]
    assert [_kind(statement) for statement in before] == expected
    sql = {_kind(statement): statement.normalized for statement in before}
    assert sql["turn_load"] == norm(_T2_SQL)
    if with_file:
        assert sql["attachment_check"] == norm(_A8_SQL)


# ---------------------------------------------------------------------------
# 7. OpenAPI
# ---------------------------------------------------------------------------


def test_chat_context_budget_openapi_422_names_both_codes(world: World, agent: MagicMock) -> None:
    """The 422 of the message, legacy and confirm routes names ``context_overflow`` and
    ``attachment_bytes_exceeded``."""
    paths = create_app(agent=agent, config=_app_config()).openapi()["paths"]
    operations = {
        "message": paths["/api/chats/{chat_id}/messages"]["post"],
        "legacy": paths["/api/message"]["post"],
        "confirm": paths["/api/confirm/{confirmation_id}"]["post"],
    }
    codes = ["context_overflow", "attachment_bytes_exceeded"]
    named = {
        name: [
            code
            for code in codes
            if code in operation["responses"].get("422", {}).get("description", "")
        ]
        for name, operation in operations.items()
    }
    assert named == dict.fromkeys(operations, codes)
