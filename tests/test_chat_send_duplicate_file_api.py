"""A file listed by two concurrent sends of one chat is in the second turn once (GH-294,
issue Decision 5; GH-189 audit S4).

Two sends A and B of the same chat both list a file: each checks its files
(``attachments.check_sendable``) before it takes the chat's hold, so B can pass the
check before A links the file to A's message. When B then runs, the file is among
the chat's active attachments (``turn.attachments``) AND among B's own files.
Decision 5: the turn's file list is the chat's active attachments followed by those
of the message's own files that aren't among them (compared by id), so the file
appears once, in its earlier position. The send rule's token and byte checks, slot
4, the stored ``included_attachment_ids`` and the ``tool.call`` audit row's
``attachment_ids`` all use that list.

Harness: the app from ``create_app()`` on the FakeDb world of tests/tenancy_world.py
(an Editor of org A with a real session cookie), the attachments root under
``tmp_path`` and derived files written with tests/attachment_derived.py. The REAL
``Agent`` (main's tool-call recorder, an isolated registry with memory.recall: allow,
no side effect) talks to a fake Swiss LLM that answers its queue in order and
records every call's messages; a subclass records the slot each run gets. Both sends
go through one ``httpx.AsyncClient`` in the test's event loop: B's file check is
gated (``attachments.check_sendable`` wrapped: its first call, B's, waits after it
returned), A runs to completion, then B is released. Deterministic, bounded waits.

What is pinned:
- B's run gets [F, H, G] when A sent [F, H] and B lists [F, G]: F once, in its
  earlier position; the provider's current user message holds each file's text
  once; B's stored assistant rows record [F, H, G]; B's ``tool.call`` audit row
  carries those three ids (``attachment_count`` 3). A plain send (A's) is unchanged:
  its run gets its own files [F, H] in upload order.
- A file whose stored token estimate (or derived bytes) fits the turn once but not
  twice: B runs (200, final) with the file once, never the 422 ``context_overflow``
  (or ``attachment_bytes_exceeded``).

Security notes:
- Every id, name and file text here is a fixed fake value; no network, no real
  PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from pydantic import BaseModel, Field

from admino import attachments, organizations
from admino import main as main_module
from admino.agent import Agent
from admino.llm import LLMResponse, LLMStreamDelta
from admino.models import AgentConfig, AgentResult, LLMMessage, ToolCall
from admino.server import create_app
from admino.tools import registry
from tests.attachment_derived import write_derived
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    CLIENT_IP,
    build_world,
    make_config,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from fastapi import FastAPI

    from tests.tenancy_world import Account, World

_WAIT_S: Final = 5.0
_T0: Final = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
_REPLY: Final = "Here is my answer, 294."
_A_MESSAGE: Final = "First send 294: read the two files"
_B_MESSAGE: Final = "Second send 294: compare them"
_MIB: Final = 1_048_576
# The files: names and texts are canaries.
_F_NAME: Final = "falcon-notes-294.txt"
_F_TEXT: Final = "falconcanary 294 the first file"
_H_NAME: Final = "harrier-plan-294.txt"
_H_TEXT: Final = "harriercanary 294 the second file"
_G_NAME: Final = "grebe-memo-294.txt"
_G_TEXT: Final = "grebecanary 294 the third file"
_RECALL: Final = ToolCall(
    tool="memory", action="recall", args={"key": "plan"}, tool_call_id="call-294-recall"
)


def _at(minutes: int) -> datetime:
    return _T0 + timedelta(minutes=minutes)


# ---------------------------------------------------------------------------
# The fake LLM, the tool and the recording agent
# ---------------------------------------------------------------------------


class _FakeLLM:
    """A Swiss client: each call answers the next queued response, then ``_REPLY``, and
    records the messages it got (copied at call time)."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self.calls: list[tuple[LLMMessage, ...]] = []
        self.queue: list[LLMResponse] = []

    def _next(self, messages: list[LLMMessage]) -> LLMResponse:
        self.calls.append(tuple(message.model_copy(deep=True) for message in messages))
        return self.queue.pop(0) if self.queue else LLMResponse(content=_REPLY)

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        return self._next(messages)

    def chat_stream(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        return self._play(self._next(messages))

    async def _play(self, response: LLMResponse) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        if response.content:
            yield LLMStreamDelta(content=response.content)
        yield response

    async def close(self) -> None:
        """Nothing to close."""


class _KeyArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)


class _RecordingAgent(Agent):
    """The real agent; every run records (its user message, the ids of the slot it got)."""

    def __init__(self, llm: _FakeLLM) -> None:
        super().__init__(
            llm_client=llm,  # type: ignore[arg-type]
            tool_call_recorder=main_module._build_tool_call_recorder(),
            agent_config=AgentConfig(
                max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
            ),
        )
        self.slots: list[tuple[str, list[uuid.UUID]]] = []

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        slot = [uuid.UUID(str(content.id)) for content in kwargs.get("attachments", ())]
        self.slots.append((str(kwargs.get("user_message", "")), slot))
        return await super().run(*args, **kwargs)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B (OA/ED each) and a Super Admin behind the fake database, the
    attachments root under tmp_path."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    return built


@pytest.fixture()
def llm() -> _FakeLLM:
    return _FakeLLM()


@pytest.fixture()
def agent(llm: _FakeLLM, monkeypatch: pytest.MonkeyPatch) -> _RecordingAgent:
    """The recording agent with memory.recall (allow, no side effect) in an unfrozen
    registry restored afterwards."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)

    async def recall(args: _KeyArgs, **_: Any) -> str:
        return "Recalled note 294."

    register: Any = registry.register_tool
    register("memory", "recall", "Recall a note (GH-294)", _KeyArgs, side_effect=False)(recall)
    return _RecordingAgent(llm)


@pytest.fixture()
def app(world: World, agent: _RecordingAgent) -> FastAPI:
    return create_app(agent=agent, config=make_config())


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the test's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50294))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


def _chat(db: FakeDb, account: Account) -> uuid.UUID:
    """A user-titled chat of ``account`` (no title step runs after a turn)."""
    return db.add_chat(account.user_id, title="Files 294", title_source="user")


def _file(
    db: FakeDb, chat_id: uuid.UUID, name: str, text: str, *, minute: int, **fields: Any
) -> uuid.UUID:
    """A ``ready``, unsent txt attachment of the chat (created at ``_at(minute)``) with
    its derived text part under the attachments root; ``fields`` override the row."""
    fields.setdefault("token_estimate", 20)
    fields.setdefault("derived_bytes", 64)
    attachment_id = db.add_attachment(
        chat_id, filename=name, kind="txt", status="ready", created_at=_at(minute), **fields
    )
    chat = db.chat_row(chat_id)
    assert chat is not None
    write_derived(
        Path(organizations.ATTACHMENTS_ROOT),
        plain(chat["org_id"]),
        attachment_id,
        kind="txt",
        parts=(("text", text, None),),
    )
    return attachment_id


def _gate_first_check(monkeypatch: pytest.MonkeyPatch) -> tuple[asyncio.Event, asyncio.Event]:
    """Wrap ``attachments.check_sendable``: its FIRST call returns its real result only
    after the second event is set (it sets the first event once it has the result);
    later calls run as they are."""
    real = attachments.check_sendable
    parked, release = asyncio.Event(), asyncio.Event()
    calls: list[int] = []

    async def gated(*args: Any, **kwargs: Any) -> Any:
        result = await real(*args, **kwargs)
        calls.append(len(calls))
        if len(calls) == 1:
            parked.set()
            await asyncio.wait_for(release.wait(), _WAIT_S)
        return result

    monkeypatch.setattr(attachments, "check_sendable", gated)
    return parked, release


async def _send(
    http: httpx.AsyncClient,
    account: Account,
    chat_id: uuid.UUID,
    message: str,
    ids: Sequence[uuid.UUID],
) -> httpx.Response:
    return await http.post(
        f"/api/chats/{chat_id}/messages",
        headers=account.cookie,
        json={"message": message, "attachment_ids": [str(value) for value in ids]},
    )


async def _a_then_b(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    account: Account,
    chat_id: uuid.UUID,
    a_ids: Sequence[uuid.UUID],
    b_ids: Sequence[uuid.UUID],
) -> tuple[httpx.Response, httpx.Response]:
    """B checks its files first and waits; A runs to completion; then B goes on."""
    parked, release = _gate_first_check(monkeypatch)
    async with _async_client(app) as http:
        second = asyncio.create_task(_send(http, account, chat_id, _B_MESSAGE, b_ids))
        try:
            await asyncio.wait_for(parked.wait(), _WAIT_S)
            first = await asyncio.wait_for(
                _send(http, account, chat_id, _A_MESSAGE, a_ids), _WAIT_S
            )
        finally:
            release.set()
        return first, await asyncio.wait_for(second, _WAIT_S)


def _texts(message: LLMMessage) -> list[str]:
    """A content list's text parts in order ([str content] for a str content)."""
    content: Any = message.content
    if isinstance(content, str):
        return [content]
    return [part.text for part in content if part.type == "text"]


def _current_user(call: tuple[LLMMessage, ...]) -> LLMMessage:
    """The call's current message: its last ``user`` message."""
    (*_, current) = [message for message in call if message.role == "user"]
    return current


def _rows_after(db: FakeDb, chat_id: uuid.UUID, user_text: str) -> list[dict[str, Any]]:
    """The chat's stored rows from the user message ``user_text`` on, by seq."""
    rows = db.messages_of(chat_id)
    (start,) = [
        index
        for index, row in enumerate(rows)
        if row["role"] == "user" and row["content"] == user_text
    ]
    return rows[start:]


def _answered(response: httpx.Response) -> tuple[int, Any]:
    """(status, the JSON status of a 200, else the whole body)."""
    body = response.json()
    return response.status_code, body.get("status") if response.status_code == 200 else body


# ---------------------------------------------------------------------------
# 1. The file once, in its earlier position (Decision 5)
# ---------------------------------------------------------------------------


async def test_chat_send_duplicate_file_concurrent_send_gets_the_linked_file_once(
    world: World,
    app: FastAPI,
    agent: _RecordingAgent,
    llm: _FakeLLM,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sends [F, H]; B, checked before A linked them, lists [F, G] and asks for
    memory.recall. A's run gets [F, H]; B's run gets [F, H, G]; B's first LLM call holds
    each file's text once, in that order; B's stored assistant rows record [F, H, G];
    B's ``tool.call`` audit row carries those ids and ``attachment_count`` 3."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    f_id = _file(db, chat_id, _F_NAME, _F_TEXT, minute=0)
    h_id = _file(db, chat_id, _H_NAME, _H_TEXT, minute=1)
    g_id = _file(db, chat_id, _G_NAME, _G_TEXT, minute=2)
    # A: one call (the reply); B: memory.recall, then the reply.
    llm.queue.extend(
        [
            LLMResponse(content=_REPLY),
            LLMResponse(content="", tool_calls=[_RECALL]),
            LLMResponse(content=_REPLY),
        ]
    )

    first, second = await _a_then_b(app, monkeypatch, editor, chat_id, [f_id, h_id], [f_id, g_id])

    assert (_answered(first), _answered(second)) == ((200, "final"), (200, "final"))
    assert agent.slots == [(_A_MESSAGE, [f_id, h_id]), (_B_MESSAGE, [f_id, h_id, g_id])]
    joined = "\n".join(_texts(_current_user(llm.calls[1])))
    assert [joined.count(text) for text in (_F_TEXT, _H_TEXT, _G_TEXT)] == [1, 1, 1]
    positions = [joined.find(f"File: {name}") for name in (_F_NAME, _H_NAME, _G_NAME)]
    assert -1 not in positions and positions == sorted(positions), positions
    b_rows = _rows_after(db, chat_id, _B_MESSAGE)
    assert [
        (row["role"], row["included_attachment_ids"])
        for row in b_rows
        if row["role"] == "assistant"
    ] == [("assistant", [f_id, h_id, g_id]), ("assistant", [f_id, h_id, g_id])]
    (recorded,) = db.audit_rows("tool.call")
    assert (
        recorded["metadata"].get("attachment_ids"),
        recorded["metadata"].get("attachment_count"),
    ) == ([str(f_id), str(h_id), str(g_id)], 3)


# ---------------------------------------------------------------------------
# 2. The send rule counts the file once (Decision 5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        # The default budget: 200000 - 20000 = 180000, less 4096 reserved = 175904 for
        # files: 100000 fits once, 200000 doesn't.
        pytest.param({"token_estimate": 100_000}, id="tokens"),
        # The default per-turn cap is 64 MiB: 40 MiB fits once, 80 MiB doesn't.
        pytest.param({"derived_bytes": 40 * _MIB}, id="bytes"),
    ],
)
async def test_chat_send_duplicate_file_that_fits_once_but_not_twice_runs(
    world: World,
    app: FastAPI,
    agent: _RecordingAgent,
    monkeypatch: pytest.MonkeyPatch,
    fields: dict[str, int],
) -> None:
    """A and B both list F, whose stored size fits the turn once but not twice: B is
    answered (200, final) with F once in its run and its stored rows, never the 422 of
    the send rule."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    f_id = _file(db, chat_id, _F_NAME, _F_TEXT, minute=0, **fields)

    first, second = await _a_then_b(app, monkeypatch, editor, chat_id, [f_id], [f_id])

    assert (_answered(first), _answered(second)) == ((200, "final"), (200, "final"))
    assert agent.slots == [(_A_MESSAGE, [f_id]), (_B_MESSAGE, [f_id])]
    assert [
        row["included_attachment_ids"]
        for row in _rows_after(db, chat_id, _B_MESSAGE)
        if row["role"] == "assistant"
    ] == [[f_id]]
