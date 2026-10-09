"""No provider receives a ``tool`` message without its call when a message cap cuts the
loaded history (GH-294, issue Decision 4 at the server; GH-190 server audit I-5).

With ``limits.max_context_messages`` = cap the server loads exactly the chat's latest
cap messages, so the oldest loaded one can be a ``tool`` result whose assistant call
lies before the load limit; the cap then cuts the loaded history again before each
LLM call. Decision 4's rule, checked on every LLM call's context: each ``tool``
message follows the assistant message whose tool calls name its id (directly, or
after that call's other results).

Harness: the app from ``create_app()`` on the FakeDb world of tests/tenancy_world.py
(an Editor of org A with a real session cookie) around the REAL ``Agent`` (main's
tool-call recorder, an isolated registry with google_calendar.create, confirm-gated
by the org's default matrix) and a fake Swiss LLM that records every call's messages.
The stored platform cap is 7 (settings cache and row). Each chat holds 10 stored
messages: a user message, an assistant batch of two calls (c0a, c0b), their two
results, a second batch (c1, c2) with its two results, the assistant's answer, then
two more. The latest 7 start with c0b's result, whose call lies before the load
limit, and the cap's cut before the LLM call lands between the c1/c2 batch and its
results.

What is pinned (end to end; GH-294 found the load itself already drops leading
results, ``chats.load_turn``, so this guards the whole path):
- An approval's resumed LLM call (the request and its dangling call loaded, the
  approved call's result added) and a turn's LLM call get no ``tool`` message
  without its call; the approved call's result follows its call.

Security notes:
- Every id and message here is a fixed fake value; no network, no real PostgreSQL,
  no real LLM.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest
from pydantic import BaseModel, Field

from admino import main as main_module
from admino import scoped_settings, server
from admino.agent import Agent
from admino.llm import LLMResponse, LLMStreamDelta
from admino.models import AgentConfig, LLMMessage, PendingConfirmation, ToolCall
from admino.server import create_app
from admino.tools import registry
from tests.conftest import default_test_platform_settings
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    build_world,
    make_client,
    make_config,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import AsyncIterator, Sequence

    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

_CAP: Final = 7
_REPLY: Final = "Done, 294."
_BOOK: Final = "Book the heron offsite for Friday 294"
_BOOK_CALL: Final = ToolCall(
    tool="google_calendar",
    action="create",
    args={"title": "Offsite 294"},
    tool_call_id="call-294-book",
)
_BOOK_BLOCK: Final = {
    "type": "tool_use",
    "id": "call-294-book",
    "name": "google_calendar.create",
    "input": {"title": "Offsite 294"},
}
_FIRST_BATCH: Final = ("call-294-recall-0a", "call-294-recall-0b")
_SECOND_BATCH: Final = ("call-294-recall-1", "call-294-recall-2")


class _FakeLLM:
    """A Swiss client: records each call's messages (copied) and answers ``_REPLY``."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self.calls: list[tuple[LLMMessage, ...]] = []

    def _record(self, messages: list[LLMMessage]) -> LLMResponse:
        self.calls.append(tuple(message.model_copy(deep=True) for message in messages))
        return LLMResponse(content=_REPLY)

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        return self._record(messages)

    def chat_stream(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        return self._play(self._record(messages))

    async def _play(self, response: LLMResponse) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        yield LLMStreamDelta(content=response.content)
        yield response

    async def close(self) -> None:
        """Nothing to close."""


class _BookArgs(BaseModel):
    title: str = Field(min_length=1, max_length=100)


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin behind the fake database, with the
    stored ``max_context_messages`` ``_CAP`` (row and settings cache)."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    stored = default_test_platform_settings()
    limits = stored.limits.model_copy(update={"max_context_messages": _CAP})
    monkeypatch.setattr(
        scoped_settings, "_platform_cache", stored.model_copy(update={"limits": limits})
    )
    row = db.platform_row()
    assert row is not None
    row["max_context_messages"] = _CAP
    return built


@pytest.fixture()
def llm() -> _FakeLLM:
    return _FakeLLM()


@pytest.fixture()
def client(world: World, llm: _FakeLLM, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """The app around a real Agent with google_calendar.create in an unfrozen registry
    (restored afterwards)."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)

    async def create(args: _BookArgs, **_: Any) -> str:
        return "Created the event 294."

    register: Any = registry.register_tool
    register("google_calendar", "create", "Create an event (GH-294)", _BookArgs)(create)
    agent = Agent(
        llm_client=llm,  # type: ignore[arg-type]
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    return make_client(create_app(agent=agent, config=make_config()))


def _batch(db: FakeDb, chat_id: uuid.UUID, call_ids: Sequence[str]) -> None:
    """An assistant message calling memory.recall once per id, then the results."""
    db.add_chat_message(
        chat_id,
        "assistant",
        "",
        tool_use_blocks=[
            {"type": "tool_use", "id": call_id, "name": "memory.recall", "input": {}}
            for call_id in call_ids
        ],
    )
    for call_id in call_ids:
        db.add_chat_message(chat_id, "tool", f"Recalled {call_id}.", tool_call_id=call_id)


def _seed(db: FakeDb, account: Account, tail: Sequence[tuple[str, dict[str, Any]]]) -> uuid.UUID:
    """A user-titled chat of 10 messages: a user message, the two batches with their
    results, the assistant's answer, then ``tail`` (two (role, fields) pairs). The
    latest ``_CAP`` start with c0b's result."""
    chat_id = db.add_chat(account.user_id, title="Orphans 294", title_source="user")
    db.add_chat_message(chat_id, "user", "What did I note last week? 294")
    _batch(db, chat_id, _FIRST_BATCH)
    _batch(db, chat_id, _SECOND_BATCH)
    db.add_chat_message(chat_id, "assistant", "You noted four things.")
    for role, fields in tail:
        content = fields.pop("content", "")
        db.add_chat_message(chat_id, role, content, **fields)
    rows = db.messages_of(chat_id)
    assert (len(rows), rows[-_CAP]["tool_call_id"]) == (_CAP + 3, _FIRST_BATCH[1])
    return chat_id


def _orphans(messages: Sequence[LLMMessage]) -> list[str | None]:
    """The ``tool_call_id`` of every ``tool`` message that doesn't follow the assistant
    message naming its id (directly, or after that call's other results)."""
    orphans: list[str | None] = []
    open_ids: set[str] = set()
    for message in messages:
        if message.role == "assistant":
            open_ids = {str(block.get("id")) for block in message.tool_use_blocks or []}
        elif message.role == "tool":
            if message.tool_call_id not in open_ids:
                orphans.append(message.tool_call_id)
        else:
            open_ids = set()
    return orphans


def _roles(call: Sequence[LLMMessage]) -> list[str]:
    return [message.role for message in call]


def test_chat_orphan_tool_results_approval_resume_sends_no_result_without_its_call(
    world: World, client: TestClient, llm: _FakeLLM
) -> None:
    """The request and its dangling google_calendar.create call are the newest of the 10
    stored messages; the approval loads the latest 7 (c0b's orphaned result first),
    dispatches the call and asks the LLM: no ``tool`` message of that call lacks its
    call, and the approved result follows its call."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _seed(
        db,
        editor,
        [
            ("user", {"content": _BOOK}),
            (
                "assistant",
                {"tool_use_blocks": [_BOOK_BLOCK], "status": "awaiting_confirmation"},
            ),
        ],
    )
    now = datetime.now(UTC)
    pending = PendingConfirmation(
        confirmation_id="confirm-294-orphans",
        session_id=str(chat_id),
        tool_call=_BOOK_CALL,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    server._chat_runtime.set_pending(chat_id, editor.user_id, pending)

    response = client.post(
        f"/api/confirm/{pending.confirmation_id}",
        headers=editor.cookie,
        json={
            "confirmation_id": pending.confirmation_id,
            "approved": True,
            "chat_id": str(chat_id),
        },
    )

    assert (response.status_code, response.json().get("status")) == (200, "final"), response.text
    assert llm.calls, "the resumed run made no LLM call"
    assert [_orphans(call) for call in llm.calls] == [[] for _ in llm.calls]
    assert [m.tool_call_id for m in llm.calls[0] if m.role == "tool"] == ["call-294-book"]


def test_chat_orphan_tool_results_turn_sends_no_result_without_its_call(
    world: World, client: TestClient, llm: _FakeLLM
) -> None:
    """A turn in a chat whose latest 7 messages start with c0b's orphaned result: its
    LLM call holds no ``tool`` message without its call, and ends with the new
    message."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _seed(
        db,
        editor,
        [("user", {"content": "Thanks. 294"}), ("assistant", {"content": "Any time."})],
    )

    response = client.post(
        f"/api/chats/{chat_id}/messages",
        headers=editor.cookie,
        json={"message": "And what is next? 294"},
    )

    assert (response.status_code, response.json().get("status")) == (200, "final"), response.text
    (call,) = llm.calls
    assert (_orphans(call), _roles(call)[-1], call[-1].content) == (
        [],
        "user",
        "And what is next? 294",
    )
