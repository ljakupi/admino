"""HTTP spec of retrying a failed answer with the REAL agent (GH-245, contract C4, Decision 3).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin, an Editor and a Viewer
each, all with real session cookies) around the REAL ``admino.agent.Agent``
with the real tool-call recorder of ``main._build_tool_call_recorder()``. Its
LLM is a scripted fake keyed by the turn's user message (the n-th call of a
run returns the n-th scripted step, counted by the assistant turns after the
last user message; a ``_FAIL`` step makes the call raise, so the run ends
``error`` like a provider failure), and its tools are fakes in an isolated
registry: ``google_calendar.create`` (``confirm`` by default),
``memory.store`` (an ``allow`` side effect), ``memory.recall`` (a plain
read), ``gmail.read`` (wrapped external content) and ``gmail.send`` (a
hardcoded denial). Every chat has a user title, so no title call reaches the
fake LLM.

A failed turn is made through the API (a send whose run fails, or an approved
confirmation whose continuation fails), or seeded the way the server stores
one. Then ``POST /api/chats/{chat_id}/retry`` (no body) re-runs the chat's
latest user message.

What is pinned (issue #245 "the permission engine re-evaluates every tool
call, confirm actions need fresh approval, and no earlier approval or tool
result is replayed"; Decision 3; contract C4):
- Fresh approval: the failed turn held an APPROVED ``confirm`` call (its tool
  ran once, then the continuation failed). The retry's model calls the same
  action again: the run ends ``awaiting_confirmation`` with a NEW pending
  confirmation (another id, live in ``server._chat_runtime``), the handler is
  not called, its ``tool.call`` row is ``confirm`` without success and the
  stored turn is the retried message with the new ``tool_use`` (the failed
  turn is gone). Approving the new confirmation through POST /api/confirm
  runs the call once and stores the continuation. The failed turn's approved
  confirmation id is unknown afterwards (404 ``Confirmation not found``, the
  new one still pending).
- Re-evaluation by the current policy: an action that was ``allow`` when the
  turn failed and is ``deny`` or ``confirm`` in the org's matrix now, or whose
  service is switched off now, is decided by the current policy (handler not
  called); a hardcoded denial (``gmail.send``, set to ``allow`` in the org's
  rows) stays denied; an allowed side effect after a failed turn that read
  external content (the chat's sticky ``external_content`` set) is escalated to
  ``confirm`` although the retried run's history holds no wrapped content; an
  allowed side effect that ran in the failed turn runs again when the model
  calls it again.
- No replay: the retry's first LLM call is fed exactly the messages before the
  retried message and the retried message; no LLM call of the retry is fed
  any of the failed turn's assistant or tool rows (their text, tool_use ids or
  the error reply).
- Audit: every dispatch of the retry writes its ``tool.call`` row, acting
  member of org A, targeting the chat; the failed turn's rows stay unchanged
  (append-only); no message text, tool argument or tool result is in any row.
- Logs: the retry logs ``Retrying the last message of chat <id>`` once, and no
  line names the message, a tool argument or result, a confirmation id or the
  caller's email.

The retry route and its run are only reached over HTTP, so the file collects
before GH-245 is implemented and each test fails on its own.

Security notes:
- Every message, argument, id and title here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

import pytest
from pydantic import BaseModel, Field

from admino import main as main_module
from admino import server, untrusted
from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import AgentConfig, LLMMessage, ToolCall
from admino.server import create_app
from admino.tools import registry
from tests.db_fakes import ORG_ID, FakeDb, plain
from tests.log_capture import configured_logging
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

    import httpx
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TITLE: Final = "GH-245 retry spec"
_FINAL_REPLY: Final = "All done with the osprey review."
# A step of the fake LLM's script: the call raises (a provider failure, not retried).
_FAIL: Final = "fail"
_CONFIRMATION_NOT_FOUND: Final = {"detail": "Confirmation not found"}

_BOOK: Final = "Book the osprey review for Friday"
_EVENT_TITLE: Final = "Osprey review kestrel-245"
_CREATE_FAILED: Final = ToolCall(
    tool="google_calendar",
    action="create",
    args={"title": _EVENT_TITLE},
    tool_call_id="call-cal-245-failed",
)
_CREATE_RETRY: Final = ToolCall(
    tool="google_calendar",
    action="create",
    args={"title": _EVENT_TITLE},
    tool_call_id="call-cal-245-retry",
)

_NOTE: Final = "Note the osprey plan"
_NOTE_KEY: Final = "osprey-plan-245"
_NOTE_VALUE: Final = "ship-heron-245"
_STORE_FAILED: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": _NOTE_KEY, "value": _NOTE_VALUE},
    tool_call_id="call-store-245-failed",
)
_STORE_RETRY: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": _NOTE_KEY, "value": _NOTE_VALUE},
    tool_call_id="call-store-245-retry",
)

_LOOK_UP: Final = "Look up the osprey ledger"
_LEDGER_KEY: Final = "osprey-ledger-245"
_RECALLED: Final = "Recalled: osprey ledger total 4521"
_RECALL_FAILED: Final = ToolCall(
    tool="memory", action="recall", args={"key": _LEDGER_KEY}, tool_call_id="call-recall-245-failed"
)
_RECALL_RETRY: Final = ToolCall(
    tool="memory", action="recall", args={"key": _LEDGER_KEY}, tool_call_id="call-recall-245-retry"
)

_READ_MAIL: Final = "Read the osprey mail and note the plan"
_MAIL_BODY: Final = "Quarterly osprey figures attached."
_READ_FAILED: Final = ToolCall(
    tool="gmail", action="read", args={"message_id": "m245"}, tool_call_id="call-mail-245-failed"
)

_SEND_MAIL: Final = "Send the osprey summary to the board"
_RECIPIENT: Final = "board-245@example.ch"
_SEND_FAILED: Final = ToolCall(
    tool="gmail", action="send", args={"to": _RECIPIENT}, tool_call_id="call-send-245-failed"
)
_SEND_RETRY: Final = ToolCall(
    tool="gmail", action="send", args={"to": _RECIPIENT}, tool_call_id="call-send-245-retry"
)

# The seeded failed turn of the no-replay test: its tool result and error reply.
_EARLIER_QUESTION: Final = "What is on the osprey agenda?"
_EARLIER_ANSWER: Final = "The agenda has two items."
_SEEDED_RESULT: Final = "Recalled: harrier ledger total 9917"
_ERROR_REPLY: Final = "I hit an error while processing your request. Please try again in a moment."

# ---------------------------------------------------------------------------
# Messages and stored rows
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


def _tool_use(*calls: ToolCall) -> LLMMessage:
    """An assistant turn asking for ``calls``."""
    return LLMMessage(role="assistant", content="", tool_use_blocks=[_block(c) for c in calls])


def _tool(content: str, call: ToolCall) -> LLMMessage:
    """The tool result answering ``call``."""
    return LLMMessage(role="tool", content=content, tool_call_id=call.tool_call_id)


Row = tuple[str, str, str | None, list[dict[str, Any]] | None, str]


def _row(message: LLMMessage, status: str = "complete") -> Row:
    """How a stored chat_messages row of ``message`` reads (role, content, tool ids, status)."""
    return (
        message.role,
        message.content,
        message.tool_call_id,
        message.tool_use_blocks,
        status,
    )


def _stored(db: FakeDb, chat_id: uuid.UUID) -> list[Row]:
    """The chat's stored messages by seq, as ``_row`` tuples."""
    return [
        (m["role"], m["content"], m["tool_call_id"], m["tool_use_blocks"], m["status"])
        for m in db.messages_of(chat_id)
    ]


def _seed(db: FakeDb, chat_id: uuid.UUID, *messages: LLMMessage, status: str = "complete") -> None:
    """Store ``messages`` in the chat (the last one with ``status``)."""
    for index, message in enumerate(messages):
        db.add_chat_message(
            chat_id,
            message.role,
            message.content,
            tool_use_blocks=message.tool_use_blocks,
            tool_call_id=message.tool_call_id,
            status=status if index == len(messages) - 1 else "complete",
        )


def _fed_rows(fed: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    """(role, content, tool_call_id, tool_use_blocks) of every message an LLM call was fed."""
    return [(m["role"], m["content"], m["tool_call_id"], m["tool_use_blocks"]) for m in fed]


def _calls_of(body: dict[str, Any]) -> list[tuple[str, str, str, bool]]:
    """(tool, action, permission, success) of every tool call a response reports."""
    return [(c["tool"], c["action"], c["permission"], c["success"]) for c in body["tool_calls"]]


def _audit_outcomes(db: FakeDb) -> list[tuple[str, str, str, bool, bool]]:
    """(tool, action, decision, success, escalated) of every ``tool.call`` row, in order."""
    return [
        (
            row["metadata"]["tool"],
            row["metadata"]["action"],
            row["metadata"]["decision"],
            row["metadata"]["success"],
            row["metadata"]["escalated"],
        )
        for row in db.audit_rows("tool.call")
    ]


# ---------------------------------------------------------------------------
# The fake LLM and the fake tools
# ---------------------------------------------------------------------------


class _ScriptLLM:
    """Plays a script per user message and records the non-system messages of every call.

    The n-th call of a run returns the n-th scripted step (a tool call, or
    ``_FAIL``: the call raises), counted by the assistant turns after the last
    user message; past the script it answers ``_FINAL_REPLY``. ``script``
    replaces a message's script, so a retry of the same message plays a new one.
    """

    provider = "infomaniak"

    def __init__(self) -> None:
        self._scripts: dict[str, list[ToolCall | str]] = {}
        self.calls: list[tuple[str, list[dict[str, Any]]]] = []

    def script(self, message: str, *steps: ToolCall | str) -> None:
        self._scripts[message] = list(steps)

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        last_user = max(index for index, message in enumerate(messages) if message.role == "user")
        user_message = str(messages[last_user].content)
        self.calls.append((user_message, [m.model_dump() for m in messages if m.role != "system"]))
        steps = self._scripts.get(user_message, [])
        done = sum(1 for message in messages[last_user + 1 :] if message.role == "assistant")
        if done < len(steps):
            step = steps[done]
            if isinstance(step, str):
                msg = "scripted provider failure"
                raise RuntimeError(msg)
            return LLMResponse(content="", tool_calls=[step])
        return LLMResponse(content=_FINAL_REPLY)

    async def close(self) -> None:
        """Nothing to close."""

    def since(self, index: int) -> list[list[dict[str, Any]]]:
        """The non-system messages of every LLM call after the first ``index`` calls."""
        return [fed for _, fed in self.calls[index:]]


class _EventArgs(BaseModel):
    title: str = Field(min_length=1, max_length=100)


class _KeyArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)


class _StoreArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    value: str = Field(min_length=1, max_length=200)


class _MailArgs(BaseModel):
    message_id: str = Field(min_length=1, max_length=50)


class _SendArgs(BaseModel):
    to: str = Field(min_length=1, max_length=100)


@dataclass
class _Tools:
    """What the fake side-effect tools did."""

    created: list[str] = field(default_factory=list)
    stored: list[tuple[str, str]] = field(default_factory=list)
    sent: list[str] = field(default_factory=list)


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
def tools(monkeypatch: pytest.MonkeyPatch) -> _Tools:
    """An unfrozen registry holding only the fake tools; the previous one is restored."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    seen = _Tools()

    async def create(args: _EventArgs, **_: Any) -> str:
        seen.created.append(args.title)
        # Numbered, so each run's result text is its own.
        return f"Created event {len(seen.created)}: {args.title}"

    async def store(args: _StoreArgs, **_: Any) -> str:
        seen.stored.append((args.key, args.value))
        return f"Stored memory {len(seen.stored)}: {args.key}"

    async def recall(args: _KeyArgs, **_: Any) -> str:
        return _RECALLED

    async def read(args: _MailArgs, **_: Any) -> str:
        wrapped: str = untrusted.wrap("email", f"message {args.message_id}", _MAIL_BODY)
        return wrapped

    async def send(args: _SendArgs, **_: Any) -> str:
        seen.sent.append(args.to)
        return f"Sent to {args.to}"

    register: Any = registry.register_tool
    register("google_calendar", "create", "Create an event (GH-245)", _EventArgs, side_effect=True)(
        create
    )
    register("memory", "store", "Store a note (GH-245)", _StoreArgs, side_effect=True)(store)
    register("memory", "recall", "Recall a note (GH-245)", _KeyArgs, side_effect=False)(recall)
    register("gmail", "read", "Read an email (GH-245)", _MailArgs, side_effect=False)(read)
    register("gmail", "send", "Send an email (GH-245)", _SendArgs, side_effect=True)(send)
    return seen


@pytest.fixture()
def llm() -> _ScriptLLM:
    return _ScriptLLM()


def _real_app(llm: _ScriptLLM) -> FastAPI:
    """An app around a REAL Agent with the real tool-call recorder."""
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=300.0
        ),
    )
    app: FastAPI = create_app(agent=agent, config=make_config())
    return app


@pytest.fixture()
def client(world: World, tools: _Tools, llm: _ScriptLLM) -> TestClient:
    """One app (one chat runtime) for the whole test; an escaping exception is the 500."""
    return make_client(_real_app(llm), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Requests and flows
# ---------------------------------------------------------------------------


def _new_chat(world: World, account: Account) -> uuid.UUID:
    """A live chat of ``account`` with a user title (no automatic title call)."""
    return world.db.add_chat(account.user_id, title=_TITLE, title_source="user")


def _send(client: TestClient, account: Account, chat_id: uuid.UUID, message: str) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account``."""
    return client.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
    )


def _retry(client: TestClient, account: Account, chat_id: uuid.UUID) -> httpx.Response:
    """POST /api/chats/{chat_id}/retry as ``account`` (no body)."""
    return client.post(f"/api/chats/{chat_id}/retry", headers=account.cookie)


def _confirm(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    confirmation_id: str,
    *,
    approved: bool = True,
) -> httpx.Response:
    """POST /api/confirm/{confirmation_id} naming the chat."""
    return client.post(
        f"/api/confirm/{confirmation_id}",
        headers=account.cookie,
        json={"confirmation_id": confirmation_id, "approved": approved, "chat_id": str(chat_id)},
    )


def _fail_turn(
    client: TestClient,
    llm: _ScriptLLM,
    account: Account,
    chat_id: uuid.UUID,
    message: str,
    *calls: ToolCall,
) -> None:
    """A turn whose model asks for ``calls`` (one per LLM call) and whose next LLM call
    fails: the turn is stored with its last message ``error``."""
    llm.script(message, *calls, _FAIL)
    response = _send(client, account, chat_id, message)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "error", response.json()


def _fail_after_approval(
    client: TestClient, llm: _ScriptLLM, world: World, account: Account, chat_id: uuid.UUID
) -> str:
    """A turn asks to confirm google_calendar.create; it is approved and runs; the
    continuation's LLM call fails. The stored turn ends ``error``; returns the approved
    confirmation's id."""
    llm.script(_BOOK, _CREATE_FAILED, _FAIL)
    asked = _send(client, account, chat_id, _BOOK)
    assert asked.status_code == 200, asked.text
    assert asked.json()["status"] == "awaiting_confirmation", asked.json()
    confirmation_id: str = asked.json()["pending_confirmation"]["confirmation_id"]
    approved = _confirm(client, account, chat_id, confirmation_id)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "error", approved.json()
    assert _stored(world.db, chat_id) == [
        _row(_user(_BOOK)),
        _row(_tool_use(_CREATE_FAILED), "awaiting_confirmation"),
        _row(_tool(f"Created event 1: {_EVENT_TITLE}", _CREATE_FAILED)),
        _row(_assistant(_ERROR_REPLY), "error"),
    ]
    return confirmation_id


# ---------------------------------------------------------------------------
# 1. A confirm action needs a fresh approval
# ---------------------------------------------------------------------------


def test_chat_retry_agent_confirm_action_of_an_approved_failed_turn_asks_again(
    world: World, client: TestClient, llm: _ScriptLLM, tools: _Tools
) -> None:
    """The failed turn's google_calendar.create was approved and ran; the retry's model
    calls it again: a NEW pending confirmation (another id, live in the runtime), the
    handler isn't called, the ``tool.call`` row is ``confirm`` without success, and the
    stored turn is the retried message with the new tool_use (the failed turn is gone)."""
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    approved_id = _fail_after_approval(client, llm, world, editor, chat_id)
    assert tools.created == [_EVENT_TITLE]
    llm.script(_BOOK, _CREATE_RETRY)

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "awaiting_confirmation", body
    pending = body["pending_confirmation"]
    assert (pending["tool"], pending["action"]) == ("google_calendar", "create")
    assert pending["confirmation_id"] != approved_id
    live = server._chat_runtime.get_pending(chat_id)
    assert live is not None
    assert live.confirmation_id == pending["confirmation_id"]
    assert tools.created == [_EVENT_TITLE]
    assert _audit_outcomes(world.db) == [
        ("google_calendar", "create", "confirm", False, False),
        ("google_calendar", "create", "confirm", True, False),
        ("google_calendar", "create", "confirm", False, False),
    ]
    assert _stored(world.db, chat_id) == [
        _row(_user(_BOOK)),
        _row(_tool_use(_CREATE_RETRY), "awaiting_confirmation"),
    ]


def test_chat_retry_agent_approving_the_new_confirmation_runs_the_call_once(
    world: World, client: TestClient, llm: _ScriptLLM, tools: _Tools
) -> None:
    """Approving the retry's new confirmation through POST /api/confirm runs the call
    exactly once more and stores the continuation after the retried turn."""
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    _fail_after_approval(client, llm, world, editor, chat_id)
    llm.script(_BOOK, _CREATE_RETRY)
    retried = _retry(client, editor, chat_id)
    assert retried.status_code == 200, retried.text
    new_id = retried.json()["pending_confirmation"]["confirmation_id"]

    approved = _confirm(client, editor, chat_id, new_id)

    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "final", approved.json()
    assert _calls_of(approved.json()) == [("google_calendar", "create", "confirm", True)]
    assert tools.created == [_EVENT_TITLE, _EVENT_TITLE]
    assert server._chat_runtime.get_pending(chat_id) is None
    assert _stored(world.db, chat_id) == [
        _row(_user(_BOOK)),
        _row(_tool_use(_CREATE_RETRY), "awaiting_confirmation"),
        _row(_tool(f"Created event 2: {_EVENT_TITLE}", _CREATE_RETRY)),
        _row(_assistant(_FINAL_REPLY)),
    ]


def test_chat_retry_agent_failed_turns_approved_confirmation_id_is_unknown_afterwards(
    world: World, client: TestClient, llm: _ScriptLLM, tools: _Tools
) -> None:
    """After the retry, approving the failed turn's (already approved) confirmation id is
    the 404 ``Confirmation not found``: nothing runs, nothing is stored, and the retry's
    new confirmation stays pending."""
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    approved_id = _fail_after_approval(client, llm, world, editor, chat_id)
    llm.script(_BOOK, _CREATE_RETRY)
    retried = _retry(client, editor, chat_id)
    assert retried.status_code == 200, retried.text
    new_id = retried.json()["pending_confirmation"]["confirmation_id"]
    stored = _stored(world.db, chat_id)
    audit = world.db.audit_rows("tool.call")
    llm_calls = len(llm.calls)

    replayed = _confirm(client, editor, chat_id, approved_id)

    assert (replayed.status_code, replayed.json()) == (404, _CONFIRMATION_NOT_FOUND)
    assert tools.created == [_EVENT_TITLE]
    assert len(llm.calls) == llm_calls
    assert _stored(world.db, chat_id) == stored
    assert world.db.audit_rows("tool.call") == audit
    live = server._chat_runtime.get_pending(chat_id)
    assert live is not None
    assert live.confirmation_id == new_id


# ---------------------------------------------------------------------------
# 2. Every call is decided by the current policy
# ---------------------------------------------------------------------------


def _deny_in_matrix(db: FakeDb) -> None:
    db.add_permissions(ORG_ID, {"memory": {"store": "deny"}})


def _confirm_in_matrix(db: FakeDb) -> None:
    db.add_permissions(ORG_ID, {"memory": {"store": "confirm"}})


def _switch_memory_off(db: FakeDb) -> None:
    db.org_settings[ORG_ID]["memory_enabled"] = False


@pytest.mark.parametrize(
    ("change", "status", "decision"),
    [
        pytest.param(_deny_in_matrix, "final", "deny", id="matrix-deny"),
        pytest.param(_confirm_in_matrix, "awaiting_confirmation", "confirm", id="matrix-confirm"),
        pytest.param(_switch_memory_off, "final", "deny", id="service-off"),
    ],
)
def test_chat_retry_agent_call_allowed_when_the_turn_failed_follows_the_current_policy(
    world: World,
    client: TestClient,
    llm: _ScriptLLM,
    tools: _Tools,
    change: Any,
    status: str,
    decision: str,
) -> None:
    """memory.store was ``allow`` and ran in the failed turn; the org's policy changed
    since (its matrix row, or the memory service switched off). The retry's dispatch of
    the same call is decided by the current policy: the handler isn't called again."""
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    _fail_turn(client, llm, editor, chat_id, _NOTE, _STORE_FAILED)
    assert tools.stored == [(_NOTE_KEY, _NOTE_VALUE)]
    change(world.db)
    llm.script(_NOTE, _STORE_RETRY)

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["status"], _calls_of(body)) == (
        status,
        [("memory", "store", decision, False)],
    )
    assert tools.stored == [(_NOTE_KEY, _NOTE_VALUE)]
    assert _audit_outcomes(world.db) == [
        ("memory", "store", "allow", True, False),
        ("memory", "store", decision, False, False),
    ]


def test_chat_retry_agent_hardcoded_denial_stays_denied(
    world: World, client: TestClient, llm: _ScriptLLM, tools: _Tools
) -> None:
    """gmail.send is a hardcoded denial: with the org's row set to ``allow`` it was denied
    in the failed turn and is denied again in the retry; the handler never runs."""
    world.db.add_permissions(ORG_ID, {"gmail": {"send": "allow"}})
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    _fail_turn(client, llm, editor, chat_id, _SEND_MAIL, _SEND_FAILED)
    llm.script(_SEND_MAIL, _SEND_RETRY)

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["status"], _calls_of(body)) == ("final", [("gmail", "send", "deny", False)])
    assert tools.sent == []
    assert _audit_outcomes(world.db) == [
        ("gmail", "send", "deny", False, False),
        ("gmail", "send", "deny", False, False),
    ]


def test_chat_retry_agent_side_effect_after_a_failed_turn_that_read_external_content_waits(
    world: World, client: TestClient, llm: _ScriptLLM, tools: _Tools
) -> None:
    """The failed turn read an email (a wrapped tool result: the chat's sticky
    ``external_content`` is set), then failed. The retried run's history holds no wrapped
    content (the failed turn isn't replayed), yet the allowed memory.store it asks for is
    escalated to ``confirm`` by the chat's flag: awaiting, the handler isn't called."""
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    _fail_turn(client, llm, editor, chat_id, _READ_MAIL, _READ_FAILED)
    chat = world.db.chat_row(chat_id)
    assert chat is not None
    assert chat["external_content"] is True
    before = len(llm.calls)
    llm.script(_READ_MAIL, _STORE_RETRY)

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "awaiting_confirmation", body
    pending = body["pending_confirmation"]
    assert (pending["tool"], pending["action"]) == ("memory", "store")
    assert tools.stored == []
    assert _audit_outcomes(world.db)[-1] == ("memory", "store", "confirm", False, True)
    fed = [message for call in llm.since(before) for message in call]
    assert fed
    assert not any(untrusted.contains_wrapped(str(message["content"])) for message in fed)


def test_chat_retry_agent_allowed_call_that_ran_in_the_failed_turn_runs_again(
    world: World, client: TestClient, llm: _ScriptLLM, tools: _Tools
) -> None:
    """Decision 3: a tool call that ran in the failed turn runs again when the retry's
    model calls it again (a chat without external content: no escalation)."""
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    _fail_turn(client, llm, editor, chat_id, _NOTE, _STORE_FAILED)
    llm.script(_NOTE, _STORE_RETRY)

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["status"], _calls_of(body)) == ("final", [("memory", "store", "allow", True)])
    assert tools.stored == [(_NOTE_KEY, _NOTE_VALUE), (_NOTE_KEY, _NOTE_VALUE)]


# ---------------------------------------------------------------------------
# 3. Nothing of the failed turn is replayed to the model
# ---------------------------------------------------------------------------


def test_chat_retry_agent_model_is_fed_only_the_history_before_the_retried_message(
    world: World, client: TestClient, llm: _ScriptLLM, tools: _Tools
) -> None:
    """A complete earlier turn, then a failed turn (the retried message, a tool_use, its
    tool result, the error reply). The retry's first LLM call is fed exactly the earlier
    turn and the retried message; no LLM call of the retry is fed the failed turn's tool
    result, tool_use id or error reply."""
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    _seed(world.db, chat_id, _user(_EARLIER_QUESTION), _assistant(_EARLIER_ANSWER))
    _seed(
        world.db,
        chat_id,
        _user(_LOOK_UP),
        _tool_use(_RECALL_FAILED),
        _tool(_SEEDED_RESULT, _RECALL_FAILED),
        _assistant(_ERROR_REPLY),
        status="error",
    )
    llm.script(_LOOK_UP, _RECALL_RETRY)
    before = len(llm.calls)

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "final", response.json()
    retry_calls = llm.since(before)
    assert _fed_rows(retry_calls[0]) == [
        ("user", _EARLIER_QUESTION, None, None),
        ("assistant", _EARLIER_ANSWER, None, None),
        ("user", _LOOK_UP, None, None),
    ]
    fed_text = json.dumps(retry_calls)
    replayed = [
        marker
        for marker in (_SEEDED_RESULT, _RECALL_FAILED.tool_call_id, _ERROR_REPLY)
        if marker is not None and marker in fed_text
    ]
    assert replayed == []


# ---------------------------------------------------------------------------
# 4. Audit and logs
# ---------------------------------------------------------------------------


def test_chat_retry_agent_every_dispatch_writes_a_tool_call_row_and_the_failed_turns_stay(
    world: World, client: TestClient, llm: _ScriptLLM, tools: _Tools
) -> None:
    """Each of the retry's two dispatches writes its ``tool.call`` row (acting member of
    org A, targeting the chat); the failed turn's row stays as it was (append-only); no
    row holds the message, a tool argument or a tool result."""
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    _fail_turn(client, llm, editor, chat_id, _LOOK_UP, _RECALL_FAILED)
    failed_rows = [dict(row) for row in world.db.audit_rows("tool.call")]
    assert len(failed_rows) == 1
    llm.script(_LOOK_UP, _RECALL_RETRY, _STORE_RETRY)

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    rows = world.db.audit_rows("tool.call")
    assert rows[:1] == failed_rows
    assert _audit_outcomes(world.db) == [
        ("memory", "recall", "allow", True, False),
        ("memory", "recall", "allow", True, False),
        ("memory", "store", "allow", True, False),
    ]
    assert [
        (row["target_type"], row["target_ids"], plain(row["org_id"]), plain(row["actor_user_id"]))
        for row in rows[1:]
    ] == [("chat", [str(chat_id)], plain(ORG_ID), plain(editor.user_id))] * 2
    text = json.dumps(rows, default=str).casefold()
    content = [_LOOK_UP, _LEDGER_KEY, _RECALLED, _NOTE_KEY, _NOTE_VALUE]
    assert [value for value in content if value.casefold() in text] == []


def test_chat_retry_agent_logs_the_retry_line_and_no_content(
    world: World, client: TestClient, llm: _ScriptLLM, tools: _Tools
) -> None:
    """The whole flow (a failed turn after an approval, the retry asking again, the new
    approval), logged the way main() configures it at DEBUG: the retry's line names the
    chat once; no line names the message, the tool argument or result, a confirmation id
    or the caller's email."""
    editor = world.a["editor"]
    chat_id = _new_chat(world, editor)
    with configured_logging("DEBUG", "text") as captured:
        approved_id = _fail_after_approval(client, llm, world, editor, chat_id)
        llm.script(_BOOK, _CREATE_RETRY)
        retried = _retry(client, editor, chat_id)
        assert retried.status_code == 200, retried.text
        new_id = retried.json()["pending_confirmation"]["confirmation_id"]
        approved = _confirm(client, editor, chat_id, new_id)
        assert approved.status_code == 200, approved.text

    text = captured.text.casefold()
    assert text.count(f"retrying the last message of chat {chat_id}") == 1
    secrets = [
        _BOOK,
        _EVENT_TITLE,
        "Created event",
        _FINAL_REPLY,
        approved_id,
        new_id,
        editor.email,
    ]
    assert [secret for secret in secrets if secret.casefold() in text] == []
