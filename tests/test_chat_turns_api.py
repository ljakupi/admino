"""HTTP spec of chat turns on persisted chats (GH-176, contract sections 3 to 7).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin, an Editor and a Viewer
each, plus a Super Admin, all with real session cookies). Two agent kinds:

- a stub agent (``_Script``): its ``run`` binds every call to the contract's
  ``Agent.run`` signature, records what it got (history copied at call time) and
  answers a scripted ``AgentResult`` whose ``history`` is the history it received
  plus this turn's user message (none on a confirmation resume) plus the
  scripted new messages, like the real agent;
- the REAL ``admino.agent.Agent`` (real tool-call recorder of
  ``main._build_tool_call_recorder()``) around a scripted fake LLM keyed by the
  turn's user message, with fake tools registered in an isolated registry.

A "restart" is a new ``create_app()`` (it clears ``server._chat_runtime``) on
the same FakeDb.

What is pinned:
- POST /api/chats/{chat_id}/messages: Org Admin and Editor run a turn; Viewer
  and Super Admin get 403 before any chat statement; 401 without a session;
  CSRF 403 (a same-origin request runs); extra body fields, a message over
  32768 characters or over the stored ``max_message_length`` and a non-UUID id
  are 422 with no run; unknown, other-org, other-user and trashed chats answer
  the identical 404 ``chat_not_found`` with no run and nothing written.
- The run gets ``session_id == str(chat_id)``, the persisted tail (the latest
  ``max_context_messages`` messages, chronological, leading orphan tool
  messages dropped), the caller's principal, tool policy and prompt context,
  the stored limits, and ``earlier_external_content`` = the chat's flag.
- Persistence: exactly ``result.history[len(loaded):]`` is appended in order;
  the last appended message carries the run status (final -> complete) and the
  run's tool_calls; ``last_activity_at`` is bumped; the response has ``chat_id``
  and ``session_id`` null; an agent exception is the generic 500 and a chat
  trashed during the run the 404, both with nothing appended.
- Pending confirmations: the response and GET /api/chats/{id} show it; a new
  message cancels it and persists the synthetic cancelled tool result before
  the user message; after a restart it shows ``expired`` and confirming is 404.
- POST /api/confirm with ``chat_id``: approve resumes with the pending
  confirmation, the persisted tail and the chat's flag, and persists the new
  messages; deny persists the denial tool result(s) and the assistant reply;
  exactly one of ``chat_id`` / ``session_id``; another user's or org's chat and
  a wrong confirmation id are 404 with nothing changed.
- Legacy POST /api/message and POST /api/confirm are backed by a persisted chat
  per (user, ``legacy_session_id``) (GH-8 removed GET /api/events).
- The chat route and the legacy route share one per-user ``/api/message``
  bucket; a full ``ChatRuntime`` answers 503 ``chats_busy``; logs name neither
  message content nor legacy session ids.
- Real agent: a restart keeps turn 1's tool_use / tool_result pairing in what
  the LLM is fed; the ``tool.call`` audit row targets the chat's real UUID;
  GH-243's sticky ``external_content`` flag escalates a side-effecting allow
  action after a restart even when the wrapped message is outside the tail.
- A second request while the chat runs (security audit M-1, GH-8 decision 5):
  turn A reads an email (a wrapped tool result, so the chat's
  ``external_content`` becomes true) and is parked inside the chat's lock. A
  turn B sent meanwhile, on the chat route or the legacy route, is never queued
  any more: it answers ``409 {"detail": "A message is already running in this
  chat.", "reason": "run_active"}`` at once, never runs (with the real agent: no
  LLM call, no tool, no audit row for it) and stores nothing, while A's messages
  and flag are stored. An approval B (the approve path of POST /api/confirm)
  still waits for the running turn and then runs with
  ``earlier_external_content=True``, the flag read under the lock. Both requests
  run in the test's event loop (``httpx.ASGITransport``); a ``ChatRuntime``
  subclass records each ``hold()`` call, so B is known to have reached the chat
  (refused, or queued) before A goes on.
- Lone surrogates (security audit L-2): a model-produced tool input holding
  one doesn't break the turn: 200, persisted with U+FFFD in its place.
- Non-finite numbers (GH-266, re-audit L-4): a run whose tool_use input and
  tool-call record arguments hold NaN, Infinity, -Infinity and 1e400 (as
  ``json.loads`` parses them), at the top level and nested, answers 200 on the
  chat route and on the legacy route (the response's ``tool_calls`` with null),
  and the turn is stored with null in place of each in both ``tool_use_blocks``
  and ``tool_calls`` (every finite value with its JSON type); GET
  /api/chats/{id} reads it back.

New names (``admino.chat_runtime``, the routes, ``server._chat_runtime``) are
used lazily, so the file collects before GH-176 is implemented.

Security notes:
- Every message, id and session value here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from pydantic import BaseModel, Field

from admino import main as main_module
from admino import scoped_settings, server, untrusted
from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
)
from admino.server import create_app
from admino.tools import registry
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, plain
from tests.tenancy_world import (
    CLIENT_IP,
    FORBIDDEN,
    UNAUTHORIZED,
    build_world,
    make_app,
    make_client,
    make_config,
    stub_agent,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from unittest.mock import MagicMock

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CHAT_NOT_FOUND: Final = {"detail": "Chat not found", "reason": "chat_not_found"}
_NO_PENDING: Final = {"detail": "No pending confirmation for this session"}
_CONFIRMATION_NOT_FOUND: Final = {"detail": "Confirmation not found"}
_INTERNAL_ERROR: Final = {"detail": "Internal error"}
_CHATS_BUSY: Final = {
    "detail": "Too many active chats. Try again shortly.",
    "reason": "chats_busy",
}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
# GH-8: a turn sent while the chat's run is going.
_RUN_ACTIVE: Final = {
    "detail": "A message is already running in this chat.",
    "reason": "run_active",
}
_DENIED_RESULT: Final = "Tool call denied by the user."

_CONFIRMATION_ID: Final = "confirm-176-kestrel"
_LEGACY_SESSION: Final = "legacy-176-heron"
_STUB_REPLY: Final = "Done."
_MESSAGE: Final = "Hello there"
_LONG_AGO: Final = datetime(2026, 1, 1, tzinfo=UTC)

# A statement on either chat table (FakeDb's normalized SQL).
_CHAT_SQL: Final = re.compile(r"\bchat(?:s|_messages)\b")

_PENDING_CALL: Final = ToolCall(
    tool="memory", action="store", args={"key": "plan", "value": "ship"}, tool_call_id="call-p176"
)
_OTHER_CALL: Final = ToolCall(
    tool="memory", action="recall", args={"key": "plan"}, tool_call_id="call-q176"
)
_LIST_CALL: Final = ToolCall(tool="memory", action="list", args={}, tool_call_id="call-r176")
_RECALL_RECORD: Final = ToolCallRecord(
    tool="memory",
    action="recall",
    args={"key": "plan"},
    permission="allow",
    success=True,
    duration_ms=7,
)

# ---------------------------------------------------------------------------
# Messages
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


def _dump(messages: Any) -> list[dict[str, Any]]:
    return [message.model_dump() for message in messages]


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


# ---------------------------------------------------------------------------
# The stub agent
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Reply:
    """What one stub run answers: the new messages after the user message and the outcome."""

    new: tuple[LLMMessage, ...] = (LLMMessage(role="assistant", content=_STUB_REPLY),)
    status: str = "final"
    response: str = _STUB_REPLY
    tool_calls: tuple[ToolCallRecord, ...] = ()
    pending: ToolCall | None = None
    error: Exception | None = None


@dataclass(frozen=True)
class _Run:
    """One stub run: the bound arguments (history copied at call time) and the keyword names."""

    user_message: str
    session_id: str
    history: tuple[LLMMessage, ...]
    arguments: dict[str, Any]
    keywords: frozenset[str]

    @property
    def flag(self) -> object:
        """``earlier_external_content`` when passed as a keyword, else a sentinel string."""
        if "earlier_external_content" not in self.keywords:
            return "<not passed>"
        return self.arguments["earlier_external_content"]


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
) -> None:
    """``Agent.run``'s contract signature (section 4); every stub call is bound to it."""


def _awaiting(*calls: ToolCall) -> _Reply:
    """A run that asks to confirm the first of ``calls`` (default: ``_PENDING_CALL``)."""
    asked = calls or (_PENDING_CALL,)
    first = asked[0]
    return _Reply(
        new=(_tool_use(*asked),),
        status="awaiting_confirmation",
        response=f"Action {first.tool}.{first.action} requires user confirmation.",
        tool_calls=(
            ToolCallRecord(
                tool=first.tool,
                action=first.action,
                args=first.args,
                permission="confirm",
                success=False,
                duration_ms=1,
            ),
        ),
        pending=first,
    )


class _Script:
    """Scripted replies for the stub agent's ``run`` and the record of every call."""

    def __init__(self) -> None:
        self.replies: list[_Reply] = []
        self.runs: list[_Run] = []
        # Awaited once, inside the next run, before it answers (then cleared).
        self.during: Callable[[], Awaitable[None]] | None = None

    def queue(self, *replies: _Reply) -> None:
        self.replies.extend(replies)

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        bound = inspect.signature(_run_signature).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        history = list(arguments["history"])
        self.runs.append(
            _Run(
                user_message=arguments["user_message"],
                session_id=arguments["session_id"],
                history=tuple(message.model_copy(deep=True) for message in history),
                arguments=arguments,
                keywords=frozenset(kwargs),
            )
        )
        during, self.during = self.during, None
        if during is not None:
            await during()
        reply = self.replies.pop(0) if self.replies else _Reply()
        if reply.error is not None:
            raise reply.error
        base = [message for message in history if message.role != "system"]
        if arguments["pending_confirmation"] is None:
            base.append(_user(arguments["user_message"]))
        pending = None
        if reply.pending is not None:
            pending = PendingConfirmation(
                confirmation_id=_CONFIRMATION_ID,
                session_id=arguments["session_id"],
                tool_call=reply.pending,
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
        return AgentResult(
            status=reply.status,  # type: ignore[arg-type]
            response=reply.response,
            history=[*base, *reply.new],
            tool_calls=list(reply.tool_calls),
            pending_confirmation=pending,
        )


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
# Helpers
# ---------------------------------------------------------------------------


def _restart(agent: MagicMock) -> TestClient:
    """A new app (``create_app`` clears the in-memory chat runtime) on the same FakeDb."""
    return make_client(make_app(agent), raise_server_exceptions=False)


def _send(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID | str,
    message: str = _MESSAGE,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account``."""
    return client.post(
        f"/api/chats/{chat_id}/messages",
        headers={**account.cookie, **(headers or {})},
        json={"message": message} if body is None else body,
    )


def _legacy(
    client: TestClient,
    account: Account,
    message: str = _MESSAGE,
    session_id: str = _LEGACY_SESSION,
) -> httpx.Response:
    """POST /api/message (legacy session id) as ``account``."""
    return client.post(
        "/api/message",
        headers=account.cookie,
        json={"message": message, "session_id": session_id},
    )


def _confirm(
    client: TestClient,
    account: Account,
    *,
    chat_id: uuid.UUID | None = None,
    session_id: str | None = None,
    approved: bool = True,
    confirmation_id: str = _CONFIRMATION_ID,
) -> httpx.Response:
    """POST /api/confirm/{confirmation_id} with ``chat_id`` and/or ``session_id``."""
    body: dict[str, Any] = {"confirmation_id": confirmation_id, "approved": approved}
    if chat_id is not None:
        body["chat_id"] = str(chat_id)
    if session_id is not None:
        body["session_id"] = session_id
    return client.post(f"/api/confirm/{confirmation_id}", headers=account.cookie, json=body)


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


def _snapshot(db: FakeDb, chat_id: uuid.UUID) -> tuple[dict[str, Any] | None, list[Row]]:
    """The chat row and its stored messages (to prove nothing changed)."""
    return db.chat_row(chat_id), _stored(db, chat_id)


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the httpx client lines, which name request URLs)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


# ---------------------------------------------------------------------------
# 1. The route's gates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["org_admin", "editor"])
def test_chat_turns_member_with_chat_send_runs_the_turn(
    world: World, client: TestClient, agent: MagicMock, role: str
) -> None:
    account = world.a[role]  # type: ignore[index]
    chat_id = world.db.add_chat(account.user_id)

    response = _send(client, account, chat_id)

    assert response.status_code == 200, response.text
    assert response.json()["chat_id"] == str(chat_id)
    assert agent.run.await_count == 1


@pytest.mark.parametrize("role", ["viewer", "super_admin"])
def test_chat_turns_viewer_and_super_admin_get_403_before_any_chat_statement(
    world: World, client: TestClient, agent: MagicMock, role: str
) -> None:
    """A Viewer's own chat (kept from before a demotion) and, for the Super Admin, an
    Editor's chat: 403 ``Forbidden``, no run and no statement on either chat table."""
    account = world.by_role(role)  # type: ignore[arg-type]
    owner = world.a["viewer"] if role == "viewer" else world.a["editor"]
    chat_id = world.db.add_chat(owner.user_id)
    before = len(world.db.calls)

    response = _send(client, account, chat_id)

    assert (response.status_code, response.json()) == (403, FORBIDDEN)
    assert agent.run.await_count == 0
    assert _chat_calls(world.db, before) == []
    assert world.db.messages_of(chat_id) == []


def test_chat_turns_without_session_get_401(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    chat_id = world.db.add_chat(world.a["editor"].user_id)

    response = client.post(f"/api/chats/{chat_id}/messages", json={"message": _MESSAGE})

    assert (response.status_code, response.json()) == (401, UNAUTHORIZED)
    assert agent.run.await_count == 0
    assert world.db.messages_of(chat_id) == []


def test_chat_turns_cross_origin_post_is_refused_and_same_origin_runs(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    """The CSRF middleware refuses a cross-site POST before the route; the same request
    marked same-origin reaches the route and runs (so the refusal is the route's)."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)

    refused = _send(client, editor, chat_id, headers={"Sec-Fetch-Site": "cross-site"})
    assert (refused.status_code, refused.json()) == (403, _CSRF_REFUSED)
    assert agent.run.await_count == 0
    assert world.db.messages_of(chat_id) == []

    allowed = _send(client, editor, chat_id, headers={"Sec-Fetch-Site": "same-origin"})
    assert allowed.status_code == 200, allowed.text
    assert agent.run.await_count == 1


def test_chat_turns_extra_body_field_gets_422_without_echo(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    """Whose chat it is comes from the path and the session only: a smuggled org id is a
    422 that doesn't repeat the value; no run, nothing written."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)

    response = _send(
        client, editor, chat_id, body={"message": _MESSAGE, "org_id": str(OTHER_ORG_ID)}
    )

    assert response.status_code == 422
    assert str(OTHER_ORG_ID) not in response.text
    assert agent.run.await_count == 0
    assert world.db.messages_of(chat_id) == []


def test_chat_turns_message_over_32768_characters_gets_422(
    world: World, client: TestClient, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a stored limit above it, ``ChatMessageCreate``'s 32768 bound decides: 32769
    characters are refused before the run, 32768 run."""
    _stored_limits(monkeypatch, max_message_length=100000)
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)

    refused = _send(client, editor, chat_id, "m" * 32769)
    assert refused.status_code == 422
    assert agent.run.await_count == 0
    assert world.db.messages_of(chat_id) == []

    accepted = _send(client, editor, chat_id, "m" * 32768)
    assert accepted.status_code == 200, accepted.text


def test_chat_turns_message_over_stored_max_length_gets_422(
    world: World, client: TestClient, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stored ``max_message_length`` (GH-160) applies to the chat route too, with the
    existing 422; a message at the limit runs."""
    _stored_limits(monkeypatch, max_message_length=10)
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)

    refused = _send(client, editor, chat_id, "m" * 11)
    assert refused.status_code == 422
    assert refused.json() == {"detail": "Message exceeds maximum length of 10 characters"}
    assert agent.run.await_count == 0
    assert world.db.messages_of(chat_id) == []

    accepted = _send(client, editor, chat_id, "m" * 10)
    assert accepted.status_code == 200, accepted.text


@pytest.mark.parametrize("case", ["unknown", "other_org", "other_user", "trashed"])
def test_chat_turns_missing_foreign_or_trashed_chat_gets_identical_404(
    world: World, client: TestClient, agent: MagicMock, case: str
) -> None:
    """Unknown id, another org's chat, another member's chat of the same org and the
    caller's own trashed chat: the same 404 body, no run, nothing written."""
    editor = world.a["editor"]
    db = world.db
    if case == "unknown":
        chat_id = uuid.uuid4()
    elif case == "other_org":
        chat_id = db.add_chat(world.b["editor"].user_id, last_activity_at=_LONG_AGO)
    elif case == "other_user":
        chat_id = db.add_chat(world.a["org_admin"].user_id, last_activity_at=_LONG_AGO)
    else:
        chat_id = db.add_chat(
            editor.user_id, last_activity_at=_LONG_AGO, deleted_at=datetime.now(UTC)
        )
    if case != "unknown":
        _seed(db, chat_id, _user("Earlier question"))
    before = _snapshot(db, chat_id)
    message_count = len(db.chat_messages)

    response = _send(client, editor, chat_id)

    assert (response.status_code, response.json()) == (404, _CHAT_NOT_FOUND)
    assert agent.run.await_count == 0
    assert _snapshot(db, chat_id) == before
    assert len(db.chat_messages) == message_count


def test_chat_turns_non_uuid_chat_id_gets_422(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    response = _send(client, world.a["editor"], "not-a-uuid")

    assert response.status_code == 422
    assert agent.run.await_count == 0


# ---------------------------------------------------------------------------
# 2. What the run gets
# ---------------------------------------------------------------------------


def test_chat_turns_run_gets_the_chat_id_and_the_persisted_tail(
    world: World,
    client: TestClient,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Seven stored messages, stored ``max_context_messages`` 5: the run gets the latest 5
    in chronological order minus the two leading tool results (their assistant turn is
    older), as ``session_id`` the chat's UUID, and the stored limits."""
    _stored_limits(monkeypatch, max_context_messages=5)
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    _seed(
        world.db,
        chat_id,
        _user("First question"),
        _tool_use(_OTHER_CALL, _LIST_CALL),
        _tool("Plan: ship", _OTHER_CALL),
        _tool("plan", _LIST_CALL),
        _assistant("First answer"),
        _user("Second question"),
        _assistant("Second answer"),
    )

    response = _send(client, editor, chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert run.session_id == str(chat_id)
    assert run.user_message == _MESSAGE
    assert _dump(run.history) == _dump(
        [_assistant("First answer"), _user("Second question"), _assistant("Second answer")]
    )
    assert run.arguments["agent_config"].max_context_messages == 5


def test_chat_turns_run_gets_the_callers_principal_policy_and_prompt_context(
    world: World, client: TestClient, script: _Script
) -> None:
    """Org A's own tool policy and instructions (org B's differ) and the Editor's principal."""
    editor = world.a["editor"]
    world.db.add_permissions(ORG_ID, {"memory": {"store": "confirm"}})
    # build_world stored both org_settings rows (instructions ''): set the texts in place.
    world.db.org_settings[ORG_ID]["instructions"] = "Org A instructions 176"
    world.db.org_settings[OTHER_ORG_ID]["instructions"] = "Org B instructions 176"
    chat_id = world.db.add_chat(editor.user_id)

    response = _send(client, editor, chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    principal = run.arguments["principal"]
    assert (plain(principal.user_id), plain(principal.org_id)) == (
        plain(editor.user_id),
        plain(ORG_ID),
    )
    assert run.arguments["tool_policy"].permissions.tools["memory"].actions["store"] == "confirm"
    assert run.arguments["prompt_context"].org_instructions == "Org A instructions 176"


@pytest.mark.parametrize("flag", [False, True])
def test_chat_turns_run_gets_the_chats_external_content_flag(
    world: World, client: TestClient, script: _Script, flag: bool
) -> None:
    """GH-243: ``earlier_external_content`` is the chat's sticky flag, passed explicitly."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id, external_content=flag)

    response = _send(client, editor, chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert run.flag is flag


# ---------------------------------------------------------------------------
# 3. Persistence of the turn
# ---------------------------------------------------------------------------


def test_chat_turns_appends_exactly_the_runs_new_messages_in_order(
    world: World, client: TestClient, script: _Script
) -> None:
    """``result.history[len(loaded):]`` (the user message, the tool turn, its result and
    the reply) is appended after the stored messages, all ``complete``; the run's
    tool_calls sit on the last message only; ``last_activity_at`` moves; the response
    names the chat and no session."""
    editor = world.a["editor"]
    db = world.db
    chat_id = db.add_chat(editor.user_id, created_at=_LONG_AGO, last_activity_at=_LONG_AGO)
    seeded = (_user("Earlier question"), _assistant("Earlier answer"))
    _seed(db, chat_id, *seeded)
    new = (_tool_use(_OTHER_CALL), _tool("Plan: ship", _OTHER_CALL), _assistant("Here it is."))
    script.queue(_Reply(new=new, response="Here it is.", tool_calls=(_RECALL_RECORD,)))

    response = _send(client, editor, chat_id)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["chat_id"], body["session_id"], body["status"]) == (str(chat_id), None, "final")
    assert body["response"] == "Here it is."
    assert _stored(db, chat_id) == [_row(m) for m in (*seeded, _user(_MESSAGE), *new)]
    assert [m["tool_calls"] for m in db.messages_of(chat_id)] == [None] * 5 + [
        [_RECALL_RECORD.model_dump(mode="json")]
    ]
    chat = db.chat_row(chat_id)
    assert chat is not None
    assert chat["last_activity_at"] > _LONG_AGO


@pytest.mark.parametrize(
    ("status", "stored_status"),
    [
        ("final", "complete"),
        ("awaiting_confirmation", "awaiting_confirmation"),
        ("limit_reached", "limit_reached"),
        ("error", "error"),
    ],
)
def test_chat_turns_last_appended_message_carries_the_run_status(
    world: World, client: TestClient, script: _Script, status: str, stored_status: str
) -> None:
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    head = (_tool_use(_OTHER_CALL), _tool("Plan: ship", _OTHER_CALL))
    if status == "awaiting_confirmation":
        reply = _awaiting()
        script.queue(_Reply(**{**reply.__dict__, "new": (*head, *reply.new)}))
    else:
        script.queue(
            _Reply(new=(*head, _assistant("Stopped here.")), status=status, response="Stopped.")
        )

    response = _send(client, editor, chat_id)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == status
    assert [m["status"] for m in world.db.messages_of(chat_id)] == ["complete"] * 3 + [
        stored_status
    ]


def test_chat_turns_agent_exception_gets_500_and_appends_nothing(
    world: World, client: TestClient, script: _Script
) -> None:
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id, last_activity_at=_LONG_AGO)
    _seed(world.db, chat_id, _user("Earlier question"))
    before = _snapshot(world.db, chat_id)
    script.queue(_Reply(error=RuntimeError("agent failure 176")))

    response = _send(client, editor, chat_id)

    assert (response.status_code, response.json()) == (500, _INTERNAL_ERROR)
    assert _snapshot(world.db, chat_id) == before


def test_chat_turns_chat_trashed_during_the_run_gets_404_and_appends_nothing(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    editor = world.a["editor"]
    db = world.db
    chat_id = db.add_chat(editor.user_id)
    _seed(db, chat_id, _user("Earlier question"))

    async def trash() -> None:
        db.chats[uuid.UUID(int=chat_id.int)]["deleted_at"] = datetime.now(UTC)

    script.during = trash

    response = _send(client, editor, chat_id)

    assert (response.status_code, response.json()) == (404, _CHAT_NOT_FOUND)
    assert agent.run.await_count == 1
    assert _stored(db, chat_id) == [_row(_user("Earlier question"))]


# ---------------------------------------------------------------------------
# 4. Pending confirmations
# ---------------------------------------------------------------------------


def test_chat_turns_awaiting_run_reports_the_pending_confirmation(
    world: World, client: TestClient, script: _Script
) -> None:
    """The response's ``pending_confirmation`` and GET /api/chats/{id}'s ``pending``."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting())

    response = _send(client, editor, chat_id)

    assert response.status_code == 200, response.text
    pending = response.json()["pending_confirmation"]
    assert (pending["confirmation_id"], pending["tool"], pending["action"], pending["args"]) == (
        _CONFIRMATION_ID,
        "memory",
        "store",
        {"key": "plan", "value": "ship"},
    )
    detail = _detail(client, editor, chat_id)
    assert detail["confirmation_status"] == "pending"
    assert detail["pending_confirmation"]["confirmation_id"] == _CONFIRMATION_ID


def test_chat_turns_new_message_cancels_the_pending_confirmation(
    world: World, client: TestClient, script: _Script
) -> None:
    """Sending instead of confirming: the dangling tool_use gets the synthetic cancelled
    result, passed to the run and persisted before the new user message; the old
    confirmation is gone (404) and the chat shows none."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting())
    assert _send(client, editor, chat_id).status_code == 200
    cancelled = _tool(server._CANCELLED_TOOL_RESULT_MSG, _PENDING_CALL)

    response = _send(client, editor, chat_id, "Never mind")

    assert response.status_code == 200, response.text
    assert _dump(script.runs[1].history) == _dump(
        [_user(_MESSAGE), _tool_use(_PENDING_CALL), cancelled]
    )
    assert _stored(world.db, chat_id) == [
        _row(_user(_MESSAGE)),
        _row(_tool_use(_PENDING_CALL), "awaiting_confirmation"),
        _row(cancelled),
        _row(_user("Never mind")),
        _row(_assistant(_STUB_REPLY)),
    ]
    late = _confirm(client, editor, chat_id=chat_id)
    assert (late.status_code, late.json()) == (404, _NO_PENDING)
    assert _detail(client, editor, chat_id)["confirmation_status"] == "none"


def test_chat_turns_pending_confirmation_after_restart_is_expired(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """Pending confirmations live in memory only: after a restart the chat shows
    ``expired`` (no pending confirmation) and confirming is 404, with no run."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting())
    assert _send(client, editor, chat_id).status_code == 200
    assert _detail(client, editor, chat_id)["confirmation_status"] == "pending"
    before = _snapshot(world.db, chat_id)

    restarted = _restart(agent)

    detail = _detail(restarted, editor, chat_id)
    assert (detail["confirmation_status"], detail["pending_confirmation"]) == ("expired", None)
    response = _confirm(restarted, editor, chat_id=chat_id)
    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert agent.run.await_count == 1
    assert _snapshot(world.db, chat_id) == before


# ---------------------------------------------------------------------------
# 5. POST /api/confirm with chat_id
# ---------------------------------------------------------------------------


def test_chat_turns_confirm_approve_resumes_with_the_persisted_tail(
    world: World, client: TestClient, script: _Script
) -> None:
    """Approve: the run gets the pending confirmation, the persisted tail as stored (the
    dangling tool_use is NOT closed: the resume dispatches it), the chat's flag and the
    chat's UUID; its new messages are appended and the chat shows no confirmation."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id, external_content=True)
    script.queue(_awaiting())
    assert _send(client, editor, chat_id).status_code == 200
    stored_record = ToolCallRecord(
        tool="memory",
        action="store",
        args={"key": "plan", "value": "ship"},
        permission="confirm",
        success=True,
        duration_ms=3,
    )
    resumed = (_tool("Stored memory: plan", _PENDING_CALL), _assistant("Saved your plan."))
    script.queue(_Reply(new=resumed, response="Saved your plan.", tool_calls=(stored_record,)))

    response = _confirm(client, editor, chat_id=chat_id)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["chat_id"], body["session_id"], body["status"]) == (str(chat_id), None, "final")
    assert body["response"] == "Saved your plan."
    run = script.runs[1]
    pending = run.arguments["pending_confirmation"]
    assert pending is not None
    assert (pending.confirmation_id, pending.tool_call) == (_CONFIRMATION_ID, _PENDING_CALL)
    assert (run.user_message, run.session_id, run.flag) == ("", str(chat_id), True)
    assert _dump(run.history) == _dump([_user(_MESSAGE), _tool_use(_PENDING_CALL)])
    assert _stored(world.db, chat_id) == [
        _row(_user(_MESSAGE)),
        _row(_tool_use(_PENDING_CALL), "awaiting_confirmation"),
        *(_row(m) for m in resumed),
    ]
    assert [m["tool_calls"] for m in world.db.messages_of(chat_id)][2:] == [
        None,
        [stored_record.model_dump(mode="json")],
    ]
    assert _detail(client, editor, chat_id)["confirmation_status"] == "none"


def test_chat_turns_confirm_deny_persists_the_denial(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """Deny: no run; the tool result "Tool call denied by the user." for the pending call
    and the assistant's "Action memory.store was denied." are persisted (complete, no
    tool_calls), so the history stays well-formed; the chat shows no confirmation."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting())
    assert _send(client, editor, chat_id).status_code == 200

    response = _confirm(client, editor, chat_id=chat_id, approved=False)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["chat_id"], body["session_id"], body["status"]) == (str(chat_id), None, "final")
    assert body["response"] == "Action memory.store was denied."
    assert agent.run.await_count == 1
    assert _stored(world.db, chat_id) == [
        _row(_user(_MESSAGE)),
        _row(_tool_use(_PENDING_CALL), "awaiting_confirmation"),
        _row(_tool(_DENIED_RESULT, _PENDING_CALL)),
        _row(_assistant("Action memory.store was denied.")),
    ]
    assert [m["tool_calls"] for m in world.db.messages_of(chat_id)][2:] == [None, None]
    assert _detail(client, editor, chat_id)["confirmation_status"] == "none"


def test_chat_turns_confirm_deny_closes_every_dangling_tool_use(
    world: World, client: TestClient, script: _Script
) -> None:
    """A batch whose first call asked for confirmation leaves two dangling tool_use blocks:
    the pending call gets the denial, the other one today's cancelled text, in block order."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting(_PENDING_CALL, _OTHER_CALL))
    assert _send(client, editor, chat_id).status_code == 200

    response = _confirm(client, editor, chat_id=chat_id, approved=False)

    assert response.status_code == 200, response.text
    assert _stored(world.db, chat_id)[2:] == [
        _row(_tool(_DENIED_RESULT, _PENDING_CALL)),
        _row(_tool(server._CANCELLED_TOOL_RESULT_MSG, _OTHER_CALL)),
        _row(_assistant("Action memory.store was denied.")),
    ]


def test_chat_turns_confirm_needs_exactly_one_of_chat_id_and_session_id(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    """Both or neither: 422 that repeats neither value. ``chat_id`` alone is a valid body
    (here a chat without a pending confirmation: today's 404)."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)

    both = _confirm(client, editor, chat_id=chat_id, session_id=_LEGACY_SESSION)
    neither = _confirm(client, editor)
    alone = _confirm(client, editor, chat_id=chat_id)

    assert (both.status_code, neither.status_code) == (422, 422)
    assert str(chat_id) not in both.text
    assert _LEGACY_SESSION not in both.text
    assert (alone.status_code, alone.json()) == (404, _NO_PENDING)
    assert agent.run.await_count == 0


@pytest.mark.parametrize("intruder", ["same_org_admin", "other_org_editor"])
def test_chat_turns_confirm_on_another_users_chat_gets_404_and_changes_nothing(
    world: World, client: TestClient, agent: MagicMock, script: _Script, intruder: str
) -> None:
    """The Editor's pending confirmation, confirmed by another member of org A or by org
    B's Editor with the right ids: today's 404 body; no run; the owner still sees it."""
    editor = world.a["editor"]
    other = world.a["org_admin"] if intruder == "same_org_admin" else world.b["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting())
    assert _send(client, editor, chat_id).status_code == 200
    before = _snapshot(world.db, chat_id)

    response = _confirm(client, other, chat_id=chat_id)

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert agent.run.await_count == 1
    assert _snapshot(world.db, chat_id) == before
    assert _detail(client, editor, chat_id)["confirmation_status"] == "pending"


def test_chat_turns_confirm_with_a_wrong_confirmation_id_gets_404(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    script.queue(_awaiting())
    assert _send(client, editor, chat_id).status_code == 200
    before = _snapshot(world.db, chat_id)

    response = _confirm(client, editor, chat_id=chat_id, confirmation_id="confirm-176-other")

    assert (response.status_code, response.json()) == (404, _CONFIRMATION_NOT_FOUND)
    assert agent.run.await_count == 1
    assert _snapshot(world.db, chat_id) == before
    assert _detail(client, editor, chat_id)["confirmation_status"] == "pending"


# ---------------------------------------------------------------------------
# 6. Legacy session ids (until #177)
# ---------------------------------------------------------------------------


def test_chat_turns_legacy_message_creates_a_persisted_legacy_chat(
    world: World, client: TestClient, script: _Script
) -> None:
    """The first POST /api/message of a session id creates the caller's chat with that
    ``legacy_session_id``; the run gets the chat's UUID; the response echoes the session
    id and names the chat; the chat is in GET /api/chats."""
    editor = world.a["editor"]

    response = _legacy(client, editor, "first")

    assert response.status_code == 200, response.text
    (chat,) = world.db.chats_of(editor.user_id)
    assert chat["legacy_session_id"] == _LEGACY_SESSION
    body = response.json()
    assert (body["chat_id"], body["session_id"]) == (str(chat["id"]), _LEGACY_SESSION)
    assert script.runs[0].session_id == str(chat["id"])
    assert _stored(world.db, chat["id"]) == [_row(_user("first")), _row(_assistant(_STUB_REPLY))]
    listed = client.get("/api/chats", headers=editor.cookie)
    assert listed.status_code == 200, listed.text
    assert [item["id"] for item in listed.json()["chats"]] == [str(chat["id"])]


def test_chat_turns_legacy_second_message_reuses_the_chat_after_restart(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    editor = world.a["editor"]
    assert _legacy(client, editor, "first").status_code == 200

    response = _legacy(_restart(agent), editor, "second")

    assert response.status_code == 200, response.text
    (chat,) = world.db.chats_of(editor.user_id)
    assert _dump(script.runs[1].history) == _dump([_user("first"), _assistant(_STUB_REPLY)])
    assert response.json()["chat_id"] == str(chat["id"])
    assert len(world.db.messages_of(chat["id"])) == 4


def test_chat_turns_legacy_session_id_of_another_user_is_their_own_chat(
    world: World, client: TestClient, script: _Script
) -> None:
    """Org A's Org Admin sends under the Editor's session id: a chat of their own, a run
    without the Editor's turn."""
    editor, admin = world.a["editor"], world.a["org_admin"]
    assert _legacy(client, editor, "editor turn").status_code == 200

    response = _legacy(client, admin, "admin turn")

    assert response.status_code == 200, response.text
    (editor_chat,) = world.db.chats_of(editor.user_id)
    (admin_chat,) = world.db.chats_of(admin.user_id)
    assert plain(admin_chat["id"]) != plain(editor_chat["id"])
    assert admin_chat["legacy_session_id"] == _LEGACY_SESSION
    assert response.json()["chat_id"] == str(admin_chat["id"])
    assert script.runs[1].history == ()
    assert len(world.db.messages_of(editor_chat["id"])) == 2


def test_chat_turns_legacy_confirm_finds_the_pending_confirmation_by_session_id(
    world: World, client: TestClient, script: _Script
) -> None:
    """POST /api/confirm with the legacy ``session_id`` resumes the legacy chat's pending
    confirmation (session id echoed, chat named). An unknown session id is today's 404 and
    creates no chat."""
    editor = world.a["editor"]
    unknown = _confirm(client, editor, session_id="legacy-176-unknown")
    assert (unknown.status_code, unknown.json()) == (404, _NO_PENDING)
    assert world.db.chats_of(editor.user_id) == []
    script.queue(_awaiting())
    assert _legacy(client, editor).status_code == 200
    (chat,) = world.db.chats_of(editor.user_id)
    script.queue(_Reply(new=(_tool("Stored memory: plan", _PENDING_CALL), _assistant("Saved."))))

    response = _confirm(client, editor, session_id=_LEGACY_SESSION)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["chat_id"], body["session_id"]) == (str(chat["id"]), _LEGACY_SESSION)
    run = script.runs[1]
    assert run.arguments["pending_confirmation"] is not None
    assert run.session_id == str(chat["id"])
    assert [row[1] for row in _stored(world.db, chat["id"])][2:] == [
        "Stored memory: plan",
        "Saved.",
    ]


# ---------------------------------------------------------------------------
# 7. Rate bucket, runtime capacity, logs
# ---------------------------------------------------------------------------


def test_chat_turns_chat_route_and_legacy_route_share_one_rate_bucket(
    world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``/api/message`` with burst 2 and no refill to speak of: one chat-route and one
    legacy request spend it, the next request on either route is 429; another user's
    bucket is untouched."""
    monkeypatch.setitem(server._RATE_LIMITS, "/api/message", (0.0001, 2))
    editor, admin = world.a["editor"], world.a["org_admin"]
    chat_id = world.db.add_chat(editor.user_id)

    assert _send(client, editor, chat_id).status_code == 200
    assert _legacy(client, editor).status_code == 200
    assert _send(client, editor, chat_id).status_code == 429
    assert _legacy(client, editor).status_code == 429

    other = _send(client, admin, world.db.add_chat(admin.user_id))
    assert other.status_code == 200, other.text


def test_chat_turns_full_runtime_gets_503_chats_busy(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``ChatRuntime`` of one entry, held by the Editor's in-flight turn: the Org Admin's
    turn on another chat (sent from inside the running agent) is 503 ``chats_busy`` with
    nothing appended; the in-flight turn completes."""
    from admino.chat_runtime import ChatRuntime

    app = make_app(agent)
    client = make_client(app, raise_server_exceptions=False)
    monkeypatch.setattr(server, "_chat_runtime", ChatRuntime(max_entries=1, idle_s=900.0))
    editor, admin = world.a["editor"], world.a["org_admin"]
    busy_chat = world.db.add_chat(editor.user_id)
    other_chat = world.db.add_chat(admin.user_id)
    nested: list[httpx.Response] = []

    async def second_turn() -> None:
        transport = httpx.ASGITransport(
            app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50001)
        )
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as inner:
            nested.append(
                await inner.post(
                    f"/api/chats/{other_chat}/messages",
                    headers=admin.cookie,
                    json={"message": "second chat"},
                )
            )

    script.during = second_turn

    response = _send(client, editor, busy_chat)

    assert response.status_code == 200, response.text
    (busy,) = nested
    assert (busy.status_code, busy.json()) == (503, _CHATS_BUSY)
    assert world.db.messages_of(other_chat) == []
    assert agent.run.await_count == 1


def test_chat_turns_logs_name_neither_content_nor_legacy_session_id(
    world: World, client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """Logs name chat ids only: no message text and no legacy session id in any app record."""
    caplog.set_level(logging.DEBUG)
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    legacy_session = "legacy-canary-176-plover"

    chat_turn = _send(client, editor, chat_id, "chat-canary-176-curlew")
    legacy_turn = _legacy(client, editor, "legacy-canary-176-avocet", legacy_session)

    assert (chat_turn.status_code, legacy_turn.status_code) == (200, 200)
    text = _app_log_text(caplog)
    for canary in ("chat-canary-176-curlew", "legacy-canary-176-avocet", legacy_session):
        assert canary not in text


# ---------------------------------------------------------------------------
# 8. The real agent: restart round trip, audit target, sticky external content
# ---------------------------------------------------------------------------

_FINAL_REPLY: Final = "All done."
_RECALLED: Final = "Plan: ship GH-176"
_MAIL_BODY: Final = "Quarterly figures attached."

_RECALL: Final = ToolCall(
    tool="memory", action="recall", args={"key": "plan"}, tool_call_id="call-rt176"
)
_READ_MAIL: Final = ToolCall(
    tool="gmail", action="read", args={"message_id": "m176"}, tool_call_id="call-mail176"
)
_STORE: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": "plan", "value": "ship"},
    tool_call_id="call-store176",
)


class _KeyArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)


class _StoreArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    value: str = Field(min_length=1, max_length=200)


class _MailArgs(BaseModel):
    message_id: str = Field(min_length=1, max_length=50)


@dataclass
class _Tools:
    """What the fake tools did: the notes ``memory.store`` wrote."""

    stored: list[tuple[str, str]] = field(default_factory=list)


class _ScriptLLM:
    """Plays a script per user message (the n-th call of a turn returns the n-th scripted
    tool call, counted by the assistant turns after the user message, then the final
    reply) and records the non-system messages of every call."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self._scripts: dict[str, list[ToolCall]] = {}
        self.calls: list[tuple[str, list[dict[str, Any]]]] = []

    def script(self, message: str, *calls: ToolCall) -> None:
        self._scripts[message] = list(calls)

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
            return LLMResponse(content="", tool_calls=[steps[done]])
        return LLMResponse(content=_FINAL_REPLY)

    async def close(self) -> None:
        """Nothing to close."""

    def fed(self, message: str) -> list[list[dict[str, Any]]]:
        """The non-system messages of every LLM call of ``message``'s turn."""
        return [fed for user_message, fed in self.calls if user_message == message]


@pytest.fixture()
def tools(monkeypatch: pytest.MonkeyPatch) -> _Tools:
    """An unfrozen registry holding memory.recall (plain result), gmail.read (wrapped
    external content) and memory.store (a side effect); the previous one is restored."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    seen = _Tools()

    async def recall(args: _KeyArgs, **_: Any) -> str:
        return _RECALLED

    async def read(args: _MailArgs, **_: Any) -> str:
        wrapped: str = untrusted.wrap("email", f"message {args.message_id}", _MAIL_BODY)
        return wrapped

    async def store(args: _StoreArgs, **_: Any) -> str:
        seen.stored.append((args.key, args.value))
        return f"Stored memory: {args.key}"

    register: Any = registry.register_tool
    register("memory", "recall", "Recall a note (GH-176)", _KeyArgs, side_effect=False)(recall)
    register("gmail", "read", "Read an email (GH-176)", _MailArgs, side_effect=False)(read)
    register("memory", "store", "Store a note (GH-176)", _StoreArgs, side_effect=True)(store)
    return seen


@pytest.fixture()
def llm() -> _ScriptLLM:
    return _ScriptLLM()


def _real_app(llm: _ScriptLLM) -> FastAPI:
    """A new app (a restart) around a new REAL Agent with the real tool-call recorder."""
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    app: FastAPI = create_app(agent=agent, config=make_config())
    return app


def _real_client(llm: _ScriptLLM) -> TestClient:
    """A client of ``_real_app(llm)``."""
    return make_client(_real_app(llm), raise_server_exceptions=False)


def test_chat_turns_restart_round_trip_keeps_the_tool_use_pairing(
    world: World, tools: _Tools, llm: _ScriptLLM
) -> None:
    """Turn 1 calls a tool; after a restart, turn 2's LLM call is fed turn 1 from the
    database with the tool_use and its tool_result adjacent and under the same id, and
    the stored rows are in that order by seq."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    llm.script("turn one", _RECALL)
    first = _send(_real_client(llm), editor, chat_id, "turn one")
    assert first.status_code == 200, first.text

    second = _send(_real_client(llm), editor, chat_id, "turn two")

    assert second.status_code == 200, second.text
    fed = llm.fed("turn two")[0]
    assert [(m["role"], m["content"], m["tool_call_id"]) for m in fed] == [
        ("user", "turn one", None),
        ("assistant", "", None),
        ("tool", _RECALLED, _RECALL.tool_call_id),
        ("assistant", _FINAL_REPLY, None),
        ("user", "turn two", None),
    ]
    assert fed[1]["tool_use_blocks"] == [_block(_RECALL)]
    assert _stored(world.db, chat_id) == [
        _row(_user("turn one")),
        _row(_tool_use(_RECALL)),
        _row(_tool(_RECALLED, _RECALL)),
        _row(_assistant(_FINAL_REPLY)),
        _row(_user("turn two")),
        _row(_assistant(_FINAL_REPLY)),
    ]


def test_chat_turns_tool_call_audit_row_targets_the_chats_uuid(
    world: World, tools: _Tools, llm: _ScriptLLM
) -> None:
    """The ``tool.call`` row of a chat turn targets the chat's real id (no uuid5 bridge)."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    llm.script("turn one", _RECALL)

    response = _send(_real_client(llm), editor, chat_id, "turn one")

    assert response.status_code == 200, response.text
    (row,) = world.db.audit_rows("tool.call")
    assert (row["target_type"], row["target_ids"]) == ("chat", [str(chat_id)])
    assert (plain(row["org_id"]), plain(row["actor_user_id"])) == (
        plain(ORG_ID),
        plain(editor.user_id),
    )


def test_chat_turns_external_content_flag_escalates_after_restart_outside_the_tail(
    world: World, tools: _Tools, llm: _ScriptLLM, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GH-243 across turns: reading an email sets the chat's ``external_content``; after a
    plain turn, a stored ``max_context_messages`` of 2 and a restart, the loaded tail (the
    plain turn) holds no wrapped content, yet an allowed side effect (memory.store) waits
    for confirmation."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    llm.script("read my mail", _READ_MAIL)
    llm.script("store a note", _STORE)
    before = _real_client(llm)
    assert _send(before, editor, chat_id, "read my mail").status_code == 200
    chat = world.db.chat_row(chat_id)
    assert chat is not None
    assert chat["external_content"] is True
    assert _send(before, editor, chat_id, "plain hello").status_code == 200
    stored = world.db.messages_of(chat_id)
    assert [m["role"] for m in stored] == [
        "user",
        "assistant",
        "tool",
        "assistant",
        "user",
        "assistant",
    ]
    assert untrusted.contains_wrapped(stored[2]["content"])
    assert not any(untrusted.contains_wrapped(m["content"]) for m in stored[-2:])
    _stored_limits(monkeypatch, max_context_messages=2)

    response = _send(_real_client(llm), editor, chat_id, "store a note")

    assert response.status_code == 200, response.text
    fed = [m for call in llm.fed("store a note") for m in call]
    assert not any(untrusted.contains_wrapped(m["content"]) for m in fed)
    body = response.json()
    assert body["status"] == "awaiting_confirmation"
    pending = body["pending_confirmation"]
    assert (pending["tool"], pending["action"]) == ("memory", "store")
    assert tools.stored == []
    assert world.db.audit_rows("tool.call")[-1]["metadata"]["escalated"] is True


def test_chat_turns_chat_without_external_content_runs_an_allowed_side_effect(
    world: World, tools: _Tools, llm: _ScriptLLM
) -> None:
    """The control case: the same allowed memory.store in a chat that never held external
    content runs at once (so the escalation above comes from the chat's flag)."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    llm.script("store a note", _STORE)

    response = _send(_real_client(llm), editor, chat_id, "store a note")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "final"
    assert tools.stored == [("plan", "ship")]
    chat = world.db.chat_row(chat_id)
    assert chat is not None
    assert chat["external_content"] is False


# ---------------------------------------------------------------------------
# 9. A second turn while the chat runs is 409; an approval waits (audit M-1, GH-8)
# ---------------------------------------------------------------------------

_WAIT_S: Final = 5.0


def _watched_runtime(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Swap in a real ``ChatRuntime`` that records every ``hold()`` call (its chat id) when
    it is made, i.e. before the caller waits for the chat's lock or is refused it (GH-8's
    ``wait`` keyword is passed through)."""
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


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the caller's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50002))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _until(condition: Callable[[], bool]) -> None:
    """Yield to the event loop until ``condition()`` holds (at most ``_WAIT_S`` seconds)."""

    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(poll(), _WAIT_S)


async def _while_first_runs(
    app: FastAPI,
    runtime: Any,
    gate: tuple[asyncio.Event, asyncio.Event],
    ahead: Callable[[httpx.AsyncClient], Awaitable[httpx.Response]],
    meanwhile: Callable[[httpx.AsyncClient], Awaitable[httpx.Response]],
) -> tuple[httpx.Response, httpx.Response]:
    """Send ``ahead``; once its run is parked inside the chat's lock (``gate``'s first
    event set), send ``meanwhile`` and wait until it has called ``hold()`` (a confirmation
    then waits for the lock) or has already answered (a turn's refusal is immediate);
    then release the first run (``gate``'s second event). Returns both responses."""
    parked, release = gate
    async with _async_client(app) as http:
        first = asyncio.create_task(ahead(http))
        try:
            await asyncio.wait_for(parked.wait(), _WAIT_S)
            holds = len(runtime.holds)
            second = asyncio.create_task(meanwhile(http))
            await _until(lambda: len(runtime.holds) > holds or second.done())
        finally:
            release.set()
        responses = await asyncio.wait_for(asyncio.gather(first, second), _WAIT_S)
    return responses[0], responses[1]


def _park_next_run(script: _Script) -> tuple[asyncio.Event, asyncio.Event]:
    """The next stub run sets the first event, then waits for the second (bounded)."""
    parked, release = asyncio.Event(), asyncio.Event()

    async def park() -> None:
        parked.set()
        await asyncio.wait_for(release.wait(), _WAIT_S)

    script.during = park
    return parked, release


def _mail_turn() -> tuple[LLMMessage, ...]:
    """A turn's new messages after reading an email: the call, its wrapped result, a reply."""
    wrapped = untrusted.wrap("email", "message m176", _MAIL_BODY)
    return (_tool_use(_READ_MAIL), _tool(wrapped, _READ_MAIL), _assistant("One new email."))


async def _post_turn(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID, message: str
) -> httpx.Response:
    return await http.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
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
    return await http.post(f"/api/confirm/{_CONFIRMATION_ID}", headers=account.cookie, json=body)


def _flag_of(db: FakeDb, chat_id: uuid.UUID) -> object:
    chat = db.chat_row(chat_id)
    assert chat is not None
    return chat["external_content"]


async def test_chat_turns_turn_sent_while_the_chat_runs_gets_409_and_stores_nothing(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GH-8: turn B, sent while turn A (reading an email) holds the chat, is refused at
    once with 409 ``run_active`` instead of queueing behind A: B never runs (so it can't
    run with a stale flag) and stores nothing; A's messages and the chat's flag are
    stored."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    app = make_app(agent)
    runtime = _watched_runtime(monkeypatch)
    gate = _park_next_run(script)
    mail_turn = _mail_turn()  # one wrapping boundary for the reply and the check
    script.queue(_Reply(new=mail_turn, response="One new email."))

    first, second = await _while_first_runs(
        app,
        runtime,
        gate,
        lambda http: _post_turn(http, editor, chat_id, "read my mail"),
        lambda http: _post_turn(http, editor, chat_id, "store a note"),
    )

    assert (first.status_code, first.json()["status"]) == (200, "final"), first.text
    assert (second.status_code, second.json()) == (409, _RUN_ACTIVE)
    assert [run.user_message for run in script.runs] == ["read my mail"]
    assert [run.flag for run in script.runs] == [False]
    assert _flag_of(world.db, chat_id) is True
    assert _stored(world.db, chat_id) == [_row(_user("read my mail")), *map(_row, mail_turn)]


async def test_chat_turns_legacy_turn_sent_while_the_chat_runs_gets_409_and_stores_nothing(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same on POST /api/message: two turns of one legacy session id, the second sent
    while the first (which reads an email) runs. The second is 409 ``run_active``: no run,
    no second chat, nothing stored; the first is stored in the legacy chat."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id, legacy_session_id=_LEGACY_SESSION)
    app = make_app(agent)
    runtime = _watched_runtime(monkeypatch)
    gate = _park_next_run(script)
    mail_turn = _mail_turn()  # one wrapping boundary for the reply and the check
    script.queue(_Reply(new=mail_turn, response="One new email."))

    first, second = await _while_first_runs(
        app,
        runtime,
        gate,
        lambda http: _post_legacy(http, editor, "read my mail"),
        lambda http: _post_legacy(http, editor, "store a note"),
    )

    assert (first.status_code, first.json()["chat_id"]) == (200, str(chat_id)), first.text
    assert (second.status_code, second.json()) == (409, _RUN_ACTIVE)
    assert [run.user_message for run in script.runs] == ["read my mail"]
    assert [plain(chat["id"]) for chat in world.db.chats_of(editor.user_id)] == [plain(chat_id)]
    assert _flag_of(world.db, chat_id) is True
    assert _stored(world.db, chat_id) == [_row(_user("read my mail")), *map(_row, mail_turn)]


async def test_chat_turns_queued_approval_runs_with_the_flag_the_turn_ahead_stored(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The approve path of POST /api/confirm: the chat awaits a confirmation; turn A (a
    new message, so that one is cancelled) reads an email and asks to confirm again under
    the same confirmation id (the stub reuses it). The approval B, sent while A runs,
    waits on the lock, resumes A's confirmation and runs with
    ``earlier_external_content=True``."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    app = make_app(agent)
    runtime = _watched_runtime(monkeypatch)
    script.queue(_awaiting(_OTHER_CALL))
    async with _async_client(app) as http:
        earlier = await _post_turn(http, editor, chat_id, "plan it")
    assert earlier.json()["status"] == "awaiting_confirmation", earlier.text
    gate = _park_next_run(script)
    asks = _awaiting(_PENDING_CALL)
    script.queue(_Reply(**{**asks.__dict__, "new": (*_mail_turn()[:2], *asks.new)}))

    first, second = await _while_first_runs(
        app,
        runtime,
        gate,
        lambda http: _post_turn(http, editor, chat_id, "read my mail"),
        lambda http: _post_approval(http, editor, chat_id),
    )

    assert (first.status_code, second.status_code) == (200, 200), (first.text, second.text)
    assert first.json()["status"] == "awaiting_confirmation"
    assert _flag_of(world.db, chat_id) is True
    resumed = script.runs[2]
    pending = resumed.arguments["pending_confirmation"]
    assert pending is not None
    assert (pending.tool_call, resumed.user_message) == (_PENDING_CALL, "")
    assert [run.flag for run in script.runs] == [False, False, True]


class _ParkingLLM(_ScriptLLM):
    """A ``_ScriptLLM`` whose first call of the ``park_on`` turn sets ``parked`` and then
    waits for ``release`` (bounded) before answering."""

    def __init__(self, park_on: str) -> None:
        super().__init__()
        self._park_on = park_on
        self.parked = asyncio.Event()
        self.release = asyncio.Event()

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        users = [message for message in messages if message.role == "user"]
        if not self.parked.is_set() and str(users[-1].content) == self._park_on:
            self.parked.set()
            await asyncio.wait_for(self.release.wait(), _WAIT_S)
        return await super().chat(messages, tools, stream=stream)


async def test_chat_turns_turn_sent_while_the_chat_runs_never_reaches_the_real_agent(
    world: World, tools: _Tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end with the real agent: turn A reads an email (its LLM call parked); turn B,
    sent meanwhile, asks for memory.store (allowed, a side effect). B is 409
    ``run_active``: no LLM call for B, memory.store never runs, the only ``tool.call``
    audit row is A's gmail.read, and only A's turn is stored, with the chat's flag set."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    llm = _ParkingLLM("read my mail")
    llm.script("read my mail", _READ_MAIL)
    llm.script("store a note", _STORE)
    app = _real_app(llm)
    runtime = _watched_runtime(monkeypatch)

    first, second = await _while_first_runs(
        app,
        runtime,
        (llm.parked, llm.release),
        lambda http: _post_turn(http, editor, chat_id, "read my mail"),
        lambda http: _post_turn(http, editor, chat_id, "store a note"),
    )

    assert (first.status_code, first.json()["status"]) == (200, "final"), first.text
    assert (second.status_code, second.json()) == (409, _RUN_ACTIVE)
    assert llm.fed("store a note") == []
    assert tools.stored == []
    assert [
        (row["metadata"]["tool"], row["metadata"]["action"])
        for row in world.db.audit_rows("tool.call")
    ] == [("gmail", "read")]
    stored = world.db.messages_of(chat_id)
    assert [(m["role"], m["content"]) for m in stored if m["role"] == "user"] == [
        ("user", "read my mail")
    ]
    assert [m["role"] for m in stored] == ["user", "assistant", "tool", "assistant"]
    assert _flag_of(world.db, chat_id) is True


# ---------------------------------------------------------------------------
# 10. A lone surrogate in a model's tool input (audit L-2)
# ---------------------------------------------------------------------------


def test_chat_turns_lone_surrogate_in_a_tool_input_is_persisted_replaced(
    world: World, client: TestClient, script: _Script
) -> None:
    """The model's tool input carries lone surrogates (free-form JSON gets them past
    Pydantic; PostgreSQL's JSONB refuses them). The turn still answers 200 and is
    persisted, each lone surrogate stored as U+FFFD."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id)
    high, low, replaced = chr(0xD800), chr(0xDFFF), chr(0xFFFD)
    asked = ToolCall(
        tool="memory",
        action="recall",
        args={"key": f"pl{high}an", f"no{low}te": "x"},
        tool_call_id="call-s176",
    )
    new = (_tool_use(asked), _tool("No note under that key.", asked), _assistant("Not found."))
    script.queue(_Reply(new=new, response="Not found."))

    response = _send(client, editor, chat_id)

    assert response.status_code == 200, response.text
    stored = world.db.messages_of(chat_id)
    assert [m["role"] for m in stored] == ["user", "assistant", "tool", "assistant"]
    assert stored[1]["tool_use_blocks"] == [
        {
            "type": "tool_use",
            "id": "call-s176",
            "name": "memory.recall",
            "input": {"key": f"pl{replaced}an", f"no{replaced}te": "x"},
        }
    ]


# ---------------------------------------------------------------------------
# 11. Non-finite numbers in a model's tool arguments (GH-266, re-audit L-4)
# ---------------------------------------------------------------------------

# A model's tool-call arguments as json.loads parses them: NaN, Infinity, -Infinity and
# overflowing literals (1e400 is inf), at the top level and nested in objects and arrays.
_NON_FINITE_ARGUMENTS: Final = """{
    "nan": NaN, "inf": Infinity, "minus_inf": -Infinity, "huge": 1e400,
    "ratio": 0.25, "count": 3, "exact": true, "key": "plan", "none": null,
    "nested": {
        "values": [NaN, 1.5, -1e400, {"deep": Infinity, "kept": -2.0}],
        "minus_inf": -Infinity,
        "zero": 0.0
    }
}"""
# The same arguments as stored: null in place of each non-finite number, the rest as is.
_NON_FINITE_STORED: Final[dict[str, Any]] = {
    "nan": None,
    "inf": None,
    "minus_inf": None,
    "huge": None,
    "ratio": 0.25,
    "count": 3,
    "exact": True,
    "key": "plan",
    "none": None,
    "nested": {
        "values": [None, 1.5, None, {"deep": None, "kept": -2.0}],
        "minus_inf": None,
        "zero": 0.0,
    },
}
_NON_FINITE_CALL_ID: Final = "call-nf266"


def _json(value: Any) -> str:
    """Canonical JSON text: equal only when every key, value and JSON type is (3 is not
    3.0, true is not 1)."""
    return json.dumps(value, sort_keys=True)


def _non_finite_block(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "tool_use",
        "id": _NON_FINITE_CALL_ID,
        "name": "memory.recall",
        "input": arguments,
    }


def _non_finite_record(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": "memory",
        "action": "recall",
        "args": arguments,
        "permission": "allow",
        "success": True,
        "duration_ms": 7,
    }


@pytest.mark.parametrize("route", ["chat_route", "legacy_route"])
def test_chat_turns_non_finite_numbers_in_tool_arguments_are_stored_as_null(
    world: World, client: TestClient, script: _Script, route: str
) -> None:
    """The run's tool_use block input and its tool-call record's arguments hold NaN,
    Infinity, -Infinity and 1e400, at the top level and nested. The turn answers 200
    (never 500; the response's tool_calls carry null) and is stored: null in place of
    each in both ``tool_use_blocks`` and ``tool_calls``, every finite value as it was.
    GET /api/chats/{id} then reads the turn back."""
    editor = world.a["editor"]
    chat_id = world.db.add_chat(editor.user_id) if route == "chat_route" else None
    record = ToolCallRecord.model_validate(_non_finite_record(json.loads(_NON_FINITE_ARGUMENTS)))
    asked = LLMMessage(
        role="assistant",
        content="",
        tool_use_blocks=[_non_finite_block(json.loads(_NON_FINITE_ARGUMENTS))],
    )
    result = LLMMessage(role="tool", content="No note.", tool_call_id=_NON_FINITE_CALL_ID)
    script.queue(
        _Reply(
            new=(asked, result, _assistant("Not found.")),
            response="Not found.",
            tool_calls=(record,),
        )
    )

    response = _legacy(client, editor) if chat_id is None else _send(client, editor, chat_id)

    assert response.status_code == 200, response.text
    expected_record = _non_finite_record(_NON_FINITE_STORED)
    assert _json(response.json()["tool_calls"]) == _json([expected_record])
    if chat_id is None:
        (chat,) = world.db.chats_of(editor.user_id)
        chat_id = plain(chat["id"])
    stored = world.db.messages_of(chat_id)
    assert [(m["role"], m["status"]) for m in stored] == [
        ("user", "complete"),
        ("assistant", "complete"),
        ("tool", "complete"),
        ("assistant", "complete"),
    ]
    assert _json(stored[1]["tool_use_blocks"]) == _json([_non_finite_block(_NON_FINITE_STORED)])
    assert _json(stored[3]["tool_calls"]) == _json([expected_record])
    detail = _detail(client, editor, chat_id)
    assert [m["role"] for m in detail["messages"]] == ["user", "assistant", "tool", "assistant"]
    assert _json(detail["messages"][3]["tool_calls"]) == _json([expected_record])
