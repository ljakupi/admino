"""HTTP spec of POST /api/chats/{chat_id}/retry, the JSON run (GH-245, contract C4).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin, an Editor and a Viewer
each, plus a Super Admin, all with real session cookies) around a stub agent
(``_Script``): its ``run`` binds every call to the real ``Agent.run``
signature, records what it got (history copied at call time, the keyword names)
and answers a scripted ``AgentResult`` whose ``history`` is the history it
received, the turn's user message and the scripted new messages, like the real
agent. Failed turns are seeded exactly as the server stores them: the run's
last message carries the status (``error`` on the assistant reply, ``stopped``
on a partial reply, on a ``tool`` row or on the user row itself).

What is pinned:
- Who: Org Admin and Editor retry their own failed chat (200); Viewer and Super
  Admin get 403 before any chat statement; 401 without a session; a cross-origin
  POST is the CSRF 403 (the same request same-origin runs); a non-UUID id is the
  422 validation list. Unknown, another org's, a colleague's and a trashed chat
  answer the identical 404 ``chat_not_found``. Every refusal runs nothing,
  stores nothing and leaves the chat runtime's pending confirmations as they were.
- When (Decision 1): the 409 ``{"detail": "The last answer can't be retried.",
  "reason": "not_retryable"}`` for a latest message ``complete``,
  ``awaiting_confirmation`` (live pending, which stays pending, or expired),
  ``limit_reached``, an empty chat and an ``error`` answer followed by an org
  notice. Retryable: a latest ``error`` reply, a ``stopped`` reply, ``tool``
  row or user row, and GH-24's pending-limit ``error`` turn.
- The run (Decision 3, C4 step 9): the stored text of the latest user message
  (a blank one sent with files too), the messages before it in the send's
  window (the latest stored ``max_context_messages`` of them), ``str(chat_id)``,
  the caller's principal, tool policy and prompt context, the stored limits,
  the chat's ``external_content`` flag (a flag the failed turn set stays set);
  exactly a send's keywords: no ``pending_confirmation``, no ``attachments``
  without files.
- Storage (Decision 2): the failed turn (the latest user row through the
  latest row) is gone by id; the chat holds its earlier rows (same ids), the
  user message stored again with its text, then exactly the run's new
  messages, the last with the run's status; ``last_activity_at`` moves. The
  answer is the ChatResponse a send of the same message answers. A retry that
  fails again replaces the first failure and can be retried again; an
  ``awaiting_confirmation`` retry keeps its new pending confirmation.
- A run that stores nothing: an agent exception is the generic 500 and a chat
  trashed during the run the 404, the failed turn unchanged (and still
  retryable after the 500).
- Limits (Decision 4): a retry while a run of the chat is parked inside the
  hold is the 409 ``run_active`` at once (also when the chat's last answer is
  ``complete``: the hold refuses before the retry target is read), with no
  second run; the per-user runtime bound is the 429 ``rate_limit`` and a full
  runtime the 503 ``chats_busy``.
- Rate limit: the retry spends the caller's ``/api/message`` bucket shared
  with sends, both ways; another user's bucket is untouched.
- Logs: one ``Retrying the last message of chat <id>`` line; no message text,
  tool result, reply or file name in any app record.
- GH-302 (Decision 1, contract C1 and C3): a failed turn the store can't replace
  (a stopped turn, or an approval turn ending ``error``, whose tool-call message was
  stored without tool_use blocks because the provider sent no call ids) answers
  exactly the 409 ``not_retryable`` before the run: no agent run (so no LLM or tool
  call), the chat row, every message (ids included) and the files' rows with their
  message links as they were, the chat's pending confirmation kept, no audit row. The
  refusal is R1''s (``chats.read_retry_target``) under the chat's hold: the owner
  check (T1) is the last statement before ``hold()``, R1' the only one after it (no
  history read, no file, no store). No app record carries the turn's texts or file
  name. Their well-formed twins (the same turns with tool_use blocks) are still
  retried: 200, the failed turn replaced.
- GH-304 (Decision 6, contract C7; #302 review suggestion 1): a well-formed failed
  turn whose ``seq`` range holds rows of another chat of the same owner and org (each
  malformed for the shape check if it counted) is retried (200) with its own user
  message and history and replaced, and the other chat (row, messages with their ids,
  file) is untouched, also with its rows on both sides of the range and for a tool
  turn ending ``stopped``.

New names (the route) are reached through HTTP only, so the file collects
before GH-245 is implemented.

Security notes:
- Every message, id and file name here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from fastapi.routing import APIRoute

from admino import scoped_settings, server, untrusted
from admino.agent import Agent
from admino.logs import safe_log
from admino.models import (
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
)
from tests.conftest import default_test_platform_settings
from tests.db_fakes import ORG_ID, OTHER_ORG_ID, FakeDb, plain
from tests.tenancy_world import (
    CLIENT_IP,
    FORBIDDEN,
    UNAUTHORIZED,
    build_world,
    chat_runtime_state,
    make_app,
    make_client,
    seed_pending_confirmation,
    stub_agent,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)
from tests.test_chats_retry import R1 as R1_PRIME
from tests.test_chats_retry import _canon

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from unittest.mock import MagicMock

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RETRY_PATH: Final = "/api/chats/{chat_id}/retry"

_NOT_RETRYABLE: Final = {
    "detail": "The last answer can't be retried.",
    "reason": "not_retryable",
}
_CHAT_NOT_FOUND: Final = {"detail": "Chat not found", "reason": "chat_not_found"}
_RUN_ACTIVE: Final = {
    "detail": "A message is already running in this chat.",
    "reason": "run_active",
}
_USER_CHATS_BUSY: Final = {
    "detail": "Too many of your chats are active. Try again shortly.",
    "reason": "rate_limit",
}
_CHATS_BUSY: Final = {
    "detail": "Too many active chats. Try again shortly.",
    "reason": "chats_busy",
}
_INTERNAL_ERROR: Final = {"detail": "Internal error"}
_CSRF_REFUSED: Final = {"detail": "Cross-origin request refused"}
_RATE_LIMITED: Final = {"detail": "Rate limit exceeded"}

_CONFIRMATION_ID: Final = "confirm-245-wagtail"
_SEEDED_CONFIRMATION: Final = "confirm-245-seeded"
_STUB_REPLY: Final = "Done."
_LONG_AGO: Final = datetime(2026, 1, 1, tzinfo=UTC)

# The retried message (the failed turn's user message) and the failed turn's texts.
_MESSAGE: Final = "Second question 245"
_FAILED_REPLY: Final = "The provider failed 245"
_TOOL_RESULT: Final = "Plan: ship GH-245"
_NOTICE: Final = "Your permissions changed 245."
_PENDING_LIMIT_RESULT: Final = "Tool call denied: too many confirmations are pending."
_PENDING_LIMIT_REPLY: Final = (
    "Action memory.store was not run: too many confirmations are pending."
    " Approve or deny one of them first."
)

# The keywords a send passes to Agent.run for a chat without attachments (C4 step 9).
_SEND_KEYWORDS: Final = frozenset(
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

# A statement on either chat table (FakeDb's normalized SQL).
_CHAT_SQL: Final = re.compile(r"\bchat(?:s|_messages)\b")

_RECALL: Final = ToolCall(
    tool="memory", action="recall", args={"key": "plan"}, tool_call_id="call-r245"
)
_PENDING_CALL: Final = ToolCall(
    tool="memory", action="store", args={"key": "plan", "value": "ship"}, tool_call_id="call-p245"
)
_LIST_CALL: Final = ToolCall(tool="memory", action="list", args={}, tool_call_id="call-l245")
_RECALL_RECORD: Final = ToolCallRecord(
    tool="memory",
    action="recall",
    args={"key": "plan"},
    permission="allow",
    success=True,
    duration_ms=7,
)

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


def _ids(db: FakeDb, chat_id: uuid.UUID) -> list[uuid.UUID]:
    """The ids of the chat's stored messages by seq (plain UUIDs)."""
    return [plain(m["id"]) for m in db.messages_of(chat_id)]


def _seed(
    db: FakeDb, chat_id: uuid.UUID, *messages: LLMMessage, status: str = "complete"
) -> list[uuid.UUID]:
    """Store ``messages`` in the chat (the last one with ``status``); their ids."""
    return [
        plain(
            db.add_chat_message(
                chat_id,
                message.role,
                message.content,
                tool_use_blocks=message.tool_use_blocks,
                tool_call_id=message.tool_call_id,
                status=status if index == len(messages) - 1 else "complete",
            )
        )
        for index, message in enumerate(messages)
    ]


# The chat before the failed turn: one finished exchange.
_EARLIER: Final = (_user("First question 245"), _assistant("First answer 245"))

# Each retryable shape of a failed last turn (Decision 1): its messages and the status
# the run's last message was stored with.
_FAILED_SHAPES: Final[dict[str, tuple[tuple[LLMMessage, ...], str]]] = {
    # _terminal_error: the provider failed after a tool call; the reply is the error.
    "error_reply": (
        (
            _user(_MESSAGE),
            _tool_use(_RECALL),
            _tool(_TOOL_RESULT, _RECALL),
            _assistant(_FAILED_REPLY),
        ),
        "error",
    ),
    # A stop during the answer: the partial reply is stored stopped.
    "stopped_reply": ((_user(_MESSAGE), _assistant("Here is the beginn")), "stopped"),
    # A stop after a tool result, before the next answer.
    "stopped_tool": (
        (_user(_MESSAGE), _tool_use(_RECALL), _tool(_TOOL_RESULT, _RECALL)),
        "stopped",
    ),
    # A stop before any output: the agent appends nothing, the user row is stopped.
    "stopped_user": ((_user(_MESSAGE),), "stopped"),
    # GH-24: a confirmation refused at the pending limit, stored as an error turn.
    "pending_limit": (
        (
            _user(_MESSAGE),
            _tool_use(_PENDING_CALL),
            _tool(_PENDING_LIMIT_RESULT, _PENDING_CALL),
            _assistant(_PENDING_LIMIT_REPLY),
        ),
        "error",
    ),
}


@dataclass(frozen=True)
class _Failed:
    """A chat whose last turn failed: its id and the ids of the earlier and failed rows."""

    chat_id: uuid.UUID
    earlier_ids: list[uuid.UUID]
    failed_ids: list[uuid.UUID]


def _failed_chat(
    db: FakeDb,
    owner: uuid.UUID,
    shape: str = "error_reply",
    *,
    earlier: tuple[LLMMessage, ...] = _EARLIER,
    **chat: Any,
) -> _Failed:
    """A chat of ``owner`` (last active long ago unless given) with ``earlier`` and a
    failed last turn of ``shape``."""
    chat.setdefault("last_activity_at", _LONG_AGO)
    chat_id = db.add_chat(owner, **chat)
    earlier_ids = _seed(db, chat_id, *earlier) if earlier else []
    failed, status = _FAILED_SHAPES[shape]
    return _Failed(chat_id, earlier_ids, _seed(db, chat_id, *failed, status=status))


# ---------------------------------------------------------------------------
# The stub agent
# ---------------------------------------------------------------------------

_RUN_SIGNATURE: Final = inspect.signature(Agent.run)


@dataclass(frozen=True)
class _Reply:
    """What one stub run answers: the new messages after the user message and the outcome."""

    new: tuple[LLMMessage, ...] = (LLMMessage(role="assistant", content=_STUB_REPLY),)
    status: str = "final"
    response: str = _STUB_REPLY
    tool_calls: tuple[ToolCallRecord, ...] = ()
    pending: ToolCall | None = None
    error_code: str | None = None
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


def _awaiting() -> _Reply:
    """A run that asks to confirm ``_PENDING_CALL``."""
    return _Reply(
        new=(_tool_use(_PENDING_CALL),),
        status="awaiting_confirmation",
        response="Action memory.store requires user confirmation.",
        tool_calls=(
            ToolCallRecord(
                tool="memory",
                action="store",
                args=_PENDING_CALL.args,
                permission="confirm",
                success=False,
                duration_ms=1,
            ),
        ),
        pending=_PENDING_CALL,
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
        # Bound to the real Agent.run signature (``self`` stands in as None).
        bound = _RUN_SIGNATURE.bind(None, *args, **kwargs)
        bound.apply_defaults()
        arguments = {name: value for name, value in bound.arguments.items() if name != "self"}
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
            error_code=reply.error_code,  # type: ignore[arg-type]
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


def _retry(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID | str,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """POST /api/chats/{chat_id}/retry as ``account`` (no body)."""
    return client.post(
        _RETRY_PATH.format(chat_id=chat_id), headers={**account.cookie, **(headers or {})}
    )


def _send(
    client: TestClient, account: Account, chat_id: uuid.UUID, message: str = _MESSAGE
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account``."""
    return client.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
    )


def _detail(client: TestClient, account: Account, chat_id: uuid.UUID) -> dict[str, Any]:
    """GET /api/chats/{chat_id} as its owner (must succeed)."""
    response = client.get(f"/api/chats/{chat_id}", headers=account.cookie)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _route_registered(app: Any) -> bool:
    """Whether the app has the POST retry route (a refusal before routing proves nothing)."""
    return any(
        isinstance(route, APIRoute) and route.path == _RETRY_PATH and "POST" in route.methods
        for route in app.routes
    )


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


def _snapshot(db: FakeDb, chat_id: uuid.UUID) -> tuple[Any, ...]:
    """The chat row, its stored messages (ids included) and its attachments rows."""
    return db.chat_row(chat_id), db.messages_of(chat_id), db.attachments_of(chat_id)


def _pending(db: FakeDb) -> Any:
    """Every stored chat's pending confirmation in the chat runtime (as JSON values)."""
    state = chat_runtime_state(db)
    assert state is not None
    return state["pending"]


def _bumped(db: FakeDb, chat_id: uuid.UUID) -> bool:
    chat = db.chat_row(chat_id)
    assert chat is not None
    return bool(chat["last_activity_at"] > _LONG_AGO)


# ---------------------------------------------------------------------------
# 1. Who may retry, and the refusals before the chat is read
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["org_admin", "editor"])
def test_chat_retry_member_with_chat_send_retries_their_failed_chat(
    world: World, client: TestClient, script: _Script, role: str
) -> None:
    account = world.a[role]  # type: ignore[index]
    failed = _failed_chat(world.db, account.user_id)

    response = _retry(client, account, failed.chat_id)

    assert response.status_code == 200, response.text
    assert response.json()["chat_id"] == str(failed.chat_id)
    assert [run.user_message for run in script.runs] == [_MESSAGE]


@pytest.mark.parametrize("role", ["viewer", "super_admin"])
def test_chat_retry_viewer_and_super_admin_get_403_before_any_chat_statement(
    world: World, client: TestClient, agent: MagicMock, role: str
) -> None:
    """A Viewer's own failed chat (kept from before a demotion) and, for the Super Admin,
    an Editor's failed chat: 403 ``Forbidden``, no run, no statement on either chat
    table, nothing changed."""
    account = world.by_role(role)  # type: ignore[arg-type]
    owner = world.a["viewer"] if role == "viewer" else world.a["editor"]
    failed = _failed_chat(world.db, owner.user_id)
    before = _snapshot(world.db, failed.chat_id)
    runtime = chat_runtime_state(world.db)
    calls = len(world.db.calls)

    response = _retry(client, account, failed.chat_id)

    assert _route_registered(client.app)
    assert (response.status_code, response.json()) == (403, FORBIDDEN)
    assert agent.run.await_count == 0
    assert _chat_calls(world.db, calls) == []
    assert _snapshot(world.db, failed.chat_id) == before
    assert chat_runtime_state(world.db) == runtime


def test_chat_retry_without_session_gets_401(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    failed = _failed_chat(world.db, world.a["editor"].user_id)
    before = _snapshot(world.db, failed.chat_id)

    response = client.post(_RETRY_PATH.format(chat_id=failed.chat_id))

    assert _route_registered(client.app)
    assert (response.status_code, response.json()) == (401, UNAUTHORIZED)
    assert agent.run.await_count == 0
    assert _snapshot(world.db, failed.chat_id) == before


def test_chat_retry_cross_origin_post_is_refused_and_same_origin_runs(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    """The CSRF middleware refuses a cross-site retry before the route (nothing run or
    changed); the same request marked same-origin reaches the route and runs."""
    editor = world.a["editor"]
    failed = _failed_chat(world.db, editor.user_id)
    before = _snapshot(world.db, failed.chat_id)

    refused = _retry(client, editor, failed.chat_id, headers={"Sec-Fetch-Site": "cross-site"})
    assert (refused.status_code, refused.json()) == (403, _CSRF_REFUSED)
    assert agent.run.await_count == 0
    assert _snapshot(world.db, failed.chat_id) == before

    allowed = _retry(client, editor, failed.chat_id, headers={"Sec-Fetch-Site": "same-origin"})
    assert allowed.status_code == 200, allowed.text
    assert agent.run.await_count == 1


def test_chat_retry_non_uuid_chat_id_gets_the_422_validation_list(
    world: World, client: TestClient, agent: MagicMock
) -> None:
    response = _retry(client, world.a["editor"], "not-a-uuid")

    assert response.status_code == 422, response.text
    assert [error["loc"] for error in response.json()["detail"]] == [["path", "chat_id"]]
    assert agent.run.await_count == 0


@pytest.mark.parametrize("case", ["unknown", "other_org", "colleague", "trashed"])
def test_chat_retry_missing_foreign_or_trashed_chat_gets_identical_404(
    world: World, client: TestClient, agent: MagicMock, case: str
) -> None:
    """Each chat but the unknown id ends with a failed answer (so it would be retryable
    for its owner): the same 404 body, no run, nothing written or changed. The chat
    runtime is untouched too: the owner check comes before the hold (C4 step 3), so a
    chat the caller can't reach gets no runtime entry (which would count against the
    caller's per-user bound)."""
    editor = world.a["editor"]
    db = world.db
    if case == "unknown":
        chat_id = uuid.uuid4()
    elif case == "other_org":
        chat_id = _failed_chat(db, world.b["editor"].user_id).chat_id
    elif case == "colleague":
        chat_id = _failed_chat(db, world.a["org_admin"].user_id).chat_id
    else:
        chat_id = _failed_chat(db, editor.user_id, deleted_at=datetime.now(UTC)).chat_id
    before = _snapshot(db, chat_id)
    message_count = len(db.chat_messages)
    runtime = chat_runtime_state(db)

    response = _retry(client, editor, chat_id)

    assert (response.status_code, response.json()) == (404, _CHAT_NOT_FOUND)
    assert agent.run.await_count == 0
    assert _snapshot(db, chat_id) == before
    assert len(db.chat_messages) == message_count
    assert chat_runtime_state(db) == runtime


# ---------------------------------------------------------------------------
# 2. A last answer that didn't fail: the 409 not_retryable
# ---------------------------------------------------------------------------


def _not_retryable_chat(world: World, case: str) -> uuid.UUID:
    """The Editor's chat whose latest message is ``case`` (Decision 1's 409 list)."""
    db = world.db
    chat_id = db.add_chat(world.a["editor"].user_id, last_activity_at=_LONG_AGO)
    if case == "empty":
        return chat_id
    _seed(db, chat_id, *_EARLIER)
    if case == "complete":
        _seed(db, chat_id, _user(_MESSAGE), _assistant("A fine answer 245"))
    elif case in ("awaiting_pending", "awaiting_expired"):
        _seed(
            db, chat_id, _user(_MESSAGE), _tool_use(_PENDING_CALL), status="awaiting_confirmation"
        )
    elif case == "limit_reached":
        _seed(
            db,
            chat_id,
            _user(_MESSAGE),
            _tool_use(_RECALL),
            _tool(_TOOL_RESULT, _RECALL),
            status="limit_reached",
        )
    else:  # error_then_notice: GH-66's org notice (a user message) after a failed answer.
        _seed(db, chat_id, _user(_MESSAGE), _assistant(_FAILED_REPLY), status="error")
        _seed(db, chat_id, _user(_NOTICE))
    if case == "awaiting_pending":
        seed_pending_confirmation(world.a["editor"], chat_id, _SEEDED_CONFIRMATION)
    return chat_id


@pytest.mark.parametrize(
    "case",
    [
        "complete",
        "awaiting_pending",
        "awaiting_expired",
        "limit_reached",
        "empty",
        "error_then_notice",
    ],
)
def test_chat_retry_last_answer_that_did_not_fail_gets_409_not_retryable(
    world: World, client: TestClient, agent: MagicMock, case: str
) -> None:
    """The exact 409 body; no run; the chat, its messages and every pending confirmation
    as they were (a live one is still pending afterwards)."""
    editor = world.a["editor"]
    chat_id = _not_retryable_chat(world, case)
    before = _snapshot(world.db, chat_id)
    pending = _pending(world.db)

    response = _retry(client, editor, chat_id)

    assert (response.status_code, response.json()) == (409, _NOT_RETRYABLE)
    assert agent.run.await_count == 0
    assert _snapshot(world.db, chat_id) == before
    assert _pending(world.db) == pending
    # Only the live case holds one (so "kept" above isn't vacuous there).
    assert (pending[str(chat_id)] is not None) is (case == "awaiting_pending")


# ---------------------------------------------------------------------------
# 3. Every retryable shape of a failed turn
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", list(_FAILED_SHAPES))
def test_chat_retry_failed_last_turn_is_rerun_and_replaced(
    world: World, client: TestClient, script: _Script, shape: str
) -> None:
    """A latest ``error`` reply, a ``stopped`` reply, ``tool`` row or user row, GH-24's
    pending-limit turn: the run gets the failed turn's user message and the messages
    before it; the chat ends with those (same ids), the user message again and the
    run's reply; no row of the failed turn is left."""
    editor = world.a["editor"]
    failed = _failed_chat(world.db, editor.user_id, shape)

    response = _retry(client, editor, failed.chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert run.user_message == _MESSAGE
    assert _dump(run.history) == _dump(_EARLIER)
    assert _stored(world.db, failed.chat_id) == [
        *map(_row, _EARLIER),
        _row(_user(_MESSAGE)),
        _row(_assistant(_STUB_REPLY)),
    ]
    ids = _ids(world.db, failed.chat_id)
    assert ids[:2] == failed.earlier_ids
    assert set(ids).isdisjoint(failed.failed_ids)


def test_chat_retry_reruns_only_the_latest_turn_after_an_earlier_failure(
    world: World, client: TestClient, script: _Script
) -> None:
    """An earlier turn that failed and was answered since stays: only the latest user
    message and what follows it are the failed turn (Decision 2)."""
    editor = world.a["editor"]
    db = world.db
    chat_id = db.add_chat(editor.user_id, last_activity_at=_LONG_AGO)
    kept = [
        *_seed(db, chat_id, _user("Zeroth question 245"), _assistant("Broke 245"), status="error"),
        *_seed(db, chat_id, *_EARLIER),
    ]
    failed_ids = _seed(db, chat_id, _user(_MESSAGE), _assistant(_FAILED_REPLY), status="error")

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert run.user_message == _MESSAGE
    assert _dump(run.history) == _dump(
        [_user("Zeroth question 245"), _assistant("Broke 245"), *_EARLIER]
    )
    assert _stored(db, chat_id) == [
        _row(_user("Zeroth question 245")),
        _row(_assistant("Broke 245"), "error"),
        *map(_row, _EARLIER),
        _row(_user(_MESSAGE)),
        _row(_assistant(_STUB_REPLY)),
    ]
    ids = _ids(db, chat_id)
    assert ids[:4] == kept
    assert set(ids).isdisjoint(failed_ids)


# ---------------------------------------------------------------------------
# 4. What the run gets
# ---------------------------------------------------------------------------


def test_chat_retry_run_gets_the_chat_id_and_the_window_before_the_retried_message(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Six earlier messages, stored ``max_context_messages`` 4: the run gets the latest 4
    BEFORE the retried message (never the failed turn), chronological, minus the leading
    tool result whose assistant turn is older; ``session_id`` is the chat's UUID; the
    stored limits."""
    _stored_limits(monkeypatch, max_context_messages=4)
    editor = world.a["editor"]
    earlier = (
        _user("First question 245"),
        _tool_use(_LIST_CALL),
        _tool("plan", _LIST_CALL),
        _assistant("First answer 245"),
        _user("Between question 245"),
        _assistant("Between answer 245"),
    )
    failed = _failed_chat(world.db, editor.user_id, earlier=earlier)

    response = _retry(client, editor, failed.chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert (run.user_message, run.session_id) == (_MESSAGE, str(failed.chat_id))
    assert _dump(run.history) == _dump(earlier[3:])
    assert run.arguments["agent_config"].max_context_messages == 4


def test_chat_retry_run_gets_the_callers_principal_policy_and_prompt_context(
    world: World, client: TestClient, script: _Script
) -> None:
    """Org A's own tool policy and instructions (org B's differ) and the Editor's principal."""
    editor = world.a["editor"]
    world.db.add_permissions(ORG_ID, {"memory": {"store": "confirm"}})
    # build_world stored both org_settings rows (instructions ''): set the texts in place.
    world.db.org_settings[ORG_ID]["instructions"] = "Org A instructions 245"
    world.db.org_settings[OTHER_ORG_ID]["instructions"] = "Org B instructions 245"
    failed = _failed_chat(world.db, editor.user_id)

    response = _retry(client, editor, failed.chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    principal = run.arguments["principal"]
    assert (plain(principal.user_id), plain(principal.org_id)) == (
        plain(editor.user_id),
        plain(ORG_ID),
    )
    assert run.arguments["tool_policy"].permissions.tools["memory"].actions["store"] == "confirm"
    assert run.arguments["prompt_context"].org_instructions == "Org A instructions 245"


@pytest.mark.parametrize("flag", [False, True])
def test_chat_retry_run_gets_the_chats_external_content_flag(
    world: World, client: TestClient, script: _Script, flag: bool
) -> None:
    """GH-243: ``earlier_external_content`` is the chat's sticky flag, passed explicitly.
    True when the failed turn read an email (its wrapped result set the flag): the
    flag stays set although that result is deleted (migration 0025: never reset)."""
    editor = world.a["editor"]
    db = world.db
    chat_id = db.add_chat(editor.user_id, external_content=flag, last_activity_at=_LONG_AGO)
    _seed(db, chat_id, *_EARLIER)
    result = untrusted.wrap("email", "message m245", "Quarterly figures 245") if flag else "none"
    _seed(
        db,
        chat_id,
        _user(_MESSAGE),
        _tool_use(_RECALL),
        _tool(result, _RECALL),
        _assistant(_FAILED_REPLY),
        status="error",
    )

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert run.flag is flag
    chat = db.chat_row(chat_id)
    assert chat is not None
    assert chat["external_content"] is flag


def test_chat_retry_run_gets_what_a_send_of_the_same_message_gets(
    world: World, client: TestClient, script: _Script
) -> None:
    """C4 step 9: exactly a send's keywords (no ``pending_confirmation``, no
    ``attachments`` without files) with the same values as a send of the retried
    message to a chat holding only the earlier messages, but the session id."""
    editor = world.a["editor"]
    failed = _failed_chat(world.db, editor.user_id)
    twin = world.db.add_chat(editor.user_id)
    _seed(world.db, twin, *_EARLIER)

    retried = _retry(client, editor, failed.chat_id)
    sent = _send(client, editor, twin)

    assert (retried.status_code, sent.status_code) == (200, 200), retried.text
    retry_run, send_run = script.runs
    assert retry_run.keywords == _SEND_KEYWORDS
    assert send_run.keywords == _SEND_KEYWORDS
    assert retry_run.arguments["pending_confirmation"] is None
    assert retry_run.arguments["attachments"] == ()
    assert retry_run.session_id == str(failed.chat_id)
    differing = {
        name
        for name in retry_run.arguments
        if name not in ("session_id", "history")
        and retry_run.arguments[name] != send_run.arguments[name]
    }
    assert differing == set()
    assert _dump(retry_run.history) == _dump(send_run.history)


def test_chat_retry_blank_message_sent_with_files_is_rerun_with_its_blank_text(
    world: World, client: TestClient, script: _Script
) -> None:
    """A blank message was accepted because it carried a file (here one excluded from the
    context, so the run has no slot): the retry runs its stored text as it is (no
    ``message_empty``, no length check) and passes no ``attachments``."""
    editor = world.a["editor"]
    db = world.db
    chat_id = db.add_chat(editor.user_id, last_activity_at=_LONG_AGO)
    _seed(db, chat_id, *_EARLIER)
    (user_id,) = _seed(db, chat_id, _user(""))
    db.add_attachment(
        chat_id,
        filename="blank-245.pdf",
        kind="pdf",
        status="ready",
        page_count=1,
        token_estimate=10,
        derived_bytes=10,
        message_id=user_id,
        active=False,
    )
    _seed(db, chat_id, _assistant(_FAILED_REPLY), status="error")

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert run.user_message == ""
    assert "attachments" not in run.keywords
    assert _dump(run.history) == _dump(_EARLIER)


# ---------------------------------------------------------------------------
# 5. How the new turn is stored and answered
# ---------------------------------------------------------------------------


def test_chat_retry_replaces_the_failed_turn_with_the_runs_messages(
    world: World, client: TestClient, script: _Script
) -> None:
    """The earlier rows keep their ids, the failed turn's rows are gone, then the user
    message (same text) and exactly ``result.history[len(loaded):]``'s run messages, all
    ``complete``; the run's tool_calls sit on the last message only; the chat's
    ``last_activity_at`` moves."""
    editor = world.a["editor"]
    db = world.db
    failed = _failed_chat(db, editor.user_id)
    new = (_tool_use(_RECALL), _tool("Plan: ship again", _RECALL), _assistant("Here it is."))
    script.queue(_Reply(new=new, response="Here it is.", tool_calls=(_RECALL_RECORD,)))

    response = _retry(client, editor, failed.chat_id)

    assert response.status_code == 200, response.text
    assert _stored(db, failed.chat_id) == [_row(m) for m in (*_EARLIER, _user(_MESSAGE), *new)]
    ids = _ids(db, failed.chat_id)
    assert ids[:2] == failed.earlier_ids
    assert set(ids).isdisjoint(failed.failed_ids)
    assert [m["tool_calls"] for m in db.messages_of(failed.chat_id)] == [None] * 5 + [
        [_RECALL_RECORD.model_dump(mode="json")]
    ]
    assert _bumped(db, failed.chat_id)


@pytest.mark.parametrize(
    ("status", "stored_status"),
    [
        ("final", "complete"),
        ("error", "error"),
        ("awaiting_confirmation", "awaiting_confirmation"),
    ],
)
def test_chat_retry_last_stored_message_carries_the_runs_status(
    world: World, client: TestClient, script: _Script, status: str, stored_status: str
) -> None:
    editor = world.a["editor"]
    failed = _failed_chat(world.db, editor.user_id)
    if status == "awaiting_confirmation":
        script.queue(_awaiting())
    else:
        script.queue(_Reply(new=(_assistant("Again 245"),), status=status, response="Again 245"))

    response = _retry(client, editor, failed.chat_id)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == status
    assert [m["status"] for m in world.db.messages_of(failed.chat_id)] == [
        "complete",
        "complete",
        "complete",
        stored_status,
    ]


def test_chat_retry_answers_the_chat_response_a_send_answers(
    world: World, client: TestClient, script: _Script
) -> None:
    """The JSON ChatResponse: the chat's id, ``session_id`` null, then the same reply,
    tool calls, status, pending confirmation, error code, context usage and notice as a
    send of the retried message to a chat holding only the earlier messages."""
    editor = world.a["editor"]
    failed = _failed_chat(world.db, editor.user_id)
    twin = world.db.add_chat(editor.user_id)
    _seed(world.db, twin, *_EARLIER)
    new = (_tool_use(_RECALL), _tool("Plan: ship again", _RECALL), _assistant("Here it is."))
    reply = _Reply(new=new, response="Here it is.", tool_calls=(_RECALL_RECORD,))
    script.queue(reply, reply)

    retried = _retry(client, editor, failed.chat_id)
    sent = _send(client, editor, twin)

    assert (retried.status_code, sent.status_code) == (200, 200), retried.text
    body, reference = retried.json(), sent.json()
    assert (body["chat_id"], body["session_id"]) == (str(failed.chat_id), None)
    assert body["tool_calls"] == [_RECALL_RECORD.model_dump(mode="json")]
    assert {k: v for k, v in body.items() if k != "chat_id"} == {
        k: v for k, v in reference.items() if k != "chat_id"
    }


def test_chat_retry_that_fails_again_replaces_the_first_failure_and_is_retryable(
    world: World, client: TestClient, script: _Script
) -> None:
    """The retry's run fails too (an LLM error): its turn replaces the first failed one
    and is stored ``error`` with the code in the answer; a second retry replaces that
    turn the same way, from the same history."""
    editor = world.a["editor"]
    db = world.db
    failed = _failed_chat(db, editor.user_id)
    script.queue(
        _Reply(
            new=(_assistant("Failed again 245"),),
            status="error",
            response="Failed again 245",
            error_code="provider_unavailable",
        )
    )

    first = _retry(client, editor, failed.chat_id)

    assert first.status_code == 200, first.text
    assert (first.json()["status"], first.json()["error_code"]) == ("error", "provider_unavailable")
    assert _stored(db, failed.chat_id) == [
        *map(_row, _EARLIER),
        _row(_user(_MESSAGE)),
        _row(_assistant("Failed again 245"), "error"),
    ]
    second_failure = _ids(db, failed.chat_id)[2:]

    second = _retry(client, editor, failed.chat_id)

    assert second.status_code == 200, second.text
    assert [run.user_message for run in script.runs] == [_MESSAGE, _MESSAGE]
    assert _dump(script.runs[1].history) == _dump(_EARLIER)
    assert _stored(db, failed.chat_id) == [
        *map(_row, _EARLIER),
        _row(_user(_MESSAGE)),
        _row(_assistant(_STUB_REPLY)),
    ]
    assert set(_ids(db, failed.chat_id)).isdisjoint([*failed.failed_ids, *second_failure])


def test_chat_retry_awaiting_confirmation_keeps_its_new_pending_confirmation(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    """A retry whose run asks for a confirmation: the answer and the chat show it as
    pending in the runtime, and it is not retryable (a second retry is the 409 with the
    confirmation kept)."""
    editor = world.a["editor"]
    failed = _failed_chat(world.db, editor.user_id)
    script.queue(_awaiting())

    response = _retry(client, editor, failed.chat_id)

    assert response.status_code == 200, response.text
    assert response.json()["pending_confirmation"]["confirmation_id"] == _CONFIRMATION_ID
    kept = server._chat_runtime.get_pending(failed.chat_id)
    assert kept is not None
    assert kept.confirmation_id == _CONFIRMATION_ID
    assert _detail(client, editor, failed.chat_id)["confirmation_status"] == "pending"

    again = _retry(client, editor, failed.chat_id)

    assert (again.status_code, again.json()) == (409, _NOT_RETRYABLE)
    assert agent.run.await_count == 1
    assert server._chat_runtime.get_pending(failed.chat_id) == kept


# ---------------------------------------------------------------------------
# 6. A run that stores nothing
# ---------------------------------------------------------------------------


def test_chat_retry_agent_exception_gets_500_and_keeps_the_failed_turn_retryable(
    world: World, client: TestClient, script: _Script
) -> None:
    editor = world.a["editor"]
    db = world.db
    failed = _failed_chat(db, editor.user_id)
    before = _snapshot(db, failed.chat_id)
    script.queue(_Reply(error=RuntimeError("agent failure 245")))

    response = _retry(client, editor, failed.chat_id)

    assert (response.status_code, response.json()) == (500, _INTERNAL_ERROR)
    assert _snapshot(db, failed.chat_id) == before

    again = _retry(client, editor, failed.chat_id)

    assert again.status_code == 200, again.text
    assert _dump(script.runs[1].history) == _dump(_EARLIER)
    assert _stored(db, failed.chat_id) == [
        *map(_row, _EARLIER),
        _row(_user(_MESSAGE)),
        _row(_assistant(_STUB_REPLY)),
    ]


def test_chat_retry_chat_trashed_during_the_run_gets_404_and_stores_nothing(
    world: World, client: TestClient, agent: MagicMock, script: _Script
) -> None:
    editor = world.a["editor"]
    db = world.db
    failed = _failed_chat(db, editor.user_id)
    messages = db.messages_of(failed.chat_id)

    async def trash() -> None:
        db.chats[uuid.UUID(int=failed.chat_id.int)]["deleted_at"] = datetime.now(UTC)

    script.during = trash

    response = _retry(client, editor, failed.chat_id)

    assert (response.status_code, response.json()) == (404, _CHAT_NOT_FOUND)
    assert agent.run.await_count == 1
    assert db.messages_of(failed.chat_id) == messages


# ---------------------------------------------------------------------------
# 7. One run per chat and the runtime's bounds
# ---------------------------------------------------------------------------

_WAIT_S: Final = 5.0


def _watched_runtime(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Swap in a real ``ChatRuntime`` that records every ``hold()`` call when it is made."""
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
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50245))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _until(condition: Callable[[], bool]) -> None:
    """Yield to the event loop until ``condition()`` holds (at most ``_WAIT_S`` seconds)."""

    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(poll(), _WAIT_S)


def _park_next_run(script: _Script) -> tuple[asyncio.Event, asyncio.Event]:
    """The next stub run sets the first event, then waits for the second (bounded)."""
    parked, release = asyncio.Event(), asyncio.Event()

    async def park() -> None:
        parked.set()
        await asyncio.wait_for(release.wait(), _WAIT_S)

    script.during = park
    return parked, release


async def _retry_while_parked(
    app: FastAPI,
    script: _Script,
    ahead: Callable[[httpx.AsyncClient], Awaitable[httpx.Response]],
    account: Account,
    chat_id: uuid.UUID,
) -> tuple[httpx.Response, httpx.Response]:
    """Send ``ahead``; once its run is parked inside the chat's hold, retry the chat and
    wait for the retry's answer (a refusal is immediate); then release the first run."""
    parked, release = _park_next_run(script)
    async with _async_client(app) as http:
        first = asyncio.create_task(ahead(http))
        try:
            await asyncio.wait_for(parked.wait(), _WAIT_S)
            second = asyncio.create_task(
                http.post(_RETRY_PATH.format(chat_id=chat_id), headers=account.cookie)
            )
            await _until(second.done)
        finally:
            release.set()
        responses = await asyncio.wait_for(asyncio.gather(first, second), _WAIT_S)
    return responses[0], responses[1]


async def test_chat_retry_while_a_retry_of_the_chat_runs_gets_409_run_active(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GH-8 / Decision 4: retry B, sent while retry A of the same chat runs, is refused at
    once with ``run_active``: one run only, and the chat holds A's turn."""
    editor = world.a["editor"]
    failed = _failed_chat(world.db, editor.user_id)
    app = make_app(agent)
    runtime = _watched_runtime(monkeypatch)

    first, second = await _retry_while_parked(
        app,
        script,
        lambda http: http.post(_RETRY_PATH.format(chat_id=failed.chat_id), headers=editor.cookie),
        editor,
        failed.chat_id,
    )

    assert first.status_code == 200, first.text
    assert (second.status_code, second.json()) == (409, _RUN_ACTIVE)
    assert len(runtime.holds) == 2
    assert [run.user_message for run in script.runs] == [_MESSAGE]
    assert _stored(world.db, failed.chat_id) == [
        *map(_row, _EARLIER),
        _row(_user(_MESSAGE)),
        _row(_assistant(_STUB_REPLY)),
    ]


async def test_chat_retry_while_a_send_of_the_chat_runs_gets_409_run_active_first(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A send runs in a chat whose last answer is complete; a retry meanwhile is the 409
    ``run_active`` (the hold refuses before the retry target is read, so the answer
    doesn't depend on a turn not stored yet), with no second run."""
    editor = world.a["editor"]
    db = world.db
    chat_id = db.add_chat(editor.user_id)
    _seed(db, chat_id, *_EARLIER)
    app = make_app(agent)
    _watched_runtime(monkeypatch)

    first, second = await _retry_while_parked(
        app,
        script,
        lambda http: http.post(
            f"/api/chats/{chat_id}/messages",
            headers=editor.cookie,
            json={"message": "Third question 245"},
        ),
        editor,
        chat_id,
    )

    assert first.status_code == 200, first.text
    assert (second.status_code, second.json()) == (409, _RUN_ACTIVE)
    assert [run.user_message for run in script.runs] == ["Third question 245"]
    assert _stored(db, chat_id) == [
        *map(_row, _EARLIER),
        _row(_user("Third question 245")),
        _row(_assistant(_STUB_REPLY)),
    ]


def test_chat_retry_at_the_users_runtime_bound_gets_429_rate_limit(
    world: World, client: TestClient, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GH-24: one runtime entry per user, the Editor's held by a pending confirmation of
    another chat: the retry is the 429 ``rate_limit``; no run, nothing stored, the other
    chat's confirmation kept."""
    from admino.chat_runtime import ChatRuntime

    monkeypatch.setattr(
        server,
        "_chat_runtime",
        ChatRuntime(max_entries=64, idle_s=900.0, max_entries_per_user=1),
    )
    editor = world.a["editor"]
    other = world.db.add_chat(editor.user_id)
    seed_pending_confirmation(editor, other, _SEEDED_CONFIRMATION)
    failed = _failed_chat(world.db, editor.user_id)
    before = _snapshot(world.db, failed.chat_id)
    pending = _pending(world.db)

    response = _retry(client, editor, failed.chat_id)

    assert (response.status_code, response.json()) == (429, _USER_CHATS_BUSY)
    assert agent.run.await_count == 0
    assert _snapshot(world.db, failed.chat_id) == before
    assert _pending(world.db) == pending


def test_chat_retry_full_runtime_gets_503_chats_busy(
    world: World, client: TestClient, agent: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A runtime of one entry, held by another user's pending confirmation (never
    evicted for someone else): the retry is the 503 ``chats_busy``; nothing run or stored."""
    from admino.chat_runtime import ChatRuntime

    monkeypatch.setattr(server, "_chat_runtime", ChatRuntime(max_entries=1, idle_s=900.0))
    admin, editor = world.a["org_admin"], world.a["editor"]
    held = world.db.add_chat(admin.user_id)
    seed_pending_confirmation(admin, held, _SEEDED_CONFIRMATION)
    failed = _failed_chat(world.db, editor.user_id)
    before = _snapshot(world.db, failed.chat_id)
    pending = _pending(world.db)

    response = _retry(client, editor, failed.chat_id)

    assert (response.status_code, response.json()) == (503, _CHATS_BUSY)
    assert agent.run.await_count == 0
    assert _snapshot(world.db, failed.chat_id) == before
    assert _pending(world.db) == pending


# ---------------------------------------------------------------------------
# 8. The per-user /api/message bucket, shared with sends
# ---------------------------------------------------------------------------


def test_chat_retry_is_refused_once_sends_spent_the_shared_bucket(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``/api/message`` with burst 2 and no refill to speak of: two sends spend it, the
    retry is the 429 before any chat statement (C4 step 1: so is a retry of another
    org's chat, which can't be told from one of the caller's); no run, nothing changed.
    Another user's retry runs."""
    monkeypatch.setitem(server._RATE_LIMITS, "/api/message", (0.0001, 2))
    editor, admin = world.a["editor"], world.a["org_admin"]
    chat_id = world.db.add_chat(editor.user_id)
    _seed(world.db, chat_id, *_EARLIER)
    failed = _failed_chat(world.db, editor.user_id)
    foreign = _failed_chat(world.db, world.b["editor"].user_id).chat_id
    before = _snapshot(world.db, failed.chat_id)

    assert _send(client, editor, chat_id, "one").status_code == 200
    assert _send(client, editor, chat_id, "two").status_code == 200
    calls = len(world.db.calls)
    refused = _retry(client, editor, failed.chat_id)
    probe = _retry(client, editor, foreign)

    assert (refused.status_code, refused.json()) == (429, _RATE_LIMITED)
    assert (probe.status_code, probe.json()) == (429, _RATE_LIMITED)
    assert _chat_calls(world.db, calls) == []
    assert [run.user_message for run in script.runs] == ["one", "two"]
    assert _snapshot(world.db, failed.chat_id) == before
    other = _retry(client, admin, _failed_chat(world.db, admin.user_id).chat_id)
    assert other.status_code == 200, other.text


def test_chat_retry_spends_the_bucket_a_send_needs(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Burst 2: two retries spend it, the next send is the 429 with no run."""
    monkeypatch.setitem(server._RATE_LIMITS, "/api/message", (0.0001, 2))
    editor = world.a["editor"]
    first = _failed_chat(world.db, editor.user_id)
    second = _failed_chat(world.db, editor.user_id)

    assert _retry(client, editor, first.chat_id).status_code == 200
    assert _retry(client, editor, second.chat_id).status_code == 200
    refused = _send(client, editor, first.chat_id, "three")

    assert (refused.status_code, refused.json()) == (429, _RATE_LIMITED)
    assert len(script.runs) == 2


# ---------------------------------------------------------------------------
# 9. Logs
# ---------------------------------------------------------------------------

_STANDARD_RECORD_ATTRS: Final = frozenset(
    set(vars(logging.LogRecord("", logging.INFO, "", 0, "", (), None))) | {"message", "asctime"}
)


def _record_text(record: logging.LogRecord) -> str:
    """A record's message, its arguments and every non-standard attribute, as text."""
    extras = [
        f"{name}={value!s}"
        for name, value in vars(record).items()
        if name not in _STANDARD_RECORD_ATTRS
    ]
    return "\n".join([record.getMessage(), repr(record.args), *extras])


def test_chat_retry_logs_the_chat_id_and_no_content(
    world: World, client: TestClient, script: _Script, caplog: pytest.LogCaptureFixture
) -> None:
    """One ``Retrying the last message of chat <id>`` line (the id via ``safe_log``); no
    app record holds a message text, the failed or new answer, a tool result or the
    retried message's file name."""
    caplog.set_level(logging.DEBUG)
    editor = world.a["editor"]
    db = world.db
    chat_id = db.add_chat(editor.user_id, last_activity_at=_LONG_AGO)
    _seed(db, chat_id, _user("retry-canary-245-earlier"), _assistant("retry-canary-245-answer"))
    (user_id,) = _seed(db, chat_id, _user("retry-canary-245-message"))
    db.add_attachment(
        chat_id,
        filename="retry-canary-245-file.pdf",
        kind="pdf",
        status="ready",
        page_count=1,
        token_estimate=10,
        derived_bytes=10,
        message_id=user_id,
        active=False,
    )
    _seed(
        db,
        chat_id,
        _tool_use(_RECALL),
        _tool("retry-canary-245-old-result", _RECALL),
        _assistant("retry-canary-245-failed"),
        status="error",
    )
    script.queue(
        _Reply(
            new=(
                _tool_use(_RECALL),
                _tool("retry-canary-245-new-result", _RECALL),
                _assistant("retry-canary-245-reply"),
            ),
            response="retry-canary-245-reply",
            tool_calls=(_RECALL_RECORD,),
        )
    )

    response = _retry(client, editor, chat_id)

    assert response.status_code == 200, response.text
    records = [
        record
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore", "asyncio"))
    ]
    retrying = [
        record
        for record in records
        if record.getMessage() == f"Retrying the last message of chat {safe_log(chat_id)}"
    ]
    assert len(retrying) == 1
    text = "\n".join(_record_text(record) for record in records)
    assert set(re.findall(r"retry-canary-245-[a-z.-]+", text)) == set()


# ---------------------------------------------------------------------------
# 10. A failed turn the store can't replace: the 409 before the run (GH-302 Decision 1)
# ---------------------------------------------------------------------------

_NO_ID_RESULT: Final = LLMMessage(role="tool", content=_TOOL_RESULT)
_PARTIAL_REPLY: Final = "Here is the beginn"

# Each failed turn's rows with their stored status. Without call ids the tool-call
# message is stored with no tool_use blocks (and its result without a call id):
# migration 0031's shape check refuses such a stopped or approval turn.
_NO_IDS_TURNS: Final[dict[str, tuple[tuple[LLMMessage, str], ...]]] = {
    "stopped_without_call_ids": (
        (_user(_MESSAGE), "complete"),
        (_assistant(""), "complete"),
        (_NO_ID_RESULT, "complete"),
        (_assistant(_PARTIAL_REPLY), "stopped"),
    ),
    "approval_without_call_ids": (
        (_user(_MESSAGE), "complete"),
        (_assistant(""), "awaiting_confirmation"),
        (_NO_ID_RESULT, "complete"),
        (_assistant(_FAILED_REPLY), "error"),
    ),
}
# Their well-formed twins: the same turns with the call ids (tool_use blocks stored).
_WITH_IDS_TURNS: Final[dict[str, tuple[tuple[LLMMessage, str], ...]]] = {
    "stopped_with_call_ids": (
        (_user(_MESSAGE), "complete"),
        (_tool_use(_RECALL), "complete"),
        (_tool(_TOOL_RESULT, _RECALL), "complete"),
        (_assistant(_PARTIAL_REPLY), "stopped"),
    ),
    "approval_with_call_ids": (
        (_user(_MESSAGE), "complete"),
        (_tool_use(_PENDING_CALL), "awaiting_confirmation"),
        (_tool(_TOOL_RESULT, _PENDING_CALL), "complete"),
        (_assistant(_FAILED_REPLY), "error"),
    ),
}

# The statements that locate the refusal: the owner check (turn_setup's T1) and R1'.
_R1_PRIME_FORM: Final = _canon(R1_PRIME)


def _form(sql: str) -> str:
    """A statement's form: T1, R1' (contract C1's exact text), else its own SQL."""
    normalized = _canon(sql)
    if normalized == _R1_PRIME_FORM:
        return "R1'"
    if "from organizations o" in normalized and "left join chats c" in normalized:
        return "T1"
    return sql


def _turn_chat(
    world: World, turn: tuple[tuple[LLMMessage, str], ...], *, file_name: str = "turn-302.pdf"
) -> _Failed:
    """The Editor's chat (last active long ago): ``_EARLIER``, then ``turn`` row by row
    with its statuses, and an excluded file sent with the turn's user message."""
    db = world.db
    chat_id = db.add_chat(world.a["editor"].user_id, last_activity_at=_LONG_AGO)
    earlier_ids = _seed(db, chat_id, *_EARLIER)
    failed_ids = [
        plain(
            db.add_chat_message(
                chat_id,
                message.role,
                message.content,
                tool_use_blocks=message.tool_use_blocks,
                tool_call_id=message.tool_call_id,
                status=status,
            )
        )
        for message, status in turn
    ]
    db.add_attachment(
        chat_id,
        filename=file_name,
        kind="pdf",
        status="ready",
        page_count=1,
        token_estimate=10,
        derived_bytes=10,
        message_id=failed_ids[0],
        active=False,
    )
    return _Failed(chat_id, earlier_ids, failed_ids)


def _marked_runtime(monkeypatch: pytest.MonkeyPatch, db: FakeDb) -> list[int]:
    """Swap in a real ``ChatRuntime`` that records how many statements ran when each
    ``hold()`` is taken; return that list."""
    from admino.chat_runtime import ChatRuntime

    marks: list[int] = []

    class _Marked(ChatRuntime):
        def __init__(self) -> None:
            super().__init__(max_entries=64, idle_s=900.0)

        def hold(self, chat_id: uuid.UUID, owner_user_id: uuid.UUID, **kwargs: Any) -> Any:
            marks.append(len(db.calls))
            return super().hold(chat_id, owner_user_id, **kwargs)

    monkeypatch.setattr(server, "_chat_runtime", _Marked())
    return marks


@pytest.mark.parametrize("shape", list(_NO_IDS_TURNS))
def test_chat_retry_failed_turn_the_store_cannot_replace_gets_409_before_the_run(
    world: World, client: TestClient, agent: MagicMock, shape: str
) -> None:
    """The exact 409 ``not_retryable``; no run (no LLM call, no tool call); the chat row,
    every message (ids included), the file row and its link to the user message as they
    were; the chat's pending confirmation kept; no audit row."""
    editor = world.a["editor"]
    db = world.db
    failed = _turn_chat(world, _NO_IDS_TURNS[shape])
    seed_pending_confirmation(editor, failed.chat_id, _SEEDED_CONFIRMATION)
    before = _snapshot(db, failed.chat_id)
    pending = _pending(db)
    audit = db.audit_rows()

    response = _retry(client, editor, failed.chat_id)

    assert (response.status_code, response.json()) == (409, _NOT_RETRYABLE)
    assert agent.run.await_count == 0
    assert _snapshot(db, failed.chat_id) == before
    assert _pending(db) == pending
    assert pending[str(failed.chat_id)] is not None
    assert db.audit_rows() == audit


@pytest.mark.parametrize("shape", list(_NO_IDS_TURNS))
def test_chat_retry_failed_turn_the_store_cannot_replace_is_refused_by_r1_prime_under_the_hold(
    world: World, client: TestClient, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """Contract C3: the 409 is ``read_retry_target``'s None under the chat's hold. The
    owner check (T1) is the last statement before ``hold()``; after it the request runs
    R1' (contract C1's exact text) and nothing else: no history read, no file, no store."""
    editor = world.a["editor"]
    db = world.db
    failed = _turn_chat(world, _NO_IDS_TURNS[shape])
    marks = _marked_runtime(monkeypatch, db)
    since = len(db.calls)

    response = _retry(client, editor, failed.chat_id)

    assert response.status_code == 409, response.text
    (held_at,) = marks
    before_hold = [_form(call.sql) for call in db.calls[since:held_at]]
    under_hold = [_form(call.sql) for call in db.calls[held_at:]]
    assert (before_hold[-1:], under_hold) == (["T1"], ["R1'"])


def test_chat_retry_failed_turn_the_store_cannot_replace_logs_no_content(
    world: World, client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """A log line about the refusal, if any, carries no message text, tool result,
    reply or file name of the chat (any app record, DEBUG)."""
    caplog.set_level(logging.DEBUG)
    turn = (
        (_user("retry-canary-302-message"), "complete"),
        (_assistant("retry-canary-302-call"), "complete"),
        (LLMMessage(role="tool", content="retry-canary-302-result"), "complete"),
        (_assistant("retry-canary-302-partial"), "stopped"),
    )
    failed = _turn_chat(world, turn, file_name="retry-canary-302-file.pdf")

    response = _retry(client, world.a["editor"], failed.chat_id)

    assert (response.status_code, response.json()) == (409, _NOT_RETRYABLE)
    records = [
        record
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore", "asyncio"))
    ]
    text = "\n".join(_record_text(record) for record in records)
    assert set(re.findall(r"retry-canary-302-[a-z.-]+", text)) == set()


@pytest.mark.parametrize("shape", list(_WITH_IDS_TURNS))
def test_chat_retry_well_formed_twin_with_tool_use_blocks_is_still_retried(
    world: World, client: TestClient, script: _Script, shape: str
) -> None:
    """The shape check refuses only what the store refuses: the same turn with its
    tool_use blocks runs (the failed turn's user message, the history before it) and is
    replaced: the earlier rows (same ids), the user message again, the run's reply."""
    editor = world.a["editor"]
    db = world.db
    failed = _turn_chat(world, _WITH_IDS_TURNS[shape])

    response = _retry(client, editor, failed.chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert (run.user_message, _dump(run.history)) == (_MESSAGE, _dump(_EARLIER))
    assert _stored(db, failed.chat_id) == [
        *map(_row, _EARLIER),
        _row(_user(_MESSAGE)),
        _row(_assistant(_STUB_REPLY)),
    ]
    ids = _ids(db, failed.chat_id)
    assert ids[:2] == failed.earlier_ids
    assert set(ids).isdisjoint(failed.failed_ids)


# ---------------------------------------------------------------------------
# 11. Another chat's rows inside the failed turn (GH-304 Decision 6, contract C7)
# ---------------------------------------------------------------------------

_OTHER_QUESTION: Final = "Other question 304"

# The own chat's well-formed failed turn (after ``_EARLIER``) interleaved with rows of
# another chat of the same owner and org, in insertion order (so seq order): each
# (chat, message, stored status), the chat "mine" or "other". Every "other" row
# strictly inside the own turn's range is malformed for the shape check (a user row, a
# complete no-block reply, a limit_reached or a stopped row), so counting it would
# answer the 409 ``not_retryable``.
_INTERLEAVED_TURNS: Final[dict[str, tuple[tuple[str, LLMMessage, str], ...]]] = {
    # The reviewer's draft (PR #303): the other chat's complete no-block reply mid-turn.
    "other_chats_complete_reply_mid_turn": (
        ("other", _user(_OTHER_QUESTION), "complete"),
        ("mine", _user(_MESSAGE), "complete"),
        ("other", _assistant("Other answer 304"), "complete"),
        ("mine", _assistant(_FAILED_REPLY), "error"),
    ),
    # Before the range, between every own row and after the own latest row.
    "other_chats_rows_on_both_sides_of_a_tool_turn": (
        ("other", _user(_OTHER_QUESTION), "complete"),
        ("mine", _user(_MESSAGE), "complete"),
        ("other", _assistant("Other answer 304"), "complete"),
        ("mine", _tool_use(_RECALL), "complete"),
        ("other", _user("Other follow-up 304"), "complete"),
        ("mine", _tool(_TOOL_RESULT, _RECALL), "complete"),
        ("other", _assistant("Other partial 304"), "limit_reached"),
        ("mine", _assistant(_FAILED_REPLY), "error"),
        ("other", _assistant("Other late answer 304"), "complete"),
    ),
    "other_chats_rows_in_a_tool_turn_ending_stopped": (
        ("mine", _user(_MESSAGE), "complete"),
        ("other", _user(_OTHER_QUESTION), "complete"),
        ("mine", _tool_use(_RECALL), "complete"),
        ("other", _assistant("Other answer 304"), "complete"),
        ("mine", _tool(_TOOL_RESULT, _RECALL), "complete"),
        ("other", _assistant("Other stop 304"), "stopped"),
        ("mine", _assistant(_PARTIAL_REPLY), "stopped"),
    ),
}


def _interleaved_turn(
    world: World, placed: tuple[tuple[str, LLMMessage, str], ...]
) -> tuple[_Failed, uuid.UUID]:
    """The Editor's chat (last active long ago) with ``_EARLIER``, then ``placed`` row by
    row into it or into another chat of the Editor (a file on that chat's first
    question); the own chat's ``_Failed`` and the other chat's id."""
    db = world.db
    owner = world.a["editor"].user_id
    mine = db.add_chat(owner, last_activity_at=_LONG_AGO)
    other = db.add_chat(owner, title="Other 304", last_activity_at=_LONG_AGO)
    earlier_ids = _seed(db, mine, *_EARLIER)
    failed_ids: list[uuid.UUID] = []
    other_ids: list[uuid.UUID] = []
    for side, message, status in placed:
        stored = plain(
            db.add_chat_message(
                mine if side == "mine" else other,
                message.role,
                message.content,
                tool_use_blocks=message.tool_use_blocks,
                tool_call_id=message.tool_call_id,
                status=status,
            )
        )
        (failed_ids if side == "mine" else other_ids).append(stored)
    db.add_attachment(
        other,
        filename="other-304.pdf",
        kind="pdf",
        status="ready",
        page_count=1,
        token_estimate=10,
        derived_bytes=10,
        message_id=other_ids[0],
    )
    return _Failed(mine, earlier_ids, failed_ids), other


@pytest.mark.parametrize("case", list(_INTERLEAVED_TURNS))
def test_chat_retry_other_chats_rows_inside_the_failed_turn_leave_the_retry_unchanged(
    world: World, client: TestClient, script: _Script, case: str
) -> None:
    """GH-304 (C7): the own failed turn is retried (200) with its own user message and
    the history before it; it is replaced (the earlier rows with their ids, the user
    message again, the run's reply), and the other chat's row, messages (ids included)
    and file are exactly as they were, its rows inside the replaced range too."""
    editor = world.a["editor"]
    db = world.db
    failed, other = _interleaved_turn(world, _INTERLEAVED_TURNS[case])
    other_before = _snapshot(db, other)

    response = _retry(client, editor, failed.chat_id)

    assert response.status_code == 200, response.text
    (run,) = script.runs
    assert (run.user_message, _dump(run.history)) == (_MESSAGE, _dump(_EARLIER))
    assert _stored(db, failed.chat_id) == [
        *map(_row, _EARLIER),
        _row(_user(_MESSAGE)),
        _row(_assistant(_STUB_REPLY)),
    ]
    ids = _ids(db, failed.chat_id)
    assert ids[:2] == failed.earlier_ids
    assert set(ids).isdisjoint(failed.failed_ids)
    assert _snapshot(db, other) == other_before
