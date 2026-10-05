"""HTTP spec of the per-user chat-runtime bound and eviction at global capacity (GH-24).

Contract sections 1 and 4 (``RUN_DIR/contract.md``), issue #24 criteria "Per-user bound on
the chat runtime" and its integration test, and the Decisions "rate_limit (429) for the
runtime bound" and "Eviction at global capacity". The app from ``create_app()`` runs
against the FakeDb world of tests/tenancy_world.py (orgs A and B with an Org Admin, an
Editor and a Viewer each, real session cookies) around a stub agent (``_Script``, the
pattern of tests/test_chat_turns_api.py: every call bound to ``Agent.run``'s signature,
scripted results whose history is the received history plus the turn). Small runtimes are
swapped in AFTER ``make_app`` (``create_app()`` clears the module runtime) on a fake
monotonic clock that never moves, so no entry ever turns idle.

What is pinned:
- Server wiring: ``server._MAX_CHAT_RUNTIME_ENTRIES_PER_USER == 16`` next to the global
  1024 and the idle 900.0; ``create_app()`` clears the module runtime without replacing
  it; that runtime refuses a 17th chat of one Editor whose 16 chats each hold a pending
  confirmation, while a colleague's turn runs.
- The per-user 429: a user whose entries are all in use or hold a pending confirmation
  gets 429 exactly ``{"detail": "Too many of your chats are active. Try again shortly.",
  "reason": "rate_limit"}`` for a turn in another chat, on POST /api/chats/{id}/messages
  and on the legacy POST /api/message: no run, nothing stored, the runtime unchanged,
  the message never echoed. Another user of the org and a user of the other org still
  run a turn at that moment (also from inside the user's blocked run).
- A user at the bound with an entry that is only a lock (no pending confirmation, not in
  use) gets the turn: that entry goes, the pending confirmation stays actionable.
- Global capacity (no per-user bound): a new chat of user U evicts U's own least
  recently used entry without a pending confirmation, else anyone's without one, else
  U's own with one (that confirmation is gone: ``expired``, confirming is 404). Another
  user's (another org's) pending confirmation is never evicted: after org A churns
  through new chats, org B's Editor still approves (the resume runs) or denies (200).
  With only other users' pending confirmations and entries in use left, the turn is
  503 ``chats_busy`` with no run and nothing stored.
- The 429 spends and blocks no other route: GET /api/chats/{id} and POST /api/confirm on
  a chat of the same user work afterwards (their buckets at burst 1), and once the
  approval leaves that chat a lock only, the refused turn runs.
- Logs (tracker section 5): the eviction and 429 paths log no message content, no tool
  argument of any pending confirmation, no user id and no id of another chat.
- GH-24 audit fix (server audit L-1): POST /api/confirm on a chat of the caller's that
  has no runtime entry (named by ``chat_id`` or the legacy ``session_id``, approve or
  deny) is the 404 ``No pending confirmation for this session`` and creates no entry:
  never the 429 at the caller's per-user bound, and at global capacity it evicts nothing
  (the caller's own pending confirmation in another chat stays pending and approvable).
  Guards: a lock-only chat is the same 404, a wrong confirmation id is the 404
  ``Confirmation not found`` with the pending one kept, another user's or org's chat is
  the 404 at the bound too; none of them runs, stores or changes the runtime.
- GH-266 (server audit L-1 of #176): the first POST /api/message of a brand-new
  ``session_id`` refused with the 429 ``rate_limit`` or the 503 ``chats_busy`` leaves no
  chat: GET /api/chats unchanged, no chats row, no message, no run, the runtime
  unchanged. Controls: the same refusal on an existing legacy chat keeps it unchanged;
  once the refusal clears, the session runs in exactly one chat, created by that turn,
  whose id is the response's ``chat_id``, the run's session id and a runtime entry's
  key (``session_id`` echoed); a concurrent first message of the same session that
  inserts first (a FakeDb hook before the INSERT) makes the turn run, be stored and
  hold its runtime entry in that winner's chat, the session's only chat.

``admino.chat_runtime`` and the new server names are used lazily, so the file collects
before GH-24 is implemented and each test fails on its own.

Security notes:
- Every message, id and argument here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import copy
import inspect
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest

from admino import server
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
)
from tests.db_fakes import FakeDb, norm, plain
from tests.tenancy_world import (
    CLIENT_IP,
    build_world,
    chat_runtime_state,
    make_app,
    make_client,
    seed_chat,
    seed_pending_confirmation,
    stub_agent,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import Awaitable, Callable, Iterator
    from unittest.mock import MagicMock

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_USER_CHATS_BUSY: Final = {
    "detail": "Too many of your chats are active. Try again shortly.",
    "reason": "rate_limit",
}
_CHATS_BUSY: Final = {
    "detail": "Too many active chats. Try again shortly.",
    "reason": "chats_busy",
}
_NO_PENDING: Final = {"detail": "No pending confirmation for this session"}
_CONFIRMATION_NOT_FOUND: Final = {"detail": "Confirmation not found"}

_CONFIRMATION_ID: Final = "confirm-24-plover"
_WRONG_CONFIRMATION_ID: Final = "confirm-24-wrong-tern"
_LEGACY_SESSION: Final = "legacy-24-heron"
_STUB_REPLY: Final = "Done."
_MESSAGE: Final = "Hello there"
_REFUSED_MESSAGE: Final = "BOUND-CANARY-24-message-sandpiper"
_SAVED: Final = "Saved your plan."
_DENIAL: Final = "Action memory.store was denied."
_IDLE_S: Final = 900.0
# A global bound that never binds, for the per-user cases.
_ROOMY: Final = 64

_PENDING_CALL: Final = ToolCall(
    tool="memory", action="store", args={"key": "plan", "value": "ship"}, tool_call_id="call-p24"
)
_ROUTES: Final = ("chat_route", "legacy_route")

# ---------------------------------------------------------------------------
# Messages and the stub agent (tests/test_chat_turns_api.py's pattern)
# ---------------------------------------------------------------------------


def _user(content: str) -> LLMMessage:
    return LLMMessage(role="user", content=content)


def _assistant(content: str) -> LLMMessage:
    return LLMMessage(role="assistant", content=content)


def _tool_use(call: ToolCall) -> LLMMessage:
    """An assistant turn asking for ``call``."""
    block = {
        "type": "tool_use",
        "id": call.tool_call_id,
        "name": f"{call.tool}.{call.action}",
        "input": dict(call.args),
    }
    return LLMMessage(role="assistant", content="", tool_use_blocks=[block])


def _tool(content: str, call: ToolCall) -> LLMMessage:
    return LLMMessage(role="tool", content=content, tool_call_id=call.tool_call_id)


@dataclass(frozen=True)
class _Reply:
    """What one stub run answers: the new messages after the user message and the outcome."""

    new: tuple[LLMMessage, ...] = (LLMMessage(role="assistant", content=_STUB_REPLY),)
    status: str = "final"
    response: str = _STUB_REPLY
    tool_calls: tuple[ToolCallRecord, ...] = ()
    pending: ToolCall | None = None


@dataclass(frozen=True)
class _Run:
    """One stub run: the user message, the session id and every bound argument."""

    user_message: str
    session_id: str
    arguments: dict[str, Any]


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
    """``Agent.run``'s signature; every stub call is bound to it."""


def _awaiting(call: ToolCall = _PENDING_CALL) -> _Reply:
    """A run that ends waiting for the confirmation of ``call``."""
    return _Reply(
        new=(_tool_use(call),),
        status="awaiting_confirmation",
        response=f"Action {call.tool}.{call.action} requires user confirmation.",
        tool_calls=(
            ToolCallRecord(
                tool=call.tool,
                action=call.action,
                args=call.args,
                permission="confirm",
                success=False,
                duration_ms=1,
            ),
        ),
        pending=call,
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
                arguments=arguments,
            )
        )
        during, self.during = self.during, None
        if during is not None:
            await during()
        reply = self.replies.pop(0) if self.replies else _Reply()
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

    def ran_in(self, chat_id: uuid.UUID) -> bool:
        """Whether any run named ``chat_id`` as its session id."""
        return any(run.session_id == str(chat_id) for run in self.runs)


class _Clock:
    """A fake monotonic clock that never moves: no runtime entry ever turns idle."""

    def __call__(self) -> float:
        return 1000.0


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
def module_runtime() -> Iterator[Any]:
    """The server's module-level chat runtime, emptied again after the test."""
    runtime = server._chat_runtime
    yield runtime
    runtime.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client(agent: MagicMock) -> tuple[FastAPI, TestClient]:
    """The app around the stub agent and its client (an escaping exception is a 500)."""
    app = make_app(agent)
    return app, make_client(app, raise_server_exceptions=False)


def _use_runtime(
    monkeypatch: pytest.MonkeyPatch, *, max_entries: int, max_entries_per_user: int | None = None
) -> None:
    """Swap ``server._chat_runtime`` for a small one on a clock that never moves.

    Call after ``make_app``. Without ``max_entries_per_user`` the keyword isn't passed
    (only the global bound, the contract's default).
    """
    from admino.chat_runtime import ChatRuntime

    per_user: dict[str, int] = {}
    if max_entries_per_user is not None:
        per_user["max_entries_per_user"] = max_entries_per_user
    monkeypatch.setattr(
        server,
        "_chat_runtime",
        ChatRuntime(max_entries=max_entries, idle_s=_IDLE_S, clock=_Clock(), **per_user),
    )


def _send(
    client: TestClient, account: Account, chat_id: uuid.UUID, message: str = _MESSAGE
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account``."""
    return client.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
    )


def _turn(
    client: TestClient, route: str, account: Account, chat_id: uuid.UUID, message: str = _MESSAGE
) -> httpx.Response:
    """A turn on ``route``: the chat route in ``chat_id``, or the legacy route under
    ``_LEGACY_SESSION`` (``chat_id`` is then the account's chat of that session id)."""
    if route == "legacy_route":
        return client.post(
            "/api/message",
            headers=account.cookie,
            json={"message": message, "session_id": _LEGACY_SESSION},
        )
    return _send(client, account, chat_id, message)


def _confirm(
    client: TestClient, account: Account, chat_id: uuid.UUID, *, approved: bool = True
) -> httpx.Response:
    """POST /api/confirm/{_CONFIRMATION_ID} for ``chat_id``."""
    return client.post(
        f"/api/confirm/{_CONFIRMATION_ID}",
        headers=account.cookie,
        json={"confirmation_id": _CONFIRMATION_ID, "approved": approved, "chat_id": str(chat_id)},
    )


def _confirm_by(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    *,
    reference: str = "chat_id",
    approved: bool = True,
    confirmation_id: str = _CONFIRMATION_ID,
) -> httpx.Response:
    """POST /api/confirm/{confirmation_id} naming the chat by ``chat_id`` or, with
    ``reference="session_id"``, by the legacy ``_LEGACY_SESSION`` (``chat_id`` is then the
    account's chat of that session id)."""
    chat: dict[str, str] = (
        {"session_id": _LEGACY_SESSION} if reference == "session_id" else {"chat_id": str(chat_id)}
    )
    return client.post(
        f"/api/confirm/{confirmation_id}",
        headers=account.cookie,
        json={"confirmation_id": confirmation_id, "approved": approved, **chat},
    )


def _confirmation_status(client: TestClient, account: Account, chat_id: uuid.UUID) -> str:
    """GET /api/chats/{chat_id}'s ``confirmation_status`` (the request must succeed)."""
    response = client.get(f"/api/chats/{chat_id}", headers=account.cookie)
    assert response.status_code == 200, response.text
    status: str = response.json()["confirmation_status"]
    return status


def _finished(
    client: TestClient, account: Account, chat_id: uuid.UUID, message: str = _MESSAGE
) -> None:
    """A turn that runs and ends ``final``: the chat's entry is then only a lock."""
    response = _send(client, account, chat_id, message)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "final"


def _awaited(
    client: TestClient,
    script: _Script,
    account: Account,
    chat_id: uuid.UUID,
    call: ToolCall = _PENDING_CALL,
) -> None:
    """A turn that ends waiting for the confirmation of ``call`` (kept in the runtime)."""
    script.queue(_awaiting(call))
    response = _send(client, account, chat_id)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "awaiting_confirmation"


def _new_chat(db: FakeDb, account: Account) -> uuid.UUID:
    """A new empty chat of ``account`` (no runtime entry yet)."""
    return seed_chat(db, account)


def _tables(db: FakeDb) -> Any:
    """A deep copy of the chats and chat_messages tables (to prove nothing was stored)."""
    return copy.deepcopy((db.chats, db.chat_messages))


async def _nested_post(app: FastAPI, account: Account, chat_id: uuid.UUID) -> httpx.Response:
    """A chat turn sent from inside a running agent (same event loop, its own client)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50001))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as inner:
        return await inner.post(
            f"/api/chats/{chat_id}/messages",
            headers=account.cookie,
            json={"message": _REFUSED_MESSAGE},
        )


def _entries_of(user_id: uuid.UUID) -> int:
    """How many runtime entries (not in use) ``user_id`` holds, counted by dropping them
    with ``ChatRuntime.forget_user``: destructive, so only a test's last check."""
    runtime = server._chat_runtime
    before = len(runtime)
    runtime.forget_user(user_id)
    return before - len(runtime)


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the httpx client lines, which name request URLs)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


# ---------------------------------------------------------------------------
# 1. Server wiring: 16 entries per user
# ---------------------------------------------------------------------------


def test_chat_runtime_bound_server_constants_pin_16_entries_per_user() -> None:
    assert (
        server._MAX_CHAT_RUNTIME_ENTRIES,
        server._CHAT_IDLE_EVICT_S,
        server._MAX_CHAT_RUNTIME_ENTRIES_PER_USER,
    ) == (1024, 900.0, 16)


def test_chat_runtime_bound_module_runtime_refuses_a_17th_chat_of_one_user(
    world: World, agent: MagicMock, module_runtime: Any
) -> None:
    """The module runtime as the server builds it: create_app() clears it (same object);
    an Editor whose 16 chats each hold a pending confirmation gets the 429 for a 17th
    chat, with no run and nothing stored, while a colleague's turn runs."""
    _, client = _client(agent)
    assert server._chat_runtime is module_runtime
    editor, colleague = world.a["editor"], world.a["org_admin"]
    for number in range(16):
        seed_pending_confirmation(editor, _new_chat(world.db, editor), f"confirm-24-{number}")
    seventeenth = _new_chat(world.db, editor)
    runs, tables, state = agent.run.await_count, _tables(world.db), chat_runtime_state(world.db)

    response = _send(client, editor, seventeenth)

    assert (response.status_code, response.json()) == (429, _USER_CHATS_BUSY)
    assert agent.run.await_count == runs
    assert _tables(world.db) == tables
    assert chat_runtime_state(world.db) == state
    colleague_turn = _send(client, colleague, _new_chat(world.db, colleague))
    assert colleague_turn.status_code == 200, colleague_turn.text


# ---------------------------------------------------------------------------
# 2. The per-user 429 (criterion 12, part 1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", _ROUTES)
def test_chat_runtime_bound_user_with_only_pending_chats_gets_429_and_others_still_run(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """Bound 2: the Editor's two chats hold pending confirmations, so a turn in a third
    chat is 429 ``rate_limit`` (exact body, the message not echoed), with no run, nothing
    stored and the runtime unchanged; then org A's Org Admin and org B's Editor each run
    a turn in a chat of their own (200)."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=_ROOMY, max_entries_per_user=2)
    editor, colleague, other_org = world.a["editor"], world.a["org_admin"], world.b["editor"]
    for _ in range(2):
        _awaited(client, script, editor, _new_chat(world.db, editor))
    legacy = _LEGACY_SESSION if route == "legacy_route" else None
    third = seed_chat(world.db, editor, legacy_session_id=legacy)
    runs, tables, state = agent.run.await_count, _tables(world.db), chat_runtime_state(world.db)

    response = _turn(client, route, editor, third, _REFUSED_MESSAGE)

    assert (response.status_code, response.json()) == (429, _USER_CHATS_BUSY)
    assert _REFUSED_MESSAGE not in response.text
    assert agent.run.await_count == runs
    assert _tables(world.db) == tables
    assert chat_runtime_state(world.db) == state
    for account in (colleague, other_org):
        own = seed_chat(world.db, account, legacy_session_id=legacy)
        other = _turn(client, route, account, own)
        assert other.status_code == 200, other.text
        assert other.json()["chat_id"] == str(own)


def test_chat_runtime_bound_user_with_a_running_and_a_pending_chat_gets_429_meanwhile(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bound 2: one chat of the Editor holds a pending confirmation, the other is in use by
    a run that is still going. From inside that run, the Editor's turn in a third chat is
    429 ``rate_limit`` (no run, nothing stored, runtime unchanged) while org A's Org
    Admin and org B's Editor run turns (200); the blocked run then completes."""
    app, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=_ROOMY, max_entries_per_user=2)
    editor, colleague, other_org = world.a["editor"], world.a["org_admin"], world.b["editor"]
    _awaited(client, script, editor, _new_chat(world.db, editor))
    running, third = _new_chat(world.db, editor), _new_chat(world.db, editor)
    colleague_chat, other_org_chat = _new_chat(world.db, colleague), _new_chat(world.db, other_org)
    nested: dict[str, httpx.Response] = {}
    seen: list[Any] = []

    async def meanwhile() -> None:
        seen.append((chat_runtime_state(world.db), _tables(world.db)))
        nested["third"] = await _nested_post(app, editor, third)
        seen.append((chat_runtime_state(world.db), _tables(world.db)))
        nested["colleague"] = await _nested_post(app, colleague, colleague_chat)
        nested["other_org"] = await _nested_post(app, other_org, other_org_chat)

    script.during = meanwhile

    response = _send(client, editor, running)

    assert response.status_code == 200, response.text
    assert (nested["third"].status_code, nested["third"].json()) == (429, _USER_CHATS_BUSY)
    assert seen[0] == seen[1]
    assert not script.ran_in(third)
    assert (nested["colleague"].status_code, nested["other_org"].status_code) == (200, 200)


# ---------------------------------------------------------------------------
# 3. At the bound, the user's own lock-only entry gives way
# ---------------------------------------------------------------------------


def test_chat_runtime_bound_user_at_bound_loses_own_lock_only_entry_and_keeps_pending(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bound 2: the Editor's chats are one with a pending confirmation and one that only
    ran (a lock). A turn in a third chat runs (200, stored); the lock-only entry is the one
    that went (two entries left), and the pending confirmation is kept and approvable."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=_ROOMY, max_entries_per_user=2)
    editor = world.a["editor"]
    pending_chat, lock_chat, third = (_new_chat(world.db, editor) for _ in range(3))
    _awaited(client, script, editor, pending_chat)
    _finished(client, editor, lock_chat)

    response = _send(client, editor, third)

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "final"
    assert [m["role"] for m in world.db.messages_of(third)] == ["user", "assistant"]
    state = chat_runtime_state(world.db)
    assert state is not None
    assert state["entries"] == 2
    assert state["pending"][str(pending_chat)]["confirmation_id"] == _CONFIRMATION_ID
    script.queue(_Reply(new=(_tool("Stored memory: plan", _PENDING_CALL),), response=_SAVED))
    approved = _confirm(client, editor, pending_chat)
    assert approved.status_code == 200, approved.text
    assert (approved.json()["status"], approved.json()["response"]) == ("final", _SAVED)


# ---------------------------------------------------------------------------
# 4. Eviction at global capacity (criterion 12, part 2)
# ---------------------------------------------------------------------------


def test_chat_runtime_bound_at_capacity_new_chat_evicts_requesters_own_lock_first(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Capacity 3, least recently used first: org B's Editor's lock-only chat, the org A
    Editor's lock-only chat, org B's Editor's pending chat. The A Editor's new chat evicts
    their OWN lock-only entry, not B's older one: B keeps two entries (with the pending
    confirmation), the A Editor one (the new chat)."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=3)
    editor, other_org = world.a["editor"], world.b["editor"]
    _finished(client, other_org, _new_chat(world.db, other_org))
    _finished(client, editor, _new_chat(world.db, editor))
    other_pending = _new_chat(world.db, other_org)
    _awaited(client, script, other_org, other_pending)

    response = _send(client, editor, _new_chat(world.db, editor))

    assert response.status_code == 200, response.text
    assert _confirmation_status(client, other_org, other_pending) == "pending"
    assert (_entries_of(other_org.user_id), _entries_of(editor.user_id)) == (2, 1)


def test_chat_runtime_bound_at_capacity_new_chat_evicts_another_users_lock_before_own_pending(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Capacity 3, least recently used first: the A Editor's pending chat, org A's Org
    Admin's lock-only chat, org B's Editor's pending chat. The A Editor's new chat evicts
    the Org Admin's lock-only entry (nothing is lost), not the Editor's older pending
    confirmation: both confirmations stay pending."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=3)
    editor, colleague, other_org = world.a["editor"], world.a["org_admin"], world.b["editor"]
    own_pending, other_pending = _new_chat(world.db, editor), _new_chat(world.db, other_org)
    _awaited(client, script, editor, own_pending)
    _finished(client, colleague, _new_chat(world.db, colleague))
    _awaited(client, script, other_org, other_pending)

    response = _send(client, editor, _new_chat(world.db, editor))

    assert response.status_code == 200, response.text
    assert _confirmation_status(client, editor, own_pending) == "pending"
    assert _confirmation_status(client, other_org, other_pending) == "pending"
    assert _entries_of(colleague.user_id) == 0


def test_chat_runtime_bound_at_capacity_new_chat_evicts_requesters_own_pending_last(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Capacity 3, least recently used first: org B's Editor's pending chat, then two
    pending chats of the A Editor. With no entry free of a pending confirmation, the A
    Editor's new chat runs and costs the Editor's OWN least recently used confirmation
    (``expired``, confirming it is 404); the Editor's other one and org B's stay pending."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=3)
    editor, other_org = world.a["editor"], world.b["editor"]
    other_pending = _new_chat(world.db, other_org)
    oldest, newer = _new_chat(world.db, editor), _new_chat(world.db, editor)
    _awaited(client, script, other_org, other_pending)
    _awaited(client, script, editor, oldest)
    _awaited(client, script, editor, newer)

    response = _send(client, editor, _new_chat(world.db, editor))

    assert response.status_code == 200, response.text
    assert _confirmation_status(client, editor, oldest) == "expired"
    lost = _confirm(client, editor, oldest)
    assert (lost.status_code, lost.json()) == (404, _NO_PENDING)
    assert _confirmation_status(client, editor, newer) == "pending"
    assert _confirmation_status(client, other_org, other_pending) == "pending"


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
def test_chat_runtime_bound_other_orgs_pending_confirmation_survives_churn_and_stays_actionable(
    world: World,
    agent: MagicMock,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    """Capacity 3: org B's Editor waits for a confirmation (the least recently used entry),
    org A's Editor holds one too; then org A's Org Admin and Editor take turns in eight new
    chats. Org B's confirmation is never evicted: approving resumes the run with it (200),
    denying stores the denial (200)."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=3)
    editor, colleague, other_org = world.a["editor"], world.a["org_admin"], world.b["editor"]
    other_pending = _new_chat(world.db, other_org)
    _awaited(client, script, other_org, other_pending)
    _awaited(client, script, editor, _new_chat(world.db, editor))
    for _ in range(4):
        _finished(client, colleague, _new_chat(world.db, colleague))
        _finished(client, editor, _new_chat(world.db, editor))
    runs = agent.run.await_count
    script.queue(_Reply(new=(_tool("Stored memory: plan", _PENDING_CALL),), response=_SAVED))

    response = _confirm(client, other_org, other_pending, approved=approved)

    assert response.status_code == 200, response.text
    body = response.json()
    if approved:
        assert (body["status"], body["response"]) == ("final", _SAVED)
        resumed = script.runs[-1].arguments["pending_confirmation"]
        assert (resumed.confirmation_id, script.runs[-1].session_id) == (
            _CONFIRMATION_ID,
            str(other_pending),
        )
    else:
        assert (body["status"], body["response"], agent.run.await_count) == (
            "final",
            _DENIAL,
            runs,
        )
        assert world.db.messages_of(other_pending)[-1]["content"] == _DENIAL


def test_chat_runtime_bound_at_capacity_with_only_others_pending_and_in_use_gets_503(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Capacity 3: org B's Editor's and org A's Org Admin's chats hold pending
    confirmations, and the A Editor's turn is running in the third. From inside that run,
    the A Editor's turn in another chat is 503 ``chats_busy`` (another user's pending
    confirmation is never evicted): no run, nothing stored, runtime unchanged; both
    confirmations stay pending and the running turn completes."""
    app, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=3)
    editor, colleague, other_org = world.a["editor"], world.a["org_admin"], world.b["editor"]
    other_pending, colleague_pending = (
        _new_chat(world.db, other_org),
        _new_chat(world.db, colleague),
    )
    _awaited(client, script, other_org, other_pending)
    _awaited(client, script, colleague, colleague_pending)
    running, refused = _new_chat(world.db, editor), _new_chat(world.db, editor)
    nested: list[httpx.Response] = []
    seen: list[Any] = []

    async def meanwhile() -> None:
        seen.append((chat_runtime_state(world.db), _tables(world.db)))
        nested.append(await _nested_post(app, editor, refused))
        seen.append((chat_runtime_state(world.db), _tables(world.db)))

    script.during = meanwhile

    response = _send(client, editor, running)

    assert response.status_code == 200, response.text
    (busy,) = nested
    assert (busy.status_code, busy.json()) == (503, _CHATS_BUSY)
    assert seen[0] == seen[1]
    assert not script.ran_in(refused)
    assert _confirmation_status(client, other_org, other_pending) == "pending"
    assert _confirmation_status(client, colleague, colleague_pending) == "pending"


# ---------------------------------------------------------------------------
# 5. The 429 spends and blocks no other route
# ---------------------------------------------------------------------------


def test_chat_runtime_bound_429_leaves_chat_detail_and_confirm_working(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bound 2, both chats pending: after the 429, GET /api/chats/{id} (bucket burst 1)
    shows the confirmation pending and POST /api/confirm (bucket burst 1) approves it;
    that chat is then only a lock, so the refused turn runs when sent again."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=_ROOMY, max_entries_per_user=2)
    monkeypatch.setitem(server._RATE_LIMITS, "/api/chats/get", (0.0001, 1))
    monkeypatch.setitem(server._RATE_LIMITS, "/api/confirm", (0.0001, 1))
    editor = world.a["editor"]
    first, second, third = (_new_chat(world.db, editor) for _ in range(3))
    _awaited(client, script, editor, first)
    _awaited(client, script, editor, second)
    refused = _send(client, editor, third)
    assert (refused.status_code, refused.json()) == (429, _USER_CHATS_BUSY)

    status = _confirmation_status(client, editor, first)
    script.queue(_Reply(new=(_tool("Stored memory: plan", _PENDING_CALL),), response=_SAVED))
    approved = _confirm(client, editor, first)
    retried = _send(client, editor, third)

    assert status == "pending"
    assert approved.status_code == 200, approved.text
    assert (approved.json()["status"], approved.json()["response"]) == ("final", _SAVED)
    assert retried.status_code == 200, retried.text
    assert script.ran_in(third)


# ---------------------------------------------------------------------------
# 6. Logs (tracker section 5)
# ---------------------------------------------------------------------------


def _canary_call(tag: str) -> ToolCall:
    """A confirm-gated call whose arguments are canaries (content: never logged)."""
    return ToolCall(
        tool="memory",
        action="store",
        args={"key": f"LOG-KEY-24-{tag}", "value": f"LOG-VALUE-24-{tag}"},
        tool_call_id=f"call-log24-{tag}",
    )


def test_chat_runtime_bound_eviction_and_429_logs_carry_no_content_ids_or_arguments(
    world: World,
    agent: MagicMock,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Capacity 4, bound 2. Logged from the first step on: the A Editor's new chat evicts
    the Org Admin's lock-only entry; the Editor's next chat (at the bound) evicts the
    Editor's own lock-only one; the next is the 429; the Org Admin's new chat evicts the
    Admin's own pending confirmation. No record names a message, a tool argument, a user
    id or any chat other than the requests' own."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=4, max_entries_per_user=2)
    editor, colleague, other_org = world.a["editor"], world.a["org_admin"], world.b["editor"]
    other_pending, colleague_pending = (
        _new_chat(world.db, other_org),
        _new_chat(world.db, colleague),
    )
    colleague_lock, editor_pending = _new_chat(world.db, colleague), _new_chat(world.db, editor)
    _awaited(client, script, other_org, other_pending, _canary_call("other-org"))
    _awaited(client, script, colleague, colleague_pending, _canary_call("colleague"))
    _finished(client, colleague, colleague_lock)
    _awaited(client, script, editor, editor_pending, _canary_call("editor"))
    messages = [f"LOG-CANARY-24-message-{number}" for number in range(4)]
    caplog.set_level(logging.DEBUG)
    caplog.clear()

    statuses = [_send(client, editor, _new_chat(world.db, editor), messages[0]).status_code]
    script.queue(_awaiting(_canary_call("editor-second")))
    statuses.append(_send(client, editor, _new_chat(world.db, editor), messages[1]).status_code)
    statuses.append(_send(client, editor, _new_chat(world.db, editor), messages[2]).status_code)
    statuses.append(
        _send(client, colleague, _new_chat(world.db, colleague), messages[3]).status_code
    )

    assert statuses == [200, 200, 429, 200]
    state = chat_runtime_state(world.db)
    assert state is not None
    pending = state["pending"]
    assert (pending[str(colleague_pending)] is None, pending[str(other_pending)] is None) == (
        True,
        False,
    )
    text = _app_log_text(caplog)
    assert text
    arguments = [
        f"LOG-{part}-24-{tag}"
        for part in ("KEY", "VALUE")
        for tag in ("other-org", "colleague", "editor", "editor-second")
    ]
    user_ids = [
        form for account in world.everyone() for form in (str(account.user_id), account.user_id.hex)
    ]
    other_chats = [
        str(chat) for chat in (other_pending, colleague_pending, colleague_lock, editor_pending)
    ]
    forbidden = [*messages, *arguments, *user_ids, *other_chats]
    assert [value for value in forbidden if value in text] == []


# ---------------------------------------------------------------------------
# 7. A confirm with nothing to confirm creates no entry (GH-24 audit fix, server L-1)
# ---------------------------------------------------------------------------


def _editor_at_bound(
    client: TestClient, script: _Script, world: World, monkeypatch: pytest.MonkeyPatch
) -> Account:
    """Bound 2 (global roomy): org A's Editor, whose two entries hold pending confirmations."""
    _use_runtime(monkeypatch, max_entries=_ROOMY, max_entries_per_user=2)
    editor = world.a["editor"]
    for _ in range(2):
        _awaited(client, script, editor, _new_chat(world.db, editor))
    return editor


@pytest.mark.parametrize(
    ("reference", "approved"),
    [("chat_id", True), ("chat_id", False), ("session_id", True)],
    ids=["approve", "deny", "legacy_session_id"],
)
def test_chat_runtime_bound_confirm_on_chat_without_entry_at_user_bound_is_404_not_429(
    world: World,
    agent: MagicMock,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    reference: str,
    approved: bool,
) -> None:
    """Bound 2, both of the Editor's entries pinned by pending confirmations: a confirm on a
    third chat of theirs, which has no runtime entry, is the 404 ``No pending
    confirmation`` (not the 429 ``rate_limit``), whether approving or denying and whether
    the chat is named by ``chat_id`` or the legacy ``session_id``: no run, nothing stored,
    the runtime unchanged (no entry created, both confirmations kept)."""
    _, client = _client(agent)
    editor = _editor_at_bound(client, script, world, monkeypatch)
    legacy = _LEGACY_SESSION if reference == "session_id" else None
    third = seed_chat(world.db, editor, legacy_session_id=legacy)
    runs, tables, state = agent.run.await_count, _tables(world.db), chat_runtime_state(world.db)

    response = _confirm_by(client, editor, third, reference=reference, approved=approved)

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert agent.run.await_count == runs
    assert _tables(world.db) == tables
    assert chat_runtime_state(world.db) == state


def test_chat_runtime_bound_confirm_on_chat_without_entry_at_capacity_keeps_own_confirmation(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Capacity 3, no per-user bound: the A Editor's chat ``kept``, org A's Org Admin's and
    org B's Editor's chats each hold a pending confirmation, so the only entry that could
    go is the Editor's own. A confirm on another chat of the Editor's, without an entry,
    is the 404 ``No pending confirmation`` and evicts nothing: ``kept`` stays pending (GET
    detail), the runtime is unchanged, nothing runs or is stored, and approving ``kept``
    afterwards resumes its run (200)."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=3)
    editor, colleague, other_org = world.a["editor"], world.a["org_admin"], world.b["editor"]
    kept = _new_chat(world.db, editor)
    _awaited(client, script, editor, kept)
    _awaited(client, script, colleague, _new_chat(world.db, colleague))
    _awaited(client, script, other_org, _new_chat(world.db, other_org))
    stale = _new_chat(world.db, editor)
    runs, tables, state = agent.run.await_count, _tables(world.db), chat_runtime_state(world.db)

    response = _confirm(client, editor, stale)

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert _confirmation_status(client, editor, kept) == "pending"
    assert chat_runtime_state(world.db) == state
    assert (agent.run.await_count, _tables(world.db)) == (runs, tables)
    script.queue(_Reply(new=(_tool("Stored memory: plan", _PENDING_CALL),), response=_SAVED))
    approved = _confirm(client, editor, kept)
    assert approved.status_code == 200, approved.text
    assert (approved.json()["status"], approved.json()["response"]) == ("final", _SAVED)


def test_chat_runtime_bound_confirm_on_lock_only_chat_is_404_and_changes_nothing(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guard. Bound 2: the Editor's chats are one with a pending confirmation and one whose
    turn finished (its entry only a lock). A confirm on the lock-only chat is the 404 ``No
    pending confirmation``: no run, nothing stored, the runtime unchanged."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=_ROOMY, max_entries_per_user=2)
    editor = world.a["editor"]
    _awaited(client, script, editor, _new_chat(world.db, editor))
    lock_only = _new_chat(world.db, editor)
    _finished(client, editor, lock_only)
    runs, tables, state = agent.run.await_count, _tables(world.db), chat_runtime_state(world.db)

    response = _confirm(client, editor, lock_only)

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert agent.run.await_count == runs
    assert _tables(world.db) == tables
    assert chat_runtime_state(world.db) == state


def test_chat_runtime_bound_confirm_with_wrong_id_is_404_and_keeps_the_pending_one(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guard. A confirm naming a chat whose pending confirmation has another id is the 404
    ``Confirmation not found``: no run, nothing stored, the pending one kept (runtime
    unchanged)."""
    _, client = _client(agent)
    _use_runtime(monkeypatch, max_entries=_ROOMY, max_entries_per_user=2)
    editor = world.a["editor"]
    pending_chat = _new_chat(world.db, editor)
    _awaited(client, script, editor, pending_chat)
    runs, tables, state = agent.run.await_count, _tables(world.db), chat_runtime_state(world.db)

    response = _confirm_by(client, editor, pending_chat, confirmation_id=_WRONG_CONFIRMATION_ID)

    assert (response.status_code, response.json()) == (404, _CONFIRMATION_NOT_FOUND)
    assert agent.run.await_count == runs
    assert _tables(world.db) == tables
    assert chat_runtime_state(world.db) == state


@pytest.mark.parametrize("owner", ["same_org", "other_org"])
def test_chat_runtime_bound_confirm_on_another_users_chat_at_bound_is_404(
    world: World,
    agent: MagicMock,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    owner: str,
) -> None:
    """Guard. Bound 2, both of the A Editor's entries pending: a confirm naming a chat of
    org A's Org Admin or of org B's Editor, which holds a confirmation with the same id, is
    the 404 ``No pending confirmation`` (never the 429): no run, nothing stored, the
    owner's confirmation and the runtime unchanged."""
    _, client = _client(agent)
    editor = _editor_at_bound(client, script, world, monkeypatch)
    account = world.a["org_admin"] if owner == "same_org" else world.b["editor"]
    foreign = _new_chat(world.db, account)
    _awaited(client, script, account, foreign)
    runs, tables, state = agent.run.await_count, _tables(world.db), chat_runtime_state(world.db)

    response = _confirm(client, editor, foreign)

    assert (response.status_code, response.json()) == (404, _NO_PENDING)
    assert agent.run.await_count == runs
    assert _tables(world.db) == tables
    assert chat_runtime_state(world.db) == state


# ---------------------------------------------------------------------------
# 8. A refused first legacy message leaves no chat (GH-266, server audit L-1)
# ---------------------------------------------------------------------------

_NEW_SESSION: Final = "legacy-266-new-avocet"
_RETRY_MESSAGE: Final = "Second try"
_REFUSALS: Final = ("rate_limit", "chats_busy")


@dataclass(frozen=True)
class _Refusal:
    """A runtime that refuses the Editor a new entry: the answer, and how it clears."""

    answer: tuple[int, dict[str, str]]
    clear: Callable[[], None]


def _refusing_new_entries(
    client: TestClient,
    script: _Script,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    refusal: str,
) -> _Refusal:
    """Org A's Editor (one listed chat without a runtime entry) gets no new runtime entry.

    ``rate_limit``: bound 2, both of the Editor's other chats hold a pending
    confirmation (429). ``chats_busy``: capacity 2, org B's Editor's and org A's Org
    Admin's chats hold one each (503). Clearing denies one of those confirmations, so
    its chat is then only a lock and gives way.
    """
    editor = world.a["editor"]
    seed_chat(world.db, editor, title="Earlier plan", messages=[("user", "Earlier question")])
    if refusal == "rate_limit":
        _use_runtime(monkeypatch, max_entries=_ROOMY, max_entries_per_user=2)
        owner, answer = editor, (429, _USER_CHATS_BUSY)
        pending = [_new_chat(world.db, editor) for _ in range(2)]
        for chat_id in pending:
            _awaited(client, script, editor, chat_id)
    else:
        _use_runtime(monkeypatch, max_entries=2)
        owner, answer = world.a["org_admin"], (503, _CHATS_BUSY)
        other_org = world.b["editor"]
        _awaited(client, script, other_org, _new_chat(world.db, other_org))
        pending = [_new_chat(world.db, owner)]
        _awaited(client, script, owner, pending[0])

    def clear() -> None:
        denied = _confirm(client, owner, pending[0], approved=False)
        assert denied.status_code == 200, denied.text

    return _Refusal(answer=answer, clear=clear)


def _legacy_turn(
    client: TestClient, account: Account, message: str = _MESSAGE, session_id: str = _NEW_SESSION
) -> httpx.Response:
    """POST /api/message under ``session_id`` as ``account``."""
    return client.post(
        "/api/message",
        headers=account.cookie,
        json={"message": message, "session_id": session_id},
    )


def _listed(client: TestClient, account: Account) -> Any:
    """GET /api/chats as ``account`` (must succeed): the JSON body."""
    response = client.get("/api/chats", headers=account.cookie)
    assert response.status_code == 200, response.text
    return response.json()


def _session_chats(world: World, account: Account, session_id: str) -> list[dict[str, Any]]:
    """The account's chats rows of a legacy session id."""
    return [
        row for row in world.db.chats_of(account.user_id) if row["legacy_session_id"] == session_id
    ]


def _race_legacy_insert(
    monkeypatch: pytest.MonkeyPatch, db: FakeDb, owner: uuid.UUID, session_id: str
) -> list[uuid.UUID]:
    """Store the owner's chat of ``session_id`` right before the first INSERT INTO chats
    runs (a concurrent first message of the same session that inserted first); returns
    the list that chat's id lands in (tests/test_chats.py's hook)."""
    raced: list[uuid.UUID] = []
    original = db.handle

    def racing(method: str, sql: str, args: tuple[Any, ...], via: str, tx: int | None) -> Any:
        if not raced and norm(sql).startswith("insert into chats"):
            raced.append(db.add_chat(owner, legacy_session_id=session_id))
        return original(method, sql, args, via, tx)

    monkeypatch.setattr(db, "handle", racing)
    return raced


@pytest.mark.parametrize("refusal", _REFUSALS)
def test_chat_runtime_bound_refused_first_legacy_message_leaves_no_chat(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    """The first POST /api/message of a brand-new session id, refused with the 429
    ``rate_limit`` or the 503 ``chats_busy``, leaves GET /api/chats unchanged: no chats
    row, no message, no run, the runtime unchanged."""
    _, client = _client(agent)
    editor = world.a["editor"]
    refused = _refusing_new_entries(client, script, world, monkeypatch, refusal)
    listed = _listed(client, editor)
    runs, tables, state = agent.run.await_count, _tables(world.db), chat_runtime_state(world.db)

    response = _legacy_turn(client, editor, _REFUSED_MESSAGE)

    assert (response.status_code, response.json()) == refused.answer
    assert _listed(client, editor) == listed
    assert _tables(world.db) == tables
    assert (agent.run.await_count, chat_runtime_state(world.db)) == (runs, state)


@pytest.mark.parametrize("refusal", _REFUSALS)
def test_chat_runtime_bound_refused_message_on_existing_legacy_chat_keeps_it_unchanged(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    """Control: the session's chat exists (with an exchange, no runtime entry). The same
    refusal leaves it listed and unchanged; nothing runs or is stored."""
    _, client = _client(agent)
    editor = world.a["editor"]
    refused = _refusing_new_entries(client, script, world, monkeypatch, refusal)
    existing = seed_chat(
        world.db,
        editor,
        messages=[("user", "Earlier legacy question"), ("assistant", "Earlier answer")],
        legacy_session_id=_NEW_SESSION,
    )
    listed = _listed(client, editor)
    runs, tables, state = agent.run.await_count, _tables(world.db), chat_runtime_state(world.db)

    response = _legacy_turn(client, editor, _REFUSED_MESSAGE)

    assert (response.status_code, response.json()) == refused.answer
    assert str(existing) in [chat["id"] for chat in listed["chats"]]
    assert _listed(client, editor) == listed
    assert _tables(world.db) == tables
    assert (agent.run.await_count, chat_runtime_state(world.db)) == (runs, state)


@pytest.mark.parametrize("refusal", _REFUSALS)
def test_chat_runtime_bound_first_legacy_message_after_refusal_creates_one_chat_when_it_runs(
    world: World, agent: MagicMock, script: _Script, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    """Once the refusal clears, the same new session id runs: exactly one chat of the
    session, created by this turn (not by the refused message), whose id is the
    response's ``chat_id``, the run's session id and a runtime entry's key; the session
    id is echoed and the turn stored in it."""
    _, client = _client(agent)
    editor = world.a["editor"]
    refused = _refusing_new_entries(client, script, world, monkeypatch, refusal)
    assert _legacy_turn(client, editor, _REFUSED_MESSAGE).status_code == refused.answer[0]
    refused.clear()
    cleared = datetime.now(UTC)

    response = _legacy_turn(client, editor, _RETRY_MESSAGE)

    assert response.status_code == 200, response.text
    (chat,) = _session_chats(world, editor, _NEW_SESSION)
    chat_id = plain(chat["id"])
    assert chat["created_at"] >= cleared
    body = response.json()
    assert (body["chat_id"], body["session_id"]) == (str(chat_id), _NEW_SESSION)
    assert script.runs[-1].session_id == str(chat_id)
    assert chat_id in server._chat_runtime
    assert [m["content"] for m in world.db.messages_of(chat_id)] == [_RETRY_MESSAGE, _STUB_REPLY]


def test_chat_runtime_bound_concurrent_first_legacy_message_runs_in_the_winners_chat(
    world: World,
    agent: MagicMock,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    module_runtime: Any,
) -> None:
    """A concurrent first message of the same session id inserts its chat between this
    turn's lookup and its INSERT: the turn runs and is stored in that chat, under that
    chat's runtime entry, and it stays the session's only chat."""
    _, client = _client(agent)
    editor = world.a["editor"]
    raced = _race_legacy_insert(monkeypatch, world.db, editor.user_id, _NEW_SESSION)

    response = _legacy_turn(client, editor)

    assert response.status_code == 200, response.text
    (winner,) = raced
    assert [plain(row["id"]) for row in world.db.chats_of(editor.user_id)] == [winner]
    body = response.json()
    assert (body["chat_id"], body["session_id"]) == (str(winner), _NEW_SESSION)
    assert script.runs[-1].session_id == str(winner)
    assert [m["content"] for m in world.db.messages_of(winner)] == [_MESSAGE, _STUB_REPLY]
    assert winner in server._chat_runtime
