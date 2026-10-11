"""HTTP spec: the GH-66 promotion notice never breaks a chat awaiting a confirmation (GH-24).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin and an Editor each, all
with real session cookies). The real promotion flow of GH-161 runs:
the Org Admin promotes ``gmail.send`` with their password, the 5-minute
cooldown passes on the promotion clock (``admino.org_permissions.current_time``)
and the org's next request that completes due promotions (the admin's
``GET /api/org/critical-permissions``, a turn, a confirmation) stores the
notice through ``chats.append_org_notice`` (contract section 2: S12a locks the
org's live chats, S12b inserts into each whose latest message isn't
``awaiting_confirmation``).

Chat X is the Editor's chat whose latest stored message awaits a confirmation,
created by a real turn through the API: a stub agent (bound to ``Agent.run``'s
signature) answers ``awaiting_confirmation`` with an assistant ``tool_use``
block (single shape), or with a batch whose second call waits (batch shape:
the latest row is the first call's ``tool`` result). One flow uses the REAL
``Agent`` around a scripted fake LLM.

What is pinned (issue #24 criteria 11 and 13, contract sections 2 and 6):
- A completed promotion stores no notice in X (its rows unchanged, the latest
  still ``awaiting_confirmation``, the confirmation still pending), exactly one
  in each other live chat of org A (the Editor's second chat, the Org Admin's
  chat) and none in org B's chat; single and batch shapes.
- Approve, deny, timeout expiry (``server._utc_now`` moved past
  ``expires_at``) followed by a new turn, and a new turn while still pending:
  each leaves a well-formed history (contract section 6) in X and in the
  history the agent is given (the resolving run and the next turn's run): the
  closing ``tool`` result(s) follow the ``tool_use`` directly. Each case both
  with the promotion completed by an earlier admin request and by the
  resolving request itself (``_resolve_due_promotions`` runs at its start).
- Once X is resolved, a LATER completed promotion's notice is stored in X.
- With the real agent, the provider-facing history after an approval that
  follows the notice has every ``tool_use`` immediately followed by its result.
- Section 5: the notice reaches only the promoting org; no log line names the
  notice, a message, a tool argument, an email or a password.

GH-24 names (``server._utc_now``) are looked up lazily in the test bodies, so
the file collects before GH-24 is implemented.

Security notes:
- Every message, id, email and password here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest
from pydantic import BaseModel, Field

from admino import main as main_module
from admino import server
from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import (
    AgentConfig,
    AgentResult,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
)
from admino.server import create_app
from admino.tools import registry
from tests.db_fakes import FakeDb
from tests.log_capture import configured_logging
from tests.tenancy_world import (
    PASSWORD,
    build_world,
    make_app,
    make_client,
    make_config,
    seed_chat,
    stub_agent,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import Sequence
    from unittest.mock import MagicMock

    import httpx
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CRITICAL: Final = "/api/org/critical-permissions"
_GMAIL_SEND: Final = ("gmail", "send")
_OUTLOOK_SEND: Final = ("outlook", "send")
_COOLDOWN: Final = timedelta(minutes=5)
# The second promotion (after X is resolved) starts well after the first completed.
_LATER: Final = timedelta(minutes=20)

_NOTICE_GMAIL: Final = (
    "PERMISSION UPDATE: The following actions are now available with user confirmation: "
    "gmail.send. Earlier denials for these actions no longer apply."
)
_NOTICE_OUTLOOK: Final = (
    "PERMISSION UPDATE: The following actions are now available with user confirmation: "
    "outlook.send. Earlier denials for these actions no longer apply."
)
_NOTICE_MARKER: Final = "PERMISSION UPDATE"

_CONFIRMATION_ID: Final = "confirm-24-osprey"
_OPENING: Final = "Please file the plan for the harrier review"
_NEXT: Final = "Never mind, skip the harrier filing"
_FOLLOW_UP: Final = "What else is open for the harrier review?"
_REPLY: Final = "Done with the harrier note."
_SAVED: Final = "Saved the harrier plan."
_STORED_RESULT: Final = "Stored memory: harrier-plan"
_RECALLED: Final = "Recalled: harrier plan draft"
_DENIED_RESULT: Final = "Tool call denied by the user."
_DENIAL: Final = "Action memory.store was denied."
_ARG_VALUE: Final = "ship-harrier-24"
_SEEDED: Final = (("user", "Earlier question about ospreys"), ("assistant", "Earlier answer."))

_PENDING_CALL: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": "harrier-plan", "value": _ARG_VALUE},
    tool_call_id="call-p24",
)
_FIRST_CALL: Final = ToolCall(
    tool="memory", action="recall", args={"key": "harrier-plan"}, tool_call_id="call-a24"
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
    """How a stored chat_messages row of ``message`` reads."""
    return (message.role, message.content, message.tool_call_id, message.tool_use_blocks, status)


def _stored(db: FakeDb, chat_id: uuid.UUID) -> list[Row]:
    """The chat's stored messages by seq, as ``_row`` tuples."""
    return [
        (m["role"], m["content"], m["tool_call_id"], m["tool_use_blocks"], m["status"])
        for m in db.messages_of(chat_id)
    ]


def _added(db: FakeDb, chat_id: uuid.UUID) -> list[tuple[str, str, str]]:
    """(role, content, status) of every message stored after a seeded chat's two."""
    return [(m["role"], m["content"], m["status"]) for m in db.messages_of(chat_id)[2:]]


def _notice_row(content: str) -> tuple[str, str, str]:
    return ("user", content, "complete")


# ---------------------------------------------------------------------------
# Well-formed history (contract section 6)
# ---------------------------------------------------------------------------

_Shape = tuple[str, str | None, tuple[str, ...]]


def _shape(message: LLMMessage | Mapping[str, Any]) -> _Shape:
    """(role, tool_call_id, ids of the tool_use blocks) of a message, row or dumped message."""
    if isinstance(message, LLMMessage):
        role, call_id, blocks = message.role, message.tool_call_id, message.tool_use_blocks
    else:
        role, call_id, blocks = message["role"], message["tool_call_id"], message["tool_use_blocks"]
    return role, call_id, tuple(str(block["id"]) for block in blocks or ())


def _assert_well_formed(
    messages: Sequence[LLMMessage | Mapping[str, Any]], *, dangling_tail_ok: bool | None = None
) -> None:
    """Every assistant message with n > 0 tool_use blocks is directly followed by exactly
    n ``tool`` messages answering the blocks' ids in block order (no user or assistant
    message in between), and every ``tool`` message is such an answer.

    The only exception: the very end of a history that legitimately awaits a
    confirmation may stop after a prefix of the answers. For stored rows that is a
    chat whose latest row has status ``awaiting_confirmation`` (the default); for a
    history handed to the agent, pass ``dangling_tail_ok`` (True only for an approved
    resume, which dispatches the call).
    """
    if dangling_tail_ok is None:
        last = messages[-1] if messages else None
        dangling_tail_ok = isinstance(last, Mapping) and last["status"] == "awaiting_confirmation"
    shapes = [_shape(message) for message in messages]
    index = 0
    while index < len(shapes):
        role, call_id, block_ids = shapes[index]
        assert role != "tool", f"tool result {call_id!r} at {index} answers no tool_use: {shapes}"
        index += 1
        if role != "assistant" or not block_ids:
            continue
        answers = shapes[index : index + len(block_ids)]
        got = [(answer_role, answer_id) for answer_role, answer_id, _ in answers]
        wanted = [("tool", block_id) for block_id in block_ids]
        open_tail = (
            dangling_tail_ok
            and index + len(answers) == len(shapes)
            and len(answers) < len(block_ids)
        )
        expected = wanted[: len(answers)] if open_tail else wanted
        assert got == expected, (
            f"tool_use at {index - 1} is not directly followed by its results: {shapes}"
        )
        index += len(answers)


def _assert_chat_well_formed(db: FakeDb, chat_id: uuid.UUID) -> None:
    """The chat's stored rows (by seq) are a well-formed history."""
    _assert_well_formed(db.messages_of(chat_id))


# ---------------------------------------------------------------------------
# The stub agent
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Reply:
    """What one stub run answers: its new messages (after the user message) and outcome."""

    new: tuple[LLMMessage, ...] = (LLMMessage(role="assistant", content=_REPLY),)
    status: str = "final"
    response: str = _REPLY
    pending: ToolCall | None = None


@dataclass(frozen=True)
class _Run:
    """One stub run: the history it got (copied at call time) and whether it resumed."""

    user_message: str
    history: tuple[LLMMessage, ...]
    resumed: bool


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


class _Script:
    """Scripted replies for the stub agent's ``run``, the record of every call and the
    last pending confirmation it handed out."""

    def __init__(self) -> None:
        self.replies: list[_Reply] = []
        self.runs: list[_Run] = []
        self.pending: PendingConfirmation | None = None

    def queue(self, *replies: _Reply) -> None:
        self.replies.extend(replies)

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        bound = inspect.signature(_run_signature).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        history = list(arguments["history"])
        resumed = arguments["pending_confirmation"] is not None
        self.runs.append(
            _Run(
                user_message=arguments["user_message"],
                history=tuple(message.model_copy(deep=True) for message in history),
                resumed=resumed,
            )
        )
        reply = self.replies.pop(0) if self.replies else _Reply()
        base = [message for message in history if message.role != "system"]
        if not resumed:
            base.append(_user(arguments["user_message"]))
        pending = None
        if reply.pending is not None:
            created = datetime.now(UTC)
            pending = PendingConfirmation(
                confirmation_id=_CONFIRMATION_ID,
                session_id=arguments["session_id"],
                tool_call=reply.pending,
                created_at=created,
                expires_at=created + timedelta(minutes=5),
            )
            self.pending = pending
        return AgentResult(
            status=reply.status,  # type: ignore[arg-type]
            response=reply.response,
            history=[*base, *reply.new],
            tool_calls=[],
            pending_confirmation=pending,
        )


def _awaiting(new: tuple[LLMMessage, ...]) -> _Reply:
    """A run that ends waiting for ``_PENDING_CALL``'s confirmation after ``new``."""
    return _Reply(
        new=new,
        status="awaiting_confirmation",
        response="Action memory.store requires user confirmation.",
        pending=_PENDING_CALL,
    )


# What X holds after the opening user message, per shape: the last one awaits.
_OPENINGS: Final[dict[str, tuple[LLMMessage, ...]]] = {
    # One call that waits: the assistant tool_use row is the latest.
    "single": (_tool_use(_PENDING_CALL),),
    # A batch whose 2nd call waits: the 1st call's tool result row is the latest.
    "batch": (_tool_use(_FIRST_CALL, _PENDING_CALL), _tool(_RECALLED, _FIRST_CALL)),
}

_RESOLUTIONS: Final = ("approve", "deny", "expiry-then-turn", "new-turn")
_TRIGGERS: Final = ("admin-request-first", "resolving-request")


def _closing(resolution: str) -> list[LLMMessage]:
    """What resolving X stores after the awaiting row(s), in order."""
    if resolution == "approve":
        return [_tool(_STORED_RESULT, _PENDING_CALL), _assistant(_SAVED)]
    if resolution == "deny":
        return [_tool(_DENIED_RESULT, _PENDING_CALL), _assistant(_DENIAL)]
    return [
        _tool(server._CANCELLED_TOOL_RESULT_MSG, _PENDING_CALL),
        _user(_NEXT),
        _assistant(_REPLY),
    ]


def _awaiting_rows(shape: str) -> list[Row]:
    """X's rows while it awaits: the opening user message, then the run's messages (the
    last one stored ``awaiting_confirmation``)."""
    opening = _OPENINGS[shape]
    return [
        _row(_user(_OPENING)),
        *(_row(message) for message in opening[:-1]),
        _row(opening[-1], "awaiting_confirmation"),
    ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED each) and a Super Admin, behind the fake database."""
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


class _Clock:
    """Moves the promotion clock seam ``admino.org_permissions.current_time``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._monkeypatch = monkeypatch
        self.t0 = datetime.now(UTC).replace(microsecond=0)

    def at(self, offset: timedelta = timedelta(0)) -> None:
        when = self.t0 + offset
        self._monkeypatch.setattr("admino.org_permissions.current_time", lambda: when)


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    return _Clock(monkeypatch)


@dataclass(frozen=True)
class _Chats:
    """The live chats around X: the Editor's second chat (Y), the Org Admin's (Z) and an
    org B Editor's (W), each seeded with two complete messages."""

    y: uuid.UUID
    z: uuid.UUID
    w: uuid.UUID


def _seed_others(world: World) -> _Chats:
    return _Chats(
        y=seed_chat(world.db, world.a["editor"], messages=_SEEDED),
        z=seed_chat(world.db, world.a["org_admin"], messages=_SEEDED),
        w=seed_chat(world.db, world.b["editor"], messages=_SEEDED),
    )


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


def _send(client: TestClient, account: Account, chat_id: uuid.UUID, message: str) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account``."""
    return client.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
    )


def _confirm(
    client: TestClient,
    account: Account,
    chat_id: uuid.UUID,
    *,
    approved: bool,
    confirmation_id: str = _CONFIRMATION_ID,
) -> httpx.Response:
    """POST /api/confirm/{confirmation_id} naming the chat."""
    return client.post(
        f"/api/confirm/{confirmation_id}",
        headers=account.cookie,
        json={"confirmation_id": confirmation_id, "approved": approved, "chat_id": str(chat_id)},
    )


def _detail(client: TestClient, account: Account, chat_id: uuid.UUID) -> dict[str, Any]:
    """GET /api/chats/{chat_id} as its owner (must succeed; completes no promotion)."""
    response = client.get(f"/api/chats/{chat_id}", headers=account.cookie)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _promote(
    client: TestClient, clock: _Clock, admin: Account, pair: tuple[str, str], at: timedelta
) -> None:
    """The Org Admin promotes ``pair`` at ``at`` (with their password); the clock then
    stands at the end of the cooldown, so the org's next resolving request completes it."""
    clock.at(at)
    response = client.patch(
        f"{_CRITICAL}/{pair[0]}/{pair[1]}", headers=admin.cookie, json={"password": PASSWORD}
    )
    assert response.status_code == 200, response.text
    clock.at(at + _COOLDOWN)


def _admin_request(client: TestClient, admin: Account) -> None:
    """The Org Admin's GET of the critical permissions: a request not about X that
    completes the org's due promotions."""
    response = client.get(_CRITICAL, headers=admin.cookie)
    assert response.status_code == 200, response.text


def _open_awaiting(client: TestClient, world: World, script: _Script, shape: str) -> uuid.UUID:
    """A real turn through the API leaves the Editor's new chat X awaiting a confirmation."""
    editor = world.a["editor"]
    chat_x = world.db.add_chat(editor.user_id)
    script.queue(_awaiting(_OPENINGS[shape]))
    response = _send(client, editor, chat_x, _OPENING)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "awaiting_confirmation", response.json()
    assert _stored(world.db, chat_x) == _awaiting_rows(shape)
    return chat_x


def _expire(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    world: World,
    script: _Script,
    chat_x: uuid.UUID,
) -> None:
    """Move the server's clock past X's ``expires_at``; X's detail (which reaps) then
    shows the confirmation as expired."""
    assert script.pending is not None
    past_expiry = script.pending.expires_at + timedelta(seconds=1)
    monkeypatch.setattr(server, "_utc_now", lambda: past_expiry)
    assert _detail(client, world.a["editor"], chat_x)["confirmation_status"] == "expired"


def _resolve(
    client: TestClient, world: World, script: _Script, chat_x: uuid.UUID, resolution: str
) -> httpx.Response:
    """Resolve X: approve, deny, or send a new turn (after the expiry, or still pending)."""
    editor = world.a["editor"]
    if resolution == "approve":
        script.queue(_Reply(new=tuple(_closing("approve")), response=_SAVED))
        return _confirm(client, editor, chat_x, approved=True)
    if resolution == "deny":
        return _confirm(client, editor, chat_x, approved=False)
    return _send(client, editor, chat_x, _NEXT)


@dataclass
class _Scene:
    """X (awaiting), the chats around it, and how many stub runs happened before X was
    resolved."""

    chat_x: uuid.UUID
    others: _Chats
    runs_before: int = 0


def _play(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    world: World,
    script: _Script,
    clock: _Clock,
    *,
    shape: str,
    resolution: str,
    trigger: str,
) -> _Scene:
    """X awaits; gmail.send is promoted and its cooldown passes; for an expiry X's
    confirmation expires first; the promotion completes by the admin's request
    (``admin-request-first``) or by the request resolving X (``resolving-request``);
    then X is resolved."""
    chat_x = _open_awaiting(client, world, script, shape)
    scene = _Scene(chat_x=chat_x, others=_seed_others(world))
    _promote(client, clock, world.a["org_admin"], _GMAIL_SEND, timedelta(0))
    if resolution == "expiry-then-turn":
        _expire(monkeypatch, client, world, script, chat_x)
    if trigger == "admin-request-first":
        _admin_request(client, world.a["org_admin"])
    scene.runs_before = len(script.runs)
    response = _resolve(client, world, script, chat_x, resolution)
    assert response.status_code == 200, response.text
    return scene


# ---------------------------------------------------------------------------
# 1. A completed promotion skips the chat awaiting a confirmation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", ["single", "batch"])
def test_promotion_notice_skips_the_chat_awaiting_a_confirmation(
    world: World, client: TestClient, script: _Script, clock: _Clock, shape: str
) -> None:
    """The admin's request (not about X) completes the promotion: X's rows are unchanged
    (latest still awaiting, the confirmation still pending), every other live chat of
    org A gets exactly one notice, org B's chat none. Batch: X's latest row is the
    first call's ``tool`` result."""
    chat_x = _open_awaiting(client, world, script, shape)
    others = _seed_others(world)
    before = _stored(world.db, chat_x)
    _promote(client, clock, world.a["org_admin"], _GMAIL_SEND, timedelta(0))

    _admin_request(client, world.a["org_admin"])

    assert {chat: _added(world.db, chat) for chat in (others.y, others.z, others.w)} == {
        others.y: [_notice_row(_NOTICE_GMAIL)],
        others.z: [_notice_row(_NOTICE_GMAIL)],
        others.w: [],
    }
    assert _stored(world.db, chat_x) == before
    assert before[-1][-1] == "awaiting_confirmation"
    assert _detail(client, world.a["editor"], chat_x)["confirmation_status"] == "pending"


# ---------------------------------------------------------------------------
# 2. Approve, deny, expiry and a new turn each leave a well-formed history
# ---------------------------------------------------------------------------

_CELLS: Final = [
    *(
        pytest.param("single", resolution, trigger, id=f"single-{resolution}-{trigger}")
        for resolution in _RESOLUTIONS
        for trigger in _TRIGGERS
    ),
    *(
        pytest.param("batch", resolution, "resolving-request", id=f"batch-{resolution}")
        for resolution in _RESOLUTIONS
    ),
]


@pytest.mark.parametrize(("shape", "resolution", "trigger"), _CELLS)
def test_promotion_notice_resolving_the_awaiting_chat_leaves_a_well_formed_history(
    world: World,
    client: TestClient,
    script: _Script,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    shape: str,
    resolution: str,
    trigger: str,
) -> None:
    """The promotion completed (the other chats got the notice); X holds no notice, its
    closing ``tool`` result(s) follow the ``tool_use`` directly (contract section 6), the
    run resolving X (an approved resume: ending with the awaiting rows; a turn: with the
    cancelled result) and the next turn's run are given well-formed histories."""
    scene = _play(
        monkeypatch,
        client,
        world,
        script,
        clock,
        shape=shape,
        resolution=resolution,
        trigger=trigger,
    )
    chat_x, editor = scene.chat_x, world.a["editor"]
    assert _added(world.db, scene.others.y) == [_notice_row(_NOTICE_GMAIL)]

    awaited = [_user(_OPENING), *_OPENINGS[shape]]
    if resolution == "deny":
        assert len(script.runs) == scene.runs_before
    else:
        (resolving,) = script.runs[scene.runs_before :]
        _assert_well_formed(resolving.history, dangling_tail_ok=resolving.resumed)
        expected_history = (
            awaited
            if resolution == "approve"
            else [*awaited, _tool(server._CANCELLED_TOOL_RESULT_MSG, _PENDING_CALL)]
        )
        assert _dump(resolving.history) == _dump(expected_history)
    _assert_chat_well_formed(world.db, chat_x)
    assert _stored(world.db, chat_x) == [
        *_awaiting_rows(shape),
        *(_row(message) for message in _closing(resolution)),
    ]

    follow_up = _send(client, editor, chat_x, _FOLLOW_UP)

    assert follow_up.status_code == 200, follow_up.text
    _assert_well_formed(script.runs[-1].history, dangling_tail_ok=False)
    _assert_chat_well_formed(world.db, chat_x)


# ---------------------------------------------------------------------------
# 3. Once resolved, the chat gets a later promotion's notice
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("resolution", _RESOLUTIONS)
def test_promotion_notice_later_promotion_reaches_the_resolved_chat(
    world: World,
    client: TestClient,
    script: _Script,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    resolution: str,
) -> None:
    """X no longer awaits once resolved: a later completed promotion (outlook.send) stores
    its notice in X, after the closing rows, exactly once; X never got the first one."""
    scene = _play(
        monkeypatch,
        client,
        world,
        script,
        clock,
        shape="single",
        resolution=resolution,
        trigger="admin-request-first",
    )
    _promote(client, clock, world.a["org_admin"], _OUTLOOK_SEND, _LATER)

    _admin_request(client, world.a["org_admin"])

    assert _added(world.db, scene.others.y) == [
        _notice_row(_NOTICE_GMAIL),
        _notice_row(_NOTICE_OUTLOOK),
    ]
    assert _stored(world.db, scene.chat_x) == [
        *_awaiting_rows("single"),
        *(_row(message) for message in _closing(resolution)),
        _row(_user(_NOTICE_OUTLOOK)),
    ]
    _assert_chat_well_formed(world.db, scene.chat_x)


# ---------------------------------------------------------------------------
# 4. The real agent: what the provider is fed after an approval
# ---------------------------------------------------------------------------

_FINAL_REPLY: Final = "All done with the harrier plan."
_STORE: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": "harrier-plan", "value": _ARG_VALUE},
    tool_call_id="call-store24",
)
_STORE_MESSAGE: Final = "Store the harrier plan as a note"


class _StoreArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    value: str = Field(min_length=1, max_length=200)


@dataclass
class _Tools:
    """What the fake ``memory.store`` wrote."""

    stored: list[tuple[str, str]] = field(default_factory=list)


class _ScriptLLM:
    """Plays a script per user message (the n-th call of a turn returns the n-th scripted
    tool call, counted by the assistant turns after the last user message, then the final
    reply) and records the non-system messages of every call."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self._scripts: dict[str, list[ToolCall]] = {}
        self.calls: list[list[dict[str, Any]]] = []

    def script(self, message: str, *calls: ToolCall) -> None:
        self._scripts[message] = list(calls)

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls.append([m.model_dump() for m in messages if m.role != "system"])
        last_user = max(index for index, message in enumerate(messages) if message.role == "user")
        steps = self._scripts.get(str(messages[last_user].content), [])
        done = sum(1 for message in messages[last_user + 1 :] if message.role == "assistant")
        if done < len(steps):
            return LLMResponse(content="", tool_calls=[steps[done]])
        return LLMResponse(content=_FINAL_REPLY)

    async def close(self) -> None:
        """Nothing to close."""


@pytest.fixture()
def tools(monkeypatch: pytest.MonkeyPatch) -> _Tools:
    """An unfrozen registry holding memory.store (a side effect); the previous one is
    restored."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    seen = _Tools()

    async def store(args: _StoreArgs, **_: Any) -> str:
        seen.stored.append((args.key, args.value))
        return f"Stored memory: {args.key}"

    register: Any = registry.register_tool
    register("memory", "store", "Store a note (GH-24)", _StoreArgs, side_effect=True)(store)
    return seen


def _real_client(llm: _ScriptLLM) -> TestClient:
    """The app around the REAL Agent (real tool-call recorder) and ``llm``."""
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=300.0
        ),
    )
    app: FastAPI = create_app(agent=agent, config=make_config())
    return make_client(app, raise_server_exceptions=False)


def test_promotion_notice_real_agent_approval_after_the_notice_feeds_a_well_formed_history(
    world: World, tools: _Tools, clock: _Clock
) -> None:
    """A chat holding external content makes the allowed memory.store wait (GH-243); the
    promotion completes; the approval dispatches the call, and every LLM call was fed a
    history whose every ``tool_use`` is immediately followed by its result."""
    llm = _ScriptLLM()
    llm.script(_STORE_MESSAGE, _STORE)
    client = _real_client(llm)
    editor = world.a["editor"]
    chat_x = world.db.add_chat(editor.user_id, external_content=True)
    others = _seed_others(world)
    opened = _send(client, editor, chat_x, _STORE_MESSAGE)
    assert opened.status_code == 200, opened.text
    assert opened.json()["status"] == "awaiting_confirmation", opened.json()
    confirmation_id = opened.json()["pending_confirmation"]["confirmation_id"]
    _promote(client, clock, world.a["org_admin"], _GMAIL_SEND, timedelta(0))
    _admin_request(client, world.a["org_admin"])
    assert _added(world.db, others.y) == [_notice_row(_NOTICE_GMAIL)]

    approved = _confirm(client, editor, chat_x, approved=True, confirmation_id=confirmation_id)

    assert approved.status_code == 200, approved.text
    assert (approved.json()["status"], tools.stored) == ("final", [("harrier-plan", _ARG_VALUE)])
    for fed in llm.calls:
        _assert_well_formed(fed, dangling_tail_ok=False)
    assert [(m["role"], m["tool_call_id"]) for m in llm.calls[-1]] == [
        ("user", None),
        ("assistant", None),
        ("tool", _STORE.tool_call_id),
    ]
    assert _NOTICE_MARKER not in str(llm.calls[-1])
    _assert_chat_well_formed(world.db, chat_x)


# ---------------------------------------------------------------------------
# 5. Section 5: no content in the logs
# ---------------------------------------------------------------------------


def test_promotion_notice_skip_and_approval_log_no_content(
    world: World,
    client: TestClient,
    script: _Script,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole flow (X awaits, the approval completes the promotion and resumes), logged
    the way main() configures it at DEBUG, names neither the notice, a message, a tool
    argument or result, an email nor the password; the chat lines are there (the scan
    isn't of an empty log)."""
    with configured_logging("DEBUG", "text") as captured:
        _play(
            monkeypatch,
            client,
            world,
            script,
            clock,
            shape="single",
            resolution="approve",
            trigger="resolving-request",
        )

    text = captured.text.casefold()
    assert "resuming agent for chat" in text
    secrets = [
        _NOTICE_MARKER,
        _OPENING,
        _ARG_VALUE,
        _STORED_RESULT,
        _SAVED,
        PASSWORD,
        *(account.email for account in world.everyone()),
    ]
    assert [secret for secret in secrets if secret.casefold() in text] == []
