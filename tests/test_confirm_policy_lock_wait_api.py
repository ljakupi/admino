"""``POST /api/confirm/{id}`` after waiting for the chat's hold: the approval completes the
org's due promotions and loads the org's tool policy under the hold (GH-296, issue
Decisions 1 to 3; #294 security audit L-1).

An approval waits for a run of its chat that is going (``ChatRuntime.hold``). Decision 1:
under the hold, after the confirmation checks (nothing pending, another id or expired:
404; the body's id differs: 400) and right after the platform settings read of #294, the
route first completes the org's due promotions, then loads the org's tool policy: once
per request, for an approval and a denial alike. A refused confirm (404 or 400, before or
under the hold) completes no promotion and loads no policy. Decision 2: the approved call
gets the org's policy as stored when the approval leaves the wait. A pair the Org Admin
set to ``deny`` meanwhile (``PATCH /api/org/permissions``) is refused by the registry as a
denied tool: the handler never runs, the call's result is the permission engine's denial
and its ``tool.call`` audit row records ``decision`` ``deny``. A pair set to ``allow``, or
left unchanged, runs; org B's Org Admin denying the same pair in org B doesn't reach org
A's approval. Decision 3: a promotion that becomes due during the wait is completed by
the approval itself: the resumed run's policy holds the promoted pair at ``confirm``, the
org's other live chats get its notice once, the chat being approved none (it still awaits
its confirmation, #24 contract section 2), org B's chat none.

Harness: the app from ``create_app()`` on the FakeDb world of tests/tenancy_world.py
(orgs A and B with an Org Admin and an Editor each, a Super Admin, real session
cookies), org A storing ``memory.store`` at ``confirm``. The REAL ``Agent`` (real
tool-call recorder, so every dispatch writes its ``tool.call`` row) runs around a fake LLM
that always answers a final reply; a subclass records the ``tool_policy`` of every run.
The registry is swapped for an unfrozen one holding only ``memory.store`` with a
recording handler. The Editor's chat awaits the confirmation of that call (its rows
stored, the pending confirmation in a ``ChatRuntime`` subclass that counts every
``hold()`` call when it is made and how many callers are inside a hold). Requests run in
the test's event loop through one ``httpx.AsyncClient``: a holder task keeps the chat's
hold, the approval is started and queued (its ``hold()`` call is counted), the change is
made (an Org Admin's PATCH, or the promotion clock ``admino.org_permissions.current_time``
moved past the cooldown), then the hold is released. Every wait is bounded.

Security notes:
- Every id, name, email, password and message here is a fixed fake value; no network,
  no real PostgreSQL, no real LLM.
- The log check scans the configured log output and every record (message and args) of
  the refused approval for the tool arguments, the messages, the emails and the password.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from pydantic import BaseModel, Field

from admino import main as main_module
from admino import org_permissions, server
from admino.agent import Agent
from admino.chat_runtime import ChatRuntime
from admino.llm import LLMResponse
from admino.models import AgentConfig, AgentResult, LLMMessage, PendingConfirmation, ToolCall
from admino.permissions import check_permission, validate_permissions_config
from admino.server import create_app
from admino.tools import registry
from tests.db_fakes import FakeDb
from tests.log_capture import configured_logging
from tests.tenancy_world import (
    CLIENT_IP,
    PASSWORD,
    build_world,
    make_config,
    seed_chat,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import uuid
    from collections.abc import AsyncIterator, Awaitable, Callable
    from pathlib import Path

    from fastapi import FastAPI

    from admino.models import ToolPolicy
    from tests.tenancy_world import Account, World

_WAIT_S: Final = 5.0
_PERMISSIONS: Final = "/api/org/permissions"
_CRITICAL: Final = "/api/org/critical-permissions"
_COOLDOWN: Final = timedelta(minutes=5)
_CONFIRMATION_ID: Final = "confirm-296-kestrel"
_OTHER_ID: Final = "confirm-296-other"
_STORE_MESSAGE: Final = "Note the kestrel survey plan for Tuesday 296"
_ARG_KEY: Final = "kestrel-plan-296"
_ARG_VALUE: Final = "vireo-canary-296-survey"
_FINAL_REPLY: Final = "Finished with the kestrel survey 296."
_STORE_CALL: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": _ARG_KEY, "value": _ARG_VALUE},
    tool_call_id="call-296-store",
)
_STORE_BLOCK: Final = {
    "type": "tool_use",
    "id": "call-296-store",
    "name": "memory.store",
    "input": {"key": _ARG_KEY, "value": _ARG_VALUE},
}
_SEEDED: Final = (("user", "Earlier question about plovers"), ("assistant", "Earlier answer."))
_NOTICE_MARKER: Final = "PERMISSION UPDATE"
_NOTICE_GMAIL: Final = (
    "PERMISSION UPDATE: The following actions are now available with user confirmation: "
    "gmail.send. Earlier denials for these actions no longer apply."
)
_NO_PENDING: Final = {"detail": "No pending confirmation for this session"}
_NOT_FOUND: Final = {"detail": "Confirmation not found"}
_MISMATCH: Final = {"detail": "Confirmation ID mismatch"}


# ---------------------------------------------------------------------------
# The tool, the LLM and the agent
# ---------------------------------------------------------------------------


class _StoreArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    value: str = Field(min_length=1, max_length=200)


@dataclass
class _Handler:
    """Every (key, value) the fake ``memory.store`` handler ran with."""

    calls: list[tuple[str, str]] = field(default_factory=list)


class _FinalLLM:
    """Answers every call with ``_FINAL_REPLY`` and records the non-system messages fed."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self.calls: list[list[dict[str, Any]]] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls.append([m.model_dump() for m in messages if m.role != "system"])
        return LLMResponse(content=_FINAL_REPLY)

    async def close(self) -> None:
        """Nothing to close."""


class _RecordingAgent(Agent):
    """The real Agent; records the ``tool_policy`` every run is given."""

    def __init__(self, llm: _FinalLLM) -> None:
        # The fake answers ``chat`` only: the runs here are JSON, never streamed.
        client: Any = llm
        super().__init__(
            llm_client=client,
            tool_call_recorder=main_module._build_tool_call_recorder(),
            agent_config=AgentConfig(
                max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=300.0
            ),
        )
        self.policies: list[ToolPolicy] = []

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        self.policies.append(kwargs["tool_policy"])
        return await super().run(*args, **kwargs)


# ---------------------------------------------------------------------------
# The watched runtime and the promotion clock
# ---------------------------------------------------------------------------


class _WatchedRuntime(ChatRuntime):
    """A real ``ChatRuntime`` that counts every ``hold()`` when it is entered (before the
    caller waits for the chat's lock) and how many callers are inside a hold now."""

    def __init__(self) -> None:
        super().__init__(max_entries=64, idle_s=900.0)
        self.holds = 0
        self.inside = 0

    @contextlib.asynccontextmanager
    async def hold(
        self, chat_id: uuid.UUID, owner_user_id: uuid.UUID, *, wait: bool = True
    ) -> AsyncIterator[None]:
        self.holds += 1
        async with super().hold(chat_id, owner_user_id, wait=wait):
            self.inside += 1
            try:
                yield
            finally:
                self.inside -= 1


class _Clock:
    """Moves the promotion clock seam ``admino.org_permissions.current_time``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._monkeypatch = monkeypatch
        self.t0 = datetime.now(UTC).replace(microsecond=0)

    def at(self, offset: timedelta = timedelta(0)) -> None:
        when = self.t0 + offset
        self._monkeypatch.setattr("admino.org_permissions.current_time", lambda: when)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> World:
    """Orgs A and B (OA/ED each) and a Super Admin behind the fake database; org A
    stores memory.store at 'confirm' (org B keeps the default 'allow')."""
    db = FakeDb()
    built = build_world(db)
    db.add_permissions(built.org_a, {"memory": {"store": "confirm"}})
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    return built


@pytest.fixture()
def handler(monkeypatch: pytest.MonkeyPatch) -> _Handler:
    """An unfrozen registry holding only memory.store (a side effect) with a recording
    handler; the previous registry is restored."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    seen = _Handler()

    async def store(args: _StoreArgs, **_: Any) -> str:
        seen.calls.append((args.key, args.value))
        return f"Stored memory: {args.key}"

    register: Any = registry.register_tool
    register("memory", "store", "Store a note (GH-296)", _StoreArgs, side_effect=True)(store)
    return seen


@pytest.fixture()
def llm() -> _FinalLLM:
    return _FinalLLM()


@pytest.fixture()
def agent(llm: _FinalLLM) -> _RecordingAgent:
    return _RecordingAgent(llm)


@pytest.fixture()
def app(world: World, handler: _Handler, agent: _RecordingAgent) -> FastAPI:
    return create_app(agent=agent, config=make_config())


@pytest.fixture()
def runtime(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> _WatchedRuntime:
    """The watched runtime as ``server._chat_runtime`` (after create_app, which clears it)."""
    watched = _WatchedRuntime()
    monkeypatch.setattr(server, "_chat_runtime", watched)
    return watched


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    return _Clock(monkeypatch)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the test's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50296))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


def _pending(chat_id: uuid.UUID) -> PendingConfirmation:
    """The live (5 minutes) memory.store confirmation ``_CONFIRMATION_ID`` of the chat."""
    now = datetime.now(UTC)
    return PendingConfirmation(
        confirmation_id=_CONFIRMATION_ID,
        session_id=str(chat_id),
        tool_call=_STORE_CALL,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def _awaiting_chat(
    db: FakeDb, runtime: ChatRuntime, account: Account
) -> tuple[uuid.UUID, PendingConfirmation]:
    """A user-titled chat of ``account`` whose request awaits ``_STORE_CALL``'s
    confirmation: its rows stored, the confirmation pending in ``runtime``."""
    chat_id = db.add_chat(account.user_id, title="Kestrel notes 296", title_source="user")
    db.add_chat_message(chat_id, "user", _STORE_MESSAGE)
    db.add_chat_message(
        chat_id, "assistant", "", tool_use_blocks=[_STORE_BLOCK], status="awaiting_confirmation"
    )
    pending = _pending(chat_id)
    runtime.set_pending(chat_id, account.user_id, pending)
    return chat_id, pending


async def _confirm(
    http: httpx.AsyncClient,
    account: Account,
    chat_id: uuid.UUID,
    *,
    approved: bool,
    path_id: str = _CONFIRMATION_ID,
    body_id: str = _CONFIRMATION_ID,
) -> httpx.Response:
    body = {"confirmation_id": body_id, "approved": approved, "chat_id": str(chat_id)}
    return await http.post(f"/api/confirm/{path_id}", headers=account.cookie, json=body)


async def _set_store(http: httpx.AsyncClient, admin: Account, permission: str) -> None:
    """The Org Admin's PATCH of memory.store in their own org (must succeed)."""
    response = await http.patch(
        _PERMISSIONS,
        headers=admin.cookie,
        json={"tool": "memory", "action": "store", "permission": permission},
    )
    assert response.status_code == 200, response.text


async def _promote(http: httpx.AsyncClient, clock: _Clock, admin: Account) -> None:
    """The Org Admin promotes gmail.send (with their password) at the clock's t0."""
    clock.at()
    response = await http.patch(
        f"{_CRITICAL}/gmail/send", headers=admin.cookie, json={"password": PASSWORD}
    )
    assert response.status_code == 200, response.text


async def _until(condition: Callable[[], bool]) -> None:
    """Yield to the event loop until ``condition()`` holds (at most ``_WAIT_S``)."""

    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(poll(), _WAIT_S)


async def _behind_a_holder(
    http: httpx.AsyncClient,
    runtime: _WatchedRuntime,
    account: Account,
    chat_id: uuid.UUID,
    *,
    approved: bool,
    meanwhile: Callable[[], Awaitable[None]],
) -> httpx.Response:
    """A holder task holds the chat; the confirm is started and waits for the hold (its
    ``hold()`` call is counted); ``meanwhile`` runs; the holder lets go; the confirm's
    response."""
    inside, release = asyncio.Event(), asyncio.Event()

    async def holder() -> None:
        async with runtime.hold(chat_id, account.user_id):
            inside.set()
            await asyncio.wait_for(release.wait(), _WAIT_S)

    held = asyncio.create_task(holder())
    try:
        await asyncio.wait_for(inside.wait(), _WAIT_S)
        holds = runtime.holds
        confirm = asyncio.create_task(_confirm(http, account, chat_id, approved=approved))
        await _until(lambda: runtime.holds > holds)
        assert runtime.inside == 1, "the holder alone is inside the hold while the confirm waits"
        await meanwhile()
    finally:
        release.set()
        await asyncio.wait_for(held, _WAIT_S)
    return await asyncio.wait_for(confirm, _WAIT_S)


def _spy_policy_reads(
    monkeypatch: pytest.MonkeyPatch, runtime: _WatchedRuntime
) -> list[tuple[str, int]]:
    """Record every ``org_permissions.resolve_due_promotions`` and ``load_tool_policy``
    call, in order, with how many callers were inside a hold of the runtime."""
    reads: list[tuple[str, int]] = []
    for name in ("resolve_due_promotions", "load_tool_policy"):
        real = getattr(org_permissions, name)

        async def spy(*args: Any, _name: str = name, _real: Any = real, **kwargs: Any) -> Any:
            reads.append((_name, runtime.inside))
            return await _real(*args, **kwargs)

        monkeypatch.setattr(org_permissions, name, spy)
    return reads


def _reported(response: httpx.Response) -> list[tuple[str, str, str, bool]]:
    """(tool, action, permission, success) of every tool call the response reports."""
    return [
        (call["tool"], call["action"], call["permission"], call["success"])
        for call in response.json()["tool_calls"]
    ]


def _audited(db: FakeDb) -> list[dict[str, Any]]:
    """The ``tool.call`` audit rows' metadata (without the duration)."""
    return [
        {key: value for key, value in row["metadata"].items() if key != "duration_ms"}
        for row in db.audit_rows("tool.call")
    ]


def _tool_call_row(decision: str, *, success: bool) -> dict[str, Any]:
    return {
        "tool": "memory",
        "action": "store",
        "decision": decision,
        "success": success,
        "escalated": False,
    }


def _tool_results(db: FakeDb, chat_id: uuid.UUID) -> list[str]:
    """The contents of the chat's stored ``tool`` rows, in order."""
    return [str(m["content"]) for m in db.messages_of(chat_id) if m["role"] == "tool"]


def _notices(db: FakeDb, chats: dict[str, uuid.UUID]) -> dict[str, list[str]]:
    """Per named chat, the promotion notices stored in it."""
    return {
        name: [
            str(m["content"])
            for m in db.messages_of(chat_id)
            if m["role"] == "user" and _NOTICE_MARKER in str(m["content"])
        ]
        for name, chat_id in chats.items()
    }


def _decision(policy: ToolPolicy, tool: str, action: str) -> str:
    """The permission engine's decision for (tool, action) under ``policy``."""
    return check_permission(tool, action, policy.permissions, promoted=policy.promoted).allowed


def _org_store(db: FakeDb, org_id: uuid.UUID) -> str:
    """The org's stored memory.store permission."""
    return db.org_permissions(org_id)["memory"]["store"]


def _ran_once(response: httpx.Response, handler: _Handler) -> None:
    """The approval answered 200 final and the handler ran exactly once, with the
    approved arguments."""
    assert (response.status_code, response.json().get("status")) == (200, "final"), response.text
    assert handler.calls == [(_ARG_KEY, _ARG_VALUE)]


# ---------------------------------------------------------------------------
# 1. The approved call gets the policy stored when it leaves the wait (Decision 2)
# ---------------------------------------------------------------------------


async def test_confirm_policy_lock_wait_pair_denied_during_the_wait_is_refused_not_run(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
    llm: _FinalLLM,
) -> None:
    """The Org Admin sets memory.store to ``deny`` while the approval waits for the hold:
    the approval answers 200, the handler never ran, the response and the ``tool.call``
    row report the call as denied, and the tool result stored and fed to the LLM is the
    permission engine's denial for the stored policy."""
    db = world.db
    editor, admin = world.a["editor"], world.a["org_admin"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)

    async with _async_client(app) as http:

        async def deny() -> None:
            await _set_store(http, admin, "deny")

        response = await _behind_a_holder(
            http, runtime, editor, chat_id, approved=True, meanwhile=deny
        )

    assert _org_store(db, world.org_a) == "deny"
    assert (response.status_code, response.json().get("status")) == (200, "final"), response.text
    assert (handler.calls, _reported(response), _audited(db)) == (
        [],
        [("memory", "store", "deny", False)],
        [_tool_call_row("deny", success=False)],
    )
    engine = check_permission(
        "memory", "store", validate_permissions_config(db.org_permissions(world.org_a))
    )
    assert engine.allowed == "deny"
    assert (_tool_results(db, chat_id), llm.calls[-1][-1]["content"]) == (
        [engine.reason],
        engine.reason,
    )


async def test_confirm_policy_lock_wait_pair_allowed_during_the_wait_runs_as_allowed(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
) -> None:
    """The Org Admin sets memory.store from ``confirm`` to ``allow`` while the approval
    waits: the call runs once with the approved arguments, and the response and the
    ``tool.call`` row record the stored ``allow``."""
    db = world.db
    editor, admin = world.a["editor"], world.a["org_admin"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)

    async with _async_client(app) as http:

        async def allow() -> None:
            await _set_store(http, admin, "allow")

        response = await _behind_a_holder(
            http, runtime, editor, chat_id, approved=True, meanwhile=allow
        )

    assert _org_store(db, world.org_a) == "allow"
    _ran_once(response, handler)
    assert (_reported(response), _audited(db)) == (
        [("memory", "store", "allow", True)],
        [_tool_call_row("allow", success=True)],
    )


async def test_confirm_policy_lock_wait_pair_left_unchanged_runs_as_confirmed(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
) -> None:
    """Nothing changes while the approval waits: the confirmed call runs once with the
    approved arguments, recorded as ``confirm`` (org A's stored state; org B's is
    ``allow``)."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)

    async with _async_client(app) as http:

        async def nothing() -> None:
            await asyncio.sleep(0)

        response = await _behind_a_holder(
            http, runtime, editor, chat_id, approved=True, meanwhile=nothing
        )

    _ran_once(response, handler)
    assert (_reported(response), _audited(db)) == (
        [("memory", "store", "confirm", True)],
        [_tool_call_row("confirm", success=True)],
    )


async def test_confirm_policy_lock_wait_other_orgs_deny_during_the_wait_does_not_reach_it(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
) -> None:
    """Org B's Org Admin sets memory.store to ``deny`` in org B while org A's approval
    waits: org A's approved call runs once, recorded as org A's ``confirm``."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)

    async with _async_client(app) as http:

        async def deny_in_b() -> None:
            await _set_store(http, world.b["org_admin"], "deny")

        response = await _behind_a_holder(
            http, runtime, editor, chat_id, approved=True, meanwhile=deny_in_b
        )

    assert (_org_store(db, world.org_b), _org_store(db, world.org_a)) == ("deny", "confirm")
    _ran_once(response, handler)
    assert (_reported(response), _audited(db)) == (
        [("memory", "store", "confirm", True)],
        [_tool_call_row("confirm", success=True)],
    )


# ---------------------------------------------------------------------------
# 2. A promotion that becomes due during the wait (Decision 3)
# ---------------------------------------------------------------------------


async def test_confirm_policy_lock_wait_promotion_due_during_the_wait_is_completed_by_it(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
    agent: _RecordingAgent,
    clock: _Clock,
) -> None:
    """The Org Admin promoted gmail.send; the approval starts one second before the
    cooldown ends and the cooldown passes while it waits. The approval completes the
    promotion: the resumed run's policy holds gmail.send at ``confirm`` (stored so), the
    org's other live chats got the notice exactly once, the approved chat and org B's
    chat none."""
    db = world.db
    editor, admin = world.a["editor"], world.a["org_admin"]
    chat_x, _ = _awaiting_chat(db, runtime, editor)
    chats = {
        "x": chat_x,
        "y": seed_chat(db, editor, messages=_SEEDED),
        "z": seed_chat(db, admin, messages=_SEEDED),
        "w": seed_chat(db, world.b["editor"], messages=_SEEDED),
    }

    async with _async_client(app) as http:
        await _promote(http, clock, admin)
        clock.at(_COOLDOWN - timedelta(seconds=1))

        async def cooldown_passes() -> None:
            clock.at(_COOLDOWN)

        response = await _behind_a_holder(
            http, runtime, editor, chat_x, approved=True, meanwhile=cooldown_passes
        )

    _ran_once(response, handler)
    (policy,) = agent.policies
    assert (
        db.org_permissions(world.org_a)["gmail"]["send"],
        policy.promoted,
        _decision(policy, "gmail", "send"),
    ) == ("confirm", frozenset({("gmail", "send")}), "confirm")
    assert _notices(db, chats) == {"x": [], "y": [_NOTICE_GMAIL], "z": [_NOTICE_GMAIL], "w": []}


# ---------------------------------------------------------------------------
# 3. Where and how often the reads happen (Decision 1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
async def test_confirm_policy_lock_wait_completes_promotions_then_loads_the_policy_once_held(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    """An approval and a denial each complete the org's due promotions, then load the
    org's tool policy: exactly once each, in that order, while the confirm is inside the
    chat's hold."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)
    reads = _spy_policy_reads(monkeypatch, runtime)

    async with _async_client(app) as http:
        response = await asyncio.wait_for(
            _confirm(http, editor, chat_id, approved=approved), _WAIT_S
        )

    assert response.status_code == 200, response.text
    assert reads == [("resolve_due_promotions", 1), ("load_tool_policy", 1)]


_REFUSALS: Final = [
    "no-runtime-entry",
    "other-orgs-chat",
    "none-pending",
    "wrong-id",
    "expired",
    "body-mismatch",
]


@pytest.mark.parametrize("refusal", _REFUSALS)
async def test_confirm_policy_lock_wait_refused_confirm_completes_no_promotion_loads_no_policy(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
    agent: _RecordingAgent,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    refusal: str,
) -> None:
    """A promotion of org A is due. A confirm refused before the hold (the chat has no
    runtime entry; it names org B's awaiting chat) or under it (nothing pending; another
    id; expired while it waited; the body's id differs) answers its 404 or 400, completes
    no promotion (gmail.send still stored ``deny``, no notice in the org's other chat),
    loads no policy and runs nothing."""
    db = world.db
    editor = world.a["editor"]
    chat_id, pending = _awaiting_chat(db, runtime, editor)
    sibling = seed_chat(db, editor, messages=_SEEDED)
    target, path_id, body_id = chat_id, _CONFIRMATION_ID, _CONFIRMATION_ID
    expected: tuple[int, dict[str, str]] = (404, _NO_PENDING)
    if refusal == "no-runtime-entry":
        target = db.add_chat(editor.user_id, title="No entry 296", title_source="user")
    elif refusal == "other-orgs-chat":
        target, _ = _awaiting_chat(db, runtime, world.b["editor"])
    elif refusal == "none-pending":
        runtime.pop_pending(chat_id)
    elif refusal == "wrong-id":
        path_id = body_id = _OTHER_ID
        expected = (404, _NOT_FOUND)
    elif refusal == "expired":
        # The request's reap is skipped; the expiry check under the hold refuses it.
        monkeypatch.setattr(server, "_reap_expired_confirmations", lambda: None)
        monkeypatch.setattr(server, "_utc_now", lambda: pending.expires_at)
    else:
        body_id = _OTHER_ID
        expected = (400, _MISMATCH)

    async with _async_client(app) as http:
        await _promote(http, clock, world.a["org_admin"])
        clock.at(_COOLDOWN)
        reads = _spy_policy_reads(monkeypatch, runtime)
        response = await asyncio.wait_for(
            _confirm(http, editor, target, approved=True, path_id=path_id, body_id=body_id),
            _WAIT_S,
        )

    assert ((response.status_code, response.json()), reads) == (expected, [])
    assert (
        db.org_permissions(world.org_a)["gmail"]["send"],
        _notices(db, {"sibling": sibling}),
        agent.policies,
        handler.calls,
    ) == ("deny", {"sibling": []}, [], [])


# ---------------------------------------------------------------------------
# 4. Section 5: no content in the logs
# ---------------------------------------------------------------------------


async def test_confirm_policy_lock_wait_refused_approval_logs_no_content(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
) -> None:
    """The approval refused by a ``deny`` set during its wait, logged the way main()
    configures it at DEBUG, names neither a tool argument, the chat's message, the reply,
    an email nor the password, in the output or in any record's message or args; the
    resume line is there (the scan isn't of an empty log) and the call was refused."""
    db = world.db
    editor, admin = world.a["editor"], world.a["org_admin"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)

    with configured_logging("DEBUG", "text") as captured:
        async with _async_client(app) as http:

            async def deny() -> None:
                await _set_store(http, admin, "deny")

            response = await _behind_a_holder(
                http, runtime, editor, chat_id, approved=True, meanwhile=deny
            )

    assert (response.status_code, handler.calls) == (200, []), response.text
    text = captured.text.casefold()
    assert "resuming agent for chat" in text
    records = [
        f"{record.getMessage()}\n{record.msg}\n{record.args!r}".casefold()
        for record in captured.records
    ]
    probes = [
        _STORE_MESSAGE,
        _ARG_KEY,
        _ARG_VALUE,
        _FINAL_REPLY,
        PASSWORD,
        *(account.email for account in world.everyone()),
    ]
    leaks = [
        probe
        for probe in probes
        if probe.casefold() in text or any(probe.casefold() in record for record in records)
    ]
    assert leaks == []
