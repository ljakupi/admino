"""``POST /api/confirm/{id}`` for a chat trashed while the confirm waited for its hold: the
org's due promotions and its tool policy are read under the hold before the ``404
chat_not_found`` (GH-298 criterion 2, issue Decision 5; #296 Decision 1, #296 review
note 1, #294 Decision 7).

Decision 5 pins today's behaviour. With the account check passing, an approval whose chat
was trashed while it waited passes the confirmation checks and reads the platform
settings, completes the org's due promotions (the pair stored as ``confirm``, the org's
other live chats get the notice once, another org's chats none), loads the tool policy
once, then answers the ``404 chat_not_found`` with its pending confirmation removed
first. Nothing of the approval is run, stored or audited. A denial whose chat was
trashed meanwhile makes the same reads before its ``404``. The reads sit where #296
Decision 1 puts them: right after the platform settings read, while the confirmation is
still pending (before the denial consumes it and before the approval's trashed check).
The negative: the same flow on a live chat with nothing due answers ``200``.

Harness (copied from tests/test_confirm_policy_lock_wait_api.py and
tests/test_confirm_lock_wait_api.py): the app from ``create_app()`` on the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin, an Editor and a Viewer each, a
Super Admin, real session cookies), org A storing ``memory.store`` at ``confirm``. The
REAL ``Agent`` (real tool-call recorder) runs around a fake LLM that always answers a
final reply; a subclass records every run's ``tool_policy``. The registry is swapped for
an unfrozen one holding only ``memory.store`` with a recording handler. The Editor's chat
awaits that call's confirmation (its rows stored, the confirmation pending in a
``ChatRuntime`` subclass that counts every ``hold()`` call when it is made and how many
callers are inside a hold). Requests run in the test's event loop through one
``httpx.AsyncClient``: a holder task keeps the chat's hold, the confirm is started and
queued (its ``hold()`` call is counted), then the chat is trashed (``chats.trash_chat``,
the transaction the DELETE route runs before its own pop of the pending confirmation) and
the promotion clock ``admino.org_permissions.current_time`` is moved past the cooldown of
the gmail.send promotion the Org Admin requested before the wait; the holder then lets go.
One timeline records, in order, the trash, the clock move, the holder leaving the hold and
every platform settings read, ``org_permissions.resolve_due_promotions`` and
``org_permissions.load_tool_policy`` call (with how many callers are inside a hold and
whether the confirmation is still pending). Every wait is bounded.

Security notes:
- Every id, name, email, password and message here is a fixed fake value; no network, no
  real PostgreSQL, no real LLM.
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

from admino import chats, org_permissions, scoped_settings, server
from admino import main as main_module
from admino.agent import Agent
from admino.chat_runtime import ChatRuntime
from admino.llm import LLMResponse
from admino.models import AgentConfig, AgentResult, LLMMessage, PendingConfirmation, ToolCall
from admino.server import create_app
from admino.tenancy import TenantContext
from admino.tools import registry
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    CHAT_NOT_FOUND,
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
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

    from fastapi import FastAPI

    from admino.models import ToolPolicy
    from tests.tenancy_world import Account, World

_WAIT_S: Final = 5.0
_CRITICAL: Final = "/api/org/critical-permissions"
_COOLDOWN: Final = timedelta(minutes=5)
_CONFIRMATION_ID: Final = "confirm-298-avocet"
_STORE_MESSAGE: Final = "Note the avocet survey plan for Thursday 298"
_ARG_KEY: Final = "avocet-plan-298"
_ARG_VALUE: Final = "godwit-canary-298-survey"
_FINAL_REPLY: Final = "Finished with the avocet survey 298."
_DENIAL: Final = "Action memory.store was denied."
_STORE_CALL: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": _ARG_KEY, "value": _ARG_VALUE},
    tool_call_id="call-298-store",
)
_STORE_BLOCK: Final = {
    "type": "tool_use",
    "id": "call-298-store",
    "name": "memory.store",
    "input": {"key": _ARG_KEY, "value": _ARG_VALUE},
}
_SEEDED: Final = (("user", "Earlier question about stilts"), ("assistant", "Earlier answer."))
_NOTICE_MARKER: Final = "PERMISSION UPDATE"
_NOTICE_GMAIL: Final = (
    "PERMISSION UPDATE: The following actions are now available with user confirmation: "
    "gmail.send. Earlier denials for these actions no longer apply."
)

# Timeline entries: the test's own steps, and every read (name, callers inside a hold,
# whether the confirmation is still pending).
_TRASHED: Final = ("trashed",)
_DUE: Final = ("cooldown-passed",)
_HOLDER_LEAVES: Final = ("holder-leaves",)
_READS_UNDER_THE_HOLD: Final = [
    ("platform-settings", 1, True),
    ("resolve_due_promotions", 1, True),
    ("load_tool_policy", 1, True),
]


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
    """Answers every call with ``_FINAL_REPLY`` and counts the calls."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self.calls = 0

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls += 1
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
    """Orgs A and B (OA/ED/VI each) and a Super Admin behind the fake database; org A
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
    register("memory", "store", "Store a note (GH-298)", _StoreArgs, side_effect=True)(store)
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
# The scenario
# ---------------------------------------------------------------------------


@dataclass
class _Outcome:
    """What one confirm behind a holder left: its response, the timeline, the chats
    (``awaiting``: the confirm's chat; ``sibling``: the Org Admin's live chat in org A;
    ``org_b``: org B's Editor's live chat) and the awaiting chat's messages before."""

    response: httpx.Response
    timeline: list[tuple[Any, ...]]
    chats: dict[str, uuid.UUID]
    messages_before: list[dict[str, Any]]


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the test's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50298))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


def _editor_tenant(account: Account) -> TenantContext:
    """The org scope of an Editor account."""
    assert account.org_id is not None
    assert account.role == "editor"
    return TenantContext(org_id=account.org_id, user_id=account.user_id, role="editor")


def _awaiting_chat(db: FakeDb, runtime: ChatRuntime, account: Account) -> uuid.UUID:
    """A user-titled chat of ``account`` whose request awaits ``_STORE_CALL``'s
    confirmation: its rows stored, the live (5 minutes) confirmation pending in
    ``runtime``."""
    chat_id = db.add_chat(account.user_id, title="Avocet notes 298", title_source="user")
    db.add_chat_message(chat_id, "user", _STORE_MESSAGE)
    db.add_chat_message(
        chat_id, "assistant", "", tool_use_blocks=[_STORE_BLOCK], status="awaiting_confirmation"
    )
    now = datetime.now(UTC)
    pending = PendingConfirmation(
        confirmation_id=_CONFIRMATION_ID,
        session_id=str(chat_id),
        tool_call=_STORE_CALL,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    runtime.set_pending(chat_id, account.user_id, pending)
    return chat_id


async def _confirm(
    http: httpx.AsyncClient, account: Account, chat_id: uuid.UUID, *, approved: bool
) -> httpx.Response:
    body = {"confirmation_id": _CONFIRMATION_ID, "approved": approved, "chat_id": str(chat_id)}
    return await http.post(f"/api/confirm/{_CONFIRMATION_ID}", headers=account.cookie, json=body)


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


def _spy_reads(
    monkeypatch: pytest.MonkeyPatch,
    runtime: _WatchedRuntime,
    chat_id: uuid.UUID,
    timeline: list[tuple[Any, ...]],
) -> None:
    """Append every platform settings read (``current_platform_settings`` or
    ``load_platform_settings``), ``resolve_due_promotions`` and ``load_tool_policy`` call
    to ``timeline``: (name, callers inside a hold, the chat's confirmation still
    pending)."""
    spied = (
        (scoped_settings, "current_platform_settings", "platform-settings"),
        (scoped_settings, "load_platform_settings", "platform-settings"),
        (org_permissions, "resolve_due_promotions", "resolve_due_promotions"),
        (org_permissions, "load_tool_policy", "load_tool_policy"),
    )
    for module, name, label in spied:
        real = getattr(module, name)

        async def spy(*args: Any, _label: str = label, _real: Any = real, **kwargs: Any) -> Any:
            pending = runtime.get_pending(chat_id) is not None
            timeline.append((_label, runtime.inside, pending))
            return await _real(*args, **kwargs)

        monkeypatch.setattr(module, name, spy)


async def _confirm_behind_a_holder(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    *,
    approved: bool,
    trashed: bool,
) -> _Outcome:
    """The Editor's confirm (an approval or a denial) of their awaiting chat, queued
    behind a holder task. With ``trashed``, the Org Admin first promotes gmail.send (its
    cooldown ends one second after the confirm starts), and while the confirm waits the
    chat is trashed and the cooldown passes. Without it, nothing is promoted and the
    chat stays live."""
    db = world.db
    editor, admin = world.a["editor"], world.a["org_admin"]
    chat_id = _awaiting_chat(db, runtime, editor)
    named = {
        "awaiting": chat_id,
        "sibling": seed_chat(db, admin, messages=_SEEDED),
        "org_b": seed_chat(db, world.b["editor"], messages=_SEEDED),
    }
    messages_before = db.messages_of(chat_id)
    timeline: list[tuple[Any, ...]] = []
    inside, release = asyncio.Event(), asyncio.Event()

    async def holder() -> None:
        async with runtime.hold(chat_id, editor.user_id):
            inside.set()
            await asyncio.wait_for(release.wait(), _WAIT_S)
            timeline.append(_HOLDER_LEAVES)

    async with _async_client(app) as http:
        if trashed:
            await _promote(http, clock, admin)
            clock.at(_COOLDOWN - timedelta(seconds=1))
        _spy_reads(monkeypatch, runtime, chat_id, timeline)
        held = asyncio.create_task(holder())
        try:
            await asyncio.wait_for(inside.wait(), _WAIT_S)
            holds = runtime.holds
            confirm = asyncio.create_task(_confirm(http, editor, chat_id, approved=approved))
            await _until(lambda: runtime.holds > holds)
            assert runtime.inside == 1, "the holder alone is inside the hold while it waits"
            if trashed:
                pool: Any = db.pool
                await chats.trash_chat(pool, _editor_tenant(editor), chat_id, ip=None)
                timeline.append(_TRASHED)
                clock.at(_COOLDOWN)
                timeline.append(_DUE)
        finally:
            release.set()
            await asyncio.wait_for(held, _WAIT_S)
        response = await asyncio.wait_for(confirm, _WAIT_S)
    return _Outcome(
        response=response, timeline=timeline, chats=named, messages_before=messages_before
    )


def _notices(db: FakeDb, named: dict[str, uuid.UUID]) -> dict[str, list[str]]:
    """Per named chat, the promotion notices stored in it."""
    return {
        name: [
            str(m["content"])
            for m in db.messages_of(chat_id)
            if m["role"] == "user" and _NOTICE_MARKER in str(m["content"])
        ]
        for name, chat_id in named.items()
    }


# ---------------------------------------------------------------------------
# 1. Trashed during the wait: the reads, then the 404 (Decision 5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
async def test_confirm_trashed_policy_reads_trashed_during_the_wait_answers_chat_not_found(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    """An approval and a denial whose chat was trashed while they waited answer the 404
    ``chat_not_found`` body."""
    outcome = await _confirm_behind_a_holder(
        world, app, runtime, clock, monkeypatch, approved=approved, trashed=True
    )

    assert (outcome.response.status_code, outcome.response.json()) == (404, CHAT_NOT_FOUND)


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
async def test_confirm_trashed_policy_reads_trashed_during_the_wait_completes_the_due_promotion(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    """The gmail.send promotion requested before the wait fell due during it: the trashed
    confirm completed it before its 404. gmail.send is stored ``confirm`` in org A, the
    org's other live chat got the notice exactly once, org B's chat and the trashed chat
    none."""
    outcome = await _confirm_behind_a_holder(
        world, app, runtime, clock, monkeypatch, approved=approved, trashed=True
    )

    db = world.db
    assert outcome.response.status_code == 404, outcome.response.text
    assert (
        db.org_permissions(world.org_a)["gmail"]["send"],
        _notices(db, outcome.chats),
    ) == ("confirm", {"awaiting": [], "sibling": [_NOTICE_GMAIL], "org_b": []})


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
async def test_confirm_trashed_policy_reads_trashed_during_the_wait_reads_once_after_the_wait(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    """After the chat was trashed, the cooldown passed and the holder left the hold, the
    trashed confirm read the platform settings, completed the due promotions, then
    loaded the tool policy: once each, in that order, inside the chat's hold and while
    its confirmation was still pending; nothing was read before the wait."""
    outcome = await _confirm_behind_a_holder(
        world, app, runtime, clock, monkeypatch, approved=approved, trashed=True
    )

    assert outcome.response.status_code == 404, outcome.response.text
    assert outcome.timeline == [_TRASHED, _DUE, _HOLDER_LEAVES, *_READS_UNDER_THE_HOLD]


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
async def test_confirm_trashed_policy_reads_trashed_during_the_wait_runs_and_stores_nothing(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
    agent: _RecordingAgent,
    llm: _FinalLLM,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    """Right after the trashed confirm's 404 (the reaper never ran, the confirmation was
    live) nothing is pending for the chat, no agent run started, the LLM and the tool
    handler were never called, the chat's messages are those it had before and no
    ``tool.call`` row was written."""
    outcome = await _confirm_behind_a_holder(
        world, app, runtime, clock, monkeypatch, approved=approved, trashed=True
    )

    db = world.db
    chat_id = outcome.chats["awaiting"]
    assert outcome.response.status_code == 404, outcome.response.text
    assert (
        runtime.get_pending(chat_id),
        agent.policies,
        llm.calls,
        handler.calls,
        db.messages_of(chat_id),
        db.audit_rows("tool.call"),
    ) == (None, [], 0, [], outcome.messages_before, [])


# ---------------------------------------------------------------------------
# 2. The negative: a live chat with nothing due runs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
async def test_confirm_trashed_policy_reads_live_chat_nothing_due_answers_200(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    """The same flow with the chat left live and nothing due: the approval runs the
    approved call once (200, the final reply) and the denial answers 200 with its
    denial, each after the same three reads under the hold; gmail.send stays ``deny``."""
    outcome = await _confirm_behind_a_holder(
        world, app, runtime, clock, monkeypatch, approved=approved, trashed=False
    )

    body = outcome.response.json()
    expected = (_FINAL_REPLY, [(_ARG_KEY, _ARG_VALUE)]) if approved else (_DENIAL, [])
    assert (outcome.response.status_code, body.get("status")) == (200, "final"), body
    assert (body["response"], handler.calls) == expected
    assert (
        outcome.timeline,
        world.db.org_permissions(world.org_a)["gmail"]["send"],
    ) == ([_HOLDER_LEAVES, *_READS_UNDER_THE_HOLD], "deny")
