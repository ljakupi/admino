"""``POST /api/confirm/{id}`` after waiting for the chat's hold: the approval re-checks the
approving user's account under the hold (GH-298, issue Decisions 1 to 4; #296 security
audit I-2).

The caller's principal is resolved when the request arrives; an approval then waits
for a run of its chat that is going (``ChatRuntime.hold``). Decision 1: as the first
step under the hold, before the confirmation checks (nothing pending, another id or
expired: 404; the body's id differs: 400) and before the platform settings, promotions
and tool policy reads of #294 and #296, the route reads the caller's account again,
once, for an approval and a denial alike. The account must still pass the account
rules of session resolution (the user ``active`` and not deleted, a member's org
``active``, the row a valid ``Principal`` of the same user, kind and org as the
request's principal) and its role must still have ``chat.send``. Decision 2: an
account that no longer passes answers ``401 {"detail": "Unauthorized"}``, a role
without ``chat.send`` ``403 {"detail": "Forbidden"}``: exactly what the same confirm
sent after the change answers (``require_session`` / ``require_chat_sender``), JSON
even for a streamed confirm, and the per-IP budget of unresolved session cookies is
not spent. Decision 3: a refused confirm changes nothing: no agent run, the handler
never runs, no ``tool.call`` row, no stored message, no due promotion completed, no
platform settings or tool policy read, the pending confirmation left as it is (a
removed user's is already dropped with the account), no content logged. Decision 4:
an account that passes goes on as today (a role change that keeps ``chat.send``, an
unchanged user, another member's or another org's change), and the run gets the
request's principal (the approver's user and org).

Both member roles have ``chat.send`` (#306), so a role change that loses it (#306,
Decision 8: the re-check stays) withdraws ``chat.send`` from the role the member
moves to, for that test only: the approving Org Admin made an Editor while only Org
Admins have it (refused), another member made an Org Admin while only Editors have it
(the approval runs).

Harness: the app from ``create_app()`` on the FakeDb world of tests/tenancy_world.py
(orgs A and B with an Org Admin and an Editor each, a Super Admin, real session
cookies), plus a second Editor of org A (the colleague) and, for the demotion, a
second Org Admin of org A (the approver), org A storing ``memory.store`` at
``confirm``. The REAL ``Agent`` (real tool-call recorder, so every dispatch writes its
``tool.call`` row) runs around a fake LLM that always answers a final reply; a
subclass records the principal of every run. The registry is swapped for an unfrozen
one holding only ``memory.store`` with a recording handler. The approver's chat (the
Editor's, or the second Org Admin's) awaits the confirmation of that call (its rows
stored, the pending confirmation in a ``ChatRuntime`` subclass that counts every
``hold()`` call when it is made and how many callers are inside a hold). Requests run
in the test's event loop through one ``httpx.AsyncClient``: a holder task keeps the
chat's hold, the confirm is started and queued (its ``hold()`` call is counted), the
change is made through the API (an Org Admin's deactivation, removal or role change;
the Super Admin's org deactivation or deletion schedule) or, for account rows the API
can't produce, in the fake's users table, then the hold is released. Every wait is
bounded.

Security notes:
- Every id, name, email, password and message here is a fixed fake value; no network,
  no real PostgreSQL, no real LLM.
- The log check scans the configured log output and every record (message and args) of
  the refused approval for the tool arguments, the messages, the emails and the
  password.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from pydantic import BaseModel, Field

from admino import access, org_permissions, scoped_settings, server
from admino import main as main_module
from admino.access import Capability
from admino.agent import Agent
from admino.chat_runtime import ChatRuntime
from admino.llm import LLMResponse
from admino.models import AgentConfig, AgentResult, LLMMessage, PendingConfirmation, ToolCall
from admino.server import create_app
from admino.tools import registry
from tests.db_fakes import FakeDb, fake_hash
from tests.log_capture import configured_logging
from tests.tenancy_world import (
    CLIENT_IP,
    FORBIDDEN,
    PASSWORD,
    UNAUTHORIZED,
    Account,
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
    from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
    from pathlib import Path

    from fastapi import FastAPI

    from tests.log_capture import CapturedLogs
    from tests.tenancy_world import World

_WAIT_S: Final = 5.0
_CRITICAL: Final = "/api/org/critical-permissions"
_COOLDOWN: Final = timedelta(minutes=5)
_CONFIRMATION_ID: Final = "confirm-298-osprey"
_OTHER_ID: Final = "confirm-298-other"
_STORE_MESSAGE: Final = "Note the osprey nest count for Monday 298"
_ARG_KEY: Final = "osprey-count-298"
_ARG_VALUE: Final = "merlin-canary-298-nests"
_FINAL_REPLY: Final = "Stored the osprey count 298."
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
_SEEDED: Final = (("user", "Earlier question about terns"), ("assistant", "Earlier answer."))
_NOTICE_MARKER: Final = "PERMISSION UPDATE"
_COLLEAGUE_EMAIL: Final = "org-a-colleague-editor-298@example.ch"
_APPROVING_ADMIN_EMAIL: Final = "org-a-approving-admin-298@example.ch"
_TOOL_CALL_RUN: Final = {
    "tool": "memory",
    "action": "store",
    "decision": "confirm",
    "success": True,
    "escalated": False,
}
# The rate-limit key of the per-IP budget of cookies that resolve to no session.
_UNRESOLVED_COOKIE_BUDGET: Final = (server._SESSION_FAILURE_ROUTE, f"ip:{CLIENT_IP}")


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
    """Answers every call with ``_FINAL_REPLY``."""

    provider = "infomaniak"

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        return LLMResponse(content=_FINAL_REPLY)

    async def close(self) -> None:
        """Nothing to close."""


class _RecordingAgent(Agent):
    """The real Agent; records (user id, kind, org id) of the principal of every run."""

    def __init__(self, llm: _FinalLLM) -> None:
        # The fake answers ``chat`` only: an approval that runs here is JSON.
        client: Any = llm
        super().__init__(
            llm_client=client,
            tool_call_recorder=main_module._build_tool_call_recorder(),
            agent_config=AgentConfig(
                max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=300.0
            ),
        )
        self.principals: list[tuple[uuid.UUID, str, uuid.UUID | None]] = []

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        principal = kwargs["principal"]
        self.principals.append((principal.user_id, principal.kind, principal.org_id))
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
    stores memory.store at 'confirm'."""
    db = FakeDb()
    built = build_world(db)
    db.add_permissions(built.org_a, {"memory": {"store": "confirm"}})
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    use_attachment_storage(monkeypatch, built, tmp_path / "attachments")
    return built


@pytest.fixture()
def colleague(world: World) -> Account:
    """A second active Editor of org A, with a live session."""
    user_id = world.db.add_account(
        role="editor",
        org_id=world.org_a,
        email=_COLLEAGUE_EMAIL,
        password_hash=fake_hash(PASSWORD),
    )
    return Account(
        user_id=user_id,
        org_id=world.org_a,
        role="editor",
        email=_COLLEAGUE_EMAIL,
        token=world.db.open_session(user_id),
    )


def _second_org_admin(world: World) -> Account:
    """A second active Org Admin of org A, with a live session (org A's Org Admin can
    demote it without hitting the last-admin guard)."""
    user_id = world.db.add_account(
        role="org_admin",
        org_id=world.org_a,
        email=_APPROVING_ADMIN_EMAIL,
        password_hash=fake_hash(PASSWORD),
    )
    return Account(
        user_id=user_id,
        org_id=world.org_a,
        role="org_admin",
        email=_APPROVING_ADMIN_EMAIL,
        token=world.db.open_session(user_id),
    )


def _chat_send_only_for(monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    """Leave ``chat.send`` to ``role`` alone for this test (#306, Decision 8): both
    member roles have it, so a role change that loses it needs it withdrawn from the
    other role."""
    monkeypatch.setattr(
        access,
        "_MATRIX",
        MappingProxyType({**access._MATRIX, Capability.CHAT_SEND: frozenset({role})}),
    )


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
def agent() -> _RecordingAgent:
    return _RecordingAgent(_FinalLLM())


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
# The changes made while the approval waits (through the API)
# ---------------------------------------------------------------------------

# A change made through the API while the approval waits: (client, world, target).
type _Change = Callable[[httpx.AsyncClient, World, Account], Awaitable[None]]


def _org_admin_of(world: World, target: Account) -> Account:
    """The Org Admin of the target's org."""
    return world.a["org_admin"] if target.org_id == world.org_a else world.b["org_admin"]


def _succeeded(response: httpx.Response) -> None:
    """The change request must succeed (the change is the test's precondition)."""
    assert response.is_success, response.text


async def _deactivate(http: httpx.AsyncClient, world: World, target: Account) -> None:
    """The target's Org Admin deactivates the target (``POST .../deactivate``)."""
    admin = _org_admin_of(world, target)
    _succeeded(await http.post(f"/api/org/users/{target.user_id}/deactivate", headers=admin.cookie))


async def _remove(http: httpx.AsyncClient, world: World, target: Account) -> None:
    """The target's Org Admin removes the target from the org (``DELETE``)."""
    admin = _org_admin_of(world, target)
    _succeeded(await http.delete(f"/api/org/users/{target.user_id}", headers=admin.cookie))


async def _set_role(http: httpx.AsyncClient, world: World, target: Account, role: str) -> None:
    """The target's Org Admin gives the target ``role`` (``PATCH /api/org/users/{id}``)."""
    admin = _org_admin_of(world, target)
    _succeeded(
        await http.patch(
            f"/api/org/users/{target.user_id}", headers=admin.cookie, json={"role": role}
        )
    )


async def _demote(http: httpx.AsyncClient, world: World, target: Account) -> None:
    """The target's Org Admin makes the target (an Org Admin) an Editor (``PATCH``)."""
    await _set_role(http, world, target, "editor")


async def _promote_to_admin(http: httpx.AsyncClient, world: World, target: Account) -> None:
    """The target's Org Admin makes the target an Org Admin (``PATCH``)."""
    await _set_role(http, world, target, "org_admin")


async def _deactivate_org(http: httpx.AsyncClient, world: World, target: Account) -> None:
    """The Super Admin deactivates the target's org."""
    _succeeded(
        await http.post(
            f"/api/platform/orgs/{target.org_id}/deactivate", headers=world.super_admin.cookie
        )
    )


async def _schedule_org_deletion(http: httpx.AsyncClient, world: World, target: Account) -> None:
    """The Super Admin schedules the target's org for deletion."""
    _succeeded(
        await http.post(
            f"/api/platform/orgs/{target.org_id}/deletion", headers=world.super_admin.cookie
        )
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the test's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50298))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


def _awaiting_chat(
    db: FakeDb, runtime: ChatRuntime, account: Account
) -> tuple[uuid.UUID, PendingConfirmation]:
    """A user-titled chat of ``account`` whose request awaits ``_STORE_CALL``'s
    confirmation: its rows stored, the live (5 minutes) confirmation pending in
    ``runtime``."""
    chat_id = db.add_chat(account.user_id, title="Osprey notes 298", title_source="user")
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
    return chat_id, pending


async def _confirm(
    http: httpx.AsyncClient,
    account: Account,
    chat_id: uuid.UUID,
    *,
    approved: bool = True,
    path_id: str = _CONFIRMATION_ID,
    body_id: str = _CONFIRMATION_ID,
    streamed: bool = False,
) -> httpx.Response:
    body = {"confirmation_id": body_id, "approved": approved, "chat_id": str(chat_id)}
    headers = {**account.cookie, **({"Accept": "text/event-stream"} if streamed else {})}
    return await http.post(f"/api/confirm/{path_id}", headers=headers, json=body)


async def _until(condition: Callable[[], bool]) -> None:
    """Yield to the event loop until ``condition()`` holds (at most ``_WAIT_S``)."""

    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(poll(), _WAIT_S)


async def _behind_a_holder(
    runtime: _WatchedRuntime,
    account: Account,
    chat_id: uuid.UUID,
    *,
    send: Callable[[], Coroutine[Any, Any, httpx.Response]],
    meanwhile: Callable[[], Awaitable[None]],
) -> httpx.Response:
    """A holder task holds the chat; the confirm (``send``) is started and waits for the
    hold (its ``hold()`` call is counted); ``meanwhile`` runs; the holder lets go; the
    confirm's response."""
    inside, release = asyncio.Event(), asyncio.Event()

    async def holder() -> None:
        async with runtime.hold(chat_id, account.user_id):
            inside.set()
            await asyncio.wait_for(release.wait(), _WAIT_S)

    held = asyncio.create_task(holder())
    try:
        await asyncio.wait_for(inside.wait(), _WAIT_S)
        holds = runtime.holds
        confirm = asyncio.create_task(send())
        await _until(lambda: runtime.holds > holds)
        assert runtime.inside == 1, "the holder alone is inside the hold while the confirm waits"
        await meanwhile()
    finally:
        release.set()
        await asyncio.wait_for(held, _WAIT_S)
    return await asyncio.wait_for(confirm, _WAIT_S)


def _spy_reads(monkeypatch: pytest.MonkeyPatch, reads: list[str]) -> None:
    """Record into ``reads`` every platform settings read, due promotion completion and
    tool policy load, by name, in order."""
    spied = (
        (scoped_settings, "current_platform_settings"),
        (scoped_settings, "load_platform_settings"),
        (org_permissions, "resolve_due_promotions"),
        (org_permissions, "load_tool_policy"),
    )
    for module, name in spied:
        real = getattr(module, name)

        async def spy(*args: Any, _name: str = name, _real: Any = real, **kwargs: Any) -> Any:
            reads.append(_name)
            return await _real(*args, **kwargs)

        monkeypatch.setattr(module, name, spy)


async def _promote_gmail_send(http: httpx.AsyncClient, clock: _Clock, admin: Account) -> None:
    """The Org Admin promotes gmail.send (with their password) at t0; the clock then
    stands past the cooldown, so the promotion is due."""
    clock.at()
    response = await http.patch(
        f"{_CRITICAL}/gmail/send", headers=admin.cookie, json={"password": PASSWORD}
    )
    assert response.status_code == 200, response.text
    clock.at(_COOLDOWN)


def _notices(db: FakeDb, chat_id: uuid.UUID) -> list[str]:
    """The promotion notices stored in the chat."""
    return [
        str(m["content"])
        for m in db.messages_of(chat_id)
        if m["role"] == "user" and _NOTICE_MARKER in str(m["content"])
    ]


def _audited(db: FakeDb) -> list[dict[str, Any]]:
    """The ``tool.call`` audit rows' metadata (without the duration)."""
    return [
        {key: value for key, value in row["metadata"].items() if key != "duration_ms"}
        for row in db.audit_rows("tool.call")
    ]


def _answer(response: httpx.Response) -> tuple[int, Any]:
    """(status, JSON body) of an answer."""
    return response.status_code, response.json()


# ---------------------------------------------------------------------------
# 1. A change of the approving user while the approval waits refuses it (Decisions 1-3)
# ---------------------------------------------------------------------------

# The role change losing chat.send: the approver is a second Org Admin of org A, made an
# Editor while only Org Admins have chat.send.
_DEMOTED: Final = "demoted-to-editor"


def _approver(world: World, monkeypatch: pytest.MonkeyPatch, change: str) -> Account:
    """The approving member: org A's Editor; for ``_DEMOTED`` a second Org Admin of org A,
    with ``chat.send`` left to Org Admins (so the demotion to Editor loses it)."""
    if change != _DEMOTED:
        return world.a["editor"]
    _chat_send_only_for(monkeypatch, "org_admin")
    return _second_org_admin(world)


_REFUSING: Final[dict[str, tuple[_Change, tuple[int, dict[str, str]]]]] = {
    "deactivated": (_deactivate, (401, UNAUTHORIZED)),
    "removed": (_remove, (401, UNAUTHORIZED)),
    _DEMOTED: (_demote, (403, FORBIDDEN)),
    "org-deactivated": (_deactivate_org, (401, UNAUTHORIZED)),
    "org-deletion-scheduled": (_schedule_org_deletion, (401, UNAUTHORIZED)),
}


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
@pytest.mark.parametrize("change", list(_REFUSING))
async def test_confirm_account_lock_wait_change_during_the_wait_refuses_like_a_later_request(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
    agent: _RecordingAgent,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    approved: bool,
) -> None:
    """The approving Editor is deactivated or removed from the org, the approving Org
    Admin is made an Editor (``chat.send`` left to Org Admins), or the approver's org is
    deactivated or scheduled for deletion while the approval (or denial) waits for the
    hold: it answers exactly what the same confirm sent after the change with the same
    cookie answers (401 or 403). Nothing of it runs or is stored: no agent run, no
    handler call, no ``tool.call`` row, the chat's messages as they were, org A's due
    promotion of gmail.send not completed (no notice in the Org Admin's chat), no
    platform settings, promotion or policy read after the change, and the pending
    confirmation left as it is (a removed user's is dropped with the account)."""
    db = world.db
    approver, admin = _approver(world, monkeypatch, change), world.a["org_admin"]
    chat_id, pending = _awaiting_chat(db, runtime, approver)
    sibling = seed_chat(db, admin, messages=_SEEDED)
    stored = db.messages_of(chat_id)
    make_change, expected = _REFUSING[change]
    reads: list[str] = []

    async with _async_client(app) as http:
        await _promote_gmail_send(http, clock, admin)

        async def meanwhile() -> None:
            await make_change(http, world, approver)
            _spy_reads(monkeypatch, reads)

        refused = await _behind_a_holder(
            runtime,
            approver,
            chat_id,
            send=lambda: _confirm(http, approver, chat_id, approved=approved),
            meanwhile=meanwhile,
        )
        left = (list(reads), runtime.get_pending(chat_id), db.messages_of(chat_id))
        later = await asyncio.wait_for(
            _confirm(http, approver, chat_id, approved=approved), _WAIT_S
        )

    removed = change == "removed"
    assert (_answer(refused), _answer(later)) == (expected, expected)
    assert (handler.calls, agent.principals, _audited(db), left) == (
        [],
        [],
        [],
        ([], None if removed else pending, [] if removed else stored),
    )
    assert (db.org_permissions(world.org_a)["gmail"]["send"], _notices(db, sibling)) == (
        "deny",
        [],
    )


# ---------------------------------------------------------------------------
# 2. The re-check comes before the confirmation checks (Decision 1)
# ---------------------------------------------------------------------------

_ORDER_CHANGES: Final[dict[str, tuple[_Change, tuple[int, dict[str, str]]]]] = {
    "deactivated": (_deactivate, (401, UNAUTHORIZED)),
    _DEMOTED: (_demote, (403, FORBIDDEN)),
}
_CHECKS: Final = ["none-pending", "wrong-id", "expired", "body-mismatch"]


@pytest.mark.parametrize("check", _CHECKS)
@pytest.mark.parametrize("change", list(_ORDER_CHANGES))
async def test_confirm_account_lock_wait_recheck_comes_before_the_confirmation_checks(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    check: str,
) -> None:
    """A deactivated Editor (or an Org Admin made an Editor while only Org Admins have
    ``chat.send``) whose waiting approval would have failed a confirmation check under
    the hold (nothing pending any more, another id, expired while it waited, the body's
    id differs: 404 or 400) gets the 401 (403) instead, as the same confirm sent after
    the change does."""
    db = world.db
    approver = _approver(world, monkeypatch, change)
    chat_id, pending = _awaiting_chat(db, runtime, approver)
    make_change, expected = _ORDER_CHANGES[change]
    path_id = body_id = _CONFIRMATION_ID
    if check == "wrong-id":
        path_id = body_id = _OTHER_ID
    elif check == "body-mismatch":
        body_id = _OTHER_ID

    async with _async_client(app) as http:

        async def send() -> httpx.Response:
            return await _confirm(http, approver, chat_id, path_id=path_id, body_id=body_id)

        async def meanwhile() -> None:
            await make_change(http, world, approver)
            if check == "none-pending":
                runtime.pop_pending(chat_id)
            elif check == "expired":
                monkeypatch.setattr(server, "_utc_now", lambda: pending.expires_at)

        refused = await _behind_a_holder(runtime, approver, chat_id, send=send, meanwhile=meanwhile)
        later = await asyncio.wait_for(send(), _WAIT_S)

    assert (_answer(refused), _answer(later), handler.calls) == (expected, expected, [])


# ---------------------------------------------------------------------------
# 3. Account rows the API can't produce (Decision 1: the account rules)
# ---------------------------------------------------------------------------


def _moved_to_org_b(world: World, row: dict[str, Any]) -> None:
    row["org_id"] = world.org_b


def _now_a_super_admin(world: World, row: dict[str, Any]) -> None:
    row.update(kind="super_admin", org_id=None, role=None)


def _malformed_role(world: World, row: dict[str, Any]) -> None:
    row["role"] = "owner"


def _soft_deleted(world: World, row: dict[str, Any]) -> None:
    row["deleted_at"] = datetime.now(UTC)


_ROW_CHANGES: Final[dict[str, Callable[[World, dict[str, Any]], None]]] = {
    "moved-to-another-org": _moved_to_org_b,
    "kind-super-admin": _now_a_super_admin,
    "malformed-role": _malformed_role,
    "deleted-at-set": _soft_deleted,
}


@pytest.mark.parametrize("row_change", list(_ROW_CHANGES))
async def test_confirm_account_lock_wait_account_row_failing_the_rules_is_unauthorized(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
    agent: _RecordingAgent,
    row_change: str,
) -> None:
    """While the approval waits, the approving Editor's users row stops forming the
    request's principal: it names org B, it became a Super Admin row, its role is no
    member role, or it is marked deleted (status still ``active``). The approval
    answers 401 ``Unauthorized``, runs nothing, records no ``tool.call`` row and leaves
    the pending confirmation as it is."""
    db = world.db
    editor = world.a["editor"]
    chat_id, pending = _awaiting_chat(db, runtime, editor)

    async with _async_client(app) as http:

        async def meanwhile() -> None:
            _ROW_CHANGES[row_change](world, db.users[editor.user_id])

        refused = await _behind_a_holder(
            runtime,
            editor,
            chat_id,
            send=lambda: _confirm(http, editor, chat_id),
            meanwhile=meanwhile,
        )

    assert (_answer(refused), handler.calls, agent.principals, _audited(db)) == (
        (401, UNAUTHORIZED),
        [],
        [],
        [],
    )
    assert runtime.get_pending(chat_id) == pending


# ---------------------------------------------------------------------------
# 4. Streamed confirms, the cookie budget and the logs (Decisions 2 and 3)
# ---------------------------------------------------------------------------


async def test_confirm_account_lock_wait_streamed_refusal_is_the_json_error(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
) -> None:
    """A streamed approval (``Accept: text/event-stream``) whose Editor is deactivated
    while it waits answers the JSON 401, as the same streamed confirm sent after the
    change does; nothing ran."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)

    async with _async_client(app) as http:

        async def send() -> httpx.Response:
            return await _confirm(http, editor, chat_id, streamed=True)

        async def meanwhile() -> None:
            await _deactivate(http, world, editor)

        refused = await _behind_a_holder(runtime, editor, chat_id, send=send, meanwhile=meanwhile)
        later = await asyncio.wait_for(send(), _WAIT_S)

    kinds = [r.headers.get("content-type") for r in (refused, later)]
    assert ([r.status_code for r in (refused, later)], kinds) == (
        [401, 401],
        ["application/json", "application/json"],
    ), refused.text
    assert ([r.json() for r in (refused, later)], handler.calls) == (
        [UNAUTHORIZED, UNAUTHORIZED],
        [],
    )


async def test_confirm_account_lock_wait_refusal_spends_no_unresolved_cookie_budget(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
) -> None:
    """The approval refused because its Editor was deactivated during the wait spends
    nothing of the client IP's budget of unresolved session cookies (its cookie
    resolved when it arrived); the same confirm sent after the change, whose cookie no
    longer resolves, does spend it."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)

    async with _async_client(app) as http:

        async def meanwhile() -> None:
            await _deactivate(http, world, editor)

        refused = await _behind_a_holder(
            runtime,
            editor,
            chat_id,
            send=lambda: _confirm(http, editor, chat_id),
            meanwhile=meanwhile,
        )
        spent_by_refusal = _UNRESOLVED_COOKIE_BUDGET in server._rate_buckets
        later = await asyncio.wait_for(_confirm(http, editor, chat_id), _WAIT_S)
        spent_later = _UNRESOLVED_COOKIE_BUDGET in server._rate_buckets

    assert (_answer(refused), _answer(later), spent_by_refusal, spent_later) == (
        (401, UNAUTHORIZED),
        (401, UNAUTHORIZED),
        False,
        True,
    )


async def test_confirm_account_lock_wait_refused_approval_logs_no_content(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
) -> None:
    """The approval refused because its Editor was deactivated during the wait, logged
    the way main() configures it at DEBUG, names neither a tool argument, the chat's
    message, the reply, an email nor the password, in the output or in any record's
    message or args. Positive control: the request's content-free timing line
    (``route=confirm status=401``) is in the output, and a record carrying a probe is
    found by the same scan."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)
    probes = [
        _STORE_MESSAGE,
        _ARG_KEY,
        _ARG_VALUE,
        _FINAL_REPLY,
        PASSWORD,
        *(account.email for account in world.everyone()),
    ]

    def leaks(captured: CapturedLogs) -> list[tuple[str, str]]:
        text = captured.text.casefold()
        records = [
            f"{record.getMessage()}\n{record.msg}\n{record.args!r}".casefold()
            for record in captured.records
        ]
        found = [("text", p) for p in probes if p.casefold() in text]
        return found + [
            ("record", p) for p in probes if any(p.casefold() in record for record in records)
        ]

    with configured_logging("DEBUG", "text") as captured:
        async with _async_client(app) as http:

            async def meanwhile() -> None:
                await _deactivate(http, world, editor)

            refused = await _behind_a_holder(
                runtime,
                editor,
                chat_id,
                send=lambda: _confirm(http, editor, chat_id),
                meanwhile=meanwhile,
            )
        found = leaks(captured)
        timing_line = "route=confirm status=401" in captured.text
        logging.getLogger("admino.server").debug("Leak-scan control %s", _ARG_VALUE)
        control = leaks(captured)

    assert (_answer(refused), handler.calls, timing_line) == ((401, UNAUTHORIZED), [], True)
    assert (found, control) == ([], [("text", _ARG_VALUE), ("record", _ARG_VALUE)])


# ---------------------------------------------------------------------------
# 5. What goes on (Decision 4): only the approving user's own change counts
# ---------------------------------------------------------------------------


_KEEPING: Final[dict[str, tuple[_Change, str] | None]] = {
    "unchanged": None,
    "promoted-to-org-admin": (_promote_to_admin, "approver"),
    "colleague-deactivated": (_deactivate, "colleague"),
    "colleague-removed": (_remove, "colleague"),
    "colleague-loses-chat-send": (_promote_to_admin, "colleague"),
    "org-b-editor-deactivated": (_deactivate, "org-b-editor"),
    "org-b-editor-loses-chat-send": (_promote_to_admin, "org-b-editor"),
    "org-b-deactivated": (_deactivate_org, "org-b-editor"),
}
# The cases whose member is made an Org Admin while only Editors have chat.send, so that
# member loses it (the approving Editor keeps it).
_LOSING_CHAT_SEND: Final = frozenset({"colleague-loses-chat-send", "org-b-editor-loses-chat-send"})


@pytest.mark.parametrize("case", list(_KEEPING))
async def test_confirm_account_lock_wait_approval_runs_when_the_approver_still_passes(
    world: World,
    colleague: Account,
    app: FastAPI,
    runtime: _WatchedRuntime,
    handler: _Handler,
    agent: _RecordingAgent,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    """Nothing changes, the approving Editor is promoted to Org Admin (keeps
    ``chat.send``), another Editor of org A is deactivated, removed or made an Org Admin
    while only Editors have ``chat.send`` (so it loses it), or org B's Editor (likewise)
    or org B itself changes while the approval waits: the approval runs. It answers 200
    final, the handler ran once with the approved arguments, one ``tool.call`` row
    records the confirmed call, and the run got the request's principal (the approver's
    user id, kind and org)."""
    if case in _LOSING_CHAT_SEND:
        _chat_send_only_for(monkeypatch, "editor")
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)
    targets = {"approver": editor, "colleague": colleague, "org-b-editor": world.b["editor"]}
    keeping = _KEEPING[case]

    async with _async_client(app) as http:

        async def meanwhile() -> None:
            if keeping is None:
                await asyncio.sleep(0)
            else:
                make_change, target = keeping
                await make_change(http, world, targets[target])

        response = await _behind_a_holder(
            runtime,
            editor,
            chat_id,
            send=lambda: _confirm(http, editor, chat_id),
            meanwhile=meanwhile,
        )

    assert (response.status_code, response.json().get("status")) == (200, "final"), response.text
    assert (handler.calls, _audited(db), agent.principals) == (
        [(_ARG_KEY, _ARG_VALUE)],
        [_TOOL_CALL_RUN],
        [(editor.user_id, "member", world.org_a)],
    )
