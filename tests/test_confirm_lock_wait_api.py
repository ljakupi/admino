"""``POST /api/confirm/{id}`` after waiting for the chat's hold: the platform settings are
read under the hold, and a chat trashed meanwhile leaves nothing pending (GH-294, issue
Decisions 6 and 7; GH-189 audit S1 and review note 5).

An approval waits for a run of its chat that is going (``ChatRuntime.hold``): that
run may store the very confirmation it approves. Decision 6: the route reads the
stored platform settings once, under the chat's hold, after the confirmation checks
(a 404 or 400 reads nothing more), so the approved run gets the ``image_input``,
limits, retry limit and ``max_input_tokens`` stored when it starts; a denial reads
them at the same point. Decision 7: when the chat was trashed while the approval
waited, the answer is the ``404 chat_not_found`` and the pending confirmation is
removed before it (nothing run, stored or audited).

Harness: the app from ``create_app()`` on the FakeDb world of tests/tenancy_world.py
(orgs A and B with an Org Admin and an Editor each, a Super Admin, real session
cookies), the attachments root under ``tmp_path``, a stub agent bound to
``Agent.run``'s signature (it records every call: the ``agent_config``, the slot and
the pending confirmation) and a ``ChatRuntime`` subclass that records each
``hold()`` call when it is made and how many callers are inside a hold. Requests run
in the test's event loop through one ``httpx.AsyncClient``: the chat's hold is held
by a running turn (its stub run parks) or by a holder task, the approval is started
and queued, the platform settings are changed through ``PATCH
/api/platform/settings`` as the Super Admin (which refreshes the settings cache) or
the chat is trashed (``chats.trash_chat``, the transaction the DELETE route runs
before its own pop of the pending confirmation), and the hold is then released.
Every wait is bounded.

Security notes:
- Every id, name and message here is a fixed fake value; no network, no real
  PostgreSQL, no real LLM.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest

from admino import chats, context_budget, organizations, scoped_settings, server
from admino.chat_runtime import ChatRuntime
from admino.models import AgentConfig, AgentResult, LLMMessage, PendingConfirmation, ToolCall
from admino.server import create_app
from admino.tenancy import TenantContext
from tests.attachment_derived import png_bytes, write_derived
from tests.conftest import default_test_platform_settings
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    CHAT_NOT_FOUND,
    CLIENT_IP,
    build_world,
    make_config,
    stub_agent,
    use_attachment_storage,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Sequence

    from fastapi import FastAPI

    from tests.tenancy_world import Account, World

_WAIT_S: Final = 5.0
_REPLY: Final = "Booked it, 294."
_BOOK: Final = "Book the heron offsite for Friday 294"
_CONFIRMATION_ID: Final = "confirm-294-heron"
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
_PHOTO_NAME: Final = "heron-photo-294.png"
_IMAGE_UNSUPPORTED: Final = {
    "detail": "The current model does not accept image input",
    "reason": "image_input_unsupported",
}
_NO_PENDING: Final = {"detail": "No pending confirmation for this session"}
_NOT_FOUND: Final = {"detail": "Confirmation not found"}
_MISMATCH: Final = {"detail": "Confirmation ID mismatch"}
# The default platform: max_input_tokens 200000, max_retries 2, the LimitsConfig
# defaults (10 tool calls, 300 s, 20 messages). A patch made during the wait sets these.
_CHANGED: Final = {
    "llm": {"max_input_tokens": 64000, "max_retries": 4},
    "limits": {
        "max_tool_calls_per_message": 7,
        "confirmation_timeout_s": 120,
        "max_context_messages": 5,
    },
}


# ---------------------------------------------------------------------------
# The stub agent
# ---------------------------------------------------------------------------


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
    stream: Any = None,
    attachments: Sequence[Any] = (),
) -> None:
    """``Agent.run``'s signature; every stub call binds to it."""


def _pending(chat_id: uuid.UUID, *, expires_in: timedelta = timedelta(minutes=5)) -> Any:
    """The google_calendar.create confirmation ``_CONFIRMATION_ID`` of the chat."""
    now = datetime.now(UTC)
    return PendingConfirmation(
        confirmation_id=_CONFIRMATION_ID,
        session_id=str(chat_id),
        tool_call=_BOOK_CALL,
        created_at=now,
        expires_at=now + expires_in,
    )


class _Script:
    """The stub agent's ``run``: records each call. A resumed confirmation answers the
    approved call's tool result plus ``_REPLY``; a turn asks for ``_BOOK_CALL`` (after
    ``during``, a one-shot hook, returns) and ends awaiting its confirmation."""

    def __init__(self) -> None:
        self.runs: list[dict[str, Any]] = []
        self.during: Callable[[], Awaitable[None]] | None = None

    async def run(self, *args: Any, **kwargs: Any) -> AgentResult:
        bound = inspect.signature(_run_signature).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = dict(bound.arguments)
        self.runs.append(arguments)
        history: list[LLMMessage] = kwargs["history"]
        pending = arguments["pending_confirmation"]
        if pending is not None:
            new = [
                LLMMessage(
                    role="tool", content="Created 294.", tool_call_id=pending.tool_call.tool_call_id
                ),
                LLMMessage(role="assistant", content=_REPLY),
            ]
            return AgentResult(
                status="final",
                response=_REPLY,
                history=[*history, *new],
                tool_calls=[],
                pending_confirmation=None,
            )
        during, self.during = self.during, None
        if during is not None:
            await during()
        new = [
            LLMMessage(role="user", content=arguments["user_message"]),
            LLMMessage(role="assistant", content="", tool_use_blocks=[_BOOK_BLOCK]),
        ]
        return AgentResult(
            status="awaiting_confirmation",
            response="",
            history=[*history, *new],
            tool_calls=[],
            pending_confirmation=_pending(uuid.UUID(arguments["session_id"])),
        )


# ---------------------------------------------------------------------------
# The watched runtime
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
def script() -> _Script:
    return _Script()


@pytest.fixture()
def app(world: World, script: _Script) -> FastAPI:
    agent = stub_agent()
    agent.run.side_effect = script.run
    return create_app(agent=agent, config=make_config())


@pytest.fixture()
def runtime(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> _WatchedRuntime:
    """The watched runtime as ``server._chat_runtime`` (after create_app, which clears it)."""
    watched = _WatchedRuntime()
    monkeypatch.setattr(server, "_chat_runtime", watched)
    return watched


def _async_client(app: FastAPI) -> httpx.AsyncClient:
    """A client running the app in the test's event loop (concurrent requests)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(CLIENT_IP, 50295))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


def _editor_tenant(account: Account) -> TenantContext:
    """The org scope of an Editor account."""
    assert account.org_id is not None
    assert account.role == "editor"
    return TenantContext(org_id=account.org_id, user_id=account.user_id, role="editor")


def _chat(db: FakeDb, account: Account) -> uuid.UUID:
    """A user-titled chat of ``account`` (no title step runs after a turn)."""
    return db.add_chat(account.user_id, title="Approvals 294", title_source="user")


def _photo(db: FakeDb, chat_id: uuid.UUID, message_id: uuid.UUID) -> uuid.UUID:
    """A ready png attachment sent with ``message_id``, with its derived image part."""
    attachment_id = db.add_attachment(
        chat_id,
        filename=_PHOTO_NAME,
        kind="png",
        status="ready",
        token_estimate=85,
        derived_bytes=len(png_bytes()),
        message_id=message_id,
        created_at=datetime(2026, 10, 1, 9, 0, tzinfo=UTC),
    )
    chat = db.chat_row(chat_id)
    assert chat is not None
    write_derived(
        Path(organizations.ATTACHMENTS_ROOT),
        plain(chat["org_id"]),
        attachment_id,
        kind="png",
        parts=(("image", png_bytes(), "image/png", None, None),),
    )
    return attachment_id


def _awaiting_chat(
    db: FakeDb, runtime: ChatRuntime, account: Account, *, with_photo: bool = False
) -> tuple[uuid.UUID, PendingConfirmation]:
    """A chat whose request (with a photo when asked) awaits ``_BOOK_CALL``'s
    confirmation, held in ``runtime``."""
    chat_id = _chat(db, account)
    request = db.add_chat_message(chat_id, "user", _BOOK)
    db.add_chat_message(
        chat_id, "assistant", "", tool_use_blocks=[_BOOK_BLOCK], status="awaiting_confirmation"
    )
    if with_photo:
        _photo(db, chat_id, request)
    pending = _pending(chat_id)
    runtime.set_pending(chat_id, account.user_id, pending)
    return chat_id, pending


def _image_input_off(db: FakeDb, monkeypatch: pytest.MonkeyPatch) -> None:
    """The stored platform ``llm.image_input`` false: in the row and the settings cache."""
    stored = default_test_platform_settings()
    llm = stored.llm.model_copy(update={"image_input": False})
    monkeypatch.setattr(scoped_settings, "_platform_cache", stored.model_copy(update={"llm": llm}))
    row = db.platform_row()
    assert row is not None
    row["image_input"] = False


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


async def _patch_platform(http: httpx.AsyncClient, world: World, body: Any) -> None:
    """PATCH /api/platform/settings as the Super Admin (must succeed)."""
    response = await http.patch(
        "/api/platform/settings", headers=world.super_admin.cookie, json=body
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
    """A holder task holds the chat; the confirm is started and waits for the hold;
    ``meanwhile`` runs; the holder lets go; the confirm's response."""
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
        await meanwhile()
    finally:
        release.set()
        await asyncio.wait_for(held, _WAIT_S)
    return await asyncio.wait_for(confirm, _WAIT_S)


def _spy_settings_reads(monkeypatch: pytest.MonkeyPatch, runtime: _WatchedRuntime) -> list[int]:
    """Record, for every platform settings read (``current_platform_settings`` or
    ``load_platform_settings``), how many callers were inside a hold of the runtime."""
    reads: list[int] = []
    for name in ("current_platform_settings", "load_platform_settings"):
        real = getattr(scoped_settings, name)

        async def spy(*args: Any, _real: Any = real, **kwargs: Any) -> Any:
            reads.append(runtime.inside)
            return await _real(*args, **kwargs)

        monkeypatch.setattr(scoped_settings, name, spy)
    return reads


def _config_of(run: dict[str, Any]) -> dict[str, Any]:
    config: AgentConfig = run["agent_config"]
    return {
        "max_input_tokens": config.max_input_tokens,
        "llm_max_retries": config.llm_max_retries,
        "max_tool_calls": config.max_tool_calls,
        "confirmation_timeout_s": config.confirmation_timeout_s,
        "max_context_messages": config.max_context_messages,
        "image_input": config.image_input,
    }


# ---------------------------------------------------------------------------
# 1. Settings read under the hold (Decision 6)
# ---------------------------------------------------------------------------


async def test_confirm_lock_wait_image_input_turned_off_behind_a_running_turn_is_422(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    script: _Script,
) -> None:
    """A turn of a chat with a sent photo runs (image input on) and will store the
    confirmation; its approval is queued behind it; image input is turned off meanwhile.
    The approval is the 422 ``image_input_unsupported``: the resumed run never starts,
    nothing more is stored and the confirmation stays pending."""
    db = world.db
    editor = world.a["editor"]
    chat_id = _chat(db, editor)
    earlier = db.add_chat_message(chat_id, "user", "Here is the photo 294")
    db.add_chat_message(chat_id, "assistant", "Nice photo.")
    _photo(db, chat_id, earlier)
    parked, release = asyncio.Event(), asyncio.Event()

    async def park() -> None:
        parked.set()
        await asyncio.wait_for(release.wait(), _WAIT_S)

    script.during = park
    async with _async_client(app) as http:
        turn = asyncio.create_task(
            http.post(
                f"/api/chats/{chat_id}/messages", headers=editor.cookie, json={"message": _BOOK}
            )
        )
        try:
            await asyncio.wait_for(parked.wait(), _WAIT_S)
            holds = runtime.holds
            confirm = asyncio.create_task(_confirm(http, editor, chat_id, approved=True))
            await _until(lambda: runtime.holds > holds)
            await _patch_platform(http, world, {"llm": {"image_input": False}})
        finally:
            release.set()
        asked = await asyncio.wait_for(turn, _WAIT_S)
        assert (asked.status_code, asked.json()["status"]) == (200, "awaiting_confirmation")
        stored = db.messages_of(chat_id)
        response = await asyncio.wait_for(confirm, _WAIT_S)

    assert (response.status_code, response.json()) == (422, _IMAGE_UNSUPPORTED)
    pending = runtime.get_pending(chat_id)
    assert (len(script.runs), pending is not None and pending.confirmation_id) == (
        1,
        _CONFIRMATION_ID,
    )
    assert db.messages_of(chat_id) == stored


async def test_confirm_lock_wait_image_input_turned_on_during_the_wait_runs_with_the_image(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Image input is off and the chat's request sent a photo; the approval waits for the
    hold; image input is turned on meanwhile. The approval resumes (200, final) with
    ``agent_config.image_input`` true and the photo's image part in its slot."""
    db = world.db
    editor = world.a["editor"]
    _image_input_off(db, monkeypatch)
    chat_id, _ = _awaiting_chat(db, runtime, editor, with_photo=True)

    async with _async_client(app) as http:

        async def turn_on() -> None:
            await _patch_platform(http, world, {"llm": {"image_input": True}})

        response = await _behind_a_holder(
            http, runtime, editor, chat_id, approved=True, meanwhile=turn_on
        )

    assert (response.status_code, response.json().get("status")) == (200, "final"), response.text
    (run,) = script.runs
    assert run["agent_config"].image_input is True
    assert [[part.type for part in content.parts] for content in run["attachments"]] == [["image"]]


async def test_confirm_lock_wait_approval_gets_the_limits_stored_during_the_wait(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    script: _Script,
) -> None:
    """``max_input_tokens``, the retry limit, the tool-call limit, the confirmation
    timeout and ``max_context_messages`` changed while the approval waited: the resumed
    run's ``agent_config`` carries the new values."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)

    async with _async_client(app) as http:

        async def change() -> None:
            await _patch_platform(http, world, _CHANGED)

        response = await _behind_a_holder(
            http, runtime, editor, chat_id, approved=True, meanwhile=change
        )

    assert (response.status_code, response.json().get("status")) == (200, "final"), response.text
    (run,) = script.runs
    assert _config_of(run) == {
        "max_input_tokens": 64000,
        "llm_max_retries": 4,
        "max_tool_calls": 7,
        "confirmation_timeout_s": 120.0,
        "max_context_messages": 5,
        "image_input": True,
    }


async def test_confirm_lock_wait_denial_usage_has_the_budget_stored_during_the_wait(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    script: _Script,
) -> None:
    """``max_input_tokens`` changed to 64000 while a denial waited: its
    ``context_usage.max`` is that model's budget at the config's 10 % margin (57600)."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)

    async with _async_client(app) as http:

        async def change() -> None:
            await _patch_platform(http, world, {"llm": {"max_input_tokens": 64000}})

        response = await _behind_a_holder(
            http, runtime, editor, chat_id, approved=False, meanwhile=change
        )

    assert response.status_code == 200, response.text
    assert (response.json()["context_usage"]["max"], script.runs) == (
        context_budget.budget_limit(64000, 10),
        [],
    )


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
async def test_confirm_lock_wait_reads_the_settings_once_under_the_hold(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    """An approval and a denial each read the platform settings exactly once, while the
    confirm is inside the chat's hold."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)
    reads = _spy_settings_reads(monkeypatch, runtime)

    async with _async_client(app) as http:
        response = await asyncio.wait_for(
            _confirm(http, editor, chat_id, approved=approved), _WAIT_S
        )

    assert response.status_code == 200, response.text
    assert reads == [1]


@pytest.mark.parametrize(
    "refusal", ["wrong-id", "body-mismatch", "expired", "none-pending"], ids=str
)
async def test_confirm_lock_wait_refused_confirm_reads_no_settings(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    script: _Script,
    monkeypatch: pytest.MonkeyPatch,
    refusal: str,
) -> None:
    """A confirm refused by the checks under the hold (another id: 404; the body's id
    differs: 400; expired while it waited: 404; nothing pending: 404) reads no platform
    settings and runs nothing."""
    db = world.db
    editor = world.a["editor"]
    chat_id, pending = _awaiting_chat(db, runtime, editor)
    path_id = body_id = _CONFIRMATION_ID
    if refusal == "wrong-id":
        path_id = body_id = "confirm-294-other"
        expected = (404, _NOT_FOUND)
    elif refusal == "body-mismatch":
        body_id = "confirm-294-other"
        expected = (400, _MISMATCH)
    elif refusal == "expired":
        # The request's reap is skipped; the expiry check under the hold refuses it.
        monkeypatch.setattr(server, "_reap_expired_confirmations", lambda: None)
        monkeypatch.setattr(server, "_utc_now", lambda: pending.expires_at)
        expected = (404, _NO_PENDING)
    else:
        runtime.pop_pending(chat_id)
        expected = (404, _NO_PENDING)
    reads = _spy_settings_reads(monkeypatch, runtime)

    async with _async_client(app) as http:
        response = await asyncio.wait_for(
            _confirm(http, editor, chat_id, approved=True, path_id=path_id, body_id=body_id),
            _WAIT_S,
        )

    assert ((response.status_code, response.json()), reads, script.runs) == (expected, [], [])


# ---------------------------------------------------------------------------
# 2. A chat trashed during the wait (Decision 7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
async def test_confirm_lock_wait_chat_trashed_during_the_wait_is_404_with_nothing_pending(
    world: World,
    app: FastAPI,
    runtime: _WatchedRuntime,
    script: _Script,
    approved: bool,
) -> None:
    """The chat is trashed while the confirm waits for its hold: the 404
    ``chat_not_found``, the chat's runtime entry holds no pending confirmation right
    after the response (the reaper never ran, the confirmation was live), nothing run,
    and no table changed after the trash (no message, no audit row)."""
    db = world.db
    editor = world.a["editor"]
    chat_id, _ = _awaiting_chat(db, runtime, editor)
    after_trash: dict[str, Any] = {}

    async with _async_client(app) as http:

        async def trash() -> None:
            pool: Any = db.pool
            await chats.trash_chat(pool, _editor_tenant(editor), chat_id, ip=None)
            after_trash.update(db.snapshot())

        response = await _behind_a_holder(
            http, runtime, editor, chat_id, approved=approved, meanwhile=trash
        )

    assert (response.status_code, response.json()) == (404, CHAT_NOT_FOUND)
    assert (runtime.get_pending(chat_id), script.runs) == (None, [])
    assert db.snapshot() == after_trash
