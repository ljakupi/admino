"""HTTP spec of the per-user pending-confirmation limit (GH-24, contract sections 3, 4, 6).

The app from ``create_app()`` runs against the FakeDb world of
tests/tenancy_world.py (orgs A and B with an Org Admin and an Editor each,
real session cookies). The agent is a stub (``_Script``, the pattern of
tests/test_chat_turns_api.py): its ``run`` binds every call to ``Agent.run``'s
signature, records what it got and answers a scripted ``AgentResult`` whose
history is the history it received plus this turn's user message (none on a
confirmation resume) plus the scripted new messages; a run asking for a
confirmation ends with the assistant ``tool_use`` turn and carries a
``PendingConfirmation`` for the chat.

What is pinned (issue #24 criteria 3 and 8, the "rate_limit for the
pending-confirmation limit" decision):
- One user with the stored ``limits.max_pending_confirmations`` (3) pending
  confirmations in other chats: a run that ends asking for another one is HTTP
  200 with ``status: "error"``, ``error_code: "rate_limit"``, no
  ``pending_confirmation``, the reply "Action <tool>.<action> was not run: too
  many confirmations are pending. Approve or deny one of them first." and the
  run's ``tool_calls`` (never a 429). The runtime keeps nothing for that chat,
  whose detail shows ``confirmation_status: "none"``; the first 3 stay.
- What such a turn stores, in one append: the run's new messages, one ``tool``
  row per dangling ``tool_use`` block in block order (the pending call's
  "Tool call denied: too many confirmations are pending.", any other one the
  existing cancelled result), then the reply with status ``error`` and the
  run's tool_calls; the history is well-formed (contract section 6) and the
  next turn gets it unchanged.
- The same on the legacy POST /api/message (session id echoed) and on the
  approved resume of POST /api/confirm; a run replacing its own chat's
  consumed or cancelled confirmation never counts it.
- The limit is the stored platform setting, read per request (raised through
  PATCH /api/platform/settings, lowered in the settings cache).
- Slots are freed by a new message cancelling a pending confirmation, by an
  expired one reaped at the start of the next request (``server._utc_now``
  moved), by a denial, and by a turn whose chat was trashed during the run.
- Other users of the same org and users of org B never count, and are never
  limited by someone else being at the limit.
- ``ChatResponse.error_code`` accepts ``rate_limit``; ``AgentResult`` and
  ``LLM_ERROR_CODES`` don't have it; the OpenAPI schema lists it beside the
  eight LLM codes (GH-25 adds ``malformed_response``).
- Logs name no message content, tool argument or confirmation id.

New names (``server._utc_now``) are used lazily, so the file collects before
GH-24 is implemented.

Security notes:
- Every message, id and argument here is a fixed fake value.
- No network, no real PostgreSQL, no real LLM.
"""

from __future__ import annotations

import inspect
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest
from pydantic import ValidationError

from admino import chats, scoped_settings, server
from admino.models import (
    LLM_ERROR_CODES,
    AgentConfig,
    AgentResult,
    ChatResponse,
    LLMMessage,
    PendingConfirmation,
    ToolCall,
    ToolCallRecord,
)
from tests.conftest import default_test_platform_settings
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    CHAT_NOT_FOUND,
    build_world,
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
    from collections.abc import Awaitable, Callable, Sequence
    from unittest.mock import MagicMock

    import httpx
    from fastapi.testclient import TestClient

    from tests.tenancy_world import Account, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The eight LLM error codes of GH-242 and GH-25 (models.LLMErrorCode), spelled out.
_LLM_CODES: Final = frozenset(
    {
        "not_configured",
        "missing_model",
        "provider_unavailable",
        "rate_limited",
        "timeout",
        "residency_blocked",
        "context_too_long",
        "malformed_response",
    }
)
# The tool result stored for the call whose confirmation was refused (contract section 4).
_PENDING_LIMIT_RESULT: Final = "Tool call denied: too many confirmations are pending."

_STUB_REPLY: Final = "Done."
_MESSAGE: Final = "Please do it"
_PLATFORM_SETTINGS: Final = "/api/platform/settings"

# The confirmation id of a stub reply that asks for no confirmation (never used).
_UNUSED_CONFIRMATION: Final = "confirm-24-unused"

# ---------------------------------------------------------------------------
# Messages and calls
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


def _call(label: str, tool: str = "memory", action: str = "store") -> ToolCall:
    """A tool call with fake arguments and the id ``call-24-<label>``."""
    return ToolCall(
        tool=tool,
        action=action,
        args={"key": f"note-{label}", "value": "ship"},
        tool_call_id=f"call-24-{label}",
    )


def _record(call: ToolCall, permission: str = "confirm", success: bool = False) -> ToolCallRecord:
    """The run's summary of ``call`` (a confirm call that didn't run, by default)."""
    return ToolCallRecord.model_validate(
        {
            "tool": call.tool,
            "action": call.action,
            "args": call.args,
            "permission": permission,
            "success": success,
            "duration_ms": 1,
        }
    )


def _limit_reply(call: ToolCall) -> str:
    """The documented reply of a run whose confirmation was refused (contract section 4)."""
    return (
        f"Action {call.tool}.{call.action} was not run: too many confirmations are pending."
        " Approve or deny one of them first."
    )


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


def _assert_well_formed(messages: Sequence[dict[str, Any] | LLMMessage]) -> None:
    """Contract section 6: every assistant turn with ``n`` tool_use blocks is directly
    followed by exactly ``n`` tool rows answering its blocks in block order, and no
    tool row stands anywhere else; only the very end of a chat whose latest row is
    ``awaiting_confirmation`` may leave blocks unanswered."""
    rows = [
        message.model_dump() if isinstance(message, LLMMessage) else dict(message)
        for message in messages
    ]
    awaiting = bool(rows) and rows[-1].get("status") == "awaiting_confirmation"
    answered: set[int] = set()
    for index, row in enumerate(rows):
        blocks = row.get("tool_use_blocks") or []
        if row["role"] != "assistant" or not blocks:
            continue
        wanted = [("tool", block["id"]) for block in blocks]
        span = rows[index + 1 : index + 1 + len(wanted)]
        got = [(r["role"], r["tool_call_id"]) for r in span]
        open_tail = awaiting and index + 1 + len(got) == len(rows) and got == wanted[: len(got)]
        assert got == wanted or open_tail, f"tool_use at {index} answered by {got}, not {wanted}"
        answered.update(range(index + 1, index + 1 + len(got)))
    strays = [i for i, row in enumerate(rows) if row["role"] == "tool" and i not in answered]
    assert strays == [], f"tool rows outside a tool_use answer: {strays}"


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
    confirmation_id: str = _UNUSED_CONFIRMATION
    expires_in: timedelta = timedelta(minutes=10)


@dataclass(frozen=True)
class _Run:
    """One stub run: the bound arguments (history copied at call time)."""

    user_message: str
    session_id: str
    history: tuple[LLMMessage, ...]
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


def _asks(
    call: ToolCall,
    confirmation_id: str,
    *,
    head: tuple[LLMMessage, ...] = (),
    earlier: tuple[ToolCallRecord, ...] = (),
    expires_in: timedelta = timedelta(minutes=10),
) -> _Reply:
    """A run that ends asking to confirm ``call`` (after ``head``, its earlier messages)."""
    return _Reply(
        new=(*head, _tool_use(call)),
        status="awaiting_confirmation",
        response=f"Action {call.tool}.{call.action} requires user confirmation.",
        tool_calls=(*earlier, _record(call)),
        pending=call,
        confirmation_id=confirmation_id,
        expires_in=expires_in,
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
            now = datetime.now(UTC)
            pending = PendingConfirmation(
                confirmation_id=reply.confirmation_id,
                session_id=arguments["session_id"],
                tool_call=reply.pending,
                created_at=now,
                expires_at=now + reply.expires_in,
            )
        return AgentResult.model_validate(
            {
                "status": reply.status,
                "response": reply.response,
                "history": [*base, *reply.new],
                "tool_calls": list(reply.tool_calls),
                "pending_confirmation": pending,
            }
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
    """The app around the stub agent (``create_app`` cleared the runtime); an escaping
    exception becomes the app's 500."""
    return make_client(make_app(agent), raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _send(
    client: TestClient, account: Account, chat_id: uuid.UUID, message: str = _MESSAGE
) -> httpx.Response:
    """POST /api/chats/{chat_id}/messages as ``account``."""
    return client.post(
        f"/api/chats/{chat_id}/messages", headers=account.cookie, json={"message": message}
    )


def _legacy(
    client: TestClient, account: Account, session_id: str, message: str = _MESSAGE
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
    chat_id: uuid.UUID,
    confirmation_id: str,
    *,
    approved: bool = True,
) -> httpx.Response:
    """POST /api/confirm/{confirmation_id} for the chat."""
    return client.post(
        f"/api/confirm/{confirmation_id}",
        headers=account.cookie,
        json={
            "confirmation_id": confirmation_id,
            "approved": approved,
            "chat_id": str(chat_id),
        },
    )


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


def _pending_id(chat_id: uuid.UUID) -> str | None:
    """The confirmation id the server's runtime keeps for the chat, or None."""
    pending = server._chat_runtime.get_pending(uuid.UUID(str(chat_id)))
    return None if pending is None else pending.confirmation_id


def _ask(
    client: TestClient,
    script: _Script,
    account: Account,
    chat_id: uuid.UUID,
    call: ToolCall,
    confirmation_id: str,
    *,
    message: str = _MESSAGE,
    expires_in: timedelta = timedelta(minutes=10),
) -> httpx.Response:
    """A turn in the chat whose run ends asking to confirm ``call``."""
    script.queue(_asks(call, confirmation_id, expires_in=expires_in))
    return _send(client, account, chat_id, message)


def _assert_kept(response: httpx.Response, confirmation_id: str) -> None:
    """The run's confirmation was kept: 200 awaiting it."""
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "awaiting_confirmation", body
    assert body["error_code"] is None
    assert body["pending_confirmation"]["confirmation_id"] == confirmation_id


def _fill(
    world: World, client: TestClient, script: _Script, account: Account, tag: str, count: int
) -> list[uuid.UUID]:
    """``count`` new chats of ``account``, each holding a kept pending confirmation
    ``confirm-24-<tag><n>`` (call ``call-24-<tag><n>``); their ids."""
    created: list[uuid.UUID] = []
    for n in range(1, count + 1):
        chat_id = world.db.add_chat(account.user_id)
        confirmation_id = f"confirm-24-{tag}{n}"
        _assert_kept(
            _ask(client, script, account, chat_id, _call(f"{tag}{n}"), confirmation_id),
            confirmation_id,
        )
        created.append(chat_id)
    return created


def _assert_limited(
    response: httpx.Response,
    chat_id: uuid.UUID,
    call: ToolCall,
    tool_calls: Sequence[ToolCallRecord],
    *,
    session_id: str | None = None,
) -> None:
    """The documented 200 of a run whose confirmation was refused (never a 429)."""
    assert response.status_code == 200, response.text
    assert response.json() == {
        "chat_id": str(chat_id),
        "session_id": session_id,
        "response": _limit_reply(call),
        "tool_calls": [record.model_dump(mode="json") for record in tool_calls],
        "status": "error",
        "pending_confirmation": None,
        "error_code": "rate_limit",
    }


def _limited_once(
    world: World,
    client: TestClient,
    script: _Script,
    account: Account,
    tag: str,
    call: ToolCall | None = None,
) -> tuple[uuid.UUID, ToolCall]:
    """A new chat of ``account`` whose confirm action is refused (the account at the
    limit); the chat and the call."""
    chat_id = world.db.add_chat(account.user_id)
    asked = call or _call(tag)
    response = _ask(client, script, account, chat_id, asked, f"confirm-24-{tag}")
    _assert_limited(response, chat_id, asked, (_record(asked),))
    return chat_id, asked


def _spy_appends(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the chat id of every ``chats.append_messages`` call from now on."""
    seen: list[str] = []
    real = chats.append_messages

    async def spy(pool: Any, tenant: Any, chat_id: Any, messages: Any, **kwargs: Any) -> None:
        seen.append(str(chat_id))
        await real(pool, tenant, chat_id, messages, **kwargs)

    monkeypatch.setattr(chats, "append_messages", spy)
    return seen


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the httpx client lines, which name request URLs)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


def _enum_values(schema: Any, components: dict[str, Any]) -> set[str]:
    """Every ``enum``/``const`` string a JSON schema admits ($refs resolved)."""
    if isinstance(schema, list):
        return {value for item in schema for value in _enum_values(item, components)}
    if not isinstance(schema, dict):
        return set()
    found: set[str] = set()
    ref = schema.get("$ref")
    if isinstance(ref, str):
        found |= _enum_values(components[ref.rsplit("/", 1)[-1]], components)
    found |= {value for value in schema.get("enum", []) if isinstance(value, str)}
    if isinstance(schema.get("const"), str):
        found.add(schema["const"])
    for key in ("anyOf", "oneOf", "allOf"):
        found |= _enum_values(schema.get(key, []), components)
    return found


# ---------------------------------------------------------------------------
# 1. The limit (criterion 8)
# ---------------------------------------------------------------------------


def test_confirmation_limits_fourth_confirm_action_gets_rate_limit_and_others_still_create_one(
    world: World, client: TestClient, script: _Script
) -> None:
    """Max 3: the Editor's confirm actions in chats 1 to 3 are kept; chat 4's is HTTP 200
    ``rate_limit`` with no pending confirmation; the runtime keeps the first 3 and none for
    chat 4, whose detail shows ``none``. Org A's Org Admin and org B's Editor can each
    still create one."""
    editor = world.a["editor"]
    kept = _fill(world, client, script, editor, "ed", 3)

    fourth, _ = _limited_once(world, client, script, editor, "ed4")

    assert [_pending_id(chat_id) for chat_id in (*kept, fourth)] == [
        "confirm-24-ed1",
        "confirm-24-ed2",
        "confirm-24-ed3",
        None,
    ]
    detail = _detail(client, editor, fourth)
    assert (detail["confirmation_status"], detail["pending_confirmation"]) == ("none", None)
    for account, tag in ((world.a["org_admin"], "oa1"), (world.b["editor"], "be1")):
        chat_id = world.db.add_chat(account.user_id)
        response = _ask(client, script, account, chat_id, _call(tag), f"confirm-24-{tag}")
        _assert_kept(response, f"confirm-24-{tag}")
        assert _pending_id(chat_id) == f"confirm-24-{tag}"


# ---------------------------------------------------------------------------
# 2. What a refused turn stores
# ---------------------------------------------------------------------------


def test_confirmation_limits_refused_turn_stores_the_denied_result_and_the_reply(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One append after the chat's earlier messages: the user message, the tool_use turn,
    the denied call's "too many confirmations" result, then the reply with status
    ``error`` and the run's tool_calls (on it only); everything before is ``complete``
    and the history is well-formed."""
    editor = world.a["editor"]
    db = world.db
    _fill(world, client, script, editor, "ed", 3)
    chat_id = db.add_chat(editor.user_id)
    earlier = (_user("Earlier question"), _assistant("Earlier answer"))
    for message in earlier:
        db.add_chat_message(chat_id, message.role, message.content)
    appends = _spy_appends(monkeypatch)
    call = _call("ed4")

    response = _ask(client, script, editor, chat_id, call, "confirm-24-ed4")

    _assert_limited(response, chat_id, call, (_record(call),))
    assert appends == [str(chat_id)]
    assert _stored(db, chat_id) == [
        *(_row(message) for message in earlier),
        _row(_user(_MESSAGE)),
        _row(_tool_use(call)),
        _row(_tool(_PENDING_LIMIT_RESULT, call)),
        _row(_assistant(_limit_reply(call)), "error"),
    ]
    assert [m["tool_calls"] for m in db.messages_of(chat_id)] == [None] * 5 + [
        [_record(call).model_dump(mode="json")]
    ]
    _assert_well_formed(db.messages_of(chat_id))


def test_confirmation_limits_refused_batch_closes_every_dangling_call_in_block_order(
    world: World, client: TestClient, script: _Script
) -> None:
    """A batch of three calls: the first ran (its result is stored), the second asked for
    the refused confirmation, the third never ran. The second gets the "too many
    confirmations" result, the third the existing cancelled result, in block order; the
    reply names the asked call (google_calendar.create), not the batch's first."""
    editor = world.a["editor"]
    db = world.db
    _fill(world, client, script, editor, "ed", 3)
    chat_id = db.add_chat(editor.user_id)
    ran = _call("b1", "memory", "recall")
    asked = _call("b2", "google_calendar", "create")
    later = _call("b3", "memory", "list")
    reply = _Reply(
        new=(_tool_use(ran, asked, later), _tool("Plan: ship", ran)),
        status="awaiting_confirmation",
        response="Action google_calendar.create requires user confirmation.",
        tool_calls=(_record(ran, "allow", success=True), _record(asked)),
        pending=asked,
        confirmation_id="confirm-24-b2",
    )
    script.queue(reply)

    response = _send(client, editor, chat_id)

    _assert_limited(response, chat_id, asked, reply.tool_calls)
    assert _stored(db, chat_id) == [
        _row(_user(_MESSAGE)),
        _row(_tool_use(ran, asked, later)),
        _row(_tool("Plan: ship", ran)),
        _row(_tool(_PENDING_LIMIT_RESULT, asked)),
        _row(_tool(server._CANCELLED_TOOL_RESULT_MSG, later)),
        _row(_assistant(_limit_reply(asked)), "error"),
    ]
    assert _pending_id(chat_id) is None
    _assert_well_formed(db.messages_of(chat_id))


def test_confirmation_limits_next_turn_after_a_refusal_gets_the_stored_history_unchanged(
    world: World, client: TestClient, script: _Script
) -> None:
    """The next message in the refused chat (the Editor still at the limit) runs normally
    with the stored turn as its history, nothing added: the refused call is already
    answered, so no cancelled result appears."""
    editor = world.a["editor"]
    db = world.db
    _fill(world, client, script, editor, "ed", 3)
    chat_id, call = _limited_once(world, client, script, editor, "ed4")

    response = _send(client, editor, chat_id, "Try again later")

    assert response.status_code == 200, response.text
    assert (response.json()["status"], response.json()["error_code"]) == ("final", None)
    history = script.runs[-1].history
    assert _dump(history) == _dump(
        [
            _user(_MESSAGE),
            _tool_use(call),
            _tool(_PENDING_LIMIT_RESULT, call),
            _assistant(_limit_reply(call)),
        ]
    )
    _assert_well_formed(history)
    assert _stored(db, chat_id)[-2:] == [
        _row(_user("Try again later")),
        _row(_assistant(_STUB_REPLY)),
    ]
    _assert_well_formed(db.messages_of(chat_id))


# ---------------------------------------------------------------------------
# 3. The legacy route and the approved resume
# ---------------------------------------------------------------------------


def test_confirmation_limits_legacy_message_at_the_limit_gets_rate_limit(
    world: World, client: TestClient, script: _Script
) -> None:
    """POST /api/message: the same 200 ``rate_limit`` with the session id echoed and the
    legacy chat named; the same rows stored; nothing kept for that chat."""
    editor = world.a["editor"]
    db = world.db
    session_id = "legacy-24-wren"
    _fill(world, client, script, editor, "ed", 3)
    call = _call("lg")
    script.queue(_asks(call, "confirm-24-lg"))

    response = _legacy(client, editor, session_id)

    (legacy_chat,) = [c for c in db.chats_of(editor.user_id) if c["legacy_session_id"]]
    chat_id = uuid.UUID(str(legacy_chat["id"]))
    _assert_limited(response, chat_id, call, (_record(call),), session_id=session_id)
    assert _pending_id(chat_id) is None
    assert _stored(db, chat_id) == [
        _row(_user(_MESSAGE)),
        _row(_tool_use(call)),
        _row(_tool(_PENDING_LIMIT_RESULT, call)),
        _row(_assistant(_limit_reply(call)), "error"),
    ]


def test_confirmation_limits_approved_resume_counts_the_other_chats_only(
    world: World, client: TestClient, script: _Script
) -> None:
    """Chat A's confirmation plus two others (seeded, so 3 in all): approving A's resumes
    a run that asks for another one, which is kept (A's own consumed confirmation never
    counts). With a third other chat seeded, the next approved resume of A asking again
    is the 200 ``rate_limit``: nothing kept for A, the others untouched, and A's stored
    history well-formed."""
    editor = world.a["editor"]
    db = world.db
    chat_a = db.add_chat(editor.user_id)
    first = _call("ra1")
    _assert_kept(_ask(client, script, editor, chat_a, first, "confirm-24-ra1"), "confirm-24-ra1")
    others = [seed_chat(db, editor) for _ in range(3)]
    seed_pending_confirmation(editor, others[0], "confirm-24-s1")
    seed_pending_confirmation(editor, others[1], "confirm-24-s2")
    second = _call("ra2")
    script.queue(
        _asks(
            second,
            "confirm-24-ra2",
            head=(_tool("Stored memory: note-ra1", first),),
            earlier=(_record(first, success=True),),
        )
    )

    kept = _confirm(client, editor, chat_a, "confirm-24-ra1")

    _assert_kept(kept, "confirm-24-ra2")
    assert _pending_id(chat_a) == "confirm-24-ra2"
    seed_pending_confirmation(editor, others[2], "confirm-24-s3")
    third = _call("ra3", "google_calendar", "create")
    refused = _asks(
        third,
        "confirm-24-ra3",
        head=(_tool("Stored memory: note-ra2", second),),
        earlier=(_record(second, success=True),),
    )
    script.queue(refused)

    response = _confirm(client, editor, chat_a, "confirm-24-ra2")

    _assert_limited(response, chat_a, third, refused.tool_calls)
    assert _pending_id(chat_a) is None
    assert [_pending_id(chat_id) for chat_id in others] == [
        "confirm-24-s1",
        "confirm-24-s2",
        "confirm-24-s3",
    ]
    assert _stored(db, chat_a)[-4:] == [
        _row(_tool("Stored memory: note-ra2", second)),
        _row(_tool_use(third)),
        _row(_tool(_PENDING_LIMIT_RESULT, third)),
        _row(_assistant(_limit_reply(third)), "error"),
    ]
    _assert_well_formed(db.messages_of(chat_a))


def test_confirmation_limits_turn_replacing_its_own_cancelled_pending_is_kept(
    world: World, client: TestClient, script: _Script
) -> None:
    """At the limit, a new message in chat 1 (cancelling its pending confirmation) whose
    run asks again is kept: chat 1's own never counts. A 4th chat is still refused."""
    editor = world.a["editor"]
    first, *_ = _fill(world, client, script, editor, "ed", 3)

    again = _ask(client, script, editor, first, _call("ed1b"), "confirm-24-ed1b")

    _assert_kept(again, "confirm-24-ed1b")
    assert _pending_id(first) == "confirm-24-ed1b"
    _limited_once(world, client, script, editor, "ed4")


# ---------------------------------------------------------------------------
# 4. The stored limit, read per request
# ---------------------------------------------------------------------------


def test_confirmation_limits_raised_stored_limit_applies_to_the_next_request(
    world: World, client: TestClient, script: _Script
) -> None:
    """At 3 the 4th is refused; the Super Admin raises ``max_pending_confirmations`` to 4
    (PATCH /api/platform/settings, no restart): the next one is kept, the one after is
    refused."""
    editor = world.a["editor"]
    _fill(world, client, script, editor, "ed", 3)
    _limited_once(world, client, script, editor, "ed4")

    patched = client.patch(
        _PLATFORM_SETTINGS,
        headers=world.super_admin.cookie,
        json={"limits": {"max_pending_confirmations": 4}},
    )

    assert patched.status_code == 200, patched.text
    fifth = world.db.add_chat(editor.user_id)
    _assert_kept(
        _ask(client, script, editor, fifth, _call("ed5"), "confirm-24-ed5"), "confirm-24-ed5"
    )
    _limited_once(world, client, script, editor, "ed6")


def test_confirmation_limits_lowered_stored_limit_applies_to_the_next_request(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stored limit lowered to 1 after the app started: the 1st is kept, the 2nd is
    refused."""
    editor = world.a["editor"]
    _stored_limits(monkeypatch, max_pending_confirmations=1)

    (kept,) = _fill(world, client, script, editor, "ed", 1)

    _limited_once(world, client, script, editor, "ed2")
    assert _pending_id(kept) == "confirm-24-ed1"


# ---------------------------------------------------------------------------
# 5. Freeing a slot
# ---------------------------------------------------------------------------


def test_confirmation_limits_new_message_cancelling_a_pending_frees_its_slot(
    world: World, client: TestClient, script: _Script
) -> None:
    """A plain message in chat 1 cancels its confirmation: the next confirm action in a new
    chat is kept, the one after is refused."""
    editor = world.a["editor"]
    first, *_ = _fill(world, client, script, editor, "ed", 3)

    cancelled = _send(client, editor, first, "Never mind")

    assert cancelled.status_code == 200, cancelled.text
    assert _pending_id(first) is None
    fourth = world.db.add_chat(editor.user_id)
    _assert_kept(
        _ask(client, script, editor, fourth, _call("ed4"), "confirm-24-ed4"), "confirm-24-ed4"
    )
    _limited_once(world, client, script, editor, "ed5")


def test_confirmation_limits_expired_pending_is_reaped_and_frees_its_slot(
    world: World, client: TestClient, script: _Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Chat 1's confirmation expires after 1 minute, the others after 10. With the server's
    clock 2 minutes on, the next request reaps it first: a new confirm action is kept
    (chat 1 shows ``expired``), the one after is refused."""
    editor = world.a["editor"]
    first = world.db.add_chat(editor.user_id)
    _assert_kept(
        _ask(
            client,
            script,
            editor,
            first,
            _call("ex1"),
            "confirm-24-ex1",
            expires_in=timedelta(minutes=1),
        ),
        "confirm-24-ex1",
    )
    _fill(world, client, script, editor, "ex", 2)
    later = datetime.now(UTC) + timedelta(minutes=2)
    monkeypatch.setattr(server, "_utc_now", lambda: later)
    fourth = world.db.add_chat(editor.user_id)

    response = _ask(client, script, editor, fourth, _call("ex4"), "confirm-24-ex4")

    _assert_kept(response, "confirm-24-ex4")
    assert _pending_id(first) is None
    assert _detail(client, editor, first)["confirmation_status"] == "expired"
    _limited_once(world, client, script, editor, "ex5")


def test_confirmation_limits_denied_pending_frees_its_slot(
    world: World, client: TestClient, script: _Script
) -> None:
    """Denying chat 1's confirmation: the next confirm action is kept, the one after is
    refused."""
    editor = world.a["editor"]
    first, *_ = _fill(world, client, script, editor, "dn", 3)

    denied = _confirm(client, editor, first, "confirm-24-dn1", approved=False)

    assert denied.status_code == 200, denied.text
    assert _pending_id(first) is None
    fourth = world.db.add_chat(editor.user_id)
    _assert_kept(
        _ask(client, script, editor, fourth, _call("dn4"), "confirm-24-dn4"), "confirm-24-dn4"
    )
    _limited_once(world, client, script, editor, "dn5")


def test_confirmation_limits_chat_trashed_during_the_run_keeps_no_pending(
    world: World, client: TestClient, script: _Script
) -> None:
    """Two kept, then a run asking for a confirmation in a chat trashed meanwhile: the
    404 ``chat_not_found``, and no confirmation kept for it (contract section 4: one
    stored before the append is dropped again), so the next one is kept and the one
    after is refused."""
    editor = world.a["editor"]
    db = world.db
    _fill(world, client, script, editor, "tr", 2)
    doomed = db.add_chat(editor.user_id)

    async def trash() -> None:
        db.chats[uuid.UUID(int=doomed.int)]["deleted_at"] = datetime.now(UTC)

    script.during = trash

    response = _ask(client, script, editor, doomed, _call("tr3"), "confirm-24-tr3")

    assert (response.status_code, response.json()) == (404, CHAT_NOT_FOUND)
    assert _pending_id(doomed) is None
    assert db.messages_of(doomed) == []
    fourth = db.add_chat(editor.user_id)
    _assert_kept(
        _ask(client, script, editor, fourth, _call("tr4"), "confirm-24-tr4"), "confirm-24-tr4"
    )
    _limited_once(world, client, script, editor, "tr5")


# ---------------------------------------------------------------------------
# 6. Isolation between users and orgs
# ---------------------------------------------------------------------------


def test_confirmation_limits_users_and_orgs_never_count_for_each_other(
    world: World, client: TestClient, script: _Script
) -> None:
    """Org A's Org Admin (Y) and org B's Editor (Z) hold one each; the Editor (X) still gets
    three and the 4th is refused; with X at the limit, Y and Z still get their 2nd and 3rd;
    then each of them is refused their own 4th. Nobody loses a kept confirmation."""
    x, y, z = world.a["editor"], world.a["org_admin"], world.b["editor"]
    y_chats = _fill(world, client, script, y, "y", 1)
    z_chats = _fill(world, client, script, z, "z", 1)

    x_chats = _fill(world, client, script, x, "x", 3)
    _limited_once(world, client, script, x, "x4")

    for account, tag, held in ((y, "y", y_chats), (z, "z", z_chats)):
        for n in (2, 3):
            chat_id = world.db.add_chat(account.user_id)
            _assert_kept(
                _ask(client, script, account, chat_id, _call(f"{tag}{n}"), f"confirm-24-{tag}{n}"),
                f"confirm-24-{tag}{n}",
            )
            held.append(chat_id)
        _limited_once(world, client, script, account, f"{tag}4")
    assert [_pending_id(c) for c in (*x_chats, *y_chats, *z_chats)] == [
        f"confirm-24-{tag}{n}" for tag in ("x", "y", "z") for n in (1, 2, 3)
    ]


# ---------------------------------------------------------------------------
# 7. The models and the OpenAPI contract
# ---------------------------------------------------------------------------


def test_confirmation_limits_rate_limit_is_a_chat_response_code_only() -> None:
    """``ChatResponse`` accepts and serializes ``error_code="rate_limit"``; it is not an
    LLM error code: ``AgentResult`` refuses it and ``LLM_ERROR_CODES`` stays the eight."""
    response = ChatResponse.model_validate(
        {
            "chat_id": str(uuid.UUID(int=24)),
            "response": "Refused.",
            "status": "error",
            "error_code": "rate_limit",
        }
    )

    assert response.model_dump(mode="json")["error_code"] == "rate_limit"
    assert ChatResponse.model_validate_json(response.model_dump_json()).error_code == "rate_limit"
    with pytest.raises(ValidationError):
        AgentResult.model_validate({"status": "error", "error_code": "rate_limit"})
    assert frozenset(LLM_ERROR_CODES) == _LLM_CODES


def test_confirmation_limits_openapi_lists_rate_limit_beside_the_llm_codes() -> None:
    """The contract clients read: ``ChatResponse.error_code`` admits exactly the eight LLM
    codes and ``rate_limit`` (or null)."""
    schema = make_app(stub_agent()).openapi()
    components = schema["components"]["schemas"]

    error_code = components["ChatResponse"]["properties"]["error_code"]

    assert _enum_values(error_code, components) == {*_LLM_CODES, "rate_limit"}


# ---------------------------------------------------------------------------
# 8. Logs
# ---------------------------------------------------------------------------


def test_confirmation_limits_refusal_logs_no_content_arguments_or_confirmation_ids(
    world: World, client: TestClient, script: _Script, caplog: pytest.LogCaptureFixture
) -> None:
    """A refused turn: no app log record names the message, the tool arguments, the call
    id or any confirmation id; the response doesn't repeat the refused confirmation id."""
    caplog.set_level(logging.DEBUG)
    editor = world.a["editor"]
    _fill(world, client, script, editor, "lc", 3)
    chat_id = world.db.add_chat(editor.user_id)
    call = ToolCall(
        tool="memory",
        action="store",
        args={"key": "limit-canary-24-key", "value": "limit-canary-24-value"},
        tool_call_id="limit-canary-24-call",
    )

    response = _ask(
        client,
        script,
        editor,
        chat_id,
        call,
        "limit-canary-24-confirm",
        message="limit-canary-24-message",
    )

    _assert_limited(response, chat_id, call, (_record(call),))
    assert "limit-canary-24-confirm" not in response.text
    text = _app_log_text(caplog)
    canaries = (
        "limit-canary-24-message",
        "limit-canary-24-key",
        "limit-canary-24-value",
        "limit-canary-24-call",
        "limit-canary-24-confirm",
        "confirm-24-lc1",
        "confirm-24-lc2",
        "confirm-24-lc3",
    )
    assert [canary for canary in canaries if canary in text] == []
