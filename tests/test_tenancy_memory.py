"""Tenant isolation of agent memory through the chat route (GH-163, memory row).

Memory has no HTTP route of its own: the LLM reaches it through tool calls
during ``POST /api/message``. So its cross-org case runs end to end: the app
from ``create_app()`` drives a REAL ``Agent`` (with the real tool-call
recorder of ``main._build_tool_call_recorder()``), the registry holds the
REAL ``memory.store`` / ``memory.recall`` / ``memory.list`` handlers (wrapped
by a spy that records which tenant each invocation ran for), and the LLM is a
scripted fake (``_FakeLLM``: each user message picks a script of tool calls;
it records every message text it is fed and the tool results of the turn).
The database is the FakeDb world of tests/tenancy_world.py: orgs A and B with
an Org Admin, an Editor and a Viewer each, plus a Super Admin, all with real
session cookies resolved by the real ``server.require_session``. Every user
chats under the same chat session id, so a history keyed by chat id alone
would hand one user's notes to another's LLM.

Inputs: the world, the fake LLM's scripts. Outputs (asserted):
- Org B's users (Editor and Org Admin) never recall, list or overwrite org A's
  note: ``recall`` answers "not found", ``list`` "No memories stored.", a
  ``store`` of the same key keeps A's note and lands in B's own row (with B's
  org id); A's recall still returns A's value.
- LLM-supplied ``org_id`` / ``user_id`` tool arguments naming org A (#17's
  tenancy line, "tool arguments") are refused with the existing
  "unexpected fields" result: the handler isn't invoked and no memory
  statement runs for that call; the next plain call runs for B.
- Every memory SQL statement, handler invocation and ``tool.call`` audit row
  of B's run carries B's user id and org id, never A's.
- A's note value is never fed to B's LLM, never in B's HTTP responses, and no
  note value is in any app log record (#139 section 5).
- A Viewer (either org) and the Super Admin get ``403 {"detail": "Forbidden"}``
  on the memory path: no LLM call, no handler, no memory statement, no audit
  row (role gate, operator blindness).

All database calls are faked. No network, no real PostgreSQL, no real LLM.

Security notes:
- The tool context comes from the session's principal only, never from LLM
  arguments; memory queries filter by user AND org.
- The note values here are fixed fake values, never real secrets.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino import main as main_module
from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import (
    AgentConfig,
    MemoryListArgs,
    MemoryRecallArgs,
    MemoryStoreArgs,
    ToolCall,
)
from admino.server import create_app
from admino.tools import memory, registry
from tests.db_fakes import FakeDb, plain
from tests.tenancy_world import (
    FORBIDDEN,
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
    from fastapi.testclient import TestClient

    from admino.models import LLMMessage
    from admino.tenancy import TenantContext
    from admino.tools.registry import ToolHandler
    from tests.db_fakes import Call
    from tests.tenancy_world import Account, MemberRole, World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CHAT_ID: Final = "shared-chat-163"
_FINAL_REPLY: Final = "All done."

_KEY: Final = "plan"
_A_SECRET: Final = "A-secret-163-kestrel-ledger"
_B_VALUE: Final = "B-value-163-osprey-quill"
_OVERWRITE: Final = "overwritten-by-org-b-163"
_STORED: Final = f"Stored memory: {_KEY}"
_NOT_FOUND: Final = f"No memory found for key: {_KEY}"
_NO_MEMORIES: Final = "No memories stored."
_EXTRA_REFUSED: Final = "Argument validation failed: unexpected fields are not permitted."

# A memory statement: SELECT ... FROM memory, INSERT INTO memory, UPDATE memory.
_MEMORY_SQL: Final = r"(?:\bfrom memory\b|\binto memory\b|^update memory\b)"

_B_READERS: Final = [
    pytest.param("editor", id="org-b-editor"),
    pytest.param("org_admin", id="org-b-org-admin"),
]

Step = tuple[str, str, dict[str, Any]]

# ---------------------------------------------------------------------------
# Fakes: the LLM and the handler spy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _LLMCall:
    """What one LLM call received: the turn's user message, every message it was fed
    (system, history, tool results; serialized whole, so the arguments of earlier tool
    calls are included) and the tool results after that user message."""

    user_message: str
    seen: tuple[str, ...]
    tool_results: tuple[str, ...]


class _FakeLLM:
    """Plays a script per user message: the n-th call of a chat turn returns the n-th
    scripted tool call (counted by the assistant turns after the user message), then a
    final reply."""

    provider = "infomaniak"

    def __init__(self) -> None:
        self._scripts: dict[str, list[ToolCall]] = {}
        self.calls: list[_LLMCall] = []

    def script(self, message: str, *steps: Step) -> str:
        """Script the tool calls the LLM makes for ``message``; return the message."""
        assert message not in self._scripts, f"script {message!r} twice"
        number = len(self._scripts)
        self._scripts[message] = [
            ToolCall(tool=tool, action=action, args=args, tool_call_id=f"call-{number}-{index}")
            for index, (tool, action, args) in enumerate(steps)
        ]
        return message

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        """Answer the next scripted tool call of the current turn, or the final reply."""
        last_user = max(index for index, message in enumerate(messages) if message.role == "user")
        user_message = str(messages[last_user].content)
        after = messages[last_user + 1 :]
        self.calls.append(
            _LLMCall(
                user_message=user_message,
                seen=tuple(message.model_dump_json() for message in messages),
                tool_results=tuple(str(m.content) for m in after if m.role == "tool"),
            )
        )
        steps = self._scripts.get(user_message, [])
        done = sum(1 for message in after if message.role == "assistant")
        if done < len(steps):
            return LLMResponse(content="", tool_calls=[steps[done]])
        return LLMResponse(content=_FINAL_REPLY)

    async def close(self) -> None:
        """Nothing to close."""

    def calls_of(self, message: str) -> list[_LLMCall]:
        """Every LLM call of ``message``'s turn."""
        return [call for call in self.calls if call.user_message == message]

    def results_of(self, message: str) -> list[str]:
        """The tool results the LLM was fed in the last call of ``message``'s turn."""
        calls = self.calls_of(message)
        assert calls, f"the LLM never saw {message!r}"
        return list(calls[-1].tool_results)

    def seen_in(self, message: str) -> str:
        """Every message the LLM was fed during ``message``'s turn, serialized and joined."""
        calls = self.calls_of(message)
        assert calls, f"the LLM never saw {message!r}"
        return "\n".join(text for call in calls for text in call.seen)


@dataclass(frozen=True)
class _HandlerCall:
    """One invocation of a real memory handler and the tenant it ran for."""

    function: str
    user_id: uuid.UUID
    org_id: uuid.UUID


@dataclass
class _Handlers:
    """Wraps the real memory handlers: records every invocation, then delegates."""

    calls: list[_HandlerCall] = field(default_factory=list)

    def wrap(self, function: str, handler: ToolHandler) -> ToolHandler:
        """``handler`` behind a recorder of ``function``'s invocations."""

        async def spy(args: Any, *, tenant: TenantContext, **kwargs: Any) -> str:
            self.calls.append(_HandlerCall(function, plain(tenant.user_id), plain(tenant.org_id)))
            return await handler(args, tenant=tenant, **kwargs)

        return spy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin, behind the fake database."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    # memory.py binds get_pool at import: point that name at the fake too.
    monkeypatch.setattr(memory, "get_pool", lambda: db.pool)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture()
def handlers(monkeypatch: pytest.MonkeyPatch) -> _Handlers:
    """An unfrozen registry holding exactly the three real memory handlers (spied); the
    previous registry is restored after (the registry reads its globals at call time)."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)
    spy = _Handlers()
    real: list[tuple[str, type[Any], ToolHandler]] = [
        ("store", MemoryStoreArgs, memory.memory_store),
        ("recall", MemoryRecallArgs, memory.memory_recall),
        ("list", MemoryListArgs, memory.memory_list),
    ]
    for action, schema, handler in real:
        function = f"memory.{action}"
        registry.register_tool("memory", action, f"{function} (GH-163 suite)", schema)(
            spy.wrap(function, handler)
        )
    return spy


@pytest.fixture()
def llm() -> _FakeLLM:
    """The scripted LLM."""
    return _FakeLLM()


@pytest.fixture()
def client(world: World, handlers: _Handlers, llm: _FakeLLM) -> TestClient:
    """The app with a real Agent (real tool-call recorder) around the fake LLM."""
    agent = Agent(
        llm_client=llm,
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    return make_client(create_app(agent=agent, config=make_config()))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chat(client: TestClient, account: Account, message: str) -> httpx.Response:
    """POST /api/message as ``account``, in the chat every user shares the id of."""
    return client.post(
        "/api/message",
        headers=account.cookie,
        json={"message": message, "session_id": _CHAT_ID},
    )


def _ok(*responses: httpx.Response) -> None:
    for response in responses:
        assert response.status_code == 200, response.text


def _store(value: str) -> Step:
    return ("memory", "store", {"key": _KEY, "value": value})


def _recall() -> Step:
    return ("memory", "recall", {"key": _KEY})


def _list() -> Step:
    return ("memory", "list", {})


def _seed_a_note(client: TestClient, world: World, llm: _FakeLLM) -> Account:
    """Org A's Editor stores ``plan = _A_SECRET`` through the chat; return that Editor."""
    owner = world.a["editor"]
    message = llm.script("A: remember the plan", _store(_A_SECRET))
    _ok(_chat(client, owner, message))
    assert llm.results_of(message) == [_STORED]
    assert world.db.memories_of(owner.user_id) == {_KEY: _A_SECRET}
    return owner


def _binds(call: Call, value: uuid.UUID) -> bool:
    return any(str(arg) == str(value) for arg in call.args)


@dataclass(frozen=True)
class _Mark:
    """Where the recorded statements, handler calls and audit rows stood before a run."""

    statements: int
    handler_calls: int
    audit_rows: int


def _mark(world: World, handlers: _Handlers) -> _Mark:
    return _Mark(
        statements=len(world.db.calls),
        handler_calls=len(handlers.calls),
        audit_rows=len(world.db.audit_rows("tool.call")),
    )


def _memory_statements(world: World, since: int = 0) -> list[Call]:
    return [call for call in world.db.calls[since:] if re.search(_MEMORY_SQL, call.normalized)]


def _assert_run_belongs_to(
    world: World, handlers: _Handlers, mark: _Mark, caller: Account, other: Account
) -> None:
    """Every memory statement, handler call and tool.call row since ``mark`` carries the
    caller's user id and org id, never ``other``'s."""
    assert caller.org_id is not None and other.org_id is not None
    for call in _memory_statements(world, mark.statements):
        assert _binds(call, caller.user_id) and _binds(call, caller.org_id), call.sql
        assert not _binds(call, other.user_id) and not _binds(call, other.org_id), call.sql
    for invocation in handlers.calls[mark.handler_calls :]:
        assert (invocation.user_id, invocation.org_id) == (caller.user_id, caller.org_id)
    for row in world.db.audit_rows("tool.call")[mark.audit_rows :]:
        assert plain(row["org_id"]) == caller.org_id, row
        assert plain(row["actor_user_id"]) == caller.user_id, row


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every captured app record (not the httpx client lines, which name request URLs)."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(
        formatter.format(record)
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


# ---------------------------------------------------------------------------
# 1. Org B never reads, lists or overwrites org A's notes
# ---------------------------------------------------------------------------


class TestCrossOrgNotes:
    """memory.* run by org B's members only ever touch B's own notes (memory row)."""

    @pytest.mark.parametrize("reader_role", _B_READERS)
    def test_tenancy_memory_other_org_recall_finds_nothing(
        self,
        world: World,
        client: TestClient,
        llm: _FakeLLM,
        handlers: _Handlers,
        reader_role: MemberRole,
    ) -> None:
        """B's recall of A's key answers "not found"; A's recall still finds A's note."""
        owner = _seed_a_note(client, world, llm)
        reader = world.b[reader_role]
        probe = llm.script("B: what is the plan?", _recall())
        check = llm.script("A: what is the plan?", _recall())
        mark = _mark(world, handlers)

        probed = _chat(client, reader, probe)
        checked = _chat(client, owner, check)

        _ok(probed, checked)
        assert llm.results_of(probe) == [_NOT_FOUND]
        assert _A_SECRET not in llm.seen_in(probe)
        assert _A_SECRET not in probed.text
        assert llm.results_of(check) == [_A_SECRET]
        assert handlers.calls[mark.handler_calls :][0] == _HandlerCall(
            "memory.recall", reader.user_id, world.org_b
        )

    @pytest.mark.parametrize("reader_role", _B_READERS)
    def test_tenancy_memory_other_org_list_shows_no_memories(
        self,
        world: World,
        client: TestClient,
        llm: _FakeLLM,
        handlers: _Handlers,
        reader_role: MemberRole,
    ) -> None:
        """B's list answers "No memories stored." while A has a note."""
        _seed_a_note(client, world, llm)
        reader = world.b[reader_role]
        probe = llm.script("B: list my notes", _list())
        mark = _mark(world, handlers)

        response = _chat(client, reader, probe)

        _ok(response)
        assert llm.results_of(probe) == [_NO_MEMORIES]
        assert _A_SECRET not in llm.seen_in(probe)
        assert _A_SECRET not in response.text
        _assert_run_belongs_to(world, handlers, mark, reader, world.a["editor"])

    @pytest.mark.parametrize("writer_role", _B_READERS)
    def test_tenancy_memory_other_org_store_same_key_keeps_the_owners_note(
        self,
        world: World,
        client: TestClient,
        llm: _FakeLLM,
        handlers: _Handlers,
        writer_role: MemberRole,
    ) -> None:
        """B stores under A's key: B gets its own row (B's org id), A's note is untouched,
        and each recalls their own value."""
        owner = _seed_a_note(client, world, llm)
        writer = world.b[writer_role]
        stored = llm.script("B: remember the plan", _store(_B_VALUE))
        recalled_b = llm.script("B: what is the plan now?", _recall())
        recalled_a = llm.script("A: is my plan still there?", _recall())
        mark = _mark(world, handlers)

        first = _chat(client, writer, stored)
        second = _chat(client, writer, recalled_b)
        third = _chat(client, owner, recalled_a)

        _ok(first, second, third)
        assert llm.results_of(stored) == [_STORED]
        assert world.db.memories_of(owner.user_id) == {_KEY: _A_SECRET}
        assert world.db.memories_of(writer.user_id) == {_KEY: _B_VALUE}
        assert plain(world.db.memory[(writer.user_id, _KEY)]["org_id"]) == world.org_b
        assert plain(world.db.memory[(owner.user_id, _KEY)]["org_id"]) == world.org_a
        assert llm.results_of(recalled_b) == [_B_VALUE]
        assert _A_SECRET not in llm.seen_in(recalled_b)
        assert _A_SECRET not in first.text + second.text
        assert llm.results_of(recalled_a) == [_A_SECRET]
        assert [call.function for call in handlers.calls[mark.handler_calls :]] == [
            "memory.store",
            "memory.recall",
            "memory.recall",
        ]


# ---------------------------------------------------------------------------
# 2. LLM-supplied org/user ids in tool arguments are refused (#17)
# ---------------------------------------------------------------------------

_SMUGGLED_FIELDS: Final = [
    pytest.param(("org_id",), id="org_id"),
    pytest.param(("user_id",), id="user_id"),
    pytest.param(("org_id", "user_id"), id="org_id-and-user_id"),
]

# action -> (the smuggling call's own args, the plain call that follows, its result).
_PLAIN: Final[dict[str, tuple[dict[str, Any], Step, str]]] = {
    "recall": ({"key": _KEY}, ("memory", "recall", {"key": _KEY}), _NOT_FOUND),
    "list": ({}, ("memory", "list", {}), _NO_MEMORIES),
    "store": (
        {"key": _KEY, "value": _OVERWRITE},
        ("memory", "store", {"key": _KEY, "value": _B_VALUE}),
        _STORED,
    ),
}


def _smuggled_value(world: World, name: str) -> str:
    """The id an injected LLM puts under ``name`` to reach org A's Editor's notes."""
    values = {"org_id": str(world.org_a), "user_id": str(world.a["editor"].user_id)}
    return values[name]


class TestSmuggledIdsInToolArguments:
    """A tool argument naming another org or user is refused before the handler runs."""

    @pytest.mark.parametrize("action", ["recall", "list", "store"])
    @pytest.mark.parametrize("fields", _SMUGGLED_FIELDS)
    def test_tenancy_memory_foreign_ids_in_tool_arguments_are_refused(
        self,
        world: World,
        client: TestClient,
        llm: _FakeLLM,
        handlers: _Handlers,
        action: str,
        fields: tuple[str, ...],
    ) -> None:
        """B's LLM names org A / A's Editor in the arguments: "unexpected fields", no
        handler call and no memory statement for it; the plain call that follows runs
        for B only, and A's note never reaches B's LLM or response."""
        owner = _seed_a_note(client, world, llm)
        caller = world.b["editor"]
        own_args, plain_step, plain_result = _PLAIN[action]
        smuggling = {**own_args, **{name: _smuggled_value(world, name) for name in fields}}
        message = llm.script(
            f"B: {action} with smuggled {'+'.join(fields)}",
            ("memory", action, smuggling),
            plain_step,
        )
        mark = _mark(world, handlers)

        response = _chat(client, caller, message)

        _ok(response)
        assert llm.results_of(message) == [_EXTRA_REFUSED, plain_result]
        assert handlers.calls[mark.handler_calls :] == [
            _HandlerCall(f"memory.{action}", caller.user_id, world.org_b)
        ]
        assert len(_memory_statements(world, mark.statements)) == 1
        _assert_run_belongs_to(world, handlers, mark, caller, owner)
        assert world.db.memories_of(owner.user_id) == {_KEY: _A_SECRET}
        assert _A_SECRET not in llm.seen_in(message)
        assert _A_SECRET not in response.text
        assert _OVERWRITE not in world.db.memories_of(caller.user_id).values()

    @pytest.mark.parametrize("fields", _SMUGGLED_FIELDS)
    def test_tenancy_memory_refused_call_is_audited_for_the_caller_as_failed(
        self,
        world: World,
        client: TestClient,
        llm: _FakeLLM,
        handlers: _Handlers,
        fields: tuple[str, ...],
    ) -> None:
        """The refused call's tool.call row is B's (org and actor) and says it failed."""
        _seed_a_note(client, world, llm)
        caller = world.b["editor"]
        smuggling = {"key": _KEY, **{name: _smuggled_value(world, name) for name in fields}}
        message = llm.script(
            f"B: recall only, smuggled {'+'.join(fields)}", ("memory", "recall", smuggling)
        )
        mark = _mark(world, handlers)

        _ok(_chat(client, caller, message))

        rows = world.db.audit_rows("tool.call")[mark.audit_rows :]
        assert len(rows) == 1, rows
        assert plain(rows[0]["org_id"]) == world.org_b
        assert plain(rows[0]["actor_user_id"]) == caller.user_id
        assert rows[0]["metadata"]["success"] is False
        assert handlers.calls[mark.handler_calls :] == []
        assert _memory_statements(world, mark.statements) == []


# ---------------------------------------------------------------------------
# 3. Every memory statement of B's run binds B's ids
# ---------------------------------------------------------------------------


class TestStatementsBindTheCaller:
    """The tenant of every memory statement comes from the session, never the LLM."""

    @pytest.mark.parametrize("caller_role", _B_READERS)
    def test_tenancy_memory_statements_of_org_b_bind_org_b_ids_only(
        self,
        world: World,
        client: TestClient,
        llm: _FakeLLM,
        handlers: _Handlers,
        caller_role: MemberRole,
    ) -> None:
        """B's store, recall, list and a smuggled recall: every memory statement binds B's
        user id and org id and never A's; every handler call and tool.call row is B's."""
        owner = _seed_a_note(client, world, llm)
        caller = world.b[caller_role]
        message = llm.script(
            "B: store, recall, list, and try A's ids",
            _store(_B_VALUE),
            _recall(),
            _list(),
            ("memory", "recall", {"key": _KEY, "org_id": str(world.org_a)}),
        )
        mark = _mark(world, handlers)

        response = _chat(client, caller, message)

        _ok(response)
        assert llm.results_of(message) == [_STORED, _B_VALUE, _KEY, _EXTRA_REFUSED]
        statements = _memory_statements(world, mark.statements)
        assert len(statements) == 3, [call.sql for call in statements]
        assert len(world.db.audit_rows("tool.call")[mark.audit_rows :]) == 4
        _assert_run_belongs_to(world, handlers, mark, caller, owner)


# ---------------------------------------------------------------------------
# 4. No note value in the logs
# ---------------------------------------------------------------------------


class TestNoNoteInLogs:
    """No note value in any app log record of A's or B's runs (#139 section 5)."""

    def test_tenancy_memory_cross_org_runs_log_no_note_value(
        self,
        world: World,
        client: TestClient,
        llm: _FakeLLM,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        _seed_a_note(client, world, llm)
        caller = world.b["editor"]
        probe = llm.script(
            "B: recall, list, overwrite, smuggle",
            _recall(),
            _list(),
            _store(_B_VALUE),
            (
                "memory",
                "store",
                {"key": _KEY, "value": _OVERWRITE, "user_id": str(world.a["editor"].user_id)},
            ),
        )

        response = _chat(client, caller, probe)

        _ok(response)
        assert llm.results_of(probe) == [_NOT_FOUND, _NO_MEMORIES, _STORED, _EXTRA_REFUSED]
        text = _app_log_text(caplog)
        assert text, "no app log record was captured: the scan would be vacuous"
        for value in (_A_SECRET, _B_VALUE, _OVERWRITE):
            assert value not in text, value


# ---------------------------------------------------------------------------
# 5. Role gate and operator blindness on the memory path
# ---------------------------------------------------------------------------


def _assert_refused_without_memory_access(
    world: World, response: httpx.Response, llm: _FakeLLM, handlers: _Handlers
) -> None:
    assert (response.status_code, response.json()) == (403, FORBIDDEN)
    assert llm.calls == []
    assert handlers.calls == []
    assert _memory_statements(world) == []
    assert world.db.audit_rows("tool.call") == []
    assert _A_SECRET not in response.text


class TestMemoryPathRoles:
    """Only members who may chat reach memory; Viewers and the Super Admin get 403."""

    @pytest.mark.parametrize("org", ["a", "b"])
    def test_tenancy_memory_viewer_is_refused_before_any_memory_access(
        self,
        world: World,
        client: TestClient,
        llm: _FakeLLM,
        handlers: _Handlers,
        org: str,
    ) -> None:
        owner = world.a["editor"]
        world.db.add_memory(owner.user_id, _KEY, _A_SECRET)
        viewer = (world.a if org == "a" else world.b)["viewer"]
        message = llm.script("Viewer: what is the plan?", _recall(), _list())

        response = _chat(client, viewer, message)

        _assert_refused_without_memory_access(world, response, llm, handlers)
        assert world.db.memories_of(owner.user_id) == {_KEY: _A_SECRET}

    def test_tenancy_memory_super_admin_is_refused_before_any_memory_access(
        self,
        world: World,
        client: TestClient,
        llm: _FakeLLM,
        handlers: _Handlers,
    ) -> None:
        """Operator blindness: the Super Admin can't reach any org's notes via the chat."""
        owner = world.a["editor"]
        world.db.add_memory(owner.user_id, _KEY, _A_SECRET)
        message = llm.script("Operator: what is the plan?", _recall(), _list())

        response = _chat(client, world.super_admin, message)

        _assert_refused_without_memory_access(world, response, llm, handlers)
        assert world.db.memories_of(owner.user_id) == {_KEY: _A_SECRET}
