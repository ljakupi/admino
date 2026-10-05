"""End-to-end spec for tool-call auditing and the NDJSON log removal (GH-147, GH-149).

A real ``Agent`` runs one tool call through the real registry, wired to the
recorder ``main._build_tool_call_recorder()`` builds, with the database pool
mocked. What these tests pin down:

- A tool call by a logged-in member writes exactly one ``audit_events`` row
  through one parameterized INSERT: action ``tool.call``, actor kind ``member``
  with the member's ``actor_user_id``, the member's ``org_id``, the session's
  chat as target, and metadata with exactly ``tool, action, decision, success,
  duration_ms, escalated`` (GH-243 added ``escalated``). The tool's argument values
  and its output appear in no bind parameter.
- GH-149 retires #147's default-org bridge: the default org's id
  (``00000000-0000-4000-8000-000000000001``; GH-154 removed the constant) appears
  in no bind parameter, and a principal without an organization (a Super Admin)
  can't write a tool.call row, so the run aborts (H-1) and nothing is written.
- ``Agent.run`` takes the caller's ``principal`` as a required keyword and the
  agent passes it to the recorder with the seven content-free fields (GH-243 added
  ``escalated``). GH-161: every run also passes its org's ``tool_policy`` (the
  agent holds no permissions).
- A turn without a tool call writes nothing (conversation entries are gone).
- GH-162: the member's run reaches the tool handler with the member's own
  ``TenantContext`` (``tenant=``); a Super Admin's run (no organization, so no
  tool context) never reaches the handler at all, and still ends with the
  fixed audit error with nothing written.
- The NDJSON audit log is gone: ``admino.audit`` doesn't exist, no source file
  names an ``.ndjson`` file, and a full run with a tool call creates no
  ``.ndjson`` file.

All asyncpg calls are mocked. No real PostgreSQL connections are made.

Security notes:
- No content in audit events (tracker #139 §5): argument values and tool output
  must never reach the audit store.
- Tenant isolation: each row lands in the acting member's org, never in a
  shared default org.
"""

from __future__ import annotations

import importlib
import inspect
import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811
from pydantic import BaseModel, Field

import admino.main as main_module
from admino.access import Principal
from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import AgentConfig, ToolCall
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tenancy import TenantContext
from admino.tools.registry import clear_registry, register_tool

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator

    from admino.models import LLMMessage

_SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "admino"
_SESSION = "s-e2e-4b1c"
_ARG_MARKER = "SECRET-ARG-7f3a"
_OUTPUT_MARKER = "SECRET-OUTPUT-91bc"
_USER_ID = uuid.UUID("4d5e6f70-8192-4a3b-9c4d-5e6f7a8b9c0d")
_ORG_ID = uuid.UUID("e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b")
# #147's default organization (GH-154 removed accounts.DEFAULT_ORG_ID).
_DEFAULT_ORG_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
_MEMBER = Principal(user_id=_USER_ID, kind="member", org_id=_ORG_ID, role="editor")
_SUPER_ADMIN = Principal(user_id=_USER_ID, kind="super_admin")


class _ScriptedLLM:
    """Returns the scripted responses in order."""

    provider = "infomaniak"

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        return self._responses.pop(0)


class _ReadArgs(BaseModel):
    key: str = Field(min_length=1, max_length=200)


async def _read_handler(args: _ReadArgs, *, session_id: str, **_: object) -> str:
    return f"{_OUTPUT_MARKER}:{args.key}"


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    clear_registry()
    yield
    clear_registry()


@pytest.fixture()
def pool(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """The runtime pool the recorder resolves at call time."""
    mock_pool = MagicMock(name="runtime-pool")
    mock_pool.execute = AsyncMock(return_value="INSERT 0 1")
    monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=mock_pool))
    return mock_pool


def _agent(
    responses: list[LLMResponse],
    recorder: Any = None,
    handler: Callable[..., Awaitable[str]] = _read_handler,
) -> Agent:
    """A real Agent (GH-161 constructor: no permission state of its own)."""
    register_tool("memory", "read", "Read a note", _ReadArgs)(handler)
    return Agent(
        llm_client=_ScriptedLLM(responses),
        tool_call_recorder=recorder or main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )


def _tool_policy() -> Any:
    """The run's ToolPolicy (GH-161): memory.read allowed. Imported lazily so each test
    fails on its own until models.ToolPolicy exists."""
    from admino.models import ToolPolicy

    return ToolPolicy(
        permissions=PermissionsConfig(tools={"memory": ToolPermissions(actions={"read": "allow"})})
    )


def _tool_then_text() -> list[LLMResponse]:
    call = ToolCall(tool="memory", action="read", args={"key": _ARG_MARKER}, tool_call_id="call-1")
    return [
        LLMResponse(content="", tool_calls=[call]),
        LLMResponse(content="Here it is."),
    ]


class TestToolCallWritesOneRow:
    """A tool call writes exactly one tool.call row, with no arguments or output."""

    @pytest.mark.asyncio
    async def test_one_insert_per_tool_call(self, pool: MagicMock) -> None:
        result = await _agent(_tool_then_text()).run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        assert result.status == "final"
        assert pool.execute.await_count == 1
        sql = pool.execute.await_args.args[0]
        assert "INSERT INTO audit_events" in sql

    @pytest.mark.asyncio
    async def test_row_is_a_member_tool_call_in_the_members_org_on_the_chat(
        self, pool: MagicMock
    ) -> None:
        """actor_kind member, the member's user id and org, the session's chat."""
        await _agent(_tool_then_text()).run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        params = pool.execute.await_args.args[1:]
        org_id, actor_user_id, actor_kind, action, target_type, target_ids = params[:6]
        assert org_id == _ORG_ID
        assert actor_user_id == _USER_ID
        assert actor_kind == "member"
        assert action == "tool.call"
        assert target_type == "chat"
        assert json.loads(target_ids) == [str(main_module._session_chat_id(_SESSION))]

    @pytest.mark.asyncio
    async def test_row_follows_the_principal_of_each_run(self, pool: MagicMock) -> None:
        """Two members of two orgs: each row carries its own caller's org and user."""
        other = Principal(
            user_id=uuid.uuid4(), kind="member", org_id=uuid.uuid4(), role="org_admin"
        )
        agent = _agent([*_tool_then_text(), *_tool_then_text()])

        await agent.run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )
        await agent.run(
            "go", session_id="s-other", history=[], principal=other, tool_policy=_tool_policy()
        )

        rows = [call.args[1:3] for call in pool.execute.await_args_list]
        assert rows == [(_ORG_ID, _USER_ID), (other.org_id, other.user_id)]

    @pytest.mark.asyncio
    async def test_member_built_from_asyncpg_uuids_is_recorded(self, pool: MagicMock) -> None:
        """A Principal built from a users row (asyncpg UUIDs) records its org and user."""
        member = Principal(
            user_id=PgUUID(str(_USER_ID)),
            kind="member",
            org_id=PgUUID(str(_ORG_ID)),
            role="editor",
        )

        result = await _agent(_tool_then_text()).run(
            "go", session_id=_SESSION, history=[], principal=member, tool_policy=_tool_policy()
        )

        assert result.status == "final"
        org_id, actor_user_id = pool.execute.await_args.args[1:3]
        assert (org_id, actor_user_id) == (_ORG_ID, _USER_ID)

    @pytest.mark.asyncio
    async def test_default_org_is_in_no_bind_parameter(self, pool: MagicMock) -> None:
        """#147's bridge is retired: the default org's id never reaches the audit store."""
        await _agent(_tool_then_text()).run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        assert pool.execute.await_count == 1
        for call in pool.execute.await_args_list:
            assert _DEFAULT_ORG_ID not in call.args
            assert str(_DEFAULT_ORG_ID) not in " ".join(str(value) for value in call.args)

    @pytest.mark.asyncio
    async def test_metadata_holds_exactly_the_six_decision_fields(self, pool: MagicMock) -> None:
        await _agent(_tool_then_text()).run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        metadata = json.loads(pool.execute.await_args.args[-1])
        assert set(metadata) == {
            "tool",
            "action",
            "decision",
            "success",
            "duration_ms",
            "escalated",
        }
        assert metadata["tool"] == "memory"
        assert metadata["action"] == "read"
        assert metadata["decision"] == "allow"
        assert metadata["success"] is True
        assert isinstance(metadata["duration_ms"], int)
        assert metadata["duration_ms"] >= 0

    @pytest.mark.asyncio
    async def test_no_argument_or_output_value_in_any_bind_parameter(self, pool: MagicMock) -> None:
        result = await _agent(_tool_then_text()).run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        # The tool really ran and produced the marked output...
        assert any(_OUTPUT_MARKER in m.content for m in result.history if m.role == "tool")
        # ...but neither the argument nor the output reached the audit store.
        for call in pool.execute.await_args_list:
            flattened = " ".join(str(value) for value in call.args)
            assert _ARG_MARKER not in flattened
            assert _OUTPUT_MARKER not in flattened

    @pytest.mark.asyncio
    async def test_turn_without_tool_call_writes_nothing(self, pool: MagicMock) -> None:
        """Per-turn conversation entries are dropped without replacement."""
        result = await _agent([LLMResponse(content="Hello.")]).run(
            "hi", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        assert result.status == "final"
        pool.execute.assert_not_awaited()


class TestAuditFailureAbortsTheRun:
    """H-1: a failed tool.call write aborts the run."""

    @pytest.mark.asyncio
    async def test_write_failure_aborts_with_audit_unavailable(self, pool: MagicMock) -> None:
        pool.execute.side_effect = OSError("connection reset")

        result = await _agent(_tool_then_text()).run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        assert result.status == "error"
        assert result.response == "Internal error: audit unavailable."
        assert result.pending_confirmation is None


class TestPrincipalReachesTheRecorder:
    """The run's principal is required and handed to the recorder unchanged."""

    def test_run_requires_principal_keyword(self) -> None:
        """Agent.run(..., *, principal) — keyword-only, no default."""
        parameter = inspect.signature(Agent.run).parameters["principal"]

        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty

    @pytest.mark.asyncio
    async def test_recorder_gets_the_principal_and_seven_content_free_fields(self) -> None:
        """The agent awaits the recorder with exactly eight keywords: the principal plus
        session_id, tool, action, decision, success, duration_ms and escalated (GH-243)."""
        recorder = AsyncMock()

        await _agent(_tool_then_text(), recorder).run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        recorder.assert_awaited_once()
        assert recorder.await_args.args == ()
        kwargs = recorder.await_args.kwargs
        assert set(kwargs) == {
            "principal",
            "session_id",
            "tool",
            "action",
            "decision",
            "success",
            "duration_ms",
            "escalated",
        }
        assert kwargs["principal"] is _MEMBER
        assert (kwargs["session_id"], kwargs["tool"], kwargs["action"]) == (
            _SESSION,
            "memory",
            "read",
        )


class TestNoOrgNoToolCall:
    """A principal without an organization can't write a tool.call row: the run aborts."""

    @pytest.mark.asyncio
    async def test_super_admin_run_aborts_with_audit_unavailable(self, pool: MagicMock) -> None:
        """A Super Admin has no TenantContext, so the recorder raises and the agent aborts
        the run (H-1) with the fixed message and no pending confirmation."""
        result = await _agent(_tool_then_text()).run(
            "go",
            session_id=_SESSION,
            history=[],
            principal=_SUPER_ADMIN,
            tool_policy=_tool_policy(),
        )

        assert result.status == "error"
        assert result.response == "Internal error: audit unavailable."
        assert result.pending_confirmation is None

    @pytest.mark.asyncio
    async def test_super_admin_run_writes_nothing(self, pool: MagicMock) -> None:
        """No row lands anywhere: not in a default org, not without an org."""
        await _agent(_tool_then_text()).run(
            "go",
            session_id=_SESSION,
            history=[],
            principal=_SUPER_ADMIN,
            tool_policy=_tool_policy(),
        )

        pool.execute.assert_not_awaited()


class TestToolContextReachesTheHandler:
    """GH-162: the handler gets the run's tool context, built from the principal."""

    @pytest.mark.asyncio
    async def test_member_run_hands_the_handler_the_members_tenant(self, pool: MagicMock) -> None:
        """The member's run dispatches with TenantContext.from_principal(member): the
        handler sees the member's user_id and org_id, and the call is audited once."""
        seen: list[Any] = []

        async def tenant_handler(args: _ReadArgs, **kwargs: Any) -> str:
            seen.append(kwargs.get("tenant"))
            return f"{_OUTPUT_MARKER}:{args.key}"

        result = await _agent(_tool_then_text(), handler=tenant_handler).run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        assert result.status == "final"
        assert seen == [TenantContext.from_principal(_MEMBER)]
        assert (seen[0].user_id, seen[0].org_id) == (_USER_ID, _ORG_ID)
        assert pool.execute.await_count == 1

    @pytest.mark.asyncio
    async def test_super_admin_run_never_reaches_the_handler(self, pool: MagicMock) -> None:
        """No organization, no tool context: the handler never runs, and the run still
        ends with the fixed audit error with nothing written."""
        seen: list[Any] = []

        async def tenant_handler(args: _ReadArgs, **kwargs: Any) -> str:
            seen.append(kwargs.get("tenant"))
            return f"{_OUTPUT_MARKER}:{args.key}"

        result = await _agent(_tool_then_text(), handler=tenant_handler).run(
            "go",
            session_id=_SESSION,
            history=[],
            principal=_SUPER_ADMIN,
            tool_policy=_tool_policy(),
        )

        assert seen == []
        assert (result.status, result.response) == (
            "error",
            "Internal error: audit unavailable.",
        )
        pool.execute.assert_not_awaited()


class TestNoNdjsonAuditLog:
    """Nothing writes an .ndjson file any more."""

    def test_ndjson_audit_module_is_gone(self) -> None:
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("admino.audit")

    def test_no_source_file_names_an_ndjson_file(self) -> None:
        offenders = [
            str(path.relative_to(_SRC_DIR))
            for path in _SRC_DIR.rglob("*.py")
            if ".ndjson" in path.read_text(encoding="utf-8").lower()
        ]
        assert offenders == []

    @pytest.mark.asyncio
    async def test_a_run_with_a_tool_call_creates_no_ndjson_file(
        self, pool: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)

        await _agent(_tool_then_text()).run(
            "go", session_id=_SESSION, history=[], principal=_MEMBER, tool_policy=_tool_policy()
        )

        assert list(tmp_path.rglob("*.ndjson")) == []
