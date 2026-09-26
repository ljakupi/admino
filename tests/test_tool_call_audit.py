"""End-to-end spec for tool-call auditing and the NDJSON log removal (GH-147).

A real ``Agent`` runs one tool call through the real registry, wired to the
recorder ``main._build_tool_call_recorder()`` builds, with the database pool
mocked. What these tests pin down:

- A tool call writes exactly one ``audit_events`` row through one parameterized
  INSERT: action ``tool.call``, a system actor, the default org, the session's
  chat as target, and metadata with exactly ``tool, action, decision, success,
  duration_ms``. The tool's argument values and its output appear in no bind
  parameter.
- A turn without a tool call writes nothing (conversation entries are gone).
- The NDJSON audit log is gone: ``admino.audit`` doesn't exist, no source file
  names an ``.ndjson`` file, and a full run with a tool call creates no
  ``.ndjson`` file.

All asyncpg calls are mocked. No real PostgreSQL connections are made.

Security notes:
- No content in audit events (tracker #139 §5): argument values and tool output
  must never reach the audit store.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import BaseModel, Field

import admino.main as main_module
from admino.agent import Agent
from admino.llm import LLMResponse
from admino.models import AgentConfig, ToolCall
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tools.registry import clear_registry, register_tool

if TYPE_CHECKING:
    from collections.abc import Generator

    from admino.models import LLMMessage

_SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "admino"
_SESSION = "s-e2e-4b1c"
_ARG_MARKER = "SECRET-ARG-7f3a"
_OUTPUT_MARKER = "SECRET-OUTPUT-91bc"


class _ScriptedLLM:
    """Returns the scripted responses in order."""

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


async def _read_handler(args: _ReadArgs, *, session_id: str) -> str:
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


def _agent(responses: list[LLMResponse]) -> Agent:
    register_tool("memory", "read", "Read a note", _ReadArgs)(_read_handler)
    permissions = PermissionsConfig(tools={"memory": ToolPermissions(actions={"read": "allow"})})
    return Agent(
        llm_client=_ScriptedLLM(responses),
        tool_call_recorder=main_module._build_tool_call_recorder(),
        permissions_config=permissions,
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
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
        result = await _agent(_tool_then_text()).run("go", session_id=_SESSION, history=[])

        assert result.status == "final"
        assert pool.execute.await_count == 1
        sql = pool.execute.await_args.args[0]
        assert "INSERT INTO audit_events" in sql

    @pytest.mark.asyncio
    async def test_row_is_a_system_tool_call_in_the_default_org_on_the_chat(
        self, pool: MagicMock
    ) -> None:
        from admino.accounts import DEFAULT_ORG_ID

        await _agent(_tool_then_text()).run("go", session_id=_SESSION, history=[])

        params = pool.execute.await_args.args[1:]
        org_id, actor_user_id, actor_kind, action, target_type, target_ids = params[:6]
        assert org_id == DEFAULT_ORG_ID
        assert actor_user_id is None
        assert actor_kind == "system"
        assert action == "tool.call"
        assert target_type == "chat"
        assert json.loads(target_ids) == [str(main_module._session_chat_id(_SESSION))]

    @pytest.mark.asyncio
    async def test_metadata_holds_exactly_the_five_decision_fields(self, pool: MagicMock) -> None:
        await _agent(_tool_then_text()).run("go", session_id=_SESSION, history=[])

        metadata = json.loads(pool.execute.await_args.args[-1])
        assert set(metadata) == {"tool", "action", "decision", "success", "duration_ms"}
        assert metadata["tool"] == "memory"
        assert metadata["action"] == "read"
        assert metadata["decision"] == "allow"
        assert metadata["success"] is True
        assert isinstance(metadata["duration_ms"], int)
        assert metadata["duration_ms"] >= 0

    @pytest.mark.asyncio
    async def test_no_argument_or_output_value_in_any_bind_parameter(self, pool: MagicMock) -> None:
        result = await _agent(_tool_then_text()).run("go", session_id=_SESSION, history=[])

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
            "hi", session_id=_SESSION, history=[]
        )

        assert result.status == "final"
        pool.execute.assert_not_awaited()


class TestAuditFailureAbortsTheRun:
    """H-1: a failed tool.call write aborts the run."""

    @pytest.mark.asyncio
    async def test_write_failure_aborts_with_audit_unavailable(self, pool: MagicMock) -> None:
        pool.execute.side_effect = OSError("connection reset")

        result = await _agent(_tool_then_text()).run("go", session_id=_SESSION, history=[])

        assert result.status == "error"
        assert result.response == "Internal error: audit unavailable."
        assert result.pending_confirmation is None


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

        await _agent(_tool_then_text()).run("go", session_id=_SESSION, history=[])

        assert list(tmp_path.rglob("*.ndjson")) == []
