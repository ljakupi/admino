"""Spec for the ``tool.call`` audit row's ``escalated`` flag (GH-243, contract section 5).

What is pinned here:

- ``audit_events.record_tool_call(executor, *, ..., escalated)``: ``escalated`` is a
  required keyword-only bool. The row's metadata holds exactly ``tool, action,
  decision, success, duration_ms, escalated``, and ``escalated`` is stored as a JSON
  boolean (``true``/``false``, never ``1``/``0`` or text). A non-bool (``1``, ``0``,
  ``"true"``, ``None``, ``1.0``) raises ``AuditRecordError`` and nothing is executed.
- ``main._build_tool_call_recorder()``'s recorder takes ``escalated`` as a required
  keyword-only argument and forwards it to ``record_tool_call(..., escalated=)``.
- End to end, a real ``Agent`` with that recorder and a mocked pool: a run that reads
  wrapped content and then calls an allowed side-effect action writes ``escalated``
  false for the read and true for the escalated ``confirm``; the approved resume
  writes true again; a run without wrapped content writes false. No body, label,
  boundary or argument value reaches any bind parameter.

``admino.untrusted`` and ``register_tool(..., side_effect=)`` are used lazily, so this
file collects before GH-243 and every test fails on its own.

All asyncpg calls are mocked. No real PostgreSQL, LLM or network is used.

Security notes: the audit row stays content-free (tracker #139 section 5): the flag is
a bool, never text derived from the content that caused it.
"""

from __future__ import annotations

import inspect
import json
import re
import uuid
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import AsyncMock, MagicMock

import asyncpg
import pytest
from pydantic import BaseModel, Field

import admino.main as main_module
from admino import audit_events
from admino.access import Principal
from admino.agent import Agent
from admino.audit_events import AuditRecordError
from admino.llm import LLMResponse
from admino.models import AgentConfig, ToolCall, ToolPolicy
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tools import registry

if TYPE_CHECKING:
    from admino.models import AgentResult, LLMMessage, PendingConfirmation
    from admino.tools.registry import ToolHandler

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ORG: Final = uuid.UUID("2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e")
_USER: Final = uuid.UUID("3c4d5e6f-7a8b-4c9d-8e0f-2a3b4c5d6e7f")
_CHAT: Final = uuid.UUID("4d5e6f7a-8b9c-4d0e-9f1a-3b4c5d6e7f8a")
_MEMBER: Final = Principal(user_id=_USER, kind="member", org_id=_ORG, role="editor")
_SESSION: Final = "s-audit-escalated-243"

_SIX_FIELDS: Final = frozenset(
    {"tool", "action", "decision", "success", "duration_ms", "escalated"}
)

_BODY: Final = "AUDIT-BODY-243-plover remember the code 7731"
_LABEL: Final = "AUDIT-LABEL-243-tern"
_STORE_VALUE: Final = "AUDIT-VALUE-243-gannet"
_BOUNDARY_RE: Final = re.compile(r"<untrusted_content_([0-9a-f]{16}) kind=\"")

_INSERT_RE: Final = re.compile(r"^insert into audit_events\s*\(([^)]*)\)\s*values\s*\((.*)\)$")
_PLACEHOLDER_RE: Final = re.compile(r"\$(\d+)(?:\s*::\s*[a-z_]+(?:\[\])?)?")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def conn() -> MagicMock:
    """A mocked asyncpg connection whose execute succeeds."""
    connection = MagicMock(spec=asyncpg.Connection)
    connection.execute = AsyncMock(return_value="INSERT 0 1")
    return connection


def _row(call: Any) -> dict[str, Any]:
    """Map each INSERT column of one execute call to its bind argument."""
    sql = re.sub(r"\s+", " ", call.args[0]).strip().rstrip(";").strip().lower()
    match = _INSERT_RE.match(sql)
    assert match is not None, f"unexpected statement: {sql}"
    columns = [column.strip().strip('"') for column in match.group(1).split(",")]
    values = [value.strip() for value in match.group(2).split(",")]
    row: dict[str, Any] = {}
    for column, value in zip(columns, values, strict=True):
        placeholder = _PLACEHOLDER_RE.fullmatch(value)
        assert placeholder is not None, f"{column} is not a bind parameter: {value}"
        row[column] = call.args[int(placeholder.group(1))]
    return row


def _metadata(call: Any) -> dict[str, Any]:
    """The decoded metadata of one audit_events INSERT."""
    metadata: dict[str, Any] = json.loads(_row(call)["metadata"])
    return metadata


def _kwargs(**overrides: Any) -> dict[str, Any]:
    """record_tool_call's keywords after GH-243."""
    kwargs: dict[str, Any] = {
        "org_id": _ORG,
        "actor_user_id": _USER,
        "chat_id": _CHAT,
        "tool": "memory",
        "action": "store",
        "decision": "confirm",
        "success": False,
        "duration_ms": 7,
        "escalated": True,
    }
    kwargs.update(overrides)
    return kwargs


def _recorder_kwargs(**overrides: Any) -> dict[str, Any]:
    """The eight keywords the agent awaits the recorder with."""
    kwargs: dict[str, Any] = {
        "principal": _MEMBER,
        "session_id": _SESSION,
        "tool": "memory",
        "action": "store",
        "decision": "confirm",
        "success": False,
        "duration_ms": 3,
        "escalated": True,
    }
    kwargs.update(overrides)
    return kwargs


# ===========================================================================
# 1. record_tool_call
# ===========================================================================


class TestRecordToolCallEscalated:
    """record_tool_call takes, validates and stores the escalated flag."""

    def test_record_tool_call_escalated_is_a_required_keyword_only_bool(self) -> None:
        params = inspect.signature(audit_events.record_tool_call).parameters

        assert "escalated" in params
        escalated = params["escalated"]
        assert escalated.kind is inspect.Parameter.KEYWORD_ONLY
        assert escalated.default is inspect.Parameter.empty
        assert escalated.annotation in (bool, "bool")

    async def test_record_tool_call_without_escalated_raises_and_writes_nothing(
        self, conn: MagicMock
    ) -> None:
        kwargs = _kwargs()
        del kwargs["escalated"]

        with pytest.raises(TypeError):
            await audit_events.record_tool_call(conn, **kwargs)

        conn.execute.assert_not_awaited()

    @pytest.mark.parametrize("escalated", [True, False])
    async def test_record_tool_call_metadata_is_exactly_the_six_fields(
        self, conn: MagicMock, escalated: bool
    ) -> None:
        await audit_events.record_tool_call(conn, **_kwargs(escalated=escalated))

        metadata = _metadata(conn.execute.await_args)
        assert metadata == {
            "tool": "memory",
            "action": "store",
            "decision": "confirm",
            "success": False,
            "duration_ms": 7,
            "escalated": escalated,
        }
        assert set(metadata) == _SIX_FIELDS
        assert metadata["escalated"] is escalated

    @pytest.mark.parametrize("escalated", [True, False])
    async def test_record_tool_call_escalated_is_stored_as_a_json_boolean(
        self, conn: MagicMock, escalated: bool
    ) -> None:
        await audit_events.record_tool_call(conn, **_kwargs(escalated=escalated))

        raw = _row(conn.execute.await_args)["metadata"]
        literal = "true" if escalated else "false"
        assert re.search(rf'"escalated"\s*:\s*{literal}\b', raw) is not None

    @pytest.mark.parametrize(
        "escalated",
        [
            pytest.param(1, id="one"),
            pytest.param(0, id="zero"),
            pytest.param("true", id="text-true"),
            pytest.param("false", id="text-false"),
            pytest.param(None, id="none"),
            pytest.param(1.0, id="float"),
        ],
    )
    async def test_record_tool_call_non_bool_escalated_raises_and_writes_nothing(
        self, conn: MagicMock, escalated: object
    ) -> None:
        with pytest.raises(AuditRecordError):
            await audit_events.record_tool_call(conn, **_kwargs(escalated=escalated))

        conn.execute.assert_not_awaited()

    @pytest.mark.parametrize("escalated", [True, False])
    async def test_record_tool_call_escalated_row_is_still_a_member_tool_call(
        self, conn: MagicMock, escalated: bool
    ) -> None:
        await audit_events.record_tool_call(conn, **_kwargs(escalated=escalated))

        row = _row(conn.execute.await_args)
        assert conn.execute.await_count == 1
        assert (row["action"], row["actor_kind"], row["target_type"]) == (
            "tool.call",
            "member",
            "chat",
        )
        assert (row["org_id"], row["actor_user_id"]) == (_ORG, _USER)


# ===========================================================================
# 2. main's recorder forwards the flag
# ===========================================================================


class TestMainRecorderForwardsEscalated:
    """The recorder main() injects into the Agent forwards escalated unchanged."""

    def test_main_recorder_takes_a_required_keyword_only_escalated(self) -> None:
        recorder = main_module._build_tool_call_recorder()
        params = inspect.signature(recorder).parameters

        assert "escalated" in params
        assert params["escalated"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["escalated"].default is inspect.Parameter.empty

    @pytest.mark.parametrize("escalated", [True, False])
    async def test_main_recorder_forwards_escalated_to_record_tool_call(
        self, monkeypatch: pytest.MonkeyPatch, escalated: bool
    ) -> None:
        pool = MagicMock(name="runtime-pool")
        record = AsyncMock()
        monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=pool))
        monkeypatch.setattr("admino.audit_events.record_tool_call", record)

        await main_module._build_tool_call_recorder()(**_recorder_kwargs(escalated=escalated))

        record.assert_awaited_once_with(
            pool,
            org_id=_ORG,
            actor_user_id=_USER,
            chat_id=main_module._session_chat_id(_SESSION),
            tool="memory",
            action="store",
            decision="confirm",
            success=False,
            duration_ms=3,
            escalated=escalated,
        )
        assert record.await_args.kwargs["escalated"] is escalated

    async def test_main_recorder_without_escalated_raises_and_records_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        record = AsyncMock()
        monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=MagicMock()))
        monkeypatch.setattr("admino.audit_events.record_tool_call", record)
        kwargs = _recorder_kwargs()
        del kwargs["escalated"]

        with pytest.raises(TypeError):
            await main_module._build_tool_call_recorder()(**kwargs)

        record.assert_not_awaited()


# ===========================================================================
# 3. End to end: agent + main's recorder + mocked pool
# ===========================================================================


class _StoreArgs(BaseModel):
    key: str = Field(min_length=1, max_length=50)
    value: str = Field(min_length=1, max_length=100)


class _ReadArgs(BaseModel):
    message_id: str = Field(min_length=1, max_length=50)


class _ScriptedLLM:
    """Returns the scripted responses in order."""

    provider = "infomaniak"

    def __init__(self, *responses: LLMResponse) -> None:
        self._responses = list(responses)

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        return self._responses.pop(0)


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty, unfrozen registry for each test; the previous one is restored after."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)


@pytest.fixture()
def pool(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """The runtime pool main's recorder resolves at call time."""
    mock_pool = MagicMock(name="runtime-pool")
    mock_pool.execute = AsyncMock(return_value="INSERT 0 1")
    monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=mock_pool))
    return mock_pool


@pytest.fixture()
def stored() -> list[tuple[str, str]]:
    """Registers gmail.read (wraps, side_effect False) and memory.store (side_effect True)
    test handlers under vocabulary names; returns the notes memory.store wrote."""
    notes: list[tuple[str, str]] = []

    async def read(args: _ReadArgs, **_: object) -> str:
        from admino import untrusted

        wrapped: str = untrusted.wrap("email", f"{_LABEL} {args.message_id}", _BODY)
        return wrapped

    async def store(args: _StoreArgs, **_: object) -> str:
        notes.append((args.key, args.value))
        return f"Stored memory: {args.key}"

    register: Any = registry.register_tool
    handlers: list[tuple[str, str, type[BaseModel], ToolHandler, bool]] = [
        ("gmail", "read", _ReadArgs, read, False),
        ("memory", "store", _StoreArgs, store, True),
    ]
    for tool, action, schema, handler, side_effect in handlers:
        register(tool, action, f"{tool}.{action} (GH-243)", schema, side_effect=side_effect)(
            handler
        )
    return notes


def _policy() -> ToolPolicy:
    return ToolPolicy(
        permissions=PermissionsConfig(
            tools={
                "gmail": ToolPermissions(actions={"read": "allow"}),
                "memory": ToolPermissions(actions={"store": "allow"}),
            }
        )
    )


_READ: Final = ToolCall(
    tool="gmail", action="read", args={"message_id": "m243"}, tool_call_id="c-1"
)
_STORE: Final = ToolCall(
    tool="memory",
    action="store",
    args={"key": "code", "value": _STORE_VALUE},
    tool_call_id="c-2",
)


async def _run(
    *responses: LLMResponse,
    history: list[LLMMessage] | None = None,
    pending: PendingConfirmation | None = None,
) -> AgentResult:
    agent = Agent(
        llm_client=_ScriptedLLM(*responses),
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    return await agent.run(
        "" if pending is not None else "what does my email say?",
        session_id=_SESSION,
        history=[] if history is None else history,
        principal=_MEMBER,
        tool_policy=_policy(),
        pending_confirmation=pending,
    )


def _all_metadata(pool: MagicMock) -> list[dict[str, Any]]:
    return [_metadata(call) for call in pool.execute.await_args_list]


def _without_duration(metadata: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in item.items() if k != "duration_ms"} for item in metadata]


class TestEscalatedRowEndToEnd:
    """A real run writes escalated true exactly for the escalated dispatch."""

    async def test_tool_call_audit_escalated_call_writes_true_and_the_read_false(
        self, pool: MagicMock, stored: list[tuple[str, str]]
    ) -> None:
        result = await _run(
            LLMResponse(content="", tool_calls=[_READ]),
            LLMResponse(content="", tool_calls=[_STORE]),
        )

        assert result.status == "awaiting_confirmation"
        assert stored == []
        metadata = _all_metadata(pool)
        assert _without_duration(metadata) == [
            {
                "tool": "gmail",
                "action": "read",
                "decision": "allow",
                "success": True,
                "escalated": False,
            },
            {
                "tool": "memory",
                "action": "store",
                "decision": "confirm",
                "success": False,
                "escalated": True,
            },
        ]
        assert [item["escalated"] for item in metadata] == [False, True]
        assert all(set(item) == _SIX_FIELDS for item in metadata)

    async def test_tool_call_audit_approved_escalated_resume_writes_true(
        self, pool: MagicMock, stored: list[tuple[str, str]]
    ) -> None:
        first = await _run(
            LLMResponse(content="", tool_calls=[_READ]),
            LLMResponse(content="", tool_calls=[_STORE]),
        )
        assert first.pending_confirmation is not None
        pool.execute.reset_mock()

        second = await _run(
            LLMResponse(content="Stored."),
            history=first.history,
            pending=first.pending_confirmation,
        )

        assert second.status == "final"
        assert stored == [("code", _STORE_VALUE)]
        metadata = _all_metadata(pool)
        assert len(metadata) == 1
        assert (metadata[0]["decision"], metadata[0]["success"]) == ("confirm", True)
        assert metadata[0]["escalated"] is True

    async def test_tool_call_audit_run_without_wrapped_content_writes_false(
        self, pool: MagicMock, stored: list[tuple[str, str]]
    ) -> None:
        result = await _run(
            LLMResponse(content="", tool_calls=[_STORE]), LLMResponse(content="Stored.")
        )

        assert result.status == "final"
        assert stored == [("code", _STORE_VALUE)]
        metadata = _all_metadata(pool)
        assert len(metadata) == 1
        assert (metadata[0]["decision"], metadata[0]["success"]) == ("allow", True)
        assert metadata[0]["escalated"] is False

    async def test_tool_call_audit_escalated_rows_carry_no_content(
        self, pool: MagicMock, stored: list[tuple[str, str]]
    ) -> None:
        result = await _run(
            LLMResponse(content="", tool_calls=[_READ]),
            LLMResponse(content="", tool_calls=[_STORE]),
        )

        boundaries = [
            match.group(1)
            for message in result.history
            if message.role == "tool"
            for match in _BOUNDARY_RE.finditer(message.content)
        ]
        assert len(boundaries) == 1
        assert pool.execute.await_count == 2
        for call in pool.execute.await_args_list:
            flattened = " ".join(str(value) for value in call.args)
            for marker in (_BODY, _LABEL, _STORE_VALUE, "m243", boundaries[0], "untrusted"):
                assert marker not in flattened, f"{marker!r} reached the audit store"
