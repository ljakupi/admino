"""Regression spec for GH-189 security audit F1 (contract Amendment A1, issue Decision 10):
a run with attachments completes its tool call against the database's audit CHECK.

The bug: migration 0005's ``audit_events_metadata_check`` refuses every array value and
caps the metadata at 4096 bytes, so PostgreSQL refused every ``tool.call`` row that
carries ``attachment_ids``. The agent dispatches first and records second, so each such
run aborted with "Internal error: audit unavailable." after its tool had run, leaving
no audit row. The suite missed it because tests/db_fakes.py didn't enforce that CHECK;
it now enforces the one the shipped migrations define.

What is pinned here, end to end: a real ``Agent`` with a scripted LLM that asks for an
allowed read (``memory.read``, no side effect, so attachments don't escalate it), the
recorder ``main._build_tool_call_recorder()`` builds, and the FakeDb as the runtime
pool. A run with 1 attachment and a run with 100 attachments both:

- finish (status ``final``) with the tool's result in the history: the handler ran
  once and the run went on to the LLM's answer;
- write exactly one ``tool.call`` row: the member's, on the run's chat, with today's six
  keys plus ``attachment_ids`` (the canonical ids in slot order) and
  ``attachment_count``.

The LLM and the database are fakes. No real PostgreSQL, provider or network is used.

Security notes: the dispatched call must leave its audit row (accountability); the row
holds attachment ids and a count only, never a file's name, kind or content.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Final
from unittest.mock import MagicMock

import pytest

import admino.main as main_module
from admino import models
from admino.agent import Agent
from admino.models import AgentConfig
from admino.tools import registry
from tests.db_fakes import FakeDb
from tests.test_tool_call_audit import (
    _CHAT_ID,
    _MEMBER,
    _ORG_ID,
    _OUTPUT_MARKER,
    _SESSION,
    _USER_ID,
    _read_handler,
    _ReadArgs,
    _ScriptedLLM,
    _tool_policy,
    _tool_then_text,
)

if TYPE_CHECKING:
    from admino.models import AgentResult

# 100 distinct ids in descending order, so a sorted copy differs from slot order.
_ATTACHMENT_IDS: Final[tuple[uuid.UUID, ...]] = tuple(
    uuid.UUID(f"{0xD0000000 - n:08x}-{n:04x}-4189-8000-{0x189F00000000 + n:012x}")
    for n in range(100)
)
_FILE_TEXT: Final = "Quarterly figures, page one."
_TODAYS_SIX: Final = frozenset(
    {"tool", "action", "decision", "success", "duration_ms", "escalated"}
)
_AUDIT_UNAVAILABLE: Final = "Internal error: audit unavailable."


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty, unfrozen registry for each test; the previous one is restored after."""
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setattr(registry, "_FROZEN", False)


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    """The FakeDb (with the member's org) as the runtime pool the recorder resolves."""
    fake = FakeDb()
    fake.add_org(_ORG_ID)
    monkeypatch.setattr("admino.database.get_pool", MagicMock(return_value=fake.pool))
    return fake


def _attachments(count: int) -> list[Any]:
    """``count`` text attachments in slot order."""
    return [
        models.AttachmentContent(
            id=_ATTACHMENT_IDS[n],
            filename=f"report-{n}.txt",
            kind="txt",
            page_count=None,
            parts=(models.TextContent(text=_FILE_TEXT),),
        )
        for n in range(count)
    ]


async def _run(count: int) -> AgentResult:
    """One run with ``count`` attachments whose LLM asks for memory.read, then answers."""
    registry.register_tool("memory", "read", "Read a note", _ReadArgs, side_effect=False)(
        _read_handler
    )
    agent = Agent(
        llm_client=_ScriptedLLM(_tool_then_text()),
        tool_call_recorder=main_module._build_tool_call_recorder(),
        agent_config=AgentConfig(
            max_tool_calls=5, max_context_messages=20, confirmation_timeout_s=60.0
        ),
    )
    return await agent.run(
        "go",
        session_id=_SESSION,
        history=[],
        principal=_MEMBER,
        tool_policy=_tool_policy(),
        attachments=_attachments(count),
    )


def _content_text(content: Any) -> str:
    """A message's content as text (a str, or the text of its parts)."""
    if isinstance(content, str):
        return content
    return " ".join(getattr(part, "text", "") for part in content or ())


class TestToolCallAuditWithAttachmentsPassesTheDatabaseCheck:
    """Security audit F1: the tool.call row of an attachment run is accepted."""

    @pytest.mark.parametrize("count", [1, 100])
    async def test_tool_call_audit_attachment_run_completes_its_tool_call(
        self, db: FakeDb, count: int
    ) -> None:
        """Not "audit unavailable": the tool ran, its result is in the history and the
        run reached the LLM's answer."""
        result = await _run(count)

        tool_texts = [_content_text(m.content) for m in result.history if m.role == "tool"]
        assert (result.status, result.response) == ("final", "Here it is.")
        assert len(tool_texts) == 1
        assert _OUTPUT_MARKER in tool_texts[0]
        assert _AUDIT_UNAVAILABLE not in result.response

    @pytest.mark.parametrize("count", [1, 100])
    async def test_tool_call_audit_attachment_run_writes_its_row_with_the_ids_and_count(
        self, db: FakeDb, count: int
    ) -> None:
        """One tool.call row: the member's, on the chat, today's six keys plus the ids in
        slot order and their count."""
        await _run(count)

        rows = [row for row in db.audit if row["action"] == "tool.call"]
        assert len(rows) == 1
        row = rows[0]
        metadata = row["metadata"]
        assert (row["org_id"], row["actor_user_id"], row["actor_kind"]) == (
            _ORG_ID,
            _USER_ID,
            "member",
        )
        assert (row["target_type"], row["target_ids"]) == ("chat", [str(_CHAT_ID)])
        assert set(metadata) == _TODAYS_SIX | {"attachment_ids", "attachment_count"}
        assert (metadata["tool"], metadata["action"], metadata["decision"]) == (
            "memory",
            "read",
            "allow",
        )
        assert metadata["success"] is True
        assert metadata["attachment_ids"] == [str(item) for item in _ATTACHMENT_IDS[:count]]
        assert metadata["attachment_count"] == count
