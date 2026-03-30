"""Tests for admino.models — Pydantic model validation, constraints, and serialization.

Covers every model in models.py:
- Audit log models (ConversationAuditEntry, ToolCallAuditEntry, AuditEntry union)
- API models (ChatMessage, ChatRequest, ChatResponse, ToolCallRecord, ConfirmRequest, SSEEvent)
- Agent/LLM models (ToolCall, LLMMessage, AgentConfig, PendingConfirmation)
- JSON round-trip serialization
- Security: no secret-bearing field names
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from admino.models import (
    AgentConfig,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ConfirmRequest,
    ConversationAuditEntry,
    LLMMessage,
    PendingConfirmation,
    SSEEvent,
    ToolCall,
    ToolCallAuditEntry,
    ToolCallRecord,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW: datetime = datetime.now(UTC)
_EXPIRES: datetime = _NOW + timedelta(seconds=30)


def _make_conversation_entry(**overrides: object) -> ConversationAuditEntry:
    """Build a valid ConversationAuditEntry with optional overrides."""
    defaults: dict[str, object] = {
        "session_id": "sess-001",
        "role": "user",
        "content": "Hello",
        "model": "llama3",
        "tool_calls_count": 0,
    }
    defaults.update(overrides)
    return ConversationAuditEntry(**defaults)  # type: ignore[arg-type]


def _make_tool_call_entry(**overrides: object) -> ToolCallAuditEntry:
    """Build a valid ToolCallAuditEntry with optional overrides."""
    defaults: dict[str, object] = {
        "session_id": "sess-001",
        "tool": "gmail",
        "action": "read",
        "permission": "allow",
        "args_summary": "message_id=123",
        "success": True,
    }
    defaults.update(overrides)
    return ToolCallAuditEntry(**defaults)  # type: ignore[arg-type]


def _make_tool_call(**overrides: object) -> ToolCall:
    """Build a valid ToolCall with optional overrides."""
    defaults: dict[str, object] = {
        "tool": "gmail",
        "action": "read",
        "args": {"message_id": "123"},
    }
    defaults.update(overrides)
    return ToolCall(**defaults)  # type: ignore[arg-type]


# ===========================================================================
# ConversationAuditEntry
# ===========================================================================


class TestConversationAuditEntry:
    """Tests for the ConversationAuditEntry audit model."""

    def test_valid_construction(self) -> None:
        entry = _make_conversation_entry()
        assert entry.entry_type == "conversation"
        assert entry.role == "user"
        assert entry.content == "Hello"
        assert entry.model == "llama3"
        assert entry.tool_calls_count == 0

    def test_entry_type_fixed_to_conversation(self) -> None:
        entry = _make_conversation_entry()
        assert entry.entry_type == "conversation"

    def test_entry_type_rejects_other_values(self) -> None:
        with pytest.raises(ValidationError):
            _make_conversation_entry(entry_type="tool_call")

    def test_timestamp_auto_set_utc(self) -> None:
        before = datetime.now(UTC)
        entry = _make_conversation_entry()
        after = datetime.now(UTC)
        assert entry.timestamp.tzinfo is not None
        assert before <= entry.timestamp <= after

    @pytest.mark.parametrize("role", ["user", "assistant"])
    def test_role_accepts_valid(self, role: str) -> None:
        entry = _make_conversation_entry(role=role)
        assert entry.role == role

    @pytest.mark.parametrize("role", ["system", "tool", "admin", ""])
    def test_role_rejects_invalid(self, role: str) -> None:
        with pytest.raises(ValidationError):
            _make_conversation_entry(role=role)

    def test_content_max_length(self) -> None:
        entry = _make_conversation_entry(content="x" * 32768)
        assert len(entry.content) == 32768

    def test_content_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            _make_conversation_entry(content="x" * 32769)

    def test_session_id_max_length(self) -> None:
        entry = _make_conversation_entry(session_id="a" * 64)
        assert len(entry.session_id) == 64

    def test_session_id_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            _make_conversation_entry(session_id="a" * 65)

    def test_model_max_length(self) -> None:
        entry = _make_conversation_entry(model="m" * 128)
        assert len(entry.model) == 128

    def test_model_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            _make_conversation_entry(model="m" * 129)

    def test_tool_calls_count_ge_zero(self) -> None:
        entry = _make_conversation_entry(tool_calls_count=0)
        assert entry.tool_calls_count == 0

    def test_tool_calls_count_positive(self) -> None:
        entry = _make_conversation_entry(tool_calls_count=5)
        assert entry.tool_calls_count == 5

    def test_tool_calls_count_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_conversation_entry(tool_calls_count=-1)


# ===========================================================================
# ToolCallAuditEntry
# ===========================================================================


class TestToolCallAuditEntry:
    """Tests for the ToolCallAuditEntry audit model."""

    def test_valid_construction(self) -> None:
        entry = _make_tool_call_entry()
        assert entry.entry_type == "tool_call"
        assert entry.tool == "gmail"
        assert entry.action == "read"
        assert entry.permission == "allow"
        assert entry.success is True

    def test_entry_type_fixed_to_tool_call(self) -> None:
        entry = _make_tool_call_entry()
        assert entry.entry_type == "tool_call"

    def test_entry_type_rejects_other_values(self) -> None:
        with pytest.raises(ValidationError):
            _make_tool_call_entry(entry_type="conversation")

    def test_timestamp_auto_set_utc(self) -> None:
        before = datetime.now(UTC)
        entry = _make_tool_call_entry()
        after = datetime.now(UTC)
        assert entry.timestamp.tzinfo is not None
        assert before <= entry.timestamp <= after

    @pytest.mark.parametrize("perm", ["allow", "confirm", "deny"])
    def test_permission_accepts_valid(self, perm: str) -> None:
        entry = _make_tool_call_entry(permission=perm)
        assert entry.permission == perm

    @pytest.mark.parametrize("perm", ["reject", "block", ""])
    def test_permission_rejects_invalid(self, perm: str) -> None:
        with pytest.raises(ValidationError):
            _make_tool_call_entry(permission=perm)

    def test_args_summary_max_length(self) -> None:
        entry = _make_tool_call_entry(args_summary="x" * 512)
        assert len(entry.args_summary) == 512

    def test_args_summary_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            _make_tool_call_entry(args_summary="x" * 513)

    def test_error_default_none(self) -> None:
        entry = _make_tool_call_entry()
        assert entry.error is None

    def test_error_accepts_string(self) -> None:
        entry = _make_tool_call_entry(error="Something broke")
        assert entry.error == "Something broke"

    def test_error_max_length(self) -> None:
        entry = _make_tool_call_entry(error="e" * 512)
        assert len(entry.error) == 512  # type: ignore[arg-type]

    def test_error_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            _make_tool_call_entry(error="e" * 513)

    def test_tool_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            _make_tool_call_entry(tool="t" * 65)

    def test_action_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            _make_tool_call_entry(action="a" * 65)


# ===========================================================================
# AuditEntry union
# ===========================================================================


class TestAuditEntry:
    """AuditEntry is a type alias union; both model types are valid members."""

    def test_conversation_entry_is_audit_entry(self) -> None:
        entry = _make_conversation_entry()
        assert isinstance(entry, ConversationAuditEntry)

    def test_tool_call_entry_is_audit_entry(self) -> None:
        entry = _make_tool_call_entry()
        assert isinstance(entry, ToolCallAuditEntry)


# ===========================================================================
# ChatMessage
# ===========================================================================


class TestChatMessage:
    """Tests for the ChatMessage API model."""

    @pytest.mark.parametrize("role", ["user", "assistant", "system"])
    def test_role_accepts_valid(self, role: str) -> None:
        msg = ChatMessage(role=role, content="hi")  # type: ignore[arg-type]
        assert msg.role == role

    @pytest.mark.parametrize("role", ["tool", "admin", ""])
    def test_role_rejects_invalid(self, role: str) -> None:
        with pytest.raises(ValidationError):
            ChatMessage(role=role, content="hi")  # type: ignore[arg-type]

    def test_content_max_length(self) -> None:
        msg = ChatMessage(role="user", content="x" * 32768)
        assert len(msg.content) == 32768

    def test_content_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            ChatMessage(role="user", content="x" * 32769)


# ===========================================================================
# ChatRequest
# ===========================================================================


class TestChatRequest:
    """Tests for the ChatRequest API model."""

    def test_valid_construction(self) -> None:
        req = ChatRequest(message="Hello", session_id="sess-01")
        assert req.message == "Hello"
        assert req.session_id == "sess-01"

    def test_message_min_length(self) -> None:
        req = ChatRequest(message="a", session_id="s")
        assert req.message == "a"

    def test_message_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ChatRequest(message="", session_id="s")

    def test_message_max_length(self) -> None:
        req = ChatRequest(message="x" * 32768, session_id="s")
        assert len(req.message) == 32768

    def test_message_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            ChatRequest(message="x" * 32769, session_id="s")

    @pytest.mark.parametrize(
        "sid",
        ["abc", "ABC", "123", "a-b", "a_b", "A1-b_2", "x" * 64],
    )
    def test_session_id_accepts_valid(self, sid: str) -> None:
        req = ChatRequest(message="hi", session_id=sid)
        assert req.session_id == sid

    @pytest.mark.parametrize(
        "sid",
        ["has space", "has@char", "has.dot", "has/slash", "", "a" * 65],
    )
    def test_session_id_rejects_invalid(self, sid: str) -> None:
        with pytest.raises(ValidationError):
            ChatRequest(message="hi", session_id=sid)


# ===========================================================================
# ToolCallRecord
# ===========================================================================


class TestToolCallRecord:
    """Tests for the ToolCallRecord API model."""

    def test_valid_construction(self) -> None:
        rec = ToolCallRecord(tool="gmail", action="read", permission="allow", success=True)
        assert rec.tool == "gmail"
        assert rec.permission == "allow"

    @pytest.mark.parametrize("perm", ["allow", "confirm", "deny"])
    def test_permission_accepts_valid(self, perm: str) -> None:
        rec = ToolCallRecord(tool="t", action="a", permission=perm, success=True)  # type: ignore[arg-type]
        assert rec.permission == perm

    @pytest.mark.parametrize("perm", ["block", "reject", ""])
    def test_permission_rejects_invalid(self, perm: str) -> None:
        with pytest.raises(ValidationError):
            ToolCallRecord(tool="t", action="a", permission=perm, success=True)  # type: ignore[arg-type]

    def test_tool_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            ToolCallRecord(tool="t" * 65, action="a", permission="allow", success=True)

    def test_action_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            ToolCallRecord(tool="t", action="a" * 65, permission="allow", success=True)


# ===========================================================================
# ChatResponse
# ===========================================================================


class TestChatResponse:
    """Tests for the ChatResponse API model."""

    def test_valid_construction(self) -> None:
        resp = ChatResponse(session_id="s1", response="ok")
        assert resp.session_id == "s1"
        assert resp.response == "ok"
        assert resp.tool_calls == []

    def test_with_tool_calls(self) -> None:
        rec = ToolCallRecord(tool="gmail", action="read", permission="allow", success=True)
        resp = ChatResponse(session_id="s1", response="done", tool_calls=[rec])
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].tool == "gmail"

    def test_response_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            ChatResponse(session_id="s1", response="x" * 65537)

    def test_session_id_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            ChatResponse(session_id="s" * 65, response="ok")


# ===========================================================================
# ConfirmRequest
# ===========================================================================


class TestConfirmRequest:
    """Tests for the ConfirmRequest API model."""

    def test_valid_construction(self) -> None:
        req = ConfirmRequest(session_id="sess-1", confirmation_id="conf-1", approved=True)
        assert req.approved is True

    @pytest.mark.parametrize(
        "sid",
        ["abc", "a-b_c", "X123", "x" * 64],
    )
    def test_session_id_accepts_valid(self, sid: str) -> None:
        req = ConfirmRequest(session_id=sid, confirmation_id="c1", approved=False)
        assert req.session_id == sid

    @pytest.mark.parametrize(
        "sid",
        ["has space", "bad@char", "", "a" * 65],
    )
    def test_session_id_rejects_invalid(self, sid: str) -> None:
        with pytest.raises(ValidationError):
            ConfirmRequest(session_id=sid, confirmation_id="c1", approved=True)

    def test_confirmation_id_min_length(self) -> None:
        req = ConfirmRequest(session_id="s", confirmation_id="x", approved=True)
        assert req.confirmation_id == "x"

    def test_confirmation_id_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ConfirmRequest(session_id="s", confirmation_id="", approved=True)

    def test_confirmation_id_max_length(self) -> None:
        req = ConfirmRequest(session_id="s", confirmation_id="c" * 64, approved=True)
        assert len(req.confirmation_id) == 64

    def test_confirmation_id_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            ConfirmRequest(session_id="s", confirmation_id="c" * 65, approved=True)


# ===========================================================================
# SSEEvent
# ===========================================================================


class TestSSEEvent:
    """Tests for the SSEEvent model."""

    def test_valid_construction(self) -> None:
        ev = SSEEvent(event="message", data='{"text":"hi"}')
        assert ev.event == "message"

    def test_event_max_length(self) -> None:
        ev = SSEEvent(event="e" * 64, data="d")
        assert len(ev.event) == 64

    def test_event_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            SSEEvent(event="e" * 65, data="d")

    def test_data_max_length(self) -> None:
        ev = SSEEvent(event="e", data="d" * 65536)
        assert len(ev.data) == 65536

    def test_data_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            SSEEvent(event="e", data="d" * 65537)


# ===========================================================================
# ToolCall
# ===========================================================================


class TestToolCall:
    """Tests for the ToolCall agent model."""

    def test_valid_construction(self) -> None:
        tc = _make_tool_call()
        assert tc.tool == "gmail"
        assert tc.action == "read"
        assert tc.args == {"message_id": "123"}

    def test_tool_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            _make_tool_call(tool="t" * 65)

    def test_action_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            _make_tool_call(action="a" * 65)

    def test_args_default_empty_dict(self) -> None:
        tc = ToolCall(tool="t", action="a")
        assert tc.args == {}

    def test_args_nested_dict(self) -> None:
        tc = _make_tool_call(args={"outer": {"inner": [1, 2, 3]}})
        assert tc.args["outer"]["inner"] == [1, 2, 3]

    def test_args_mixed_types(self) -> None:
        tc = _make_tool_call(args={"s": "str", "i": 42, "f": 3.14, "b": True, "n": None})
        assert tc.args["s"] == "str"
        assert tc.args["n"] is None


# ===========================================================================
# LLMMessage
# ===========================================================================


class TestLLMMessage:
    """Tests for the LLMMessage model."""

    @pytest.mark.parametrize("role", ["user", "assistant", "system", "tool"])
    def test_role_accepts_valid(self, role: str) -> None:
        msg = LLMMessage(role=role, content="hi")  # type: ignore[arg-type]
        assert msg.role == role

    @pytest.mark.parametrize("role", ["admin", "function", ""])
    def test_role_rejects_invalid(self, role: str) -> None:
        with pytest.raises(ValidationError):
            LLMMessage(role=role, content="hi")  # type: ignore[arg-type]

    def test_content_max_length(self) -> None:
        msg = LLMMessage(role="user", content="c" * 65536)
        assert len(msg.content) == 65536

    def test_content_exceeds_max_length(self) -> None:
        with pytest.raises(ValidationError):
            LLMMessage(role="user", content="c" * 65537)

    def test_tool_call_id_default_none(self) -> None:
        msg = LLMMessage(role="user", content="hi")
        assert msg.tool_call_id is None

    def test_tool_call_id_accepts_value(self) -> None:
        msg = LLMMessage(role="tool", content="result", tool_call_id="tc-1")
        assert msg.tool_call_id == "tc-1"

    def test_tool_call_id_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            LLMMessage(role="tool", content="r", tool_call_id="x" * 65)


# ===========================================================================
# AgentConfig
# ===========================================================================


class TestAgentConfig:
    """Tests for the AgentConfig model."""

    def test_defaults(self) -> None:
        cfg = AgentConfig()
        assert cfg.max_tool_calls == 10
        assert cfg.max_context_messages == 40
        assert cfg.confirmation_timeout_s == 30.0

    def test_max_tool_calls_boundaries(self) -> None:
        assert AgentConfig(max_tool_calls=1).max_tool_calls == 1
        assert AgentConfig(max_tool_calls=50).max_tool_calls == 50

    @pytest.mark.parametrize("val", [0, -1, 51, 100])
    def test_max_tool_calls_out_of_range(self, val: int) -> None:
        with pytest.raises(ValidationError):
            AgentConfig(max_tool_calls=val)

    def test_max_context_messages_boundaries(self) -> None:
        assert AgentConfig(max_context_messages=1).max_context_messages == 1
        assert AgentConfig(max_context_messages=200).max_context_messages == 200

    @pytest.mark.parametrize("val", [0, -1, 201, 500])
    def test_max_context_messages_out_of_range(self, val: int) -> None:
        with pytest.raises(ValidationError):
            AgentConfig(max_context_messages=val)

    def test_confirmation_timeout_boundaries(self) -> None:
        assert AgentConfig(confirmation_timeout_s=1.0).confirmation_timeout_s == 1.0
        assert AgentConfig(confirmation_timeout_s=300.0).confirmation_timeout_s == 300.0

    @pytest.mark.parametrize("val", [0.0, 0.5, -1.0, 300.1, 1000.0])
    def test_confirmation_timeout_out_of_range(self, val: float) -> None:
        with pytest.raises(ValidationError):
            AgentConfig(confirmation_timeout_s=val)


# ===========================================================================
# PendingConfirmation
# ===========================================================================


class TestPendingConfirmation:
    """Tests for the PendingConfirmation model."""

    def test_valid_construction(self) -> None:
        tc = _make_tool_call()
        pc = PendingConfirmation(
            confirmation_id="c1",
            session_id="s1",
            tool_call=tc,
            expires_at=_EXPIRES,
        )
        assert pc.confirmation_id == "c1"
        assert pc.tool_call.tool == "gmail"

    def test_created_at_auto_set_utc(self) -> None:
        before = datetime.now(UTC)
        pc = PendingConfirmation(
            confirmation_id="c1",
            session_id="s1",
            tool_call=_make_tool_call(),
            expires_at=_EXPIRES,
        )
        after = datetime.now(UTC)
        assert pc.created_at.tzinfo is not None
        assert before <= pc.created_at <= after

    def test_expires_at_required(self) -> None:
        with pytest.raises(ValidationError):
            PendingConfirmation(
                confirmation_id="c1",
                session_id="s1",
                tool_call=_make_tool_call(),
                # expires_at omitted
            )

    def test_contains_tool_call(self) -> None:
        tc = _make_tool_call(tool="calendar", action="create", args={"title": "Meeting"})
        pc = PendingConfirmation(
            confirmation_id="c2",
            session_id="s2",
            tool_call=tc,
            expires_at=_EXPIRES,
        )
        assert pc.tool_call.tool == "calendar"
        assert pc.tool_call.action == "create"
        assert pc.tool_call.args["title"] == "Meeting"

    def test_confirmation_id_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            PendingConfirmation(
                confirmation_id="c" * 65,
                session_id="s1",
                tool_call=_make_tool_call(),
                expires_at=_EXPIRES,
            )

    def test_session_id_max_length_exceeded(self) -> None:
        with pytest.raises(ValidationError):
            PendingConfirmation(
                confirmation_id="c1",
                session_id="s" * 65,
                tool_call=_make_tool_call(),
                expires_at=_EXPIRES,
            )


# ===========================================================================
# JSON round-trip serialization
# ===========================================================================


class TestJsonRoundTrip:
    """Every model must survive model_dump_json -> model_validate_json."""

    def test_conversation_audit_entry(self) -> None:
        original = _make_conversation_entry()
        raw = original.model_dump_json()
        restored = ConversationAuditEntry.model_validate_json(raw)
        assert restored == original

    def test_tool_call_audit_entry(self) -> None:
        original = _make_tool_call_entry(error="oops")
        raw = original.model_dump_json()
        restored = ToolCallAuditEntry.model_validate_json(raw)
        assert restored == original

    def test_chat_message(self) -> None:
        original = ChatMessage(role="user", content="hello")
        raw = original.model_dump_json()
        restored = ChatMessage.model_validate_json(raw)
        assert restored == original

    def test_chat_request(self) -> None:
        original = ChatRequest(message="hi", session_id="s1")
        raw = original.model_dump_json()
        restored = ChatRequest.model_validate_json(raw)
        assert restored == original

    def test_chat_response(self) -> None:
        rec = ToolCallRecord(tool="t", action="a", permission="allow", success=True)
        original = ChatResponse(session_id="s", response="ok", tool_calls=[rec])
        raw = original.model_dump_json()
        restored = ChatResponse.model_validate_json(raw)
        assert restored == original

    def test_tool_call_record(self) -> None:
        original = ToolCallRecord(tool="t", action="a", permission="deny", success=False)
        raw = original.model_dump_json()
        restored = ToolCallRecord.model_validate_json(raw)
        assert restored == original

    def test_confirm_request(self) -> None:
        original = ConfirmRequest(session_id="s", confirmation_id="c", approved=True)
        raw = original.model_dump_json()
        restored = ConfirmRequest.model_validate_json(raw)
        assert restored == original

    def test_sse_event(self) -> None:
        original = SSEEvent(event="message", data="payload")
        raw = original.model_dump_json()
        restored = SSEEvent.model_validate_json(raw)
        assert restored == original

    def test_tool_call(self) -> None:
        original = _make_tool_call(args={"nested": {"key": [1, 2]}})
        raw = original.model_dump_json()
        restored = ToolCall.model_validate_json(raw)
        assert restored == original

    def test_llm_message(self) -> None:
        original = LLMMessage(role="tool", content="result", tool_call_id="tc-1")
        raw = original.model_dump_json()
        restored = LLMMessage.model_validate_json(raw)
        assert restored == original

    def test_agent_config(self) -> None:
        original = AgentConfig(max_tool_calls=5, max_context_messages=20)
        raw = original.model_dump_json()
        restored = AgentConfig.model_validate_json(raw)
        assert restored == original

    def test_pending_confirmation(self) -> None:
        original = PendingConfirmation(
            confirmation_id="c1",
            session_id="s1",
            tool_call=_make_tool_call(),
            expires_at=_EXPIRES,
        )
        raw = original.model_dump_json()
        restored = PendingConfirmation.model_validate_json(raw)
        assert restored == original


# ===========================================================================
# Datetime ISO 8601 serialization
# ===========================================================================


class TestDatetimeSerialization:
    """Datetime fields must serialize to ISO 8601 with UTC timezone info."""

    def test_conversation_entry_timestamp_iso(self) -> None:
        entry = _make_conversation_entry()
        data = json.loads(entry.model_dump_json())
        ts_str: str = data["timestamp"]
        # Must parse back to a timezone-aware datetime
        parsed = datetime.fromisoformat(ts_str)
        assert parsed.tzinfo is not None

    def test_tool_call_entry_timestamp_iso(self) -> None:
        entry = _make_tool_call_entry()
        data = json.loads(entry.model_dump_json())
        ts_str: str = data["timestamp"]
        parsed = datetime.fromisoformat(ts_str)
        assert parsed.tzinfo is not None

    def test_pending_confirmation_timestamps_iso(self) -> None:
        pc = PendingConfirmation(
            confirmation_id="c1",
            session_id="s1",
            tool_call=_make_tool_call(),
            expires_at=_EXPIRES,
        )
        data = json.loads(pc.model_dump_json())
        for field in ("created_at", "expires_at"):
            parsed = datetime.fromisoformat(data[field])
            assert parsed.tzinfo is not None


# ===========================================================================
# Security: no secret-bearing field names
# ===========================================================================

_FORBIDDEN_FIELD_NAMES = {"token", "password", "secret", "key", "credential", "api_key"}

_ALL_MODELS = [
    ConversationAuditEntry,
    ToolCallAuditEntry,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ToolCallRecord,
    ConfirmRequest,
    SSEEvent,
    ToolCall,
    LLMMessage,
    AgentConfig,
    PendingConfirmation,
]


@pytest.mark.parametrize("model_cls", _ALL_MODELS, ids=lambda c: c.__name__)
def test_no_secret_field_names(model_cls: type) -> None:
    """No model should have fields named token, password, secret, key, credential, or api_key."""
    field_names = set(model_cls.model_fields.keys())
    overlap = field_names & _FORBIDDEN_FIELD_NAMES
    assert overlap == set(), f"{model_cls.__name__} has forbidden fields: {overlap}"
